#define PAM_SM_AUTH
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>

#define GUARD_DIR "/var/lib/promptworks-auth-guard"
#define GUARD_STATE GUARD_DIR "/state"
#define MATCH_HISTORY GUARD_DIR "/time-match-history"
#define ROLLBACK_HELPER "/usr/local/sbin/promptworks-auth-rollback"
#define DEFAULT_KEY_FILE "/etc/promptworks-auth/offline.key"
#define DEFAULT_HOST_FILE "/etc/promptworks-auth/host-id"
#define DEFAULT_BINDING_FILE "/etc/promptworks-auth/binding.json"
#define PROTOCOL_LABEL "PromptWorks-TimeMatch-v1"
#define RESPONSE_DIGITS 8
#define MATCH_DIGITS 3
#define WINDOW_SECONDS 60
#define MIN_REMAINING_SECONDS 20

static void secure_bzero(void *p, size_t n) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    OPENSSL_cleanse(p, n);
#else
    volatile unsigned char *v=(volatile unsigned char*)p; while(n--) *v++=0;
#endif
}

static int read_small_file(const char *path, char *out, size_t cap) {
    if (!path || !out || cap < 2) return -1;
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0) return -1;
    struct stat st;
    if(fstat(fd,&st)!=0 || !S_ISREG(st.st_mode) || st.st_uid!=0 || (st.st_mode & 0022)!=0){close(fd);return -1;}
    ssize_t n=read(fd,out,cap-1); close(fd);
    if(n<=0) return -1;
    out[n]=0;
    while(n>0 && (out[n-1]=='\n'||out[n-1]=='\r'||out[n-1]==' '||out[n-1]=='\t')) out[--n]=0;
    return (int)n;
}

static int hexval(char c){ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return -1; }
static int decode_hex32(const char *hex, unsigned char out[32]) {
    if(!hex || strlen(hex)!=64) return -1;
    for(int i=0;i<32;i++){int a=hexval(hex[i*2]),b=hexval(hex[i*2+1]);if(a<0||b<0)return -1;out[i]=(unsigned char)((a<<4)|b);} return 0;
}

static int constant_time_digits_eq(const char *a,const char *b,size_t n){
    unsigned char d=0; if(!a||!b)return 0;
    for(size_t i=0;i<n;i++)d|=(unsigned char)(a[i]^b[i]);
    return d==0 && a[n]==0 && b[n]==0;
}

/* Bounded single-use history: never reuse a 3-digit match number in the same 60-second epoch. */
static int match_seen_or_record(long long epoch, const char *number){
    int fd=open(MATCH_HISTORY,O_RDWR|O_CREAT|O_CLOEXEC|O_NOFOLLOW,0600); if(fd<0)return -1;
    if(flock(fd,LOCK_EX)!=0){close(fd);return -1;}
    char buf[32768]={0}; ssize_t n=read(fd,buf,sizeof(buf)-1); if(n<0)n=0; buf[n]=0;
    char needle[64]; snprintf(needle,sizeof(needle),"%lld:%s\n",epoch,number);
    int seen=strstr(buf,needle)!=NULL;
    if(!seen){
        char out[32768]={0}; size_t used=0; char *save=NULL,*line=strtok_r(buf,"\n",&save); int count=0; char *lines[2048];
        while(line && count<2048){lines[count++]=line;line=strtok_r(NULL,"\n",&save);}
        int start=count>1800?count-1800:0;
        for(int i=start;i<count;i++){
            long long e=0; if(sscanf(lines[i],"%lld:",&e)!=1 || e < epoch-4) continue;
            size_t l=strlen(lines[i]); if(used+l+1<sizeof(out)){memcpy(out+used,lines[i],l);used+=l;out[used++]='\n';}
        }
        size_t l=strlen(needle); if(used+l<sizeof(out)){memcpy(out+used,needle,l);used+=l;}
        lseek(fd,0,SEEK_SET);ftruncate(fd,0);if(write(fd,out,used)!=(ssize_t)used)seen=-1;fsync(fd);
    }
    flock(fd,LOCK_UN);close(fd);return seen;
}

static int generate_match_number(long long epoch, char out[MATCH_DIGITS+1]) {
    for(int tries=0;tries<1024;tries++){
        uint16_t x=0; if(RAND_bytes((unsigned char*)&x,sizeof(x))!=1)return -1;
        unsigned int v=(unsigned int)(x % 1000U);
        snprintf(out,MATCH_DIGITS+1,"%03u",v);
        int seen=match_seen_or_record(epoch,out); if(seen==0)return 0; if(seen<0)return -1;
    }
    return -1;
}

/*
 * Time-bound number matching.
 * The human-visible 3-digit number is not a secret. The 8-digit decision code is
 * HMAC-SHA256 over the bound host, time epoch, match number and explicit decision.
 * Every request number is single-use within its epoch, which blocks replay of a
 * captured decision code into another request in that epoch.
 */
static int decision_code(const unsigned char key[32], const char *host, long long epoch,
                         const char *number, const char *decision, char out[16]) {
    if(!host || !number || !decision || strlen(number)!=MATCH_DIGITS) return -1;
    char payload[1024];
    int n=snprintf(payload,sizeof(payload),"%s\n%s\n%lld\n%s\n%s",PROTOCOL_LABEL,host,epoch,number,decision);
    if(n<=0 || (size_t)n>=sizeof(payload)) return -1;
    unsigned int mdlen=0; unsigned char md[EVP_MAX_MD_SIZE];
    if(!HMAC(EVP_sha256(),key,32,(unsigned char*)payload,n,md,&mdlen) || mdlen<20){secure_bzero(payload,sizeof(payload));return -1;}
    int off=md[mdlen-1]&0x0f;
    if(off+3 >= (int)mdlen){secure_bzero(md,sizeof(md));secure_bzero(payload,sizeof(payload));return -1;}
    uint32_t bin=((uint32_t)(md[off]&0x7f)<<24)|((uint32_t)(md[off+1]&0xff)<<16)|((uint32_t)(md[off+2]&0xff)<<8)|(uint32_t)(md[off+3]&0xff);
    snprintf(out,16,"%08u",(unsigned int)(bin%100000000U));
    secure_bzero(md,sizeof(md)); secure_bzero(payload,sizeof(payload)); return 0;
}

/* First-install commissioning guard: 3 invalid/expired checks before first success restore original PAM. */
static void guard_record(int success){
    int fd=open(GUARD_STATE,O_RDWR|O_CLOEXEC|O_NOFOLLOW); if(fd<0)return;
    if(flock(fd,LOCK_EX)!=0){close(fd);return;}
    char b[128]={0};ssize_t n=read(fd,b,sizeof(b)-1);if(n<0)n=0;b[n]=0;
    char state[32]="armed";int failures=0;
    if(sscanf(b,"%31s %d",state,&failures)<1){strcpy(state,"armed");failures=0;}
    if(strcmp(state,"armed")!=0){flock(fd,LOCK_UN);close(fd);return;}
    if(success){strcpy(state,"passed");failures=0;}else{failures++;if(failures>=3)strcpy(state,"rollback");}
    lseek(fd,0,SEEK_SET);ftruncate(fd,0);dprintf(fd,"%s %d\n",state,failures);fsync(fd);
    int trigger=!success&&failures>=3;flock(fd,LOCK_UN);close(fd);
    if(trigger){pid_t pid=fork();if(pid==0){setsid();int dn=open("/dev/null",O_RDWR);if(dn>=0){dup2(dn,0);dup2(dn,1);dup2(dn,2);if(dn>2)close(dn);}execl(ROLLBACK_HELPER,ROLLBACK_HELPER,"--auto",(char*)NULL);_exit(127);}}
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *p,int flags,int argc,const char **argv){
    (void)flags;
    const char *keyfile=DEFAULT_KEY_FILE,*hostfile=DEFAULT_HOST_FILE,*bindingfile=DEFAULT_BINDING_FILE;
    for(int i=0;i<argc;i++){if(!strncmp(argv[i],"keyfile=",8))keyfile=argv[i]+8;else if(!strncmp(argv[i],"hostfile=",9))hostfile=argv[i]+9;else if(!strncmp(argv[i],"bindingfile=",12))bindingfile=argv[i]+12;}

    char hex[96]={0},host[256]="this Linux host",binding[2048]={0}; unsigned char key[32];
    int blen=read_small_file(bindingfile,binding,sizeof(binding));
    if(blen<64 || !strstr(binding,"\"deviceId\"") || !strstr(binding,"\"pairingId\"") || !strstr(binding,"\"approvalKeyFingerprint\"")){
        pam_error(p,"PromptWorks single-device binding unavailable or insecure");guard_record(0);return PAM_AUTH_ERR;
    }
    if(read_small_file(keyfile,hex,sizeof(hex))!=64 || decode_hex32(hex,key)!=0){
        pam_error(p,"PromptWorks bound runtime key unavailable or insecure");guard_record(0);secure_bzero(hex,sizeof(hex));return PAM_AUTH_ERR;
    }
    (void)read_small_file(hostfile,host,sizeof(host));

    time_t now=time(NULL); if(now==(time_t)-1){guard_record(0);secure_bzero(key,sizeof(key));return PAM_AUTH_ERR;}
    int remaining=WINDOW_SECONDS-(int)(now%WINDOW_SECONDS);
    if(remaining<MIN_REMAINING_SECONDS){
        pam_info(p,"PromptWorks is waiting %d seconds for a fresh authentication window…",remaining);
        sleep((unsigned int)remaining+1U);
        now=time(NULL);
    }
    long long epoch=(long long)(now/WINDOW_SECONDS);
    time_t deadline=(time_t)((epoch+1)*WINDOW_SECONDS);
    remaining=(int)(deadline-now);

    char number[MATCH_DIGITS+1];
    if(generate_match_number(epoch,number)!=0){
        pam_error(p,"PromptWorks could not generate a secure number match");guard_record(0);secure_bzero(key,sizeof(key));secure_bzero(hex,sizeof(hex));return PAM_AUTH_ERR;
    }

    pam_info(p,"PromptWorks NUMBER MATCH for %s: %s",host,number);
    pam_info(p,"Open the ONE enrolled Prompt-Works-Sudo-Auth APK, enter/select %s and APPROVE or DENY within %d seconds.",number,remaining);
    pam_info(p,"The phone will show an 8-digit decision code. Enter it below. Expired or replayed codes are rejected.");

    char *response=NULL; int pr=pam_prompt(p,PAM_PROMPT_ECHO_ON,&response,"PromptWorks decision code: ");
    time_t answered=time(NULL);
    char approve[16]={0},deny[16]={0}; int approved=0,denied=0,valid_input=0;
    if(pr==PAM_SUCCESS && response && strlen(response)==RESPONSE_DIGITS && answered<deadline){
        valid_input=1; for(size_t i=0;i<RESPONSE_DIGITS;i++)if(!isdigit((unsigned char)response[i]))valid_input=0;
        if(valid_input && decision_code(key,host,epoch,number,"approve",approve)==0 && decision_code(key,host,epoch,number,"deny",deny)==0){
            approved=constant_time_digits_eq(response,approve,RESPONSE_DIGITS);
            denied=constant_time_digits_eq(response,deny,RESPONSE_DIGITS);
        }
    }
    if(response){secure_bzero(response,strlen(response));free(response);}
    secure_bzero(approve,sizeof(approve));secure_bzero(deny,sizeof(deny));secure_bzero(key,sizeof(key));secure_bzero(hex,sizeof(hex));

    if(approved){guard_record(1);return PAM_SUCCESS;}
    if(denied){pam_error(p,"PromptWorks request was DENIED on the enrolled phone");return PAM_AUTH_ERR;}
    if(answered>=deadline) pam_error(p,"PromptWorks number match expired; run sudo again for a new number");
    else pam_error(p,"PromptWorks decision code rejected");
    guard_record(0);return PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t*p,int f,int ac,const char**av){(void)p;(void)f;(void)ac;(void)av;return PAM_SUCCESS;}
