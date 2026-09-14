#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define LABEL "PromptWorks-TimeMatch-v1"
#define WINDOW 60
#define MIN_REMAIN 20

static void wipe(void *p,size_t n){ OPENSSL_cleanse(p,n); }
static int hexv(char c){ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return -1; }
static int read_root_file(const char *path,char *out,size_t cap){
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW); if(fd<0)return -1;
    struct stat st; if(fstat(fd,&st)!=0||!S_ISREG(st.st_mode)||st.st_uid!=0||(st.st_mode&0022)){close(fd);return -1;}
    ssize_t n=read(fd,out,cap-1); close(fd); if(n<=0)return -1; out[n]=0;
    while(n>0&&(out[n-1]=='\n'||out[n-1]=='\r'||out[n-1]==' '||out[n-1]=='\t')) out[--n]=0;
    return (int)n;
}
static int decode32(const char *hex,unsigned char out[32]){ if(!hex||strlen(hex)!=64)return -1; for(int i=0;i<32;i++){int a=hexv(hex[i*2]),b=hexv(hex[i*2+1]); if(a<0||b<0)return -1; out[i]=(unsigned char)((a<<4)|b);} return 0; }
static int code(const unsigned char key[32],const char *host,long long epoch,const char *num,const char *decision,char out[9]){
    char payload[1024]; int n=snprintf(payload,sizeof(payload),"%s\n%s\n%lld\n%s\n%s",LABEL,host,epoch,num,decision);
    if(n<=0||(size_t)n>=sizeof(payload))return -1;
    unsigned char md[EVP_MAX_MD_SIZE]; unsigned int mdlen=0;
    if(!HMAC(EVP_sha256(),key,32,(unsigned char*)payload,(size_t)n,md,&mdlen)||mdlen<20){wipe(payload,sizeof(payload));return -1;}
    int off=md[mdlen-1]&0x0f; if(off+3>=(int)mdlen){wipe(md,sizeof(md));wipe(payload,sizeof(payload));return -1;}
    uint32_t bin=((uint32_t)(md[off]&0x7f)<<24)|((uint32_t)md[off+1]<<16)|((uint32_t)md[off+2]<<8)|md[off+3];
    snprintf(out,9,"%08u",(unsigned)(bin%100000000U)); wipe(md,sizeof(md)); wipe(payload,sizeof(payload)); return 0;
}
static int ct_eq(const char *a,const char *b){ unsigned char d=0; for(int i=0;i<8;i++)d|=(unsigned char)(a[i]^b[i]); return d==0&&a[8]==0&&b[8]==0; }
int main(int argc,char **argv){
    const char *keyfile="/etc/promptworks-auth/offline.key",*hostfile="/etc/promptworks-auth/host-id",*purpose="backend change";
    if(geteuid()!=0){fprintf(stderr,"PromptWorks update gate must run as root.\n");return 2;}
    for(int i=1;i<argc;i++){ if(!strcmp(argv[i],"--key")&&i+1<argc)keyfile=argv[++i]; else if(!strcmp(argv[i],"--host")&&i+1<argc)hostfile=argv[++i]; else if(!strcmp(argv[i],"--purpose")&&i+1<argc)purpose=argv[++i]; else {fprintf(stderr,"usage: %s [--key FILE] [--host FILE] [--purpose TEXT]\n",argv[0]);return 2;} }
    char hex[96]={0},host[256]={0}; unsigned char key[32];
    if(read_root_file(keyfile,hex,sizeof(hex))!=64||decode32(hex,key)!=0||read_root_file(hostfile,host,sizeof(host))<=0){fprintf(stderr,"PromptWorks active binding material is unavailable or unsafe.\n");wipe(hex,sizeof(hex));return 3;}
    time_t now=time(NULL); int rem=WINDOW-(int)(now%WINDOW); if(rem<MIN_REMAIN){printf("Waiting %d seconds for a fresh approval window...\n",rem);fflush(stdout);sleep((unsigned)rem+1U);now=time(NULL);}
    long long epoch=(long long)(now/WINDOW); time_t deadline=(time_t)((epoch+1)*WINDOW); rem=(int)(deadline-now);
    unsigned short r=0; if(RAND_bytes((unsigned char*)&r,sizeof(r))!=1){fprintf(stderr,"Secure random generation failed.\n");wipe(key,sizeof(key));return 4;}
    char num[4]; snprintf(num,sizeof(num),"%03u",(unsigned)(r%1000U));
    printf("\n============================================================\n");
    printf(" PromptWorks protected backend-change approval\n");
    printf("============================================================\n");
    printf("Purpose: %s\n",purpose);
    printf("Host:    %s\n",host);
    printf("NUMBER MATCH: %s\n",num);
    printf("Expires in:   %d seconds\n\n",rem);
    printf("Open the CURRENT/OLD enrolled PromptWorks APK, enter %s,\n",num);
    printf("choose APPROVE or DENY, pass strong biometric, then enter\n");
    printf("the 8-digit decision code here.\n\nPromptWorks update decision code: "); fflush(stdout);
    char resp[64]={0}; if(!fgets(resp,sizeof(resp),stdin)){wipe(key,sizeof(key));return 5;} size_t l=strcspn(resp,"\r\n");resp[l]=0;
    time_t answered=time(NULL); char yes[9]={0},no[9]={0}; int ok=0,deny=0,valid=(strlen(resp)==8&&answered<deadline);
    for(int i=0;valid&&i<8;i++)if(!isdigit((unsigned char)resp[i]))valid=0;
    if(valid&&code(key,host,epoch,num,"approve",yes)==0&&code(key,host,epoch,num,"deny",no)==0){ok=ct_eq(resp,yes);deny=ct_eq(resp,no);}
    wipe(key,sizeof(key));wipe(hex,sizeof(hex));wipe(yes,sizeof(yes));wipe(no,sizeof(no));wipe(resp,sizeof(resp));
    if(ok){printf("[APPROVED] Current enrolled APK authorized this backend change.\n");return 0;}
    if(deny){fprintf(stderr,"[DENIED] Current enrolled APK explicitly denied this backend change.\n");return 10;}
    if(answered>=deadline)fprintf(stderr,"[EXPIRED] Approval window expired. No backend change authorized.\n"); else fprintf(stderr,"[REJECTED] Invalid update decision code. No backend change authorized.\n");
    return 11;
}
