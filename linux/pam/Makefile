CC?=cc
CFLAGS?=-O2 -fPIC -Wall -Wextra -Werror=format-security -fstack-protector-strong -D_FORTIFY_SOURCE=2
LDFLAGS?=-Wl,-z,relro,-z,now
all:
	$(CC) $(CFLAGS) -shared -o pam_promptworks.so pam_promptworks.c -lpam -lcrypto $(LDFLAGS)
clean:
	rm -f pam_promptworks.so
