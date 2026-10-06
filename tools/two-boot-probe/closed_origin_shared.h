#ifndef PODBAY_CLOSED_ORIGIN_SHARED_H
#define PODBAY_CLOSED_ORIGIN_SHARED_H
/* Private x86_64 guest protocol. No admission or production authority type. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/capability.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define ORIGIN_MAGIC 0x4f524731u
#define ORIGIN_TIMEOUT_MS 10000
#define ORIGIN_FILE_CAP (4u * 1024u * 1024u)
#define ORIGIN_POLICY "guest-root-vault-v1;source24;stage-absent;owner1000;no-admission"
enum probe_mode { PROBE_CLEAN=1, PROBE_OUTSIDE, PROBE_FD, PROBE_DIRFD, PROBE_MMAP, PROBE_SCM };
enum probe_phase { PROBE_READY=1, PROBE_OPENED, PROBE_DONE };
struct probe_context {
    uint32_t magic, mode;
    uint64_t device, inode, bytes;
    int32_t observed_pid, observed_fd;
    char nonce[33], source_hash[65], source_path[128];
};
struct probe_message {
    uint32_t magic, phase, flags;
    int32_t pid, rc, error, data_fd;
    int32_t denied_errno[5];
    uint64_t device, inode;
    char nonce[33];
};

static inline int full_write(int fd, const void *data, size_t size) {
    const unsigned char *p=data;
    while(size) { ssize_t n=write(fd,p,size); if(n<0 && errno==EINTR)continue;
        if(n<=0)return -1;
        p+=n;size-=(size_t)n; }
    return 0;
}
static inline int64_t monotonic_ms(void) {
    struct timespec t; if(clock_gettime(CLOCK_MONOTONIC,&t))return -1;
    return (int64_t)t.tv_sec*1000+t.tv_nsec/1000000;
}
static inline int bounded_read(int fd, void *data, size_t size) {
    int64_t start=monotonic_ms(); if(start<0)return -1;
    unsigned char *p=data;
    while(size) {
        int64_t now=monotonic_ms(), left=start+ORIGIN_TIMEOUT_MS-now;
        if(now<0 || left<=0){errno=ETIMEDOUT;return -1;}
        struct pollfd q={.fd=fd,.events=POLLIN};
        int ready=poll(&q,1,(int)left); if(ready<0 && errno==EINTR)continue;
        if(ready<=0){if(!ready)errno=ETIMEDOUT;return -1;}
        ssize_t n=read(fd,p,size); if(n<0 && errno==EINTR)continue;
        if(n<=0){if(!n)errno=EPIPE;return -1;}p+=n;size-=(size_t)n;
    }
    return 0;
}
static inline int hex_text(const char *text, size_t n) {
    if(strlen(text)!=n)return 0;
    for(size_t i=0;i<n;i++)if(!((text[i]>='0'&&text[i]<='9')||(text[i]>='a'&&text[i]<='f')))return 0;
    return 1;
}
static inline int same_inode(const struct stat *a,const struct stat *b) {
    return a->st_dev==b->st_dev && a->st_ino==b->st_ino;
}

/* Small SHA-256 implementation used only to compare fixed fixture artifacts. */
struct sha256_state { uint32_t h[8]; uint64_t bytes; unsigned char block[64]; size_t used; };
static inline uint32_t ror32(uint32_t x,unsigned n){return (x>>n)|(x<<(32-n));}
static inline void sha_block(struct sha256_state *s,const unsigned char *b) {
    static const uint32_t k[64]={
      0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
      0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
      0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
      0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
      0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    uint32_t w[64];for(int i=0;i<16;i++)w[i]=(uint32_t)b[4*i]<<24|(uint32_t)b[4*i+1]<<16|(uint32_t)b[4*i+2]<<8|b[4*i+3];
    for(int i=16;i<64;i++){uint32_t a=w[i-15],z=w[i-2];w[i]=w[i-16]+(ror32(a,7)^ror32(a,18)^(a>>3))+w[i-7]+(ror32(z,17)^ror32(z,19)^(z>>10));}
    uint32_t a=s->h[0],c=s->h[2],b0=s->h[1],d=s->h[3],e=s->h[4],f=s->h[5],g=s->h[6],h=s->h[7];
    for(int i=0;i<64;i++){uint32_t t=h+(ror32(e,6)^ror32(e,11)^ror32(e,25))+((e&f)^(~e&g))+k[i]+w[i];
        uint32_t u=(ror32(a,2)^ror32(a,13)^ror32(a,22))+((a&b0)^(a&c)^(b0&c));h=g;g=f;f=e;e=d+t;d=c;c=b0;b0=a;a=t+u;}
    s->h[0]+=a;s->h[1]+=b0;s->h[2]+=c;s->h[3]+=d;s->h[4]+=e;s->h[5]+=f;s->h[6]+=g;s->h[7]+=h;
}
static inline void sha_init(struct sha256_state *s) {
    *s=(struct sha256_state){.h={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19}};
}
static inline void sha_update(struct sha256_state *s,const void *data,size_t n) {
    const unsigned char *p=data;s->bytes+=n;
    while(n){size_t m=64-s->used;if(m>n)m=n;memcpy(s->block+s->used,p,m);s->used+=m;p+=m;n-=m;
        if(s->used==64){sha_block(s,s->block);s->used=0;}}
}
static inline void sha_finish(struct sha256_state *s,char out[65]) {
    uint64_t bits=s->bytes*8;unsigned char one=128,zero=0;sha_update(s,&one,1);
    while(s->used!=56)sha_update(s,&zero,1);
    unsigned char tail[8];for(int i=0;i<8;i++)tail[7-i]=(unsigned char)(bits>>(8*i));sha_update(s,tail,8);
    for(int i=0;i<8;i++)snprintf(out+8*i,9,"%08x",s->h[i]);
    out[64]=0;
}
static inline int hash_fd(int fd,char out[65]) {
    struct stat before,after;if(fstat(fd,&before)||!S_ISREG(before.st_mode)||before.st_size<0||before.st_size>ORIGIN_FILE_CAP)return -1;
    struct sha256_state s;sha_init(&s);unsigned char bytes[8192];off_t at=0;
    for(;;){ssize_t n=pread(fd,bytes,sizeof(bytes),at);if(n<0&&errno==EINTR)continue;if(n<0)return -1;if(!n)break;
        at+=n;if(at>ORIGIN_FILE_CAP)return -1;sha_update(&s,bytes,(size_t)n);}
    if(fstat(fd,&after)||!same_inode(&before,&after)||at!=before.st_size||after.st_size!=before.st_size||
       before.st_mtim.tv_sec!=after.st_mtim.tv_sec||before.st_mtim.tv_nsec!=after.st_mtim.tv_nsec||
       before.st_ctim.tv_sec!=after.st_ctim.tv_sec||before.st_ctim.tv_nsec!=after.st_ctim.tv_nsec)return -1;
    sha_finish(&s,out);return 0;
}
static inline int hash_self_test(void) {
    struct sha256_state s;char out[65];sha_init(&s);sha_finish(&s,out);
    if(strcmp(out,"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))return 0;
    sha_init(&s);sha_update(&s,"abc",3);sha_finish(&s,out);
    if(strcmp(out,"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"))return 0;
    const char *v="abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha_init(&s);sha_update(&s,v,strlen(v));sha_finish(&s,out);
    if(strcmp(out,"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"))return 0;
    sha_init(&s);for(unsigned i=0;i<1000000;i++)sha_update(&s,"a",1);sha_finish(&s,out);
    return !strcmp(out,"cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}
static inline int drop_owner(void) {
    struct __user_cap_header_struct h={.version=_LINUX_CAPABILITY_VERSION_3,.pid=0};
    struct __user_cap_data_struct d[2]={{0}};
    if(prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_CLEAR_ALL,0,0,0))return -1;
    for(int cap=0;cap<64;cap++){errno=0;int r=prctl(PR_CAPBSET_READ,cap,0,0,0);
        if(r<0 && errno==EINVAL)break;
        if(r<0||prctl(PR_CAPBSET_DROP,cap,0,0,0))return -1;}
    if(setgroups(0,NULL)||setresgid(1000,1000,1000)||setresuid(1000,1000,1000)||syscall(SYS_capset,&h,d))return -1;
    return prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||prctl(PR_SET_DUMPABLE,0,0,0,0)?-1:0;
}
static inline int owner_sealed(void) {
    uid_t r,e,s;gid_t gr,ge,gs;struct __user_cap_header_struct h={.version=_LINUX_CAPABILITY_VERSION_3,.pid=0};
    struct __user_cap_data_struct d[2]={{0}};
    if(getresuid(&r,&e,&s)||getresgid(&gr,&ge,&gs)||getgroups(0,NULL)!=0||
       r!=1000||e!=1000||s!=1000||gr!=1000||ge!=1000||gs!=1000||syscall(SYS_capget,&h,d))return 0;
    for(int i=0;i<2;i++)if(d[i].effective||d[i].permitted||d[i].inheritable)return 0;
    for(int cap=0;cap<64;cap++){errno=0;int v=prctl(PR_CAPBSET_READ,cap,0,0,0);if(v<0&&errno==EINVAL)break;if(v!=0)return 0;}
    return prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)==1&&prctl(PR_GET_DUMPABLE,0,0,0,0)==0;
}
#endif
