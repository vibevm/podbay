#define _GNU_SOURCE
/* Fixed diagnostic child. Boot B never receives or restores a Boot A FD. */
#include "r1_two_boot_checkpoint.h"
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <stddef.h>
#include <sys/ptrace.h>
#include <sys/socket.h>

#if !defined(__x86_64__)
#error The guest policy requires x86_64.
#endif
#define ALLOW(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(n),0,1), BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
static int seal(void) {
    struct sock_filter rules[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_X86_64,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,0x40000000u,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
        ALLOW(SYS_read),ALLOW(SYS_write),ALLOW(SYS_close),ALLOW(SYS_poll),
        ALLOW(SYS_openat),ALLOW(SYS_open),ALLOW(SYS_fstat),ALLOW(SYS_newfstatat),
        ALLOW(SYS_pread64),ALLOW(SYS_pwrite64),ALLOW(SYS_fsync),ALLOW(SYS_fcntl),
        ALLOW(SYS_clock_gettime),ALLOW(SYS_getpid),ALLOW(SYS_brk),ALLOW(SYS_mmap),
        ALLOW(SYS_munmap),ALLOW(SYS_mprotect),ALLOW(SYS_rt_sigreturn),ALLOW(SYS_exit),ALLOW(SYS_exit_group),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM)
    };
    struct sock_fprog p={.len=(unsigned short)(sizeof(rules)/sizeof(rules[0])),.filter=rules};
    return (int)syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,&p);
}
static struct r1_context context;
static int errors[8];
static void reply(unsigned phase,unsigned flags,int rc,int error,int fd) {
    struct r1_message m={.magic=R1_MAGIC,.phase=phase,.flags=flags,.pid=getpid(),.rc=rc,
      .error=error,.data_fd=fd,.device=context.device,.inode=context.inode};
    memcpy(m.nonce,context.nonce,sizeof(m.nonce));memcpy(m.boot,context.boot,sizeof(m.boot));
    memcpy(m.denials,errors,sizeof(m.denials));if(full_write(1,&m,sizeof(m)))_exit(110);
}
static void need(int ok){if(!ok){reply(0,0,-1,errno,-1);_exit(111);}}
static void command(char wanted){char c=0;need(!bounded_read(0,&c,1)&&c==wanted);}
static void forbidden(long r){need(r==-1&&errno==EPERM);}
static int exact_file(int fd){struct stat s;return !fstat(fd,&s)&&S_ISREG(s.st_mode)&&s.st_uid==1000&&s.st_gid==1000&&
    (s.st_mode&07777)==0600&&s.st_nlink==1&&(uint64_t)s.st_dev==context.device&&
    (uint64_t)s.st_ino==context.inode&&(uint64_t)s.st_size==context.bytes;}
static void check_file(int fd){unsigned char h[100];char hash[65];need(exact_file(fd)&&pread(fd,h,100,0)==100&&
    !memcmp(h,"SQLite format 3\0",16)&&h[60]==0&&h[61]==0&&h[62]==0&&h[63]==24);
    need(!hash_fd(fd,hash)&&!strcmp(hash,context.hash));}
static void broker(void){
    for(int fd=3;fd<=257;fd++){errno=0;need(fcntl(fd,F_GETFD)==-1&&errno==EBADF);}
    need(!seal());
    errno=0;forbidden(syscall(SYS_socket,AF_UNIX,SOCK_STREAM,0));
    errno=0;forbidden(syscall(SYS_sendmsg,-1,NULL,0));
    errno=0;forbidden(syscall(SYS_recvmsg,-1,NULL,0));
    errno=0;forbidden(syscall(SYS_unshare,CLONE_NEWNS));
    errno=0;forbidden(syscall(SYS_setns,-1,CLONE_NEWNS));
    errno=0;forbidden(syscall(SYS_ptrace,PTRACE_TRACEME,0,0,0));
    errno=0;forbidden(syscall(SYS_pidfd_getfd,-1,0,0));
    errno=0;forbidden(syscall(SYS_prctl,PR_SET_DUMPABLE,1,0,0,0));
    errno=0;long child=syscall(SYS_fork);if(!child)_exit(112);forbidden(child);
    char *const args[]={"/absent",NULL};char *const env[]={NULL};
    errno=0;forbidden(syscall(SYS_execve,"/absent",args,env));
    reply(R1_READY,7,0,0,-1);command('G');
    int fd=open("/probe/store/db.sqlite",(context.mode==R1_BROKER_WRITE?O_RDWR:O_RDONLY)|O_NOFOLLOW|O_CLOEXEC);
    need(fd>=0);check_file(fd);
    if(context.mode==R1_BROKER_WRITE){unsigned char h[100];need(pread(fd,h,100,0)==100&&pwrite(fd,h,100,0)==100&&!fsync(fd));check_file(fd);}
    reply(R1_OPENED,15,context.mode==R1_BROKER_WRITE?100:0,0,fd);
    /* An explicit refresh binds crash readiness to an actually still-open FD.
       After H, keep it open without an idle deadline until exact process death. */
    command('H');check_file(fd);reply(R1_HELD,15,0,0,fd);
    char c;ssize_t n;do{n=read(0,&c,1);}while(n<0&&errno==EINTR);
    need(n==1&&c=='S');need(!close(fd));reply(R1_DONE,1,0,0,-1);
}
static void deny_path(const char *path,unsigned index,int flags){errno=0;int fd=open(path,flags|O_CLOEXEC);int e=errno;
    if(fd>=0)close(fd);
    need(fd==-1&&(e==EACCES||e==EPERM));errors[index]=e;}
static void outside(void){
    for(int fd=3;fd<=257;fd++){errno=0;need(fcntl(fd,F_GETFD)==-1&&errno==EBADF);}
    reply(R1_READY,3,0,0,-1);command('G');
    const char *suffix[]={"","-wal","-shm","-journal"};char path[256];
    for(unsigned i=0;i<4;i++){snprintf(path,sizeof(path),"%s%s",R1_SOURCE,suffix[i]);deny_path(path,i,O_RDWR);}
    if(context.target_pid==1)snprintf(path,sizeof(path),"/proc/1/root%s",R1_SOURCE);
    else snprintf(path,sizeof(path),"/proc/%d/root/probe/store/db.sqlite",context.target_pid);
    deny_path(path,4,O_RDWR);
    snprintf(path,sizeof(path),"/proc/%d/fd/%d",context.target_pid,context.target_fd);deny_path(path,5,O_RDWR);
    snprintf(path,sizeof(path),"/proc/%d/ns/mnt",context.target_pid);deny_path(path,6,O_RDONLY);
    errno=0;need(unshare(CLONE_NEWNS)==-1&&errno==EPERM);errors[7]=errno;
    reply(R1_DONE,255,-1,errors[0],-1);
}
int main(int argc,char **argv){
    if(argc==2&&!strcmp(argv[1],"--self-test"))return getuid()!=0&&hash_self_test()?0:3;
    if(argc!=1||getppid()!=1||getuid()!=1000||geteuid()!=1000)return 3;
    if(prctl(PR_SET_DUMPABLE,0,0,0,0)||!owner_sealed())return 4;
    need(!bounded_read(0,&context,sizeof(context))&&context.magic==R1_MAGIC&&
      context.mode>=R1_BROKER_WRITE&&context.mode<=R1_OUTSIDE&&
      memchr(context.nonce,0,sizeof(context.nonce))&&hex_text(context.nonce,32)&&
      memchr(context.boot,0,sizeof(context.boot))&&r1_uuid(context.boot)&&
      memchr(context.hash,0,sizeof(context.hash))&&hex_text(context.hash,64)&&
      context.bytes>=4096&&context.bytes<=ORIGIN_FILE_CAP&&context.target_pid>=0);
    if(context.mode==R1_OUTSIDE)outside();else broker();return 0;
}
