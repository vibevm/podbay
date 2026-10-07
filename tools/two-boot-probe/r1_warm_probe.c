#define _GNU_SOURCE
/* Owner-UID diagnostic only. A pre-established observation pipe is not custody. */
#include "r1_warm_shared.h"
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <stddef.h>
#include <sys/ptrace.h>
#include <sys/socket.h>

#if !defined(__x86_64__)
#error The fixed guest policy requires x86_64.
#endif
#define ALLOW(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(n),0,1), BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
static int seal(void){
    struct sock_filter r[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_X86_64,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,0x40000000u,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
        ALLOW(SYS_read),ALLOW(SYS_write),ALLOW(SYS_close),ALLOW(SYS_poll),ALLOW(SYS_openat),ALLOW(SYS_open),
        ALLOW(SYS_fstat),ALLOW(SYS_newfstatat),ALLOW(SYS_pread64),ALLOW(SYS_fcntl),ALLOW(SYS_clock_gettime),
        ALLOW(SYS_getpid),ALLOW(SYS_getppid),ALLOW(SYS_brk),ALLOW(SYS_mmap),ALLOW(SYS_munmap),ALLOW(SYS_mprotect),
        ALLOW(SYS_rt_sigreturn),ALLOW(SYS_exit),ALLOW(SYS_exit_group),ALLOW(SYS_seccomp),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM)
    };
    struct sock_fprog p={.len=(unsigned short)(sizeof(r)/sizeof(r[0])),.filter=r};
    return (int)syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,&p);
}
static int forbid_new_opens(void){
    /* An additional filter can only reduce the already-installed policy. */
    struct sock_filter r[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_open,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_openat,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
    };
    struct sock_fprog p={.len=(unsigned short)(sizeof(r)/sizeof(r[0])),.filter=r};
    return (int)syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,&p);
}
static struct w_context context;
static unsigned response_sequence,command_sequence;
static int denials[8];
static void reply(unsigned phase,unsigned flags,int rc,int error,int fd){
    struct w_message m={.magic=W_MAGIC,.sequence=++response_sequence,.phase=phase,.flags=flags,.pid=getpid(),
      .parent_pid=getppid(),.rc=rc,.error=error,.data_fd=fd,.birth=context.self_birth,.device=context.device,.inode=context.inode};
    memcpy(m.nonce,context.nonce,33);memcpy(m.boot,context.boot,37);memcpy(m.denials,denials,sizeof(denials));
    if(full_write(1,&m,sizeof(m)))_exit(110);
}
static void need(int ok){if(!ok){reply(0,0,-1,errno,-1);_exit(111);}}
static void command(unsigned kind){struct w_command c;
    need(!bounded_read(0,&c,sizeof(c))&&w_command_matches(&c,&context,++command_sequence,kind));}
static void forbidden(long value){need(value==-1&&errno==EPERM);}
static void verify_seal(int opens_forbidden){
    errno=0;forbidden(syscall(SYS_socket,AF_UNIX,SOCK_STREAM,0));
    errno=0;forbidden(syscall(SYS_sendmsg,-1,NULL,0));errno=0;forbidden(syscall(SYS_recvmsg,-1,NULL,0));
    errno=0;forbidden(syscall(SYS_unshare,CLONE_NEWNS));errno=0;forbidden(syscall(SYS_setns,-1,CLONE_NEWNS));
    errno=0;forbidden(syscall(SYS_ptrace,PTRACE_TRACEME,0,0,0));errno=0;forbidden(syscall(SYS_pidfd_getfd,-1,0,0));
    errno=0;forbidden(syscall(SYS_prctl,PR_SET_DUMPABLE,1,0,0,0));
    errno=0;long child=syscall(SYS_fork);if(!child)_exit(112);forbidden(child);
    char *const args[]={"/absent",NULL};char *const env[]={NULL};errno=0;forbidden(syscall(SYS_execve,"/absent",args,env));
    if(opens_forbidden){errno=0;forbidden(syscall(SYS_open,"/probe/store/db.sqlite",O_RDONLY,0));
        errno=0;forbidden(syscall(SYS_openat,AT_FDCWD,"/probe/store/db.sqlite",O_RDONLY,0));}
}
static void check_fd(int fd){struct stat s;unsigned char h[100];char digest[65];
    need(!fstat(fd,&s)&&S_ISREG(s.st_mode)&&s.st_uid==1000&&s.st_gid==1000&&(s.st_mode&07777)==0600&&s.st_nlink==1&&
      (uint64_t)s.st_dev==context.device&&(uint64_t)s.st_ino==context.inode&&(uint64_t)s.st_size==context.bytes&&
      pread(fd,h,sizeof(h),0)==100&&!memcmp(h,"SQLite format 3\0",16)&&h[60]==0&&h[61]==0&&h[62]==0&&h[63]==24&&
      !hash_fd(fd,digest)&&!strcmp(digest,context.hash));
}
static void broker(void){
    need(getppid()==context.parent_pid&&context.parent_pid>1&&!seal());verify_seal(0);reply(W_READY,7,0,0,-1);
    command(W_OPEN);int fd=open("/probe/store/db.sqlite",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    need(fd==3);check_fd(fd);need(!forbid_new_opens());verify_seal(1);reply(W_OPENED,15,100,0,fd);
    command(W_HOLD_BEFORE);need(getppid()==context.parent_pid);check_fd(fd);reply(W_BEFORE,15,100,0,fd);
    command(W_HOLD_AFTER);need(getppid()==1);check_fd(fd);reply(W_AFTER,15,100,0,fd);
    command(W_CHECK_SEAL);need(getppid()==1);verify_seal(1);reply(W_SEALED,31,0,0,fd);
    command(W_HOLD_LAST);need(getppid()==1);check_fd(fd);reply(W_LAST,15,100,0,fd);
    /* Do not close the actual FD or exit on an idle timeout before exact kill. */
    char byte;ssize_t n;do{n=read(0,&byte,1);}while(n<0&&errno==EINTR);
    need(0); /* No accepted command follows the last held-FD observation. */
}
static void deny_path(const char *path,unsigned i,int flags){errno=0;int fd=open(path,flags|O_CLOEXEC);int e=errno;
    if(fd>=0)close(fd);
    need(fd<0&&(e==EACCES||e==EPERM));denials[i]=e;
}
static void outside(void){
    need(context.parent_pid==1&&getppid()==1);reply(W_READY,3,0,0,-1);command(W_RUN_OUTSIDE);
    char path[256];const char *suffix[]={"","-wal","-shm","-journal"};
    for(unsigned i=0;i<4;i++){snprintf(path,sizeof(path),"%s%s",W_SOURCE,suffix[i]);deny_path(path,i,O_RDWR);}
    if(context.target_pid==1)snprintf(path,sizeof(path),"/proc/1/root%s",W_SOURCE);
    else snprintf(path,sizeof(path),"/proc/%d/root/probe/store/db.sqlite",context.target_pid);
    deny_path(path,4,O_RDWR);snprintf(path,sizeof(path),"/proc/%d/fd/%d",context.target_pid,context.target_fd);deny_path(path,5,O_RDWR);
    snprintf(path,sizeof(path),"/proc/%d/ns/mnt",context.target_pid);deny_path(path,6,O_RDONLY);
    errno=0;need(unshare(CLONE_NEWNS)==-1&&errno==EPERM);denials[7]=errno;reply(W_DONE,255,-1,denials[0],-1);
}
int main(int argc,char **argv){
    if(argc==2&&!strcmp(argv[1],"--self-test"))return getuid()!=0&&hash_self_test()?0:3;
    if(argc!=2||strcmp(argv[1],"--guest-only")||getuid()!=1000||geteuid()!=1000||getppid()<1)return 3;
    int death_signal=-1;if(prctl(PR_SET_DUMPABLE,0,0,0,0)||!owner_sealed()||prctl(PR_GET_PDEATHSIG,&death_signal)||death_signal)return 4;
    need(!bounded_read(0,&context,sizeof(context))&&context.magic==W_MAGIC&&(context.mode==W_BROKER||context.mode==W_OUTSIDE)&&
      context.self_pid==getpid()&&context.self_birth>0&&context.parent_pid==getppid()&&context.bytes>=4096&&context.bytes<=ORIGIN_FILE_CAP&&
      memchr(context.nonce,0,33)&&hex_text(context.nonce,32)&&memchr(context.boot,0,37)&&w_uuid(context.boot)&&
      memchr(context.hash,0,65)&&hex_text(context.hash,64));
    for(int fd=3;fd<=257;fd++){errno=0;need(fcntl(fd,F_GETFD)==-1&&errno==EBADF);}
    if(context.mode==W_BROKER)broker();else outside();return 0;
}
