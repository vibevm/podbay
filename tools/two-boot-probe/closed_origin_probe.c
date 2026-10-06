#define _GNU_SOURCE
/* Fixed guest child. Root PID1 chooses every mode and supplies one private pipe. */
#include "closed_origin_shared.h"
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>

#if !defined(__x86_64__)
#error The guest syscall policy is x86_64 only.
#endif

#define ALLOW(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(n),0,1), BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
static int seal_filter(void) {
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
        ALLOW(SYS_clock_gettime),ALLOW(SYS_getpid),ALLOW(SYS_getuid),ALLOW(SYS_geteuid),
        ALLOW(SYS_brk),ALLOW(SYS_mmap),ALLOW(SYS_munmap),ALLOW(SYS_mprotect),
        ALLOW(SYS_rt_sigreturn),ALLOW(SYS_exit),ALLOW(SYS_exit_group),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM)
    };
    struct sock_fprog p={.len=(unsigned short)(sizeof(rules)/sizeof(rules[0])),.filter=rules};
    return (int)syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,&p);
}
static struct probe_context context;
static int denial_results[5];
static void reply(unsigned phase,unsigned flags,int rc,int error,int fd) {
    struct probe_message m={.magic=ORIGIN_MAGIC,.phase=phase,.flags=flags,.pid=getpid(),
        .rc=rc,.error=error,.data_fd=fd,.device=context.device,.inode=context.inode};
    memcpy(m.nonce,context.nonce,sizeof(m.nonce));
    memcpy(m.denied_errno,denial_results,sizeof(m.denied_errno));
    if(full_write(1,&m,sizeof(m)))_exit(110);
}
static void need(int ok) { if(!ok){reply(0,0,-1,errno,-1);_exit(111);} }
static void command(char wanted) { char c=0;need(!bounded_read(0,&c,1)&&c==wanted); }
static int denied_path(const char *path,int flags,unsigned index) {
    errno=0;int fd=open(path,flags|O_CLOEXEC);int e=errno;
    if(fd>=0)close(fd);
    denial_results[index]=e;
    return fd<0&&(e==EACCES||e==EPERM);
}
static int exact_fd(int fd) {
    struct stat s;
    return !fstat(fd,&s)&&S_ISREG(s.st_mode)&&s.st_uid==1000&&s.st_gid==1000&&
        (s.st_mode&07777)==0600&&s.st_nlink==1&&(uint64_t)s.st_dev==context.device&&
        (uint64_t)s.st_ino==context.inode&&(uint64_t)s.st_size==context.bytes;
}
static void read_write_same_bytes(int fd) {
    unsigned char bytes[100];
    need(exact_fd(fd));
    need(pread(fd,bytes,sizeof(bytes),0)==sizeof(bytes));
    need(!memcmp(bytes,"SQLite format 3\0",16)&&bytes[60]==0&&bytes[61]==0&&bytes[62]==0&&bytes[63]==24);
    need(pwrite(fd,bytes,sizeof(bytes),0)==sizeof(bytes)&&!fsync(fd));
    char hash[65];need(!hash_fd(fd,hash)&&!strcmp(hash,context.source_hash));
}
static void forbidden(long result) { need(result==-1&&errno==EPERM); }
static void clean(void) {
    for(int fd=3;fd<=257;fd++){errno=0;need(fcntl(fd,F_GETFD)==-1&&errno==EBADF);}
    need(!seal_filter());
    /* These are actual kernel calls; no missing path/FD is mistaken for denial. */
    errno=0;forbidden(syscall(SYS_socket,AF_UNIX,SOCK_STREAM,0));
    errno=0;forbidden(syscall(SYS_sendmsg,-1,NULL,0));
    errno=0;forbidden(syscall(SYS_recvmsg,-1,NULL,0));
    errno=0;forbidden(syscall(SYS_unshare,CLONE_NEWNS));
    errno=0;forbidden(syscall(SYS_setns,-1,CLONE_NEWNS));
    errno=0;forbidden(syscall(SYS_ptrace,PTRACE_TRACEME,0,0,0));
    errno=0;forbidden(syscall(SYS_pidfd_getfd,-1,0,0));
    errno=0;forbidden(syscall(SYS_prctl,PR_SET_DUMPABLE,1,0,0,0));
    errno=0;long child=syscall(SYS_fork);if(!child)_exit(112);forbidden(child);
    char *const a[]={"/absent",NULL};char *const e[]={NULL};
    errno=0;forbidden(syscall(SYS_execve,"/absent",a,e));
    reply(PROBE_READY,7,0,0,-1);
    command('G');
    int fd=open("/probe/store/db.sqlite",O_RDWR|O_NOFOLLOW|O_CLOEXEC);need(fd>=0);
    read_write_same_bytes(fd);
    reply(PROBE_OPENED,15,100,0,fd);
    /* PID1 deliberately kills this process with its exact pidfd while the FD is open. */
    command('S');close(fd);reply(PROBE_DONE,1,0,0,-1);
}
static void outside(void) {
    for(int fd=3;fd<=257;fd++){errno=0;need(fcntl(fd,F_GETFD)==-1&&errno==EBADF);}
    reply(PROBE_READY,3,0,0,-1);command('G');
    need(denied_path(context.source_path,O_RDWR,0));
    char path[256];
    snprintf(path,sizeof(path),"/proc/%d/root/probe/store/db.sqlite",context.observed_pid);
    /* PID1 has a different root; its root alias uses the actual vault pathname. */
    if(context.observed_pid==1)snprintf(path,sizeof(path),"/proc/1/root%s",context.source_path);
    need(denied_path(path,O_RDWR,1));
    snprintf(path,sizeof(path),"/proc/%d/fd/%d",context.observed_pid,context.observed_fd);
    need(denied_path(path,O_RDWR,2));
    snprintf(path,sizeof(path),"/proc/%d/ns/mnt",context.observed_pid);
    need(denied_path(path,O_RDONLY,3));
    errno=0;need(unshare(CLONE_NEWNS)==-1&&errno==EPERM);denial_results[4]=errno;
    reply(PROBE_DONE,31,-1,denial_results[0],-1);
}
static int receive_right(void) {
    char byte=0,control[CMSG_SPACE(sizeof(int))];struct iovec iov={.iov_base=&byte,.iov_len=1};
    struct msghdr m={.msg_iov=&iov,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof(control)};
    need(recvmsg(3,&m,MSG_CMSG_CLOEXEC)==1&&byte=='F'&&!(m.msg_flags&(MSG_TRUNC|MSG_CTRUNC)));
    struct cmsghdr *c=CMSG_FIRSTHDR(&m);
    need(c&&c->cmsg_level==SOL_SOCKET&&c->cmsg_type==SCM_RIGHTS&&c->cmsg_len==CMSG_LEN(sizeof(int))&&!CMSG_NXTHDR(&m,c));
    int fd;memcpy(&fd,CMSG_DATA(c),sizeof(fd));close(3);return fd;
}
static void dirty(void) {
    for(int fd=4;fd<=257;fd++){errno=0;need(fcntl(fd,F_GETFD)==-1&&errno==EBADF);}
    need(fcntl(3,F_GETFD)>=0);
    unsigned char *mapping=MAP_FAILED;
    if(context.mode==PROBE_MMAP){need(exact_fd(3));mapping=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED,3,0);need(mapping!=MAP_FAILED);need(!close(3));}
    reply(PROBE_READY,3,0,0,context.mode==PROBE_MMAP?-1:3);
    command('G');
    need(denied_path(context.source_path,O_RDWR,0));
    int fd=3;
    if(context.mode==PROBE_DIRFD)fd=openat(3,"db.sqlite",O_RDWR|O_NOFOLLOW|O_CLOEXEC);
    if(context.mode==PROBE_SCM)fd=receive_right();
    if(context.mode==PROBE_MMAP){
        need(!memcmp(mapping,"SQLite format 3\0",16)&&mapping[63]==24);
        volatile unsigned char *v=mapping;unsigned char first=v[0];v[0]=first;
        need(!msync(mapping,4096,MS_SYNC));
    }else{need(fd>=0);read_write_same_bytes(fd);}
    reply(PROBE_OPENED,15,context.mode==PROBE_MMAP?0:100,0,context.mode==PROBE_MMAP?-1:fd);
    command('S');
    if(context.mode==PROBE_MMAP)need(!munmap(mapping,4096));
    else {need(!close(fd));if(context.mode==PROBE_DIRFD)need(!close(3));}
    reply(PROBE_DONE,1,0,0,-1);
}
int main(int argc,char **argv) {
    if(argc==2&&!strcmp(argv[1],"--self-test"))return getuid()!=0&&hash_self_test()?0:3;
    if(argc!=1||getppid()!=1||getuid()!=1000||geteuid()!=1000)return 3;
    if(prctl(PR_SET_DUMPABLE,0,0,0,0)||!owner_sealed())return 4;
    need(!bounded_read(0,&context,sizeof(context)));
    need(context.magic==ORIGIN_MAGIC&&context.mode>=PROBE_CLEAN&&context.mode<=PROBE_SCM&&
         memchr(context.nonce,0,sizeof(context.nonce))&&hex_text(context.nonce,32)&&
         memchr(context.source_hash,0,sizeof(context.source_hash))&&hex_text(context.source_hash,64)&&
         memchr(context.source_path,0,sizeof(context.source_path))&&context.bytes>=4096&&context.bytes<=ORIGIN_FILE_CAP);
    if(context.mode==PROBE_CLEAN)clean();else if(context.mode==PROBE_OUTSIDE)outside();else dirty();
    return 0;
}
