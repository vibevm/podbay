#define _GNU_SOURCE
/* Guest-only PID1. Fixed diagnostics; never a production origin constructor. */
#include "closed_origin_shared.h"
#include <sched.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/wait.h>

static char nonce[33],boot_id[37],source_hash[65],init_hash[65],probe_hash[65],policy_hash[65],lineage[33];
static const char *case_name="none";
static unsigned sequence,late;
static struct stat original;
static uint64_t pid1_birth;
struct child { pid_t pid;int pidfd,control,status,live;uint64_t birth; };
static struct child children[3];
static int seed_fd=-1;

static uint64_t birth_of(pid_t pid) {
    char path[64],text[4096];snprintf(path,sizeof(path),"/proc/%ld/stat",(long)pid);
    int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return 0;
    ssize_t n=read(fd,text,sizeof(text)-1);close(fd);if(n<=0)return 0;text[n]=0;
    char *p=strrchr(text,')');if(!p)return 0;p+=2;
    for(int i=3;i<22;i++){p=strchr(p,' ');if(!p)return 0;p++;}
    char *end;unsigned long long b=strtoull(p,&end,10);return end!=p&&*end==' '?b:0;
}
static void event(const char *name,pid_t pid,uint64_t birth,int rc,int error) {
    printf("{\"schema\":1,\"event\":\"%s\",\"nonce\":\"%s\",\"boot_id\":\"%s\",\"sequence\":%u,\"case\":\"%s\",\"gate\":\"CLOSED\",\"admission\":\"UNIMPLEMENTED\",\"policy_sha256\":\"%s\",\"pid1_sha256\":\"%s\",\"probe_sha256\":\"%s\",\"lineage\":\"%s\",\"db_sha256\":\"%s\",\"db_device\":%llu,\"db_inode\":%llu,\"db_uid\":%u,\"pid\":%ld,\"birth_ticks\":%llu,\"rc\":%d,\"errno\":%d,\"late\":%s}\n",
      name,nonce,boot_id,++sequence,case_name,policy_hash,init_hash,probe_hash,lineage,source_hash,
      (unsigned long long)original.st_dev,(unsigned long long)original.st_ino,(unsigned)original.st_uid,
      (long)pid,(unsigned long long)birth,rc,error,late?"true":"false");
    fflush(stdout);
}
static _Noreturn void halt_guest(void) { sync();reboot(RB_POWER_OFF);for(;;)pause(); }
static void abort_children(void) {
    for(size_t i=0;i<3;i++)if(children[i].live){
        struct child *c=&children[i];
        if(c->pidfd>=0)syscall(SYS_pidfd_send_signal,c->pidfd,SIGKILL,NULL,0);
        else kill(c->pid,SIGKILL); /* Only our retained, unreaped child. */
        struct pollfd p={.fd=c->pidfd,.events=POLLIN};
        if(c->pidfd>=0&&poll(&p,1,ORIGIN_TIMEOUT_MS)>0){int status;while(waitpid(c->pid,&status,0)<0&&errno==EINTR){}c->live=0;}
    }
}
static _Noreturn void fail(const char *why) {
    int e=errno;abort_children();event(why,1,pid1_birth,-1,e);halt_guest();
}
static void need(int ok,const char *why) { if(!ok)fail(why); }
static int read_file(const char *path,char *out,size_t cap) {
    int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);if(fd<0)return -1;
    ssize_t n=read(fd,out,cap-1);char extra;int end=n>=0&&read(fd,&extra,1)==0;close(fd);
    if(!end)return -1;
    out[n]=0;return (int)n;
}
static void absent(int dir,const char *name) {
    struct stat s;need(fstatat(dir,name,&s,AT_SYMLINK_NOFOLLOW)==-1&&errno==ENOENT,"failed_absence");
}
static int directory_at(int parent,const char *name,uid_t uid) {
    need(!mkdirat(parent,name,0700),"failed_exclusive_directory");
    int fd=openat(parent,name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);need(fd>=0,"failed_directory_open");
    need(!fchown(fd,uid,uid)&&!fchmod(fd,0700)&&!fsync(fd)&&!fsync(parent),"failed_directory_identity");
    return fd;
}
static void record(int vault,const char *name) {
    char bytes[768];int n=snprintf(bytes,sizeof(bytes),
      "PODBAY-GUEST-CLOSED-ORIGIN/1\ncase=%s\nnonce=%s\nboot=%s\nstate=%s\nsource_device=%llu\nsource_inode=%llu\nsource_uid=1000\nsource_sha256=%s\nlineage=%s\npolicy=%s\nadmission=UNIMPLEMENTED\nstage=ABSENT\n",
      case_name,nonce,boot_id,late?"LATE_ENGAGEMENT":"CLOSED_SOURCE24",(unsigned long long)original.st_dev,
      (unsigned long long)original.st_ino,source_hash,lineage,policy_hash);
    need(n>0&&(size_t)n<sizeof(bytes),"failed_record_bound");
    int fd=openat(vault,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    need(fd>=0&&!full_write(fd,bytes,(size_t)n)&&!fsync(fd)&&!close(fd)&&!fsync(vault),"failed_record_durability");
}
static void request_origin(int vault,int repeated) {
    if(late){
        if(!repeated)record(vault,"late.record");
        else {struct stat s;need(!fstatat(vault,"late.record",&s,AT_SYMLINK_NOFOLLOW)&&S_ISREG(s.st_mode)&&s.st_uid==0&&(s.st_mode&07777)==0600&&s.st_nlink==1,"failed_late_retention");}
        absent(vault,"origin.record");event(repeated?"late_refusal_after_reap":"late_refusal",1,pid1_birth,-1,0);
    }else{need(!repeated,"failed_origin_order");record(vault,"origin.record");event("origin_acquired",1,pid1_birth,0,0);}
}
static void child_exec(int control,int status,int retained,int clean,const char *state_path) {
    if(dup2(control,0)<0||dup2(status,1)<0||dup2(status,2)<0)_exit(120);
    if(clean){
        if(unshare(CLONE_NEWNS)||mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)||
           mount("tmpfs","/run/sealed","tmpfs",MS_NOSUID|MS_NODEV,"size=8m,mode=0755")||
           mkdir("/run/sealed/probe",0755)||chmod("/run/sealed/probe",0755)||
           mkdir("/run/sealed/probe/store",0700))_exit(121);
        int target=open("/run/sealed/probe/run",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0755);
        if(target<0)_exit(121);
        close(target);
        if(mount(state_path,"/run/sealed/probe/store",NULL,MS_BIND,NULL)||
           mount("/bin/origin-probe","/run/sealed/probe/run",NULL,MS_BIND,NULL)||
           mount(NULL,"/run/sealed/probe/run",NULL,MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV,NULL)||
           chdir("/run/sealed")||chroot(".")||chdir("/"))_exit(121);
    }else if(chdir("/"))_exit(121);
    if(retained>=0){if(dup2(retained,3)<0||syscall(SYS_close_range,4u,UINT_MAX,0))_exit(122);}
    else if(syscall(SYS_close_range,3u,UINT_MAX,0))_exit(122);
    if(drop_owner())_exit(123);
    char *args[]={clean?"/probe/run":"/bin/origin-probe",NULL};char *env[]={"LC_ALL=C",NULL};
    execve(args[0],args,env);_exit(124);
}
static struct child *spawn(struct probe_context *ctx,int retained,int clean,const char *state_path) {
    struct child *c=NULL;for(size_t i=0;i<3;i++)if(!children[i].live){c=&children[i];break;}
    need(c!=NULL,"failed_child_bound");
    int commands[2],messages[2];need(!pipe2(commands,O_CLOEXEC)&&!pipe2(messages,O_CLOEXEC),"failed_pipes");
    pid_t pid=fork();need(pid>=0,"failed_fork");
    if(!pid)child_exec(commands[0],messages[1],retained,clean,state_path);
    close(commands[0]);close(messages[1]);
    *c=(struct child){.pid=pid,.pidfd=-1,.control=commands[1],.status=messages[0],.live=1};
    c->pidfd=(int)syscall(SYS_pidfd_open,pid,0);c->birth=birth_of(pid);
    need(c->pidfd>=0&&c->birth>0,"failed_child_pin");
    need(!full_write(c->control,ctx,sizeof(*ctx)),"failed_child_context");
    return c;
}
static struct probe_message phase(struct child *c,unsigned expected,unsigned flags) {
    struct probe_message m;
    need(!bounded_read(c->status,&m,sizeof(m)),"failed_child_deadline");
    need(m.magic==ORIGIN_MAGIC&&m.phase==expected&&m.flags==flags&&m.pid==c->pid&&
         !memcmp(m.nonce,nonce,sizeof(m.nonce))&&m.device==(uint64_t)original.st_dev&&
         m.inode==(uint64_t)original.st_ino&&birth_of(c->pid)==c->birth,"failed_child_protocol");
    return m;
}
static void command(struct child *c,char b) { need(!full_write(c->control,&b,1),"failed_child_command"); }
static void reap(struct child *c,int killed) {
    if(killed)need(!syscall(SYS_pidfd_send_signal,c->pidfd,SIGKILL,NULL,0),"failed_exact_kill");
    struct pollfd p={.fd=c->pidfd,.events=POLLIN};int ready;
    do{ready=poll(&p,1,ORIGIN_TIMEOUT_MS);}while(ready<0&&errno==EINTR);
    need(ready==1&&(p.revents&POLLIN),"failed_exact_exit_deadline");
    int status;pid_t got;do{got=waitpid(c->pid,&status,0);}while(got<0&&errno==EINTR);
    need(got==c->pid&&(killed?(WIFSIGNALED(status)&&WTERMSIG(status)==SIGKILL):(WIFEXITED(status)&&WEXITSTATUS(status)==0)),"failed_child_exit");
    c->live=0;event(killed?"broker_killed_reaped":"child_reaped",c->pid,c->birth,killed?-SIGKILL:0,0);
    close(c->control);close(c->status);close(c->pidfd);
}
static void check_store(int state,int db) {
    struct stat s,p;char hash[65];unsigned char header[100];
    need(!fstat(db,&s)&&!fstatat(state,"db.sqlite",&p,AT_SYMLINK_NOFOLLOW)&&same_inode(&s,&original)&&same_inode(&p,&original)&&
         S_ISREG(s.st_mode)&&s.st_uid==1000&&s.st_gid==1000&&(s.st_mode&07777)==0600&&s.st_nlink==1,
         "failed_store_identity");
    need(!hash_fd(db,hash)&&!strcmp(hash,source_hash)&&pread(db,header,100,0)==100&&!memcmp(header,"SQLite format 3\0",16)&&
         header[60]==0&&header[61]==0&&header[62]==0&&header[63]==24,"failed_source24_bytes");
    absent(state,"stage.sqlite");absent(state,"db.sqlite-wal");absent(state,"db.sqlite-shm");absent(state,"db.sqlite-journal");
}
static void outside(struct probe_context ctx,pid_t target,int target_fd,int after_death) {
    ctx.mode=PROBE_OUTSIDE;ctx.observed_pid=target;ctx.observed_fd=target_fd;
    struct child *c=spawn(&ctx,-1,0,NULL);phase(c,PROBE_READY,3);command(c,'G');
    struct probe_message m=phase(c,PROBE_DONE,31);
    const char *names[]={"raw_path","proc_root","proc_fd","namespace_handle","unshare"};
    for(unsigned i=0;i<5;i++){
        need(m.denied_errno[i]==EPERM||(i<4&&m.denied_errno[i]==EACCES),"failed_denial_errno");
        char name[80];snprintf(name,sizeof(name),"outside_%s_denied_%s",names[i],after_death?"after_death":"before_death");
        event(name,c->pid,c->birth,-1,m.denied_errno[i]);
    }
    reap(c,0);
}
static void send_right(int socket,int fd) {
    char byte='F',control[CMSG_SPACE(sizeof(int))];memset(control,0,sizeof(control));
    struct iovec iov={.iov_base=&byte,.iov_len=1};struct msghdr m={.msg_iov=&iov,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof(control)};
    struct cmsghdr *c=CMSG_FIRSTHDR(&m);c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;c->cmsg_len=CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c),&fd,sizeof(fd));need(sendmsg(socket,&m,0)==1,"failed_queue_rights");
}
static void run_case(int fixture,const char *name,unsigned mode) {
    case_name=name;late=0;
    int casefd=directory_at(fixture,name,0),vault=directory_at(casefd,"vault",0),state=directory_at(vault,"state",1000);
    int lock=openat(state,"db.sqlite.manager.lock",O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    need(lock>=0&&!fchown(lock,1000,1000)&&!flock(lock,LOCK_EX|LOCK_NB),"failed_manager_lock");
    int db=openat(state,"db.sqlite",O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);need(db>=0,"failed_source_create");
    unsigned char data[8192];off_t at=0;
    for(;;){ssize_t n=pread(seed_fd,data,sizeof(data),at);need(n>=0,"failed_seed_read");if(!n)break;
        need(!full_write(db,data,(size_t)n),"failed_source_write");at+=n;}
    need(!fchown(db,1000,1000)&&!fchmod(db,0600)&&!fsync(db)&&!fsync(lock)&&!fsync(state)&&!fstat(db,&original),"failed_source_sync");
    check_store(state,db);event("source24_pinned",1,pid1_birth,24,0);
    char state_path[128];snprintf(state_path,sizeof(state_path),"/fixture/%s/vault/state",name);
    struct probe_context ctx={.magic=ORIGIN_MAGIC,.mode=mode,.device=original.st_dev,.inode=original.st_ino,.bytes=original.st_size};
    memcpy(ctx.nonce,nonce,sizeof(ctx.nonce));memcpy(ctx.source_hash,source_hash,sizeof(ctx.source_hash));
    snprintf(ctx.source_path,sizeof(ctx.source_path),"/fixture/%s/vault/state/db.sqlite",name);
    if(mode==PROBE_CLEAN){
        request_origin(vault,0);
        /* Deliberate high inherited data descriptor: child close_range must remove it. */
        need(dup2(db,257)==257,"failed_high_fd_control");
        struct child *broker=spawn(&ctx,-1,1,state_path);close(257);
        phase(broker,PROBE_READY,7);event("clean_exec_sealed",broker->pid,broker->birth,0,0);command(broker,'G');
        struct probe_message opened=phase(broker,PROBE_OPENED,15);need(opened.data_fd>=3,"failed_broker_fd");
        event("sealed_source_opened",broker->pid,broker->birth,opened.rc,opened.error);
        outside(ctx,broker->pid,opened.data_fd,0);
        reap(broker,1);
        outside(ctx,1,db,1);
        int competitor=openat(state,"db.sqlite.manager.lock",O_RDWR|O_NOFOLLOW|O_CLOEXEC);need(competitor>=0,"failed_competing_lock_open");
        errno=0;need(flock(competitor,LOCK_EX|LOCK_NB)==-1&&(errno==EWOULDBLOCK||errno==EAGAIN),"failed_retained_manager_lock");close(competitor);
        event("pid1_closed_retained",1,pid1_birth,0,0);
    }else{
        int retained=mode==PROBE_DIRFD?state:db,rights[2]={-1,-1};
        if(mode==PROBE_SCM){need(!socketpair(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0,rights),"failed_rights_socket");send_right(rights[0],db);retained=rights[1];}
        struct child *c=spawn(&ctx,retained,0,NULL);late=1;event("issuer_started_before_origin",c->pid,c->birth,0,0);
        if(rights[0]>=0){close(rights[0]);close(rights[1]);}
        phase(c,PROBE_READY,3);event("old_capability_ready",c->pid,c->birth,0,0);command(c,'G');
        struct probe_message lived=phase(c,PROBE_OPENED,15);
        need(lived.denied_errno[0]==EPERM||lived.denied_errno[0]==EACCES,"failed_dirty_denial_errno");
        event("dirty_new_path_denied",c->pid,c->birth,-1,lived.denied_errno[0]);
        event("old_capability_access_proved",c->pid,c->birth,lived.rc,lived.error);
        request_origin(vault,0);command(c,'S');phase(c,PROBE_DONE,1);reap(c,0);request_origin(vault,1);
    }
    check_store(state,db);event("source24_preserved_stage_absent",1,pid1_birth,24,0);
    close(db);close(lock);close(state);need(!fsync(vault)&&!fsync(casefd),"failed_case_sync");close(vault);close(casefd);
}
int main(int argc,char **argv) {
    if(argc==2&&!strcmp(argv[1],"--self-test"))return getuid()!=0&&hash_self_test()?0:3;
    if(argc!=1||getpid()!=1||getuid()!=0||geteuid()!=0)return 3;
    setvbuf(stdout,NULL,_IONBF,0);umask(077);signal(SIGPIPE,SIG_IGN);
    need(!prctl(PR_SET_DUMPABLE,0,0,0,0),"failed_pid1_dumpable");
    need(!mount("proc","/proc","proc",MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL)&&
         !mount("sysfs","/sys","sysfs",MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL)&&
         !mount("devtmpfs","/dev","devtmpfs",MS_NOSUID,NULL),"failed_virtual_mounts");
    char config[512],boot[64];need(read_file("/etc/origin.config",config,sizeof(config))>0,"failed_config");
    char *save=NULL,*fields[6];for(int i=0;i<6;i++){fields[i]=strtok_r(i?NULL:config,"\n",&save);need(fields[i]!=NULL,"failed_config_fields");}
    need(!strtok_r(NULL,"\n",&save)&&hex_text(fields[0],32)&&hex_text(fields[1],64)&&hex_text(fields[2],64)&&hex_text(fields[3],64)&&hex_text(fields[4],64)&&hex_text(fields[5],32),"failed_config_shape");
    strcpy(nonce,fields[0]);strcpy(source_hash,fields[1]);strcpy(init_hash,fields[2]);strcpy(probe_hash,fields[3]);strcpy(policy_hash,fields[4]);strcpy(lineage,fields[5]);
    need(read_file("/proc/sys/kernel/random/boot_id",boot,sizeof(boot))==37&&boot[36]=='\n',"failed_boot_id");boot[36]=0;strcpy(boot_id,boot);
    struct sha256_state hash;char actual[65];sha_init(&hash);sha_update(&hash,ORIGIN_POLICY,strlen(ORIGIN_POLICY));sha_finish(&hash,actual);need(!strcmp(actual,policy_hash),"failed_policy_pin");
    int executable=open("/init",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);need(executable>=0&&!hash_fd(executable,actual)&&!strcmp(actual,init_hash),"failed_pid1_artifact");close(executable);
    executable=open("/bin/origin-probe",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);need(executable>=0&&!hash_fd(executable,actual)&&!strcmp(actual,probe_hash),"failed_probe_artifact");close(executable);
    seed_fd=open("/etc/source24.sqlite",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);need(seed_fd>=0&&!hash_fd(seed_fd,actual)&&!strcmp(actual,source_hash),"failed_seed_hash");
    pid1_birth=birth_of(1);need(pid1_birth>0,"failed_pid1_birth");event("pid1_first_closed",1,pid1_birth,0,0);
    need(!mount("/dev/vda","/fixture","ext4",MS_NODEV|MS_NOSUID|MS_NOEXEC,NULL),"failed_fixture_mount");
    int fixture=open("/fixture",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);need(fixture>=0,"failed_fixture_open");
    run_case(fixture,"clean",PROBE_CLEAN);run_case(fixture,"fd",PROBE_FD);run_case(fixture,"dirfd",PROBE_DIRFD);
    run_case(fixture,"mmap",PROBE_MMAP);run_case(fixture,"scm",PROBE_SCM);
    errno=0;need(waitpid(-1,NULL,WNOHANG)==-1&&errno==ECHILD,"failed_remaining_child");
    need(!fsync(fixture),"failed_disk_sync");close(fixture);close(seed_fd);need(!umount("/fixture"),"failed_unmount");
    event("all_cases_verified_no_admission",1,pid1_birth,0,0);halt_guest();
}
