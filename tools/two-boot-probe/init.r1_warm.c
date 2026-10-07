#define _GNU_SOURCE
/* Fixed guest PID1 observer. Custodian loss never constructs a replacement. */
#include "r1_warm_shared.h"
#include <sched.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/wait.h>

struct child { pid_t pid; int pidfd,control,status,live; uint64_t birth; struct w_context context; unsigned sent,received; };
static struct child custodian,broker,observer;
static struct w_config config;
static struct stat root_stat,vault_stat,state_stat,source_stat,lock_stat;
static int root_fd=-1,vault_fd=-1,state_fd=-1,source_fd=-1,broker_data_fd=-1;
static char current_boot[37];
static uint64_t pid1_birth;
static unsigned event_sequence,closed_established,source_pinned,custodian_started,custodian_lost,broker_dead,broker_sequence,lifecycle_failed;
static void cleanup(void);
static _Noreturn void halt_guest(void){sync();reboot(RB_POWER_OFF);for(;;)pause();}
static uint64_t process_stat(pid_t pid,pid_t *parent){
    char path[64],text[4096];snprintf(path,sizeof(path),"/proc/%ld/stat",(long)pid);
    int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return 0;
    ssize_t n=read(fd,text,sizeof(text)-1);close(fd);if(n<=0)return 0;text[n]=0;
    char *p=strrchr(text,')');if(!p)return 0;p+=2;
    for(int field=3;field<22;field++){
        if(field==4&&parent){char *end;long value=strtol(p,&end,10);if(end==p||*end!=' '||value<0||value>INT_MAX)return 0;*parent=(pid_t)value;}
        p=strchr(p,' ');if(!p)return 0;p++;
    }
    char *end;unsigned long long value=strtoull(p,&end,10);return end!=p&&*end==' '?value:0;
}
static void event(const char *name,pid_t pid,uint64_t birth,int parent,int rc,int error){
    char line[W_EVENT_CAP];
    int n=snprintf(line,sizeof(line),"{\"schema\":1,\"event\":\"%s\",\"sequence\":%u,\"nonce\":\"%s\",\"fixture_uuid\":\"%s\",\"boot_id\":\"%s\",\"gate\":\"%s\",\"admission\":\"UNIMPLEMENTED\",\"warm_adoption\":\"UNAVAILABLE\",\"origin_restored\":false,\"source_pinned\":%s,\"source_device\":%llu,\"source_inode\":%llu,\"source_uid\":%u,\"source_bytes\":%llu,\"expected_source_sha256\":\"%s\",\"source_sha256\":\"%s\",\"lineage\":\"%s\",\"policy_sha256\":\"%s\",\"pid1_sha256\":\"%s\",\"probe_sha256\":\"%s\",\"lock_inode\":%llu,\"custodian_pid\":%ld,\"custodian_birth\":%llu,\"custodian_state\":\"%s\",\"broker_pid\":%ld,\"broker_birth\":%llu,\"broker_state\":\"%s\",\"broker_fd\":%d,\"broker_sequence\":%u,\"actor_pid\":%ld,\"actor_birth\":%llu,\"actor_parent\":%d,\"rc\":%d,\"errno\":%d}\n",
      name,++event_sequence,config.nonce,config.fixture,current_boot,closed_established?"CLOSED":"PRE_CLOSURE",
      source_pinned?"true":"false",source_pinned?(unsigned long long)source_stat.st_dev:0,source_pinned?(unsigned long long)source_stat.st_ino:0,
      source_pinned?(unsigned)source_stat.st_uid:0,source_pinned?(unsigned long long)source_stat.st_size:0,
      config.source_hash,source_pinned?config.source_hash:"",config.lineage,config.policy_hash,config.init_hash,config.probe_hash,
      source_pinned?(unsigned long long)lock_stat.st_ino:0,(long)custodian.pid,(unsigned long long)custodian.birth,
      custodian_lost?"LOST":custodian.pid?(lifecycle_failed?"UNKNOWN":"LIVE"):"NOT_STARTED",(long)broker.pid,(unsigned long long)broker.birth,
      broker_dead?"DEAD":broker.pid?(lifecycle_failed?"UNKNOWN":"LIVE"):"NOT_STARTED",broker_data_fd,broker_sequence,(long)pid,(unsigned long long)birth,parent,rc,error);
    if(n<=0||(size_t)n>=sizeof(line)){cleanup();halt_guest();}
    ssize_t written;do{written=write(1,line,(size_t)n);}while(written<0&&errno==EINTR);
    if(written!=n){cleanup();halt_guest();}
}
static void cleanup(void){
    lifecycle_failed=1;
    struct child *all[]={&custodian,&broker,&observer};
    for(unsigned i=0;i<3;i++){struct child *c=all[i];if(!c->live)continue;
        if(c->pidfd>=0)syscall(SYS_pidfd_send_signal,c->pidfd,SIGKILL,NULL,0);else kill(c->pid,SIGKILL);
        struct pollfd p={.fd=c->pidfd,.events=POLLIN};
        if(c->pidfd>=0&&poll(&p,1,ORIGIN_TIMEOUT_MS)>0){int status;pid_t got;do{got=waitpid(c->pid,&status,0);}while(got<0&&errno==EINTR);
            if(got==c->pid){c->live=0;if(c==&custodian)custodian_lost=1;if(c==&broker)broker_dead=1;}}
    }
}
static _Noreturn void fail(const char *why){int error=errno;cleanup();event(why,1,pid1_birth,0,-1,error);halt_guest();}
static void need(int ok,const char *why){if(!ok)fail(why);}
static int read_text(const char *path,char *text,size_t cap){
    int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);if(fd<0)return -1;
    ssize_t n=read(fd,text,cap-1);char extra;int end=n>=0&&read(fd,&extra,1)==0;close(fd);
    if(!end)return -1;
    text[n]=0;return (int)n;
}
static void absent(int fd,const char *name){struct stat s;need(fstatat(fd,name,&s,AT_SYMLINK_NOFOLLOW)<0&&errno==ENOENT,"failed_existing_companion");}
static int directory(int parent,const char *name,uid_t uid){
    need(!mkdirat(parent,name,0700),"failed_existing_directory");int fd=openat(parent,name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    need(fd>=0&&!fchown(fd,uid,uid)&&!fchmod(fd,0700)&&!fsync(fd)&&!fsync(parent),"failed_directory_setup");return fd;
}
static int private_file(int fd,int parent,const char *name,struct stat *out){struct stat named;
    return !fstat(fd,out)&&!fstatat(parent,name,&named,AT_SYMLINK_NOFOLLOW)&&same_inode(out,&named)&&S_ISREG(out->st_mode)&&
      out->st_uid==1000&&out->st_gid==1000&&(out->st_mode&07777)==0600&&out->st_nlink==1;
}
static void verify_closed(void){
    struct stat now;int fds[]={root_fd,vault_fd,state_fd};struct stat *pins[]={&root_stat,&vault_stat,&state_stat};
    for(unsigned i=0;i<3;i++)need(!fstat(fds[i],&now)&&same_inode(&now,pins[i])&&S_ISDIR(now.st_mode)&&
      now.st_uid==(i==2?1000u:0u)&&now.st_gid==now.st_uid&&(now.st_mode&07777)==0700,"failed_closed_directory_identity");
    char hash[65];unsigned char h[100];need(private_file(source_fd,state_fd,"db.sqlite",&now)&&same_inode(&now,&source_stat)&&
      now.st_size==source_stat.st_size&&!hash_fd(source_fd,hash)&&!strcmp(hash,config.source_hash)&&
      pread(source_fd,h,sizeof(h),0)==100&&!memcmp(h,"SQLite format 3\0",16)&&h[60]==0&&h[61]==0&&h[62]==0&&h[63]==24,"failed_source24_identity");
    need(!fstatat(state_fd,"db.sqlite.manager.lock",&now,AT_SYMLINK_NOFOLLOW)&&same_inode(&now,&lock_stat)&&
      S_ISREG(now.st_mode)&&now.st_uid==1000&&now.st_gid==1000&&(now.st_mode&07777)==0600&&now.st_nlink==1,"failed_lock_identity");
    absent(state_fd,"stage.sqlite");absent(state_fd,"db.sqlite-wal");absent(state_fd,"db.sqlite-shm");absent(state_fd,"db.sqlite-journal");
}
static void alive(struct child *c,int parent){struct pollfd p={.fd=c->pidfd,.events=POLLIN};pid_t actual=-1;
    need(c->live&&poll(&p,1,0)==0&&process_stat(c->pid,&actual)==c->birth&&actual==parent,"failed_live_process_identity");}
static void pin_child(struct child *c,pid_t pid,int parent){
    c->pid=pid;c->live=1;c->pidfd=-1;c->pidfd=(int)syscall(SYS_pidfd_open,pid,0);pid_t actual=-1;c->birth=process_stat(pid,&actual);
    need(c->pidfd>=0&&c->birth&&actual==parent,"failed_child_pin");alive(c,parent);
}
static void exec_probe(int commands,int messages,int is_broker){
    if(dup2(commands,0)<0||dup2(messages,1)<0||dup2(messages,2)<0)_exit(120);
    if(is_broker){
        if(unshare(CLONE_NEWNS)||mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)||
          mount("tmpfs","/run/sealed","tmpfs",MS_NODEV|MS_NOSUID,"size=8m,mode=0755")||
          mkdir("/run/sealed/probe",0755)||chmod("/run/sealed/probe",0755)||mkdir("/run/sealed/probe/store",0700))_exit(121);
        int target=open("/run/sealed/probe/run",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0755);if(target<0)_exit(121);close(target);
        if(mount("/fixture/vault/state","/run/sealed/probe/store",NULL,MS_BIND,NULL)||
          mount("/bin/r1-warm-probe","/run/sealed/probe/run",NULL,MS_BIND,NULL)||
          mount(NULL,"/run/sealed/probe/run",NULL,MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV,NULL)||
          chdir("/run/sealed")||chroot(".")||chdir("/"))_exit(121);
    }else if(chdir("/"))_exit(121);
    if(syscall(SYS_close_range,3u,UINT_MAX,0)||prctl(PR_SET_PDEATHSIG,0)||drop_owner())_exit(122);
    char *args[]={is_broker?"/probe/run":"/bin/r1-warm-probe","--guest-only",NULL};char *env[]={"LC_ALL=C",NULL};execve(args[0],args,env);_exit(123);
}
static struct w_context context(struct child *c,unsigned mode,int parent){struct w_context x={.magic=W_MAGIC,.mode=mode,
    .self_pid=c->pid,.parent_pid=parent,.self_birth=c->birth,.device=source_stat.st_dev,.inode=source_stat.st_ino,.bytes=source_stat.st_size};
    memcpy(x.nonce,config.nonce,33);memcpy(x.boot,current_boot,37);memcpy(x.hash,config.source_hash,65);return x;
}
static void send_context(struct child *c){need(!full_write(c->control,&c->context,sizeof(c->context)),"failed_context_send");}
static void command(struct child *c,unsigned kind){struct w_command m={.magic=W_MAGIC,.sequence=++c->sent,.kind=kind,.target_pid=c->pid};
    memcpy(m.nonce,config.nonce,33);memcpy(m.boot,current_boot,37);need(!full_write(c->control,&m,sizeof(m)),"failed_command_send");}
static struct w_message phase(struct child *c,unsigned expected,unsigned flags,int parent,int rc){struct w_message m;
    need(!bounded_read(c->status,&m,sizeof(m))&&w_message_matches(&m,&c->context,++c->received,expected,flags,parent)&&m.rc==rc&&
      (expected==W_DONE?(m.error==EPERM||m.error==EACCES):m.error==0),"failed_protocol_response");
    if(expected==W_DONE){pid_t actual=-1;need(c->live&&process_stat(c->pid,&actual)==c->birth&&actual==parent,"failed_completed_probe_identity");}
    else alive(c,parent);
    if(c==&broker)broker_sequence=m.sequence;
    return m;
}
static void reap(struct child *c,int killed,const char *name,int parent){
    if(killed)need(!syscall(SYS_pidfd_send_signal,c->pidfd,SIGKILL,NULL,0),"failed_exact_kill");
    struct pollfd p={.fd=c->pidfd,.events=POLLIN};int ready;do{ready=poll(&p,1,ORIGIN_TIMEOUT_MS);}while(ready<0&&errno==EINTR);
    need(ready==1&&(p.revents&POLLIN),"failed_exit_deadline");int status;pid_t got;do{got=waitpid(c->pid,&status,0);}while(got<0&&errno==EINTR);
    need(got==c->pid&&(killed?(WIFSIGNALED(status)&&WTERMSIG(status)==SIGKILL):(WIFEXITED(status)&&WEXITSTATUS(status)==0)),"failed_exact_reap");
    c->live=0;if(c==&custodian)custodian_lost=1;if(c==&broker)broker_dead=1;
    event(name,c->pid,c->birth,parent,killed?-SIGKILL:0,0);close(c->pidfd);
    if(c->control>=0)close(c->control);
    if(c->status>=0)close(c->status);
}
static void outside(pid_t target,int fd,const char *point){
    int commands[2],messages[2];need(!pipe2(commands,O_CLOEXEC)&&!pipe2(messages,O_CLOEXEC),"failed_probe_pipes");
    pid_t pid=fork();need(pid>=0,"failed_probe_fork");if(!pid)exec_probe(commands[0],messages[1],0);
    close(commands[0]);close(messages[1]);observer=(struct child){.control=commands[1],.status=messages[0]};pin_child(&observer,pid,1);
    observer.context=context(&observer,W_OUTSIDE,1);observer.context.target_pid=target;observer.context.target_fd=fd;send_context(&observer);
    phase(&observer,W_READY,3,1,0);command(&observer,W_RUN_OUTSIDE);struct w_message m=phase(&observer,W_DONE,255,1,-1);
    const char *names[]={"source","wal","shm","journal","proc_root","proc_fd","namespace","unshare"};
    for(unsigned i=0;i<8;i++){need(m.denials[i]==EPERM||(i<7&&m.denials[i]==EACCES),"failed_outside_denial");char name[96];
      snprintf(name,sizeof(name),"outside_%s_%s",point,names[i]);event(name,observer.pid,observer.birth,1,-1,m.denials[i]);}
    reap(&observer,0,"outside_reaped",1);
}
static void keep_custodian_pipes(int commands,int messages,int notice){
    int originals[]={commands,messages,notice},copies[3];
    for(unsigned i=0;i<3;i++){copies[i]=fcntl(originals[i],F_DUPFD_CLOEXEC,512);if(copies[i]<0)_exit(124);}
    if(syscall(SYS_close_range,3u,511u,0))_exit(124);
    for(unsigned i=0;i<3;i++)if(dup2(copies[i],3+(int)i)<0)_exit(124);
    if(syscall(SYS_close_range,6u,UINT_MAX,0))_exit(124);
}
static _Noreturn void custodian_main(int commands,int messages,int notice){
    if(getppid()!=1||getuid()!=0||geteuid()!=0||prctl(PR_SET_DUMPABLE,0,0,0,0))_exit(125);
    keep_custodian_pipes(commands,messages,notice);
    /* This independently opened lock OFD belongs only to this process. The
       broker's close_range removes its inherited copy before owner exec. */
    int lock=open("/fixture/vault/state/db.sqlite.manager.lock",O_RDWR|O_NOFOLLOW|O_CLOEXEC);struct stat s;
    if(lock<0||fstat(lock,&s)||!same_inode(&s,&lock_stat)||s.st_uid!=1000||(s.st_mode&07777)!=0600||flock(lock,LOCK_EX|LOCK_NB))_exit(126);
    int data=open(W_SOURCE,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(data<0||fstat(data,&s)||!same_inode(&s,&source_stat)||dup2(data,257)!=257)_exit(126);
    close(data);pid_t child=fork();if(child<0)_exit(127);if(!child)exec_probe(3,4,1);
    close(3);close(4);close(257);
    pid_t actual=-1;struct w_notice n={.magic=W_MAGIC,.sequence=1,.custodian_pid=getpid(),.broker_pid=child,.uid=geteuid(),
      .custodian_birth=process_stat(getpid(),NULL),.broker_birth=process_stat(child,&actual),.device=lock_stat.st_dev,.lock_inode=lock_stat.st_ino};
    memcpy(n.nonce,config.nonce,33);memcpy(n.boot,current_boot,37);
    if(actual!=getpid()||!n.custodian_birth||!n.broker_birth||full_write(5,&n,sizeof(n)))_exit(128);
    close(5);close(0);close(1);close(2);
    for(;;)pause(); /* No fallback, replacement launch, release or adoption. */
}
static int begin_custodian(void){
    /* The actual launcher refuses before pipe/open/fork on every warm retry. */
    if(!w_can_launch(custodian_started,custodian_lost)){errno=EOWNERDEAD;return -1;}
    if(getpid()!=1||getuid()!=0||geteuid()!=0){errno=EPERM;return -1;}
    custodian_started=1;int commands[2],messages[2],notice[2];
    need(!pipe2(commands,O_CLOEXEC)&&!pipe2(messages,O_CLOEXEC)&&!pipe2(notice,O_CLOEXEC),"failed_custodian_pipes");
    pid_t pid=fork();need(pid>=0,"failed_custodian_fork");if(!pid)custodian_main(commands[0],messages[1],notice[1]);
    close(commands[0]);close(messages[1]);close(notice[1]);custodian=(struct child){.control=-1,.status=notice[0]};pin_child(&custodian,pid,1);
    struct w_notice n;need(!bounded_read(notice[0],&n,sizeof(n))&&n.magic==W_MAGIC&&n.sequence==1&&n.uid==0&&
      n.custodian_pid==pid&&n.custodian_birth==custodian.birth&&n.broker_pid>1&&n.broker_pid!=pid&&n.broker_birth>0&&
      n.device==(uint64_t)lock_stat.st_dev&&n.lock_inode==(uint64_t)lock_stat.st_ino&&
      !memcmp(n.nonce,config.nonce,33)&&!memcmp(n.boot,current_boot,37),"failed_custodian_notice");
    broker=(struct child){.control=commands[1],.status=messages[0]};pin_child(&broker,n.broker_pid,pid);
    need(broker.birth==n.broker_birth,"failed_broker_birth");alive(&custodian,1);
    /* Observe lock contention before loss; never reacquire it after loss. */
    int fd=openat(state_fd,"db.sqlite.manager.lock",O_RDWR|O_NOFOLLOW|O_CLOEXEC);need(fd>=0,"failed_lock_observation");
    errno=0;int locked=flock(fd,LOCK_EX|LOCK_NB),error=errno;close(fd);
    need(locked<0&&(error==EWOULDBLOCK||error==EAGAIN),"failed_exclusive_custodian_lock");
    event("custodian_lock_held",custodian.pid,custodian.birth,1,0,0);
    broker.context=context(&broker,W_BROKER,custodian.pid);send_context(&broker);return 0;
}
static void held(unsigned command_kind,unsigned response,const char *name,int parent){
    command(&broker,command_kind);struct w_message m=phase(&broker,response,15,parent,100);
    need(m.data_fd==broker_data_fd,"failed_held_fd_replaced");event(name,broker.pid,broker.birth,parent,100,0);
}
static void bootstrap(void){
    need(!prctl(PR_SET_DUMPABLE,0,0,0,0)&&!syscall(SYS_close_range,3u,UINT_MAX,0),"failed_pid1_sanitize");
    need(!mount("proc","/proc","proc",MS_NODEV|MS_NOSUID|MS_NOEXEC,NULL)&&!mount("sysfs","/sys","sysfs",MS_NODEV|MS_NOSUID|MS_NOEXEC,NULL)&&
      !mount("devtmpfs","/dev","devtmpfs",MS_NOSUID,NULL),"failed_virtual_mounts");
    char text[640],boot[64],cmdline[4096],*save=NULL,*fields[7];
    need(read_text("/proc/cmdline",cmdline,sizeof(cmdline))>0&&w_cmdline(cmdline),"failed_warm_mode");
    need(read_text("/etc/r1-warm.config",text,sizeof(text))>0,"failed_config");
    for(unsigned i=0;i<7;i++){fields[i]=strtok_r(i?NULL:text,"\n",&save);need(fields[i]!=NULL,"failed_config_fields");}
    need(!strtok_r(NULL,"\n",&save)&&hex_text(fields[0],32)&&w_uuid(fields[1])&&hex_text(fields[2],64)&&hex_text(fields[3],32)&&
      hex_text(fields[4],64)&&hex_text(fields[5],64)&&hex_text(fields[6],64),"failed_config_shape");
    strcpy(config.nonce,fields[0]);strcpy(config.fixture,fields[1]);strcpy(config.source_hash,fields[2]);strcpy(config.lineage,fields[3]);
    strcpy(config.policy_hash,fields[4]);strcpy(config.init_hash,fields[5]);strcpy(config.probe_hash,fields[6]);
    need(read_text("/proc/sys/kernel/random/boot_id",boot,sizeof(boot))==37&&boot[36]=='\n',"failed_boot_id");boot[36]=0;
    need(w_uuid(boot),"failed_boot_id_shape");strcpy(current_boot,boot);pid1_birth=process_stat(1,NULL);need(pid1_birth>0,"failed_pid1_birth");
    char hash[65];struct sha256_state h;sha_init(&h);sha_update(&h,W_POLICY,strlen(W_POLICY));sha_finish(&h,hash);need(!strcmp(hash,config.policy_hash),"failed_policy_pin");
    int fd=open("/init",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);need(fd>=0&&!hash_fd(fd,hash)&&!strcmp(hash,config.init_hash),"failed_init_pin");close(fd);
    fd=open("/bin/r1-warm-probe",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);need(fd>=0&&!hash_fd(fd,hash)&&!strcmp(hash,config.probe_hash),"failed_probe_pin");close(fd);
    errno=0;need(waitpid(-1,NULL,WNOHANG)==-1&&errno==ECHILD,"failed_prior_child");struct stat s;
    need(!lstat("/fixture",&s)&&S_ISDIR(s.st_mode)&&s.st_uid==0&&s.st_gid==0&&(s.st_mode&07777)==0700,"failed_closed_mountpoint");
    closed_established=1;event("closed_before_source",1,pid1_birth,0,0,0);
}
static void prepare_source(void){
    need(!mount("/dev/vda","/fixture","ext4",MS_NODEV|MS_NOSUID|MS_NOEXEC,NULL),"failed_fixture_mount");
    root_fd=open("/fixture",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    need(root_fd>=0&&!fchmod(root_fd,0700)&&!fsync(root_fd)&&!fstat(root_fd,&root_stat),"failed_root_policy");
    vault_fd=directory(root_fd,"vault",0);state_fd=directory(vault_fd,"state",1000);
    need(!fstat(vault_fd,&vault_stat)&&!fstat(state_fd,&state_stat),"failed_directory_pins");event("vault_closed_created",1,pid1_birth,0,0,0);
    event("seed_read_started",1,pid1_birth,0,0,0);int seed=open("/etc/source24.sqlite",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);char hash[65];
    need(seed>=0&&!hash_fd(seed,hash)&&!strcmp(hash,config.source_hash),"failed_seed_pin");
    source_fd=openat(state_fd,"db.sqlite",O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);need(source_fd>=0,"failed_fresh_source");
    unsigned char bytes[8192];off_t at=0;for(;;){ssize_t n=pread(seed,bytes,sizeof(bytes),at);need(n>=0,"failed_seed_read");if(!n)break;
      need(!full_write(source_fd,bytes,(size_t)n),"failed_source_copy");at+=n;}
    close(seed);need(!fchown(source_fd,1000,1000)&&!fsync(source_fd)&&private_file(source_fd,state_fd,"db.sqlite",&source_stat),"failed_source_identity");
    int lock=openat(state_fd,"db.sqlite.manager.lock",O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    need(lock>=0&&!fchown(lock,1000,1000)&&!fsync(lock)&&private_file(lock,state_fd,"db.sqlite.manager.lock",&lock_stat),"failed_new_lock");
    close(lock); /* No lock FD or held lock is inherited from PID1. */
    need(!fsync(state_fd)&&!fsync(vault_fd)&&!fsync(root_fd),"failed_source_sync");verify_closed();source_pinned=1;event("source24_verified",1,pid1_birth,0,24,0);
}
int main(int argc,char **argv){
    if(argc==2&&!strcmp(argv[1],"--self-test"))return getuid()!=0&&hash_self_test()?0:3;
    if(argc!=1||getpid()!=1||getuid()!=0||geteuid()!=0)return 3;
    umask(077);signal(SIGPIPE,SIG_IGN);bootstrap();prepare_source();outside(1,source_fd,"before_custodian");
    need(!begin_custodian(),"failed_cold_custodian_start");phase(&broker,W_READY,7,custodian.pid,0);event("broker_clean_exec_sealed",broker.pid,broker.birth,custodian.pid,0,0);
    command(&broker,W_OPEN);struct w_message opened=phase(&broker,W_OPENED,15,custodian.pid,100);need(opened.data_fd==3,"failed_broker_fd");broker_data_fd=opened.data_fd;
    event("broker_source_opened",broker.pid,broker.birth,custodian.pid,100,0);held(W_HOLD_BEFORE,W_BEFORE,"broker_fd_before_loss",custodian.pid);
    outside(broker.pid,broker_data_fd,"custodian_alive");verify_closed();alive(&broker,custodian.pid);alive(&custodian,1);
    reap(&custodian,1,"custodian_killed_reaped",1);verify_closed();alive(&broker,1);
    held(W_HOLD_AFTER,W_AFTER,"broker_same_fd_after_loss",1);
    errno=0;need(begin_custodian()==-1&&errno==EOWNERDEAD,"failed_warm_replacement_refusal");event("replacement_custodian_refused",1,pid1_birth,0,-1,EOWNERDEAD);
    command(&broker,W_CHECK_SEAL);struct w_message sealed=phase(&broker,W_SEALED,31,1,0);need(sealed.data_fd==broker_data_fd,"failed_seal_fd");event("broker_seal_persists",broker.pid,broker.birth,1,0,0);
    outside(broker.pid,broker_data_fd,"after_custodian_loss");verify_closed();held(W_HOLD_LAST,W_LAST,"broker_fd_still_held",1);
    reap(&broker,1,"broker_killed_reaped",1);outside(1,source_fd,"after_broker_death");verify_closed();
    char boot[64];need(read_text("/proc/sys/kernel/random/boot_id",boot,sizeof(boot))==37&&boot[36]=='\n',"failed_final_boot_read");boot[36]=0;
    need(!strcmp(boot,current_boot)&&process_stat(1,NULL)==pid1_birth,"failed_kernel_changed");errno=0;
    need(waitpid(-1,NULL,WNOHANG)==-1&&errno==ECHILD,"failed_remaining_children");event("source_preserved_no_children",1,pid1_birth,0,24,0);
    close(source_fd);close(state_fd);close(vault_fd);close(root_fd);need(!umount("/fixture"),"failed_fixture_unmount");
    event("warm_loss_closed_no_admission",1,pid1_birth,0,0,0);halt_guest();
}
