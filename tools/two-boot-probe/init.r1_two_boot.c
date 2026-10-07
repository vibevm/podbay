#define _GNU_SOURCE
/* Fixed minimal guest PID1. A checkpoint is diagnostic data, never authority. */
#include "r1_two_boot_checkpoint.h"
#include <sched.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/wait.h>

static struct r1_checkpoint config, saved;
static struct stat source_stat, root_stat, vault_stat, state_stat, lock_stat, checkpoint_stat;
static char current_boot[37], checkpoint_hash[65], boot_phase;
static uint64_t custodian_birth;
static unsigned sequence, source_pinned, closure_established;
struct child { pid_t pid; int pidfd, control, status, live; uint64_t birth; };
static struct child children[3];
static void cleanup_children(void);
static _Noreturn void halt_guest(void);

static uint64_t birth_of(pid_t pid) {
    char path[64], text[4096];snprintf(path,sizeof(path),"/proc/%ld/stat",(long)pid);
    int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return 0;
    ssize_t n=read(fd,text,sizeof(text)-1);close(fd);if(n<=0)return 0;text[n]=0;
    char *p=strrchr(text,')');if(!p)return 0;p+=2;
    for(int i=3;i<22;i++){p=strchr(p,' ');if(!p)return 0;p++;}
    char *end;unsigned long long value=strtoull(p,&end,10);return end!=p&&*end==' '?value:0;
}
static void event(const char *name,pid_t pid,uint64_t birth,int rc,int error) {
    char line[R1_EVENT_CAP];
    int count=snprintf(line,sizeof(line),"{\"schema\":1,\"event\":\"%s\",\"phase\":\"%c\",\"sequence\":%u,\"nonce\":\"%s\",\"fixture_uuid\":\"%s\",\"boot_id\":\"%s\",\"boot_a\":\"%s\",\"gate\":\"%s\",\"admission\":\"UNIMPLEMENTED\",\"origin_restored\":false,\"source_pinned\":%s,\"source_device\":%llu,\"source_inode\":%llu,\"source_uid\":%u,\"source_bytes\":%llu,\"expected_source_sha256\":\"%s\",\"source_sha256\":\"%s\",\"lineage\":\"%s\",\"policy_sha256\":\"%s\",\"pid1_sha256\":\"%s\",\"probe_sha256\":\"%s\",\"checkpoint_sha256\":\"%s\",\"checkpoint_inode\":%llu,\"old_broker_pid\":%llu,\"old_broker_birth\":%llu,\"actor_pid\":%ld,\"actor_birth\":%llu,\"rc\":%d,\"errno\":%d}\n",
      name,boot_phase?boot_phase:'?',++sequence,config.nonce,config.fixture,current_boot,saved.boot_a,r1_gate_label(closure_established),
      source_pinned?"true":"false",source_pinned?(unsigned long long)source_stat.st_dev:0,
      source_pinned?(unsigned long long)source_stat.st_ino:0,source_pinned?(unsigned)source_stat.st_uid:0,
      source_pinned?(unsigned long long)source_stat.st_size:0,config.source_hash,source_pinned?config.source_hash:"",
      config.lineage,config.policy_hash,config.init_hash,config.probe_hash,checkpoint_hash,
      (unsigned long long)checkpoint_stat.st_ino,(unsigned long long)saved.broker_pid,
      (unsigned long long)saved.broker_birth,(long)pid,(unsigned long long)birth,rc,error);
    /* One bounded write request. EINTR reports no written bytes; retry only
       that case, never complete a short positive write with another fragment.
       This does not establish kernel/user console atomicity. */
    if(count<=0||(size_t)count>=sizeof(line)){
        cleanup_children();halt_guest();
    }
    ssize_t written;do{written=write(STDOUT_FILENO,line,(size_t)count);}while(written<0&&errno==EINTR);
    if(written!=count){
        cleanup_children();halt_guest();
    }
}
static _Noreturn void halt_guest(void){sync();reboot(RB_POWER_OFF);for(;;)pause();}
static void cleanup_children(void){
    for(unsigned i=0;i<3;i++)if(children[i].live){struct child *c=&children[i];
        if(c->pidfd>=0)syscall(SYS_pidfd_send_signal,c->pidfd,SIGKILL,NULL,0);else kill(c->pid,SIGKILL);
        struct pollfd p={.fd=c->pidfd,.events=POLLIN};
        if(c->pidfd>=0&&poll(&p,1,ORIGIN_TIMEOUT_MS)>0){int status;while(waitpid(c->pid,&status,0)<0&&errno==EINTR){}c->live=0;}}
}
static _Noreturn void fail(const char *why){int error=errno;cleanup_children();event(why,1,custodian_birth,-1,error);halt_guest();}
static void need(int ok,const char *why){if(!ok)fail(why);}
static int read_text(const char *path,char *out,size_t cap){
    int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);if(fd<0)return -1;
    ssize_t n=read(fd,out,cap-1);char extra;int end=n>=0&&read(fd,&extra,1)==0;close(fd);
    if(!end)return -1;
    out[n]=0;return (int)n;
}
static void absent(int fd,const char *name,const char *reason){struct stat s;
    need(fstatat(fd,name,&s,AT_SYMLINK_NOFOLLOW)==-1&&errno==ENOENT,reason);}
static int directory(int parent,const char *name,int create,uid_t owner){
    if(create)need(!mkdirat(parent,name,0700),"failed_fresh_directory");
    int fd=openat(parent,name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    need(fd>=0,"failed_directory_open");
    if(create)need(!fchown(fd,owner,owner)&&!fchmod(fd,0700)&&!fsync(fd)&&!fsync(parent),"failed_directory_sync");
    struct stat s;need(!fstat(fd,&s)&&S_ISDIR(s.st_mode)&&s.st_uid==owner&&s.st_gid==owner&&(s.st_mode&07777)==0700,"failed_directory_identity");return fd;
}
static void private_file(int fd,int parent,const char *name,uid_t uid,struct stat *out){struct stat named;
    need(!fstat(fd,out)&&!fstatat(parent,name,&named,AT_SYMLINK_NOFOLLOW)&&same_inode(out,&named)&&S_ISREG(out->st_mode)&&
       out->st_uid==uid&&out->st_gid==uid&&(out->st_mode&07777)==0600&&out->st_nlink==1,"failed_private_file_identity");}
static void no_stage_or_journal(int state){
    absent(state,"stage.sqlite","failed_stage_present");absent(state,"db.sqlite-wal","failed_wal_present");
    absent(state,"db.sqlite-shm","failed_shm_present");absent(state,"db.sqlite-journal","failed_journal_present");
}
static void verify_source(int state,int fd){struct stat now;char hash[65];unsigned char h[100];
    private_file(fd,state,"db.sqlite",1000,&now);
    need(same_inode(&now,&source_stat)&&now.st_size==source_stat.st_size&&!hash_fd(fd,hash)&&!strcmp(hash,config.source_hash)&&
       pread(fd,h,100,0)==100&&!memcmp(h,"SQLite format 3\0",16)&&h[60]==0&&h[61]==0&&h[62]==0&&h[63]==24,"failed_source24_bytes");
    no_stage_or_journal(state);
}
static void exec_child(int commands,int messages,int broker){
    if(dup2(commands,0)<0||dup2(messages,1)<0||dup2(messages,2)<0)_exit(120);
    if(broker){
        if(unshare(CLONE_NEWNS)||mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)||
           mount("tmpfs","/run/sealed","tmpfs",MS_NODEV|MS_NOSUID,"size=8m,mode=0755")||
           mkdir("/run/sealed/probe",0755)||chmod("/run/sealed/probe",0755)||mkdir("/run/sealed/probe/store",0700))_exit(121);
        int target=open("/run/sealed/probe/run",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0755);if(target<0)_exit(121);close(target);
        if(mount("/fixture/vault/state","/run/sealed/probe/store",NULL,MS_BIND,NULL)||
           mount("/bin/r1-probe","/run/sealed/probe/run",NULL,MS_BIND,NULL)||
           mount(NULL,"/run/sealed/probe/run",NULL,MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV,NULL)||
           chdir("/run/sealed")||chroot(".")||chdir("/"))_exit(121);
    }else if(chdir("/"))_exit(121);
    if(syscall(SYS_close_range,3u,UINT_MAX,0)||drop_owner())_exit(122);
    char *args[]={broker?"/probe/run":"/bin/r1-probe",NULL};char *env[]={"LC_ALL=C",NULL};
    execve(args[0],args,env);_exit(123);
}
static struct child *spawn(struct r1_context *ctx,int broker){struct child *c=NULL;
    for(unsigned i=0;i<3;i++)if(!children[i].live){c=&children[i];break;}
    need(c!=NULL,"failed_child_bound");
    int commands[2],messages[2];need(!pipe2(commands,O_CLOEXEC)&&!pipe2(messages,O_CLOEXEC),"failed_pipes");
    pid_t pid=fork();need(pid>=0,"failed_fork");if(!pid)exec_child(commands[0],messages[1],broker);
    close(commands[0]);close(messages[1]);*c=(struct child){.pid=pid,.pidfd=-1,.control=commands[1],.status=messages[0],.live=1};
    c->pidfd=(int)syscall(SYS_pidfd_open,pid,0);c->birth=birth_of(pid);need(c->pidfd>=0&&c->birth,"failed_child_identity");
    need(!full_write(c->control,ctx,sizeof(*ctx)),"failed_context_send");return c;
}
static struct r1_message phase(struct child *c,unsigned expected,unsigned flags){struct r1_message m;
    need(!bounded_read(c->status,&m,sizeof(m)),"failed_phase_deadline");
    need(r1_message_matches(&m,config.nonce,current_boot,c->pid,expected,flags,source_stat.st_dev,source_stat.st_ino)&&
       birth_of(c->pid)==c->birth,"failed_phase_identity");return m;
}
static void command(struct child *c,char value){need(!full_write(c->control,&value,1),"failed_command");}
static void reap(struct child *c,int kill_it){
    if(kill_it)need(!syscall(SYS_pidfd_send_signal,c->pidfd,SIGKILL,NULL,0),"failed_pidfd_kill");
    struct pollfd p={.fd=c->pidfd,.events=POLLIN};int ready;do{ready=poll(&p,1,ORIGIN_TIMEOUT_MS);}while(ready<0&&errno==EINTR);
    need(ready==1&&(p.revents&POLLIN),"failed_reap_deadline");int status;pid_t got;
    do{got=waitpid(c->pid,&status,0);}while(got<0&&errno==EINTR);
    need(got==c->pid&&(kill_it?(WIFSIGNALED(status)&&WTERMSIG(status)==SIGKILL):(WIFEXITED(status)&&WEXITSTATUS(status)==0)),"failed_child_exit");
    c->live=0;event(kill_it?"broker_killed_reaped":"outside_reaped",c->pid,c->birth,kill_it?-SIGKILL:0,0);
    close(c->pidfd);close(c->control);close(c->status);
}
static struct r1_context context(unsigned mode){struct r1_context c={.magic=R1_MAGIC,.mode=mode,
    .device=source_stat.st_dev,.inode=source_stat.st_ino,.bytes=source_stat.st_size};
    memcpy(c.nonce,config.nonce,sizeof(c.nonce));memcpy(c.boot,current_boot,sizeof(c.boot));memcpy(c.hash,config.source_hash,sizeof(c.hash));return c;}
static void outside(pid_t target,int fd,const char *point){struct r1_context ctx=context(R1_OUTSIDE);ctx.target_pid=target;ctx.target_fd=fd;
    struct child *c=spawn(&ctx,0);phase(c,R1_READY,3);command(c,'G');struct r1_message m=phase(c,R1_DONE,255);
    const char *names[]={"source","wal","shm","journal","proc_root","proc_fd","namespace","unshare"};
    for(unsigned i=0;i<8;i++){need(m.denials[i]==EPERM||(i<7&&m.denials[i]==EACCES),"failed_denial_errno");
        char name[96];snprintf(name,sizeof(name),"outside_%s_%s",point,names[i]);event(name,c->pid,c->birth,-1,m.denials[i]);}
    reap(c,0);
}
static void read_checkpoint(int vault,struct r1_checkpoint *record){
    absent(vault,"checkpoint.writing","refused_partial_checkpoint");
    int fd=openat(vault,"checkpoint.record",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);need(fd>=0,"refused_missing_checkpoint");
    private_file(fd,vault,"checkpoint.record",0,&checkpoint_stat);
    need(checkpoint_stat.st_size>0&&checkpoint_stat.st_size<R1_RECORD_CAP,"refused_checkpoint_size");
    char data[R1_RECORD_CAP];ssize_t n=pread(fd,data,sizeof(data),0);
    need(n==checkpoint_stat.st_size&&r1_decode(data,(size_t)n,record),"refused_malformed_checkpoint");
    need(!hash_fd(fd,checkpoint_hash),"refused_checkpoint_readback");close(fd);
}
static void publish_checkpoint(int root,int vault,int state,int source,int lock,struct child *broker,int held_fd){
    saved=config;strcpy(saved.boot_a,current_boot);saved.device=source_stat.st_dev;saved.root_inode=root_stat.st_ino;
    saved.vault_inode=vault_stat.st_ino;saved.state_inode=state_stat.st_ino;saved.source_inode=source_stat.st_ino;
    saved.lock_inode=lock_stat.st_ino;saved.source_bytes=source_stat.st_size;saved.custodian_birth=custodian_birth;
    saved.broker_pid=broker->pid;saved.broker_birth=broker->birth;saved.broker_fd=(uint64_t)held_fd;
    char bytes[R1_RECORD_CAP];size_t n=r1_encode(&saved,bytes);need(n>0,"failed_checkpoint_encoding");
    absent(vault,"checkpoint.record","failed_existing_checkpoint");absent(vault,"checkpoint.writing","failed_existing_writing");
    need(!fsync(source)&&!fsync(lock)&&!fsync(state)&&!fsync(vault)&&!fsync(root),"failed_source_checkpoint_sync");
    int fd=openat(vault,"checkpoint.writing",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    need(fd>=0&&!full_write(fd,bytes,n)&&!fsync(fd)&&!close(fd),"failed_checkpoint_file_sync");
    need(!syscall(SYS_renameat2,vault,"checkpoint.writing",vault,"checkpoint.record",RENAME_NOREPLACE)&&!fsync(vault)&&!fsync(root),"failed_checkpoint_publication");
    struct r1_checkpoint decoded;read_checkpoint(vault,&decoded);char check[R1_RECORD_CAP];size_t count=r1_encode(&decoded,check);
    need(count==n&&!memcmp(check,bytes,n),"failed_checkpoint_exact_readback");event("checkpoint_durable",1,custodian_birth,0,0);
}
static void bootstrap(void){
    need(!prctl(PR_SET_DUMPABLE,0,0,0,0)&&!syscall(SYS_close_range,3u,UINT_MAX,0),"failed_pid1_sanitize");
    need(!mount("proc","/proc","proc",MS_NODEV|MS_NOSUID|MS_NOEXEC,NULL)&&
       !mount("sysfs","/sys","sysfs",MS_NODEV|MS_NOSUID|MS_NOEXEC,NULL)&&
       !mount("devtmpfs","/dev","devtmpfs",MS_NOSUID,NULL),"failed_virtual_mounts");
    char cmdline[4096],text[640],boot[64],*save=NULL;
    need(read_text("/proc/cmdline",cmdline,sizeof(cmdline))>0,"failed_cmdline");
    boot_phase=r1_command_phase(cmdline);need(boot_phase!=0,"failed_phase");
    need(read_text("/etc/r1.config",text,sizeof(text))>0,"failed_config");char *fields[7];save=NULL;
    for(unsigned i=0;i<7;i++){fields[i]=strtok_r(i?NULL:text,"\n",&save);need(fields[i]!=NULL,"failed_config_fields");}
    need(!strtok_r(NULL,"\n",&save)&&hex_text(fields[0],32)&&r1_uuid(fields[1])&&hex_text(fields[2],64)&&
       hex_text(fields[3],32)&&hex_text(fields[4],64)&&hex_text(fields[5],64)&&hex_text(fields[6],64),"failed_config_shape");
    strcpy(config.nonce,fields[0]);strcpy(config.fixture,fields[1]);strcpy(config.source_hash,fields[2]);strcpy(config.lineage,fields[3]);
    strcpy(config.policy_hash,fields[4]);strcpy(config.init_hash,fields[5]);strcpy(config.probe_hash,fields[6]);
    need(read_text("/proc/sys/kernel/random/boot_id",boot,sizeof(boot))==37&&boot[36]=='\n',"failed_boot_id");boot[36]=0;
    need(r1_uuid(boot),"failed_boot_format");strcpy(current_boot,boot);custodian_birth=birth_of(1);need(custodian_birth>0,"failed_pid1_birth");
    char actual[65];struct sha256_state h;sha_init(&h);sha_update(&h,R1_POLICY,strlen(R1_POLICY));sha_finish(&h,actual);
    need(!strcmp(actual,config.policy_hash),"failed_policy");
    int fd=open("/init",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);need(fd>=0&&!hash_fd(fd,actual)&&!strcmp(actual,config.init_hash),"failed_init_pin");close(fd);
    fd=open("/bin/r1-probe",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);need(fd>=0&&!hash_fd(fd,actual)&&!strcmp(actual,config.probe_hash),"failed_probe_pin");close(fd);
    errno=0;need(waitpid(-1,NULL,WNOHANG)==-1&&errno==ECHILD,"failed_prior_child");
    /* No seed/source was opened. PID1's fixed launch closure is active already;
       /fixture is still unmounted and root0700 in the pinned initramfs. */
    struct stat s;need(!lstat("/fixture",&s)&&S_ISDIR(s.st_mode)&&s.st_uid==0&&(s.st_mode&07777)==0700,"failed_closed_mountpoint");
    closure_established=1;
    event("closed_before_source",1,custodian_birth,0,0);
}
int main(int argc,char **argv){
    if(argc==2&&!strcmp(argv[1],"--self-test"))return getuid()!=0&&hash_self_test()?0:3;
    if(argc!=1||getpid()!=1||getuid()!=0||geteuid()!=0)return 3;
    setvbuf(stdout,NULL,_IONBF,0);umask(077);signal(SIGPIPE,SIG_IGN);bootstrap();
    need(!mount("/dev/vda","/fixture","ext4",MS_NODEV|MS_NOSUID|MS_NOEXEC,NULL),"failed_fixture_mount");
    int root=open("/fixture",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);need(root>=0,"failed_root_open");
    if(boot_phase=='A')need(!fchmod(root,0700)&&!fsync(root),"failed_initial_root_policy");
    need(!fstat(root,&root_stat)&&root_stat.st_uid==0&&root_stat.st_gid==0&&(root_stat.st_mode&07777)==0700,"failed_root_policy");
    int vault=directory(root,"vault",boot_phase=='A',0),state=directory(vault,"state",boot_phase=='A',1000);
    need(!fstat(vault,&vault_stat)&&!fstat(state,&state_stat),"failed_directory_pins");
    event(boot_phase=='A'?"vault_closed_created":"vault_closed_recovered",1,custodian_birth,0,0);
    if(boot_phase=='B'){
        read_checkpoint(vault,&saved);need(r1_same_pins(&saved,&config,current_boot),"refused_foreign_checkpoint");
        need(saved.device==(uint64_t)root_stat.st_dev&&saved.root_inode==(uint64_t)root_stat.st_ino&&
          saved.vault_inode==(uint64_t)vault_stat.st_ino&&saved.state_inode==(uint64_t)state_stat.st_ino,"refused_parent_identity");
        event("historical_checkpoint_verified_no_authority",1,custodian_birth,0,0);
    }
    no_stage_or_journal(state);
    int lock=openat(state,"db.sqlite.manager.lock",O_RDWR|O_NOFOLLOW|O_CLOEXEC|(boot_phase=='A'?(O_CREAT|O_EXCL):0),0600);
    need(lock>=0,"failed_lock_open");if(boot_phase=='A')need(!fchown(lock,1000,1000),"failed_lock_owner");
    private_file(lock,state,"db.sqlite.manager.lock",1000,&lock_stat);
    if(boot_phase=='B')need(saved.lock_inode==(uint64_t)lock_stat.st_ino&&saved.device==(uint64_t)lock_stat.st_dev,"refused_lock_identity");
    need(!flock(lock,LOCK_EX|LOCK_NB),"failed_new_lock_custody");event("fresh_lock_custody",1,custodian_birth,0,0);
    event(boot_phase=='A'?"seed_read_started":"source_read_started",1,custodian_birth,0,0);
    int source;
    if(boot_phase=='A'){
        int seed=open("/etc/source24.sqlite",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);char hash[65];
        need(seed>=0&&!hash_fd(seed,hash)&&!strcmp(hash,config.source_hash),"failed_seed_pin");
        source=openat(state,"db.sqlite",O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);need(source>=0,"failed_fresh_source");
        unsigned char bytes[8192];off_t at=0;for(;;){ssize_t n=pread(seed,bytes,sizeof(bytes),at);need(n>=0,"failed_seed_read");if(!n)break;
            need(!full_write(source,bytes,(size_t)n),"failed_source_copy");at+=n;}
        close(seed);need(!fchown(source,1000,1000)&&!fsync(source)&&!fsync(lock)&&!fsync(state)&&!fsync(vault)&&!fsync(root),"failed_source_sync");
    }else{source=openat(state,"db.sqlite",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);need(source>=0,"refused_source_open");}
    private_file(source,state,"db.sqlite",1000,&source_stat);
    if(boot_phase=='B')need(saved.source_inode==(uint64_t)source_stat.st_ino&&saved.device==(uint64_t)source_stat.st_dev&&
       saved.source_bytes==(uint64_t)source_stat.st_size,"refused_source_identity");
    verify_source(state,source);source_pinned=1;event("source24_verified",1,custodian_birth,24,0);
    if(boot_phase=='B')outside(1,source,"before_broker");
    need(dup2(source,257)==257,"failed_high_fd_control");
    struct r1_context ctx=context(boot_phase=='A'?R1_BROKER_WRITE:R1_BROKER_READ);
    struct child *broker=spawn(&ctx,1);close(257);phase(broker,R1_READY,7);event("clean_exec_sealed",broker->pid,broker->birth,0,0);
    command(broker,'G');struct r1_message opened=phase(broker,R1_OPENED,15);need(opened.data_fd>=3,"failed_held_fd");
    event("broker_source_opened",broker->pid,broker->birth,opened.rc,opened.error);outside(broker->pid,opened.data_fd,"broker_alive");
    if(boot_phase=='A')publish_checkpoint(root,vault,state,source,lock,broker,opened.data_fd);
    verify_source(state,source);command(broker,'H');struct r1_message held=phase(broker,R1_HELD,15);
    need(held.data_fd==opened.data_fd,"failed_held_fd_changed");struct pollfd alive={.fd=broker->pidfd,.events=POLLIN};
    need(poll(&alive,1,0)==0,"failed_broker_alive");event("broker_fd_confirmed",broker->pid,broker->birth,0,0);
    if(boot_phase=='A'){event("crash_ready_live_broker_closed",broker->pid,broker->birth,0,0);for(;;)pause();}
    reap(broker,1);outside(1,source,"after_broker_death");verify_source(state,source);
    struct r1_checkpoint final;char previous[65];strcpy(previous,checkpoint_hash);read_checkpoint(vault,&final);
    need(!strcmp(previous,checkpoint_hash),"failed_checkpoint_changed");event("source_checkpoint_preserved",1,custodian_birth,24,0);
    errno=0;need(waitpid(-1,NULL,WNOHANG)==-1&&errno==ECHILD,"failed_remaining_children");
    close(source);close(lock);close(state);close(vault);close(root);need(!umount("/fixture"),"failed_unmount");
    event("recovered_closed_no_admission",1,custodian_birth,0,0);halt_guest();
}
