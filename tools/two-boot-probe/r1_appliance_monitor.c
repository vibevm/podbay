#define _GNU_SOURCE
/* Fixed root diagnostic observer. Never used as a production origin producer. */
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <stddef.h>
#include "r1_appliance_pins.h"
#include <dirent.h>
#include <poll.h>
#include <sys/file.h>
#include <sys/syscall.h>
#include "r1_producer_watch.h"
static void die_at(int line) {
    static const char message[]="R1_APPLIANCE_MONITOR_FAILED_NO_ADMISSION\n";
    ssize_t ignored=write(2,message,sizeof(message)-1); (void)ignored;
    dprintf(2,"observer_line=%d\n",line);
    _exit(111);
}
#define die() die_at(__LINE__)
static void timed(int sig) { (void)sig; die(); }
static int command(char *const args[],char *buf,size_t cap) {
    int p[2],s; if(pipe2(p,O_CLOEXEC))die();
    pid_t pid=fork();if(pid<0)die();
    if(!pid) {
        if(dup2(p[1],1)<0 || dup2(p[1],2)<0) _exit(112);
        close(p[0]);close(p[1]);
        char *const env[]={"PATH=/usr/bin:/bin","LC_ALL=C","SYSTEMD_COLORS=0",NULL};
        execve(args[0],args,env);_exit(113);
    }
    close(p[1]);size_t n=0;ssize_t r;
    while((r=read(p[0],buf+n,cap-1-n))>0){n+=(size_t)r;if(n==cap-1)die();}
    close(p[0]);if(r<0 || waitpid(pid,&s,0)!=pid || !WIFEXITED(s))die();
    buf[n]=0;return WEXITSTATUS(s);
}
static void property(const char *unit,const char *prop,const char *want) {
    char b[4096];char *a[]={"/usr/bin/systemctl","show","--value","--property",(char *)prop,(char *)unit,NULL};
    if(command(a,b,sizeof b) || strcmp(b,want))die();
}
static void text(const char *path,char *buf,size_t cap) {
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)die();
    ssize_t n=read(fd,buf,cap-1);if(n<1 || (size_t)n==cap-1)die();buf[n]=0;close(fd);
}
static void metadata(const char *path,uid_t uid,mode_t mode) {
    struct stat s;if(lstat(path,&s)||s.st_uid!=uid||s.st_gid!=uid||(s.st_mode & 077777)!=mode)die();
    if(S_ISREG(s.st_mode)&&s.st_nlink!=1)die();
}
static unsigned long long micros(void) {
    struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))die();
    return (unsigned long long)t.tv_sec*1000000ULL+(unsigned long long)t.tv_nsec/1000;
}
static unsigned long long numeric(const char *unit,const char *prop) {
    char b[256],*end;char *a[]={"/usr/bin/systemctl","show","--value","--property",(char *)prop,(char *)unit,NULL};
    if(command(a,b,sizeof b)||b[0]<'0'||b[0]>'9')die();
    errno=0;unsigned long long n=strtoull(b,&end,10);
    if(errno||strcmp(end,"\n"))die();
    return n;
}
static void monitor_ready(void) {
    const char *name=getenv("NOTIFY_SOCKET");
    struct sockaddr_un address={.sun_family=AF_UNIX};
    if(!name||!name[0]||strlen(name)>=sizeof address.sun_path||(name[0]!='/'&&name[0]!='@'))die();
    size_t length=strlen(name);memcpy(address.sun_path,name,length+1);
    if(name[0]=='@')address.sun_path[0]=0;
    int fd=socket(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0);if(fd<0)die();
    socklen_t size=(socklen_t)(offsetof(struct sockaddr_un,sun_path)+length+(name[0]=='/'?1:0));
    /* This is MONITOR readiness after arming, never producer readiness. */
    if(sendto(fd,"READY=1",7,MSG_NOSIGNAL,(struct sockaddr *)&address,size)!=7||close(fd))die();
}
static void no_events(struct watches w) {
    uint32_t flags[2]={0,0};if(watch_drain(w,flags)||flags[0]||flags[1])die();
}
static int live(int fd) {
    struct pollfd p={.fd=fd,.events=POLLIN};int n=poll(&p,1,0);if(n<0)die();return !n;
}
static void delay(void) { struct timespec t={0,10000000};if(nanosleep(&t,NULL)&&errno!=EINTR)die(); }
static void sealed_process(pid_t pid,unsigned long long inode) {
    char path[128],b[65536];snprintf(path,sizeof path,"/proc/%ld/status",(long)pid);text(path,b,sizeof b);
    const char *required[]={"\nUid:\t1000\t1000\t1000\t1000\n","\nGid:\t1000\t1000\t1000\t1000\n","\nCapInh:\t0000000000000000\n","\nCapPrm:\t0000000000000000\n","\nCapEff:\t0000000000000000\n","\nCapBnd:\t0000000000000000\n","\nCapAmb:\t0000000000000000\n","\nNoNewPrivs:\t1\n","\nSeccomp:\t2\n"};
    for(size_t i=0;i<sizeof required/sizeof *required;i++)if(!strstr(b,required[i]))die();
    snprintf(path,sizeof path,"/proc/%ld/fd",(long)pid);DIR *d=opendir(path);if(!d)die();unsigned mask=0;struct dirent *entry;
    while((entry=readdir(d))) {if(!strcmp(entry->d_name,".")||!strcmp(entry->d_name,".."))continue;char *end;long n=strtol(entry->d_name,&end,10);if(*end||n<0||n>5||(mask&(1u<<n)))die();mask|=1u<<n;}
    if(closedir(d)||mask!=63)die();
    snprintf(path,sizeof path,"/proc/%ld/fd/3",(long)pid);struct stat st;if(stat(path,&st)||st.st_ino!=inode||st.st_uid!=1000||(st.st_mode&07777)!=0600)die();
    snprintf(path,sizeof path,"/proc/%ld/maps",(long)pid);text(path,b,sizeof b);
    if(strstr(b,"db.sqlite")||strstr(b,"500000000000"))die();
    snprintf(path,sizeof path,"/proc/%ld/root",(long)pid);char link[256];ssize_t n=readlink(path,link,sizeof link-1);if(n<0)die();link[n]=0;
    if(strcmp(link,"/run/r1-appliance/empty"))die();
}
static void outside(pid_t custodian) {
    pid_t p=fork();if(p<0)die();
    if(!p){
        if(setgroups(0,NULL)||setgid(1000)||setuid(1000))_exit(114);
        const char *paths[]={"/fixture/vault/state/db.sqlite","/fixture/vault/state/db.sqlite.manager.lock","/fixture/vault/state/db.sqlite-wal","/fixture/vault/state/db.sqlite-shm","/fixture/vault/state/db.sqlite-journal"};
        for(size_t i=0;i<5;i++){int f=open(paths[i],O_RDONLY|O_CLOEXEC);if(f>=0||errno!=EACCES)_exit(115);}
        char path[128];snprintf(path,sizeof path,"/proc/%ld/fd/3",(long)custodian);if(open(path,O_RDONLY|O_CLOEXEC)>=0||errno!=EACCES)_exit(116);
        snprintf(path,sizeof path,"/proc/%ld/root",(long)custodian);if(open(path,O_PATH|O_DIRECTORY)>=0||errno!=EACCES)_exit(117);
        int pf=(int)syscall(SYS_pidfd_open,custodian,0);if(pf<0)_exit(118);
        if(syscall(SYS_pidfd_getfd,pf,3,0)>=0||errno!=EPERM)_exit(119);
        close(pf);_exit(0);
    }
    int s;if(waitpid(p,&s,0)!=p||!WIFEXITED(s)||WEXITSTATUS(s))die();
}
int main(int argc,char **argv) {
    (void)argv;if(argc!=1||getuid()!=0||geteuid()!=0||getpid()==1)return 125;
    signal(SIGALRM,timed);alarm(90);
    const char *unit="r1-appliance-keeper.service",*issuer="r1-appliance-issuer.service";
    const char *source="/fixture/vault/state/db.sqlite",*lock="/fixture/vault/state/db.sqlite.manager.lock";
    char b[8192],boot[64],pid1[64];text("/proc/1/comm",pid1,sizeof pid1);if(strcmp(pid1,"systemd\n"))die();
    text("/proc/sys/kernel/random/boot_id",boot,sizeof boot);if(strlen(boot)!=37)die();boot[36]=0;
    metadata("/fixture",0,040700);metadata("/fixture/vault",0,040700);metadata("/fixture/vault/state",1000,040700);metadata(source,1000,0600);metadata(lock,1000,0600);
    property(unit,"Type","notify\n");property(unit,"NotifyAccess","main\n");property(unit,"Restart","no\n");property(unit,"KillMode","process\n");
    if(numeric(unit,"ExecMainStartTimestampMonotonic")||numeric(issuer,"ExecMainStartTimestampMonotonic"))die();
    /* Self-test uses disposable controls, never the protected source or lock. */
    const char *a="/run/r1-appliance/watch-a",*z="/run/r1-appliance/watch-b";
    int f=open(a,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);if(f<0||write(f,"x",1)!=1||close(f))die();
    f=open(z,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);if(f<0||close(f))die();
    struct watches control=watch_start(a,z);if(control.fd<0)die();char byte;
    f=open(a,O_RDONLY|O_CLOEXEC);if(f<0||read(f,&byte,1)!=1||close(f))die();f=open(z,O_RDONLY|O_CLOEXEC);if(f<0||close(f))die();
    uint32_t flags[2]={0,0};if(watch_drain(control,flags)||flags[0]!=(IN_OPEN|IN_ACCESS)||flags[1]!=IN_OPEN||close(control.fd)||unlink(a)||unlink(z))die();
    struct watches w=watch_start(source,lock);if(w.fd<0)die();no_events(w);
    unsigned long long armed=micros();monitor_ready();
    char read_event[4096]={0};
    for(;;){
        f=open("/run/r1-appliance/keeper.log",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
        if(f>=0){ssize_t n=read(f,read_event,sizeof read_event-1);if(n<0||close(f))die();if(n>0&&read_event[n-1]=='\n'){read_event[n]=0;break;}}
        else if(errno!=ENOENT)die();
        if(micros()-armed>30000000ULL)die();
        delay();
    }
    char rb[37],generation[65],nonce[65],sha[65],bound[65];unsigned long long kp,kbirth,cp,cbirth,dev,ino,li,size;int consumed=0;
    int fields=sscanf(read_event,"APPLIANCE_READ {\"schema\":1,\"boot_id\":\"%36[0-9a-f-]\",\"generation\":\"%64[0-9a-f]\",\"keeper_pid\":%llu,\"keeper_birth\":%llu,\"custodian_pid\":%llu,\"custodian_birth\":%llu,\"device\":%llu,\"source_inode\":%llu,\"lock_inode\":%llu,\"bytes\":%llu,\"nonce\":\"%64[0-9a-f]\",\"source_sha256\":\"%64[0-9a-f]\",\"bound_sha256\":\"%64[0-9a-f]\",\"migration_admission\":\"UNAVAILABLE\",\"ready\":false}\n%n",rb,generation,&kp,&kbirth,&cp,&cbirth,&dev,&ino,&li,&size,nonce,sha,bound,&consumed);
    if(fields!=13||consumed!=(int)strlen(read_event)||strcmp(rb,boot)||strcmp(generation,GENERATION)||strcmp(sha,SOURCE_SHA)||kp<2||cp<2||kp==cp||!kbirth||!cbirth||!dev||!size||!ino||!li||strlen(nonce)!=64||strlen(bound)!=64)die();
    if(numeric(unit,"MainPID")!=kp||numeric(unit,"ExecMainStartTimestampMonotonic")<armed||numeric(unit,"ActiveEnterTimestampMonotonic")||numeric(unit,"NRestarts")||numeric(issuer,"ExecMainStartTimestampMonotonic"))die();
    property(unit,"ActiveState","activating\n");property(issuer,"ActiveState","inactive\n");
    int keeper=(int)syscall(SYS_pidfd_open,kp,0),child=(int)syscall(SYS_pidfd_open,cp,0);if(keeper<0||child<0||!live(keeper)||!live(child))die();
    sealed_process((pid_t)cp,ino);
    flags[0]=flags[1]=0;if(watch_drain(w,flags)||flags[0]!=(IN_OPEN|IN_ACCESS)||flags[1]!=IN_OPEN)die();
    /* End watched read window before observer's own lock contention probe. */
    if(close(w.fd))die();
    outside((pid_t)cp);
    f=open(lock,O_RDONLY|O_CLOEXEC);if(f<0||!flock(f,LOCK_EX|LOCK_NB)||errno!=EWOULDBLOCK||close(f))die();
    if(!live(keeper)||!live(child)||syscall(SYS_pidfd_send_signal,keeper,SIGKILL,NULL,0))die();
    unsigned long long killed=micros();while(live(keeper)||live(child)){if(micros()-killed>5000000)die();delay();}
    close(keeper);close(child);
    for(;;){char *show[]={"/usr/bin/systemctl","show","--value","--property","ActiveState",(char *)unit,NULL};if(command(show,b,sizeof b))die();if(!strcmp(b,"failed\n"))break;if(micros()-killed>10000000)die();delay();}
    property(unit,"ExecMainCode","2\n");property(unit,"ExecMainStatus","9\n");
    if(numeric(unit,"NRestarts")||numeric(unit,"ActiveEnterTimestampMonotonic")||numeric(issuer,"ExecMainStartTimestampMonotonic"))die();
    /* No surviving keeper/custodian in service cgroup. */
    f=open("/sys/fs/cgroup/system.slice/r1-appliance-keeper.service/cgroup.procs",O_RDONLY|O_CLOEXEC);
    if(f>=0){if(read(f,b,sizeof b)!=0||close(f))die();}else if(errno!=ENOENT)die();
    w=watch_start(source,lock);if(w.fd<0)die();no_events(w);
    char *retry[]={"/usr/local/libexec/podbay-r1-appliance-keeper",NULL};
    if(command(retry,b,sizeof b)!=2||strcmp(b,"APPLIANCE_ATTEMPT_SPENT\nAPPLIANCE_KEEPER_REFUSED_OR_LOST\n"))die();
    no_events(w);if(close(w.fd))die();
    f=open(lock,O_RDONLY|O_CLOEXEC);if(f<0||flock(f,LOCK_EX|LOCK_NB)||close(f))die();
    if(numeric(unit,"NRestarts")||numeric(issuer,"ExecMainStartTimestampMonotonic"))die();
    char event[8192];read_event[strlen(read_event)-1]=0;
    int n=snprintf(event,sizeof event,"R1_APPLIANCE_READ_V1 {\"schema\":1,\"event\":\"DISPOSABLE_READ_CUSTODY_ESTABLISHED_AND_LOST_NO_MIGRATION\",\"read\":%s,\"armed_us\":%llu,\"killed_us\":%llu,\"finished_us\":%llu,\"watch_control\":true,\"fd_seal\":true,\"outside_denials\":8,\"lock_contended\":true,\"loss_observed\":true,\"spent_retry_refused\":true,\"issuer_starts\":0,\"production_origin\":\"UNAVAILABLE\",\"migration_admission\":\"UNAVAILABLE\"}\n",read_event+15,armed,killed,micros());
    if(n<1||(size_t)n>=sizeof event)die();
    int events=open("/dev/ttyS1",O_WRONLY|O_NOCTTY|O_CLOEXEC);if(events<0)die();struct termios serial;if(tcgetattr(events,&serial))die();cfmakeraw(&serial);serial.c_cflag|=CLOCAL|CREAD;
    if(cfsetispeed(&serial,B115200)||cfsetospeed(&serial,B115200)||tcsetattr(events,TCSANOW,&serial)||write(events,event,(size_t)n)!=n||tcdrain(events)||close(events))die();
    char *power[]={"/usr/bin/systemctl","--no-block","poweroff",NULL};if(command(power,b,sizeof b))die();alarm(0);return 0;
}
