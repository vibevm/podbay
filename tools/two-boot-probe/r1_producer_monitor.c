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
#include "r1_producer_pins.h"
#include "r1_producer_watch.h"
static const char refusal[]="{\"schema\":\"podbay.r1.producer-refusal/2\",\"lifecycle_schema\":\"podbay.r1.producer-lifecycle/2\",\"code\":\"COLD_BOOT_PROVENANCE_UNAVAILABLE\",\"production_origin\":\"UNAVAILABLE\",\"admission\":\"UNAVAILABLE\",\"ready\":false,\"retry\":false}\n";
static void die(void) {
    static const char message[]="R1_PRODUCER_MONITOR_FAILED_NO_ADMISSION\n";
    ssize_t ignored=write(2,message,sizeof(message)-1); (void)ignored;
    _exit(111);
}
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
static void hashcheck(void) {
    char b[4096];char *a[]={"/bin/busybox","sha256sum","-c","/etc/r1-producer-artifacts.sha256",NULL};
    if(command(a,b,sizeof b))die();
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
int main(int argc,char **argv) {
    (void)argv;
    if(argc!=1||getuid()!=0||geteuid()!=0||getpid()==1)return 125;
    signal(SIGALRM,timed);alarm(60);
    const char *unit="podbay-r1-boot-producer-v2.service";
    const char *issuer="r1-producer-issuer.service";
    const char *source="/fixture/vault/state/db.sqlite",*lock="/fixture/vault/manager.lock";
    char b[4096],boot[64],pid1[64];
    text("/proc/1/comm",pid1,sizeof pid1);if(strcmp(pid1,"systemd\n"))die();
    text("/proc/sys/kernel/random/boot_id",boot,sizeof boot);
    if(strlen(boot)!=37||boot[36]!='\n')die();
    boot[36]=0;
    hashcheck();
    metadata("/fixture",0,040700);metadata("/fixture/vault",0,040700);
    metadata("/fixture/vault/state",1000,040700);metadata(source,1000,0600);metadata(lock,0,0600);
    property(unit,"Type","notify\n");property(unit,"NotifyAccess","main\n");property(unit,"Restart","no\n");
    if(numeric(unit,"ExecMainStartTimestampMonotonic")||numeric(issuer,"ExecMainStartTimestampMonotonic"))die();
    struct watches w=watch_start(source,lock);if(w.fd<0)die();
    /* Real positive control before the measurement window: verify each watch,
       and source read detection, then drain before enabling producer startup. */
    int fd=open(source,O_RDONLY|O_CLOEXEC);char byte;
    if(fd<0||read(fd,&byte,1)!=1||close(fd))die();
    fd=open(lock,O_RDONLY|O_CLOEXEC);if(fd<0||close(fd))die();
    uint32_t control[2]={0,0};
    if(watch_drain(w,control)||control[0]!=(IN_OPEN|IN_ACCESS)||control[1]!=IN_OPEN)die();
    no_events(w);
    unsigned long long armed=micros();monitor_ready();
    for(;;) {
        no_events(w);
        char *show[]={"/usr/bin/systemctl","show","--value","--property","ActiveState",(char *)unit,NULL};
        if(command(show,b,sizeof b))die();
        if(!strcmp(b,"failed\n"))break;
        if(strcmp(b,"inactive\n")&&strcmp(b,"activating\n"))die();
        if(micros()-armed>30000000ULL)die();
        struct timespec delay={0,10000000};if(nanosleep(&delay,NULL)&&errno!=EINTR)die();
    }
    property(unit,"Result","exit-code\n");property(unit,"ExecMainCode","1\n");property(unit,"ExecMainStatus","2\n");
    if(numeric(unit,"ActiveEnterTimestampMonotonic")||numeric(unit,"NRestarts"))die();
    unsigned long long start=numeric(unit,"ExecMainStartTimestampMonotonic");
    unsigned long long exited=numeric(unit,"ExecMainExitTimestampMonotonic");
    unsigned long long producer=numeric(unit,"ExecMainPID");
    if(!armed||start<armed||exited<start||producer<2)die();
    property(issuer,"ActiveState","inactive\n");
    if(numeric(issuer,"ExecMainStartTimestampMonotonic")||numeric(issuer,"MainPID"))die();
    text("/run/r1-producer.out",b,sizeof b);if(strcmp(b,refusal))die();
    struct stat st;if(lstat("/run/r1-producer.err",&st)||st.st_size||!S_ISREG(st.st_mode))die();
    if(!lstat("/tmp/r1-producer-issuer-ran",&st)||errno!=ENOENT)die();
    no_events(w);unsigned long long finished=micros();
    if(close(w.fd))die();
    /* Only after measurement ends: our own source hashing and UID probe. */
    hashcheck();
    pid_t p=fork();if(p<0)die();
    if(!p) {
        if(setgroups(0,NULL)||setgid(1000)||setuid(1000))_exit(114);
        const char *paths[]={"/fixture/vault/state/db.sqlite","/fixture/vault/state/db.sqlite-wal","/fixture/vault/state/db.sqlite-shm","/fixture/vault/state/db.sqlite-journal"};
        for(size_t i=0;i<4;i++){int f=open(paths[i],O_RDONLY|O_CLOEXEC);if(f>=0||errno!=EACCES)_exit(115);}
        _exit(0);
    }
    int status;if(waitpid(p,&status,0)!=p||!WIFEXITED(status)||WEXITSTATUS(status))die();
    int n=snprintf(b,sizeof b,"R1_PRODUCER_V2 {\"schema\":1,\"event\":\"PRODUCER_REFUSED_BEFORE_READY_ISSUER_BLOCKED_NO_PRODUCTION_ORIGIN\",\"boot_id\":\"%s\",\"pid1\":1,\"monitor_pid\":%ld,\"producer_pid\":%llu,\"producer_sha256\":\"%s\",\"systemd_sha256\":\"%s\",\"archive_generation\":\"%s\",\"armed_us\":%llu,\"producer_start_us\":%llu,\"producer_exit_us\":%llu,\"window_end_us\":%llu,\"producer_exit\":2,\"producer_ready\":false,\"issuer_starts\":0,\"source_events\":0,\"lock_events\":0,\"watch_control_passed\":true,\"outside_denials\":4,\"production_origin\":\"UNAVAILABLE\",\"admission\":\"UNAVAILABLE\"}\n",boot,(long)getpid(),producer,PRODUCER_SHA,SYSTEMD_SHA,GENERATION,armed,start,exited,finished);
    if(n<1||n>=2048)die();
    int events=open("/dev/ttyS1",O_WRONLY|O_NOCTTY|O_CLOEXEC|O_NONBLOCK);if(events<0)die();
    struct termios serial;if(tcgetattr(events,&serial))die();cfmakeraw(&serial);serial.c_cflag|=CLOCAL|CREAD;
    if(cfsetispeed(&serial,B115200)||cfsetospeed(&serial,B115200)||tcsetattr(events,TCSANOW,&serial)||fcntl(events,F_SETFL,0))die();
    if(write(events,b,(size_t)n)!=n||tcdrain(events)||close(events))die();
    char *power[]={"/usr/bin/systemctl","--no-block","poweroff",NULL};if(command(power,b,sizeof b))die();
    alarm(0);return 0;
}
