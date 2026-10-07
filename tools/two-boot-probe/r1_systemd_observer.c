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
#include "r1_systemd_pins.h"
static const char refusal[]="{\"schema\":\"podbay.r1.refusal/1\",\"manifest_schema\":\"podbay.r1.install-manifest/1\",\"code\":\"COLD_BOOT_PROVENANCE_UNAVAILABLE\",\"gate\":\"UNESTABLISHED\",\"admission\":\"UNAVAILABLE\"}\n";
static void die(void) {
    static const char message[]="R1_OBSERVER_FAILED_NO_ADMISSION\n";
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
    char b[4096];char *a[]={"/bin/busybox","sha256sum","-c","/etc/r1-artifacts.sha256",NULL};
    if(command(a,b,sizeof b))die();
}
int main(void) {
    if(getuid()!=0 || geteuid()!=0 || getpid()==1)die();
    signal(SIGALRM,timed);alarm(45);
    char b[4096],boot[64],pid1[64];
    text("/proc/1/comm",pid1,sizeof pid1);if(strcmp(pid1,"systemd\n"))die();
    text("/proc/sys/kernel/random/boot_id",boot,sizeof boot);
    if(strlen(boot)!=37||boot[36]!='\n')die();
    boot[36]=0;
    hashcheck();
    property("podbay-r1-closed-bootstrap.service","ActiveState","failed\n");
    property("podbay-r1-closed-bootstrap.service","Result","exit-code\n");
    property("podbay-r1-closed-bootstrap.service","ExecMainCode","1\n");
    property("podbay-r1-closed-bootstrap.service","ExecMainStatus","2\n");
    text("/run/r1-bootstrap.out",b,sizeof b);if(strcmp(b,refusal))die();
    struct stat errfile;
    if(lstat("/run/r1-bootstrap.err",&errfile)||!S_ISREG(errfile.st_mode)||errfile.st_size!=0)die();
    const char *blocked[]={"r1-issuer.service","podbay-r1-custodian.service"};
    for(size_t i=0;i<2;i++) {
        property(blocked[i],"ActiveState","inactive\n");
        property(blocked[i],"ExecMainStartTimestampMonotonic","0\n");
        property(blocked[i],"MainPID","0\n");
    }
    struct stat missing;if(!lstat("/tmp/r1-issuer-ran",&missing)||errno!=ENOENT)die();
    metadata("/fixture",0,040700);metadata("/fixture/vault",0,040700);
    metadata("/fixture/vault/state",1000,040700);
    metadata("/fixture/vault/state/db.sqlite",1000,0600);
    metadata("/fixture/vault/manager.lock",0,0600);
    struct stat root,source,lock;
    if(stat("/fixture",&root)||stat("/fixture/vault/state/db.sqlite",&source)||
       stat("/fixture/vault/manager.lock",&lock)||source.st_dev!=root.st_dev||
       lock.st_dev!=root.st_dev||source.st_ino==lock.st_ino||lock.st_size!=0)die();
    /* Direct real custodian invocation is separately negative-only. */
    char *a[]={"/usr/local/libexec/podbay-r1-linux","custodian","--manifest","/etc/podbay/r1-install-manifest.json",NULL};
    if(command(a,b,sizeof b)!=2||strcmp(b,refusal))die();
    pid_t p=fork();if(p<0)die();
    if(!p) {
        if(setgroups(0,NULL)||setgid(1000)||setuid(1000))_exit(114);
        const char *paths[]={"/fixture/vault/state/db.sqlite","/fixture/vault/state/db.sqlite-wal","/fixture/vault/state/db.sqlite-shm","/fixture/vault/state/db.sqlite-journal"};
        for(size_t i=0;i<4;i++){int f=open(paths[i],O_RDONLY|O_CLOEXEC);if(f>=0||errno!=EACCES)_exit(115);}
        _exit(0);
    }
    int status;if(waitpid(p,&status,0)!=p||!WIFEXITED(status)||WEXITSTATUS(status))die();
    hashcheck();
    int n=snprintf(b,sizeof b,"R1_SYSTEMD {\"schema\":1,\"event\":\"BOOTSTRAP_REFUSED_ISSUERS_BLOCKED_NO_PRODUCTION_ADMISSION\",\"boot_id\":\"%s\",\"pid1\":1,\"observer_pid\":%ld,\"enforcer_sha256\":\"%s\",\"manifest_sha256\":\"%s\",\"systemd_sha256\":\"%s\",\"archive_generation\":\"%s\",\"bootstrap_exit\":2,\"custodian_exit\":2,\"issuer_starts\":0,\"outside_denials\":4,\"enforcer_gate\":\"UNESTABLISHED\",\"admission\":\"UNAVAILABLE\"}\n",boot,(long)getpid(),ENFORCER_SHA,MANIFEST_SHA,SYSTEMD_SHA,GENERATION);
    if(n<1 || n>=2048)die();
    int events=open("/dev/ttyS1",O_WRONLY|O_NOCTTY|O_CLOEXEC|O_NONBLOCK);
    if(events<0)die();
    struct termios serial;
    if(tcgetattr(events,&serial))die();
    cfmakeraw(&serial);serial.c_cflag|=CLOCAL|CREAD;
    if(cfsetispeed(&serial,B115200)||cfsetospeed(&serial,B115200)||
       tcsetattr(events,TCSANOW,&serial)||fcntl(events,F_SETFL,0))die();
    if(write(events,b,(size_t)n)!=n||tcdrain(events)||close(events))die();
    char *power[]={"/usr/bin/systemctl","--no-block","poweroff",NULL};
    if(command(power,b,sizeof b))die();
    alarm(0);return 0;
}
