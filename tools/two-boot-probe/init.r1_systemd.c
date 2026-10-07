#define _GNU_SOURCE
/* Disposable root-in-archive setup only. No source/checkpoint opens or forks. */
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static void fail(void) {
    static const char msg[] = "R1_SETUP_FAILED_NO_ADMISSION\n";
    ssize_t ignored=write(2, msg, sizeof(msg)-1); (void)ignored;
    (void)reboot(RB_POWER_OFF);
    for (;;) pause();
}
static void denying(const char *path) {
    struct stat s;
    if (lstat(path, &s) || !S_ISDIR(s.st_mode) || s.st_uid || s.st_gid ||
        (s.st_mode & 07777) != 0700) fail();
}
int main(void) {
    /* Never enter guest shutdown handling from an accidental host invocation. */
    if (getpid()!=1 || getuid()!=0 || geteuid()!=0) return 125;
    umask(0077);
    if (mount("proc", "/proc", "proc", MS_NOSUID|MS_NODEV|MS_NOEXEC, NULL) ||
        mount("sysfs", "/sys", "sysfs", MS_NOSUID|MS_NODEV|MS_NOEXEC, NULL) ||
        mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID|MS_NOEXEC, "mode=0755") ||
        mount("tmpfs", "/run", "tmpfs", MS_NOSUID|MS_NODEV, "mode=0755")) fail();
    if(mkdir("/sys/fs/cgroup",0755) && errno!=EEXIST) fail();
    if(mount("cgroup2", "/sys/fs/cgroup", "cgroup2", MS_NOSUID|MS_NODEV|MS_NOEXEC, NULL)) fail();
    int fd=open("/dev/console",O_RDWR|O_NOCTTY|O_CLOEXEC);
    if(fd<0) fail();
    for(int i=0;i<3;i++) if(dup2(fd,i)<0) fail();
    if(syscall(SYS_close_range,3U,~0U,0)) fail();
    denying("/fixture");
    /* root0700 existed in both archive and fresh disk before this mount. */
    if(mount("/dev/vda","/fixture","ext4",MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC,"noload")) fail();
    denying("/fixture"); denying("/fixture/vault");
    char *const argv[]={"/usr/lib/systemd/systemd","--system","--unit=r1-test.target",NULL};
    char *const env[]={"PATH=/usr/bin:/bin","LANG=C","SYSTEMD_LOG_TARGET=console",
        "SYSTEMD_LOG_LEVEL=warning","SYSTEMD_SHOW_STATUS=false","SYSTEMD_COLORS=0",NULL};
    execve(argv[0],argv,env);
    fail();
}
