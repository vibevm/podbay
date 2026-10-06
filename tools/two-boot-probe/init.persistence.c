#define _GNU_SOURCE
/* Disposable PID1 marker persistence only. No Owner process or v25 admission. */
#include <errno.h>
#include <fcntl.h>
#include <linux/reboot.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define PREFIX "PODBAY-PERSISTENCE/1\nstate=CLOSED\nadmission=UNIMPLEMENTED\nnonce="
#define SUFFIX "\npayload=DISPOSABLE-CLOSED-MARKER-NOT-V25-AUTHORITY\n"
static int lower_hex(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }
static int uuid_valid(const char *s) {
    for (int i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) { if (s[i] != '-') return 0; }
        else if (!lower_hex(s[i])) return 0;
    }
    return s[36] == 0;
}
static size_t marker(char *out, size_t cap, const char *nonce, const char *boot) {
    int n = snprintf(out, cap, PREFIX "%s\nboot_a=%s" SUFFIX, nonce, boot);
    return n > 0 && (size_t)n < cap ? (size_t)n : 0;
}
static int validate_marker(const char *data, size_t n, const char *nonce, const char *current, char prior[37]) {
    char expected[512];
    size_t offset = strlen(PREFIX) + 32 + strlen("\nboot_a=");
    if (n < offset + 36 || !uuid_valid(current)) return 0;
    memcpy(prior, data + offset, 36); prior[36] = 0;
    if (!uuid_valid(prior) || !strcmp(prior, current)) return 0;
    size_t want = marker(expected, sizeof(expected), nonce, prior);
    return want == n && !memcmp(expected, data, n);
}
static _Noreturn void halt(void) {
    sync(); reboot(RB_POWER_OFF);
    for (;;) pause(); /* Never return PID1 or start an issuer if poweroff fails. */
}
static _Noreturn void fail(const char *why) {
    printf("{\"event\":\"persistence_refused\",\"gate\":\"CLOSED\",\"admission\":\"UNIMPLEMENTED\",\"reason\":\"%s\"}\n", why);
    fflush(stdout); halt();
}
static ssize_t exact_read(int fd, char *buffer, size_t capacity) {
    size_t n = 0;
    while (n < capacity) {
        ssize_t got = read(fd, buffer+n, capacity-n);
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) return -1;
        if (!got) return (ssize_t)n;
        n += (size_t)got;
    }
    return -1; /* At the bound, refuse rather than truncate. */
}
static void read_text(const char *path, char *out, size_t cap) {
    int fd = open(path, O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if (fd < 0) fail("input_open");
    ssize_t n = exact_read(fd,out,cap-1); close(fd);
    if (n < 0) fail("input_length");
    out[n] = 0;
}
static void write_all(int fd, const char *bytes, size_t n) {
    while (n) { ssize_t wrote = write(fd, bytes, n); if (wrote < 0 && errno == EINTR) continue;
        if (wrote <= 0) fail("marker_write");
        bytes += wrote; n -= (size_t)wrote; }
}
static void absent(int directory, const char *name) {
    struct stat st;
    if (!fstatat(directory,name,&st,AT_SYMLINK_NOFOLLOW) || errno != ENOENT) fail("existing_or_partial_gate");
}
int main(void) {
    if (getpid()!=1 || getuid()!=0 || geteuid()!=0) return 3;
    setvbuf(stdout,NULL,_IONBF,0); umask(077);
    if (mount("proc","/proc","proc",MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL) ||
        mount("sysfs","/sys","sysfs",MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL) ||
        mount("devtmpfs","/dev","devtmpfs",MS_NOSUID,NULL)) fail("virtual_mount");
    char cmd[4096], nonce[64], boot[64], data[512], prior[37]={0};
    read_text("/proc/cmdline",cmd,sizeof(cmd));
    int phase = strstr(cmd,"persistence.phase=A") ? 'A' : strstr(cmd,"persistence.phase=B") ? 'B' : 0;
    if (!phase) fail("phase");
    read_text("/etc/nonce",nonce,sizeof(nonce));
    if (strlen(nonce)!=32) fail("nonce_length");
    for (int i=0;i<32;i++) if (!lower_hex(nonce[i])) fail("nonce_format");
    read_text("/proc/sys/kernel/random/boot_id",boot,sizeof(boot));
    if (strlen(boot)!=37 || boot[36]!='\n') fail("boot_id_length");
    boot[36]=0; if (!uuid_valid(boot)) fail("boot_id_format");
    if (mount("/dev/vda","/fixture","ext4",MS_NODEV|MS_NOSUID|MS_NOEXEC,NULL)) fail("fixture_mount");
    if (phase=='A') {
        if (mkdir("/fixture/closed",0700)) fail("fresh_directory");
        int parent=open("/fixture",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        if (parent<0 || fsync(parent)) fail("new_directory_fsync");
        close(parent);
    }
    int directory=open("/fixture/closed",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    struct stat ds;
    if (directory<0 || fstat(directory,&ds) || ds.st_uid || ds.st_gid || (ds.st_mode&07777)!=0700) fail("directory_identity");
    absent(directory,"gate.writing");
    size_t n;
    if (phase=='A') {
        absent(directory,"gate.record");
        n=marker(data,sizeof(data),nonce,boot); if (!n) fail("marker_bound");
        int fd=openat(directory,"gate.writing",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
        if (fd<0) fail("exclusive_marker");
        write_all(fd,data,n); if (fsync(fd) || close(fd)) fail("marker_fsync");
        if (syscall(SYS_renameat2,directory,"gate.writing",directory,"gate.record",RENAME_NOREPLACE) || fsync(directory)) fail("publication_fsync");
    } else {
        int fd=openat(directory,"gate.record",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
        struct stat st;
        if (fd<0 || fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_uid || st.st_gid || (st.st_mode&07777)!=0600 || st.st_nlink!=1) fail("marker_identity");
        ssize_t got=exact_read(fd,data,sizeof(data)); close(fd);
        if (got<0 || !validate_marker(data,(size_t)got,nonce,boot,prior)) fail("malformed_or_foreign_gate");
        n=(size_t)got;
    }
    struct stat st;
    if (fstatat(directory,"gate.record",&st,AT_SYMLINK_NOFOLLOW) || !S_ISREG(st.st_mode) || st.st_nlink!=1 || st.st_uid || st.st_gid || (st.st_mode&07777)!=0600 || (size_t)st.st_size!=n) fail("final_marker_identity");
    if (fsync(directory)) fail("directory_flush");
    close(directory);
    if (umount("/fixture")) fail("fixture_unmount");
    printf("{\"event\":\"closed_marker_persistence\",\"phase\":\"%c\",\"gate\":\"CLOSED\",\"admission\":\"UNIMPLEMENTED\",\"nonce\":\"%s\",\"boot_id\":\"%s\",\"boot_a\":\"%s\",\"inode\":%llu,\"marker_hex\":\"", phase,nonce,boot,phase=='A'?boot:prior,(unsigned long long)st.st_ino);
    for (size_t i=0;i<n;i++) printf("%02x",(unsigned char)data[i]);
    puts("\"}"); halt();
}
