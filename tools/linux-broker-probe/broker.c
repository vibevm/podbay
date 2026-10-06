#define _GNU_SOURCE
/* Fixed, disposable experiment. No caller-selected path or worker program. */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sqlite3.h>

#if !defined(__x86_64__)
#error This reviewed filter is for Linux x86_64 only.
#endif

#define PREFIX "codex-podbay-broker-probe-"
#define STORE "/probe/store/db.sqlite"
#define TIMEOUT_MS 15000
#define RECORD_MAGIC 0x42505242U

static volatile sig_atomic_t interrupted;
static void on_signal(int sig) { interrupted = sig; }

static void record(const char *name, int ok, long a, long b) {
    printf("{\"event\":\"%s\",\"ok\":%s,\"a\":%ld,\"b\":%ld}\n",
           name, ok ? "true" : "false", a, b);
    fflush(stdout);
}

struct message {
    unsigned magic;
    int kind; /* 0: assertion, 1: sealed/await begin, 2: open/await stop, 3: done */
    int ok;
    long a, b;
    char name[64];
};

static int write_all(int fd, const void *buf, size_t len) {
    const char *p = buf;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n < 0 && errno == EINTR && !interrupted) continue;
        if (n <= 0) return -1;
        p += n; len -= (size_t)n;
    }
    return 0;
}

static void worker_message(const char *name, int ok, long a, long b, int kind) {
    struct message m = { .magic = RECORD_MAGIC, .kind = kind, .ok = ok, .a = a, .b = b };
    (void)snprintf(m.name, sizeof m.name, "%s", name);
    if (write_all(STDOUT_FILENO, &m, sizeof m) || !ok) _exit(90);
}

static void worker_require(const char *name, int ok, long a, long b) {
    worker_message(name, ok, a, b, 0);
}

#define W_CHECK(name, expr) do { errno = 0; int check_ok = !!(expr); int saved_errno = errno; worker_require((name), check_ok, saved_errno, 0); } while (0)

static int read_record(int fd, struct message *m) {
    size_t got = 0;
    while (got < sizeof *m) {
        struct pollfd p = { .fd = fd, .events = POLLIN };
        int r = poll(&p, 1, TIMEOUT_MS);
        if (r < 0 && errno == EINTR && !interrupted) continue;
        if (r <= 0 || interrupted) return -1;
        ssize_t n = read(fd, (char *)m + got, sizeof *m - got);
        if (n <= 0) return -1;
        got += (size_t)n;
    }
    return m->magic == RECORD_MAGIC && memchr(m->name, 0, sizeof m->name) ? 0 : -1;
}

static int phase(int fd, int expected, long *value) {
    struct message m;
    for (;;) {
        if (read_record(fd, &m)) { record("worker_protocol", 0, expected, errno); return -1; }
        record(m.name, m.ok, m.a, m.b);
        if (!m.ok) return -1;
        if (m.kind == expected) { if (value) *value = m.a; return 0; }
        if (m.kind != 0) return -1;
    }
}

static int same_inode(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

static int drop_identity(uid_t uid, gid_t gid) {
    struct __user_cap_header_struct h = { .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0 };
    struct __user_cap_data_struct d[2] = {{0}};
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)) return -1;
    for (int cap = 0; cap <= CAP_LAST_CAP; ++cap)
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0)) return -1;
    if (setgroups(0, NULL) || setresgid(gid, gid, gid) || setresuid(uid, uid, uid)) return -1;
    if (syscall(SYS_capset, &h, d)) return -1;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)) return -1;
    uid_t r, e, s; gid_t gr, ge, gs;
    if (getresuid(&r, &e, &s) || getresgid(&gr, &ge, &gs) || getgroups(0, NULL) != 0) return -1;
    if (r != uid || e != uid || s != uid || gr != gid || ge != gid || gs != gid) return -1;
    if (syscall(SYS_capget, &h, d)) return -1;
    for (unsigned i = 0; i < 2; ++i)
        if (d[i].effective || d[i].permitted || d[i].inheritable) return -1;
    for (int cap = 0; cap <= CAP_LAST_CAP; ++cap)
        if (prctl(PR_CAPBSET_READ, cap, 0, 0, 0) != 0) return -1;
    return prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 0 &&
           prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1 ? 0 : -1;
}

#define ALLOW_NR(n) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (n), 0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
static int seal_filter(void) {
    /* No prctl setters/getters, execution, process creation, networking, mount,
       namespace, ptrace, cross-process memory, io_uring or descriptor import. */
    struct sock_filter ins[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x40000000U, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        ALLOW_NR(SYS_read), ALLOW_NR(SYS_write), ALLOW_NR(SYS_close),
        ALLOW_NR(SYS_openat), ALLOW_NR(SYS_open), ALLOW_NR(SYS_fstat),
        ALLOW_NR(SYS_newfstatat), ALLOW_NR(SYS_stat), ALLOW_NR(SYS_lstat),
        ALLOW_NR(SYS_statx), ALLOW_NR(SYS_pread64), ALLOW_NR(SYS_pwrite64),
        ALLOW_NR(SYS_lseek), ALLOW_NR(SYS_fcntl), ALLOW_NR(SYS_fsync),
        ALLOW_NR(SYS_fdatasync), ALLOW_NR(SYS_ftruncate),
        ALLOW_NR(SYS_unlink), ALLOW_NR(SYS_unlinkat),
        ALLOW_NR(SYS_access), ALLOW_NR(SYS_faccessat), ALLOW_NR(SYS_faccessat2),
        ALLOW_NR(SYS_getcwd), ALLOW_NR(SYS_readlink), ALLOW_NR(SYS_readlinkat),
        ALLOW_NR(SYS_mmap), ALLOW_NR(SYS_munmap), ALLOW_NR(SYS_mprotect),
        ALLOW_NR(SYS_mremap), ALLOW_NR(SYS_madvise), ALLOW_NR(SYS_brk),
        ALLOW_NR(SYS_clock_gettime), ALLOW_NR(SYS_gettimeofday), ALLOW_NR(SYS_time),
        ALLOW_NR(SYS_getrandom), ALLOW_NR(SYS_getpid), ALLOW_NR(SYS_getppid),
        ALLOW_NR(SYS_gettid), ALLOW_NR(SYS_getuid), ALLOW_NR(SYS_geteuid),
        ALLOW_NR(SYS_getgid), ALLOW_NR(SYS_getegid), ALLOW_NR(SYS_futex),
        ALLOW_NR(SYS_rt_sigaction), ALLOW_NR(SYS_rt_sigprocmask),
        ALLOW_NR(SYS_rt_sigreturn), ALLOW_NR(SYS_restart_syscall),
        ALLOW_NR(SYS_exit), ALLOW_NR(SYS_exit_group),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM)
    };
    struct sock_fprog p = { .len = (unsigned short)(sizeof ins / sizeof ins[0]), .filter = ins };
    return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &p);
}

static int collect_fds(int *fds, size_t cap) {
    DIR *d = opendir("/proc/self/fd");
    if (!d) return -1;
    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(d))) {
        char *end = NULL;
        long fd = strtol(ent->d_name, &end, 10);
        if (*ent->d_name && end && !*end && fd >= 3) {
            if ((size_t)count == cap) { closedir(d); return -1; }
            fds[count++] = (int)fd;
        }
    }
    closedir(d);
    return count;
}

static int sql_value(sqlite3 *db, int expected) {
    sqlite3_stmt *s = NULL;
    int ok = sqlite3_prepare_v2(db, "SELECT value FROM specimen WHERE id=1", -1, &s, NULL) == SQLITE_OK;
    if (ok) ok = sqlite3_step(s) == SQLITE_ROW && sqlite3_column_int(s, 0) == expected;
    sqlite3_finalize(s);
    return ok;
}

static void denied_worker(const char *name, long result) {
    int e = errno;
    worker_require(name, result == -1 && e == EPERM, result, e);
}

static void worker(const char *vault, uid_t uid, gid_t gid, const struct stat *original,
                   int read_control, int write_status, int inherited_db, int inherited_dir) {
    if (dup2(read_control, 0) < 0 || dup2(write_status, 1) < 0 || dup2(write_status, 2) < 0) _exit(91);
    char sandbox[PATH_MAX], source[PATH_MAX], dest[PATH_MAX];
    (void)snprintf(sandbox, sizeof sandbox, "%s/sandbox", vault);
    (void)snprintf(source, sizeof source, "%s/state", vault);
    W_CHECK("private_namespace", unshare(CLONE_NEWNS) == 0);
    W_CHECK("private_propagation", mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0);
    W_CHECK("private_tmpfs", mount("tmpfs", sandbox, "tmpfs", MS_NODEV | MS_NOSUID, "size=4m,mode=0755") == 0);
    W_CHECK("sandbox_chdir", chdir(sandbox) == 0);
    W_CHECK("sandbox_probe_dir", mkdir("probe", 0755) == 0 && chmod("probe", 0755) == 0);
    W_CHECK("sandbox_store_dir", mkdir("probe/store", 0700) == 0);
    (void)snprintf(dest, sizeof dest, "%s/sandbox/probe/store", vault);
    W_CHECK("exact_directory_bind", mount(source, dest, NULL, MS_BIND, NULL) == 0);
    int fds[256];
    int count = collect_fds(fds, sizeof fds / sizeof fds[0]);
    worker_require("fd_inventory", count > 0, count, 0);
    W_CHECK("private_root", chroot(".") == 0 && chdir("/") == 0);
    W_CHECK("close_unrelated_fds", syscall(SYS_close_range, 3U, UINT_MAX, 0) == 0);
    for (int i = 0; i < count; ++i) {
        errno = 0;
        int r = fcntl(fds[i], F_GETFD);
        worker_require("closed_fd_ebadf", r == -1 && errno == EBADF, fds[i], errno);
    }
    errno = 0;
    worker_require("inherited_db_ebadf", fcntl(inherited_db, F_GETFD) == -1 && errno == EBADF, inherited_db, 0);
    errno = 0;
    worker_require("inherited_dir_ebadf", fcntl(inherited_dir, F_GETFD) == -1 && errno == EBADF, inherited_dir, 0);
    worker_require("final_identity_seal", drop_identity(uid, gid) == 0, uid, gid);
    W_CHECK("seccomp_default_deny", seal_filter() == 0);
    worker_message("sealed_ready", 1, 0, 0, 1);
    char command = 0;
    worker_require("begin_handshake", read(0, &command, 1) == 1 && command == 'B', command, 0);

    errno = 0; long fork_result = syscall(SYS_fork);
    if (fork_result == 0) _exit(92); /* no work in an unexpectedly permitted child */
    denied_worker("sealed_fork_denied", fork_result);
    char *const args[] = { "/absent", NULL };
    char *const env[] = { NULL };
    errno = 0; denied_worker("sealed_exec_denied", syscall(SYS_execve, "/absent", args, env));
    errno = 0; denied_worker("sealed_socket_denied", syscall(SYS_socket, AF_UNIX, SOCK_STREAM, 0));
    errno = 0; denied_worker("sealed_sendmsg_denied", syscall(SYS_sendmsg, -1, NULL, 0));
    errno = 0; denied_worker("sealed_unshare_denied", syscall(SYS_unshare, CLONE_NEWNS));
    errno = 0; denied_worker("sealed_setns_denied", syscall(SYS_setns, -1, CLONE_NEWNS));
    errno = 0; denied_worker("sealed_ptrace_denied", syscall(SYS_ptrace, PTRACE_TRACEME, 0, 0, 0));
    errno = 0; denied_worker("sealed_pidfd_getfd_denied", syscall(SYS_pidfd_getfd, -1, 0, 0));
    errno = 0; denied_worker("sealed_dumpable_reset_denied", syscall(SYS_prctl, PR_SET_DUMPABLE, 1, 0, 0, 0));

    int fd = open(STORE, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    worker_require("inside_raw_open", fd >= 0, fd, errno);
    struct stat actual = {0};
    int stat_ok = fstat(fd, &actual) == 0 && same_inode(&actual, original) &&
        actual.st_uid == uid && (actual.st_mode & 0777) == 0600 && actual.st_nlink == 1;
    worker_require("inside_exact_identity", stat_ok, (long)actual.st_dev, (long)actual.st_ino);
    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(STORE, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX, NULL);
    worker_require("inside_sqlite_rw_open", rc == SQLITE_OK, rc, db ? sqlite3_system_errno(db) : 0);
    rc = sqlite3_exec(db, "PRAGMA mmap_size=0; BEGIN IMMEDIATE; UPDATE specimen SET value=99 WHERE id=1; ROLLBACK;", NULL, NULL, NULL);
    worker_require("inside_sqlite_update_rollback", rc == SQLITE_OK && sql_value(db, 42), rc, sqlite3_system_errno(db));
    worker_message("inside_open_ready", 1, fd, 0, 2);
    command = 0;
    worker_require("stop_handshake", read(0, &command, 1) == 1 && command == 'S', command, 0);
    worker_require("inside_sqlite_close", sqlite3_close(db) == SQLITE_OK && close(fd) == 0, 0, 0);
    worker_message("worker_done", 1, 0, 0, 3);
    _exit(0);
}

static int refused_open(const char *event, const char *path) {
    errno = 0;
    int fd = open(path, O_RDWR | O_CLOEXEC);
    int e = errno;
    if (fd >= 0) close(fd);
    int ok = fd == -1 && (e == EACCES || e == EPERM);
    record(event, ok, fd, e);
    return ok;
}

static int mapping(const char *path, const char *value) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    int r = write_all(fd, value, strlen(value));
    close(fd);
    return r;
}

static void outside(uid_t uid, gid_t gid, const char *dbpath, const char *alias,
                    const char *mount_target, pid_t worker_pid, int inside_fd) {
    if (syscall(SYS_close_range, 3U, UINT_MAX, 0) || drop_identity(uid, gid)) _exit(93);
    /* The outside attacker is free to expose itself and create its own userns. */
    if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0)) _exit(93);
    int ok = 1;
    ok &= refused_open("outside_absolute_open_denied", dbpath);
    ok &= refused_open("outside_symlink_open_denied", alias);
    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(dbpath, &db, SQLITE_OPEN_READWRITE, NULL);
    int se = db ? sqlite3_system_errno(db) : 0;
    int sql_ok = rc == SQLITE_CANTOPEN && (se == EACCES || se == EPERM);
    record("outside_sqlite_rw_denied", sql_ok, rc, se);
    ok &= sql_ok;
    sqlite3_close(db);
    char path[PATH_MAX];
    (void)snprintf(path, sizeof path, "/proc/%ld/root%s", (long)worker_pid, STORE);
    ok &= refused_open("outside_proc_root_denied", path);
    (void)snprintf(path, sizeof path, "/proc/%ld/fd/%d", (long)worker_pid, inside_fd);
    ok &= refused_open("outside_proc_fd_denied", path);
    (void)snprintf(path, sizeof path, "/proc/%ld/ns/mnt", (long)worker_pid);
    errno = 0; int nsfd = open(path, O_RDONLY | O_CLOEXEC); int ne = errno;
    if (nsfd >= 0) close(nsfd);
    record("outside_worker_namespace_handle_denied", nsfd < 0 && (ne == EACCES || ne == EPERM), nsfd, ne);
    ok &= nsfd < 0 && (ne == EACCES || ne == EPERM);
    errno = 0; int ur = unshare(CLONE_NEWNS); int ue = errno;
    record("outside_mount_namespace_syscall_denied", ur < 0 && ue == EPERM, ur, ue);
    ok &= ur < 0 && ue == EPERM;
    /* If this host admits user namespaces, test its actual capability scope. */
    errno = 0; ur = unshare(CLONE_NEWUSER | CLONE_NEWNS); ue = errno;
    record("outside_userns_attempt", ur == 0 || (ur < 0 && ue == EPERM), ur, ue);
    if (ur == 0) {
        char uid_map[80], gid_map[80];
        (void)snprintf(uid_map, sizeof uid_map, "0 %lu 1\n", (unsigned long)uid);
        (void)snprintf(gid_map, sizeof gid_map, "0 %lu 1\n", (unsigned long)gid);
        int maps = mapping("/proc/self/setgroups", "deny\n") == 0 &&
            mapping("/proc/self/uid_map", uid_map) == 0 && mapping("/proc/self/gid_map", gid_map) == 0;
        record("outside_userns_maps", maps, getuid(), getgid()); ok &= maps;
        int priv = mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0;
        record("outside_userns_private_propagation", priv, errno, 0); ok &= priv;
        ok &= refused_open("outside_userns_raw_open_denied", dbpath);
        if (priv) {
            char source_dir[PATH_MAX];
            (void)snprintf(source_dir, sizeof source_dir, "%s", dbpath);
            char *last_slash = strrchr(source_dir, '/');
            if (!last_slash) _exit(94);
            *last_slash = 0;
            errno = 0; int mr = mount(source_dir, mount_target, NULL, MS_BIND, NULL); int me = errno;
            record("outside_userns_bind_denied", mr < 0 && (me == EACCES || me == EPERM), mr, me);
            ok &= mr < 0 && (me == EACCES || me == EPERM);
        }
    } else ok &= ue == EPERM;
    _exit(ok ? 0 : 94);
}

static void leak_negative(uid_t uid, gid_t gid, const char *dbpath, int dbfd, int dirfd,
                          const unsigned char *original, const struct stat *identity) {
    /* Deliberately broken diagnostic: the normal worker closes these handles. */
    if (dup2(dbfd, 3) < 0 || dup2(dirfd, 4) < 0 || syscall(SYS_close_range, 5U, UINT_MAX, 0)) _exit(95);
    dbfd = 3; dirfd = 4;
    if (drop_identity(uid, gid)) _exit(95);
    int ok = refused_open("negative_new_path_still_denied", dbpath);
    unsigned char bytes[16];
    ssize_t n = pread(dbfd, bytes, sizeof bytes, 0);
    int read_ok = n == (ssize_t)sizeof bytes && !memcmp(bytes, original, sizeof bytes);
    record("negative_leaked_db_pread_works", read_ok, n, errno); ok &= read_ok;
    ssize_t written = read_ok ? pwrite(dbfd, bytes, sizeof bytes, 0) : -1;
    int write_ok = written == (ssize_t)sizeof bytes && fsync(dbfd) == 0;
    record("negative_leaked_db_pwrite_works", write_ok, written, errno); ok &= write_ok;
    int via_dir = openat(dirfd, "db.sqlite", O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    struct stat st = {0};
    int dir_ok = via_dir >= 0 && fstat(via_dir, &st) == 0 && same_inode(&st, identity);
    record("negative_leaked_dir_openat_works", dir_ok, via_dir, errno); ok &= dir_ok;
    if (via_dir >= 0) close(via_dir);
    _exit(ok ? 0 : 96);
}

static int wait_exact(pid_t *pid) {
    if (*pid <= 0) return 0;
    pid_t p = *pid;
    int pidfd = (int)syscall(SYS_pidfd_open, p, 0);
    struct pollfd fd = { .fd = pidfd, .events = POLLIN };
    int ready = pidfd >= 0 ? poll(&fd, 1, TIMEOUT_MS) : -1;
    if (pidfd >= 0) close(pidfd);
    if (ready <= 0) kill(p, SIGKILL);
    int status = 0;
    pid_t r;
    do { r = waitpid(p, &status, 0); } while (r < 0 && errno == EINTR);
    *pid = -1;
    int ok = ready > 0 && r == p && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    printf("{\"event\":\"child_reaped\",\"ok\":%s,\"pid\":%ld,\"status\":%d}\n", ok ? "true" : "false", (long)p, status);
    fflush(stdout);
    return ok ? 0 : -1;
}

static void kill_reap(pid_t *pid) {
    if (*pid > 0) { kill(*pid, SIGKILL); (void)wait_exact(pid); }
}

static char *read_file(const char *path, size_t *length) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;
    size_t cap = 1024 * 1024, used = 0;
    char *buf = malloc(cap);
    if (!buf) { close(fd); return NULL; }
    while (used < cap) {
        ssize_t n = read(fd, buf + used, cap - used);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { free(buf); close(fd); return NULL; }
        if (!n) { close(fd); *length = used; return buf; }
        used += (size_t)n;
    }
    free(buf); close(fd); return NULL;
}

static int remove_file(int dirfd, const char *name, uid_t owner, const struct stat *exact) {
    struct stat s;
    if (fstatat(dirfd, name, &s, AT_SYMLINK_NOFOLLOW)) return errno == ENOENT ? 0 : -1;
    if (!S_ISREG(s.st_mode) || s.st_uid != owner || s.st_nlink != 1 || (exact && !same_inode(&s, exact))) return -1;
    return unlinkat(dirfd, name, 0);
}

static int remove_dir(int dirfd, const char *name, const struct stat *exact) {
    struct stat s;
    if (fstatat(dirfd, name, &s, AT_SYMLINK_NOFOLLOW)) return errno == ENOENT ? 0 : -1;
    if (!S_ISDIR(s.st_mode) || !same_inode(&s, exact) || s.st_uid != exact->st_uid) return -1;
    return unlinkat(dirfd, name, AT_REMOVEDIR);
}

static int parse_id(const char *s, unsigned long *v) {
    if (!s || !*s) return -1;
    char *end = NULL; errno = 0;
    unsigned long x = strtoul(s, &end, 10);
    if (errno || !end || *end || x == 0 || x >= UINT_MAX) return -1;
    *v = x; return 0;
}

#define CHECK(name, expr) do { errno = 0; int check_ok = !!(expr); int saved_errno = errno; record((name), check_ok, saved_errno, 0); if (!check_ok) goto cleanup; } while (0)

int main(int argc, char **argv) {
    unsigned long owner, group;
    if (argc != 2 || strcmp(argv[1], "--test-only") || getuid() != 0 || geteuid() != 0 ||
        parse_id(getenv("SUDO_UID"), &owner) || parse_id(getenv("SUDO_GID"), &group)) {
        fputs("usage: sudo -n broker --test-only (non-root invoking UID/GID required; no path arguments)\n", stderr);
        return 2;
    }
    uid_t uid = (uid_t)owner; gid_t gid = (gid_t)group;
    if (clearenv() || prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) ||
        syscall(SYS_close_range, 3U, UINT_MAX, 0) || prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)) return 2;
    umask(0077);
    struct sigaction sa = { .sa_handler = on_signal };
    sigemptyset(&sa.sa_mask); sigaction(SIGINT, &sa, NULL); sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
    int ok = 0, clean = 1;
    int rootfd = -1, varfd = -1, tmpfd = -1, vaultfd = -1, statefd = -1, dbfd = -1;
    int commands[2] = {-1, -1}, messages[2] = {-1, -1};
    pid_t child = -1, attacker = -1, leaked = -1;
    struct stat vault_stat = {0}, state_stat = {0}, sandbox_stat = {0}, db_stat = {0}, alias_stat = {0}, target_stat = {0}, ns_before = {0};
    int made_vault = 0, made_state = 0, made_sandbox = 0, made_alias = 0, made_target = 0;
    char name[128] = {0}, vault[PATH_MAX] = {0}, dbpath[PATH_MAX], alias_name[160], alias[PATH_MAX], target_name[160], target[PATH_MAX];
    unsigned char *bytes = NULL;
    char *mounts_before = NULL;
    size_t bytes_len = 0, mounts_len = 0;
    sqlite3 *db = NULL;

    record("sqlite_versions_header_runtime", sqlite3_libversion_number() >= 3012000, SQLITE_VERSION_NUMBER, sqlite3_libversion_number());

    CHECK("host_namespace_recorded", stat("/proc/self/ns/mnt", &ns_before) == 0);
    mounts_before = read_file("/proc/self/mountinfo", &mounts_len);
    CHECK("host_mounts_recorded", mounts_before != NULL);
    rootfd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat anchor;
    CHECK("root_anchor", rootfd >= 0 && fstat(rootfd, &anchor) == 0 && anchor.st_uid == 0 && !(anchor.st_mode & 0022));
    varfd = openat(rootfd, "var", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    CHECK("var_anchor", varfd >= 0 && fstat(varfd, &anchor) == 0 && anchor.st_uid == 0 && !(anchor.st_mode & 0022));
    tmpfd = openat(varfd, "tmp", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    CHECK("sticky_root_tmp_anchor", tmpfd >= 0 && fstat(tmpfd, &anchor) == 0 && anchor.st_uid == 0 && (anchor.st_mode & S_ISVTX));
    unsigned char nonce[16];
    CHECK("root_generated_nonce", getrandom(nonce, sizeof nonce, 0) == (ssize_t)sizeof nonce);
    char hex[33];
    for (size_t i = 0; i < sizeof nonce; ++i) (void)snprintf(hex + i * 2, 3, "%02x", nonce[i]);
    (void)snprintf(name, sizeof name, PREFIX "%s", hex);
    (void)snprintf(vault, sizeof vault, "/var/tmp/%s", name);
    (void)snprintf(dbpath, sizeof dbpath, "/var/tmp/%s/state/db.sqlite", name);
    (void)snprintf(alias_name, sizeof alias_name, "%s.alias", name);
    (void)snprintf(alias, sizeof alias, "/var/tmp/%s", alias_name);
    (void)snprintf(target_name, sizeof target_name, "%s.mount-target", name);
    (void)snprintf(target, sizeof target, "/var/tmp/%s", target_name);
    CHECK("vault_mkdir", mkdirat(tmpfd, name, 0700) == 0); made_vault = 1;
    CHECK("vault_identity", fstatat(tmpfd, name, &vault_stat, AT_SYMLINK_NOFOLLOW) == 0 && vault_stat.st_uid == 0 && (vault_stat.st_mode & 0777) == 0700);
    vaultfd = openat(tmpfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    CHECK("vault_pinned", vaultfd >= 0);
    printf("{\"event\":\"fixture\",\"vault\":\"%s\",\"alias\":\"%s\",\"mount_target\":\"%s\",\"uid\":%lu,\"gid\":%lu,\"dev\":%lu,\"ino\":%lu}\n",
           vault, alias, target, owner, group, (unsigned long)vault_stat.st_dev, (unsigned long)vault_stat.st_ino); fflush(stdout);
    CHECK("state_mkdir", mkdirat(vaultfd, "state", 0700) == 0); made_state = 1;
    statefd = openat(vaultfd, "state", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    CHECK("state_owner", statefd >= 0 && fchown(statefd, uid, gid) == 0 && fstat(statefd, &state_stat) == 0);
    CHECK("sandbox_mkdir", mkdirat(vaultfd, "sandbox", 0700) == 0); made_sandbox = 1;
    CHECK("sandbox_identity", fstatat(vaultfd, "sandbox", &sandbox_stat, AT_SYMLINK_NOFOLLOW) == 0);
    CHECK("sqlite_singlethread", sqlite3_config(SQLITE_CONFIG_SINGLETHREAD) == SQLITE_OK);
    CHECK("fixture_sqlite_create", sqlite3_open_v2(dbpath, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) == SQLITE_OK);
    CHECK("fixture_sqlite_seed", sqlite3_exec(db, "PRAGMA journal_mode=DELETE; PRAGMA mmap_size=0; CREATE TABLE specimen(id INTEGER PRIMARY KEY, value INTEGER); INSERT INTO specimen VALUES(1,42);", NULL, NULL, NULL) == SQLITE_OK);
    CHECK("fixture_sqlite_close", sqlite3_close(db) == SQLITE_OK); db = NULL;
    dbfd = openat(statefd, "db.sqlite", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    CHECK("fixture_owner_identity", dbfd >= 0 && fchown(dbfd, uid, gid) == 0 && fchmod(dbfd, 0600) == 0 && fstat(dbfd, &db_stat) == 0 && S_ISREG(db_stat.st_mode) && db_stat.st_nlink == 1);
    bytes = (unsigned char *)read_file(dbpath, &bytes_len);
    CHECK("fixture_bytes_recorded", bytes && bytes_len >= 16 && bytes_len == (size_t)db_stat.st_size);
    printf("{\"event\":\"original_db\",\"dev\":%lu,\"ino\":%lu,\"uid\":%lu,\"mode\":384,\"bytes\":%zu}\n",
           (unsigned long)db_stat.st_dev, (unsigned long)db_stat.st_ino, owner, bytes_len); fflush(stdout);
    CHECK("alias_create", symlinkat(dbpath, tmpfd, alias_name) == 0); made_alias = 1;
    CHECK("alias_identity", fstatat(tmpfd, alias_name, &alias_stat, AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(alias_stat.st_mode) && alias_stat.st_uid == 0);
    CHECK("mount_target_create", mkdirat(tmpfd, target_name, 0755) == 0); made_target = 1;
    CHECK("mount_target_identity", fchmodat(tmpfd, target_name, 0755, 0) == 0 && fstatat(tmpfd, target_name, &target_stat, AT_SYMLINK_NOFOLLOW) == 0 && target_stat.st_uid == 0);
    CHECK("control_pipes", pipe2(commands, O_CLOEXEC) == 0 && pipe2(messages, O_CLOEXEC) == 0);
    child = fork();
    if (child == 0) worker(vault, uid, gid, &db_stat, commands[0], messages[1], dbfd, statefd);
    CHECK("worker_fork", child > 0);
    close(commands[0]); commands[0] = -1; close(messages[1]); messages[1] = -1;
    CHECK("worker_sealed_phase", phase(messages[0], 1, NULL) == 0);
    CHECK("worker_begin", write_all(commands[1], "B", 1) == 0);
    long inside_fd = -1;
    CHECK("worker_open_phase", phase(messages[0], 2, &inside_fd) == 0);
    attacker = fork();
    if (attacker == 0) outside(uid, gid, dbpath, alias, target, child, (int)inside_fd);
    CHECK("outside_fork", attacker > 0);
    CHECK("outside_finished", wait_exact(&attacker) == 0);
    leaked = fork();
    if (leaked == 0) leak_negative(uid, gid, dbpath, dbfd, statefd, bytes, &db_stat);
    CHECK("negative_fork", leaked > 0);
    CHECK("negative_finished", wait_exact(&leaked) == 0);
    CHECK("worker_stop", write_all(commands[1], "S", 1) == 0);
    CHECK("worker_done_phase", phase(messages[0], 3, NULL) == 0);
    CHECK("worker_finished", wait_exact(&child) == 0);
    struct stat final, final_path;
    size_t final_len = 0;
    char *final_bytes = read_file(dbpath, &final_len);
    int unchanged = final_bytes && final_len == bytes_len && !memcmp(bytes, final_bytes, bytes_len) &&
        fstat(dbfd, &final) == 0 && same_inode(&db_stat, &final) && final.st_uid == uid && (final.st_mode & 0777) == 0600 &&
        fstatat(statefd, "db.sqlite", &final_path, AT_SYMLINK_NOFOLLOW) == 0 && same_inode(&db_stat, &final_path);
    free(final_bytes);
    CHECK("exact_db_bytes_identity_preserved", unchanged);
    ok = 1;

cleanup:
    if (db) sqlite3_close(db);
    kill_reap(&attacker); kill_reap(&leaked); kill_reap(&child);
    /* Reap any unexpected fork descendant adopted via CHILD_SUBREAPER. */
    int descendant_status = 0;
    pid_t unexpected = waitpid(-1, &descendant_status, WNOHANG);
    if (unexpected != -1 || errno != ECHILD) { record("unexpected_descendant", 0, unexpected, errno); clean = 0; }
    else record("no_remaining_children", 1, 0, 0);
    for (int i = 0; i < 2; ++i) { if (commands[i] >= 0) close(commands[i]); if (messages[i] >= 0) close(messages[i]); }
    if (dbfd >= 0) close(dbfd);
    if (made_alias) {
        struct stat s;
        if (fstatat(tmpfd, alias_name, &s, AT_SYMLINK_NOFOLLOW) || !same_inode(&s, &alias_stat) || s.st_uid != 0 || !S_ISLNK(s.st_mode) || unlinkat(tmpfd, alias_name, 0)) clean = 0;
    }
    if (made_target && remove_dir(tmpfd, target_name, &target_stat)) clean = 0;
    if (made_state && statefd >= 0) {
        if (remove_file(statefd, "db.sqlite", uid, db_stat.st_ino ? &db_stat : NULL)) clean = 0;
        const char *sidecars[] = {"db.sqlite-journal", "db.sqlite-wal", "db.sqlite-shm"};
        for (size_t i = 0; i < sizeof sidecars / sizeof sidecars[0]; ++i)
            if (remove_file(statefd, sidecars[i], uid, NULL)) clean = 0;
        if (remove_dir(vaultfd, "state", &state_stat)) clean = 0;
    } else if (made_state) clean = 0;
    if (statefd >= 0) close(statefd);
    if (made_sandbox && remove_dir(vaultfd, "sandbox", &sandbox_stat)) clean = 0;
    if (vaultfd >= 0) close(vaultfd);
    if (made_vault && remove_dir(tmpfd, name, &vault_stat)) clean = 0;
    struct stat ns_after;
    size_t after_len = 0;
    char *mounts_after = read_file("/proc/self/mountinfo", &after_len);
    int host_same = mounts_before && mounts_after && mounts_len == after_len && !memcmp(mounts_before, mounts_after, mounts_len) &&
        stat("/proc/self/ns/mnt", &ns_after) == 0 && same_inode(&ns_before, &ns_after);
    record("host_namespace_mounts_unchanged", host_same, 0, 0); clean &= host_same;
    free(mounts_before); free(mounts_after); free(bytes);
    if (tmpfd >= 0) close(tmpfd);
    if (varfd >= 0) close(varfd);
    if (rootfd >= 0) close(rootfd);
    printf("{\"event\":\"cleanup\",\"ok\":%s,\"vault\":\"%s\",\"interrupted\":%d}\n", clean ? "true" : "false", vault, (int)interrupted);
    record("probe_result", ok && clean && !interrupted, ok, clean);
    return ok && clean && !interrupted ? 0 : 1;
}
