#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "../load-probe/probe_parse.h"

#ifndef CONTROL_OWNER_UID
#define CONTROL_OWNER_UID 0
#endif
#ifndef CONTROL_ROOT
#define CONTROL_ROOT "/data/adb/mosey-plk110-cn/control"
#endif
#ifndef CONTROL_PROC
#define CONTROL_PROC "/proc"
#endif
#ifndef CONTROL_EXE
#define CONTROL_EXE "/odm/bin/mosey_server"
#endif
#ifndef CONTROL_MODULE
#define CONTROL_MODULE "/data/adb/modules/moseyPLK.service"
#endif
#ifndef CONTROL_SHELL
#define CONTROL_SHELL "/system/bin/sh"
#endif
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_send_signal
#define SYS_pidfd_send_signal 424
#endif

static int read_text(const char *path, char *out, size_t cap, int private_file) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        (private_file && (st.st_uid != CONTROL_OWNER_UID || (st.st_mode & 0777) != 0600))) {
        close(fd); return -1;
    }
    size_t used = 0;
    while (used < cap - 1) {
        ssize_t n = read(fd, out + used, cap - 1 - used);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { close(fd); return -1; }
        if (n == 0) { out[used] = 0; close(fd); return used ? 0 : -1; }
        used += (size_t)n;
    }
    close(fd); return -1;
}
static int proc_path(char *out, size_t cap, pid_t pid, const char *suffix) {
    int n = snprintf(out, cap, CONTROL_PROC "/%ld/%s", (long)pid, suffix);
    return n > 0 && (size_t)n < cap ? 0 : -1;
}
static int token(pid_t pid, unsigned long long expected) {
    char path[4096], data[4096];
    if (proc_path(path, sizeof(path), pid, "stat") || read_text(path, data, sizeof(data), 0)) return 0;
    char *at = strrchr(data, ')');
    if (!at || at[1] != ' ' || at[2] == 'Z' || at[2] == 'X') return 0;
    at += 2;
    for (int field = 3; field < 22; ++field) {
        at = strchr(at, ' ');
        if (!at) return 0;
        ++at;
    }
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(at, &end, 10);
    return !errno && end != at && (*end == ' ' || *end == '\n' || *end == 0) && value == expected;
}
static int identity(pid_t pid, unsigned long long start, unsigned long long dev, unsigned long long ino) {
    char path[4096], data[65536], exe[4096];
    if (!token(pid, start) || proc_path(path, sizeof(path), pid, "exe")) return 0;
    ssize_t n = readlink(path, exe, sizeof(exe)-1);
    if (n <= 0 || (size_t)n >= sizeof(exe)-1) return 0;
    exe[n] = 0;
    if (strcmp(exe, CONTROL_EXE)) return 0;
    struct stat actual, mounted;
    if (stat(path, &actual) || stat(CONTROL_EXE, &mounted) ||
        (unsigned long long)actual.st_dev != dev || (unsigned long long)actual.st_ino != ino ||
        actual.st_dev != mounted.st_dev || actual.st_ino != mounted.st_ino) return 0;
    if (proc_path(path, sizeof(path), pid, "attr/current") || read_text(path, data, sizeof(data), 0)) return 0;
    data[strcspn(data, "\n")] = 0;
    if (strcmp(data, "u:r:mosey_server:s0")) return 0;
    if (proc_path(path, sizeof(path), pid, "status") || read_text(path, data, sizeof(data), 0)) return 0;
    struct probe_status status;
    if (probe_parse_status(data, strlen(data), &status)) return 0;
    for (size_t i=0; i<4; ++i) {
        if (status.uid[i] != 1000 || status.gid[i] != 1000 || status.caps[i] != 0x3000) return 0;
    }
    char *groups = strstr(data, "\nGroups:");
    if (!groups) return 0;
    groups += 8;
    int inet = 0;
    while (*groups && *groups != '\n') {
        while (*groups == ' ' || *groups == '\t') ++groups;
        if (*groups == '\n' || !*groups) break;
        char *end = NULL;
        unsigned long group = strtoul(groups, &end, 10);
        if (end == groups) return 0;
        if (group == 3003) inet = 1;
        groups = end;
    }
    return inet && token(pid, start);
}
static int terminate_owned(void) {
    char record[512], boot[80], recorded_boot[80], trailing;
    long pid = 0;
    unsigned long long start=0, dev=0, ino=0;
    struct stat directory;
    if (lstat(CONTROL_ROOT, &directory) || !S_ISDIR(directory.st_mode) ||
        directory.st_uid != CONTROL_OWNER_UID || (directory.st_mode & 0777) != 0700 ||
        read_text(CONTROL_ROOT "/owned", record, sizeof(record), 1) ||
        read_text(CONTROL_PROC "/sys/kernel/random/boot_id", boot, sizeof(boot), 0)) return 65;
    if (sscanf(record, "1 %79s %ld %llu %llu %llu %c", recorded_boot, &pid, &start, &dev, &ino, &trailing) != 5 ||
        pid <= 1 || pid > INT_MAX || start == 0 || ino == 0) return 65;
    boot[strcspn(boot, "\n")] = 0;
    if (strcmp(boot, recorded_boot)) return 66;
    int fd = (int)syscall(SYS_pidfd_open, (pid_t)pid, 0);
    if (fd < 0) return errno == ENOSYS ? 69 : 67;
    /* Re-read every identity AFTER obtaining a lifetime-bound pidfd. A recycled
       PID cannot redirect the signal even if it changes after this check. */
    if (!identity((pid_t)pid, start, dev, ino)) { close(fd); return 66; }
    int result = (int)syscall(SYS_pidfd_send_signal, fd, SIGTERM, NULL, 0);
    close(fd);
    return result == 0 ? 0 : 68;
}
static double monotonic(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_BOOTTIME, &ts)) return -1;
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
}
static int run_start(const char *seconds) {
    char *end;
    long duration = strtol(seconds, &end, 10);
    if (!*seconds || *end || duration < 1 || duration > 180) return 64;
    double begin = monotonic();
    if (begin < 0) return 70;
    pid_t child = fork();
    if (child < 0) return 70;
    if (child == 0) {
        if (setsid() < 0) _exit(70);
        execl(CONTROL_SHELL, "sh", CONTROL_MODULE "/registration-compat.sh", "control", seconds, (char *)NULL);
        _exit(70);
    }
    struct timespec nap = {0, 20000000};
    for (;;) {
        int status;
        pid_t got = waitpid(child, &status, WNOHANG);
        if (got == child) return WIFEXITED(status) ? WEXITSTATUS(status) : 71;
        if (got < 0 && errno != EINTR) return 70;
        double now = monotonic();
        if (now < 0 || now - begin >= (double)duration) {
            /* Only the registration supervisor group. The donor/pipe drain run
               in a separate session and are never killed by this budget. */
            if (kill(-child, SIGTERM) && errno == ESRCH) (void)kill(child, SIGTERM);
            return 124;
        }
        (void)nanosleep(&nap, NULL);
    }
}
int main(int argc, char **argv) {
    if (getuid() != CONTROL_OWNER_UID || geteuid() != CONTROL_OWNER_UID) return 77;
    char caller[128];
    if (read_text(CONTROL_PROC "/self/attr/current", caller, sizeof(caller), 0)) return 78;
    caller[strcspn(caller, "\n")] = 0;
    if (strcmp(caller, "u:r:ksu:s0")) return 78;
    char self_ns[128], init_ns[128];
    ssize_t self_len = readlink(CONTROL_PROC "/self/ns/mnt", self_ns, sizeof(self_ns)-1);
    ssize_t init_len = readlink(CONTROL_PROC "/1/ns/mnt", init_ns, sizeof(init_ns)-1);
    if (self_len <= 0 || init_len <= 0 || self_len >= (ssize_t)sizeof(self_ns)-1 ||
        init_len >= (ssize_t)sizeof(init_ns)-1 || self_len != init_len ||
        memcmp(self_ns, init_ns, (size_t)self_len)) return 79;
    if (argc == 2 && !strcmp(argv[1], "terminate")) return terminate_owned();
    if (argc == 2 && !strcmp(argv[1], "probe")) {
        int fd = (int)syscall(SYS_pidfd_open, getpid(), 0);
        if (fd < 0) return 69;
        close(fd); return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "run-start")) return run_start(argv[2]);
    return 64;
}
