#define _GNU_SOURCE
#include "probe_parse.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/types.h>
#include <unistd.h>

enum { EXIT_IDENTITY = 10, EXIT_NOT_LOADED = 11, EXIT_READ_ERROR = 12, EXIT_USAGE = 64 };
enum { ERR_UID = 1, ERR_GID = 2, ERR_GROUPS = 4, ERR_CONTEXT = 8,
       ERR_STATUS = 16, ERR_AUXV = 32, ERR_EXE = 64, ERR_MNT = 128, ERR_ENV = 256 };

/* No writes except stdout. Fixed paths refer exclusively to this process. */
static int read_self_file(const char *path, char *buffer, size_t capacity, size_t *length) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0 || capacity < 2) {
        if (fd >= 0) close(fd);
        return -1;
    }
    size_t used = 0;
    int success = 0;
    for (;;) {
        char overflow;
        void *destination = used < capacity - 1 ? buffer + used : &overflow;
        size_t available = used < capacity - 1 ? capacity - 1 - used : 1;
        ssize_t count = read(fd, destination, available);
        if (count < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (count == 0) { success = 1; break; }
        if (used == capacity - 1) break;
        used += (size_t)count;
    }
    if (close(fd) != 0) success = 0;
    if (!success || used == 0) { buffer[0] = '\0'; return -1; }
    buffer[used] = '\0';
    *length = used;
    return 0;
}

static int read_self_link(const char *path, char *buffer, size_t capacity) {
    ssize_t count = readlink(path, buffer, capacity);
    if (count <= 0 || (size_t)count >= capacity) { buffer[0] = '\0'; return -1; }
    buffer[count] = '\0';
    return 0;
}

static void print_escaped(const char *key, const char *value) {
    printf("%s=", key);
    for (const unsigned char *p = (const unsigned char *)value; *p != '\0'; ++p) {
        if (*p >= 0x21 && *p <= 0x7e && *p != '%' && *p != '=') putchar(*p);
        else printf("%%%02X", (unsigned int)*p);
    }
    putchar('\n');
}

static int context_valid(char *context, size_t length) {
    if (length > 0 && context[length - 1] == '\0') --length;
    if (length > 0 && context[length - 1] == '\n') --length;
    if (length == 0) return 0;
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)context[i];
        if (c < 0x21 || c > 0x7e) return 0;
    }
    context[length] = '\0';
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 2 || (strcmp(argv[1], "baseline") != 0 && strcmp(argv[1], "preload") != 0)) {
        puts("PROBE_SCHEMA=1\nRESULT=USAGE_ERROR\nEXIT_CODE=64");
        return EXIT_USAGE;
    }
    int preload = strcmp(argv[1], "preload") == 0;
    unsigned int errors = 0;
    uid_t ru = 0, eu = 0, su = 0;
    gid_t rg = 0, eg = 0, sg = 0;
    if (getresuid(&ru, &eu, &su) != 0) errors |= ERR_UID;
    if (getresgid(&rg, &eg, &sg) != 0) errors |= ERR_GID;
    uint32_t uid[3] = {(uint32_t)ru, (uint32_t)eu, (uint32_t)su};
    uint32_t gid[3] = {(uint32_t)rg, (uint32_t)eg, (uint32_t)sg};

    gid_t groups[1024];
    int group_count = getgroups(0, NULL);
    int has_inet = 0;
    if (group_count < 0 || group_count > (int)(sizeof(groups) / sizeof(groups[0]))) {
        errors |= ERR_GROUPS;
        group_count = -1;
    } else {
        /* Pass capacity even for an empty list, so a group change cannot fake a read. */
        int actual = getgroups((int)(sizeof(groups) / sizeof(groups[0])), groups);
        if (actual < 0 || actual != group_count) { errors |= ERR_GROUPS; group_count = -1; }
        else for (int i = 0; i < group_count; ++i) if (groups[i] == 3003) has_inet = 1;
    }

    char context[256] = {0};
    size_t length = 0;
    if (read_self_file("/proc/self/attr/current", context, sizeof(context), &length) != 0 ||
        !context_valid(context, length)) {
        errors |= ERR_CONTEXT;
        context[0] = '\0';
    }
    char status_text[65536];
    struct probe_status status = {0};
    if (read_self_file("/proc/self/status", status_text, sizeof(status_text), &length) != 0 ||
        probe_parse_status(status_text, length, &status) != 0) errors |= ERR_STATUS;
    errno = 0;
    unsigned long secure = getauxval(AT_SECURE);
    if (errno != 0 || secure > 1) errors |= ERR_AUXV;
    char executable[4096] = {0}, mount_namespace[128] = {0};
    if (read_self_link("/proc/self/exe", executable, sizeof(executable)) != 0) errors |= ERR_EXE;
    if (read_self_link("/proc/self/ns/mnt", mount_namespace, sizeof(mount_namespace)) != 0) errors |= ERR_MNT;
    int env_expected = probe_preload_contains(getenv("LD_PRELOAD"), MOSEY_PROBE_EXPECTED_LIBRARY);
    if (env_expected < 0) errors |= ERR_ENV;

    int marker_found = 0, marker_initialized = 0, marker_origin_expected = 0;
    if (preload) {
        /* RTLD_DEFAULT searches existing objects; it never loads a library. */
        (void)dlerror();
        void *symbol = dlsym(RTLD_DEFAULT, MOSEY_PROBE_MARKER_NAME);
        const char *lookup_error = dlerror();
        if (symbol != NULL && lookup_error == NULL) {
            marker_found = 1;
            Dl_info info = {0};
            marker_origin_expected = dladdr(symbol, &info) != 0 && info.dli_fname != NULL &&
                strcmp(info.dli_fname, MOSEY_PROBE_EXPECTED_LIBRARY) == 0;
            /* Only call our marker when the loader identifies the expected object. */
            if (marker_origin_expected) {
                uint64_t (*marker)(void) = NULL;
                _Static_assert(sizeof(marker) == sizeof(symbol), "POSIX dlsym pointer size");
                memcpy(&marker, &symbol, sizeof(marker));
                marker_initialized = marker() == MOSEY_PROBE_MARKER_VALUE;
            }
        }
    }
    int identity_ok = errors == 0 && probe_identity_matches(&status, uid, gid, has_inet, context);
    const char *result;
    int exit_code;
    if (errors != 0) { result = "READ_ERROR"; exit_code = EXIT_READ_ERROR; }
    else if (!identity_ok) { result = "IDENTITY_MISMATCH"; exit_code = EXIT_IDENTITY; }
    else if (preload && !(env_expected == 1 && marker_found && marker_origin_expected && marker_initialized)) {
        result = "PRELOAD_NOT_LOADED"; exit_code = EXIT_NOT_LOADED;
    } else { result = preload ? "PRELOAD_OK" : "BASELINE_IDENTITY_OK"; exit_code = 0; }

    puts("PROBE_SCHEMA=1");
    printf("MODE=%s\nPID=%jd\n", argv[1], (intmax_t)getpid());
    printf("UID_VALID=%d\n", (errors & ERR_UID) == 0);
    printf("UID_REAL=%" PRIu32 "\nUID_EFFECTIVE=%" PRIu32 "\nUID_SAVED=%" PRIu32 "\n", uid[0], uid[1], uid[2]);
    printf("GID_VALID=%d\n", (errors & ERR_GID) == 0);
    printf("GID_REAL=%" PRIu32 "\nGID_EFFECTIVE=%" PRIu32 "\nGID_SAVED=%" PRIu32 "\n", gid[0], gid[1], gid[2]);
    printf("GROUPS_VALID=%d\nGROUPS=", (errors & ERR_GROUPS) == 0);
    if (group_count < 0) fputs("UNKNOWN", stdout);
    else for (int i = 0; i < group_count; ++i) printf("%s%ju", i == 0 ? "" : ",", (uintmax_t)groups[i]);
    printf("\nHAS_INET_GROUP=%d\n", has_inet);
    printf("CONTEXT_VALID=%d\n", (errors & ERR_CONTEXT) == 0);
    print_escaped("SELINUX_CONTEXT", (errors & ERR_CONTEXT) == 0 ? context : "UNKNOWN");
    printf("STATUS_VALID=%d\n", (errors & ERR_STATUS) == 0);
    printf("UID_FS=%" PRIu32 "\nGID_FS=%" PRIu32 "\n", status.uid[3], status.gid[3]);
    printf("CAP_INH=%016" PRIx64 "\nCAP_PRM=%016" PRIx64 "\nCAP_EFF=%016" PRIx64 "\nCAP_AMB=%016" PRIx64 "\n",
           status.caps[0], status.caps[1], status.caps[2], status.caps[3]);
    printf("AT_SECURE_VALID=%d\nAT_SECURE=%lu\n", (errors & ERR_AUXV) == 0, secure);
    printf("EXE_VALID=%d\n", (errors & ERR_EXE) == 0);
    print_escaped("EXE", (errors & ERR_EXE) == 0 ? executable : "UNKNOWN");
    printf("MNT_NS_VALID=%d\n", (errors & ERR_MNT) == 0);
    print_escaped("MNT_NS", (errors & ERR_MNT) == 0 ? mount_namespace : "UNKNOWN");
    printf("LD_PRELOAD_VALID=%d\nLD_PRELOAD_EXPECTED=%d\n", (errors & ERR_ENV) == 0, env_expected == 1);
    if (preload) printf("MARKER_FOUND=%d\nMARKER_ORIGIN_EXPECTED=%d\nMARKER_INITIALIZED=%d\n",
                        marker_found, marker_origin_expected, marker_initialized);
    else puts("MARKER_FOUND=NOT_CHECKED\nMARKER_ORIGIN_EXPECTED=NOT_CHECKED\nMARKER_INITIALIZED=NOT_CHECKED");
    printf("READ_ERROR_MASK=%u\nIDENTITY_OK=%d\nRESULT=%s\nEXIT_CODE=%d\n", errors, identity_ok, result, exit_code);
    if (fflush(stdout) != 0) return EXIT_READ_ERROR;
    return exit_code;
}
