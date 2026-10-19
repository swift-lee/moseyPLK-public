#define _GNU_SOURCE
#include "identity.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

enum { READ_UID = 1, READ_GID = 2, READ_GROUPS = 4, READ_STATUS = 8,
       READ_CONTEXT = 16, READ_EXE = 32 };

static int self_file(const char *path, char *buffer, size_t capacity, size_t *length) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
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

static int executable(char *buffer, size_t capacity) {
    ssize_t length = readlink("/proc/self/exe", buffer, capacity);
    if (length <= 0 || (size_t)length >= capacity) { buffer[0] = '\0'; return -1; }
    buffer[length] = '\0';
    return 0;
}

int regcompat_target_executable(void) {
    char path[4096];
    return executable(path, sizeof(path)) == 0 &&
        strcmp(path, MOSEY_REGCOMPAT_EXPECTED_EXE) == 0;
}

void regcompat_read_identity(struct regcompat_identity *identity) {
    memset(identity, 0, sizeof(*identity));
    uid_t ru = 0, eu = 0, su = 0;
    gid_t rg = 0, eg = 0, sg = 0;
    if (getresuid(&ru, &eu, &su) != 0) identity->read_errors |= READ_UID;
    if (getresgid(&rg, &eg, &sg) != 0) identity->read_errors |= READ_GID;
    identity->uid[0] = (uint32_t)ru;
    identity->uid[1] = (uint32_t)eu;
    identity->uid[2] = (uint32_t)su;
    identity->gid[0] = (uint32_t)rg;
    identity->gid[1] = (uint32_t)eg;
    identity->gid[2] = (uint32_t)sg;

    gid_t groups[1024];
    int count = getgroups(0, NULL);
    if (count < 0 || count > (int)(sizeof(groups) / sizeof(groups[0]))) {
        identity->read_errors |= READ_GROUPS;
    } else {
        int actual = getgroups((int)(sizeof(groups) / sizeof(groups[0])), groups);
        if (actual < 0 || actual != count) identity->read_errors |= READ_GROUPS;
        else for (int i = 0; i < count; ++i) if (groups[i] == 3003) identity->has_inet = 1;
    }
    size_t length = 0;
    char status[65536];
    if (self_file("/proc/self/status", status, sizeof(status), &length) != 0 ||
        probe_parse_status(status, length, &identity->status) != 0) identity->read_errors |= READ_STATUS;

    char *context = identity->context;
    if (self_file("/proc/self/attr/current", context, sizeof(identity->context), &length) != 0) {
        identity->read_errors |= READ_CONTEXT;
    } else {
        if (length > 0 && context[length - 1] == '\0') --length;
        if (length > 0 && context[length - 1] == '\n') --length;
        for (size_t i = 0; i < length; ++i) {
            unsigned char c = (unsigned char)context[i];
            if (c < 0x21 || c > 0x7e) identity->read_errors |= READ_CONTEXT;
        }
        context[length] = '\0';
        if (length == 0) identity->read_errors |= READ_CONTEXT;
    }
    if (executable(identity->executable, sizeof(identity->executable)) != 0)
        identity->read_errors |= READ_EXE;
}

const char *regcompat_identity_reason(const struct regcompat_identity *identity) {
    if (identity->read_errors != 0) return "read_error";
    if (strcmp(identity->executable, MOSEY_REGCOMPAT_EXPECTED_EXE) != 0) return "executable";
    if (strcmp(identity->context, MOSEY_PROBE_CONTEXT) != 0) return "selinux";
    if (identity->has_inet != 1) return "inet_group";
    for (size_t i = 0; i < 4; ++i) {
        if (identity->status.uid[i] != 1000 || (i < 3 && identity->uid[i] != 1000)) return "uid";
        if (identity->status.gid[i] != 1000 || (i < 3 && identity->gid[i] != 1000)) return "gid";
        if (identity->status.caps[i] != MOSEY_PROBE_CAPS) return "capabilities";
    }
    return "ok";
}
