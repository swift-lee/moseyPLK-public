/* HOST TEST ONLY. The Android build must never include this file. */
#ifndef MOSEY_REGCOMPAT_HOST_TEST
#error Host fixture must be explicitly enabled
#endif
#include "identity.h"

#include <stdlib.h>
#include <string.h>

void regcompat_read_identity_actual(struct regcompat_identity *identity);
int regcompat_target_executable_actual(void);

int regcompat_target_executable(void) { return regcompat_target_executable_actual(); }

void regcompat_read_identity(struct regcompat_identity *identity) {
    regcompat_read_identity_actual(identity);
    const char *fault = getenv("HOST_IDENTITY_FAULT");
    if (fault != NULL && strcmp(fault, "real") == 0) return;
    /* Keep /proc/self/exe from the real host read. Simulate only the Android
     * credentials and SELinux label which an unprivileged host cannot adopt. */
    identity->read_errors = 0;
    identity->has_inet = 1;
    strcpy(identity->context, MOSEY_PROBE_CONTEXT);
    for (size_t i = 0; i < 4; ++i) {
        identity->status.uid[i] = identity->status.gid[i] = 1000;
        identity->status.caps[i] = MOSEY_PROBE_CAPS;
        if (i < 3) identity->uid[i] = identity->gid[i] = 1000;
    }
    if (fault == NULL) return;
    if (strcmp(fault, "uid") == 0) identity->status.uid[3] = 0;
    else if (strcmp(fault, "gid") == 0) identity->status.gid[3] = 0;
    else if (strcmp(fault, "caps") == 0) identity->status.caps[3] = 0;
    else if (strcmp(fault, "inet") == 0) identity->has_inet = 0;
    else if (strcmp(fault, "selinux") == 0) strcpy(identity->context, "u:r:ksu:s0");
    else identity->read_errors = 1;
}
