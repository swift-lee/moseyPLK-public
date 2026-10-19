#ifndef MOSEY_REGCOMPAT_IDENTITY_H
#define MOSEY_REGCOMPAT_IDENTITY_H

#include "../load-probe/probe_parse.h"

#ifndef MOSEY_REGCOMPAT_EXPECTED_EXE
#define MOSEY_REGCOMPAT_EXPECTED_EXE "/odm/bin/mosey_server"
#endif
#ifndef MOSEY_REGCOMPAT_BINDER_LIBRARY
#define MOSEY_REGCOMPAT_BINDER_LIBRARY "/system/lib64/libbinder_ndk.so"
#endif
#ifndef MOSEY_REGCOMPAT_EXPECTED_LIBRARY
#define MOSEY_REGCOMPAT_EXPECTED_LIBRARY "/odm/lib64/libmosey_registration_compat.so"
#endif
#define MOSEY_REGCOMPAT_INSTANCE "com.google.android.moseyservice.IMoseyService/default"
#define MOSEY_REGCOMPAT_DESCRIPTOR "com.google.android.moseyservice.IMoseyService"

struct regcompat_identity {
    struct probe_status status;
    uint32_t uid[3];
    uint32_t gid[3];
    int has_inet;
    unsigned int read_errors;
    char context[256];
    char executable[4096];
};

/* Fixed read-only /proc/self paths and process credential queries only. */
void regcompat_read_identity(struct regcompat_identity *identity);
int regcompat_target_executable(void);
/* The returned strings are fixed tokens, safe to place in diagnostic lines. */
const char *regcompat_identity_reason(const struct regcompat_identity *identity);

#endif
