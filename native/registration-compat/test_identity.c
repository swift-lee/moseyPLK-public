#include "identity.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static struct regcompat_identity good(void) {
    struct regcompat_identity identity = {0};
    for (size_t i = 0; i < 4; ++i) {
        identity.status.uid[i] = 1000;
        identity.status.gid[i] = 1000;
        identity.status.caps[i] = MOSEY_PROBE_CAPS;
        if (i < 3) identity.uid[i] = identity.gid[i] = 1000;
    }
    identity.has_inet = 1;
    strcpy(identity.context, MOSEY_PROBE_CONTEXT);
    strcpy(identity.executable, MOSEY_REGCOMPAT_EXPECTED_EXE);
    return identity;
}

int main(void) {
    unsigned int checks = 0;
    struct regcompat_identity identity = good();
    assert(strcmp(regcompat_identity_reason(&identity), "ok") == 0);
    ++checks;
    for (size_t i = 0; i < 4; ++i) {
        identity = good(); identity.status.uid[i] = 0;
        assert(strcmp(regcompat_identity_reason(&identity), "uid") == 0); ++checks;
        identity = good(); identity.status.gid[i] = 0;
        assert(strcmp(regcompat_identity_reason(&identity), "gid") == 0); ++checks;
        identity = good(); identity.status.caps[i] = 0;
        assert(strcmp(regcompat_identity_reason(&identity), "capabilities") == 0); ++checks;
        identity = good(); identity.status.caps[i] |= UINT64_C(1) << 21;
        assert(strcmp(regcompat_identity_reason(&identity), "capabilities") == 0); ++checks;
        if (i < 3) {
            identity = good(); identity.uid[i] = 0;
            assert(strcmp(regcompat_identity_reason(&identity), "uid") == 0); ++checks;
            identity = good(); identity.gid[i] = 0;
            assert(strcmp(regcompat_identity_reason(&identity), "gid") == 0); ++checks;
        }
    }
    for (unsigned int i = 0; i < 6; ++i) {
        identity = good(); identity.read_errors = 1U << i;
        assert(strcmp(regcompat_identity_reason(&identity), "read_error") == 0); ++checks;
    }
    identity = good(); identity.has_inet = 0;
    assert(strcmp(regcompat_identity_reason(&identity), "inet_group") == 0); ++checks;
    identity = good(); strcpy(identity.context, "u:r:ksu:s0");
    assert(strcmp(regcompat_identity_reason(&identity), "selinux") == 0); ++checks;
    identity = good(); strcat(identity.executable, " (deleted)");
    assert(strcmp(regcompat_identity_reason(&identity), "executable") == 0); ++checks;
    identity = good(); strcpy(identity.executable, "/vendor/bin/mosey_launcher");
    assert(strcmp(regcompat_identity_reason(&identity), "executable") == 0); ++checks;
    regcompat_read_identity(&identity);
    assert(strcmp(regcompat_identity_reason(&identity), "ok") != 0); ++checks;
    assert(regcompat_target_executable() == 0); ++checks;
    printf("registration identity: %u checks passed (including real host rejection)\n", checks);
    return 0;
}
