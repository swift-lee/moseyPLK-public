#ifndef MOSEY_LOAD_PROBE_PARSE_H
#define MOSEY_LOAD_PROBE_PARSE_H

#include <stddef.h>
#include <stdint.h>

#define MOSEY_PROBE_CONTEXT "u:r:mosey_server:s0"
#define MOSEY_PROBE_CAPS UINT64_C(0x3000)
#define MOSEY_PROBE_MARKER_NAME "mosey_plk110_probe_loaded_before_main_v1"
#define MOSEY_PROBE_MARKER_VALUE UINT64_C(0x4d4f534559505231)
#ifndef MOSEY_PROBE_EXPECTED_LIBRARY
#define MOSEY_PROBE_EXPECTED_LIBRARY "/odm/lib64/libmosey_load_probe.so"
#endif

struct probe_status {
    uint32_t uid[4];
    uint32_t gid[4];
    uint64_t caps[4]; /* Inheritable, permitted, effective, ambient. */
};

/* All parsers return -1 on malformed, missing, duplicate or overflowing input. */
int probe_parse_status(const char *text, size_t length, struct probe_status *out);
/* Returns 1 for an exact colon/space-separated token, 0 if absent, -1 if too long. */
int probe_preload_contains(const char *value, const char *expected);
/* Pure predicate; callers must additionally verify successful OS reads. */
int probe_identity_matches(const struct probe_status *status,
                           const uint32_t real_effective_saved_uid[3],
                           const uint32_t real_effective_saved_gid[3],
                           int has_inet_group, const char *context);
uint64_t mosey_plk110_probe_loaded_before_main_v1(void);

#endif
