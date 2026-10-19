#include "probe_parse.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned int checks;
#define CHECK(condition) do { ++checks; if (!(condition)) { \
    fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #condition); exit(1); \
} } while (0)

static const char fixture[] =
    "Name:\tmosey_load_prob\n"
    "Uid:\t1000\t1000\t1000\t1000\n"
    "Gid:\t1000\t1000\t1000\t1000\n"
    "CapInh:\t0000000000003000\n"
    "CapPrm:\t0000000000003000\n"
    "CapEff:\t0000000000003000\n"
    "CapBnd:\t000001ffffffffff\n"
    "CapAmb:\t0000000000003000\n";

static void reject_replacement(const char *needle, const char *replacement) {
    char changed[2048];
    const char *found = strstr(fixture, needle);
    CHECK(found != NULL);
    size_t prefix = (size_t)(found - fixture);
    size_t replacement_length = strlen(replacement);
    size_t suffix_length = strlen(found + strlen(needle));
    CHECK(prefix + replacement_length + suffix_length < sizeof(changed));
    memcpy(changed, fixture, prefix);
    memcpy(changed + prefix, replacement, replacement_length);
    memcpy(changed + prefix + replacement_length, found + strlen(needle), suffix_length + 1);
    struct probe_status untouched;
    memset(&untouched, 0xa5, sizeof(untouched));
    struct probe_status out = untouched;
    CHECK(probe_parse_status(changed, strlen(changed), &out) == -1);
    CHECK(memcmp(&out, &untouched, sizeof(out)) == 0);
}

int main(void) {
    struct probe_status status = {0};
    CHECK(probe_parse_status(fixture, sizeof(fixture) - 1, &status) == 0);
    CHECK(probe_parse_status(fixture, sizeof(fixture) - 2, &status) == 0);
    CHECK(probe_parse_status(fixture, sizeof(fixture), &status) == -1); /* Embedded NUL. */
    CHECK(probe_parse_status(NULL, 0, &status) == -1);
    CHECK(probe_parse_status(fixture, sizeof(fixture) - 1, NULL) == -1);
    CHECK(probe_parse_status("", 0, &status) == -1);
    reject_replacement("CapAmb:\t0000000000003000\n", "");
    reject_replacement("CapAmb:\t0000000000003000\n", "CapAmb:\t3000\nCapAmb:\t3000\n");
    reject_replacement("CapInh:\t0000000000003000", "CapInh:\t00000000000003000");
    reject_replacement("CapPrm:\t0000000000003000", "CapPrm:\t0x3000");
    reject_replacement("CapEff:\t0000000000003000", "CapEff:\t3000oops");
    reject_replacement("CapEff:\t0000000000003000", "CapEff:\t3000 4000");
    reject_replacement("CapEff:\t0000000000003000", "CapEff:\t");
    reject_replacement("CapEff:\t0000000000003000", "CapEff:3000");
    reject_replacement("CapEff:\t0000000000003000", "CapEff:\t3000\r");
    reject_replacement("Uid:\t1000\t1000\t1000\t1000", "Uid:\t4294967296\t1000\t1000\t1000");
    reject_replacement("Uid:\t1000\t1000\t1000\t1000", "Uid:\t-1\t1000\t1000\t1000");
    reject_replacement("Uid:\t1000\t1000\t1000\t1000", "Uid:\t1000\t1000\t1000");
    reject_replacement("Uid:\t1000\t1000\t1000\t1000", "Uid:\t1000\t1000\t1000\t1000\t1000");
    reject_replacement("Gid:\t1000\t1000\t1000\t1000", "Gid:\t1000\t1000\t1000\t1000a");
    reject_replacement("Gid:\t1000\t1000\t1000\t1000", "Gid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000");

    CHECK(probe_parse_status(fixture, sizeof(fixture) - 1, &status) == 0);
    uint32_t uid[3] = {1000, 1000, 1000}, gid[3] = {1000, 1000, 1000};
    CHECK(probe_identity_matches(&status, uid, gid, 1, MOSEY_PROBE_CONTEXT));
    for (size_t i = 0; i < 4; ++i) {
        struct probe_status changed = status;
        changed.uid[i] = 0;
        CHECK(!probe_identity_matches(&changed, uid, gid, 1, MOSEY_PROBE_CONTEXT));
        changed = status;
        changed.gid[i] = 0;
        CHECK(!probe_identity_matches(&changed, uid, gid, 1, MOSEY_PROBE_CONTEXT));
        changed = status;
        changed.caps[i] = 0x2000;
        CHECK(!probe_identity_matches(&changed, uid, gid, 1, MOSEY_PROBE_CONTEXT));
        changed.caps[i] = 0x7000;
        CHECK(!probe_identity_matches(&changed, uid, gid, 1, MOSEY_PROBE_CONTEXT));
    }
    for (size_t i = 0; i < 3; ++i) {
        uid[i] = 0;
        CHECK(!probe_identity_matches(&status, uid, gid, 1, MOSEY_PROBE_CONTEXT));
        uid[i] = 1000;
        gid[i] = 0;
        CHECK(!probe_identity_matches(&status, uid, gid, 1, MOSEY_PROBE_CONTEXT));
        gid[i] = 1000;
    }
    CHECK(!probe_identity_matches(&status, uid, gid, 0, MOSEY_PROBE_CONTEXT));
    CHECK(!probe_identity_matches(&status, uid, gid, 1, "u:r:ksu:s0"));
    CHECK(!probe_identity_matches(NULL, uid, gid, 1, MOSEY_PROBE_CONTEXT));
    CHECK(!probe_identity_matches(&status, NULL, gid, 1, MOSEY_PROBE_CONTEXT));
    CHECK(!probe_identity_matches(&status, uid, NULL, 1, MOSEY_PROBE_CONTEXT));
    CHECK(!probe_identity_matches(&status, uid, gid, 1, NULL));

    CHECK(probe_preload_contains(NULL, "/expected.so") == 0);
    CHECK(probe_preload_contains("", "/expected.so") == 0);
    CHECK(probe_preload_contains("/expected.so", "/expected.so") == 1);
    CHECK(probe_preload_contains(" : /first.so:/expected.so /last.so :", "/expected.so") == 1);
    CHECK(probe_preload_contains("/expected.so.extra", "/expected.so") == 0);
    CHECK(probe_preload_contains("/other/expected.so", "/expected.so") == 0);
    CHECK(probe_preload_contains("expected.so", "/expected.so") == 0);
    CHECK(probe_preload_contains("/first.so\n/expected.so", "/expected.so") == 0);
    CHECK(probe_preload_contains("/expected.so", NULL) == -1);
    CHECK(probe_preload_contains("/expected.so", "") == -1);
    char large[32769];
    memset(large, 'x', sizeof(large) - 1);
    large[sizeof(large) - 1] = '\0';
    CHECK(probe_preload_contains(large, "/expected.so") == -1);
    printf("parser and identity checks passed: %u\n", checks);
    return 0;
}
