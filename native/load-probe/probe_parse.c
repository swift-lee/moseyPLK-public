#include "probe_parse.h"

#include <string.h>

static int horizontal_space(char c) { return c == ' ' || c == '\t'; }

static int parse_ids(const char *text, size_t length, uint32_t ids[4]) {
    size_t offset = 0;
    for (size_t i = 0; i < 4; ++i) {
        while (offset < length && horizontal_space(text[offset])) ++offset;
        if (offset == length || text[offset] < '0' || text[offset] > '9') return -1;
        uint32_t value = 0;
        do {
            uint32_t digit = (uint32_t)(text[offset] - '0');
            if (value > (UINT32_MAX - digit) / 10U) return -1;
            value = value * 10U + digit;
            ++offset;
        } while (offset < length && text[offset] >= '0' && text[offset] <= '9');
        ids[i] = value;
        if (i != 3 && (offset == length || !horizontal_space(text[offset]))) return -1;
    }
    while (offset < length && horizontal_space(text[offset])) ++offset;
    return offset == length ? 0 : -1;
}

static int parse_cap(const char *text, size_t length, uint64_t *out) {
    size_t offset = 0;
    while (offset < length && horizontal_space(text[offset])) ++offset;
    unsigned int digits = 0;
    uint64_t value = 0;
    while (offset < length && !horizontal_space(text[offset])) {
        unsigned int digit;
        char c = text[offset++];
        if (c >= '0' && c <= '9') digit = (unsigned int)(c - '0');
        else if (c >= 'a' && c <= 'f') digit = (unsigned int)(c - 'a') + 10U;
        else if (c >= 'A' && c <= 'F') digit = (unsigned int)(c - 'A') + 10U;
        else return -1;
        if (++digits > 16U) return -1;
        value = value * UINT64_C(16) + digit;
    }
    while (offset < length && horizontal_space(text[offset])) ++offset;
    if (digits == 0 || offset != length) return -1;
    *out = value;
    return 0;
}

int probe_parse_status(const char *text, size_t length, struct probe_status *out) {
    static const char *const names[] = {"Uid:", "Gid:", "CapInh:", "CapPrm:", "CapEff:", "CapAmb:"};
    if (text == NULL || out == NULL || memchr(text, '\0', length) != NULL) return -1;
    struct probe_status parsed = {0};
    unsigned int found = 0;
    size_t offset = 0;
    while (offset < length) {
        size_t end = offset;
        while (end < length && text[end] != '\n') ++end;
        size_t line_length = end - offset;
        for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
            size_t prefix_length = strlen(names[i]);
            if (line_length < prefix_length || memcmp(text + offset, names[i], prefix_length) != 0) continue;
            unsigned int bit = 1U << i;
            if ((found & bit) != 0) return -1;
            const char *value = text + offset + prefix_length;
            size_t value_length = line_length - prefix_length;
            if (value_length == 0 || !horizontal_space(value[0])) return -1;
            int result = i == 0 ? parse_ids(value, value_length, parsed.uid) :
                         i == 1 ? parse_ids(value, value_length, parsed.gid) :
                                  parse_cap(value, value_length, &parsed.caps[i - 2]);
            if (result != 0) return -1;
            found |= bit;
        }
        offset = end < length ? end + 1 : length;
    }
    if (found != 0x3fU) return -1;
    *out = parsed;
    return 0;
}

int probe_preload_contains(const char *value, const char *expected) {
    if (expected == NULL || expected[0] == '\0') return -1;
    if (value == NULL) return 0;
    const size_t maximum = 32768;
    size_t length = 0;
    while (length < maximum && value[length] != '\0') ++length;
    if (length == maximum) return -1;
    size_t expected_length = strlen(expected);
    size_t offset = 0;
    while (offset < length) {
        while (offset < length && (value[offset] == ':' || value[offset] == ' ')) ++offset;
        size_t start = offset;
        while (offset < length && value[offset] != ':' && value[offset] != ' ') ++offset;
        if (offset - start == expected_length && memcmp(value + start, expected, expected_length) == 0) return 1;
    }
    return 0;
}

int probe_identity_matches(const struct probe_status *status,
                           const uint32_t uid[3], const uint32_t gid[3],
                           int has_inet_group, const char *context) {
    if (status == NULL || uid == NULL || gid == NULL || context == NULL ||
        has_inet_group != 1 || strcmp(context, MOSEY_PROBE_CONTEXT) != 0) return 0;
    for (size_t i = 0; i < 4; ++i) {
        if (status->uid[i] != 1000 || status->gid[i] != 1000 || status->caps[i] != MOSEY_PROBE_CAPS) return 0;
        if (i < 3 && (uid[i] != status->uid[i] || gid[i] != status->gid[i])) return 0;
    }
    return 1;
}
