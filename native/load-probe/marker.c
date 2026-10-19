#include "probe_parse.h"

/* The constructor deliberately performs no I/O and does not call any API. */
static volatile uint64_t loaded_before_main;

__attribute__((constructor)) static void mark_loaded(void) {
    loaded_before_main = MOSEY_PROBE_MARKER_VALUE;
}

__attribute__((visibility("default")))
uint64_t mosey_plk110_probe_loaded_before_main_v1(void) {
    return loaded_before_main;
}
