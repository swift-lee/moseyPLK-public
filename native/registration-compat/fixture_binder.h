/* Host-only ABI fixture. It models counters/ordering, never Android Binder. */
#ifndef MOSEY_REGCOMPAT_FIXTURE_BINDER_H
#define MOSEY_REGCOMPAT_FIXTURE_BINDER_H
#include <stdbool.h>
#include <stdint.h>
typedef struct AIBinder {
    int remote;
    int class_mode; /* 0: good, 1: wrong, 2: no class, 3: null descriptor. */
    int32_t result;
} AIBinder;
typedef struct AIBinder_Class { const char *descriptor; } AIBinder_Class;
int32_t AServiceManager_addService(AIBinder *binder, const char *instance);
void fixture_dump(void);
#endif
