#include "fixture_binder.h"
#include "identity.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    const char *mode = argc == 2 ? argv[1] : "ok";
    if (strcmp(mode, "loadonly") == 0) return 0;
    AIBinder local = {0, 0, 0};
    AIBinder *binder = strcmp(mode, "null") == 0 ? NULL : &local;
    const char *instance = strcmp(mode, "name") == 0 ? MOSEY_REGCOMPAT_INSTANCE "x" :
        strcmp(mode, "null_name") == 0 ? NULL : MOSEY_REGCOMPAT_INSTANCE;
    local.remote = strcmp(mode, "remote") == 0;
    local.class_mode = strcmp(mode, "descriptor") == 0 ? 1 :
        strcmp(mode, "class") == 0 ? 2 : strcmp(mode, "null_descriptor") == 0 ? 3 : 0;
    local.result = strcmp(mode, "failure") == 0 ? -129 : 0;
    int count = strcmp(mode, "twice") == 0 ? 2 : 1;
    for (int i = 0; i < count; ++i) {
        errno = EDOM;
        int32_t result = AServiceManager_addService(binder, instance);
        printf("FIXTURE returned=%d errno=%d\n", result, errno);
    }
    fixture_dump();
    return 0;
}
