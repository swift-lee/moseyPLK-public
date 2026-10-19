#include "fixture_binder.h"
#include "identity.h"

#include <errno.h>
#include <stdio.h>

static int adds, remotes, classes, descriptors, downgrades;
static int order_error;

#ifndef OMIT_ADD
int32_t AServiceManager_addService(AIBinder *binder, const char *instance) {
    ++adds;
    if (downgrades > adds) order_error = 1;
    printf("FIXTURE event=add sequence=%d downgraded=%d\n", adds, downgrades);
    errno = EBUSY;
    return binder == NULL || instance == NULL ? -3 : binder->result;
}
#endif
#ifndef OMIT_REMOTE
bool AIBinder_isRemote(const AIBinder *binder) {
    ++remotes;
    return binder->remote != 0;
}
#endif
#ifndef OMIT_CLASS
const AIBinder_Class *AIBinder_getClass(AIBinder *binder) {
    static const AIBinder_Class good = {MOSEY_REGCOMPAT_DESCRIPTOR};
    static const AIBinder_Class bad = {"other.IFoo"};
    static const AIBinder_Class empty = {NULL};
    ++classes;
    if (binder->class_mode == 2) return NULL;
    return binder->class_mode == 1 ? &bad : binder->class_mode == 3 ? &empty : &good;
}
#endif
#ifndef OMIT_DESCRIPTOR
const char *AIBinder_Class_getDescriptor(const AIBinder_Class *clazz) {
    ++descriptors;
    return clazz->descriptor;
}
#endif
#ifndef OMIT_DOWNGRADE
void AIBinder_forceDowngradeToSystemStability(AIBinder *binder) {
    ++downgrades;
    if (binder == NULL || binder->remote != 0 || binder->class_mode != 0 || downgrades != adds + 1)
        order_error = 1;
    printf("FIXTURE event=downgrade sequence=%d\n", downgrades);
}
#endif
void fixture_dump(void) {
    printf("FIXTURE adds=%d remotes=%d classes=%d descriptors=%d downgrades=%d order_error=%d\n",
           adds, remotes, classes, descriptors, downgrades, order_error);
}
