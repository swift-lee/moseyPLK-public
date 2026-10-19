#define _GNU_SOURCE
#include "identity.h"

#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Public NDK ABI types; platform-only manager/stability declarations are not
 * distributed with the app NDK. Resolve them only from the already loaded
 * system libbinder_ndk; the launcher does not link that library. */
#ifdef __ANDROID__
#include <android/binder_ibinder.h>
#include <android/binder_status.h>
_Static_assert(sizeof(binder_exception_t) == sizeof(int32_t), "NDK exception ABI");
_Static_assert(EX_ILLEGAL_STATE == -5, "NDK exception constant");
#else
typedef struct AIBinder AIBinder;
typedef struct AIBinder_Class AIBinder_Class;
typedef int32_t binder_exception_t;
#define EX_ILLEGAL_STATE (-5)
#endif

typedef binder_exception_t (*add_service_fn)(AIBinder *, const char *);
typedef bool (*is_remote_fn)(const AIBinder *);
typedef void (*downgrade_fn)(AIBinder *);
typedef const AIBinder_Class *(*get_class_fn)(AIBinder *);
typedef const char *(*get_descriptor_fn)(const AIBinder_Class *);

static pthread_once_t resolve_once = PTHREAD_ONCE_INIT;
static add_service_fn original_add;
static is_remote_fn original_remote;
static downgrade_fn original_downgrade;
static get_class_fn original_class;
static get_descriptor_fn original_descriptor;
static const char *resolve_reason = "unresolved";
static const char *verified_library;
static const char own_origin_marker = 0;

/* One bounded write fits PIPE_BUF. No files, log daemon, or successful-load
 * claims from launcher context; the ksu parent is the only file log writer. */
static void diagnostic(const char *event, const char *format, ...) {
    int saved_errno = errno;
    char line[1024];
    int prefix = snprintf(line, sizeof(line), "MOSEY_REGCOMPAT pid=%jd event=%s ",
                          (intmax_t)getpid(), event);
    if (prefix > 0 && (size_t)prefix < sizeof(line)) {
        va_list arguments;
        va_start(arguments, format);
        int tail = vsnprintf(line + prefix, sizeof(line) - (size_t)prefix, format, arguments);
        va_end(arguments);
        if (tail >= 0 && (size_t)tail < sizeof(line) - (size_t)prefix - 1) {
            size_t length = (size_t)prefix + (size_t)tail;
            line[length++] = '\n';
            ssize_t result;
            do { result = write(STDERR_FILENO, line, length); } while (result < 0 && errno == EINTR);
            (void)result; /* Missing/partial logs can never count as verified success. */
        }
    }
    errno = saved_errno;
}

static int enabled(void) {
    const char *value = getenv("MOSEY_REGISTRATION_COMPAT");
    return value != NULL && strcmp(value, "1") == 0;
}

static int own_origin_expected(void) {
    Dl_info origin = {0};
    return dladdr(&own_origin_marker, &origin) != 0 && origin.dli_fname != NULL &&
        strcmp(origin.dli_fname, MOSEY_REGCOMPAT_EXPECTED_LIBRARY) == 0;
}

__attribute__((constructor)) static void loaded(void) {
    /* Deliberately no binder calls or dlsym here. LD_PRELOAD also loads this
     * object in the original launcher before its UID/capability transition. */
    if (enabled() && regcompat_target_executable())
        diagnostic("loaded", "schema=1 experiment=registration_only origin_expected=%d", own_origin_expected());
}

static void *next_symbol(const char *name, const char *version, Dl_info *origin) {
    (void)dlerror();
    void *symbol = dlvsym(RTLD_NEXT, name, version);
    if (symbol == NULL || dlerror() != NULL || dladdr(symbol, origin) == 0 ||
        origin->dli_fname == NULL || strcmp(origin->dli_fname, MOSEY_REGCOMPAT_BINDER_LIBRARY) != 0)
        return NULL;
    return symbol;
}

static void resolve(void) {
    Dl_info add_origin = {0}, remote_origin = {0}, downgrade_origin = {0};
    Dl_info class_origin = {0}, descriptor_origin = {0};
    void *symbol = next_symbol("AServiceManager_addService", "LIBBINDER_NDK", &add_origin);
    _Static_assert(sizeof(original_add) == sizeof(symbol), "POSIX dlsym pointer ABI");
    if (symbol == NULL) { resolve_reason = "add_symbol_or_origin"; return; }
    memcpy(&original_add, &symbol, sizeof(original_add));
    symbol = next_symbol("AIBinder_isRemote", "LIBBINDER_NDK", &remote_origin);
    if (symbol == NULL || remote_origin.dli_fbase != add_origin.dli_fbase) {
        resolve_reason = "remote_symbol_or_origin";
        return;
    }
    memcpy(&original_remote, &symbol, sizeof(original_remote));
    symbol = next_symbol("AIBinder_getClass", "LIBBINDER_NDK", &class_origin);
    if (symbol == NULL || class_origin.dli_fbase != add_origin.dli_fbase) {
        resolve_reason = "class_symbol_or_origin";
        return;
    }
    memcpy(&original_class, &symbol, sizeof(original_class));
    symbol = next_symbol("AIBinder_Class_getDescriptor", "LIBBINDER_NDK31", &descriptor_origin);
    if (symbol == NULL || descriptor_origin.dli_fbase != add_origin.dli_fbase) {
        resolve_reason = "descriptor_symbol_or_origin";
        return;
    }
    memcpy(&original_descriptor, &symbol, sizeof(original_descriptor));
    symbol = next_symbol("AIBinder_forceDowngradeToSystemStability", "LIBBINDER_NDK31", &downgrade_origin);
    if (symbol == NULL || downgrade_origin.dli_fbase != add_origin.dli_fbase) {
        resolve_reason = "downgrade_symbol_or_origin";
        return;
    }
    memcpy(&original_downgrade, &symbol, sizeof(original_downgrade));
    verified_library = add_origin.dli_fname;
    resolve_reason = "ok";
}

__attribute__((visibility("default")))
binder_exception_t AServiceManager_addService(AIBinder *binder, const char *instance) {
    int caller_errno = errno;
    int target = instance != NULL && strcmp(instance, MOSEY_REGCOMPAT_INSTANCE) == 0;
    int opted_in = enabled();
    (void)pthread_once(&resolve_once, resolve);
    if (!target || !opted_in || !regcompat_target_executable()) {
        /* Outside the explicitly selected experiment, preserve the platform
         * operation exactly. No remote/class query or diagnostic success. */
        if (original_add == NULL) {
            diagnostic("blocked", "reason=%s scope=passthrough", resolve_reason);
            errno = caller_errno;
            return EX_ILLEGAL_STATE;
        }
        errno = caller_errno;
        return original_add(binder, instance);
    }
    struct regcompat_identity identity;
    regcompat_read_identity(&identity);
    const char *identity_reason = regcompat_identity_reason(&identity);
    int identity_ok = strcmp(identity_reason, "ok") == 0;
    diagnostic("intercept", "target=%d enabled=%d binder_nonnull=%d", target, opted_in, binder != NULL);
    diagnostic("identity", "ok=%d reason=%s read_errors=%u", identity_ok, identity_reason, identity.read_errors);
    if (original_add == NULL) {
        diagnostic("blocked", "reason=%s", resolve_reason);
        diagnostic("add_result", "target=1 downgraded=0 called=0 code=%d source=shim", EX_ILLEGAL_STATE);
        errno = caller_errno;
        return EX_ILLEGAL_STATE;
    }
    int downgraded = 0;
    const char *blocked = !own_origin_expected() ? "self_origin" :
        !identity_ok ? identity_reason : binder == NULL ? "null_binder" :
        original_downgrade == NULL ? resolve_reason : NULL;
    if (blocked == NULL) diagnostic("api", "source=%s verified=1", verified_library);
    if (blocked == NULL && original_remote(binder)) blocked = "remote_binder";
    if (blocked == NULL) {
        const AIBinder_Class *clazz = original_class(binder);
        if (clazz == NULL) blocked = "null_class";
        else {
            const char *descriptor = original_descriptor(clazz);
            if (descriptor == NULL || strcmp(descriptor, MOSEY_REGCOMPAT_DESCRIPTOR) != 0)
                blocked = "descriptor_mismatch";
        }
    }
    if (blocked == NULL) {
        diagnostic("binder", "local=1 descriptor=1");
        diagnostic("downgrade", "phase=begin target=1 to=system");
        original_downgrade(binder);
        downgraded = 1;
        /* void API: returned is observed; it is not an independent readback. */
        diagnostic("downgrade", "phase=returned target=1 to=system");
    } else {
        diagnostic("blocked", "reason=%s", blocked);
        diagnostic("add_result", "target=1 downgraded=0 called=0 code=%d source=shim", EX_ILLEGAL_STATE);
        errno = caller_errno;
        return EX_ILLEGAL_STATE;
    }
    errno = caller_errno;
    binder_exception_t result = original_add(binder, instance); /* Exactly once, no retry. */
    int result_errno = errno;
    diagnostic("add_result", "target=%d downgraded=%d called=1 code=%" PRId32 " source=platform",
               target, downgraded, (int32_t)result);
    errno = result_errno;
    return result;
}
