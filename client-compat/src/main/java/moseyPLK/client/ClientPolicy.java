package moseyPLK.client;

/** Android-independent gate: never manufacture a Binder or a declaration. */
public final class ClientPolicy {
    public static final String PACKAGE = "com.google.android.mosey";
    public static final String INSTANCE = "com.google.android.moseyservice.IMoseyService/default";
    public static final String DESCRIPTOR = "com.google.android.moseyservice.IMoseyService";
    public static final String COMPONENT = "com.google.android.mosey.ExternalSharingService";
    public static final int EXPLICITLY_DISABLED = 2;
    public static final int MAX_ATTEMPTS = 30;
    public static final long RETRY_MILLIS = 2000L;

    private ClientPolicy() {}

    public interface BinderHandle {
        boolean alive();
        String descriptor() throws Exception;
    }

    public interface Lookup<T extends BinderHandle> {
        T check(String instance) throws Exception;
    }

    public static final class Result<T extends BinderHandle> {
        public final boolean targeted;
        public final T binder;
        public final String reason;

        private Result(boolean targeted, T binder, String reason) {
            this.targeted = targeted;
            this.binder = binder;
            this.reason = reason;
        }

        public boolean ready() { return targeted && binder != null; }
    }

    public static boolean applies(String packageName, String processName) {
        return PACKAGE.equals(packageName) && PACKAGE.equals(processName);
    }

    public static <T extends BinderHandle> Result<T> resolve(
            String packageName, String processName, String instance, Lookup<T> lookup) {
        if (!applies(packageName, processName) || !INSTANCE.equals(instance)) {
            return new Result<T>(false, null, "outside_scope");
        }
        try {
            T binder = lookup.check(INSTANCE);
            if (binder == null) return new Result<T>(true, null, "absent");
            if (!binder.alive()) return new Result<T>(true, null, "dead");
            if (!DESCRIPTOR.equals(binder.descriptor())) {
                return new Result<T>(true, null, "descriptor_mismatch");
            }
            // The descriptor query may race a process death. Recheck the handle.
            if (!binder.alive()) return new Result<T>(true, null, "died_during_check");
            return new Result<T>(true, binder, "ready");
        } catch (Exception failure) {
            return new Result<T>(true, null, "lookup_failed");
        }
    }

    public static boolean mayRecover(Result<?> result, String contextPackage,
            String componentPackage, String componentClass, boolean sameUid, int state) {
        return result != null && result.ready() && PACKAGE.equals(contextPackage)
                && PACKAGE.equals(componentPackage) && COMPONENT.equals(componentClass)
                && sameUid && state == EXPLICITLY_DISABLED;
    }
}
