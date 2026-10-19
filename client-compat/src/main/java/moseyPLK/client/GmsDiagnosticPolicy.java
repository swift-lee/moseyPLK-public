package moseyPLK.client;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

/** Version-isolated, host-testable contracts for reviewed GMS builds. */
public final class GmsDiagnosticPolicy {
    public static final String PACKAGE = "com.google.android.gms";
    public static final String SERVICE =
            "com.google.android.gms.nearby.sharing.NearbySharingChimeraService";
    public static final String PROVIDER_VERSION =
            "com.google.android.gms.nearby.sharing.PROVIDER_VERSION";

    private GmsDiagnosticPolicy() {}

    public static boolean applies(String pkg, String process, int uid) {
        return PACKAGE.equals(pkg) && PACKAGE.equals(process) && uid >= 10000 && uid < 100000;
    }

    public static Profile profileFor(long versionCode, String versionName) {
        for (Profile profile : PROFILES) {
            if (profile.versionCode == versionCode && profile.versionName.equals(versionName))
                return profile;
        }
        return null;
    }

    public static final class Profile {
        public final long versionCode;
        public final String versionName;
        private final Spec[] methods;

        private Profile(long versionCode, String versionName, Spec[] methods) {
            this.versionCode = versionCode;
            this.versionName = versionName;
            this.methods = methods.clone();
        }

        public Spec[] specs() { return methods.clone(); }

        public boolean observesClass(String name) {
            for (Spec spec : methods) if (spec.owner.equals(name)) return true;
            return false;
        }

        boolean enables(Spec candidate) {
            // Object identity excludes reconstructed Specs and other builds,
            // even when names/signatures (e.g. lifecycle methods) overlap.
            for (Spec spec : methods) {
                if (spec == candidate) return spec.enableRegistry;
            }
            return false;
        }
    }

    public static boolean moseyProvider(String pkg, String component) {
        return ClientPolicy.PACKAGE.equals(pkg) && ClientPolicy.COMPONENT.equals(component);
    }

    public static final class Spec {
        public final String owner;
        public final String method;
        public final String returns;
        public final boolean isStatic;
        public final String event;
        public final String flag;
        private final String[] parameters;
        private final boolean enableRegistry;

        Spec(String owner, String method, String returns, boolean isStatic,
                String event, String flag, String... parameters) {
            this(owner, method, returns, isStatic, event, flag, false, parameters);
        }

        private Spec(String owner, String method, String returns, boolean isStatic,
                String event, String flag, boolean enableRegistry, String... parameters) {
            this.enableRegistry = enableRegistry;
            this.owner = owner;
            this.method = method;
            this.returns = returns;
            this.isStatic = isStatic;
            this.event = event;
            this.flag = flag;
            this.parameters = parameters.clone();
        }

        public boolean matches(Method candidate) {
            if (!owner.equals(candidate.getDeclaringClass().getName())
                    || !method.equals(candidate.getName())
                    || !returns.equals(candidate.getReturnType().getName())
                    || isStatic != Modifier.isStatic(candidate.getModifiers())) return false;
            Class<?>[] actual = candidate.getParameterTypes();
            if (actual.length != parameters.length) return false;
            for (int i = 0; i < actual.length; ++i) {
                if (!parameters[i].equals(actual[i].getName())) return false;
            }
            return true;
        }

        public String label() { return owner + "." + method; }
    }

    private static Spec gate(String owner, String method, String returns,
            String event, String expression) {
        return new Spec(owner, method, returns, false, event, expression, true);
    }

    // No getters are invoked by this module. These are hooks on natural calls.
    private static final Spec[] LEGACY_SPECS = {
        gate("jpsb", "S", "boolean", "flag_read", "45704091"),
        new Spec("jpsb", "ac", "boolean", false, "flag_read", "45802344"),
        new Spec("jpse", "bd", "boolean", false, "flag_read", "45723015"),
        new Spec("jpse", "bs", "boolean", false, "flag_read", "45824526"),
        // Natural supplier calls expose the value used to seed the service's
        // memoized state even if an inner small getter was inlined by ART.
        gate("eabp", "lr", "java.lang.Object", "flag_read", "45704091"),
        new Spec("eabq", "lr", "java.lang.Object", false, "flag_read", "45723015"),
        new Spec("eabv", "lr", "java.lang.Object", false, "flag_read", "45824526"),
        new Spec("ipqt", "c", "void", false, "registry_start_returned", null),
        new Spec("ipqt", "b", "void", false, "registry_stop_returned", null),
        new Spec("ehmm", "b", "boolean", true, "provider_filter", null,
                "android.content.pm.ServiceInfo", "android.content.Context"),
        new Spec("eice", "a", "int", true, "provider_whitelist", null,
                "android.content.Context", "java.lang.String"),
        new Spec("ehkv", "a", "void", false, "provider_connected", null,
                "android.content.ComponentName", "android.os.IBinder"),
        new Spec("ehkv", "b", "void", false, "provider_disconnected", null,
                "android.content.ComponentName"),
        new Spec("ehkv", "onBindingDied", "void", false, "provider_binding_died", null,
                "android.content.ComponentName"),
        new Spec(SERVICE, "onCreate", "void", false, "nearby_create_returned", null),
        new Spec(SERVICE, "ad", "void", false, "nearby_lifecycle_returned", null, "boolean")
    };

    private static final Spec[] CURRENT_SPECS = {
        gate("jtmb", "W", "boolean", "flag_read", "45704091"),
        new Spec("jtmb", "af", "boolean", false, "flag_read", "45802344"),
        new Spec("jtme", "ba", "boolean", false, "flag_read", "45723015"),
        new Spec("jtme", "bp", "boolean", false, "flag_read", "45824526"),
        // This supplier now computes W() || U(). Its successful false->true
        // fallback has the same boolean outcome as enabling W, but must never
        // be logged as the raw value of W or mutate U / swallow its exception.
        gate("ecyv", "ln", "java.lang.Object", "registry_gate_read", "45704091|45830365"),
        new Spec("ecyw", "ln", "java.lang.Object", false, "flag_read", "45723015"),
        new Spec("ecyy", "ln", "java.lang.Object", false, "flag_read", "45824526"),
        new Spec("isye", "c", "void", false, "registry_start_returned", null),
        new Spec("isye", "b", "void", false, "registry_stop_returned", null),
        new Spec("ekkw", "b", "boolean", true, "provider_filter", null,
                "android.content.pm.ServiceInfo", "android.content.Context"),
        new Spec("elap", "a", "int", true, "provider_whitelist", null,
                "android.content.Context", "java.lang.String"),
        new Spec("ekjf", "a", "void", false, "provider_connected", null,
                "android.content.ComponentName", "android.os.IBinder"),
        new Spec("ekjf", "b", "void", false, "provider_disconnected", null,
                "android.content.ComponentName"),
        new Spec("ekjf", "onBindingDied", "void", false, "provider_binding_died", null,
                "android.content.ComponentName"),
        new Spec(SERVICE, "onCreate", "void", false, "nearby_create_returned", null),
        new Spec(SERVICE, "ad", "void", false, "nearby_lifecycle_returned", null, "boolean"),
        new Spec("jtmb", "U", "boolean", false, "flag_read", "45830365")
    };

    private static final Profile[] PROFILES = {
        new Profile(263332035L, "26.33.32 (260400-974685114)", LEGACY_SPECS),
        new Profile(263436035L, "26.34.36 (260400-981326859)", CURRENT_SPECS)
    };
}
