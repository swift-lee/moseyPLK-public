package moseyPLK.client;

import android.app.Application;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.ServiceInfo;
import android.os.Process;

import java.lang.reflect.Method;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/** Main-process entry for automatic Phenotype handling; legacy observers remain dormant. */
public final class GmsDiagnosticsHook implements IXposedHookLoadPackage, IXposedHookZygoteInit {
    private static final String TAG = "MoseyGmsDiag";
    private static final AtomicBoolean STARTED = new AtomicBoolean();
    private final DiagnosticEventLimiter events = new DiagnosticEventLimiter(256, 12);
    private final Map<Class<?>, Boolean> observed = new IdentityHashMap<Class<?>, Boolean>();
    private final ThreadLocal<Boolean> installing = new ThreadLocal<Boolean>();
    private final AtomicLong lifecycleSequence = new AtomicLong();
    private final AtomicBoolean attachmentHandled = new AtomicBoolean();
    private volatile GmsDiagnosticPolicy.Profile profile;

    @Override public void initZygote(StartupParam startup) {
        GmsModuleIdentity.record(startup.modulePath);
    }

    @Override public void handleLoadPackage(final XC_LoadPackage.LoadPackageParam loaded)
            throws Throwable {
        if (!GmsDiagnosticPolicy.applies(loaded.packageName, loaded.processName, Process.myUid()))
            return;
        if (!STARTED.compareAndSet(false, true)) return;
        emit("entry", "diagnostic_entry", "mode=phenotype_45704091", "main");
        XposedHelpers.findAndHookMethod(Application.class, "attach", Context.class,
                new XC_MethodHook() {
                    @Override protected void afterHookedMethod(MethodHookParam call) {
                        try {
                            if (call.hasThrowable() || attachmentHandled.get()) return;
                            Context context = (Context) call.args[0];
                            if (context == null || !GmsDiagnosticPolicy.PACKAGE.equals(
                                    context.getPackageName())) return;
                            PackageInfo info = context.getPackageManager().getPackageInfo(
                                    GmsDiagnosticPolicy.PACKAGE, 0);
                            if (info.applicationInfo == null
                                    || info.applicationInfo.uid != Process.myUid()) {
                                emit("build", "unsupported_build", "version_code="
                                        + info.getLongVersionCode() + " observations=skipped", "main");
                                return;
                            }
                            if (!attachmentHandled.compareAndSet(false, true)) return;
                            boolean adaptiveTest = GmsModuleIdentity.forceAdaptive();
                            emit("build", "adaptive_selected", "version_code="
                                    + info.getLongVersionCode() + " test=" + adaptiveTest, "main");
                            GmsAdaptiveRuntime.start(context, loaded.classLoader, adaptiveTest);
                        } catch (Throwable failure) {
                            emit("setup_failure", "setup_failed", type(failure), "main");
                        }
                    }
                });
    }

    private int observedCount() {
        synchronized (observed) { return observed.size(); }
    }

    private void watchLoaders() {
        XC_MethodHook watcher = new XC_MethodHook() {
            @Override protected void afterHookedMethod(MethodHookParam call) {
                try {
                    if (profile == null || Boolean.TRUE.equals(installing.get()) || call.hasThrowable()) return;
                    if (call.args.length == 0 || !(call.args[0] instanceof String)
                            || !profile.observesClass((String) call.args[0])) return;
                    Object result = call.getResult();
                    if (result instanceof Class<?>) observe((Class<?>) result);
                } catch (Throwable failure) {
                    emit("loader_callback", "observer_failed", type(failure), "main");
                }
            }
        };
        try {
            XposedHelpers.findAndHookMethod(ClassLoader.class, "loadClass", String.class, watcher);
        } catch (Throwable failure) {
            emit("loader_setup:public", "loader_watch_partial", "method=ClassLoader.loadClass/1 "
                    + type(failure), "main");
        }
        try {
            XposedHelpers.findAndHookMethod(ClassLoader.class, "loadClass", String.class,
                    boolean.class, watcher);
        } catch (Throwable failure) {
            emit("loader_setup:protected", "loader_watch_partial", "method=ClassLoader.loadClass/2 "
                    + type(failure), "main");
        }
        try {
            // DelegateLastClassLoader can bypass the base protected implementation.
            Class<?> delegate = Class.forName("dalvik.system.DelegateLastClassLoader", false, null);
            Method method = delegate.getDeclaredMethod("loadClass", String.class, boolean.class);
            XposedBridge.hookMethod(method, watcher);
        } catch (Throwable failure) {
            emit("loader_setup:delegate", "loader_watch_partial", "method=DelegateLastClassLoader.loadClass/2 "
                    + type(failure), "main");
        }
    }

    private void seed(ClassLoader loader) {
        if (profile == null || loader == null) return;
        installing.set(Boolean.TRUE);
        try {
            for (GmsDiagnosticPolicy.Spec spec : profile.specs()) {
                try {
                    // Resolve existing APK types without running <clinit>, getters,
                    // constructors, service lifecycle methods, or Binder operations.
                    observe(Class.forName(spec.owner, false, loader));
                } catch (ClassNotFoundException missing) {
                    emit("missing:" + spec.owner, "awaiting_class", "class=" + spec.owner,
                            loaderId(loader));
                } catch (Throwable failure) {
                    emit("class:" + spec.owner, "class_unavailable", "class=" + spec.owner
                            + " " + type(failure), loaderId(loader));
                }
            }
        } finally {
            installing.remove();
        }
    }

    private void observe(Class<?> owner) {
        if (profile == null || !profile.observesClass(owner.getName())) return;
        synchronized (observed) {
            if (observed.containsKey(owner)) return;
        }
        Boolean prior = installing.get();
        installing.set(Boolean.TRUE);
        try {
            Method[] methods = owner.getDeclaredMethods();
            synchronized (observed) {
                if (observed.containsKey(owner)) return;
                if (observed.size() >= 48) {
                    emit("class_limit", "class_limit_reached", "limit=48", "main");
                    return;
                }
                // Reflection can fail while dependent types are unavailable.
                // Do not permanently consume this class before reflection works.
                // Claim it once before installing any hooks to avoid duplicates.
                observed.put(owner, Boolean.TRUE);
            }
            for (final GmsDiagnosticPolicy.Spec spec : profile.specs()) {
                if (!spec.owner.equals(owner.getName())) continue;
                Method target = null;
                for (Method candidate : methods) if (spec.matches(candidate)) target = candidate;
                final String loader = loaderId(owner.getClassLoader());
                if (target == null) {
                    emit("signature:" + spec.label(), "signature_mismatch", "method=" + spec.label(), loader);
                    continue;
                }
                try {
                    XposedBridge.hookMethod(target, new XC_MethodHook() {
                        @Override protected void afterHookedMethod(MethodHookParam call) {
                            try { record(spec, call, loader); }
                            catch (Throwable failure) {
                                emit("callback:" + spec.label(), "observer_failed",
                                        "method=" + spec.label() + " " + type(failure), loader);
                            }
                            try { enableRegistry(spec, call, loader); }
                            catch (Throwable failure) {
                                emit("enable:" + spec.label(), "registry_gate_failed",
                                        "method=" + spec.label() + " " + type(failure), loader);
                            }
                        }
                    });
                    emit("hook:" + spec.label(), "observation_installed", "method=" + spec.label(), loader);
                } catch (Throwable failure) {
                    emit("hook:" + spec.label(), "hook_failed", "method=" + spec.label()
                            + " " + type(failure), loader);
                }
            }
        } finally {
            if (prior == null) installing.remove(); else installing.set(prior);
        }
    }

    private void enableRegistry(GmsDiagnosticPolicy.Spec spec,
            XC_MethodHook.MethodHookParam call, String loader) {
        if (call.args == null || call.args.length != 0
                || !GmsRegistryEnablement.shouldEnable(
                        profile, spec, call.hasThrowable(), call.getResult())) return;
        // Change only this build's natural getter/supplier results. The current
        // supplier is W || U; changing its successful false to true is a result
        // fallback for enabling W, not a call to either getter or registry.
        // Preserve exceptions, U and all provider filtering results.
        call.setResult(Boolean.TRUE);
        String instance = call.thisObject == null ? "static" : identity(call.thisObject);
        String source = "registry_gate_read".equals(spec.event)
                ? "gate=45704091 expression=" + spec.flag : "flag=45704091";
        emit("enable:" + spec.label() + ":" + instance, "registry_gate_applied",
                "method=" + spec.label() + " " + source + " original=false effective=true", loader);
    }

    private void record(GmsDiagnosticPolicy.Spec spec, XC_MethodHook.MethodHookParam call,
            String loader) {
        String detail = "method=" + spec.label();
        String instance = call.thisObject == null ? "static" : identity(call.thisObject);
        if ("provider_filter".equals(spec.event)) {
            ServiceInfo info = (ServiceInfo) call.args[0];
            if (info == null || !GmsDiagnosticPolicy.moseyProvider(info.packageName, info.name)) return;
            detail += " provider=mosey enabled=" + info.enabled + " exported=" + info.exported;
            if (info.metaData != null) detail += " provider_version="
                    + info.metaData.getInt(GmsDiagnosticPolicy.PROVIDER_VERSION, -1);
        } else if ("provider_whitelist".equals(spec.event)) {
            if (!ClientPolicy.PACKAGE.equals(call.args[1])) return;
            detail += " provider=mosey";
        } else if (spec.event.startsWith("provider_")) {
            ComponentName component = (ComponentName) call.args[0];
            if (component == null || !GmsDiagnosticPolicy.moseyProvider(
                    component.getPackageName(), component.getClassName())) return;
            detail += " provider=mosey";
            if ("provider_connected".equals(spec.event)) detail += " binder_present=" + (call.args[1] != null);
        }
        if (call.hasThrowable()) {
            detail += " threw=" + call.getThrowable().getClass().getSimpleName();
        } else if (spec.flag != null) {
            Object value = call.getResult();
            detail += ("registry_gate_read".equals(spec.event) ? " expression=" : " flag=")
                    + spec.flag + " value="
                    + (value instanceof Boolean ? ((Boolean) value).toString() : "unexpected_type");
        } else if ("boolean".equals(spec.returns) || "int".equals(spec.returns)) {
            Object value = call.getResult();
            detail += " result=" + (value instanceof Boolean || value instanceof Integer
                    ? value.toString() : "unexpected_type");
        } else {
            detail += " returned=true";
        }
        if ("nearby_lifecycle_returned".equals(spec.event)) {
            Object argument = call.args[0];
            detail += " argument=" + (argument instanceof Boolean
                    ? ((Boolean) argument).toString() : "unexpected_type");
        }
        if ("void".equals(spec.returns)) {
            // A registry can start, stop and start again using the same instance.
            // Preserve repeated lifecycle callbacks; the existing per-key budget
            // still caps their volume. The sequence is local diagnostic state.
            detail += " sequence=" + lifecycleSequence.incrementAndGet();
        }
        emit(spec.label() + ":" + instance, spec.event, detail, loader);
    }

    private static String identity(Object value) {
        return Integer.toHexString(System.identityHashCode(value));
    }

    private static String loaderId(ClassLoader loader) {
        return loader == null ? "boot" : identity(loader);
    }

    private static String type(Throwable failure) {
        return "type=" + failure.getClass().getSimpleName();
    }

    private void emit(String key, String event, String fields, String loader) {
        try {
            if (events.admit(loader + ":" + key, event + " " + fields)) {
                HookLog.write(TAG, "schema=1 event=" + event + " pid=" + Process.myPid()
                        + " uid=" + Process.myUid() + " loader=" + loader + " " + fields);
            }
        } catch (Throwable ignored) {
            // Observability must not replace a result or exception in the host app.
        }
    }
}
