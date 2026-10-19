package moseyPLK.client;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Process;

import java.io.File;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

/** Phenotype adaptation in one eligible GMS process, without active calls into business code. */
final class GmsAdaptiveRuntime {
    private static final long STARTUP_BUDGET_MS = 2000;
    private final DiagnosticEventLimiter events = new DiagnosticEventLimiter(96, 8);
    private final GmsHookTransaction transaction = new GmsHookTransaction();
    private final ThreadLocal<Boolean> resolvingClass = new ThreadLocal<Boolean>();
    private final Context context;
    private final GmsApkSnapshot snapshot;
    private final String identity;
    private final ResolvedGateSet gates;
    private final HookTelemetry telemetry;
    private final java.util.concurrent.atomic.AtomicBoolean naturalReported =
            new java.util.concurrent.atomic.AtomicBoolean();
    private final java.util.concurrent.atomic.AtomicBoolean airdropDeclaredReported =
            new java.util.concurrent.atomic.AtomicBoolean();
    private Method getter;
    private volatile boolean attempted;

    private GmsAdaptiveRuntime(Context context, GmsApkSnapshot snapshot, String identity,
            ResolvedGateSet gates, HookTelemetry telemetry) {
        this.telemetry = telemetry;
        this.context = context; this.snapshot = snapshot; this.identity = identity; this.gates = gates;
    }

    static void start(final Context context, ClassLoader initialLoader, boolean testMode) {
        final HookTelemetry telemetry = new HookTelemetry(GmsDiagnosticPolicy.PACKAGE);
        telemetry.attach(context);
        final DiagnosticEventLimiter startupEvents = new DiagnosticEventLimiter(24, 4);
        final GmsResolutionTask.Events reporter = new GmsResolutionTask.Events() {
            @Override public void event(String name, String detail) {
                telemetry.event(name, detail); log(startupEvents, name, detail, true);
            }
        };
        try {
            PackageInfo info = packageInfo(context);
            reporter.event("gms_version_advisory", GmsVersionAdvisory.evaluate(info.getLongVersionCode()).detail());
            final String identity = identity(info);
            List<File> splits = new ArrayList<File>();
            if (info.applicationInfo.splitSourceDirs != null)
                for (String split : info.applicationInfo.splitSourceDirs) splits.add(new File(split));
            final GmsApkSnapshot snapshot = new GmsApkSnapshot(
                    new File(info.applicationInfo.sourceDir), splits, GmsModuleIdentity.apk(), identity);
            GmsProfileCache cache = new GmsProfileCache(
                    context.getCodeCacheDir(), GmsResolverBuild.COMPATIBILITY_ID);
            reporter.event("adaptive_start", "rule=" + ResolvedGateSet.RULE_VERSION
                    + " version_code=" + info.getLongVersionCode() + " test=" + testMode
                    + " budget_ms=" + STARTUP_BUDGET_MS);
            GmsResolutionTask task = new GmsResolutionTask(snapshot, cache,
                    new GmsResolutionTask.Resolver() {
                        @Override public ResolvedGateSet resolve() throws Exception {
                            try { GmsModuleIdentity.loadNative(); }
                            catch (Throwable failure) {
                                throw new GmsResolutionFailure.AtStage("native_load", failure);
                            }
                            return GmsAdaptiveResolver.resolve(snapshot.baseApk);
                        }
                    }, reporter);
            GmsResolutionTask.Result result = task.await(STARTUP_BUDGET_MS);
            if (!snapshot.unchanged() || !identity.equals(identity(packageInfo(context))))
                throw new IllegalStateException("package_changed_before_install");
            GmsAdaptiveRuntime runtime = new GmsAdaptiveRuntime(context, snapshot, identity, result.gates, telemetry);
            reporter.event("profile_verified", "source=" + result.source + " expression="
                    + result.gates.expression + " proof=" + result.gates.evidenceDigest.substring(0, 16));
            runtime.watchLoaders();
            runtime.seed(context.getClassLoader());
            if (initialLoader != context.getClassLoader()) runtime.seed(initialLoader);
        } catch (TimeoutException timeout) {
            reporter.event("startup_timeout", "activation=deferred_until_next_natural_process_start");
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            reporter.event("startup_interrupted", "activation=skipped");
        } catch (ExecutionException rejected) {
            // The worker has already emitted exactly one terminal rejection, even if the
            // startup wait would have ended before it. Await never duplicates that report.
        } catch (Throwable failure) {
            reporter.event("adaptive_rejected", reason(failure));
        }
    }

    private void watchLoaders() {
        XC_MethodHook watcher = new XC_MethodHook() {
            @Override protected void afterHookedMethod(MethodHookParam call) {
                if (attempted || Boolean.TRUE.equals(resolvingClass.get()) || call.hasThrowable()
                        || call.args == null || call.args.length == 0 || !(call.args[0] instanceof String)) return;
                String name = (String) call.args[0];
                if (!target(name) || !(call.getResult() instanceof Class<?>)) return;
                observe((Class<?>) call.getResult());
            }
        };
        try { XposedHelpers.findAndHookMethod(ClassLoader.class, "loadClass", String.class, watcher); }
        catch (Throwable failure) { emit("loader_watch_partial", "public " + reason(failure)); }
        try { XposedHelpers.findAndHookMethod(ClassLoader.class, "loadClass", String.class, boolean.class, watcher); }
        catch (Throwable failure) { emit("loader_watch_partial", "protected " + reason(failure)); }
        try {
            Class<?> delegate = Class.forName("dalvik.system.DelegateLastClassLoader", false, null);
            XposedBridge.hookMethod(delegate.getDeclaredMethod("loadClass", String.class, boolean.class), watcher);
        } catch (Throwable failure) { emit("loader_watch_partial", "delegate " + reason(failure)); }
    }

    private boolean target(String name) {
        return name.equals(ResolvedGateSet.owner(gates.getterDescriptor));
    }

    private void seed(ClassLoader loader) {
        if (loader == null) return;
        String name = ResolvedGateSet.owner(gates.getterDescriptor);
        resolvingClass.set(Boolean.TRUE);
        try { observe(Class.forName(name, false, loader)); }
        catch (ClassNotFoundException unavailable) { emit("awaiting_class", "class=" + name); }
        catch (Throwable failure) { emit("class_rejected", reason(failure)); }
        finally { resolvingClass.remove(); }
    }

    private synchronized void observe(Class<?> owner) {
        if (attempted || !target(owner.getName())) return;
        Boolean previous = resolvingClass.get();
        resolvingClass.set(Boolean.TRUE);
        try {
            getter = GmsSourceGuard.method(owner, gates.getterDescriptor, snapshot.baseApk, true);
            if (!snapshot.unchanged() || !identity.equals(identity(packageInfo(context))))
                throw new IllegalStateException("package_changed_before_hooks");
            attempted = true;
            transaction.install(new GmsHookTransaction.Installer() {
                @Override public GmsHookTransaction.Handle install(final int role,
                        final GmsHookTransaction state) {
                    final XC_MethodHook.Unhook unhook = XposedBridge.hookMethod(getter, new XC_MethodHook() {
                        @Override protected void afterHookedMethod(MethodHookParam call) {
                            try {
                                Object original = call.getResult();
                                int argumentCount = call.args == null ? -1 : call.args.length;
                                boolean changed = state.shouldEnable(call.hasThrowable(), original,
                                        argumentCount);
                                if (changed) call.setResult(Boolean.TRUE);
                                emit("natural_result_" + role, "role=getter flag=45704091"
                                        + " throwable=" + call.hasThrowable() + " original="
                                        + (original instanceof Boolean ? original.toString() : "other")
                                        + " enabled=" + changed);
                                reportAirdropDeclaration(call, argumentCount);
                            } catch (Throwable failure) { emit("callback_failed", reason(failure)); }
                        }
                    });
                    if (unhook == null) throw new IllegalStateException("missing_hook_handle");
                    return new GmsHookTransaction.Handle() {
                        @Override public void remove() { unhook.unhook(); }
                    };
                }
            });
            emit("adaptive_hooks_active", "count=1 scope=phenotype flag=45704091 expression=" + gates.expression
                    + " loader=" + Integer.toHexString(System.identityHashCode(owner.getClassLoader())));
        } catch (Throwable failure) {
            attempted = true;
            emit("installation_rejected", reason(failure));
        } finally {
            if (previous == null) resolvingClass.remove(); else resolvingClass.set(previous);
        }
    }

    private static PackageInfo packageInfo(Context context) throws Exception {
        return context.getPackageManager().getPackageInfo(
                GmsDiagnosticPolicy.PACKAGE, PackageManager.GET_SIGNING_CERTIFICATES);
    }

    private static String identity(PackageInfo info) throws Exception {
        if (info.applicationInfo == null || info.applicationInfo.uid != Process.myUid()
                || info.applicationInfo.sourceDir == null || info.signingInfo == null)
            throw new IllegalStateException("package_identity_unavailable");
        String signer = GmsSignerTrust.currentSigner(info.signingInfo);
        MessageDigest sources = GmsApkSnapshot.digest();
        GmsApkSnapshot.update(sources, new File(info.applicationInfo.sourceDir).getCanonicalPath());
        List<String> splits = new ArrayList<String>();
        if (info.applicationInfo.splitSourceDirs != null) {
            for (String split : info.applicationInfo.splitSourceDirs) {
                if (split == null) throw new IllegalStateException("invalid_split_path");
                splits.add(new File(split).getCanonicalPath());
            }
        }
        java.util.Collections.sort(splits);
        GmsApkSnapshot.update(sources, Integer.toString(splits.size()));
        for (String split : splits) GmsApkSnapshot.update(sources, split);
        return GmsDiagnosticPolicy.PACKAGE + "|" + info.applicationInfo.uid + "|"
                + info.getLongVersionCode() + "|" + info.versionName + "|" + info.lastUpdateTime + "|" + signer
                + "|sources=" + GmsApkSnapshot.hex(sources.digest());
    }

    private void emit(String name, String detail) {
        boolean report = !name.startsWith("natural_result_")
                || (transaction.isActive() && naturalReported.compareAndSet(false, true));
        if (report) telemetry.event(name, detail);
        log(events, name, detail, report);
    }
    private void reportAirdropDeclaration(XC_MethodHook.MethodHookParam call, int argumentCount) {
        if (argumentCount == 0 && !call.hasThrowable()
                && Boolean.TRUE.equals(call.getResult())
                && airdropDeclaredReported.compareAndSet(false, true)) {
            emit("airdrop_declared", "scope=phenotype flag=45704091 effective=true");
        }
    }
    private static void log(DiagnosticEventLimiter limiter, String name, String detail, boolean moduleLog) {
        try {
            if (limiter.admit(name, detail)) HookLog.write("MoseyGmsDiag", "event=" + name
                    + " adaptive_rule=" + ResolvedGateSet.RULE_VERSION + " pid=" + Process.myPid()
                    + " uid=" + Process.myUid() + " " + detail, moduleLog);
        } catch (Throwable ignored) { /* Diagnostics cannot alter a natural GMS result. */ }
    }
    private static String reason(Throwable failure) {
        return "reason=" + GmsResolutionFailure.reason(failure);
    }
}
