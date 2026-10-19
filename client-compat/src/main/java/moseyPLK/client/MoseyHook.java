package moseyPLK.client;

import android.app.Application;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.os.IBinder;
import android.os.Process;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/** This class is loaded only by LSPosed; the companion UI does not load it. */
public final class MoseyHook implements IXposedHookLoadPackage {
    private static final String TAG = "MoseyClientCompat";
    private static final AtomicBoolean INSTALLED = new AtomicBoolean();
    private final ScheduledExecutorService worker = Executors.newSingleThreadScheduledExecutor(
            new ThreadFactory() {
                @Override public Thread newThread(Runnable task) {
                    Thread thread = new Thread(task, "MoseyClientCompat");
                    thread.setDaemon(true);
                    return thread;
                }
            });
    private final HookTelemetry telemetry = new HookTelemetry(ClientPolicy.PACKAGE);
    private volatile Context applicationContext;
    private volatile Method checkService;
    private String previousHookReason;
    private String previousPollReason = "not_started";
    private final RecoverySchedule recovery = new RecoverySchedule(
            new RecoverySchedule.Scheduler() {
                @Override public void schedule(Runnable task, long delayMillis) {
                    worker.schedule(task, delayMillis, TimeUnit.MILLISECONDS);
                }
            }, new RecoverySchedule.Attempt() {
                @Override public boolean run() {
                    ClientPolicy.Result<AndroidBinder> result = resolve();
                    previousPollReason = result.reason;
                    if (!result.ready()) return false;
                    event("client_interface_ready", "source=checkService descriptor=verified");
                    boolean completed = recover(result);
                    if (!completed) previousPollReason = "component_pending";
                    return completed;
                }
            }, new RecoverySchedule.Events() {
                @Override public void failed(Throwable failure) {
                    event("worker_failed", "type=" + failure.getClass().getSimpleName());
                }
                @Override public void exhausted(int attempts) {
                    event("recovery_not_ready", "attempts=" + attempts
                            + " reason=" + previousPollReason);
                }
            });

    @Override public void handleLoadPackage(final XC_LoadPackage.LoadPackageParam loaded)
            throws Throwable {
        if (!ClientPolicy.applies(loaded.packageName, loaded.processName)) return;
        if (!INSTALLED.compareAndSet(false, true)) return;
        Class<?> manager = XposedHelpers.findClass("android.os.ServiceManager", null);
        checkService = XposedHelpers.findMethodExact(manager, "checkService", String.class);
        XposedHelpers.findAndHookMethod(manager, "waitForDeclaredService", String.class,
                new XC_MethodHook() {
                    @Override protected void beforeHookedMethod(MethodHookParam call) {
                        String name = (String) call.args[0];
                        if (!ClientPolicy.INSTANCE.equals(name)) return;
                        // Establish the failure result before invoking any helper. A
                        // hook error must not fall through to an indefinite wait.
                        call.setResult(null);
                        try {
                            ClientPolicy.Result<AndroidBinder> result = resolve();
                            // A missing real service is explicitly not ready. No lazy
                            // start, synthetic Binder, or global declaration hook.
                            call.setResult(result.ready() ? result.binder.binder : null);
                            logHookResult(result.reason);
                            if (result.ready()) queueLateRecovery();
                        } catch (Throwable failure) {
                            call.setResult(null);
                            event("lookup_failed", "type=" + failure.getClass().getSimpleName());
                        }
                    }
                });
        XposedHelpers.findAndHookMethod(Application.class, "attach", Context.class,
                new XC_MethodHook() {
                    @Override protected void afterHookedMethod(MethodHookParam call) {
                        try {
                            if (call.hasThrowable()) return;
                            Context context = (Context) call.args[0];
                            if (context == null
                                    || !ClientPolicy.PACKAGE.equals(context.getPackageName())) return;
                            applicationContext = context;
                            telemetry.attach(context);
                            recovery.start();
                        } catch (Throwable failure) {
                            event("attach_failed", "type=" + failure.getClass().getSimpleName());
                        }
                    }
                });
        event("hook_installed", "scope=mosey_main pid=" + Process.myPid()
                + " uid=" + Process.myUid() + " framework=" + XposedBridge.getXposedVersion());
    }

    private ClientPolicy.Result<AndroidBinder> resolve() {
        return ClientPolicy.resolve(ClientPolicy.PACKAGE, ClientPolicy.PACKAGE,
                ClientPolicy.INSTANCE, new ClientPolicy.Lookup<AndroidBinder>() {
                    @Override public AndroidBinder check(String instance) throws Exception {
                        try {
                            IBinder binder = (IBinder) checkService.invoke(null, instance);
                            return binder == null ? null : new AndroidBinder(binder);
                        } catch (InvocationTargetException failure) {
                            // Preserve the failure as a failed gate, never as success.
                            throw new Exception("checkService failed", failure.getCause());
                        }
                    }
                });
    }

    private void queueLateRecovery() {
        if (applicationContext != null) recovery.requestLate();
    }

    @SuppressWarnings("deprecation")
    private boolean recover(ClientPolicy.Result<AndroidBinder> result) {
        Context context = applicationContext;
        if (context == null || !result.ready()) return false;
        ComponentName component = new ComponentName(ClientPolicy.PACKAGE, ClientPolicy.COMPONENT);
        try {
            PackageManager manager = context.getPackageManager();
            ServiceInfo service = manager.getServiceInfo(component,
                    PackageManager.MATCH_DISABLED_COMPONENTS);
            int state = manager.getComponentEnabledSetting(component);
            boolean sameUid = service.applicationInfo != null
                    && service.applicationInfo.uid == Process.myUid();
            if (!ClientPolicy.mayRecover(result, context.getPackageName(),
                    service.packageName, service.name, sameUid, state)) {
                event("component_unchanged", "state=" + state + " same_uid=" + sameUid);
                // Wrong owner/UID and protected states are terminal no-op outcomes.
                // Initial Binder readiness was checked before entering this branch.
                return true;
            }
            // Revalidate immediately before the only persistent operation. This is
            // PackageManager's supported API for this app in this Context's user.
            ClientPolicy.Result<AndroidBinder> fresh = resolve();
            int freshState = manager.getComponentEnabledSetting(component);
            if (!ClientPolicy.mayRecover(fresh, context.getPackageName(),
                    service.packageName, service.name, sameUid, freshState)) {
                event("component_unchanged", "reason=gate_changed state=" + freshState
                        + " binder=" + fresh.reason);
                // A state change to a protected state is a terminal no-op. When
                // state 2 remains, losing the Binder is transient and must retry.
                return freshState != PackageManager.COMPONENT_ENABLED_STATE_DISABLED;
            }
            manager.setComponentEnabledSetting(component,
                    PackageManager.COMPONENT_ENABLED_STATE_ENABLED, PackageManager.DONT_KILL_APP);
            int after = manager.getComponentEnabledSetting(component);
            event(after == PackageManager.COMPONENT_ENABLED_STATE_ENABLED
                            ? "component_recovered" : "component_recovery_pending",
                    "component=ExternalSharingService before=2 after=" + after
                            + " uid=" + Process.myUid());
            // Do not stop on an API call that failed to change state 2. Protected
            // states observed after the call are left alone on subsequent rounds.
            return after != PackageManager.COMPONENT_ENABLED_STATE_DISABLED;
        } catch (Exception failure) {
            event("recovery_failed", "type=" + failure.getClass().getSimpleName());
            return false;
        }
    }

    private synchronized void logHookResult(String reason) {
        if (!reason.equals(previousHookReason)) {
            previousHookReason = reason;
            event("declared_lookup", "instance=google_mosey result=" + reason);
        }
    }

    private void event(String name, String detail) {
        telemetry.event(name, detail);
        try { HookLog.write(TAG, "schema=1 event=" + name + " " + detail); }
        catch (Throwable ignored) { /* Logging cannot crash the injected process. */ }
    }

    private static final class AndroidBinder implements ClientPolicy.BinderHandle {
        final IBinder binder;
        AndroidBinder(IBinder binder) { this.binder = binder; }
        @Override public boolean alive() { return binder.isBinderAlive(); }
        @Override public String descriptor() throws Exception { return binder.getInterfaceDescriptor(); }
    }
}
