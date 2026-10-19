package moseyPLK.client;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.os.Process;
import android.os.SystemClock;
import android.provider.Settings;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

/** No file I/O, root command, or IPC in an injected callback. */
final class HookTelemetry {
    private final HookStateStore state;
    private final String target;
    private final ScheduledExecutorService writer = Executors.newSingleThreadScheduledExecutor(
            new ThreadFactory() {
                @Override public Thread newThread(Runnable task) {
                    Thread thread = new Thread(task, "MoseyHookState"); thread.setDaemon(true); return thread;
                }
            });
    private File directory;
    private boolean attached, queued;
    private final java.util.concurrent.atomic.AtomicBoolean failureReported =
            new java.util.concurrent.atomic.AtomicBoolean();

    HookTelemetry(String target) { this.target = target; state = new HookStateStore(target); }

    void attach(final Context context) {
        try {
            synchronized (this) { if (attached) return; attached = true; }
            writer.execute(new Runnable() {
                @Override public void run() {
                    try {
                        PackageInfo info = context.getPackageManager().getPackageInfo(target, 0);
                        if (info.applicationInfo == null || info.applicationInfo.uid != Process.myUid()) return;
                        Map<String, Object> identity = new LinkedHashMap<String, Object>();
                        identity.put("userId", Process.myUid() / 100000);
                        identity.put("uid", Process.myUid()); identity.put("pid", Process.myPid());
                        identity.put("starttime", processStarttime());
                        identity.put("bootCount", Settings.Global.getInt(context.getContentResolver(),
                                Settings.Global.BOOT_COUNT, -1));
                        String bootId = "";
                        try { bootId = read(new File("/proc/sys/kernel/random/boot_id")); }
                        catch (Exception unavailable) { /* Boot count and process identity remain mandatory. */ }
                        identity.put("bootId", bootId);
                        identity.put("targetVersionName", info.versionName == null ? "" : info.versionName);
                        identity.put("targetVersionCode", info.getLongVersionCode());
                        identity.put("targetLastUpdateTime", info.lastUpdateTime);
                        identity.put("moduleVersion", ModuleBuild.VERSION);
                        identity.put("moduleVersionCode", ModuleBuild.VERSION_CODE);
                        identity.put("moduleBuildId", ModuleBuild.BUILD_ID);
                        identity.put("moduleVariant", ModuleBuild.VARIANT);
                        state.identity(identity);
                        synchronized (HookTelemetry.this) { directory = context.getCodeCacheDir(); }
                        schedule();
                    } catch (Throwable failure) {
                        reportFailure("snapshot_identity_unavailable", failure);
                    }
                }
            });
        } catch (Throwable ignored) { }
    }

    void event(String name, String detail) {
        try { state.event(name, detail); schedule(); } catch (Throwable ignored) { }
    }

    private synchronized void schedule() {
        if (directory == null || queued) return;
        queued = true;
        try {
            writer.schedule(new Runnable() {
                @Override public void run() {
                    File destination;
                    synchronized (HookTelemetry.this) { queued = false; destination = directory; }
                    try { HookStateStore.write(destination, state.snapshot(SystemClock.elapsedRealtime())); }
                    catch (Throwable failure) {
                        reportFailure("snapshot_write_unavailable", failure);
                    }
                }
            }, 100, TimeUnit.MILLISECONDS);
        } catch (Throwable ignored) { queued = false; }
    }

    private void reportFailure(String event, Throwable failure) {
        if (failureReported.compareAndSet(false, true))
            HookLog.write("MoseyHookState", "event=" + event + " type=" + failure.getClass().getSimpleName());
    }

    private static long processStarttime() throws Exception {
        String stat = read(new File("/proc/self/stat"));
        int end = stat.lastIndexOf(')');
        if (end < 0) throw new IllegalStateException("invalid_proc_stat");
        String[] fields = stat.substring(end + 1).trim().split("\\s+");
        if (fields.length <= 19) throw new IllegalStateException("short_proc_stat");
        return Long.parseLong(fields[19]);
    }

    private static String read(File file) throws Exception {
        byte[] bytes = Files.readAllBytes(file.toPath());
        if (bytes.length > 8192) throw new IllegalStateException("oversize_proc_file");
        return new String(bytes, StandardCharsets.UTF_8).trim();
    }
}
