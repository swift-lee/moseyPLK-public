package moseyPLK.client;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Process;
import android.util.Log;
import de.robv.android.xposed.XposedBridge;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.LinkedHashMap;
import java.util.Map;

/** Executes the actual writer, reducer, logger and async Android adapter using host fakes. */
public final class HookStateTest {
    private static int assertions;
    private static void check(boolean value, String message) {
        assertions++; if (!value) throw new AssertionError(message);
    }
    private static String json(HookStateStore state) throws Exception {
        return new String(state.snapshot(123), StandardCharsets.UTF_8);
    }
    private static void reducer() throws Exception {
        HookStateStore state = new HookStateStore("com.google.android.gms");
        check(json(state).contains("\"naturalHit\":false"), "unknown process never implies hit");
        check(json(state).contains("\"airdropDeclaration\":\"unconfirmed\""),
                "new process begins with no AirDrop declaration evidence");
        state.event("natural_result_0", "too early");
        check(json(state).contains("\"naturalHit\":false"), "natural event waits for installation publication");
        state.event("adaptive_start", "start");
        check(json(state).contains("\"resolution\":\"resolving\""), "start separate from installation");
        state.event("resolution_complete", "late cache success");
        check(json(state).contains("\"installation\":\"pending\""), "worker result not installation");
        state.event("startup_timeout", "not installed");
        state.event("resolution_complete", "late success");
        state.event("profile_verified", "late success");
        state.event("adaptive_hooks_active", "late success");
        check(json(state).contains("\"resolution\":\"timeout\""), "late success preserves timeout");
        check(json(state).contains("\"workerResolution\":\"verified\""), "late worker evidence retained");
        check(json(state).contains("\"installation\":\"inactive\""), "late events cannot imply activation");
        state.event("resolution_rejected", "late rejected");
        check(json(state).contains("\"resolution\":\"timeout\""), "late rejection also preserves timeout");
        HookStateStore raced = new HookStateStore("com.google.android.gms");
        raced.event("natural_result_0", "callback races installer publication");
        raced.event("airdrop_declared", "callback races installer publication");
        raced.event("adaptive_hooks_active", "count=1");
        check(json(raced).contains("\"naturalHit\":true"), "first callback survives installation publication race");
        check(json(raced).contains("\"airdropDeclaration\":\"declared\""),
                "declaration survives installation publication race");
        raced.event("installation_rejected", "late unrelated event");
        raced.event("adaptive_start", "late unrelated event");
        check(json(raced).contains("\"airdropDeclaration\":\"declared\""),
                "AirDrop declaration is monotonic for a process snapshot");
        HookStateStore active = new HookStateStore("com.google.android.gms");
        active.event("profile_verified", "proof"); active.event("adaptive_hooks_active", "count=1");
        active.event("natural_result_0", "original=false enabled=true");
        check(json(active).contains("\"naturalHit\":true"), "active natural hit recorded");
        HookStateStore mosey = new HookStateStore("com.google.android.mosey");
        mosey.event("hook_installed", ""); mosey.event("client_interface_ready", "");
        mosey.event("component_recovered", "");
        check(json(mosey).contains("\"resolution\":\"not_applicable\""), "Mosey has no GMS resolver");
        check(json(mosey).contains("\"componentRestore\":\"restored\""), "component result recorded");
        mosey.event("declared_lookup", "instance=google_mosey result=dead");
        check(json(mosey).contains("\"binderReady\":\"unavailable\""), "latest failed Binder overrides ready");
        mosey.event("declared_lookup", "instance=google_mosey result=ready");
        check(json(mosey).contains("\"binderReady\":\"ready\""), "real matching Binder recorded");
    }
    private static void writer(Path directory) throws Exception {
        HookStateStore state = new HookStateStore("com.google.android.gms");
        state.event("quoted\"name", "line1\nline2\\");
        byte[] bytes = state.snapshot(234);
        check(new String(bytes, StandardCharsets.UTF_8).contains("line1\\u000aline2\\\\"), "JSON escaping");
        HookStateStore.write(directory.toFile(), bytes);
        Path path = directory.resolve(HookStateStore.FILE_NAME);
        check(Files.getPosixFilePermissions(path).equals(PosixFilePermissions.fromString("rw-------")), "0600");
        check(java.util.Arrays.equals(Files.readAllBytes(path), bytes), "exact atomic bytes");
        state.event("new", "new"); HookStateStore.write(directory.toFile(), state.snapshot(235));
        check(new String(Files.readAllBytes(path), StandardCharsets.UTF_8).contains("\"lastEvent\":\"new\""), "replacement");
        try { HookStateStore.write(directory.toFile(), new byte[HookStateStore.MAX_BYTES + 1]);
            throw new AssertionError("oversize accepted"); } catch (IOException expected) { assertions++; }
        Path external = directory.resolve("external"); Files.write(external, new byte[]{1});
        Files.delete(path); Files.createSymbolicLink(path, external);
        try { HookStateStore.write(directory.toFile(), bytes); throw new AssertionError("symlink accepted"); }
        catch (IOException expected) { assertions++; }
        check(Files.readAllBytes(external)[0] == 1, "symlink target unchanged");
        Files.delete(path);
        Path link = directory.resolve("cache-link"); Files.createSymbolicLink(link, directory);
        try { HookStateStore.write(link.toFile(), bytes); throw new AssertionError("parent link accepted"); }
        catch (IOException expected) { assertions++; }
        StringBuilder huge = new StringBuilder(); for (int i=0; i<20000; i++) huge.append('x');
        state.event(huge.toString(), huge.toString());
        check(state.snapshot(236).length < HookStateStore.MAX_BYTES, "diagnostic strings are bounded");
    }
    private static void adapter(Path directory) throws Exception {
        final Thread caller = Thread.currentThread();
        final PackageInfo suppliedInfo = new PackageInfo(); suppliedInfo.applicationInfo = new ApplicationInfo();
        suppliedInfo.applicationInfo.uid = Process.myUid(); suppliedInfo.versionName = "26.36.33 (260400-986028547)";
        suppliedInfo.versionCode = 263633035L; suppliedInfo.lastUpdateTime = 99;
        Context context = new Context(); context.codeCache = directory.toFile();
        context.packages = new PackageManager() {
            @Override public PackageInfo getPackageInfo(String name, int flags) {
                if (Thread.currentThread() == caller) throw new AssertionError("synchronous IPC");
                if (!name.equals("com.google.android.gms") || flags != 0) throw new AssertionError("identity query");
                return suppliedInfo;
            }
        };
        HookTelemetry telemetry = new HookTelemetry("com.google.android.gms");
        telemetry.event("adaptive_start", "pending before attach"); telemetry.attach(context);
        telemetry.event("profile_verified", "proof"); telemetry.event("adaptive_hooks_active", "count=1");
        telemetry.event("natural_result_0", "original=false enabled=true");
        telemetry.event("airdrop_declared", "scope=phenotype flag=45704091 effective=true");
        Path path = directory.resolve(HookStateStore.FILE_NAME);
        long deadline = System.nanoTime() + 3000000000L;
        while (!Files.exists(path) && System.nanoTime() < deadline) Thread.sleep(10);
        check(Files.exists(path), "async adapter publishes without caller I/O: " + Log.lines);
        String value = new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
        check(value.contains("\"targetVersionCode\":263633035"), "target code captured");
        check(value.contains("\"targetLastUpdateTime\":99"), "target update identity captured");
        check(value.contains("\"moduleVersion\":\"0.6.0\""), "compiled module version captured");
        check(value.contains("\"moduleBuildId\":\"host-test\""), "compiled build identity captured");
        check(value.contains("\"bootCount\":1") && value.contains("\"starttime\":"), "process lifetime identity");
        check(value.contains("\"naturalHit\":true"), "early events merged with async identity");
        check(value.contains("\"airdropDeclaration\":\"declared\""),
                "AirDrop declaration included in async snapshot");
        check(Files.getPosixFilePermissions(path).equals(PosixFilePermissions.fromString("rw-------")), "async 0600");
        Files.write(directory.resolve("adapter-result.json"), value.getBytes(StandardCharsets.UTF_8));
    }
    private static void logging() throws Exception {
        Log.reset(); XposedBridge.reset(); Log.fail = true;
        HookLog.write("HookTest", "event=entry");
        long deadline = System.nanoTime() + 2000000000L;
        while (XposedBridge.logLines.isEmpty() && System.nanoTime() < deadline) Thread.sleep(10);
        check(XposedBridge.logLines.size() == 1, "LSPosed receives despite logcat failure");
        check(XposedBridge.logLines.get(0).contains("[moseyPLK.client]"), "LSPosed module label");
        Log.fail = false; XposedBridge.failLog = true;
        HookLog.write("HookTest", "event=second");
        check(Log.lines.size() == 1, "logcat independent of LSPosed failure");
        HookLog.write("HookTest", "event=natural_later", false);
        check(Log.lines.size() == 2, "later getter diagnostics do not request LSPosed emission");
    }
    public static void main(String[] args) throws Exception {
        Path work = java.nio.file.Paths.get(args[0]);
        reducer(); writer(Files.createDirectory(work.resolve("store")));
        adapter(Files.createDirectory(work.resolve("adapter"))); logging();
        System.out.println("PASS " + assertions + " hook-state reducer/writer/async identity/logger assertions");
    }
}
