package moseyPLK.client;

import android.app.Application;
import android.content.Context;
import android.content.ComponentName;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.os.IBinder;
import android.os.Process;
import android.os.ServiceManager;
import android.util.Log;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/** Natural hook callbacks and bounded recovery run against fake Android services only. */
public final class MoseyHookStateTest {
    private static int assertions;
    private static void check(boolean result, String message) {
        assertions++; if (!result) throw new AssertionError(message);
    }
    private static String await(Path file, String expected) throws Exception {
        long deadline = System.nanoTime() + 3000000000L;
        while (System.nanoTime() < deadline) {
            if (Files.exists(file)) {
                String text = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
                if (text.contains(expected)) return text;
            }
            Thread.sleep(10);
        }
        throw new AssertionError("missing snapshot field: " + expected);
    }
    private static final class FakePackages extends PackageManager {
        volatile int state = COMPONENT_ENABLED_STATE_DISABLED, writes;
        final PackageInfo target = new PackageInfo();
        FakePackages() {
            target.applicationInfo = new ApplicationInfo(); target.applicationInfo.uid = Process.myUid();
            target.versionCode = 46489; target.versionName = "1.0.971384876"; target.lastUpdateTime = 44;
        }
        @Override public PackageInfo getPackageInfo(String name, int flags) {
            if (!name.equals(ClientPolicy.PACKAGE) || flags != 0) throw new AssertionError("wrong package");
            return target;
        }
        @Override public ServiceInfo getServiceInfo(ComponentName component, int flags) {
            if (!component.packageName.equals(ClientPolicy.PACKAGE) || !component.name.equals(ClientPolicy.COMPONENT))
                throw new AssertionError("wrong component");
            ServiceInfo result = new ServiceInfo(); result.applicationInfo = target.applicationInfo;
            result.packageName = ClientPolicy.PACKAGE; result.name = ClientPolicy.COMPONENT;
            return result;
        }
        @Override public int getComponentEnabledSetting(ComponentName component) { return state; }
        @Override public void setComponentEnabledSetting(ComponentName component, int value, int flags) {
            state = value; writes++;
        }
    }
    public static void main(String[] args) throws Throwable {
        Path directory = java.nio.file.Paths.get(args[0]);
        XposedBridge.reset(); Log.reset();
        MoseyHook hook = new MoseyHook();
        XC_LoadPackage.LoadPackageParam loaded = new XC_LoadPackage.LoadPackageParam();
        loaded.packageName = "unrelated"; loaded.processName = "unrelated";
        hook.handleLoadPackage(loaded);
        check(XposedBridge.hooks.isEmpty(), "outside package stays untouched");
        loaded.packageName = ClientPolicy.PACKAGE; loaded.processName = ClientPolicy.PACKAGE;
        hook.handleLoadPackage(loaded);
        check(XposedBridge.hooks.size() == 2, "only declared lookup and attach installed");
        Context context = new Context(); context.packageName = ClientPolicy.PACKAGE;
        context.codeCache = directory.toFile(); FakePackages packages = new FakePackages(); context.packages = packages;
        final IBinder binder = new IBinder() {
            @Override public boolean isBinderAlive() { return true; }
            @Override public String getInterfaceDescriptor() { return ClientPolicy.DESCRIPTOR; }
        };
        ServiceManager.binder = binder;
        XC_MethodHook attach = XposedBridge.hooks.get(Application.class.getDeclaredMethod("attach", Context.class));
        attach.fireAfter(new XC_MethodHook.MethodHookParam(null, null, new Object[]{context}));
        Path path = directory.resolve(HookStateStore.FILE_NAME);
        String text = await(path, "\"componentRestore\":\"restored\"");
        check(text.contains("\"installation\":\"active\""), "Mosey installation published");
        check(text.contains("\"binderReady\":\"ready\""), "real Binder readiness published");
        check(text.contains("\"targetVersionCode\":46489"), "Mosey version separate from GMS");
        check(packages.writes == 1 && packages.state == 1, "original single-component recovery preserved");
        XC_MethodHook lookup = XposedBridge.hooks.get(ServiceManager.class.getDeclaredMethod("waitForDeclaredService", String.class));
        XC_MethodHook.MethodHookParam unrelated = new XC_MethodHook.MethodHookParam("original", null, new Object[]{"other"});
        lookup.fireBefore(unrelated);
        check(unrelated.writes == 0, "unrelated Binder lookup unchanged");
        XC_MethodHook.MethodHookParam good = new XC_MethodHook.MethodHookParam(null, null, new Object[]{ClientPolicy.INSTANCE});
        lookup.fireBefore(good);
        check(good.getResult() == binder, "target lookup returns existing verified Binder");
        ServiceManager.binder = null;
        XC_MethodHook.MethodHookParam absent = new XC_MethodHook.MethodHookParam(null, null, new Object[]{ClientPolicy.INSTANCE});
        lookup.fireBefore(absent);
        check(absent.getResult() == null, "no fabricated Binder for absent service");
        await(path, "\"binderReady\":\"unavailable\""); assertions++;
        System.out.println("PASS " + assertions + " actual Mosey hook/recovery/snapshot integration assertions");
    }
}
