#!/usr/bin/env python3
"""Run actual GMS observer/registry-gate code against bounded host API fakes.

This does not connect to Android, load the real GMS APK, or emulate ART/LSPosed's
native hook backend. APK signatures are checked separately. Temporary fake APIs
let these tests execute production callbacks and fail on active business calls.
"""

from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap

from project_paths import BUILD_ROOT, ROOT

SOURCE = ROOT / 'client-compat/src/main/java/moseyPLK/client'
EVIDENCE = BUILD_ROOT / 'client-compat-v0.6.0/observer-tests.txt'

STUBS = {
    'moseyPLK/client/GmsModuleIdentity.java': '''
        package moseyPLK.client;
        public final class GmsModuleIdentity {
            public static boolean force;
            static void record(String path) { }
            static boolean forceAdaptive() { return force; }
        }
    ''',
    'moseyPLK/client/GmsAdaptiveRuntime.java': '''
        package moseyPLK.client;
        public final class GmsAdaptiveRuntime {
            public static int calls;
            static void start(android.content.Context context, ClassLoader loader, boolean test) { ++calls; }
        }
    ''',
    'de/robv/android/xposed/IXposedHookZygoteInit.java': '''
        package de.robv.android.xposed;
        public interface IXposedHookZygoteInit {
            final class StartupParam { public String modulePath; }
            void initZygote(StartupParam p) throws Throwable;
        }
    ''',
    'android/app/Application.java': '''
        package android.app;
        public class Application { protected void attach(android.content.Context c) {} }
    ''',
    'android/content/Context.java': '''
        package android.content;
        public class Context {
            public String getPackageName() { throw new AssertionError("active Context call"); }
            public android.content.pm.PackageManager getPackageManager() {
                throw new AssertionError("active PackageManager call");
            }
            public ClassLoader getClassLoader() { return getClass().getClassLoader(); }
        }
    ''',
    'android/content/ComponentName.java': '''
        package android.content;
        public final class ComponentName {
            private final String pkg, name;
            public ComponentName(String pkg, String name) { this.pkg=pkg; this.name=name; }
            public String getPackageName() { return pkg; }
            public String getClassName() { return name; }
            @Override public String toString() { throw new AssertionError("component toString"); }
        }
    ''',
    'android/content/pm/PackageManager.java': '''
        package android.content.pm;
        public class PackageManager {
            public PackageInfo getPackageInfo(String pkg, int flags) {
                throw new AssertionError("active PM query");
            }
        }
    ''',
    'android/content/pm/ApplicationInfo.java': '''
        package android.content.pm;
        public class ApplicationInfo { public int uid; }
    ''',
    'android/content/pm/PackageInfo.java': '''
        package android.content.pm;
        public class PackageInfo {
            public ApplicationInfo applicationInfo;
            public String versionName;
            public long versionCode;
            public long getLongVersionCode() { return versionCode; }
        }
    ''',
    'android/content/pm/ServiceInfo.java': '''
        package android.content.pm;
        public class ServiceInfo {
            public String packageName, name;
            public boolean enabled, exported;
            public android.os.Bundle metaData;
            @Override public String toString() { throw new AssertionError("ServiceInfo toString"); }
        }
    ''',
    'android/os/Bundle.java': '''
        package android.os;
        public class Bundle {
            public int getInt(String key, int fallback) { return 2; }
            @Override public String toString() { throw new AssertionError("Bundle toString"); }
        }
    ''',
    'android/os/Process.java': '''
        package android.os;
        public final class Process {
            public static int myUid() { return 10118; }
            public static int myPid() { return 4242; }
        }
    ''',
    'android/os/IBinder.java': '''
        package android.os;
        public interface IBinder {
            String getInterfaceDescriptor();
            boolean pingBinder();
            boolean isBinderAlive();
            boolean transact(int code, Object data, Object reply, int flags);
        }
    ''',
    'android/util/Log.java': '''
        package android.util;
        public final class Log {
            public static final java.util.List<String> lines = new java.util.ArrayList<String>();
            public static boolean fail;
            public static int i(String tag, String text) {
                if (fail) throw new IllegalStateException("logger unavailable");
                lines.add(tag + " " + text); return 0;
            }
            public static void reset() { lines.clear(); fail=false; }
        }
    ''',
    'de/robv/android/xposed/IXposedHookLoadPackage.java': '''
        package de.robv.android.xposed;
        public interface IXposedHookLoadPackage {
            void handleLoadPackage(de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam p)
                throws Throwable;
        }
    ''',
    'de/robv/android/xposed/callbacks/XC_LoadPackage.java': '''
        package de.robv.android.xposed.callbacks;
        public final class XC_LoadPackage {
            public static class LoadPackageParam {
                public String packageName, processName;
                public ClassLoader classLoader;
            }
        }
    ''',
    'de/robv/android/xposed/XC_MethodHook.java': '''
        package de.robv.android.xposed;
        public class XC_MethodHook {
            protected void afterHookedMethod(MethodHookParam p) throws Throwable {}
            public final void fireAfter(MethodHookParam p) throws Throwable { afterHookedMethod(p); }
            public static class MethodHookParam {
                public Object thisObject;
                public Object[] args;
                private Object result;
                private Throwable throwable;
                public int writes;
                public MethodHookParam(Object receiver, Object[] args, Object result, Throwable error) {
                    this.thisObject=receiver; this.args=args; this.result=result; this.throwable=error;
                }
                public Object getResult() { return result; }
                public Throwable getThrowable() { return throwable; }
                public boolean hasThrowable() { return throwable != null; }
                public void setResult(Object value) { ++writes; result=value; throwable=null; }
                public void setThrowable(Throwable value) { ++writes; throwable=value; result=null; }
            }
        }
    ''',
    'de/robv/android/xposed/XposedBridge.java': '''
        package de.robv.android.xposed;
        public final class XposedBridge {
            public static final java.util.Map<java.lang.reflect.Method, XC_MethodHook> hooks =
                new java.util.LinkedHashMap<java.lang.reflect.Method, XC_MethodHook>();
            public static int attempts;
            public static void log(String message) { }
            public static Object hookMethod(java.lang.reflect.Member member, XC_MethodHook callback) {
                ++attempts;
                hooks.put((java.lang.reflect.Method)member, callback);
                return null;
            }
            public static void reset() { hooks.clear(); attempts=0; }
        }
    ''',
    'de/robv/android/xposed/XposedHelpers.java': '''
        package de.robv.android.xposed;
        public final class XposedHelpers {
            public static Class<?> findClass(String name, ClassLoader loader) throws ClassNotFoundException {
                return Class.forName(name);
            }
            public static java.lang.reflect.Method findMethodExact(Class<?> owner, String name,
                    Class<?>... parameters) throws NoSuchMethodException {
                return owner.getDeclaredMethod(name, parameters);
            }
            public static final java.util.List<String> attempts = new java.util.ArrayList<String>();
            public static boolean failPublicLoad;
            public static Object findAndHookMethod(Class<?> owner, String name, Object... values)
                    throws NoSuchMethodException {
                int count=values.length-1;
                attempts.add(owner.getName()+"."+name+"/"+count);
                if (failPublicLoad && owner==ClassLoader.class && name.equals("loadClass") && count==1)
                    throw new NoSuchMethodException("injected public loader hook failure");
                Class<?>[] parameters=new Class<?>[count];
                for (int i=0;i<count;++i) parameters[i]=(Class<?>)values[i];
                return XposedBridge.hookMethod(owner.getDeclaredMethod(name, parameters),
                    (XC_MethodHook)values[count]);
            }
            public static void reset() { attempts.clear(); failPublicLoad=false; }
        }
    ''',
    'dalvik/system/DelegateLastClassLoader.java': '''
        package dalvik.system;
        public class DelegateLastClassLoader extends ClassLoader {
            @Override protected Class<?> loadClass(String name, boolean resolve)
                    throws ClassNotFoundException { return super.loadClass(name, resolve); }
        }
    ''',
    'testsupport/Probe.java': '''
        package testsupport;
        public final class Probe {
            public static int initializations, businessCalls, binderCalls;
            public static void business() { ++businessCalls; throw new AssertionError("active business call"); }
        }
    ''',
    'jpsb.java': '''
        public final class jpsb {
            static { ++testsupport.Probe.initializations; }
            public final boolean S() { testsupport.Probe.business(); return false; }
            public final boolean ac() { testsupport.Probe.business(); return false; }
        }
    ''',
    'eabp.java': '''
        public final class eabp {
            static { ++testsupport.Probe.initializations; }
            public final Object lr() { testsupport.Probe.business(); return Boolean.FALSE; }
        }
    ''',
    'jpse.java': '''
        public final class jpse {
            static { ++testsupport.Probe.initializations; }
            public final boolean bd() { testsupport.Probe.business(); return false; }
            public final boolean bs() { testsupport.Probe.business(); return false; }
        }
    ''',
    'eabq.java': '''
        public final class eabq {
            static { ++testsupport.Probe.initializations; }
            public final Object lr() { testsupport.Probe.business(); return Boolean.FALSE; }
        }
    ''',
    'eabv.java': '''
        public final class eabv {
            static { ++testsupport.Probe.initializations; }
            public final Object lr() { testsupport.Probe.business(); return Boolean.FALSE; }
        }
    ''',
    'ipqt.java': '''
        public final class ipqt {
            static { ++testsupport.Probe.initializations; }
            public final void c() { testsupport.Probe.business(); }
            public final void b() { testsupport.Probe.business(); }
        }
    ''',
    'ehmm.java': '''
        public final class ehmm {
            static { ++testsupport.Probe.initializations; }
            public static final boolean b(android.content.pm.ServiceInfo info, android.content.Context ctx) {
                testsupport.Probe.business(); return false;
            }
        }
    ''',
    'ehkv.java': '''
        public final class ehkv {
            static { ++testsupport.Probe.initializations; }
            public final void a(android.content.ComponentName n, android.os.IBinder b) { testsupport.Probe.business(); }
            public final void b(android.content.ComponentName n) { testsupport.Probe.business(); }
            public final void onBindingDied(android.content.ComponentName n) { testsupport.Probe.business(); }
        }
    ''',
}

# Both reviewed obfuscation layouts are present at once. Profile selection must
# prevent even resolving or installing callbacks on the other build's classes.
for old, current, replacements in (
    ('jpsb', 'jtmb', ((' S()', ' W()'), (' ac()', ' af()'))),
    ('jpse', 'jtme', ((' bd()', ' ba()'), (' bs()', ' bp()'))),
    ('eabp', 'ecyv', ((' lr()', ' ln()'),)),
    ('eabq', 'ecyw', ((' lr()', ' ln()'),)),
    ('eabv', 'ecyy', ((' lr()', ' ln()'),)),
    ('ipqt', 'isye', ()), ('ehmm', 'ekkw', ()), ('ehkv', 'ekjf', ()),
):
    body = STUBS[old + '.java'].replace('class ' + old, 'class ' + current)
    for before, after in replacements:
        body = body.replace(before, after)
    if current == 'jtmb':
        body = body.replace('public final boolean W()',
            'public final boolean U() { testsupport.Probe.business(); return false; } '
            'public final boolean W()')
    STUBS[current + '.java'] = body
for owner in ('eice', 'elap'):
    STUBS[owner + '.java'] = (
        'public final class ' + owner + ' {'
        ' static { ++testsupport.Probe.initializations; }'
        ' public static int a(android.content.Context c, String p) {'
        ' testsupport.Probe.business(); return 0; } }')
STUBS['com/google/android/gms/nearby/sharing/NearbySharingChimeraService.java'] = """
    package com.google.android.gms.nearby.sharing;
    public final class NearbySharingChimeraService {
        static { ++testsupport.Probe.initializations; }
        public void onCreate() { testsupport.Probe.business(); }
        public void ad(boolean active) { testsupport.Probe.business(); }
    }
"""

HARNESS = r'''
    import java.lang.reflect.Field;
    import java.lang.reflect.Method;
    import android.content.ComponentName;
    import android.content.Context;
    import android.content.pm.ServiceInfo;
    import android.os.IBinder;
    import android.util.Log;
    import de.robv.android.xposed.XC_MethodHook;
    import de.robv.android.xposed.XC_MethodHook.MethodHookParam;
    import de.robv.android.xposed.XposedBridge;
    import de.robv.android.xposed.XposedHelpers;
    import moseyPLK.client.ClientPolicy;
    import moseyPLK.client.GmsDiagnosticPolicy;
    import moseyPLK.client.GmsDiagnosticPolicy.Spec;
    import moseyPLK.client.GmsDiagnosticPolicy.Profile;
    import moseyPLK.client.GmsDiagnosticsHook;
    import moseyPLK.client.GmsModuleIdentity;
    import moseyPLK.client.GmsAdaptiveRuntime;

    public final class ObserverBehaviorTest {
        static int checks;
        static final Method RECORD, OBSERVE, WATCH, ENABLE;
        static final Field PROFILE;
        static final Profile LEGACY = GmsDiagnosticPolicy.profileFor(
                263332035L, "26.33.32 (260400-974685114)");
        static final Profile CURRENT = GmsDiagnosticPolicy.profileFor(
                263436035L, "26.34.36 (260400-981326859)");
        static Profile active;
        static {
            try {
                RECORD=GmsDiagnosticsHook.class.getDeclaredMethod("record", Spec.class, MethodHookParam.class, String.class);
                OBSERVE=GmsDiagnosticsHook.class.getDeclaredMethod("observe", Class.class);
                WATCH=GmsDiagnosticsHook.class.getDeclaredMethod("watchLoaders");
                ENABLE=GmsDiagnosticsHook.class.getDeclaredMethod("enableRegistry", Spec.class, MethodHookParam.class, String.class);
                PROFILE=GmsDiagnosticsHook.class.getDeclaredField("profile");
                RECORD.setAccessible(true); OBSERVE.setAccessible(true); WATCH.setAccessible(true);
                ENABLE.setAccessible(true); PROFILE.setAccessible(true);
            } catch (Exception e) { throw new ExceptionInInitializerError(e); }
        }
        static void check(boolean value, String label) {
            ++checks; if (!value) throw new AssertionError(label);
        }
        static String[] actual(String owner, String method) {
            if(active==CURRENT) {
                String[][] names={{"jpsb","S","jtmb","W"},{"jpsb","ac","jtmb","af"},
                    {"jpse","bd","jtme","ba"},{"jpse","bs","jtme","bp"},
                    {"eabp","lr","ecyv","ln"},{"eabq","lr","ecyw","ln"},
                    {"eabv","lr","ecyy","ln"}};
                for(String[] n:names) if(n[0].equals(owner)&&n[1].equals(method))
                    return new String[]{n[2],n[3]};
                String[][] owners={{"ipqt","isye"},{"ehmm","ekkw"},{"eice","elap"},{"ehkv","ekjf"}};
                for(String[] n:owners) if(n[0].equals(owner)) return new String[]{n[1],method};
            }
            return new String[]{owner,method};
        }
        static Spec spec(String owner, String method) {
            String[] name=actual(owner,method);
            for (Spec s:active.specs()) if(s.owner.equals(name[0])&&s.method.equals(name[1])) return s;
            throw new AssertionError("missing spec "+name[0]+"."+name[1]);
        }
        static GmsDiagnosticsHook hookForActive() throws Exception {
            GmsDiagnosticsHook hook=new GmsDiagnosticsHook();
            PROFILE.set(hook,active);
            return hook;
        }
        static void record(GmsDiagnosticsHook hook, String owner, String method, MethodHookParam call)
                throws Exception { RECORD.invoke(hook,spec(owner,method),call,"test"); }
        static void enable(GmsDiagnosticsHook hook, Spec selected, MethodHookParam call)
                throws Exception { ENABLE.invoke(hook,selected,call,"test"); }
        static XC_MethodHook observe(GmsDiagnosticsHook hook, String owner, String method)
                throws Exception {
            String[] name=actual(owner,method);
            owner=name[0]; method=name[1];
            Class<?> c=Class.forName(owner,false,ObserverBehaviorTest.class.getClassLoader());
            OBSERVE.invoke(hook,c);
            for (java.util.Map.Entry<Method,XC_MethodHook> e:XposedBridge.hooks.entrySet()) {
                if(e.getKey().getDeclaringClass()==c && e.getKey().getName().equals(method)) return e.getValue();
            }
            throw new AssertionError("hook absent "+owner+"."+method);
        }
        static long count(String marker) {
            long n=0; for(String line:Log.lines) if(line.contains(marker)) ++n; return n;
        }
        static void reset() { Log.reset(); XposedBridge.reset(); XposedHelpers.reset(); }
        static void unchanged(MethodHookParam p,Object receiver,Object[] args,Object[] elements,Object result,Throwable error) {
            check(p.thisObject==receiver,"receiver unchanged");
            check(p.args==args,"args array unchanged");
            check(args.length==elements.length,"args length unchanged");
            for(int i=0;i<args.length;++i) check(args[i]==elements[i],"arg identity unchanged "+i);
            check(p.getResult()==result,"result identity unchanged");
            check(p.getThrowable()==error,"throwable identity unchanged");
            check(p.writes==0,"no result/throwable setter called");
        }
        static void enabledOnce(MethodHookParam p,Object receiver,Object[] args,Object[] elements) {
            check(p.thisObject==receiver,"gate receiver unchanged");
            check(p.args==args,"gate args array unchanged");
            check(args.length==elements.length,"gate args length unchanged");
            for(int i=0;i<args.length;++i) check(args[i]==elements[i],"gate arg identity unchanged "+i);
            check(p.getResult()==Boolean.TRUE,"reviewed false changed to Boolean.TRUE");
            check(p.getThrowable()==null,"gate leaves successful invocation successful");
            check(p.writes==1,"exactly one result setter for reviewed false");
        }
        static final class TrapObject {
            @Override public String toString() { throw new AssertionError("active object toString"); }
        }
        static final class TrapBinder implements IBinder {
            private static void called() { ++testsupport.Probe.binderCalls; throw new AssertionError("active Binder call"); }
            public String getInterfaceDescriptor() { called(); return null; }
            public boolean pingBinder() { called(); return false; }
            public boolean isBinderAlive() { called(); return false; }
            public boolean transact(int c,Object d,Object r,int f) { called(); return false; }
            @Override public String toString() { throw new AssertionError("Binder toString"); }
        }
        static void passivity() throws Throwable {
            reset(); GmsDiagnosticsHook hook=hookForActive();
            Object receiver=new TrapObject();
            for(Object result:new Object[]{Boolean.FALSE,Boolean.TRUE,new TrapObject(),null}) {
                Object[] args=new Object[0];
                MethodHookParam p=new MethodHookParam(receiver,args,result,null);
                record(hook,"jpsb","S",p);
                unchanged(p,receiver,args,args.clone(),result,null);
            }
            XC_MethodHook callback=observe(hook,"jpsb","S");
            PROFILE.set(hook,null);
            Object[] args=new Object[0]; Object result=new TrapObject();
            Throwable error=new IllegalStateException("original failure");
            MethodHookParam p=new MethodHookParam(receiver,args,result,error);
            callback.fireAfter(p);
            unchanged(p,receiver,args,args.clone(),result,error);
            check(count("threw=IllegalStateException")==1,"original exception observed");
            Log.fail=true;
            MethodHookParam loggerFailure=new MethodHookParam(receiver,args,Boolean.FALSE,null);
            callback.fireAfter(loggerFailure);
            unchanged(loggerFailure,receiver,args,args.clone(),Boolean.FALSE,null);
            Log.fail=false;
            System.out.println("PASS production record/callback preserves result, throwable, args and logger failure");
        }
        static void providers() throws Throwable {
            reset(); GmsDiagnosticsHook hook=hookForActive();
            Object receiver=new TrapObject();
            ServiceInfo info=new ServiceInfo(); info.packageName=ClientPolicy.PACKAGE;
            info.name=ClientPolicy.COMPONENT; info.enabled=true; info.exported=true;
            info.metaData=new android.os.Bundle();
            Object[] args={info,new Context()}; Object[] original=args.clone();
            MethodHookParam p=new MethodHookParam(null,args,Boolean.TRUE,null);
            record(hook,"ehmm","b",p); unchanged(p,null,args,original,Boolean.TRUE,null);
            check(count("event=provider_filter")==1,"target provider filter observed");
            info.packageName="unrelated.package";
            record(hook,"ehmm","b",p);
            check(count("event=provider_filter")==1,"unrelated provider ignored");
            Object[] binderArgs={new ComponentName(ClientPolicy.PACKAGE,ClientPolicy.COMPONENT),new TrapBinder()};
            MethodHookParam connected=new MethodHookParam(receiver,binderArgs,null,null);
            record(hook,"ehkv","a",connected);
            unchanged(connected,receiver,binderArgs,binderArgs.clone(),null,null);
            check(count("binder_present=true")==1,"Binder presence only");
            XC_MethodHook filter=observe(hook,"ehmm","b");
            info.packageName=ClientPolicy.PACKAGE;
            MethodHookParam rejected=new MethodHookParam(null,args,Boolean.FALSE,null);
            filter.fireAfter(rejected);
            unchanged(rejected,null,args,args.clone(),Boolean.FALSE,null);
            XC_MethodHook whitelist=observe(hook,"eice","a");
            Object[] whitelistArgs={new Context(),ClientPolicy.PACKAGE};
            Integer category=Integer.valueOf(0);
            MethodHookParam denied=new MethodHookParam(null,whitelistArgs,category,null);
            whitelist.fireAfter(denied);
            unchanged(denied,null,whitelistArgs,whitelistArgs.clone(),category,null);
            Object[] invalid={new TrapObject(),new Context()};
            Throwable error=new IllegalArgumentException("original host exception");
            MethodHookParam malformed=new MethodHookParam(null,invalid,Boolean.FALSE,error);
            filter.fireAfter(malformed);
            unchanged(malformed,null,invalid,invalid.clone(),Boolean.FALSE,error);
            check(count("event=observer_failed")==1,"observer error isolated");
            check(testsupport.Probe.binderCalls==0,"zero extra Binder calls");
            System.out.println("PASS target-only provider observations; Binder/Context traps untouched; callback errors isolated");
        }
        static void lifecycle() throws Exception {
            reset(); GmsDiagnosticsHook hook=hookForActive();
            Object receiver=new TrapObject();
            MethodHookParam p=new MethodHookParam(receiver,new Object[0],null,null);
            record(hook,"ipqt","c",p); record(hook,"ipqt","b",p); record(hook,"ipqt","c",p);
            check(count("event=registry_start_returned")==2,"same instance repeated start retained");
            check(count("event=registry_stop_returned")==1,"stop retained");
            check(count("sequence=")==3,"lifecycle sequence observed");
            for(int i=0;i<100;++i) { record(hook,"ipqt","c",p); record(hook,"ipqt","b",p); }
            check(count("event=registry_start_returned")==12,"start volume capped");
            check(count("event=registry_stop_returned")==12,"stop volume capped");
            check(p.writes==0,"lifecycle observer does not override");
            System.out.println("PASS same-instance c/b/c emits three events; lifecycle capped at 12 per method/instance");
        }
        static void loaders() throws Throwable {
            reset(); GmsDiagnosticsHook hook=hookForActive();
            XposedHelpers.failPublicLoad=true; WATCH.invoke(hook);
            check(XposedHelpers.attempts.contains("java.lang.ClassLoader.loadClass/1"),"public loader attempted");
            check(XposedHelpers.attempts.contains("java.lang.ClassLoader.loadClass/2"),"protected loader attempted after failure");
            Method protectedLoad=ClassLoader.class.getDeclaredMethod("loadClass",String.class,boolean.class);
            check(XposedBridge.hooks.containsKey(protectedLoad),"protected loader installed after failure");
            Class<?> delegate=Class.forName("dalvik.system.DelegateLastClassLoader",false,null);
            Method delegateLoad=delegate.getDeclaredMethod("loadClass",String.class,boolean.class);
            check(XposedBridge.hooks.containsKey(delegateLoad),"DelegateLast installed after failure");
            PROFILE.set(hook,active);
            XC_MethodHook watcher=XposedBridge.hooks.get(protectedLoad);
            Class<?> target=Class.forName(actual("jpsb","S")[0],false,ObserverBehaviorTest.class.getClassLoader());
            MethodHookParam p=new MethodHookParam(null,new Object[]{target.getName(),Boolean.FALSE},target,null);
            watcher.fireAfter(p);
            int installed=XposedBridge.attempts;
            watcher.fireAfter(p);
            check(XposedBridge.attempts==installed,"same Class observed exactly once");
            check(p.getResult()==target && p.writes==0,"loader result untouched");
            check(testsupport.Probe.initializations==0,"Class resolution/observation does not initialize business fakes");
            check(testsupport.Probe.businessCalls==0,"zero business getter/lifecycle calls");
            Field installing=GmsDiagnosticsHook.class.getDeclaredField("installing");
            installing.setAccessible(true);
            @SuppressWarnings("unchecked") ThreadLocal<Boolean> guard=(ThreadLocal<Boolean>)installing.get(hook);
            guard.set(Boolean.TRUE);
            Class<?> other=Class.forName(actual("ipqt","c")[0],false,ObserverBehaviorTest.class.getClassLoader());
            watcher.fireAfter(new MethodHookParam(null,new Object[]{other.getName(),Boolean.FALSE},other,null));
            check(XposedBridge.attempts==installed,"reentrant loader callback skipped");
            guard.remove();
            watcher.fireAfter(new MethodHookParam(null,new Object[]{other.getName(),Boolean.FALSE},other,null));
            check(XposedBridge.attempts==installed+2,"later natural class load observed after guard cleared");
            System.out.println("PASS loader failures independent; class deduplication, no initialization and reentry guard");
        }
        static void registryGate() throws Throwable {
            for(String[] target:new String[][]{{"jpsb","S"},{"eabp","lr"}}) {
                reset(); GmsDiagnosticsHook hook=hookForActive();
                Spec selected=spec(target[0],target[1]);
                XC_MethodHook callback=observe(hook,target[0],target[1]);
                Object receiver=new TrapObject(); Object[] args=new Object[0];

                PROFILE.set(hook,null);
                // Even correctly installed callbacks do nothing until the
                // package/build verification has actually succeeded.
                MethodHookParam unverified=new MethodHookParam(receiver,args,Boolean.FALSE,null);
                callback.fireAfter(unverified);
                unchanged(unverified,receiver,args,args.clone(),Boolean.FALSE,null);
                MethodHookParam unverifiedDirect=new MethodHookParam(receiver,args,Boolean.FALSE,null);
                enable(hook,selected,unverifiedDirect);
                unchanged(unverifiedDirect,receiver,args,args.clone(),Boolean.FALSE,null);

                PROFILE.set(hook,active);
                Log.reset();
                // record remains a pure observer even in a verified instance.
                MethodHookParam observation=new MethodHookParam(receiver,args,Boolean.FALSE,null);
                record(hook,target[0],target[1],observation);
                unchanged(observation,receiver,args,args.clone(),Boolean.FALSE,null);
                Log.reset();
                // New receiver avoids deliberately deduplicated observer lines.
                Object callbackReceiver=new TrapObject();
                MethodHookParam changed=new MethodHookParam(callbackReceiver,args,Boolean.FALSE,null);
                callback.fireAfter(changed);
                enabledOnce(changed,callbackReceiver,args,args.clone());
                boolean originalObserved=false;
                for(String line:Log.lines) if(line.contains("event="+selected.event+" ")
                        && line.contains("method="+selected.label()+" ")
                        && line.contains((selected.event.equals("registry_gate_read")
                            ? "expression=" : "flag=")+selected.flag+" value=false")) originalObserved=true;
                check(originalObserved,"callback records original false before overriding "+selected.label());

                MethodHookParam direct=new MethodHookParam(receiver,args,Boolean.FALSE,null);
                enable(hook,selected,direct);
                enabledOnce(direct,receiver,args,args.clone());
                Object[] unexpectedArgs={new TrapObject(),new TrapBinder()};
                MethodHookParam wrongArgs=new MethodHookParam(receiver,unexpectedArgs,Boolean.FALSE,null);
                callback.fireAfter(wrongArgs);
                unchanged(wrongArgs,receiver,unexpectedArgs,unexpectedArgs.clone(),Boolean.FALSE,null);
                MethodHookParam nullArgs=new MethodHookParam(receiver,null,Boolean.FALSE,null);
                callback.fireAfter(nullArgs);
                check(nullArgs.thisObject==receiver && nullArgs.args==null,"null args preserved");
                check(nullArgs.getResult()==Boolean.FALSE && nullArgs.getThrowable()==null
                        && nullArgs.writes==0,"malformed target args rejected without overriding");
                // Reapplying the callback to an already true result must not
                // call setResult again, even though it is the same target.
                callback.fireAfter(changed);
                check(changed.writes==1 && changed.getResult()==Boolean.TRUE,"already enabled callback is idempotent");

                for(Object value:new Object[]{Boolean.TRUE,null,new TrapObject(),Integer.valueOf(0)}) {
                    MethodHookParam p=new MethodHookParam(receiver,args,value,null);
                    callback.fireAfter(p);
                    unchanged(p,receiver,args,args.clone(),value,null);
                    MethodHookParam manual=new MethodHookParam(receiver,args,value,null);
                    enable(hook,selected,manual);
                    unchanged(manual,receiver,args,args.clone(),value,null);
                }
                for(Object value:new Object[]{Boolean.FALSE,Boolean.TRUE,null,new TrapObject()}) {
                    Throwable failure=new IllegalStateException("original exception must survive");
                    MethodHookParam p=new MethodHookParam(receiver,args,value,failure);
                    callback.fireAfter(p);
                    unchanged(p,receiver,args,args.clone(),value,failure);
                    MethodHookParam manual=new MethodHookParam(receiver,args,value,failure);
                    enable(hook,selected,manual);
                    unchanged(manual,receiver,args,args.clone(),value,failure);
                }

                // Observer/logger availability is independent of the selected
                // gate. A logger exception cannot hide a legitimate override.
                Log.fail=true;
                MethodHookParam loggingFailure=new MethodHookParam(receiver,args,Boolean.FALSE,null);
                callback.fireAfter(loggingFailure);
                enabledOnce(loggingFailure,receiver,args,args.clone());
                Throwable original=new IllegalArgumentException("preserve despite logger failure");
                MethodHookParam thrown=new MethodHookParam(receiver,args,Boolean.FALSE,original);
                callback.fireAfter(thrown);
                unchanged(thrown,receiver,args,args.clone(),Boolean.FALSE,original);
                MethodHookParam alreadyTrue=new MethodHookParam(receiver,args,Boolean.TRUE,null);
                callback.fireAfter(alreadyTrue);
                unchanged(alreadyTrue,receiver,args,args.clone(),Boolean.TRUE,null);
                Log.fail=false;
            }
            System.out.println("PASS actual callbacks and enableRegistry: verified false-only gate, original observations, exact one setter and exception preservation");
        }
        static void otherRegistrySpecs() throws Throwable {
            reset(); GmsDiagnosticsHook hook=hookForActive();
            PROFILE.set(hook,active);
            Object receiver=new TrapObject();
            // Exercise every canonical non-target spec without executing its
            // business method. Sensitive args are traps, not queried objects.
            for(Spec selected:active.specs()) {
                if(selected==spec("jpsb","S") || selected==spec("eabp","lr")) continue;
                for(Object[] args:new Object[][]{new Object[0],{new TrapObject(),new TrapBinder(),new Context()}}) {
                    for(boolean loggerFailure:new boolean[]{false,true}) {
                        Log.fail=loggerFailure;
                        for(Throwable error:new Throwable[]{null,new IllegalStateException("non-target exception")}) {
                            MethodHookParam p=new MethodHookParam(receiver,args,Boolean.FALSE,error);
                            enable(hook,selected,p);
                            unchanged(p,receiver,args,args.clone(),Boolean.FALSE,error);
                        }
                    }
                }
            }
            Log.fail=false;
            // Use the real installed callback for neighboring flag suppliers.
            for(String[] neighbor:new String[][]{{"jpsb","ac"},{"jpse","bd"},{"jpse","bs"},
                    {"eabq","lr"},{"eabv","lr"}}) {
                XC_MethodHook callback=observe(hook,neighbor[0],neighbor[1]);
                Object[] args=new Object[0];
                for(boolean loggerFailure:new boolean[]{false,true}) {
                    Log.fail=loggerFailure;
                    MethodHookParam p=new MethodHookParam(receiver,args,Boolean.FALSE,null);
                    callback.fireAfter(p);
                    unchanged(p,receiver,args,args.clone(),Boolean.FALSE,null);
                }
            }
            Log.fail=false;
            check(testsupport.Probe.initializations==0,"gate reflection never initializes business classes");
            check(testsupport.Probe.businessCalls==0,"gate performs zero business getter/lifecycle calls");
            check(testsupport.Probe.binderCalls==0,"gate performs zero Binder calls");
            System.out.println("PASS all other canonical specs and neighboring callbacks unchanged, including logger failures; no business or Binder operations");
        }
        static void noncanonicalSpecs() throws Exception {
            reset(); GmsDiagnosticsHook hook=hookForActive();
            PROFILE.set(hook,active);
            java.lang.reflect.Constructor<Spec> constructor=Spec.class.getDeclaredConstructor(
                    String.class,String.class,String.class,boolean.class,String.class,String.class,String[].class);
            constructor.setAccessible(true);
            Object receiver=new TrapObject(); Object[] args=new Object[0];
            for(String[] target:new String[][]{{"jpsb","S","boolean"},{"eabp","lr","java.lang.Object"}}) {
                Spec selected=spec(target[0],target[1]);
                Spec copy=constructor.newInstance(selected.owner,selected.method,selected.returns,Boolean.FALSE,
                        selected.event,selected.flag,new String[0]);
                Spec wrongFlag=constructor.newInstance(selected.owner,selected.method,selected.returns,Boolean.FALSE,
                        selected.event,"45802344",new String[0]);
                Spec wrongEvent=constructor.newInstance(selected.owner,selected.method,selected.returns,Boolean.FALSE,
                        "other_event",selected.flag,new String[0]);
                for(Spec forged:new Spec[]{copy,wrongFlag,wrongEvent}) {
                    MethodHookParam p=new MethodHookParam(receiver,args,Boolean.FALSE,null);
                    enable(hook,forged,p);
                    unchanged(p,receiver,args,args.clone(),Boolean.FALSE,null);
                }
            }
            System.out.println("PASS reconstructed and forged specs cannot activate the canonical gate");
        }
        static final class BuildContext extends Context {
            final android.content.pm.PackageInfo info=new android.content.pm.PackageInfo();
            int reads;
            BuildContext(long code,String name,int uid) {
                info.versionCode=code; info.versionName=name;
                info.applicationInfo=new android.content.pm.ApplicationInfo();
                info.applicationInfo.uid=uid;
            }
            @Override public String getPackageName() { return GmsDiagnosticPolicy.PACKAGE; }
            @Override public android.content.pm.PackageManager getPackageManager() {
                return new android.content.pm.PackageManager() {
                    @Override public android.content.pm.PackageInfo getPackageInfo(String pkg,int flags) {
                        check(GmsDiagnosticPolicy.PACKAGE.equals(pkg)&&flags==0,"only own package version queried");
                        ++reads; return info;
                    }
                };
            }
        }
        static void buildEntry(long code,String name,int uid,Profile expected) throws Throwable {
            buildEntry(code,name,uid,expected,false);
        }
        static void buildEntry(long code,String name,int uid,Profile expected,boolean force) throws Throwable {
            reset();
            GmsModuleIdentity.force=force;
            GmsAdaptiveRuntime.calls=0;
            Field started=GmsDiagnosticsHook.class.getDeclaredField("STARTED");
            started.setAccessible(true);
            ((java.util.concurrent.atomic.AtomicBoolean)started.get(null)).set(false);
            GmsDiagnosticsHook hook=new GmsDiagnosticsHook();
            de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam loaded=
                new de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam();
            loaded.packageName=GmsDiagnosticPolicy.PACKAGE;
            loaded.processName=GmsDiagnosticPolicy.PACKAGE;
            loaded.classLoader=ObserverBehaviorTest.class.getClassLoader();
            hook.handleLoadPackage(loaded);
            Method attach=android.app.Application.class.getDeclaredMethod("attach",Context.class);
            check(XposedBridge.hooks.size()==1&&XposedBridge.hooks.containsKey(attach),
                    "unverified entry installs only Application.attach observer");
            BuildContext context=new BuildContext(code,name,uid);
            Object receiver=new TrapObject(); Object[] arguments={context};
            MethodHookParam call=new MethodHookParam(receiver,arguments,null,null);
            XposedBridge.hooks.get(attach).fireAfter(call);
            unchanged(call,receiver,arguments,arguments.clone(),null,null);
            check(context.reads==1,"version metadata queried once at natural attach");
            check(PROFILE.get(hook)==null,"no version selects historical static profiles");
            check(XposedBridge.hooks.size()==1,"entry adds no legacy loader/business hooks");
            boolean adaptive=uid==10118;
            check(count(adaptive?"event=adaptive_selected":"event=unsupported_build")==1,
                    "all versions delegated; bad UID rejected");
            check(GmsAdaptiveRuntime.calls==(adaptive?1:0),"version never blocks automatic runtime");
            check(count("event=build_verified")==0,"entry does not claim semantic verification");
            if(adaptive) {
                int installed=XposedBridge.attempts;
                XposedBridge.hooks.get(attach).fireAfter(call);
                check(XposedBridge.attempts==installed&&context.reads==1&&GmsAdaptiveRuntime.calls==1,
                        "repeat attach cannot activate twice");
            }
            check(testsupport.Probe.initializations==0,"attach never initializes GMS fixtures");
            check(testsupport.Probe.businessCalls==0,"attach never invokes getter/provider/lifecycle methods");
            check(testsupport.Probe.binderCalls==0,"attach performs no Binder operations");
            GmsModuleIdentity.force=false;
        }
        static void profileEntries() throws Throwable {
            buildEntry(LEGACY.versionCode,LEGACY.versionName,10118,LEGACY);
            buildEntry(CURRENT.versionCode,CURRENT.versionName,10118,CURRENT);
            buildEntry(LEGACY.versionCode,CURRENT.versionName,10118,null);
            buildEntry(CURRENT.versionCode,LEGACY.versionName,10118,null);
            buildEntry(CURRENT.versionCode,"26.34.36",10118,null);
            buildEntry(CURRENT.versionCode,null,10118,null);
            buildEntry(CURRENT.versionCode+1,CURRENT.versionName,10118,null);
            buildEntry(CURRENT.versionCode,CURRENT.versionName,110118,null);
            buildEntry(CURRENT.versionCode,CURRENT.versionName,10118,null,true);
            buildEntry(263161029L,"26.31.61 (190400-960501893)",10118,null);
            buildEntry(263633035L,"26.36.33 (260400-986028547)",10118,null);
            buildEntry(250000000L,"25.0.0",10118,null);
            buildEntry(280000000L,"28.0.0",10118,null);
            System.out.println("PASS package/attach: reviewed, below/within/above range, malformed and both variant markers enter automatic runtime; bad UID rejected (runtime stubbed)");
        }
        static void crossProfile() throws Throwable {
            reset(); GmsDiagnosticsHook hook=hookForActive();
            Profile other=active==LEGACY?CURRENT:LEGACY;
            Object receiver=new TrapObject(); Object[] args=new Object[0];
            for(Spec selected:other.specs()) {
                MethodHookParam p=new MethodHookParam(receiver,args,Boolean.FALSE,null);
                enable(hook,selected,p);
                unchanged(p,receiver,args,args.clone(),Boolean.FALSE,null);
                if(!active.observesClass(selected.owner)) {
                    OBSERVE.invoke(hook,Class.forName(selected.owner,false,ObserverBehaviorTest.class.getClassLoader()));
                    check(XposedBridge.hooks.isEmpty(),"observe rejects other build class "+selected.owner);
                }
            }
            System.out.println("PASS other-profile canonical contracts cannot install hooks or alter results");
        }
        static void compositeGate() throws Throwable {
            reset(); active=CURRENT; GmsDiagnosticsHook hook=hookForActive();
            XC_MethodHook w=observe(hook,"jtmb","W");
            XC_MethodHook u=observe(hook,"jtmb","U");
            XC_MethodHook supplier=observe(hook,"ecyv","ln");
            Object receiver=new TrapObject(); Object[] args=new Object[0];
            for(boolean rawW:new boolean[]{false,true}) for(boolean rawU:new boolean[]{false,true}) {
                // The fallback must cover a naturally completed supplier when
                // ART bypasses the inner W callback. No getter is invoked here.
                Log.reset();
                receiver=new TrapObject();
                Boolean original=Boolean.valueOf(rawW||rawU);
                MethodHookParam fallback=new MethodHookParam(receiver,args,original,null);
                supplier.fireAfter(fallback);
                if(original.booleanValue()) unchanged(fallback,receiver,args,args.clone(),original,null);
                else enabledOnce(fallback,receiver,args,args.clone());
                check(fallback.getResult()==Boolean.TRUE,"OR truth table returns the W-enabled outcome");
                check(count("expression=45704091|45830365 value="+original)==1,
                        "supplier logs expression result for every OR combination");
                check(count("flag=45704091")==0,"supplier never attributes composite result to a raw flag");
                check(count("gate=45704091 expression=45704091|45830365 original=false effective=true")
                        ==(original.booleanValue()?0:1),"fallback explicitly names composite scope");

                MethodHookParam untouchedU=new MethodHookParam(receiver,args,Boolean.valueOf(rawU),null);
                u.fireAfter(untouchedU);
                unchanged(untouchedU,receiver,args,args.clone(),Boolean.valueOf(rawU),null);

                // When the inner W callback runs, the supplier observes its
                // effective true. It must not invent a second false observation.
                Log.reset();
                receiver=new TrapObject();
                MethodHookParam inner=new MethodHookParam(receiver,args,Boolean.valueOf(rawW),null);
                w.fireAfter(inner);
                check(inner.getResult()==Boolean.TRUE,"direct W callback supplies true");
                MethodHookParam composed=new MethodHookParam(receiver,args,Boolean.TRUE,null);
                supplier.fireAfter(composed);
                unchanged(composed,receiver,args,args.clone(),Boolean.TRUE,null);
                check(count("method=ecyv.ln expression=45704091|45830365 value=true")==1,
                        "supplier records inner effective result without claiming raw W");
                check(count("method=ecyv.ln gate=45704091")==0,"nested supplier requires no second mutation");
            }
            Throwable uFailure=new IllegalStateException("original U failure");
            MethodHookParam failedU=new MethodHookParam(receiver,args,null,uFailure);
            u.fireAfter(failedU);
            unchanged(failedU,receiver,args,args.clone(),null,uFailure);
            MethodHookParam failedSupplier=new MethodHookParam(receiver,args,null,uFailure);
            supplier.fireAfter(failedSupplier);
            unchanged(failedSupplier,receiver,args,args.clone(),null,uFailure);
            check(testsupport.Probe.businessCalls==0&&testsupport.Probe.binderCalls==0,
                    "OR fallback introduces no active reads or Binder calls");
            System.out.println("PASS four OR combinations, nested effective-value attribution, unchanged U and preserved U exception");
        }
        public static void main(String[] args) throws Throwable {
            check(LEGACY!=null&&CURRENT!=null,"both reviewed profiles available");
            profileEntries();
            for(Profile selected:new Profile[]{LEGACY,CURRENT}) {
                active=selected;
                passivity(); providers(); lifecycle(); loaders();
                registryGate(); otherRegistrySpecs(); noncanonicalSpecs(); crossProfile();
                System.out.println("PASS dormant historical callbacks for profile "+selected.versionCode);
            }
            compositeGate();
            check(testsupport.Probe.initializations==0,"final fixture initialization zero");
            check(testsupport.Probe.businessCalls==0,"final business calls zero");
            check(testsupport.Probe.binderCalls==0,"final Binder calls zero");
            System.out.println("PASS "+checks+" entry routing and historical observer/registry behavior assertions");
            System.out.println("LIMIT: host fakes do not establish native LSPosed/ART installation or real GMS flag values");
        }
    }
'''


def main():
    output = []
    try:
        with tempfile.TemporaryDirectory(prefix='mosey-observer-tests-') as temporary:
            stage = Path(temporary)
            generated = stage / 'generated'
            classes = stage / 'classes'
            classes.mkdir()
            sources = []
            for name, body in {**STUBS, 'ObserverBehaviorTest.java': HARNESS}.items():
                path = generated / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(textwrap.dedent(body).strip() + '\n', encoding='utf-8')
                sources.append(str(path))
            production = [SOURCE / name for name in (
                'ClientPolicy.java', 'GmsDiagnosticPolicy.java',
                'DiagnosticEventLimiter.java', 'GmsRegistryEnablement.java', 'GmsDiagnosticsHook.java', 'HookLog.java')]
            compiled = subprocess.run([
                'java', '-m', 'jdk.compiler/com.sun.tools.javac.Main',
                '-source', '8', '-target', '8', '-encoding', 'UTF-8',
                '-Xlint:all,-options', '-Werror', '-d', str(classes),
                *map(str, production), *sources,
            ], capture_output=True, text=True, timeout=60)
            output.append(compiled.stdout + compiled.stderr)
            if compiled.returncode:
                raise RuntimeError('Observer host compilation failed')
            # The production lookup explicitly uses the bootstrap loader (null).
            # Append just the Dalvik fake, leaving all app/business fakes uninitialized.
            bootstrap = stage / 'bootstrap'
            delegate = Path('dalvik/system/DelegateLastClassLoader.class')
            (bootstrap / delegate).parent.mkdir(parents=True)
            shutil.copy2(classes / delegate, bootstrap / delegate)
            result = subprocess.run([
                'java', '-Xbootclasspath/a:' + str(bootstrap), '-cp', str(classes),
                'ObserverBehaviorTest',
            ], capture_output=True, text=True, timeout=30)
            output.append(result.stdout + result.stderr)
            if result.returncode:
                raise RuntimeError('Observer behavior test failed')
    finally:
        text = ''.join(output)
        EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
        EVIDENCE.write_text(text, encoding='utf-8')
        print(text, end='')


if __name__ == '__main__':
    main()
