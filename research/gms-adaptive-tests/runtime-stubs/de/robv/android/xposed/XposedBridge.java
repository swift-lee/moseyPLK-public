package de.robv.android.xposed;

import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.util.LinkedHashMap;
import java.util.Map;

public final class XposedBridge {
    public static final Map<Method, XC_MethodHook> hooks = new LinkedHashMap<Method, XC_MethodHook>();
    public static final Map<Method, XC_MethodHook> history = new LinkedHashMap<Method, XC_MethodHook>();
    public static int getXposedVersion() { return 82; }
    public static int businessAttempts, removals, pendingChecks;
    public static int failAt;
    public static int nullAt;
    public static Object pendingResult = Boolean.FALSE;
    public static boolean failUnhook;
    public static final java.util.List<String> logLines = java.util.Collections.synchronizedList(new java.util.ArrayList<String>());
    public static boolean failLog;
    public static void log(String message) {
        if (failLog) throw new IllegalStateException("lsposed_logger_unavailable");
        logLines.add(message);
    }
    public static XC_MethodHook.Unhook hookMethod(Member member, XC_MethodHook callback) {
        Method method = (Method) member;
        if (method.getDeclaringClass().getName().startsWith("runtimefixtures.")) {
            businessAttempts++;
            if (businessAttempts == failAt) throw new IllegalStateException("injected_hook_failure");
            XC_MethodHook.MethodHookParam pending = new XC_MethodHook.MethodHookParam(
                    pendingResult, null, new Object[0]);
            try { callback.fireAfter(pending); }
            catch (Throwable failure) { throw new AssertionError("Pending callback failed", failure); }
            if (pending.writes != 0) throw new AssertionError("Hook active before transaction commit");
            pendingChecks++;
            history.put(method, callback);
        }
        hooks.put(method, callback);
        if (method.getDeclaringClass().getName().startsWith("runtimefixtures.")
                && businessAttempts == nullAt) return null;
        return new XC_MethodHook.Unhook(method);
    }
    public static void reset() {
        hooks.clear(); history.clear(); logLines.clear(); failLog = false; businessAttempts = 0; removals = 0;
        pendingChecks = 0; failAt = 0; nullAt = 0; pendingResult = Boolean.FALSE; failUnhook = false;
    }
}
