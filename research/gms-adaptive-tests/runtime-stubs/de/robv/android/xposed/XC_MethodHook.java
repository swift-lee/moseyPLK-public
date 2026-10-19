package de.robv.android.xposed;

public class XC_MethodHook {
    protected void beforeHookedMethod(MethodHookParam call) throws Throwable { }
    public final void fireBefore(MethodHookParam call) throws Throwable { beforeHookedMethod(call); }
    protected void afterHookedMethod(MethodHookParam call) throws Throwable { }
    public final void fireAfter(MethodHookParam call) throws Throwable { afterHookedMethod(call); }
    public static final class Unhook {
        private final java.lang.reflect.Method method;
        public Unhook(java.lang.reflect.Method method) { this.method = method; }
        public void unhook() {
            XposedBridge.removals++;
            if (XposedBridge.failUnhook) throw new IllegalStateException("unhook_failure");
            XposedBridge.hooks.remove(method);
        }
    }
    public static final class MethodHookParam {
        public Object thisObject;
        public Object[] args;
        private Object result;
        private Throwable throwable;
        public int writes;
        public MethodHookParam(Object result, Throwable throwable, Object[] args) {
            this.result = result; this.throwable = throwable; this.args = args;
        }
        public Object getResult() { return result; }
        public Throwable getThrowable() { return throwable; }
        public boolean hasThrowable() { return throwable != null; }
        public void setResult(Object value) { writes++; result = value; throwable = null; }
    }
}
