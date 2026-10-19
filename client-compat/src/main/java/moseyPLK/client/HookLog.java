package moseyPLK.client;

import android.util.Log;
import de.robv.android.xposed.XposedBridge;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/** Independent bounded sinks; LSPosed transport never runs in a natural getter callback. */
final class HookLog {
    private static final ThreadPoolExecutor MODULE = new ThreadPoolExecutor(0, 1, 10,
            TimeUnit.SECONDS, new ArrayBlockingQueue<Runnable>(64), new ThreadFactory() {
                @Override public Thread newThread(Runnable work) {
                    Thread thread = new Thread(work, "MoseyModuleLog"); thread.setDaemon(true); return thread;
                }
            }, new ThreadPoolExecutor.DiscardPolicy());
    private HookLog() { }
    static void write(String tag, String message) { write(tag, message, true); }
    static void write(String tag, String message, boolean moduleLog) {
        try { Log.i(tag, message); } catch (Throwable ignored) { }
        if (!moduleLog) return;
        try {
            final String line = "[moseyPLK.client] " + tag + " " + message;
            MODULE.execute(new Runnable() {
                @Override public void run() {
                    try { XposedBridge.log(line); } catch (Throwable ignored) { }
                }
            });
        } catch (Throwable ignored) { }
    }
}
