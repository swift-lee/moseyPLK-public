package moseyPLK.client;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

public final class DiagnosticEventLimiterTest {
    private static int checks;
    private static void check(boolean value, String label) {
        ++checks;
        if (!value) throw new AssertionError(label);
    }

    public static void main(String[] args) throws Exception {
        DiagnosticEventLimiter limiter = new DiagnosticEventLimiter(3, 3);
        check(limiter.admit("loader1:flag", "false"), "first false must be recorded");
        for (int i = 0; i < 100; ++i) check(!limiter.admit("loader1:flag", "false"), "dedupe repeated read");
        check(limiter.admit("loader1:flag", "true"), "changed flag preserved");
        check(limiter.admit("loader1:flag", "false"), "change back preserved");
        check(!limiter.admit("loader1:flag", "true"), "bound alternating spam");
        check(limiter.admit("loader2:flag", "false"), "second loader is independent");
        check(limiter.admit("loader1:service2", "false"), "new service instance is independent");
        check(!limiter.admit("fourth", "value"), "bound distinct keys");
        check(!limiter.admit(null, "value") && !limiter.admit("key", null), "null ignored");

        final DiagnosticEventLimiter concurrent = new DiagnosticEventLimiter(8, 8);
        final AtomicInteger accepted = new AtomicInteger();
        final CountDownLatch start = new CountDownLatch(1);
        Thread[] threads = new Thread[16];
        for (int i = 0; i < threads.length; ++i) {
            threads[i] = new Thread(new Runnable() {
                @Override public void run() {
                    try { start.await(); } catch (InterruptedException failure) {
                        Thread.currentThread().interrupt(); return;
                    }
                    for (int n = 0; n < 100; ++n) {
                        if (concurrent.admit("same", "false")) accepted.incrementAndGet();
                    }
                }
            });
            threads[i].start();
        }
        start.countDown();
        for (Thread thread : threads) thread.join();
        check(accepted.get() == 1, "concurrent callback deduplication");
        System.out.println("PASS: " + checks + " diagnostic volume/change/concurrency checks");
    }
}
