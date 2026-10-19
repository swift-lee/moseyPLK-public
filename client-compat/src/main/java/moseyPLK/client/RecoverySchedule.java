package moseyPLK.client;

import java.util.concurrent.atomic.AtomicBoolean;

/** Bounded scheduling shared by the production worker and host tests. */
public final class RecoverySchedule {
    public interface Scheduler { void schedule(Runnable task, long delayMillis); }
    public interface Attempt { boolean run() throws Exception; }
    public interface Events {
        void failed(Throwable failure);
        void exhausted(int attempts);
    }

    private final Scheduler scheduler;
    private final Attempt attempt;
    private final Events events;
    private final AtomicBoolean started = new AtomicBoolean();
    private final AtomicBoolean lateQueued = new AtomicBoolean();
    private volatile boolean ready;

    public RecoverySchedule(Scheduler scheduler, Attempt attempt, Events events) {
        this.scheduler = scheduler;
        this.attempt = attempt;
        this.events = events;
    }

    public void start() {
        if (started.compareAndSet(false, true)) enqueueInitial(0);
    }

    private void enqueueInitial(final int count) {
        try {
            scheduler.schedule(new Runnable() {
                @Override public void run() {
                    if (ready) return;
                    if (tryOnce()) return;
                    if (count + 1 < ClientPolicy.MAX_ATTEMPTS) enqueueInitial(count + 1);
                    else safelyExhausted(count + 1);
                }
            }, count == 0 ? 0L : ClientPolicy.RETRY_MILLIS);
        } catch (Throwable failure) {
            safelyFailed(failure);
        }
    }

    /** A real successful client lookup may request one further recovery task. */
    public void requestLate() {
        if (!lateQueued.compareAndSet(false, true)) return;
        try {
            scheduler.schedule(new Runnable() {
                @Override public void run() {
                    try { tryOnce(); }
                    finally { lateQueued.set(false); }
                }
            }, 0L);
        } catch (Throwable failure) {
            lateQueued.set(false);
            safelyFailed(failure);
        }
    }

    private boolean tryOnce() {
        try {
            boolean success = attempt.run();
            if (success) ready = true;
            return success;
        } catch (Throwable failure) {
            safelyFailed(failure);
            return false;
        }
    }

    // Even a diagnostic failure must not escape into the hooked application.
    private void safelyFailed(Throwable failure) {
        try { events.failed(failure); } catch (Throwable ignored) { /* isolated */ }
    }

    private void safelyExhausted(int count) {
        try { events.exhausted(count); } catch (Throwable ignored) { /* isolated */ }
    }
}
