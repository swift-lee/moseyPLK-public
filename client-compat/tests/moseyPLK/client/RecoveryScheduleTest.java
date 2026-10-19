package moseyPLK.client;

import java.util.ArrayDeque;

/** Executes the actual production scheduling policy with a deterministic clock. */
public final class RecoveryScheduleTest {
    private static int checks;
    private static void check(boolean value, String label) {
        ++checks;
        if (!value) throw new AssertionError(label);
    }

    private static final class Entry {
        final Runnable task;
        final long delay;
        Entry(Runnable task, long delay) { this.task = task; this.delay = delay; }
    }
    private static final class Fake implements RecoverySchedule.Scheduler,
            RecoverySchedule.Attempt, RecoverySchedule.Events {
        final ArrayDeque<Entry> queue = new ArrayDeque<Entry>();
        int scheduled, maxPending, attempts, failures, exhausted;
        int successAt = Integer.MAX_VALUE;
        boolean throwAttempt, rejectSchedule, throwEvents;
        long elapsed;
        @Override public void schedule(Runnable task, long delay) {
            if (rejectSchedule) throw new IllegalStateException("executor unavailable");
            queue.addLast(new Entry(task, delay));
            ++scheduled;
            maxPending = Math.max(maxPending, queue.size());
        }
        @Override public boolean run() {
            ++attempts;
            if (throwAttempt) throw new LinkageError("simulate unexpected runtime error");
            return attempts >= successAt;
        }
        @Override public void failed(Throwable failure) {
            ++failures;
            if (throwEvents) throw new AssertionError("logger unavailable");
        }
        @Override public void exhausted(int count) {
            check(count == ClientPolicy.MAX_ATTEMPTS, "exact exhaustion count");
            ++exhausted;
            if (throwEvents) throw new AssertionError("logger unavailable");
        }
        void next() {
            Entry entry = queue.removeFirst();
            elapsed += entry.delay;
            entry.task.run();
        }
        void drain() {
            int guard = 0;
            while (!queue.isEmpty()) {
                if (++guard > 100) throw new AssertionError("unbounded schedule");
                next();
            }
        }
        RecoverySchedule policy() { return new RecoverySchedule(this, this, this); }
    }

    public static void main(String[] args) {
        Fake missing = new Fake(); RecoverySchedule first = missing.policy();
        for (int i = 0; i < 100; ++i) first.start();
        check(missing.queue.size() == 1, "duplicate attach schedules one chain");
        missing.drain();
        check(missing.attempts == 30 && missing.scheduled == 30 && missing.exhausted == 1,
                "30 real misses terminate exactly once");
        check(missing.maxPending == 1, "initial chain never piles up tasks");
        check(missing.elapsed == 58000L, "real requested delays sum to 58 seconds");
        first.start(); check(missing.queue.isEmpty(), "exhausted attach cannot restart loop");

        Fake early = new Fake(); early.successAt = 3;
        early.policy().start(); early.drain();
        check(early.attempts == 3 && early.exhausted == 0, "success stops retries");
        check(early.elapsed == 4000L, "stop immediately after third success");

        // Regress the important distinction between "Binder is ready" and
        // "component recovery completed". Ready Binder + transient PM failure
        // must keep the production retry chain alive, even without more hooks.
        Fake transientRecovery = new Fake();
        final int[] recoveryRounds = {0};
        RecoverySchedule componentPolicy = new RecoverySchedule(transientRecovery,
                new RecoverySchedule.Attempt() {
                    @Override public boolean run() {
                        ++recoveryRounds[0];
                        boolean binderReady = true;
                        boolean componentRecoveryComplete = recoveryRounds[0] >= 4;
                        return binderReady && componentRecoveryComplete;
                    }
                }, transientRecovery);
        componentPolicy.start();
        transientRecovery.next();
        check(recoveryRounds[0] == 1 && transientRecovery.queue.size() == 1,
                "ready Binder alone does not terminate incomplete recovery");
        transientRecovery.drain();
        check(recoveryRounds[0] == 4 && transientRecovery.elapsed == 6000L,
                "component recovery retries independently of later hook calls");
        check(transientRecovery.queue.isEmpty() && transientRecovery.exhausted == 0,
                "completed component recovery terminates retries");

        Fake broken = new Fake(); broken.throwAttempt = true; broken.throwEvents = true;
        broken.policy().start(); broken.drain();
        check(broken.attempts == 30 && broken.failures == 30 && broken.exhausted == 1,
                "Throwable and logger errors stay isolated and bounded");

        Fake late = new Fake(); RecoverySchedule latePolicy = late.policy();
        latePolicy.start(); late.drain();
        late.successAt = 31;
        for (int i = 0; i < 100; ++i) latePolicy.requestLate();
        check(late.queue.size() == 1, "100 real lookup notifications coalesce");
        late.drain();
        check(late.attempts == 31 && late.queue.isEmpty(), "late success works after timeout");
        latePolicy.requestLate(); late.drain();
        check(late.attempts == 32, "future caller can recover a newly disabled component");

        Fake pending = new Fake(); RecoverySchedule pendingPolicy = pending.policy();
        pendingPolicy.start(); pending.next(); // first failed, one delayed retry queued
        pending.successAt = 2;
        for (int i = 0; i < 100; ++i) pendingPolicy.requestLate();
        check(pending.queue.size() == 2, "one initial retry plus at most one extra task");
        pending.drain();
        check(pending.attempts <= 3 && pending.maxPending == 2 && pending.queue.isEmpty(),
                "interleaved initial and late readiness remain bounded");

        Fake rejected = new Fake(); rejected.rejectSchedule = true;
        RecoverySchedule rejectPolicy = rejected.policy(); rejectPolicy.start();
        rejectPolicy.requestLate();
        check(rejected.failures == 2 && rejected.attempts == 0, "executor rejection isolated");
        rejected.rejectSchedule = false; rejected.successAt = 1;
        rejectPolicy.requestLate(); rejected.drain();
        check(rejected.attempts == 1, "late queue flag cleared after rejection");

        Fake lateError = new Fake(); lateError.throwAttempt = true;
        RecoverySchedule lateErrorPolicy = lateError.policy();
        lateErrorPolicy.requestLate(); lateError.drain();
        lateError.throwAttempt = false; lateError.successAt = 2;
        lateErrorPolicy.requestLate(); lateError.drain();
        check(lateError.attempts == 2 && lateError.failures == 1,
                "late task Throwable releases duplicate guard");
        System.out.println("PASS: " + checks + " production scheduler checks");
    }
}
