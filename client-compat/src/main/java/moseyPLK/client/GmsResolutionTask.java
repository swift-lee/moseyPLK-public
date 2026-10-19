package moseyPLK.client;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/** One worker owns discovery and its native bridge. A timeout never activates hooks later. */
final class GmsResolutionTask {
    interface Resolver { ResolvedGateSet resolve() throws Exception; }
    interface Events { void event(String name, String detail); }
    static final class Result {
        final ResolvedGateSet gates;
        final String fingerprint;
        final String source;
        final long elapsedMs;
        Result(ResolvedGateSet gates, String fingerprint, String source, long elapsedMs) {
            this.gates = gates; this.fingerprint = fingerprint; this.source = source;
            this.elapsedMs = elapsedMs;
        }
    }

    private final Future<Result> future;
    private boolean consumed;

    GmsResolutionTask(final GmsApkSnapshot snapshot, final GmsProfileCache cache,
            final Resolver resolver, final Events events) {
        ExecutorService executor = Executors.newSingleThreadExecutor(new ThreadFactory() {
            @Override public Thread newThread(Runnable work) {
                Thread thread = new Thread(work, "MoseyGmsResolver");
                thread.setDaemon(true);
                return thread;
            }
        });
        future = executor.submit(new Callable<Result>() {
            @Override public Result call() throws Exception {
                long started = System.nanoTime();
                String stage = "gms_fingerprint", source = "unresolved";
                try {
                    String fingerprint = snapshot.gmsFingerprint();
                    stage = "cache";
                    ResolvedGateSet gates = null;
                    try { gates = cache.read(fingerprint); }
                    catch (Exception invalid) {
                        event(events, "cache_rejected", "reason=" + GmsResolutionFailure.reason(invalid));
                    }
                    source = gates == null ? "discovery" : "cache";
                    if (gates == null) {
                        stage = "module_generation";
                        String moduleGeneration = snapshot.moduleGeneration();
                        stage = "discovery";
                        gates = resolver.resolve();
                        if (gates == null) throw new IllegalStateException("resolver_returned_no_proof");
                        // Parsing and hashing open their inputs independently. Rehash both after
                        // discovery so a replacement cannot mix evidence. Module generation is
                        // deliberately a one-resolution guard, never part of the cache key.
                        stage = "source_recheck";
                        if (!fingerprint.equals(snapshot.gmsFingerprint()))
                            throw new IllegalStateException("gms_source_changed_during_resolution");
                        if (!moduleGeneration.equals(snapshot.moduleGeneration()))
                            throw new IllegalStateException("module_changed_during_resolution");
                        try { cache.write(fingerprint, gates); }
                        catch (Exception unavailable) {
                            event(events, "cache_write_failed", "reason=" + GmsResolutionFailure.reason(unavailable));
                        }
                    }
                    stage = "source_guard";
                    if (!snapshot.unchanged()) throw new IllegalStateException("source_changed");
                    Result result = new Result(gates, fingerprint, source, elapsed(started));
                    event(events, "resolution_complete", "stage=complete reason=verified source="
                            + source + " elapsed_ms=" + result.elapsedMs);
                    return result;
                } catch (Throwable rejected) {
                    // The worker owns the terminal report, including after await has timed out.
                    // No completion callback can install hooks in the current process.
                    event(events, "resolution_rejected", "stage=" + GmsResolutionFailure.stage(rejected, stage)
                            + " reason=" + GmsResolutionFailure.reason(rejected)
                            + " source=" + source + " elapsed_ms=" + elapsed(started));
                    if (rejected instanceof Exception) throw (Exception) rejected;
                    if (rejected instanceof Error) throw (Error) rejected;
                    throw new AssertionError(rejected);
                }
            }
        });
        executor.shutdown();
    }

    private static long elapsed(long started) {
        return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
    }

    private static void event(Events events, String name, String detail) {
        try { events.event(name, detail); }
        catch (Throwable ignored) { /* Diagnostics must not turn a valid proof into rejection. */ }
    }

    synchronized Result await(long timeoutMs)
            throws InterruptedException, ExecutionException, TimeoutException {
        if (consumed) throw new IllegalStateException("startup_budget_already_consumed");
        consumed = true;
        // Deliberately do not cancel: JNI must finish and close on its owning thread.
        // Only this wait returns a result to the installer; no completion callback does.
        return future.get(timeoutMs, TimeUnit.MILLISECONDS);
    }
}
