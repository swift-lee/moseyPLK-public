package moseyPLK.client;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

/** Executable host contracts for actual production cache, deadline and hook transaction. */
public final class GmsAdaptiveCoreTest {
    static int checks;
    static final String EVIDENCE = repeat('e');
    static final String COMPATIBILITY = repeat('c');
    static final ResolvedGateSet GATES = ResolvedGateSet.phenotype(
            "Lfixtures/Getter;->gate()Z", EVIDENCE);
    static String repeat(char c) { char[] text = new char[64]; Arrays.fill(text, c); return new String(text); }
    static void check(boolean value, String message) {
        checks++; if (!value) throw new AssertionError(message);
    }
    interface Checked { void run() throws Throwable; }
    static void rejects(Checked work, String message) throws Throwable {
        boolean rejected = false;
        try { work.run(); } catch (Exception expected) { rejected = true; }
        check(rejected, message);
    }
    static File data(Path directory, String name, String value) throws Exception {
        Path path = directory.resolve(name); Files.write(path, value.getBytes("UTF-8")); return path.toFile();
    }
    static GmsApkSnapshot snapshot(File base, File module, String identity) throws Exception {
        return new GmsApkSnapshot(base, Collections.<File>emptyList(), module, identity);
    }
    static final GmsResolutionTask.Events QUIET = new GmsResolutionTask.Events() {
        @Override public void event(String name, String detail) { }
    };

    static void model() throws Throwable {
        check("fixtures.Getter".equals(ResolvedGateSet.owner(GATES.getterDescriptor)), "owner descriptor");
        check("gate".equals(ResolvedGateSet.name(GATES.getterDescriptor)), "method descriptor");
        for (String getter : new String[]{null, "foo", "LX;->g(I)Z", "LX;->g()Ljava/lang/Boolean;"})
            rejects(() -> ResolvedGateSet.verified(getter, GATES.supplierDescriptor, null, "A", EVIDENCE), "invalid getter");
        check(GATES.supplierDescriptor == null && GATES.secondaryGetterDescriptor == null
                && "A".equals(GATES.expression), "only Phenotype getter in approved payload");
        rejects(() -> ResolvedGateSet.verified(GATES.getterDescriptor,
                "Lfixtures/Supplier;->value()Ljava/lang/Object;", null, "A", EVIDENCE), "legacy supplier rejected");
        rejects(() -> ResolvedGateSet.verified(GATES.getterDescriptor, null,
                "Lfixtures/Getter;->secondary()Z", "A", EVIDENCE), "secondary flag rejected");
        rejects(() -> ResolvedGateSet.verified(GATES.getterDescriptor, null, null,
                "A_OR_B", EVIDENCE), "legacy composite payload rejected");
        rejects(() -> ResolvedGateSet.phenotype(GATES.getterDescriptor, "bad"), "invalid evidence digest");
    }

    static void snapshots(Path directory) throws Throwable {
        File base = data(directory, "base.apk", "base-1"), module = data(directory, "module.apk", "module-1");
        File split = data(directory, "split.apk", "split-1"), split2 = data(directory, "split2.apk", "split-2");
        GmsApkSnapshot before = snapshot(base, module, "identity");
        String key = before.gmsFingerprint();
        String moduleGeneration = before.moduleGeneration();
        FileTime originalTime = Files.getLastModifiedTime(base.toPath());
        Files.write(base.toPath(), "base-2".getBytes("UTF-8")); Files.setLastModifiedTime(base.toPath(), originalTime);
        check(before.unchanged(), "same metadata fixture intentional");
        check(!key.equals(before.gmsFingerprint()), "same size/mtime never accepts stale GMS content");
        GmsApkSnapshot changedIdentity = snapshot(base, module, "changed-signer-version-user");
        check(!before.gmsFingerprint().equals(changedIdentity.gmsFingerprint()), "GMS identity bound");
        String prior = changedIdentity.gmsFingerprint();
        Files.write(module.toPath(), "module-2".getBytes("UTF-8"));
        GmsApkSnapshot updatedModule = snapshot(base, module, changedIdentity.identity);
        check(prior.equals(updatedModule.gmsFingerprint()), "module excluded from persistent GMS identity");
        check(!moduleGeneration.equals(updatedModule.moduleGeneration()), "module content has separate generation");
        GmsApkSnapshot splits = new GmsApkSnapshot(base, Arrays.asList(split, split2), module, "identity");
        check(splits.gmsFingerprint().equals(new GmsApkSnapshot(base, Arrays.asList(split2, split), module,
                "identity").gmsFingerprint()), "split order canonical");
        String priorSplit = splits.gmsFingerprint();
        Files.write(split.toPath(), "split-x".getBytes("UTF-8"));
        check(!priorSplit.equals(new GmsApkSnapshot(base, Arrays.asList(split, split2), module,
                "identity").gmsFingerprint()), "split content bound");
        rejects(() -> new GmsApkSnapshot(base, Arrays.asList(base), module, "identity"), "duplicate source");
        rejects(() -> snapshot(base, base, "identity"), "module cannot alias base");
        Files.write(base.toPath(), "new longer base".getBytes("UTF-8"));
        check(!before.unchanged(), "replacement detected");
        rejects(() -> before.gmsFingerprint(), "old snapshot cannot rehash changed GMS generation");
    }

    static void caches(Path directory) throws Throwable {
        Path parent = Files.createDirectory(directory.resolve("cache"));
        GmsProfileCache cache = new GmsProfileCache(parent.toFile(), COMPATIBILITY);
        String fingerprint = repeat('a');
        Path legacy = parent.resolve("moseyplk-gms-resolver/profile-v1.bin");
        Files.createDirectories(legacy.getParent());
        byte[] legacyBytes = "schema-two-cache-is-left-untouched".getBytes("UTF-8");
        Files.write(legacy, legacyBytes);
        check(cache.read(fingerprint) == null, "cache miss");
        cache.write(fingerprint, GATES);
        ResolvedGateSet restored = cache.read(fingerprint);
        check(restored != null && restored != GATES && restored.getterDescriptor.equals(GATES.getterDescriptor)
                && restored.expression.equals("A") && restored.supplierDescriptor == null
                && restored.secondaryGetterDescriptor == null && restored.evidenceDigest.equals(EVIDENCE), "descriptor roundtrip");
        check(cache.read(repeat('b')) == null, "foreign content key");
        check(Arrays.equals(Files.readAllBytes(legacy), legacyBytes), "schema-two file preserved without migration");
        GmsProfileCache foreignCompatibility = new GmsProfileCache(parent.toFile(), repeat('d'));
        check(foreignCompatibility.read(fingerprint) == null, "foreign resolver compatibility ID rejected");
        Path file = parent.resolve("moseyplk-gms-resolver/profile-v3.bin");
        byte[] good = Files.readAllBytes(file);
        byte[] oldRule = good.clone();
        java.nio.ByteBuffer.wrap(oldRule).putInt(8, ResolvedGateSet.RULE_VERSION - 1);
        byte[] oldPayload = Arrays.copyOf(oldRule, oldRule.length - 32);
        System.arraycopy(GmsApkSnapshot.digest().digest(oldPayload), 0, oldRule, oldPayload.length, 32);
        Files.write(file, oldRule);
        check(cache.read(fingerprint) == null, "previous rule rejected even with valid digest and matching identity");
        byte[] oldSchema = good.clone();
        java.nio.ByteBuffer.wrap(oldSchema).putInt(4, 2);
        byte[] schemaPayload = Arrays.copyOf(oldSchema, oldSchema.length - 32);
        System.arraycopy(GmsApkSnapshot.digest().digest(schemaPayload), 0, oldSchema, schemaPayload.length, 32);
        Files.write(file, oldSchema);
        check(cache.read(fingerprint) == null, "schema-two payload rejected with valid digest");
        for (int length : new int[]{0, 12, 31, 32, good.length - 1, 8193, 10000}) {
            Files.write(file, Arrays.copyOf(good, length));
            check(cache.read(fingerprint) == null, "truncated/oversized cache " + length);
        }
        byte[] damaged = good.clone(); damaged[12] ^= 1; Files.write(file, damaged);
        check(cache.read(fingerprint) == null, "checksum corruption");
        cache.write(fingerprint, GATES);
        check(cache.read(fingerprint) != null, "corruption replaced atomically");
        check(Files.getPosixFilePermissions(file).equals(java.nio.file.attribute.PosixFilePermissions.fromString("rw-------")),
                "private file permissions");
        check(Files.getPosixFilePermissions(file.getParent()).equals(
                java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")), "private directory permissions");
        Path target = directory.resolve("outside.bin"); Files.write(target, good); Files.delete(file);
        Files.createSymbolicLink(file, target);
        check(cache.read(fingerprint) == null, "cache symlink refused");
        rejects(() -> cache.write(fingerprint, GATES), "cache symlink refused on write");
        Files.delete(file);
        Path originalDir = file.getParent(); Path moved = directory.resolve("moved");
        Files.move(originalDir, moved); Files.createSymbolicLink(originalDir, moved);
        rejects(() -> cache.read(fingerprint), "directory replaced by symlink refused");
        rejects(() -> cache.write(fingerprint, GATES), "write through replaced symlink refused");
        rejects(() -> new GmsProfileCache(parent.toFile(), "bad"), "malformed compatibility ID rejected");
    }

    static void tasks(Path directory) throws Throwable {
        Path parent = Files.createDirectory(directory.resolve("task-cache"));
        File base = data(directory, "task-base.apk", "base"), module = data(directory, "task-module.apk", "module");
        GmsApkSnapshot snapshot = snapshot(base, module, "version");
        GmsProfileCache cache = new GmsProfileCache(parent.toFile(), COMPATIBILITY);
        AtomicInteger calls = new AtomicInteger();
        Thread caller = Thread.currentThread();
        GmsResolutionTask task = new GmsResolutionTask(snapshot, cache, () -> {
            check(Thread.currentThread() != caller, "discovery owns worker"); calls.incrementAndGet(); return GATES;
        }, QUIET);
        GmsResolutionTask.Result first = task.await(2000);
        check(first.gates == GATES && first.source.equals("discovery") && calls.get() == 1, "one discovery");
        rejects(() -> task.await(2000), "result only consumed once");
        GmsResolutionTask.Result cached = new GmsResolutionTask(snapshot, cache, () -> {
            throw new AssertionError("cache hit must not load native or scan");
        }, QUIET).await(2000);
        check(cached.source.equals("cache") && cached.gates.getterDescriptor.equals(GATES.getterDescriptor), "cache bypasses resolver");
        Files.write(module.toPath(), "updated-module".getBytes("UTF-8"));
        GmsApkSnapshot moduleUpdate = snapshot(base, module, "version");
        GmsResolutionTask.Result crossModule = new GmsResolutionTask(moduleUpdate, cache, () -> {
            throw new AssertionError("compatible module update must reuse profile");
        }, QUIET).await(2000);
        check(crossModule.source.equals("cache"), "module update alone preserves compatible cache key");

        CountDownLatch release = new CountDownLatch(1), finished = new CountDownLatch(1);
        GmsApkSnapshot next = snapshot(base, module, "next-version");
        GmsResolutionTask slow = new GmsResolutionTask(next, cache, () -> {
            if (!release.await(5, TimeUnit.SECONDS)) throw new IllegalStateException("test_deadlock");
            return GATES;
        }, (name, detail) -> { if (name.equals("resolution_complete")) finished.countDown(); });
        try { slow.await(10); throw new AssertionError("expected timeout"); }
        catch (TimeoutException expected) { check(true, "startup timed out"); }
        finally { release.countDown(); }
        check(finished.await(5, TimeUnit.SECONDS), "timeout does not interrupt bridge owner");
        check(cache.read(next.gmsFingerprint()) != null, "late result saved for next process");
        rejects(() -> slow.await(2000), "late result cannot be consumed for current process");

        GmsApkSnapshot newer = snapshot(base, module, "unsupported-version");
        try {
            new GmsResolutionTask(newer, cache, () -> { throw new IllegalStateException("unproved"); }, QUIET).await(2000);
            throw new AssertionError("expected rejected discovery");
        } catch (ExecutionException expected) { check(true, "rejection propagated"); }
        check(cache.read(newer.gmsFingerprint()) == null, "rejection not cached as approved");
        GmsApkSnapshot replaced = snapshot(base, module, "replaced-version");
        try {
            new GmsResolutionTask(replaced, cache, () -> {
                Files.write(base.toPath(), "new-package-generation".getBytes("UTF-8")); return GATES;
            }, QUIET).await(2000);
            throw new AssertionError("expected changed snapshot rejection");
        } catch (ExecutionException expected) { check(true, "source replacement rejects parsed result"); }
        GmsApkSnapshot replacedModule = snapshot(base, module, "module-replaced-during-resolution");
        try {
            new GmsResolutionTask(replacedModule, cache, () -> {
                Files.write(module.toPath(), "replacement-module-generation".getBytes("UTF-8"));
                return GATES;
            }, QUIET).await(2000);
            throw new AssertionError("expected changed module generation rejection");
        } catch (ExecutionException expected) {
            check(true, "module replacement rejects mixed resolution even though module is outside cache key");
        }
    }

    static void transactions() throws Throwable {
        GmsHookTransaction complete = new GmsHookTransaction();
        AtomicInteger installs = new AtomicInteger();
        check(!complete.shouldEnable(false, Boolean.FALSE, 0), "initially inactive");
        complete.install((role, state) -> {
            check(role == 0, "only getter installed");
            check(!state.shouldEnable(false, Boolean.FALSE, 0), "inactive until installation returns");
            installs.incrementAndGet(); return () -> { };
        });
        check(installs.get() == 1 && complete.shouldEnable(false, Boolean.FALSE, 0), "single getter active");
        check(complete.install((role, state) -> { throw new AssertionError("duplicate install"); }), "no duplicate hook");
        for (Object value : new Object[]{null, Boolean.TRUE, "false", Integer.valueOf(0)})
            check(!complete.shouldEnable(false, value, 0), "only Boolean false changes");
        check(!complete.shouldEnable(true, Boolean.FALSE, 0), "exception preserved");
        check(!complete.shouldEnable(false, Boolean.FALSE, 1), "wrong arity preserved");
        GmsHookTransaction failed = new GmsHookTransaction();
        rejects(() -> failed.install((role, state) -> {
            throw new IllegalStateException("injected_getter_failure");
        }), "getter hook failure propagated");
        check(!failed.shouldEnable(false, Boolean.FALSE, 0), "failed installation remains inert");
        check(!failed.install((role, state) -> { throw new AssertionError("failed transaction retried"); }), "failure terminal");
        GmsHookTransaction missing = new GmsHookTransaction();
        rejects(() -> missing.install((role, state) -> null), "null backend handle rejected");
        check(!missing.shouldEnable(false, Boolean.FALSE, 0), "null backend never active");
    }

    static final class Reports implements GmsResolutionTask.Events {
        final List<String> lines = Collections.synchronizedList(new ArrayList<String>());
        final CountDownLatch terminal = new CountDownLatch(1);
        volatile boolean throwsOnEvent;
        @Override public void event(String name, String detail) {
            lines.add(name + " " + detail);
            if (name.equals("resolution_complete") || name.equals("resolution_rejected")) terminal.countDown();
            if (throwsOnEvent) throw new AssertionError("diagnostic_backend_failed");
        }
        int count(String event) {
            int found = 0;
            synchronized (lines) { for (String line : lines) if (line.startsWith(event + " ")) found++; }
            return found;
        }
        String terminalLine() {
            synchronized (lines) {
                for (String line : lines)
                    if (line.startsWith("resolution_complete ") || line.startsWith("resolution_rejected ")) return line;
            }
            throw new AssertionError("missing terminal report");
        }
    }

    static final class ClassifiedFailure extends Exception implements GmsResolutionFailure.Classified {
        private static final long serialVersionUID = 1L;
        private final String phase, category;
        ClassifiedFailure(String stage, String reason) { phase = stage; category = reason; }
        @Override public String stage() { return phase; }
        @Override public String reason() { return category; }
    }

    static void terminalDiagnostics(Path directory) throws Throwable {
        File base = data(directory, "diagnostic-base.apk", "base");
        File module = data(directory, "diagnostic-module.apk", "module");
        GmsProfileCache cache = new GmsProfileCache(
                Files.createDirectory(directory.resolve("diagnostic-cache")).toFile(), COMPATIBILITY);
        for (boolean success : new boolean[]{false, true}) {
            CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
            Reports reports = new Reports();
            GmsApkSnapshot version = snapshot(base, module, "timeout-" + success);
            ClassifiedFailure failure = new ClassifiedFailure("supplier", "expression_rejected:Lprivate/Name;");
            GmsResolutionTask task = new GmsResolutionTask(version, cache, () -> {
                entered.countDown();
                if (!release.await(5, TimeUnit.SECONDS)) throw new IllegalStateException("test_deadlock");
                if (!success) throw failure;
                return GATES;
            }, reports);
            check(entered.await(5, TimeUnit.SECONDS), "worker reached controlled resolver");
            try { task.await(10); throw new AssertionError("expected timeout"); }
            catch (TimeoutException expected) { check(true, "deadline ends before controlled outcome"); }
            check(reports.lines.isEmpty(), "timeout alone does not claim terminal resolution");
            release.countDown();
            check(reports.terminal.await(5, TimeUnit.SECONDS), "late terminal outcome is reported");
            check(reports.count("resolution_complete") == (success ? 1 : 0)
                    && reports.count("resolution_rejected") == (success ? 0 : 1), "exactly one late terminal report");
            String expected = success ? "resolution_complete stage=complete reason=verified"
                    : "resolution_rejected stage=supplier reason=expression_rejected";
            check(reports.terminalLine().matches(expected + " source=discovery elapsed_ms=[0-9]+"),
                    "late report includes sanitized category, phase, source, elapsed");
            check((cache.read(version.gmsFingerprint()) != null) == success,
                    "only late success writes next-process cache");
            rejects(() -> task.await(2000), "late outcome never becomes a current-process activation result");
        }

        for (boolean loggerFails : new boolean[]{false, true}) {
            Reports reports = new Reports(); reports.throwsOnEvent = loggerFails;
            IllegalStateException original = new IllegalStateException("unproved");
            GmsResolutionTask task = new GmsResolutionTask(snapshot(base, module, "failure-" + loggerFails), cache,
                    () -> { throw original; }, reports);
            try { task.await(2000); throw new AssertionError("expected failure"); }
            catch (ExecutionException expected) {
                check(expected.getCause() == original, "original failure preserved despite diagnostic backend");
            }
            check(reports.count("resolution_rejected") == 1 && reports.count("resolution_complete") == 0,
                    "within-budget rejection has exactly one terminal attempt");
            check(reports.terminalLine().matches(
                    "resolution_rejected stage=discovery reason=unproved source=discovery elapsed_ms=[0-9]+"),
                    "within-budget terminal details complete");
        }

        Reports failedLogger = new Reports(); failedLogger.throwsOnEvent = true;
        GmsApkSnapshot valid = snapshot(base, module, "valid-failed-logger");
        GmsResolutionTask.Result validResult = new GmsResolutionTask(valid, cache, () -> GATES, failedLogger).await(2000);
        check(validResult.gates == GATES && cache.read(valid.gmsFingerprint()) != null,
                "terminal logger failure cannot reject valid proof or cached result");
        check(failedLogger.count("resolution_complete") == 1 && failedLogger.count("resolution_rejected") == 0,
                "logger failure cannot create a second terminal event");

        Path unavailable = Files.createDirectory(directory.resolve("unavailable-cache"));
        GmsProfileCache unavailableCache = new GmsProfileCache(unavailable.toFile(), COMPATIBILITY);
        Files.createSymbolicLink(unavailable.resolve("moseyplk-gms-resolver"),
                Files.createDirectory(directory.resolve("cache-symlink-target")));
        Reports warningLogger = new Reports(); warningLogger.throwsOnEvent = true;
        GmsResolutionTask.Result uncached = new GmsResolutionTask(snapshot(base, module, "cache-unavailable"),
                unavailableCache, () -> GATES, warningLogger).await(2000);
        check(uncached.gates == GATES && uncached.source.equals("discovery"),
                "cache warnings and their failed diagnostics preserve successful discovery");
        check(warningLogger.count("cache_rejected") == 1 && warningLogger.count("cache_write_failed") == 1
                && warningLogger.count("resolution_complete") == 1 && warningLogger.count("resolution_rejected") == 0,
                "failed cache warning logging does not duplicate terminal outcome");

        ClassifiedFailure malformed = new ClassifiedFailure("/private/path", "/private/category:raw");
        check(GmsResolutionFailure.stage(malformed, "discovery").equals("discovery"), "malformed stage excluded");
        check(GmsResolutionFailure.reason(malformed).equals("ClassifiedFailure"), "malformed reason excluded");
        check(GmsResolutionFailure.reason(new IllegalStateException("/private/path")).equals("IllegalStateException"),
                "unclassified exception message excluded");
        GmsResolutionFailure.AtStage nativeFailure = new GmsResolutionFailure.AtStage("native_load",
                new UnsatisfiedLinkError("/private/module.apk!/lib/arm64-v8a/libdexkit.so"));
        check(nativeFailure.stage().equals("native_load")
                && GmsResolutionFailure.reason(nativeFailure).equals("UnsatisfiedLinkError"),
                "native load phase retained without linker details");
    }

    public static void main(String[] args) throws Throwable {
        Path directory = new File(args[0]).toPath();
        model(); snapshots(directory); caches(directory); tasks(directory); transactions(); terminalDiagnostics(directory);
        System.out.println("PASS " + checks + " production model/cache/content-identity/deadline/transaction assertions");
    }
}
