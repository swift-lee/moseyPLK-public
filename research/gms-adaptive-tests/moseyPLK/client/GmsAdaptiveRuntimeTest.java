package moseyPLK.client;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;
import android.os.Process;
import android.util.Log;
import dalvik.system.BaseDexClassLoader;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

import java.io.File;
import java.io.FileOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** Executes production Android coordination against host APIs, never GMS/ART/native code. */
public final class GmsAdaptiveRuntimeTest {
    private static final String GETTER = "Lruntimefixtures/Getter;->gate()Z";
    private static final String SUPPLIER = "Lruntimefixtures/Supplier;->value()Ljava/lang/Object;";
    private static final String PROOF = repeat('a');
    private static final ResolvedGateSet GATES = ResolvedGateSet.phenotype(GETTER, PROOF);
    private static Path work, bytecode;
    private static byte[][] publicCertificates;
    private static int assertions, scenarios;

    private interface Checked { void run() throws Throwable; }
    private static String repeat(char value) {
        char[] values = new char[64]; Arrays.fill(values, value); return new String(values);
    }
    private static void check(boolean value, String message) {
        assertions++;
        if (!value) throw new AssertionError(message);
    }
    private static void scenario(String name, Checked body) throws Throwable {
        body.run(); scenarios++;
        check(testsupport.Probe.initializations == 0, name + ": no business class initialization");
        check(testsupport.Probe.businessCalls == 0, name + ": no active business method calls");
        System.out.println("PASS runtime " + name);
    }
    private static void rejects(String reason, Checked work) throws Throwable {
        try { work.run(); }
        catch (Exception rejected) {
            check(reason.equals(rejected.getMessage()), "expected " + reason + ", got " + rejected);
            return;
        }
        throw new AssertionError("Expected rejection: " + reason);
    }
    private static Object invoke(Object receiver, String name, Class<?>[] parameters, Object... args)
            throws Throwable {
        Method method = GmsAdaptiveRuntime.class.getDeclaredMethod(name, parameters);
        method.setAccessible(true);
        try { return method.invoke(receiver, args); }
        catch (InvocationTargetException failed) { throw failed.getCause(); }
    }
    private static String identity(PackageInfo info) throws Throwable {
        return (String) invoke(null, "identity", new Class<?>[]{PackageInfo.class}, info);
    }
    private static void observe(GmsAdaptiveRuntime runtime, Class<?> type) throws Throwable {
        invoke(runtime, "observe", new Class<?>[]{Class.class}, type);
    }
    private static boolean logged(String fragment) {
        for (String line : Log.lines) if (line.contains(fragment)) return true;
        return false;
    }
    private static int logCount(String fragment) {
        int count = 0;
        for (String line : Log.lines) if (line.contains(fragment)) count++;
        return count;
    }
    private static int logIndex(String fragment) {
        for (int i = 0; i < Log.lines.size(); i++) if (Log.lines.get(i).contains(fragment)) return i;
        return -1;
    }
    private static void emptyHooks(String reason) {
        check(XposedBridge.businessAttempts == 0, reason + ": no hook attempts");
        check(logged(reason), "rejection logged: " + reason);
    }
    private static void zip(File target, String entry, byte[] bytes) throws Exception {
        try (ZipOutputStream output = new ZipOutputStream(new FileOutputStream(target))) {
            if (entry != null) {
                output.putNextEntry(new ZipEntry(entry));
                output.write(bytes);
                output.closeEntry();
            }
        }
    }

    private static Signature[] signatures(byte[][] certificates) {
        Signature[] result = new Signature[certificates.length];
        for (int i = 0; i < result.length; i++) result[i] = new Signature(certificates[i]);
        return result;
    }

    private static SigningInfo signing(byte[] current, byte[][] history) {
        SigningInfo result = new SigningInfo();
        result.signers = new Signature[]{new Signature(current)};
        result.history = history == null ? null : signatures(history);
        return result;
    }

    private static String certificateHash(byte[] certificate) throws Exception {
        return GmsApkSnapshot.hex(GmsApkSnapshot.digest().digest(certificate));
    }

    private static void versionAdvisories() throws Throwable {
        long[][] cases = {
                {1, 0, 0, 1}, {263161028L, 0, 0, 1}, {263161029L, 1, 1, 0},
                {263332035L, 1, 1, 0}, {263367035L, 1, 1, 0}, {263436035L, 1, 1, 0},
                {263465022L, 1, 1, 0}, {263633004L, 1, 1, 0}, {263633035L, 1, 1, 0},
                {263633034L, 1, 0, 0}, {263633036L, 2, 0, 1}, {Long.MAX_VALUE, 2, 0, 1},
                {0, 3, 0, 0}, {-1, 3, 0, 0}};
        for (long[] sample : cases) {
            GmsVersionAdvisory result = GmsVersionAdvisory.evaluate(sample[0]);
            check(result.position.ordinal() == sample[1], "code determines advisory position");
            check(result.knownVersionCode == (sample[2] == 1), "known means exact full code match");
            check(result.needsRangeWarning() == (sample[3] == 1), "only outside range warns");
            check(result.versionCode == sample[0], "long code preserved without truncation");
        }
        for (long code : new long[]{1, 263161029L, 263400000L, 263633035L, Long.MAX_VALUE}) {
            Fixture fixture = new Fixture(false, "version-name-is-display-only", code); fixture.cache();
            GmsAdaptiveRuntime.start(fixture.context, fixture.loader, false);
            check(XposedBridge.businessAttempts == 1 && logged("adaptive_hooks_active"),
                    "code advisory never gates verified Phenotype result");
            check(logCount("event=gms_version_advisory ") == 1
                    && logged(GmsVersionAdvisory.evaluate(code).detail()),
                    "runtime emits code advisory once and continues");
        }
    }

    private static void signerTrust() throws Throwable {
        check(GmsSignerTrust.currentSigner(signing(publicCertificates[0], null))
                .equals(certificateHash(publicCertificates[0])), "original reviewed signer accepted directly");
        for (int current = 1; current < publicCertificates.length; current++) {
            byte[][] history = Arrays.copyOf(publicCertificates, current + 1);
            check(GmsSignerTrust.currentSigner(signing(publicCertificates[current], history))
                    .equals(certificateHash(publicCertificates[current])),
                    "historical/current descendant accepted with verified history");
        }
        // This API fake models Android having verified a later rotation. The arbitrary
        // future bytes are not presented as an actual certificate or proof of rotation.
        byte[] future = new byte[]{91, 92, 93};
        byte[][] futureHistory = Arrays.copyOf(publicCertificates, 4); futureHistory[3] = future;
        check(GmsSignerTrust.currentSigner(signing(future, futureHistory)).equals(certificateHash(future)),
                "future platform-verified descendant keeps actual current fingerprint");
        rejects("unreviewed_gms_signer", () -> GmsSignerTrust.currentSigner(signing(future, null)));
        rejects("unreviewed_gms_signer", () -> GmsSignerTrust.currentSigner(signing(future,
                new byte[][]{future})));
        rejects("unreviewed_gms_signer", () -> GmsSignerTrust.currentSigner(signing(future,
                new byte[][]{new byte[]{7}, future})));
        rejects("invalid_signing_history", () -> GmsSignerTrust.currentSigner(signing(future,
                publicCertificates)));
        rejects("unreviewed_gms_signer", () -> GmsSignerTrust.currentSigner(signing(publicCertificates[2],
                new byte[][]{publicCertificates[1], publicCertificates[2]})));
        SigningInfo missing = signing(future, futureHistory); missing.history[1] = null;
        rejects("invalid_signing_history", () -> GmsSignerTrust.currentSigner(missing));
        for (Signature[] signers : new Signature[][]{null, new Signature[0],
                new Signature[]{null}, signatures(new byte[][]{publicCertificates[0], publicCertificates[2]})}) {
            SigningInfo multiple = signing(publicCertificates[0], null); multiple.signers = signers;
            rejects("unsupported_signer_set", () -> GmsSignerTrust.currentSigner(multiple));
        }
        SigningInfo multipleFlag = signing(publicCertificates[0], null); multipleFlag.multiple = true;
        rejects("unsupported_signer_set", () -> GmsSignerTrust.currentSigner(multipleFlag));
        rejects("package_identity_unavailable", () -> GmsSignerTrust.currentSigner(null));

        Fixture rotated = new Fixture();
        String before = identity(rotated.info);
        rotated.info.signingInfo = signing(future, futureHistory);
        String after = identity(rotated.info);
        check(!before.equals(after) && after.contains(certificateHash(future)),
                "trusted rotation invalidates identity instead of retaining root fingerprint");
        rotated.install(); emptyHooks("package_changed_before_hooks");
    }

    private static final class Fixture {
        final File base, module;
        final Context context = new Context();
        final PackageManager packages = new PackageManager();
        final PackageInfo info = new PackageInfo();
        final BaseDexClassLoader loader;
        final GmsApkSnapshot snapshot;
        final GmsAdaptiveRuntime runtime;
        Fixture() throws Throwable { this(false); }
        Fixture(boolean withSplits) throws Throwable { this(withSplits, "host-unknown-build"); }
        Fixture(String versionName) throws Throwable { this(false, versionName); }
        Fixture(boolean withSplits, String versionName) throws Throwable {
            this(withSplits, versionName, 999999999L);
        }
        Fixture(boolean withSplits, String versionName, long versionCode) throws Throwable {
            XposedBridge.reset(); XposedHelpers.reset(); Log.reset();
            GmsBuildVariant.ADAPTIVE_TEST = false;
            GmsAdaptiveResolver.calls = 0;
            Process.bit64 = true; Build.SUPPORTED_64_BIT_ABIS = new String[]{"arm64-v8a"};
            Path directory = Files.createTempDirectory(work, "runtime-");
            base = directory.resolve("base.apk").toFile();
            Files.write(base.toPath(), "opaque-host-snapshot-fixture".getBytes("UTF-8"));
            module = directory.resolve("module.apk").toFile();
            zip(module, null, null);
            loader = new BaseDexClassLoader(bytecode, base.getCanonicalPath());
            context.packages = packages; context.loader = loader;
            context.codeCache = Files.createDirectory(directory.resolve("cache")).toFile();
            info.applicationInfo = new ApplicationInfo();
            info.applicationInfo.uid = Process.myUid();
            info.applicationInfo.sourceDir = base.getCanonicalPath();
            List<File> splits = new ArrayList<File>();
            if (withSplits) {
                for (String name : new String[]{"split-a.apk", "split-b.apk"}) {
                    File split = directory.resolve(name).toFile();
                    Files.write(split.toPath(), name.getBytes("UTF-8"));
                    splits.add(split);
                }
            }
            info.applicationInfo.splitSourceDirs = new String[splits.size()];
            for (int i = 0; i < splits.size(); i++)
                info.applicationInfo.splitSourceDirs[i] = splits.get(i).getCanonicalPath();
            info.versionCode = versionCode; info.versionName = versionName; info.lastUpdateTime = 100;
            info.signingInfo = new SigningInfo();
            info.signingInfo.signers = new Signature[]{new Signature(publicCertificates[2])};
            info.signingInfo.history = signatures(publicCertificates);
            packages.info = info;
            String expectedIdentity = identity(info); // Real public-cert lineage policy; no production bypass.
            snapshot = new GmsApkSnapshot(base, splits, module, expectedIdentity);
            Constructor<GmsAdaptiveRuntime> constructor = GmsAdaptiveRuntime.class.getDeclaredConstructor(
                    Context.class, GmsApkSnapshot.class, String.class, ResolvedGateSet.class, HookTelemetry.class);
            constructor.setAccessible(true);
            runtime = constructor.newInstance(context, snapshot, expectedIdentity, GATES,
                    new HookTelemetry(GmsDiagnosticPolicy.PACKAGE));
            GmsModuleIdentity.record(module.getCanonicalPath());
        }
        Class<?> getter() throws Exception { return Class.forName("runtimefixtures.Getter", false, loader); }
        Class<?> supplier() throws Exception { return Class.forName("runtimefixtures.Supplier", false, loader); }
        void install() throws Throwable { observe(runtime, getter()); }
        void cache() throws Exception {
            new GmsProfileCache(context.codeCache, GmsResolverBuild.COMPATIBILITY_ID)
                    .write(snapshot.gmsFingerprint(), GATES);
        }
    }

    private static void callbacks() throws Throwable {
        Fixture fixture = new Fixture();
        observe(fixture.runtime, fixture.getter());
        check(XposedBridge.businessAttempts == 1 && XposedBridge.pendingChecks == 1,
                "single getter callback inactive until transaction commit");
        check(logged("adaptive_hooks_active") && logged("count=1 scope=phenotype"),
                "activation reported for the verified Phenotype getter");
        observe(fixture.runtime, fixture.supplier());
        check(XposedBridge.businessAttempts == 1, "supplier is not a hook target");
        for (Map.Entry<Method, XC_MethodHook> hook : XposedBridge.history.entrySet()) {
            // Inject while the real event limiter still admits a changed detail. Counting
            // throws prevents a saturated limiter from making this test vacuously pass.
            int failures = Log.failures;
            Log.fail = true;
            XC_MethodHook.MethodHookParam loggedCall = new XC_MethodHook.MethodHookParam(
                    Boolean.FALSE, null, new Object[0]);
            hook.getValue().fireAfter(loggedCall);
            check(loggedCall.writes == 1 && loggedCall.getResult() == Boolean.TRUE,
                    "logger failure cannot prevent result change");
            check(Log.failures == failures + 2,
                    "logger failure exercised for natural result and AirDrop declaration");
            Throwable loggedException = new IllegalArgumentException("original-with-failed-logger");
            XC_MethodHook.MethodHookParam exceptionalCall = new XC_MethodHook.MethodHookParam(
                    Boolean.FALSE, loggedException, new Object[0]);
            hook.getValue().fireAfter(exceptionalCall);
            check(exceptionalCall.writes == 0 && exceptionalCall.getThrowable() == loggedException,
                    "logger failure preserves original exception");
            check(Log.failures == failures + 3, "logger failure exercised after original exception");
            Log.fail = false;
            for (Object original : new Object[]{Boolean.FALSE, Boolean.TRUE, null, Integer.valueOf(0),
                    new Object() { @Override public String toString() { throw new AssertionError("toString"); } }}) {
                for (boolean throwsOriginally : new boolean[]{false, true}) {
                    Throwable error = throwsOriginally ? new IllegalArgumentException("original") : null;
                    XC_MethodHook.MethodHookParam call = new XC_MethodHook.MethodHookParam(original, error, new Object[0]);
                    hook.getValue().fireAfter(call);
                    boolean changes = original == Boolean.FALSE && error == null;
                    check(call.writes == (changes ? 1 : 0), "false-only write count");
                    check(call.getResult() == (changes ? Boolean.TRUE : original), "original return preserved");
                    check(call.getThrowable() == error, "original exception preserved");
                }
            }
            for (Object[] args : new Object[][]{null, new Object[]{"unexpected"}}) {
                XC_MethodHook.MethodHookParam call = new XC_MethodHook.MethodHookParam(Boolean.FALSE, null, args);
                hook.getValue().fireAfter(call);
                check(call.writes == 0, "invalid arity preserves original");
            }
        }
        fixture.install();
        check(XposedBridge.businessAttempts == 1, "duplicate observations do not reinstall");
    }

    private static void declarationEvents() throws Throwable {
        Fixture invalidFirst = new Fixture();
        invalidFirst.install();
        XC_MethodHook invalidFirstHook = XposedBridge.history.values().iterator().next();
        for (XC_MethodHook.MethodHookParam call : new XC_MethodHook.MethodHookParam[]{
                new XC_MethodHook.MethodHookParam(null, null, new Object[0]),
                new XC_MethodHook.MethodHookParam(Integer.valueOf(1), null, new Object[0]),
                new XC_MethodHook.MethodHookParam(Boolean.TRUE, new IllegalStateException("original"),
                        new Object[0]),
                new XC_MethodHook.MethodHookParam(Boolean.TRUE, null, null),
                new XC_MethodHook.MethodHookParam(Boolean.TRUE, null, new Object[]{"unexpected"})}) {
            invalidFirstHook.fireAfter(call);
        }
        check(logCount("event=airdrop_declared ") == 0,
                "exception, null, other and invalid arity do not declare AirDrop support");
        int moduleEvents = XposedBridge.logLines.size();
        XC_MethodHook.MethodHookParam enabled = new XC_MethodHook.MethodHookParam(
                Boolean.FALSE, null, new Object[0]);
        invalidFirstHook.fireAfter(enabled);
        check(enabled.getResult() == Boolean.TRUE && enabled.writes == 1,
                "false getter result is enabled before declaration evaluation");
        check(logCount("event=airdrop_declared ") == 1,
                "first valid false-to-true result declares AirDrop support");
        check(XposedBridge.logLines.size() == moduleEvents + 1
                        && XposedBridge.logLines.get(XposedBridge.logLines.size() - 1)
                        .contains("event=airdrop_declared "),
                "declaration reporting is independent after natural reporting was consumed");
        invalidFirstHook.fireAfter(new XC_MethodHook.MethodHookParam(Boolean.TRUE, null, new Object[0]));
        invalidFirstHook.fireAfter(new XC_MethodHook.MethodHookParam(Boolean.FALSE, null, new Object[0]));
        check(logCount("event=airdrop_declared ") == 1,
                "AirDrop declaration event is emitted only once per process runtime");

        Fixture naturallyTrue = new Fixture();
        naturallyTrue.install();
        XC_MethodHook trueHook = XposedBridge.history.values().iterator().next();
        XC_MethodHook.MethodHookParam trueCall = new XC_MethodHook.MethodHookParam(
                Boolean.TRUE, null, new Object[0]);
        trueHook.fireAfter(trueCall);
        check(trueCall.writes == 0 && trueCall.getResult() == Boolean.TRUE,
                "natural true result remains unchanged");
        check(logCount("event=airdrop_declared ") == 1,
                "natural true result also declares AirDrop support");

        Fixture installRace = new Fixture();
        installRace.cache();
        XposedBridge.pendingResult = Boolean.TRUE;
        GmsAdaptiveRuntime.start(installRace.context, installRace.loader, false);
        int declarationIndex = logIndex("event=airdrop_declared ");
        int activeIndex = logIndex("event=adaptive_hooks_active ");
        check(declarationIndex >= 0 && activeIndex > declarationIndex,
                "natural true callback before hookMethod returns publishes declaration before activation");
        Path statePath = installRace.context.codeCache.toPath().resolve(HookStateStore.FILE_NAME);
        long deadline = System.nanoTime() + 3000000000L;
        while (!Files.exists(statePath) && System.nanoTime() < deadline) Thread.sleep(10);
        check(Files.exists(statePath), "installation-race snapshot published");
        String state = new String(Files.readAllBytes(statePath), "UTF-8");
        check(state.contains("\"installation\":\"active\"")
                        && state.contains("\"airdropDeclaration\":\"declared\""),
                "pre-activation declaration survives activation in the production snapshot");
    }

    private static void failedInstallation() throws Throwable {
        for (boolean missingHandle : new boolean[]{false, true}) {
            Fixture fixture = new Fixture();
            if (missingHandle) XposedBridge.nullAt = 1; else XposedBridge.failAt = 1;
            fixture.install();
            check(XposedBridge.businessAttempts == 1, "one attempted getter hook");
            check(!logged("adaptive_hooks_active"), "failed hook never declared active");
            check(logged(missingHandle ? "missing_hook_handle" : "injected_hook_failure"),
                    "backend failure recorded");
            fixture.install();
            check(XposedBridge.businessAttempts == 1, "failed runtime does not retry transaction");
            check(XposedBridge.hooks.size() == (missingHandle ? 1 : 0),
                    "missing handle may leave an installed callback without activation");
            for (XC_MethodHook callback : XposedBridge.history.values()) {
                XC_MethodHook.MethodHookParam call = new XC_MethodHook.MethodHookParam(
                        Boolean.FALSE, null, new Object[0]);
                callback.fireAfter(call);
                check(call.writes == 0, "backend callback without a handle remains inert");
            }
        }
    }

    private static void sourceGuards() throws Throwable {
        Fixture fixture = new Fixture();
        check(GmsSourceGuard.method(fixture.getter(), GETTER, fixture.base, true).getName().equals("gate"),
                "single matching base loader accepted");
        rejects("declaring_class_mismatch", () ->
                GmsSourceGuard.method(fixture.getter(), SUPPLIER, fixture.base, false));
        try (URLClassLoader ordinary = new URLClassLoader(new URL[]{bytecode.toUri().toURL()},
                GmsAdaptiveRuntimeTest.class.getClassLoader())) {
            Class<?> type = Class.forName("runtimefixtures.Getter", false, ordinary);
            rejects("unsupported_declaring_loader", () -> GmsSourceGuard.method(type, GETTER, fixture.base, true));
        }
        for (String[] paths : new String[][]{{}, {fixture.base.getPath(), fixture.base.getPath()}}) {
            BaseDexClassLoader loader = new BaseDexClassLoader(bytecode, paths);
            Class<?> type = Class.forName("runtimefixtures.Getter", false, loader);
            rejects("ambiguous_declaring_dex_sources", () -> GmsSourceGuard.method(type, GETTER, fixture.base, true));
        }
        BaseDexClassLoader missing = new BaseDexClassLoader(bytecode, "<missing-dex>");
        Class<?> missingType = Class.forName("runtimefixtures.Getter", false, missing);
        rejects("missing_declaring_dex", () -> GmsSourceGuard.method(missingType, GETTER, fixture.base, true));
        BaseDexClassLoader foreign = new BaseDexClassLoader(bytecode, fixture.base.getPath() + ".different");
        Class<?> foreignType = Class.forName("runtimefixtures.Getter", false, foreign);
        rejects("declaring_source_not_base_apk", () -> GmsSourceGuard.method(foreignType, GETTER, fixture.base, true));
        Class<?> wrong = Class.forName("runtimefixtures.WrongSignature", false, fixture.loader);
        for (String method : new String[]{"staticGate", "objectGate", "abstractGate", "nativeGate"})
            rejects("resolved_signature_mismatch", () -> GmsSourceGuard.method(wrong,
                    "Lruntimefixtures/WrongSignature;->" + method + "()Z", fixture.base, true));
    }

    private static void loaderRejections() throws Throwable {
        Fixture duplicate = new Fixture();
        BaseDexClassLoader another = new BaseDexClassLoader(bytecode, duplicate.base.getPath());
        observe(duplicate.runtime, duplicate.getter());
        observe(duplicate.runtime, Class.forName("runtimefixtures.Getter", false, another));
        check(XposedBridge.businessAttempts == 1, "later loader observations do not duplicate the hook");

        Fixture foreign = new Fixture();
        BaseDexClassLoader wrong = new BaseDexClassLoader(bytecode, foreign.base.getPath() + ".wrong");
        observe(foreign.runtime, Class.forName("runtimefixtures.Getter", false, wrong));
        foreign.install();
        emptyHooks("declaring_source_not_base_apk");

        Fixture multiple = new Fixture();
        BaseDexClassLoader multi = new BaseDexClassLoader(bytecode, multiple.base.getPath(), "split.apk");
        observe(multiple.runtime, Class.forName("runtimefixtures.Getter", false, multi));
        emptyHooks("ambiguous_declaring_dex_sources");
    }

    private static void packageChanges() throws Throwable {
        Fixture changed = new Fixture();
        changed.info.versionCode++;
        changed.install();
        emptyHooks("package_changed_before_hooks");

        Fixture replaced = new Fixture();
        Files.write(replaced.base.toPath(), new byte[]{1, 2, 3});
        replaced.install();
        emptyHooks("package_changed_before_hooks");

        Fixture pmFailure = new Fixture();
        pmFailure.packages.fail = true;
        pmFailure.install();
        emptyHooks("package_manager_failure");

        Fixture wrongSigner = new Fixture();
        wrongSigner.info.signingInfo.signers = new Signature[]{new Signature(new byte[]{1})};
        wrongSigner.info.signingInfo.history = wrongSigner.info.signingInfo.signers;
        wrongSigner.install();
        emptyHooks("unreviewed_gms_signer");

        Fixture wrongUid = new Fixture();
        wrongUid.info.applicationInfo.uid++;
        wrongUid.install();
        emptyHooks("package_identity_unavailable");
    }

    private static void cachedStartup() throws Throwable {
        Fixture fixture = new Fixture();
        fixture.cache();
        GmsAdaptiveRuntime.start(fixture.context, fixture.loader, false);
        check(XposedBridge.businessAttempts == 1, "real start installs the getter from verified cache");
        check(logged("profile_verified") && logged("source=cache"), "cache use logged");
        check(GmsAdaptiveResolver.calls == 0, "cache hit bypasses native resolver");
        check(fixture.packages.queries == 3, "identity checked at entry, before seed and before install");

        Fixture changed = new Fixture();
        changed.cache(); changed.packages.changeOnQuery = 2;
        GmsAdaptiveRuntime.start(changed.context, changed.loader, false);
        emptyHooks("package_changed_before_install");

        Fixture miss = new Fixture();
        Process.bit64 = false;
        try { GmsAdaptiveRuntime.start(miss.context, miss.loader, false); }
        finally { Process.bit64 = true; }
        emptyHooks("unsupported_native_abi");
        check(GmsAdaptiveResolver.calls == 0, "cache miss rejected before any native/DEX invocation");
        check(logCount("event=resolution_rejected ") == 1 && !logged("resolution_complete"),
                "worker rejection is not duplicated by actual await catch");
        check(logged("stage=native_load reason=unsupported_native_abi source=discovery elapsed_ms="),
                "actual startup rejection has native phase, sanitized reason and elapsed time");
    }

    private static void startupLoggerFailure() throws Throwable {
        Fixture fixture = new Fixture(); fixture.cache();
        Log.fail = true;
        try { GmsAdaptiveRuntime.start(fixture.context, fixture.loader, false); }
        finally { Log.fail = false; }
        check(XposedBridge.businessAttempts == 1, "startup and terminal logger failure preserve verified hook activation");
        check(Log.failures >= 4, "adaptive start, terminal result, profile and activation logging failures exercised");
        check(GmsAdaptiveResolver.calls == 0, "failed logger does not convert cache success into discovery");
    }

    private static void packageSourceChanges() throws Throwable {
        Fixture movedBase = new Fixture();
        File replacement = new File(movedBase.base.getParentFile(), "new-base.apk");
        Files.write(replacement.toPath(), new byte[]{3, 2, 1});
        movedBase.info.applicationInfo.sourceDir = replacement.getCanonicalPath();
        check(movedBase.snapshot.unchanged(), "original base still exists unchanged");
        movedBase.install();
        emptyHooks("package_changed_before_hooks");

        Fixture movedSplit = new Fixture(true);
        File split = new File(movedSplit.base.getParentFile(), "new-split.apk");
        Files.write(split.toPath(), new byte[]{4, 5, 6});
        movedSplit.info.applicationInfo.splitSourceDirs[0] = split.getCanonicalPath();
        check(movedSplit.snapshot.unchanged(), "original split still exists unchanged");
        movedSplit.install();
        emptyHooks("package_changed_before_hooks");

        Fixture reordered = new Fixture(true);
        String[] paths = reordered.info.applicationInfo.splitSourceDirs;
        String first = paths[0]; paths[0] = paths[1]; paths[1] = first;
        reordered.install();
        check(XposedBridge.businessAttempts == 1 && logged("adaptive_hooks_active"),
                "split order alone preserves identity and allows actual getter installation");
    }

    private static void loaderCallback() throws Throwable {
        Fixture fixture = new Fixture();
        invoke(fixture.runtime, "watchLoaders", new Class<?>[0]);
        Method load = ClassLoader.class.getDeclaredMethod("loadClass", String.class);
        XC_MethodHook watcher = XposedBridge.hooks.get(load);
        check(watcher != null, "actual loader callback registered");
        for (XC_MethodHook.MethodHookParam ignored : new XC_MethodHook.MethodHookParam[]{
                new XC_MethodHook.MethodHookParam(fixture.getter(), null, null),
                new XC_MethodHook.MethodHookParam(fixture.getter(), null, new Object[]{Integer.valueOf(1)}),
                new XC_MethodHook.MethodHookParam(fixture.getter(), null, new Object[]{"other.Class"}),
                new XC_MethodHook.MethodHookParam(fixture.getter(), new ClassNotFoundException(),
                        new Object[]{"runtimefixtures.Getter"})}) {
            watcher.fireAfter(ignored);
            check(XposedBridge.businessAttempts == 0 && ignored.writes == 0, "irrelevant loader callback preserved");
        }
        watcher.fireAfter(new XC_MethodHook.MethodHookParam(fixture.getter(), null,
                new Object[]{"runtimefixtures.Getter"}));
        watcher.fireAfter(new XC_MethodHook.MethodHookParam(fixture.supplier(), null,
                new Object[]{"runtimefixtures.Supplier"}));
        check(XposedBridge.businessAttempts == 1, "loader events reach real source guard and getter install");
    }

    private static void moduleIdentity() throws Throwable {
        Fixture fixture = new Fixture();
        GmsBuildVariant.ADAPTIVE_TEST = false;
        GmsModuleIdentity.record(null);
        check(!GmsModuleIdentity.forceAdaptive(), "release ignores absent module path");
        GmsModuleIdentity.record(new File(work.toFile(), "missing-module.apk").getPath());
        check(!GmsModuleIdentity.forceAdaptive(), "release never reads missing module APK");

        GmsBuildVariant.ADAPTIVE_TEST = true;
        rejects("module_apk_unavailable", () -> GmsModuleIdentity.forceAdaptive());
        GmsModuleIdentity.record(null);
        rejects("module_path_unavailable", () -> GmsModuleIdentity.forceAdaptive());
        GmsModuleIdentity.record(fixture.module.getPath());
        rejects("missing_test_marker", () -> GmsModuleIdentity.forceAdaptive());
        for (String marker : new String[]{"force_adaptive_v1", "force_adaptive_v1\nextra", "force_adaptive_v0\n"}) {
            zip(fixture.module, "assets/mosey-adaptive-test", marker.getBytes("UTF-8"));
            rejects("invalid_test_marker", () -> GmsModuleIdentity.forceAdaptive());
        }
        zip(fixture.module, "assets/mosey-adaptive-test", "force_adaptive_v1\n".getBytes("UTF-8"));
        check(GmsModuleIdentity.forceAdaptive(), "exact test marker accepted");

        GmsBuildVariant.ADAPTIVE_TEST = false;
        Process.bit64 = false;
        rejects("unsupported_native_abi", () -> GmsModuleIdentity.loadNative());
        Process.bit64 = true;
        Build.SUPPORTED_64_BIT_ABIS = new String[]{"x86_64"};
        rejects("unsupported_native_abi", () -> GmsModuleIdentity.loadNative());
        Build.SUPPORTED_64_BIT_ABIS = new String[0];
        rejects("unsupported_native_abi", () -> GmsModuleIdentity.loadNative());
        Build.SUPPORTED_64_BIT_ABIS = new String[]{"arm64-v8a"};
        rejects("native_library_not_stored", () -> GmsModuleIdentity.loadNative());
        zip(fixture.module, "lib/arm64-v8a/libdexkit.so", "compressed-not-native".getBytes("UTF-8"));
        rejects("native_library_not_stored", () -> GmsModuleIdentity.loadNative());
    }

    private static void rejectionReasons() throws Throwable {
        for (String separator : new String[]{":", "="}) {
            String actual = (String) invoke(null, "reason", new Class<?>[]{Throwable.class},
                    new GmsAdaptiveResolver.Rejected("ambiguous_candidates" + separator + "Lprivate/Name; /private/path"));
            check(actual.equals("reason=ambiguous_candidates"), "stable resolver category excludes details");
        }
        String ordinary = (String) invoke(null, "reason", new Class<?>[]{Throwable.class},
                new IllegalStateException("/private/apk/location"));
        check(ordinary.equals("reason=IllegalStateException"), "foreign exception paths excluded");
        String malformed = (String) invoke(null, "reason", new Class<?>[]{Throwable.class},
                new GmsAdaptiveResolver.Rejected("/private/path:details"));
        check(malformed.equals("reason=Rejected"), "untrusted resolver category excluded");
    }

    public static void main(String[] args) throws Throwable {
        work = new File(args[0]).toPath(); bytecode = new File(args[1]).toPath();
        publicCertificates = new byte[3][];
        for (int i = 0; i < publicCertificates.length; i++)
            publicCertificates[i] = Files.readAllBytes(new File(args[2], i + ".der").toPath());
        check(GmsApkSnapshot.hex(GmsApkSnapshot.digest().digest(publicCertificates[0])).equals(
                "f0fd6c5b410f25cb25c3b53346c8972fae30f8ee7411df910480ad6b2d60db83"), "public root fixture");
        scenario("callbacks_false_only_original_exceptions_logger_failure_duplicate", () -> callbacks());
        scenario("airdrop_declaration_valid_final_true_once_after_invalid_callbacks", () -> declarationEvents());
        scenario("single_getter_installation_failure_no_retry", () -> failedInstallation());
        scenario("actual_source_guard_loader_path_elements_signatures", () -> sourceGuards());
        scenario("actual_observe_duplicate_ignored_wrong_source_multi_dex", () -> loaderRejections());
        scenario("actual_observe_package_file_signer_uid_changes", () -> packageChanges());
        scenario("package_source_changes_rejected_split_order_accepted", () -> packageSourceChanges());
        scenario("actual_start_cache_hit_package_change_native_preflight_rejection", () -> cachedStartup());
        scenario("actual_start_logger_failure_preserves_cache_and_hooks", () -> startupLoggerFailure());
        scenario("version_range_advisory_never_blocks_semantic_activation", () -> versionAdvisories());
        scenario("reviewed_root_platform_rotation_and_identity_invalidation", () -> signerTrust());
        scenario("actual_loader_callbacks", () -> loaderCallback());
        scenario("module_variant_marker_and_native_preflight", () -> moduleIdentity());
        scenario("stable_rejection_categories_exclude_private_details", () -> rejectionReasons());
        System.out.println("PASS " + scenarios + " production runtime scenarios / " + assertions + " assertions");
        System.out.println("LIMIT: pathList/DexFile and Xposed backend are host fakes; no ART, native library, GMS code or device operations.");
    }
}
