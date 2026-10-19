package moseyPLK.client.manager

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.TimeUnit

class ManagerPolicyTest {
    private val installed = PackageIdentity(TargetApp.GMS.packageName, 10118, "26.36.33 (260400-986028547)", 263633035, 1234)
    private val module = ModuleVersion("0.6.0", 13)
    private val process = ProcessIdentity(321, 10118, "890", installed.packageName)
    private val snapshot = HookSnapshot(
        installed.packageName, 0, installed.uid, process.pid, process.starttime, 4, "boot-one", 10000,
        installed.versionName, installed.versionCode, installed.lastUpdateTime, module, "build-one", "normal",
        "verified", "active", false, "unknown", "unknown", "adaptive_hooks_active", "count=1",
    )

    private fun check(record: HookSnapshot = snapshot, pid: ProcessIdentity? = process,
                      bootCount: Int = 4, bootId: String = "boot-one", elapsed: Long = 10001): HookReading =
        SnapshotIdentity.check(record, installed, pid, bootCount, bootId, elapsed, module, "build-one")

    @Test fun currentIdentityDoesNotInventNaturalHit() {
        val reading = check()
        assertEquals(SnapshotFreshness.CURRENT, reading.freshness)
        assertFalse(reading.snapshot!!.naturalHit)
    }

    @Test fun elapsedAgeAloneDoesNotInvalidateLiveIdentity() {
        assertEquals(SnapshotFreshness.CURRENT, check(elapsed = 900_000_000).freshness)
    }

    @Test fun previousBootAndMissingBootEvidenceAreDifferent() {
        assertEquals(SnapshotFreshness.STALE, check(bootCount = 5).freshness)
        assertEquals(SnapshotFreshness.STALE, check(bootId = "boot-two").freshness)
        assertEquals(SnapshotFreshness.UNCONFIRMED, check(bootCount = -1).freshness)
    }

    @Test fun optionalBootIdUsesBootCountAndProcessProof() {
        assertEquals(SnapshotFreshness.CURRENT, check(snapshot.copy(bootId = "")).freshness)
        assertEquals(SnapshotFreshness.STALE, check(bootId = "").freshness)
    }

    @Test fun deadProcessAndPidReuseAreStale() {
        assertEquals(SnapshotFreshness.STALE, check(pid = null).freshness)
        assertEquals(SnapshotFreshness.STALE, check(pid = process.copy(starttime = "999")).freshness)
        assertEquals(SnapshotFreshness.STALE, check(pid = process.copy(uid = 99910118)).freshness)
        assertEquals(SnapshotFreshness.STALE, check(pid = process.copy(name = installed.packageName + ":persistent")).freshness)
    }

    @Test fun changedTargetVersionAndUpdateTimeAreStale() {
        listOf(
            snapshot.copy(targetVersionCode = installed.versionCode + 1),
            snapshot.copy(targetVersionName = "changed"),
            snapshot.copy(targetLastUpdateTime = installed.lastUpdateTime + 1),
            snapshot.copy(targetPackage = TargetApp.MOSEY.packageName),
            snapshot.copy(userId = 999),
            snapshot.copy(uid = 99910118),
            snapshot.copy(capturedElapsedMs = 10002),
        ).forEach { assertEquals(SnapshotFreshness.STALE, check(it).freshness) }
    }

    @Test fun installedNewModuleDoesNotRelabelOldLoadedHook() {
        assertEquals(SnapshotFreshness.OLD_MODULE, check(snapshot.copy(moduleVersion = ModuleVersion("0.1.7", 8))).freshness)
        assertEquals(SnapshotFreshness.OLD_MODULE, check(snapshot.copy(moduleBuildId = "other-build")).freshness)
    }

    @Test fun airdropDeclarationUsesFinalTrueForCurrentProcessRegardlessOfInstallation() {
        val declared = snapshot.copy(airdropDeclaration = AirDropDeclaration.DECLARED)
        listOf("active", "inactive", "pending", "rejected", "").forEach { installation ->
            assertTrue(installation, AirDropSupportPolicy.isDeclared(check(declared.copy(installation = installation))))
        }
        val oldModule = check(declared.copy(moduleVersion = ModuleVersion("0.5.9", 12)))
        assertEquals(SnapshotFreshness.OLD_MODULE, oldModule.freshness)
        assertTrue(AirDropSupportPolicy.isDeclared(oldModule))
        assertFalse(AirDropSupportPolicy.isDeclared(check(declared).copy(freshness = SnapshotFreshness.STALE)))
        assertFalse(AirDropSupportPolicy.isDeclared(check(declared).copy(freshness = SnapshotFreshness.UNCONFIRMED)))
        assertFalse(AirDropSupportPolicy.isDeclared(
            check(declared).copy(snapshot = declared.copy(targetPackage = TargetApp.MOSEY.packageName)),
        ))
        assertFalse(AirDropSupportPolicy.isDeclared(check(snapshot)))
        assertFalse(AirDropSupportPolicy.isDeclared(HookReading(freshness = SnapshotFreshness.CURRENT)))
    }

    @Test fun airdropDeclarationDoesNotChangeOverviewPolicy() {
        val base = overviewBase()
        val declaredHook = check(snapshot.copy(airdropDeclaration = AirDropDeclaration.DECLARED))
        assertTrue(AirDropSupportPolicy.isDeclared(declaredHook))
        assertEquals(
            OverviewPolicy.evaluate(base.copy(gmsHook = HookReading()), module, false),
            OverviewPolicy.evaluate(base.copy(gmsHook = declaredHook), module, false),
        )
        val declaredState = base.copy(
            gmsHook = declaredHook,
            native = base.native.copy(state = "Stopped"),
            moseyProcess = ProcessState.STOPPED,
        )
        assertEquals(
            OverviewPolicy.evaluate(declaredState.copy(gmsHook = HookReading()), module, false),
            OverviewPolicy.evaluate(declaredState, module, false),
        )
    }

    @Test fun normalizationOnlyRemovesVersionPrefixAndSurroundingSpace() {
        assertTrue(module.matches(ModuleVersion(" v0.6.0 ", 13)))
        assertTrue(module.matches(ModuleVersion("V0.6.0", 13)))
        assertFalse(module.matches(ModuleVersion("0.6.0", 12)))
        assertFalse(module.matches(ModuleVersion("0.6.0-test", 13)))
        assertFalse(module.matches(ModuleVersion("vV0.6.0", 13)))
    }

    private fun enabledState() = ManagerState(
        root = RootAccess.GRANTED, ownerUser = true, gms = installed, mosey = installed.copy(packageName = TargetApp.MOSEY.packageName),
        native = NativeReading(version = ModuleVersion("old", 1), commands = setOf("start", "stop", "restart"), available = true),
    )

    @Test fun versionMismatchDoesNotGateAnyControl() {
        val state = enabledState()
        assertFalse(state.native.version!!.matches(module))
        ControlAction.entries.forEach { assertTrue(it.name, state.canExecute(it)) }
    }

    @Test fun controlUsesCapabilitiesRatherThanVersion() {
        val state = enabledState().copy(native = NativeReading(version = module, commands = setOf("start")))
        assertTrue(state.canExecute(ControlAction.NATIVE_START))
        assertFalse(state.canExecute(ControlAction.NATIVE_STOP))
        assertTrue(state.canExecute(ControlAction.GMS_STOP))
    }

    @Test fun deniedRootWrongUserAndInFlightStateDisableControls() {
        val base = enabledState()
        val running = NativeOperation("op-1", "restart", "running", "", 1, 211)
        listOf(base.copy(root = RootAccess.DENIED), base.copy(ownerUser = false), base.copy(refreshing = true),
            base.copy(issuingCommand = true), base.copy(pendingNativeResult = true),
            base.copy(native = base.native.copy(operation = running))).forEach { state ->
            ControlAction.entries.forEach { assertFalse(it.name, state.canExecute(it)) }
        }
    }

    @Test fun missingTargetDoesNotPermitApplicationControl() {
        assertFalse(enabledState().copy(gms = null).canExecute(ControlAction.GMS_STOP))
    }

    @Test fun destructiveActionsRequireConfirmation() {
        assertFalse(ControlAction.NATIVE_START.needsConfirmation)
        ControlAction.entries.filter { it != ControlAction.NATIVE_START }.forEach { assertTrue(it.needsConfirmation) }
    }

    @Test fun onlyGmsHasAnApplicationProcessCommand() {
        val gms = RootCommands.application(ControlAction.GMS_STOP)
        assertTrue(gms.contains("am force-stop --user 0 com.google.android.gms"))
        assertFalse(gms.contains("killall"))
        assertFalse(gms.contains("pm enable"))
        assertFalse(gms.contains(TargetApp.MOSEY.packageName))
        assertTrue(runCatching { RootCommands.application(ControlAction.NATIVE_RESTART) }.isFailure)
        assertFalse(ControlAction.entries.any { it.name.startsWith("MOSEY_") })
    }

    @Test fun helperRejectsArgumentsOutsideClosedVocabulary() {
        listOf("status; reboot", "../status", "start --force", "").forEach { value ->
            assertTrue(runCatching { RootCommands.helper(value) }.isFailure)
        }
        assertTrue(RootCommands.helper("restart").contains("control.sh"))
        assertFalse(RootCommands.helper("restart").contains("service.sh"))
    }

    @Test fun snapshotReadsAreBoundedAndRejectUnsafeIdentities() {
        assertTrue(runCatching { RootCommands.snapshot(TargetApp.GMS, 0) }.isFailure)
        assertTrue(runCatching { RootCommands.snapshot(TargetApp.GMS, 99910118) }.isFailure)
        assertTrue(runCatching { RootCommands.process(-1) }.isFailure)
        val script = RootCommands.snapshot(TargetApp.GMS, 10118)
        assertTrue(script.contains("16385"))
        assertTrue(script.contains("-le 16384"))
        assertTrue(script.contains("-L"))
        assertTrue(script.contains("/proc/\$\$/fd/3"))
        assertFalse(script.contains("/proc/self/fd/3"))
        assertTrue(script.contains("600"))
        assertTrue(script.contains("timeout -k 1 12"))
    }

    @Test fun displayNameIsSanitizedBoundedAndNotPartOfInstallationIdentity() {
        assertEquals("Mosey 扩展", PackageDisplayName.sanitize("  Mosey\n\u202e扩展  ", "fallback"))
        assertEquals("fallback", PackageDisplayName.sanitize("\u0000\n\t", "fallback"))
        assertEquals("Mosey 扩展", PackageDisplayName.sanitize(
            TargetApp.MOSEY.packageName,
            "Mosey 扩展",
            TargetApp.MOSEY.packageName,
        ))
        val longName = "😀".repeat(90)
        val bounded = PackageDisplayName.sanitize(longName, "fallback")
        assertEquals(80, bounded.codePointCount(0, bounded.length))
        assertTrue(installed.sameInstallationAs(installed.copy(displayName = "Google Play services")))
        assertFalse(installed.sameInstallationAs(installed.copy(versionCode = installed.versionCode + 1)))
        assertFalse(installed.sameInstallationAs(null))
    }

    private fun processFilter(input: String): Pair<Int, String> {
        val command = ProcessBuilder("awk", "-v", "expected=10118", "-v", "target=com.google.android.gms", RootCommands.processFilter)
            .redirectErrorStream(true).start()
        command.outputStream.bufferedWriter().use { it.write(input) }
        if (!command.waitFor(5, TimeUnit.SECONDS)) {
            command.destroyForcibly()
            error("host awk fixture timed out")
        }
        return command.exitValue() to command.inputStream.bufferedReader().use { it.readText().trim() }
    }

    @Test fun processFilterRequiresExactMainProcessAndVerifiedUid() {
        assertEquals(0 to "running", processFilter("UID NAME\n10118 com.google.android.gms\n"))
        listOf("com.google.android.gms.ui", "com.google.android.gms.unstable",
            "com.google.android.gms.persistent", "com.google.android.gms:nearby").forEach { name ->
            assertEquals(name, 0 to "stopped", processFilter("UID NAME\n10118 $name\n"))
        }
    }

    @Test fun processFilterRejectsOtherUsersNeighbourNamesAndInvalidListings() {
        assertEquals(0 to "stopped", processFilter("UID NAME\n99910118 com.google.android.gms.ui\n"))
        assertEquals(0 to "stopped", processFilter("UID NAME\n10118 com.google.android.gmsfake\n"))
        assertTrue(processFilter("").first != 0)
        assertTrue(processFilter("USER COMMAND\n10118 com.google.android.gms\n").first != 0)
    }

    @Test fun partialProcessListingFailureNeverBecomesStopped() {
        val script = "ps() { printf 'UID NAME\\n10118 unrelated.app\\n'; return 1; }\n" +
            RootCommands.processesScript(TargetApp.GMS, 10118)
        val command = ProcessBuilder("sh", "-c", script).redirectErrorStream(true).start()
        if (!command.waitFor(5, TimeUnit.SECONDS)) {
            command.destroyForcibly()
            error("host ps fixture timed out")
        }
        assertEquals(88, command.exitValue())
        assertEquals("", command.inputStream.bufferedReader().use { it.readText() })
    }

    private fun overviewBase() = enabledState().copy(
        sampledAtMillis = 1,
        modulePresence = ModulePresence.PRESENT,
        native = NativeReading(state = "Running", version = module, available = true),
        moseyProcess = ProcessState.RUNNING,
    )

    @Test fun overviewNeedsServiceAndExactMoseyProcess() {
        assertEquals(OverviewLevel.WORKING, OverviewPolicy.evaluate(overviewBase(), module, false).level)
        assertEquals(OverviewLevel.NOT_RUNNING, OverviewPolicy.evaluate(
            overviewBase().copy(native = NativeReading(state = "Stopped", version = module, available = true)), module, false).level)
        assertEquals(OverviewLevel.NOT_RUNNING, OverviewPolicy.evaluate(
            overviewBase().copy(moseyProcess = ProcessState.STOPPED), module, false).level)
        assertEquals(OverviewLevel.WARNING, OverviewPolicy.evaluate(
            overviewBase().copy(moseyProcess = ProcessState.UNKNOWN), module, false).level)
    }

    @Test fun overviewDistinguishesProvenBlockersFromWarnings() {
        val base = overviewBase()
        listOf(
            base.copy(deviceSupport = DeviceSupport(false, "设备不受支持")),
            base.copy(mosey = null),
            base.copy(gms = null),
            base.copy(modulePresence = ModulePresence.ABSENT),
            base.copy(modulePresence = ModulePresence.DISABLED),
            base.copy(native = base.native.copy(state = "Unregistered")),
        ).forEach { assertEquals(OverviewLevel.NOT_RUNNING, OverviewPolicy.evaluate(it, module, false).level) }
        listOf(
            base.copy(root = RootAccess.DENIED),
            base.copy(modulePresence = ModulePresence.UNKNOWN),
            base.copy(modulePresence = ModulePresence.UPDATING),
            base.copy(native = base.native.copy(state = "Unknown")),
            base.copy(native = base.native.copy(version = ModuleVersion(module.name, module.code + 1))),
            base.copy(legacyInstalled = true),
        ).forEach { assertEquals(OverviewLevel.WARNING, OverviewPolicy.evaluate(it, module, false).level) }
        assertEquals(OverviewLevel.WARNING, OverviewPolicy.evaluate(base, module, true).level)
        assertEquals(OverviewLevel.WARNING, OverviewPolicy.evaluate(ManagerState(), module, false).level)
    }

    @Test fun overviewUsesSafeModuleProbeReasonForUnknownState() {
        val reason = "KSU 模块信息文件校验失败"
        val reading = OverviewPolicy.evaluate(
            overviewBase().copy(modulePresence = ModulePresence.UNKNOWN, modulePresenceReason = reason),
            module,
            false,
        )
        assertEquals(OverviewLevel.WARNING, reading.level)
        assertEquals(reason, reading.reason)
    }

    @Test fun restartInProgressDoesNotFlashStopped() {
        val running = NativeOperation("op-1", "restart", "running", "", 1, 211)
        val transitioning = overviewBase().copy(native = overviewBase().native.copy(state = "Stopped", operation = running),
            moseyProcess = ProcessState.STOPPED)
        assertEquals(OverviewLevel.WARNING, OverviewPolicy.evaluate(transitioning, module, false).level)
    }
}
