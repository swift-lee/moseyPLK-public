package moseyPLK.client.manager

import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class StatusProbeTest {
    @get:Rule val fixture = TemporaryFolder()

    private val ownerUid: Int by lazy {
        ProcessBuilder("id", "-u").start().inputStream.bufferedReader().use { it.readText().trim().toInt() }
    }

    private fun probe(modulesDir: Path): Pair<Int, String> {
        // The production command enforces root. This host-only fixture replaces `id -u` while
        // preserving the path, owner, symlink, size and module identity checks.
        val fakeRoot = """id() { if [ "${'$'}1" = -u ]; then printf '0\n'; else command id "${'$'}@"; fi; }
stat() { command stat "${'$'}@" 3<&-; }
"""
        val command = ProcessBuilder("sh", "-c", fakeRoot + RootCommands.modulePresenceScript(modulesDir.toString(), ownerUid))
            .redirectErrorStream(true).start()
        assertTrue("module probe timed out", command.waitFor(5, TimeUnit.SECONDS))
        return command.exitValue() to command.inputStream.bufferedReader().use { it.readText().trim() }
    }

    private fun module(modulesDir: Path): Path {
        val module = Files.createDirectory(modulesDir.resolve("moseyPLK.service"))
        Files.writeString(module.resolve("module.prop"), "id=moseyPLK.service\nversion=v-test\n")
        return module
    }

    @Test fun deviceSupportRequiresExactModelApiAndPrimaryAbi() {
        assertEquals(DeviceSupport(true), DeviceSupportPolicy.evaluate("PLK110", 36, "arm64-v8a"))
        assertFalse(DeviceSupportPolicy.evaluate("PLK111", 36, "arm64-v8a").supported)
        assertFalse(DeviceSupportPolicy.evaluate("PLK110", 35, "arm64-v8a").supported)
        assertFalse(DeviceSupportPolicy.evaluate("PLK110", 36, "x86_64").supported)
    }

    @Test fun moduleProbeDistinguishesAbsentAndMarkerStates() {
        val missingModules = fixture.root.toPath().resolve("missing-modules")
        assertEquals(0 to "absent", probe(missingModules))
        val modules = fixture.newFolder("modules").toPath()
        assertEquals(0 to "absent", probe(modules))
        val module = module(modules)
        assertEquals(0 to "present", probe(modules))

        Files.createFile(module.resolve("update"))
        assertEquals(0 to "updating", probe(modules))
        Files.createFile(module.resolve("disable"))
        assertEquals(0 to "disabled", probe(modules))
        Files.createFile(module.resolve("remove"))
        assertEquals(0 to "pending_removal", probe(modules))
    }

    @Test fun moduleProbeRejectsWrongIdentityAndSymlinkedFiles() {
        val modules = fixture.newFolder("modules").toPath()
        val module = module(modules)
        val prop = module.resolve("module.prop")
        Files.writeString(prop, "id=another.module\n")
        assertTrue(probe(modules).first != 0)
        Files.writeString(prop, "id=moseyPLK.service\nid=another.module\n")
        assertTrue(probe(modules).first != 0)
        Files.writeString(prop, "id=moseyPLK.service\n")

        val foreign = fixture.newFile("foreign-marker").toPath()
        Files.createSymbolicLink(module.resolve("disable"), foreign)
        assertTrue(probe(modules).first != 0)
        Files.delete(module.resolve("disable"))
        Files.delete(prop)
        Files.createSymbolicLink(prop, foreign)
        assertTrue(probe(modules).first != 0)
    }

    @Test fun moduleProbeIsRootOnlyFixedPathAndReadOnly() {
        val command = RootCommands.modulePresence
        assertTrue(command.contains("/data/adb/modules/moseyPLK.service"))
        assertTrue(command.contains("id -u"))
        assertTrue(command.contains("/proc/\$\$/fd/3"))
        assertFalse(command.contains("/proc/self/fd/3"))
        assertTrue(command.contains("timeout -k 1 8"))
        assertFalse(command.contains("control.sh"))
        assertFalse(command.contains("force-stop"))
    }

    @Test fun moduleProbeMapsFailuresWithoutExposingShellOutput() {
        val expected = mapOf(
            -1 to "KSU 模块检查未完成",
            90 to "KSU 模块检查未获得 root 身份",
            91 to "KSU 模块目录校验失败",
            92 to "KSU 模块目录不可读取",
            93 to "moseyPLK KSU 模块目录校验失败",
            94 to "KSU 模块信息文件校验失败",
            95 to "KSU 模块状态标记校验失败",
            126 to "KSU 模块检查失败（代码 126）",
        )
        expected.forEach { (code, reason) ->
            val reading = ModulePresenceProbe.decode(CommandResult(code, "secret shell detail"))
            assertEquals(ModulePresence.UNKNOWN, reading.presence)
            assertEquals(reason, reading.reason)
            assertFalse(reading.reason.contains("secret"))
        }
        val diagnostic = ModulePresenceProbe.decode(CommandResult(0, "present", diagnosticFailure = true))
        assertEquals(ModulePresence.UNKNOWN, diagnostic.presence)
        assertEquals("KSU 模块检查输出异常", diagnostic.reason)
        val unknown = ModulePresenceProbe.decode(CommandResult(0, "unexpected secret"))
        assertEquals(ModulePresence.UNKNOWN, unknown.presence)
        assertEquals("KSU 模块检查返回未知结果", unknown.reason)
    }

    @Test fun moduleProbeMapsOnlyTheClosedSuccessVocabulary() {
        mapOf(
            "present" to ModulePresence.PRESENT,
            "absent" to ModulePresence.ABSENT,
            "disabled" to ModulePresence.DISABLED,
            "pending_removal" to ModulePresence.PENDING_REMOVAL,
            "updating" to ModulePresence.UPDATING,
        ).forEach { (output, presence) ->
            assertEquals(ModulePresenceReading(presence), ModulePresenceProbe.decode(CommandResult(0, output)))
        }
    }

    @Test fun mainProcessFilterRejectsSecondaryProcesses() {
        fun filtered(listing: String): Pair<Int, String> {
            val command = ProcessBuilder("awk", "-v", "expected=10118", "-v", "target=com.google.android.gms", RootCommands.processFilter)
                .start()
            command.outputStream.bufferedWriter().use { it.write(listing) }
            assertTrue(command.waitFor(5, TimeUnit.SECONDS))
            return command.exitValue() to command.inputStream.bufferedReader().use { it.readText().trim() }
        }
        assertEquals(0 to "stopped", filtered("UID NAME\n10118 com.google.android.gms.persistent\n10118 com.google.android.gms:nearby\n"))
        assertEquals(0 to "stopped", filtered("UID NAME\n99910118 com.google.android.gms\n"))
        assertEquals(0 to "running", filtered("UID NAME\n10118 com.google.android.gms\n"))
    }
}
