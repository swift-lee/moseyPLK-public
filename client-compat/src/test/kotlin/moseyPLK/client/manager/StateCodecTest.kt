package moseyPLK.client.manager

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class StateCodecTest {
    private fun snapshot() = JSONObject().apply {
        put("schema", 1); put("targetPackage", "com.google.android.gms")
        put("userId", 0); put("uid", 10118); put("pid", 321); put("starttime", 890L)
        put("bootCount", 4); put("bootId", "boot-one"); put("capturedElapsedMs", 10000L)
        put("targetVersionName", "26.36.33 (260400-986028547)"); put("targetVersionCode", 263633035L)
        put("targetLastUpdateTime", 1234L); put("moduleVersion", "0.6.0"); put("moduleVersionCode", 13L)
        put("moduleBuildId", "build-one"); put("moduleVariant", "normal")
        put("resolution", "timeout"); put("installation", "inactive"); put("naturalHit", false)
        put("binderReady", "unknown"); put("componentRestore", "unknown")
        put("lastEvent", "resolution_complete"); put("lastDetail", "cached_only"); put("workerResolution", "verified")
    }

    @Test fun lateWorkerVerificationDoesNotOverwriteInactiveInstallation() {
        val result = StateCodec.snapshot(snapshot().toString())
        assertEquals("890", result.starttime)
        assertEquals("timeout", result.resolution)
        assertEquals("verified", result.workerResolution)
        assertEquals("inactive", result.installation)
        assertEquals(AirDropDeclaration.UNCONFIRMED, result.airdropDeclaration)
        assertFalse(result.naturalHit)
    }

    @Test fun airdropDeclarationAcceptsOnlyTheClosedWireVocabulary() {
        assertEquals(
            AirDropDeclaration.DECLARED,
            StateCodec.snapshot(snapshot().put("airdropDeclaration", "declared").toString()).airdropDeclaration,
        )
        assertEquals(
            AirDropDeclaration.UNCONFIRMED,
            StateCodec.snapshot(snapshot().put("airdropDeclaration", "unconfirmed").toString()).airdropDeclaration,
        )
        listOf("", "unknown", "DECLARED", "not_declared").forEach { value ->
            assertTrue(runCatching {
                StateCodec.snapshot(snapshot().put("airdropDeclaration", value).toString())
            }.isFailure)
        }
        assertTrue(runCatching {
            StateCodec.snapshot(snapshot().put("airdropDeclaration", true).toString())
        }.isFailure)
        assertTrue(runCatching {
            StateCodec.snapshot(snapshot().put("airdropDeclaration", JSONObject.NULL).toString())
        }.isFailure)
    }

    @Test fun missingIdentityAndInvalidSchemaFailClosed() {
        val absent = snapshot().apply { remove("targetLastUpdateTime") }
        assertTrue(runCatching { StateCodec.snapshot(absent.toString()) }.isFailure)
        assertTrue(runCatching { StateCodec.snapshot(snapshot().put("schema", 2).toString()) }.isFailure)
        assertTrue(runCatching { StateCodec.snapshot(snapshot().put("targetPackage", "unknown").toString()) }.isFailure)
        assertTrue(runCatching { StateCodec.snapshot(snapshot().put("pid", -1).toString()) }.isFailure)
        assertTrue(runCatching { StateCodec.snapshot(snapshot().put("starttime", "3;reboot").toString()) }.isFailure)
        assertTrue(runCatching { StateCodec.snapshot(snapshot().put("moduleBuildId", "").toString()) }.isFailure)
    }

    @Test fun oversizedTruncatedAndNulDataAreRejected() {
        assertTrue(runCatching { StateCodec.snapshot(" ".repeat(16385)) }.isFailure)
        assertTrue(runCatching { StateCodec.snapshot(snapshot().toString().dropLast(4)) }.isFailure)
        assertTrue(runCatching { StateCodec.snapshot(snapshot().put("lastDetail", "abc\u0000def").toString()) }.isFailure)
    }

    @Test fun protocolRequiresModuleAndSchema() {
        assertTrue(runCatching { StateCodec.protocol("{\"schema\":1,\"moduleId\":\"other\"}") }.isFailure)
        assertEquals(1, StateCodec.protocol("{\"schema\":1,\"moduleId\":\"moseyPLK.service\"}").getInt("schema"))
    }

    private fun operation() = JSONObject("""{"id":"op-1","command":"restart","state":"running","reason":"","startedElapsed":1,"deadlineElapsed":211}""")

    @Test fun operationParserKeepsIdentityAndAcknowledgementDistinct() {
        val parsed = StateCodec.operation(operation())!!
        assertEquals("op-1", parsed.id)
        assertTrue(parsed.running)
        assertEquals(211L, parsed.deadlineElapsed)
        assertFalse(StateCodec.operation(operation().put("state", "unconfirmed"))!!.running)
        assertNull(StateCodec.operation(null))
    }

    @Test fun operationRejectsUnknownCommandsAndInvalidDeadlines() {
        assertTrue(runCatching { StateCodec.operation(operation().put("command", "reboot")) }.isFailure)
        assertTrue(runCatching { StateCodec.operation(operation().put("state", "magic")) }.isFailure)
        assertTrue(runCatching { StateCodec.operation(operation().put("id", "../payload")) }.isFailure)
        assertTrue(runCatching { StateCodec.operation(operation().put("deadlineElapsed", 0)) }.isFailure)
    }

    private fun procStat(start: String = "890"): String = "321 (process name) S " +
        List(18) { "0" }.joinToString(" ") + " $start 0 0"

    @Test fun processParserHandlesParenthesesAndRechecksStarttime() {
        val raw = "${procStat()}\n10118\ncom.google.android.gms\n${procStat()}"
        assertEquals(ProcessIdentity(321, 10118, "890", "com.google.android.gms"), StateCodec.process(raw, 321))
        assertNull(StateCodec.process("${procStat()}\n10118\ncom.google.android.gms\n${procStat("891")}", 321))
        assertNull(StateCodec.process(raw, 322))
        assertNull(StateCodec.process("321 invalid", 321))
    }
}
