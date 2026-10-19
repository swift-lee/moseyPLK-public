package moseyPLK.client.manager

import org.json.JSONObject

/** Parsers accept bounded data only. No parsed value is ever used as a shell command. */
object StateCodec {
    fun snapshot(raw: String): HookSnapshot {
        require(raw.toByteArray(Charsets.UTF_8).size in 1..16384) { "snapshot_size" }
        val json = JSONObject(raw)
        require(json.getInt("schema") == 1) { "snapshot_schema" }
        fun text(key: String, max: Int = 256): String = json.getString(key).also {
            require(it.length <= max && it.none { c -> c == '\u0000' }) { "snapshot_field" }
        }
        val packageName = text("targetPackage")
        require(TargetApp.entries.any { it.packageName == packageName }) { "snapshot_target" }
        val pid = json.getInt("pid")
        val start = json.getLong("starttime").toString()
        require(pid > 0 && start.matches(Regex("[0-9]{1,24}"))) { "snapshot_process" }
        val buildId = text("moduleBuildId", 128)
        require(buildId.isNotBlank()) { "snapshot_module" }
        val airdropDeclaration = if (json.has("airdropDeclaration")) {
            val rawDeclaration = json.get("airdropDeclaration")
            require(rawDeclaration is String) { "snapshot_airdrop_declaration" }
            requireNotNull(AirDropDeclaration.fromWireValue(rawDeclaration)) { "snapshot_airdrop_declaration" }
        } else {
            AirDropDeclaration.UNCONFIRMED
        }
        return HookSnapshot(
            packageName, json.getInt("userId"), json.getInt("uid"), pid, start,
            json.getInt("bootCount"), text("bootId", 64), json.getLong("capturedElapsedMs"),
            text("targetVersionName"), json.getLong("targetVersionCode"), json.getLong("targetLastUpdateTime"),
            ModuleVersion(text("moduleVersion", 64), json.getLong("moduleVersionCode")),
            buildId, text("moduleVariant", 64), text("resolution", 64), text("installation", 64),
            json.getBoolean("naturalHit"), text("binderReady", 64), text("componentRestore", 64),
            text("lastEvent"), text("lastDetail", 1024),
            json.optString("workerResolution", "").take(64),
            airdropDeclaration,
        )
    }

    fun protocol(raw: String): JSONObject {
        require(raw.toByteArray(Charsets.UTF_8).size in 1..16384) { "protocol_size" }
        val json = JSONObject(raw)
        require(json.getInt("schema") == 1 && json.getString("moduleId") == "moseyPLK.service") {
            "protocol_identity"
        }
        return json
    }

    fun operation(json: JSONObject?): NativeOperation? {
        if (json == null) return null
        val id = json.getString("id")
        val command = json.getString("command")
        val state = json.getString("state")
        require(id.matches(Regex("[A-Za-z0-9_.:-]{1,128}"))) { "operation_id" }
        require(command in setOf("start", "stop", "restart")) { "operation_command" }
        require(state in setOf("running", "succeeded", "failed", "unconfirmed")) { "operation_state" }
        val start = json.getLong("startedElapsed")
        val deadline = json.getLong("deadlineElapsed")
        require(start >= 0 && deadline >= start) { "operation_deadline" }
        return NativeOperation(id, command, state, json.optString("reason", "").take(256), start, deadline)
    }

    fun process(raw: String, expectedPid: Int): ProcessIdentity? = runCatching {
        val lines = raw.lineSequence().toList()
        require(lines.size >= 4)
        fun start(line: String): String {
            require(line.substringBefore(' ').toInt() == expectedPid)
            val rest = line.substringAfterLast(") ", "").trim().split(Regex("\\s+"))
            require(rest.size > 19 && rest[19].matches(Regex("[0-9]+")))
            return rest[19]
        }
        val first = start(lines[0])
        require(first == start(lines[3]))
        ProcessIdentity(expectedPid, lines[1].toInt(), first, lines[2])
    }.getOrNull()
}
