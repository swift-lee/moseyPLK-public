package moseyPLK.client.manager

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Process
import android.os.SystemClock
import android.util.Log
import com.topjohnwu.superuser.Shell
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import moseyPLK.client.ModuleBuild

data class CommandResult(val code: Int, val output: String, val diagnosticFailure: Boolean = false) {
    val success: Boolean get() = code == 0
}

internal data class ModulePresenceReading(
    val presence: ModulePresence,
    val reason: String = "",
)

/** Converts the closed probe exit vocabulary into display-safe reasons without echoing shell output. */
internal object ModulePresenceProbe {
    fun decode(result: CommandResult): ModulePresenceReading {
        if (result.success && !result.diagnosticFailure) {
            val presence = when (result.output.trim()) {
                "present" -> ModulePresence.PRESENT
                "absent" -> ModulePresence.ABSENT
                "disabled" -> ModulePresence.DISABLED
                "pending_removal" -> ModulePresence.PENDING_REMOVAL
                "updating" -> ModulePresence.UPDATING
                else -> null
            }
            if (presence != null) return ModulePresenceReading(presence)
            return ModulePresenceReading(ModulePresence.UNKNOWN, "KSU 模块检查返回未知结果")
        }
        val reason = when (result.code) {
            -1 -> "KSU 模块检查未完成"
            90 -> "KSU 模块检查未获得 root 身份"
            91 -> "KSU 模块目录校验失败"
            92 -> "KSU 模块目录不可读取"
            93 -> "moseyPLK KSU 模块目录校验失败"
            94 -> "KSU 模块信息文件校验失败"
            95 -> "KSU 模块状态标记校验失败"
            0 -> "KSU 模块检查输出异常"
            else -> "KSU 模块检查失败（代码 ${result.code}）"
        }
        return ModulePresenceReading(ModulePresence.UNKNOWN, reason)
    }
}

data class ControlResult(
    val message: String,
    val operation: NativeOperation? = null,
    val uncertainNative: Boolean = false,
    val commandSucceeded: Boolean = false,
)

/** A foreground entry may request a root session once; retry is user initiated after denial. */
class RootSession(private val context: Context) {
    private val lock = Mutex()
    @Volatile private var shell: Shell? = null
    val available: Boolean get() = shell?.let { it.isAlive && it.isRoot } == true

    suspend fun authorize(): Boolean = withContext(Dispatchers.IO) {
        lock.withLock {
            Shell.enableVerboseLogging = false
            var candidate: Shell? = null
            try {
                val selected = shell?.takeIf { it.isAlive && it.isRoot } ?: Shell.Builder.create()
                    .setContext(context.applicationContext)
                    .setFlags(Shell.FLAG_MOUNT_MASTER)
                    .setTimeout(20)
                    .build()
                candidate = selected
                if (!selected.isRoot) {
                    selected.close()
                    shell = null
                    return@withLock false
                }
                val stdout = mutableListOf<String>()
                val result = selected.newJob().add("id -u").to(stdout).enqueue().get(20, TimeUnit.SECONDS)
                if (!result.isSuccess || stdout.singleOrNull()?.trim() != "0") {
                    selected.close()
                    shell = null
                    return@withLock false
                }
                shell = selected
                true
            } catch (failure: Exception) {
                // Authorization has not submitted a control task. Release an incomplete session.
                runCatching { candidate?.close() }
                shell = null
                throw failure
            }
        }
    }

    suspend fun execute(command: String): CommandResult = withContext(Dispatchers.IO) {
        lock.withLock {
            val selected = shell?.takeIf { it.isAlive && it.isRoot }
                ?: return@withLock CommandResult(-1, "")
            val stdout = mutableListOf<String>()
            val stderr = mutableListOf<String>()
            try {
                val result = selected.newJob().add(command).to(stdout, stderr).enqueue().get(22, TimeUnit.SECONDS)
                CommandResult(result.code, stdout.joinToString("\n").take(32768), stderr.any {
                    it.startsWith("Error:", ignoreCase = true) || it.startsWith("Exception", ignoreCase = true)
                })
            } catch (_: Exception) {
                // Only the failed client session is closed. Accepted native tasks use their own
                // setsid session and are never killed or retried by the manager.
                runCatching { selected.close() }
                shell = null
                CommandResult(-1, "")
            }
        }
    }
}

class ManagerRepository(private val context: Context) {
    private val root = RootSession(context)
    private val module = ModuleVersion(ModuleBuild.VERSION, ModuleBuild.VERSION_CODE)
    val ownerUser: Boolean = Process.myUid() / 100000 == 0
    val rootSessionAvailable: Boolean get() = root.available
    val deviceSupport: DeviceSupport get() = DeviceSupportPolicy.evaluate(
        Build.MODEL, Build.VERSION.SDK_INT, Build.SUPPORTED_ABIS.firstOrNull(),
    )
    val deviceInfo: DeviceInfo get() = DeviceInfoFormatter.format(
        manufacturer = Build.MANUFACTURER,
        brand = Build.BRAND,
        model = Build.MODEL,
        socManufacturer = Build.SOC_MANUFACTURER,
        socModel = Build.SOC_MODEL,
        supportedAbis = Build.SUPPORTED_ABIS.asIterable(),
    )

    suspend fun authorize(): RootAccess = try {
        if (!ownerUser) RootAccess.UNAVAILABLE
        else if (root.authorize()) RootAccess.GRANTED else RootAccess.DENIED
    } catch (_: Exception) {
        RootAccess.UNAVAILABLE
    }

    private fun packageIdentity(target: TargetApp): PackageIdentity? = try {
        val pm = context.packageManager
        val info = pm.getPackageInfo(target.packageName, PackageManager.PackageInfoFlags.of(0))
        val application = pm.getApplicationInfo(target.packageName, PackageManager.ApplicationInfoFlags.of(0))
        val displayName = runCatching {
            PackageDisplayName.sanitize(application.loadLabel(pm), target.title, target.packageName)
        }.getOrDefault(target.title)
        PackageIdentity(target.packageName, application.uid, info.versionName.orEmpty(), info.longVersionCode,
            info.lastUpdateTime, displayName)
    } catch (_: PackageManager.NameNotFoundException) {
        null
    }

    private fun legacyInstalled(): Boolean = try {
        context.packageManager.getPackageInfo(RootCommands.LEGACY_PACKAGE, PackageManager.PackageInfoFlags.of(0))
        true
    } catch (_: PackageManager.NameNotFoundException) {
        false
    }

    suspend fun refresh(access: RootAccess): ManagerState = withContext(Dispatchers.IO) {
        val gms = packageIdentity(TargetApp.GMS)
        val mosey = packageIdentity(TargetApp.MOSEY)
        var state = ManagerState(root = access, ownerUser = ownerUser, gms = gms, mosey = mosey,
            deviceSupport = deviceSupport,
            deviceInfo = deviceInfo,
            legacyInstalled = legacyInstalled(), sampledAtMillis = System.currentTimeMillis())
        if (access != RootAccess.GRANTED || !ownerUser) return@withContext state.copy(
            native = NativeReading(reason = "需要主用户 root 授权"),
            gmsHook = HookReading(reason = "未授权／未确认"), moseyHook = HookReading(reason = "未授权／未确认"),
        )
        val bootResult = root.execute(RootCommands.bootIdentity)
        val bootLines = if (bootResult.success) bootResult.output.lines() else emptyList()
        val bootCount = bootLines.getOrNull(0)?.toIntOrNull() ?: -1
        val bootId = bootLines.getOrNull(1).orEmpty()
        val modulePresence = readModulePresence()
        state = state.copy(
            modulePresence = modulePresence.presence,
            modulePresenceReason = modulePresence.reason,
            native = readNative(),
            gmsHook = readHook(TargetApp.GMS, gms, bootCount, bootId),
            moseyHook = readHook(TargetApp.MOSEY, mosey, bootCount, bootId),
            gmsProcess = readProcess(TargetApp.GMS, gms),
            moseyProcess = readProcess(TargetApp.MOSEY, mosey),
            sampledAtMillis = System.currentTimeMillis(),
        )
        if (root.available) state else state.copy(root = RootAccess.UNAVAILABLE)
    }

    suspend fun readProcess(target: TargetApp, installed: PackageIdentity?): ProcessState {
        if (installed == null || installed.uid !in 10000..99999) return ProcessState.UNKNOWN
        val result = root.execute(RootCommands.processes(target, installed.uid))
        if (!result.success) return ProcessState.UNKNOWN
        return when (result.output.trim()) {
            "running" -> ProcessState.RUNNING
            "stopped" -> ProcessState.STOPPED
            else -> ProcessState.UNKNOWN
        }
    }

    private suspend fun readModulePresence(): ModulePresenceReading =
        ModulePresenceProbe.decode(root.execute(RootCommands.modulePresence))

    private suspend fun readHook(target: TargetApp, installed: PackageIdentity?, bootCount: Int, bootId: String): HookReading {
        if (installed == null) return HookReading(reason = "未安装或不可读取")
        if (installed.uid !in 10000..99999) return HookReading(reason = "目标用户身份不符")
        val raw = root.execute(RootCommands.snapshot(target, installed.uid))
        if (!raw.success) return HookReading(reason = "没有可核对的记录（尚未加载或读取受限）")
        return try {
            val snapshot = StateCodec.snapshot(raw.output)
            val processResult = root.execute(RootCommands.process(snapshot.pid))
            val process = if (processResult.success) StateCodec.process(processResult.output, snapshot.pid) else null
            if (!installed.sameInstallationAs(packageIdentity(target))) return HookReading(
                SnapshotFreshness.STALE, "检查期间应用发生更新", snapshot,
            )
            SnapshotIdentity.check(snapshot, installed, process, bootCount, bootId,
                SystemClock.elapsedRealtime(), module, ModuleBuild.BUILD_ID)
        } catch (_: Exception) {
            HookReading(reason = "记录格式无效或版本尚不支持")
        }
    }

    private suspend fun legacyModuleVersion(): ModuleVersion? {
        val result = root.execute(RootCommands.moduleVersion)
        if (!result.success) return null
        val values = result.output.lineSequence().mapNotNull { line ->
            val index = line.indexOf('=')
            if (index < 0) null else line.substring(0, index) to line.substring(index + 1)
        }.toMap()
        val name = values["version"]?.take(64) ?: return null
        val code = values["versionCode"]?.toLongOrNull() ?: return null
        return ModuleVersion(name, code)
    }

    suspend fun readNative(previous: NativeReading? = null): NativeReading {
        // An in-flight poll needs one bounded status request, not repeated capability discovery.
        val commands = if (previous != null) previous.commands else {
            val capabilitiesResult = root.execute(RootCommands.helper("capabilities"))
            runCatching {
                val json = StateCodec.protocol(capabilitiesResult.output)
                require(capabilitiesResult.success && json.getBoolean("ok") && json.optBoolean("mountNamespaceVerified", false))
                val array = json.getJSONArray("commands")
                (0 until array.length()).map { array.getString(it) }.filter { it in setOf("start", "stop", "restart") }.toSet()
            }.getOrDefault(emptySet())
        }
        val statusResult = root.execute(RootCommands.helper("status"))
        val sampledAt = System.currentTimeMillis()
        return try {
            val json = StateCodec.protocol(statusResult.output)
            val version = ModuleVersion(json.getString("version").take(64), json.getLong("versionCode"))
            if (!statusResult.success || !json.getBoolean("ok")) {
                NativeReading(version = version, commands = emptySet(), reason = json.optString("reason", "读取失败").take(256), sampledAtMillis = sampledAt)
            } else {
                val state = json.getString("state")
                require(state in setOf("Running", "Stopped", "Unregistered", "Unknown"))
                val verifiedMount = json.optBoolean("mountNamespaceVerified", false)
                NativeReading(state, version, if (verifiedMount) commands else emptySet(), StateCodec.operation(json.optJSONObject("lastOperation")),
                    if (json.optBoolean("mountNamespaceVerified", false)) json.optString("reason", "")
                    else "主挂载命名空间未确认，原生控制暂不可用", sampledAt, available = true)
            }
        } catch (_: Exception) {
            NativeReading(version = if (previous != null) previous.version else legacyModuleVersion(),
                reason = "控制接口不可读取；请检查 KSU 模块及 root 配置", sampledAtMillis = sampledAt)
        }
    }

    /** Called only after capability checks and, where required, a user confirmation. */
    suspend fun execute(action: ControlAction): ControlResult {
        check(ownerUser) { "owner_user_required" }
        safeLog("control_requested action=${action.name}")
        if (action.nativeCommand != null) {
            val result = root.execute(RootCommands.helper(action.nativeCommand))
            val parsed = runCatching { StateCodec.protocol(result.output) }.getOrNull()
            if (parsed == null) return ControlResult("结果待确认；请刷新查看原生任务状态，请勿立即重复操作", uncertainNative = true)
            if (!result.success || !parsed.optBoolean("ok")) {
                val reason = parsed.optString("reason", "请求未被接受").take(256)
                safeLog("control_rejected action=${action.name}")
                return ControlResult("操作未被接受：$reason")
            }
            val operation = runCatching { StateCodec.operation(parsed.optJSONObject("operation")) }.getOrNull()
            if (operation == null || operation.command != action.nativeCommand) return ControlResult("结果待确认；请刷新查看任务状态", uncertainNative = true)
            safeLog("control_accepted action=${action.name}")
            return ControlResult("原生任务已提交", operation)
        }
        val result = root.execute(RootCommands.application(action))
        val commandSucceeded = result.success && !result.diagnosticFailure && !result.output.lineSequence().any {
            it.startsWith("Error:", ignoreCase = true) || it.startsWith("Exception", ignoreCase = true)
        }
        safeLog("control_finished action=${action.name} command_ok=$commandSucceeded")
        return ControlResult(if (commandSucceeded) "命令已完成；正在复查实际状态" else "命令失败或结果未确认；请检查 root 配置后刷新",
            commandSucceeded = commandSucceeded)
    }

    companion object {
        private fun safeLog(message: String) {
            runCatching { Log.i("MoseyManager", message) }
        }
    }
}

internal object DeviceSupportPolicy {
    fun evaluate(model: String?, sdk: Int, primaryAbi: String?): DeviceSupport = when {
        model != "PLK110" -> DeviceSupport(false, "此机型不受支持（需要 PLK110）")
        sdk != 36 -> DeviceSupport(false, "此系统版本不受支持（需要 Android API 36）")
        primaryAbi != "arm64-v8a" -> DeviceSupport(false, "此处理器架构不受支持（需要 arm64-v8a）")
        else -> DeviceSupport(true)
    }
}
