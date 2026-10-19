package moseyPLK.client.manager

import java.util.Locale

/** UI models deliberately contain no Android, root, or Xposed entry points. */
enum class TargetApp(val packageName: String, val title: String) {
    GMS("com.google.android.gms", "Google Play 服务"),
    MOSEY("com.google.android.mosey", "Mosey 扩展")
}

enum class ControlAction(val title: String, val nativeCommand: String? = null) {
    GMS_STOP("强制停止 GMS"),
    NATIVE_START("启动原生服务", "start"),
    NATIVE_STOP("停止原生服务", "stop"),
    NATIVE_RESTART("重启原生服务", "restart");

    val needsConfirmation: Boolean get() = this != NATIVE_START
}

enum class RootAccess { NOT_REQUESTED, GRANTED, DENIED, UNAVAILABLE }
enum class ProcessState { RUNNING, STOPPED, UNKNOWN }
enum class SnapshotFreshness { CURRENT, OLD_MODULE, STALE, UNCONFIRMED }
enum class AirDropDeclaration(val wireValue: String) {
    UNCONFIRMED("unconfirmed"),
    DECLARED("declared");

    companion object {
        fun fromWireValue(value: String): AirDropDeclaration? = entries.singleOrNull { it.wireValue == value }
    }
}
enum class ModulePresence { PRESENT, ABSENT, DISABLED, PENDING_REMOVAL, UPDATING, UNKNOWN }
data class DeviceSupport(val supported: Boolean, val reason: String = "")

/** Display-only device identity derived from public Android Build fields. */
data class DeviceInfo(
    val deviceName: String = "未知",
    val socName: String = "未知",
)

internal object DeviceInfoFormatter {
    private const val UNKNOWN = "未知"

    fun format(
        manufacturer: String?,
        brand: String?,
        model: String?,
        socManufacturer: String?,
        socModel: String?,
        supportedAbis: Iterable<String?>,
    ): DeviceInfo {
        val deviceName = distinctValid(manufacturer, brand, model).joinToString(" ").ifBlank { UNKNOWN }
        val soc = distinctValid(socManufacturer, socModel)
        val socName = if (soc.isNotEmpty()) soc.joinToString(" ")
        else supportedAbis.asSequence().mapNotNull(::valid).firstOrNull() ?: UNKNOWN
        return DeviceInfo(deviceName, socName)
    }

    private fun distinctValid(vararg values: String?): List<String> {
        val seen = mutableSetOf<String>()
        return values.mapNotNull(::valid).filter { seen.add(it.lowercase(Locale.ROOT)) }
    }

    private fun valid(value: String?): String? = value?.trim()?.takeIf {
        it.isNotEmpty() && !it.equals("unknown", ignoreCase = true) && !it.equals("null", ignoreCase = true)
    }
}

enum class OverviewLevel { WORKING, WARNING, NOT_RUNNING }
data class OverviewReading(val level: OverviewLevel, val reason: String)

data class PackageIdentity(
    val packageName: String,
    val uid: Int,
    val versionName: String,
    val versionCode: Long,
    val lastUpdateTime: Long,
    val displayName: String = packageName,
) {
    /** A localized application label is display-only and never changes installation identity. */
    fun sameInstallationAs(other: PackageIdentity?): Boolean = other != null &&
        packageName == other.packageName && uid == other.uid &&
        versionName == other.versionName && versionCode == other.versionCode &&
        lastUpdateTime == other.lastUpdateTime
}

internal object PackageDisplayName {
    private const val MAX_CODE_POINTS = 80

    fun sanitize(label: CharSequence?, fallback: String, packageName: String? = null): String {
        val cleaned = buildString {
            label?.forEach { character ->
                val kind = Character.getType(character)
                when {
                    character.isWhitespace() -> append(' ')
                    kind == Character.CONTROL.toInt() || kind == Character.FORMAT.toInt() -> Unit
                    else -> append(character)
                }
            }
        }.trim().replace(Regex(" +"), " ")
        if (cleaned.isEmpty() || cleaned == packageName) return fallback
        val end = if (cleaned.codePointCount(0, cleaned.length) > MAX_CODE_POINTS) {
            cleaned.offsetByCodePoints(0, MAX_CODE_POINTS)
        } else cleaned.length
        return cleaned.substring(0, end).trimEnd().ifEmpty { fallback }
    }
}

data class ModuleVersion(val name: String, val code: Long) {
    fun matches(other: ModuleVersion): Boolean = normalized(name) == normalized(other.name) && code == other.code

    companion object {
        private fun normalized(value: String): String = value.trim().let {
            if (it.startsWith('v') || it.startsWith('V')) it.drop(1) else it
        }
    }
}

data class ProcessIdentity(val pid: Int, val uid: Int, val starttime: String, val name: String)

data class HookSnapshot(
    val targetPackage: String,
    val userId: Int,
    val uid: Int,
    val pid: Int,
    val starttime: String,
    val bootCount: Int,
    val bootId: String,
    val capturedElapsedMs: Long,
    val targetVersionName: String,
    val targetVersionCode: Long,
    val targetLastUpdateTime: Long,
    val moduleVersion: ModuleVersion,
    val moduleBuildId: String,
    val moduleVariant: String,
    val resolution: String,
    val installation: String,
    val naturalHit: Boolean,
    val binderReady: String,
    val componentRestore: String,
    val lastEvent: String,
    val lastDetail: String,
    val workerResolution: String = "",
    val airdropDeclaration: AirDropDeclaration = AirDropDeclaration.UNCONFIRMED,
)

data class HookReading(
    val freshness: SnapshotFreshness = SnapshotFreshness.UNCONFIRMED,
    val reason: String = "尚未读取",
    val snapshot: HookSnapshot? = null,
)

/** A record's age alone never proves that the loaded process or hook is current. */
object SnapshotIdentity {
    fun check(
        snapshot: HookSnapshot,
        installed: PackageIdentity,
        process: ProcessIdentity?,
        bootCount: Int,
        bootId: String,
        elapsedMs: Long,
        module: ModuleVersion,
        buildId: String,
    ): HookReading {
        fun stale(reason: String) = HookReading(SnapshotFreshness.STALE, reason, snapshot)
        if (snapshot.targetPackage != installed.packageName || snapshot.userId != 0 ||
            snapshot.uid != installed.uid || installed.uid !in 10000..99999) return stale("目标身份已变化")
        if (snapshot.targetVersionCode != installed.versionCode ||
            snapshot.targetVersionName != installed.versionName ||
            snapshot.targetLastUpdateTime != installed.lastUpdateTime) return stale("目标应用已更新")
        if (bootCount < 0 || snapshot.bootCount < 0) {
            return HookReading(SnapshotFreshness.UNCONFIRMED, "无法核对本轮启动", snapshot)
        }
        if (snapshot.bootCount != bootCount) return stale("来自之前的启动")
        if (snapshot.bootId.isNotEmpty() && (bootId.isEmpty() || snapshot.bootId != bootId)) return stale("启动标识不符")
        if (snapshot.capturedElapsedMs < 0 || snapshot.capturedElapsedMs > elapsedMs) return stale("采样时间无效")
        if (process == null) return stale("记录进程已退出或无法核对")
        if (snapshot.pid != process.pid || snapshot.uid != process.uid || snapshot.starttime != process.starttime ||
            process.name != installed.packageName) return stale("进程身份已变化")
        if (!snapshot.moduleVersion.matches(module) || snapshot.moduleBuildId != buildId) {
            return HookReading(SnapshotFreshness.OLD_MODULE, "当前进程仍使用另一版模块", snapshot)
        }
        return HookReading(SnapshotFreshness.CURRENT, "已核对当前进程", snapshot)
    }
}

/** A final true is retained only for the verified lifetime of the current GMS process. */
internal object AirDropSupportPolicy {
    fun isDeclared(reading: HookReading): Boolean {
        val snapshot = reading.snapshot ?: return false
        val currentProcess = reading.freshness == SnapshotFreshness.CURRENT ||
            reading.freshness == SnapshotFreshness.OLD_MODULE
        return currentProcess &&
            snapshot.targetPackage == TargetApp.GMS.packageName &&
            snapshot.airdropDeclaration == AirDropDeclaration.DECLARED
    }
}

data class NativeOperation(
    val id: String,
    val command: String,
    val state: String,
    val reason: String,
    val startedElapsed: Long,
    val deadlineElapsed: Long,
) {
    val running: Boolean get() = state == "running"
}

data class NativeReading(
    val state: String = "Unknown",
    val version: ModuleVersion? = null,
    val commands: Set<String> = emptySet(),
    val operation: NativeOperation? = null,
    val reason: String = "尚未读取",
    val sampledAtMillis: Long = 0,
    val available: Boolean = false,
)

data class ManagerState(
    val root: RootAccess = RootAccess.NOT_REQUESTED,
    val ownerUser: Boolean = true,
    val deviceSupport: DeviceSupport = DeviceSupport(true),
    val deviceInfo: DeviceInfo = DeviceInfo(),
    val modulePresence: ModulePresence = ModulePresence.UNKNOWN,
    val modulePresenceReason: String = "",
    val refreshing: Boolean = false,
    val pullRefreshing: Boolean = false,
    val issuingCommand: Boolean = false,
    val pendingNativeResult: Boolean = false,
    val native: NativeReading = NativeReading(),
    val gms: PackageIdentity? = null,
    val mosey: PackageIdentity? = null,
    val gmsProcess: ProcessState = ProcessState.UNKNOWN,
    val moseyProcess: ProcessState = ProcessState.UNKNOWN,
    val gmsHook: HookReading = HookReading(),
    val moseyHook: HookReading = HookReading(),
    val legacyInstalled: Boolean = false,
    val sampledAtMillis: Long = 0,
    val message: String = "",
    val messageTarget: TargetApp? = null,
) {
    val busy: Boolean get() = refreshing || issuingCommand || pendingNativeResult || native.operation?.running == true

    /** Version mismatches are deliberately absent from this capability decision. */
    fun canExecute(action: ControlAction): Boolean {
        if (!ownerUser || root != RootAccess.GRANTED || busy) return false
        return when {
            action.nativeCommand != null -> action.nativeCommand in native.commands
            action == ControlAction.GMS_STOP -> gms != null
            else -> mosey != null
        }
    }
}

/** Only service and main-process readiness are claimed by the green overview. */
object OverviewPolicy {
    fun evaluate(state: ManagerState, currentModule: ModuleVersion, gmsVersionWarning: Boolean): OverviewReading {
        fun stopped(reason: String) = OverviewReading(OverviewLevel.NOT_RUNNING, reason)
        fun warning(reason: String) = OverviewReading(OverviewLevel.WARNING, reason)

        if (state.sampledAtMillis == 0L) return warning("正在检查设备状态")
        if (!state.deviceSupport.supported) return stopped(state.deviceSupport.reason.ifEmpty { "设备不受支持" })
        if (state.mosey == null) return stopped("未安装 Mosey 扩展")
        if (state.gms == null) return stopped("未安装 Google Play 服务")
        when (state.modulePresence) {
            ModulePresence.ABSENT -> return stopped("未安装 KSU 模块")
            ModulePresence.DISABLED -> return stopped("KSU 模块已停用")
            ModulePresence.PENDING_REMOVAL -> return stopped("KSU 模块待移除")
            else -> Unit
        }

        // A requested restart can temporarily remove the service/process. Wait for its terminal result.
        if (state.issuingCommand || state.pendingNativeResult || state.native.operation?.running == true) {
            return warning("正在执行操作，请等待状态复查")
        }
        when (state.native.state) {
            "Stopped" -> return stopped("Mosey 原生服务未运行")
            "Unregistered" -> return stopped("Mosey 原生服务尚未注册")
        }
        if (state.moseyProcess == ProcessState.STOPPED) return stopped("Mosey 主进程未运行")

        if (!state.ownerUser) return warning("管理操作仅支持主用户")
        if (state.root != RootAccess.GRANTED) return warning(
            if (state.root == RootAccess.NOT_REQUESTED) "正在检查 root 授权"
            else "请前往 KernelSU 授予 root 后重试",
        )
        if (state.modulePresence == ModulePresence.UPDATING) return warning("KSU 模块更新待生效")
        if (state.modulePresence != ModulePresence.PRESENT) return warning(
            state.modulePresenceReason.ifEmpty { "KSU 模块状态未确认" },
        )
        if (!state.native.available || state.native.state != "Running") return warning("原生服务状态未确认")
        if (state.moseyProcess != ProcessState.RUNNING) return warning("Mosey 主进程状态未确认")
        if (state.native.version == null) return warning("KSU 模块版本未确认")
        if (!state.native.version.matches(currentModule)) return warning("Xposed 与 KSU 模块版本不一致")
        if (state.legacyInstalled) return warning("检测到旧包名客户端，请检查 LSPosed 作用域")
        if (gmsVersionWarning) return warning("GMS 超出已知版本范围，自动适配仍会尝试")
        return OverviewReading(OverviewLevel.WORKING, "Mosey 原生服务与主进程正在运行")
    }
}
