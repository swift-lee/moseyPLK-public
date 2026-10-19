package moseyPLK.client.manager

import android.app.Application
import android.os.SystemClock
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

internal enum class RefreshTrigger { SILENT, PULL }
internal enum class RefreshDisposition { START, PROMOTE_RUNNING, IGNORE }
internal enum class ForegroundDisposition { STOP_POLLING, REQUEST_ROOT, RESUME }

internal fun foregroundDisposition(
    visible: Boolean,
    automaticRootAttempted: Boolean,
    ownerUser: Boolean,
): ForegroundDisposition = when {
    !visible -> ForegroundDisposition.STOP_POLLING
    !automaticRootAttempted && ownerUser -> ForegroundDisposition.REQUEST_ROOT
    else -> ForegroundDisposition.RESUME
}

/** Keeps full snapshots single-flight without interfering with native-operation polling. */
internal fun refreshDisposition(
    trigger: RefreshTrigger,
    refreshActive: Boolean,
    issuingCommand: Boolean,
    nativeWorkPending: Boolean,
    pollActive: Boolean,
): RefreshDisposition = when {
    refreshActive && trigger == RefreshTrigger.PULL -> RefreshDisposition.PROMOTE_RUNNING
    refreshActive -> RefreshDisposition.IGNORE
    issuingCommand || nativeWorkPending || pollActive -> RefreshDisposition.IGNORE
    else -> RefreshDisposition.START
}

internal fun ManagerState.startRefresh(trigger: RefreshTrigger): ManagerState = copy(
    refreshing = true,
    pullRefreshing = trigger == RefreshTrigger.PULL,
)

internal fun ManagerState.promoteRefreshToPull(): ManagerState = copy(pullRefreshing = true)

internal fun ManagerState.finishRefresh(): ManagerState = copy(
    refreshing = false,
    pullRefreshing = false,
)

class ManagerViewModel(application: Application) : AndroidViewModel(application) {
    private val repository = ManagerRepository(application)
    private val mutableState = MutableStateFlow(ManagerState(
        ownerUser = repository.ownerUser,
        deviceInfo = repository.deviceInfo,
    ))
    val state = mutableState.asStateFlow()
    private var foreground = false
    private var automaticRootAttempted = false
    private var refreshJob: Job? = null
    private var pollJob: Job? = null

    fun onForeground(visible: Boolean) {
        foreground = visible
        when (foregroundDisposition(visible, automaticRootAttempted, repository.ownerUser)) {
            ForegroundDisposition.STOP_POLLING -> {
                pollJob?.cancel()
                pollJob = null
            }
            ForegroundDisposition.REQUEST_ROOT -> {
                automaticRootAttempted = true
                requestRoot()
            }
            ForegroundDisposition.RESUME -> resumeForegroundWork()
        }
    }

    fun requestRoot() {
        if (mutableState.value.issuingCommand || mutableState.value.refreshing || !repository.ownerUser) return
        // Whether automatic or explicit, a completed denial is never retried on a later onStart.
        automaticRootAttempted = true
        mutableState.update { it.copy(issuingCommand = true, message = "等待 root 授权", messageTarget = null) }
        viewModelScope.launch {
            val access = repository.authorize()
            mutableState.update { it.copy(root = access, issuingCommand = false,
                message = if (access == RootAccess.GRANTED) "root 已授权" else "请前往 KernelSU 授权后重试",
                messageTarget = null) }
            if (foreground) resumeForegroundWork()
        }
    }

    fun refreshFromPull() = requestRefresh(RefreshTrigger.PULL)

    private fun refreshSilently() = requestRefresh(RefreshTrigger.SILENT)

    private fun resumeForegroundWork() {
        val current = mutableState.value
        if (current.issuingCommand) return
        if (current.pendingNativeResult || current.native.operation?.running == true) startPolling()
        else refreshSilently()
    }

    private fun requestRefresh(trigger: RefreshTrigger) {
        val current = mutableState.value
        when (refreshDisposition(
            trigger = trigger,
            refreshActive = refreshJob?.isActive == true,
            issuingCommand = current.issuingCommand,
            nativeWorkPending = current.pendingNativeResult || current.native.operation?.running == true,
            pollActive = pollJob?.isActive == true,
        )) {
            RefreshDisposition.PROMOTE_RUNNING -> {
                mutableState.update(ManagerState::promoteRefreshToPull)
                return
            }
            RefreshDisposition.IGNORE -> return
            RefreshDisposition.START -> Unit
        }

        mutableState.update { it.startRefresh(trigger) }
        refreshJob = viewModelScope.launch {
            val old = mutableState.value
            try {
                val refreshed = repository.refresh(old.root)
                // A failed read is not proof that an already accepted native task finished.
                val native = if (!refreshed.native.available && old.native.operation?.running == true) {
                    refreshed.native.copy(operation = old.native.operation)
                } else refreshed.native
                val active = mutableState.value
                mutableState.value = refreshed.copy(
                    native = native,
                    message = active.message,
                    messageTarget = active.messageTarget,
                    pendingNativeResult = old.pendingNativeResult && !refreshed.native.available,
                    refreshing = true,
                    pullRefreshing = active.pullRefreshing,
                )
                if (foreground) startPolling()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                mutableState.update { it.copy(message = "刷新未完成，请稍后重试") }
            } finally {
                mutableState.update(ManagerState::finishRefresh)
            }
        }
    }

    fun execute(action: ControlAction) {
        if (!mutableState.value.canExecute(action)) return
        val target = if (action == ControlAction.GMS_STOP) TargetApp.GMS else TargetApp.MOSEY
        mutableState.update { it.copy(issuingCommand = true, message = "正在执行：${action.title}", messageTarget = target) }
        viewModelScope.launch {
            try {
                val result = repository.execute(action)
                val (message, operation, uncertain) = result
                mutableState.update { it.copy(message = message,
                    native = if (operation != null) it.native.copy(operation = operation) else it.native) }
                if (action == ControlAction.GMS_STOP && result.commandSucceeded) {
                    // Observe from the force-stop completion, before the broader snapshot can
                    // consume many separate bounded root reads.
                    observeGmsRestart(mutableState.value.gms)
                    val observation = mutableState.value.message
                    try {
                        val refreshed = repository.refresh(mutableState.value.root)
                        mutableState.value = refreshed.copy(message = observation, messageTarget = target,
                            issuingCommand = true)
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (_: Exception) {
                        mutableState.update { it.copy(message = "$observation；完整状态刷新未完成", messageTarget = target) }
                    }
                    if (foreground) startPolling()
                    return@launch
                }
                val refreshed = repository.refresh(mutableState.value.root)
                val pending = operation?.takeIf { it.running &&
                    (!refreshed.native.available || refreshed.native.operation?.id != it.id) }
                mutableState.value = refreshed.copy(
                    message = message,
                    messageTarget = target,
                    native = if (pending != null) refreshed.native.copy(operation = pending) else refreshed.native,
                    pendingNativeResult = uncertain && !refreshed.native.available,
                    issuingCommand = true,
                )
                if (foreground) startPolling()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                mutableState.update { it.copy(message = "操作结果待确认；请刷新检查，请勿立即重复操作", messageTarget = target,
                    native = if (action.nativeCommand != null) it.native.markRunningUnconfirmed("refresh_failed") else it.native,
                    pendingNativeResult = action.nativeCommand != null) }
            } finally {
                mutableState.update { it.copy(issuingCommand = false) }
                if (foreground) startPolling()
            }
        }
    }

    fun restartGms() = execute(ControlAction.GMS_STOP)
    fun restartNativeService() = execute(ControlAction.NATIVE_RESTART)

    private suspend fun observeGmsRestart(installed: PackageIdentity?) {
        if (installed == null) return
        val deadline = SystemClock.elapsedRealtime() + 15_000L
        mutableState.update { it.copy(message = "GMS 强停命令已执行，正在复查进程") }
        var observed = ProcessState.UNKNOWN
        do {
            observed = repository.readProcess(TargetApp.GMS, installed)
            mutableState.update { it.copy(gmsProcess = observed) }
            if (observed == ProcessState.RUNNING || !repository.rootSessionAvailable) break
            if (SystemClock.elapsedRealtime() < deadline) delay(2000)
        } while (SystemClock.elapsedRealtime() < deadline)
        mutableState.update { it.copy(message = when (observed) {
            ProcessState.RUNNING -> "GMS 强停后当前已运行"
            ProcessState.STOPPED -> "GMS 强停命令已执行；系统尚未重新拉起进程"
            ProcessState.UNKNOWN -> "GMS 强停命令已执行；进程状态未确认"
        }) }
    }

    private fun startPolling(attributedToRequest: Boolean = true) {
        val operation = mutableState.value.native.operation?.takeIf { it.running }
        if (operation == null && !mutableState.value.pendingNativeResult) return
        if (!foreground || mutableState.value.issuingCommand || pollJob?.isActive == true) return
        pollJob = viewModelScope.launch {
            val limit = SystemClock.elapsedRealtime() + 235_000L
            var tracked = operation
            val attributionConfirmed = attributedToRequest && operation != null
            while (foreground && SystemClock.elapsedRealtime() < limit) {
                delay(2000)
                val fresh = repository.readNative(mutableState.value.native)
                val current = fresh.operation
                if (!repository.rootSessionAvailable) {
                    mutableState.update { it.copy(root = RootAccess.UNAVAILABLE,
                        native = fresh.copy(operation = tracked?.copy(state = "unconfirmed", reason = "root_session_lost")),
                        pendingNativeResult = false, messageTarget = TargetApp.MOSEY,
                        message = "root 会话已断开；重新授权后可继续检查，原生任务不会被终止") }
                    return@launch
                }
                if (!fresh.available) {
                    mutableState.update { it.copy(native = fresh.copy(operation = tracked), message = "任务状态暂不可读；等待确认") }
                    continue
                }
                if (current == null) {
                    mutableState.update { it.copy(native = fresh, pendingNativeResult = false, message = "尚无任务记录；请查看当前服务状态") }
                    pollJob = null
                    refreshSilently()
                    return@launch
                }
                if (tracked != null && current.id != tracked.id) {
                    mutableState.update { it.copy(native = fresh, pendingNativeResult = false, message = "任务记录已变化；上次操作结果待确认") }
                    pollJob = null
                    if (current.running) startPolling(attributedToRequest = false)
                    else refreshSilently()
                    return@launch
                }
                tracked = current
                mutableState.update { it.copy(native = fresh, pendingNativeResult = false) }
                if (!current.running) {
                    val result = if (!attributionConfirmed) "当前原生任务已结束；本次提交结果仍待确认"
                    else when (current.state) {
                        "succeeded" -> "原生操作已完成"
                        "failed" -> "原生操作未完成"
                        else -> "原生操作结果待确认"
                    }
                    mutableState.update { it.copy(message = "$result${current.reason.takeIf(String::isNotEmpty)?.let { reason -> "：$reason" }.orEmpty()}", messageTarget = TargetApp.MOSEY) }
                    // Refresh target processes and hook records after the native task ends.
                    pollJob = null
                    refreshSilently()
                    return@launch
                }
            }
            if (foreground) mutableState.update { it.copy(
                native = it.native.copy(operation = it.native.operation?.copy(state = "unconfirmed", reason = "ui_wait_timeout")),
                pendingNativeResult = false,
                message = "等待已结束，结果待确认；服务任务不会因退出界面而被终止",
            ) }
        }
    }

    private fun NativeReading.markRunningUnconfirmed(reason: String): NativeReading = copy(
        operation = operation?.let { if (it.running) it.copy(state = "unconfirmed", reason = reason) else it },
    )
}
