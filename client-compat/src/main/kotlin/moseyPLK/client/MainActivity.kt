// SPDX-License-Identifier: Apache-2.0
// UI portions adapted from GhostLock-App:
// https://github.com/YuKongA/ghostlock-app/tree/3bd95d37e4874821d4143fc7f0fbd85fc2348ee3
// and compose-miuix examples (product dependency: miuix 0.9.3):
// https://github.com/compose-miuix-ui/miuix/tree/5c91d5e5ce1a2fc7e8bdc1258a881c555102bbca
// Copyright 2025, compose-miuix-ui contributors
// Modified for moseyPLK: service status, device details, refresh and control UI.
// See the repository LICENSE and THIRD_PARTY_NOTICES.md.

package moseyPLK.client

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CheckCircleOutline
import androidx.compose.material.icons.rounded.ErrorOutline
import androidx.compose.material.icons.rounded.RemoveCircleOutline
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import moseyPLK.client.manager.AirDropSupportPolicy
import moseyPLK.client.manager.ControlAction
import moseyPLK.client.manager.ManagerState
import moseyPLK.client.manager.ManagerViewModel
import moseyPLK.client.manager.ModulePresence
import moseyPLK.client.manager.ModuleVersion
import moseyPLK.client.manager.OverviewLevel
import moseyPLK.client.manager.OverviewPolicy
import moseyPLK.client.manager.ProcessState
import moseyPLK.client.manager.RootAccess
import moseyPLK.client.manager.TargetApp
import top.yukonga.miuix.kmp.basic.BasicComponent
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.CardDefaults
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.PullToRefresh
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.TabRow
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.basic.rememberTopAppBarState
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.darkColorScheme
import top.yukonga.miuix.kmp.theme.lightColorScheme

/** The only UI entry point. No Xposed classes are loaded by this Activity. */
class MainActivity : ComponentActivity() {
    private lateinit var model: ManagerViewModel

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        model = ViewModelProvider(this)[ManagerViewModel::class.java]
        setContent {
            MiuixTheme(colors = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()) {
                val state by model.state.collectAsStateWithLifecycle()
                ManagerScreen(
                    state,
                    model::requestRoot,
                    model::refreshFromPull,
                    model::restartNativeService,
                    model::restartGms,
                )
            }
        }
    }

    override fun onStart() {
        super.onStart()
        model.onForeground(true)
    }

    override fun onStop() {
        model.onForeground(false)
        super.onStop()
    }
}

@Composable
private fun ManagerScreen(
    state: ManagerState,
    requestRoot: () -> Unit,
    refreshFromPull: () -> Unit,
    restartNativeService: () -> Unit,
    restartGms: () -> Unit,
) {
    val scrollBehavior = MiuixScrollBehavior(rememberTopAppBarState())
    var selectedTab by rememberSaveable { mutableIntStateOf(0) }
    var showNativeRestartDialog by rememberSaveable { mutableStateOf(false) }
    var showGmsDialog by rememberSaveable { mutableStateOf(false) }

    val currentModule = ModuleVersion(ModuleBuild.VERSION, ModuleBuild.VERSION_CODE)
    val gmsAdvisory = state.gms?.let { GmsVersionAdvisory.evaluate(it.versionCode) }
    val gmsVersionWarning = gmsAdvisory?.position == GmsVersionAdvisory.Position.BELOW_KNOWN_RANGE ||
        gmsAdvisory?.position == GmsVersionAdvisory.Position.ABOVE_KNOWN_RANGE
    val overview = OverviewPolicy.evaluate(state, currentModule, gmsVersionWarning)
    val canRestartService = state.canExecute(ControlAction.NATIVE_RESTART)
    val canRestartGms = state.canExecute(ControlAction.GMS_STOP)

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        topBar = {
            TopAppBar(
                title = "moseyPLK",
                scrollBehavior = scrollBehavior,
            )
        },
    ) { insets ->
        PullToRefresh(
            isRefreshing = state.pullRefreshing,
            onRefresh = refreshFromPull,
            modifier = Modifier
                .fillMaxSize()
                .padding(insets),
            refreshTexts = listOf("下拉刷新", "松开刷新", "正在读取", "已刷新"),
        ) {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .nestedScroll(scrollBehavior.nestedScrollConnection),
                contentPadding = PaddingValues(start = 12.dp, end = 12.dp, top = 8.dp, bottom = 24.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                item {
                    OverviewStatusCard(
                        level = overview.level,
                        reason = overview.reason,
                        modifier = pageWidthModifier(),
                    )
                }
                item {
                    StatusDetailsCard(
                        state = state,
                        reason = overview.reason,
                        requestRoot = requestRoot,
                        modifier = pageWidthModifier(),
                    )
                }
                item {
                    DeviceInfoCard(
                        deviceName = state.deviceInfo.deviceName,
                        socName = state.deviceInfo.socName,
                        modifier = pageWidthModifier(),
                    )
                }
                item {
                    ModuleVersionCard(
                        state = state,
                        currentModule = currentModule,
                        modifier = pageWidthModifier(),
                    )
                }
                item {
                    TabRow(
                        tabs = listOf("Mosey", "GMS"),
                        selectedTabIndex = selectedTab,
                        onTabSelected = { selectedTab = it },
                        modifier = pageWidthModifier(),
                    )
                }
                if (selectedTab == 0) {
                    item {
                        InfoCard(modifier = pageWidthModifier()) {
                            BasicComponent(title = "Mosey 主进程", summary = processLabel(state.moseyProcess))
                            BasicComponent(
                                title = state.mosey?.displayName ?: TargetApp.MOSEY.title,
                                summary = state.mosey?.let { formatPackageVersion(it.versionName, it.versionCode) }
                                    ?: "未安装或未确认",
                            )
                        }
                    }
                    item {
                        ActionCard(
                            title = "Mosey 原生服务",
                            explanation = "只重启 Mosey 原生服务，不会停止或重新启动 Mosey 应用。",
                            button = "重启原生服务",
                            buttonEnabled = canRestartService,
                            onClick = { showNativeRestartDialog = true },
                            message = state.message.takeIf { state.messageTarget == TargetApp.MOSEY },
                            modifier = pageWidthModifier(),
                        )
                    }
                } else {
                    item {
                        InfoCard(modifier = pageWidthModifier()) {
                            BasicComponent(
                                title = state.gms?.displayName ?: TargetApp.GMS.title,
                                summary = state.gms?.let { formatPackageVersion(it.versionName, it.versionCode) }
                                    ?: "未安装或未确认",
                            )
                            if (gmsVersionWarning) {
                                BasicComponent(title = "版本提醒", summary = "超出已知版本范围；自动适配仍会尝试解析。")
                            }
                        }
                    }
                    item {
                        ActionCard(
                            title = "GMS",
                            explanation = "确认后强制停止 GMS，系统可能随后重新启动它。",
                            button = "重启 GMS",
                            buttonEnabled = canRestartGms,
                            onClick = { showGmsDialog = true },
                            message = state.message.takeIf { state.messageTarget == TargetApp.GMS },
                            modifier = pageWidthModifier(),
                        )
                    }
                }
            }
        }

        OverlayDialog(
            show = showNativeRestartDialog,
            title = "重启原生服务？",
            summary = "只会提交 Mosey 原生服务重启任务，不会停止或重新启动 Mosey 应用。这可能中断正在进行的分享。",
            onDismissRequest = { showNativeRestartDialog = false },
            content = {
                Row(Modifier.fillMaxWidth()) {
                    TextButton(
                        text = "取消",
                        onClick = { showNativeRestartDialog = false },
                        modifier = Modifier.weight(1f),
                    )
                    Spacer(Modifier.width(12.dp))
                    TextButton(
                        text = "确认",
                        onClick = {
                            showNativeRestartDialog = false
                            restartNativeService()
                        },
                        enabled = canRestartService,
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.textButtonColorsPrimary(),
                    )
                }
            },
        )

        OverlayDialog(
            show = showGmsDialog,
            title = "重启 GMS？",
            summary = "将强制停止 Google Play 服务，可能中断正在进行的分享。执行后会短暂复查进程状态；系统是否立即重新启动它无法保证。",
            onDismissRequest = { showGmsDialog = false },
            content = {
                Row(Modifier.fillMaxWidth()) {
                    TextButton(
                        text = "取消",
                        onClick = { showGmsDialog = false },
                        modifier = Modifier.weight(1f),
                    )
                    Spacer(Modifier.width(12.dp))
                    TextButton(
                        text = "确认",
                        onClick = {
                            showGmsDialog = false
                            restartGms()
                        },
                        enabled = canRestartGms,
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.textButtonColorsPrimary(),
                    )
                }
            },
        )
    }
}

@Composable
private fun OverviewStatusCard(
    level: OverviewLevel,
    reason: String,
    modifier: Modifier = Modifier,
) {
    val dark = isSystemInDarkTheme()
    val cardColor = when (level) {
        OverviewLevel.WORKING -> if (dark) Color(0xFF173923) else Color(0xFFDFFAE4)
        OverviewLevel.WARNING -> if (dark) Color(0xFF3B321F) else Color(0xFFFFF4DB)
        OverviewLevel.NOT_RUNNING -> if (dark) Color(0xFF3B1715) else Color(0xFFF8E2E2)
    }
    val statusIcon = when (level) {
        OverviewLevel.WORKING -> Icons.Rounded.CheckCircleOutline
        OverviewLevel.WARNING -> Icons.Rounded.ErrorOutline
        OverviewLevel.NOT_RUNNING -> Icons.Rounded.RemoveCircleOutline
    }
    val statusIconColor = when (level) {
        OverviewLevel.WORKING -> if (dark) Color(0xFF62D783) else Color(0xFF36D167)
        OverviewLevel.WARNING -> if (dark) Color(0xFFFFC56C) else Color(0xFFF5A623)
        OverviewLevel.NOT_RUNNING -> if (dark) Color(0xFFFF8E8E) else Color(0xFFAD3939)
    }
    val title = when (level) {
        OverviewLevel.WORKING -> "工作中"
        OverviewLevel.WARNING -> "警告"
        OverviewLevel.NOT_RUNNING -> "未运行"
    }

    Card(
        modifier = modifier,
        colors = CardDefaults.defaultColors(color = cardColor),
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(110.dp),
        ) {
            Column(
                modifier = Modifier
                    .align(Alignment.TopStart)
                    .fillMaxWidth()
                    .padding(start = 16.dp, top = 14.dp, end = 104.dp),
            ) {
                Text(
                    text = title,
                    fontSize = 22.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = MiuixTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                if (level != OverviewLevel.WORKING) {
                    Text(
                        text = reason,
                        modifier = Modifier.padding(top = 2.dp),
                        fontSize = 13.sp,
                        lineHeight = 18.sp,
                        color = MiuixTheme.colorScheme.onSurface.copy(alpha = 0.64f),
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
            Icon(
                imageVector = statusIcon,
                contentDescription = null,
                tint = statusIconColor,
                modifier = Modifier
                    .align(Alignment.BottomEnd)
                    .offset(x = 27.dp, y = 31.dp)
                    .size(110.dp),
            )
        }
    }
}

@Composable
private fun StatusDetailsCard(
    state: ManagerState,
    reason: String,
    requestRoot: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val canRetryRoot = state.root != RootAccess.GRANTED &&
        state.root != RootAccess.NOT_REQUESTED && state.ownerUser
    Card(
        modifier = modifier,
        insideMargin = PaddingValues(16.dp),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(20.dp),
        ) {
            DeviceInfoItem(
                title = "AirDrop 支持",
                value = if (AirDropSupportPolicy.isDeclared(state.gmsHook)) "已声明" else "未声明",
            )
            DeviceInfoItem(title = "状态详情", value = reason)
            DeviceInfoItem(
                title = "服务状态",
                value = "原生服务：${nativeLabel(state.native.state)} · Mosey 主进程：${processLabel(state.moseyProcess)}",
            )
            state.message.takeIf { it.isNotBlank() && state.messageTarget == null }?.let {
                DeviceInfoItem(title = "最近消息", value = it)
            }
            if (state.root != RootAccess.GRANTED && state.root != RootAccess.NOT_REQUESTED) {
                Caption("请前往 KernelSU 为 moseyPLK 授予 root，然后返回这里重试。")
            }
            if (canRetryRoot) {
                TextButton(
                    text = "重试授权",
                    onClick = requestRoot,
                    enabled = !state.issuingCommand && !state.refreshing,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.textButtonColorsPrimary(),
                )
            }
        }
    }
}

@Composable
private fun DeviceInfoCard(
    deviceName: String,
    socName: String,
    modifier: Modifier = Modifier,
) {
    Card(
        modifier = modifier,
        insideMargin = PaddingValues(16.dp),
    ) {
        SelectionContainer {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(20.dp),
            ) {
                DeviceInfoItem(title = "设备", value = deviceName)
                DeviceInfoItem(title = "芯片", value = socName)
            }
        }
    }
}

@Composable
private fun DeviceInfoItem(
    title: String,
    value: String,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier) {
        Text(
            text = title,
            fontSize = 18.sp,
            fontWeight = FontWeight.Medium,
            color = MiuixTheme.colorScheme.onSurface,
        )
        Text(
            text = value,
            modifier = Modifier.padding(top = 2.dp),
            fontSize = 14.sp,
            color = MiuixTheme.colorScheme.onSurface.copy(alpha = 0.68f),
        )
    }
}

@Composable
private fun ModuleVersionCard(
    state: ManagerState,
    currentModule: ModuleVersion,
    modifier: Modifier = Modifier,
) {
    Column(modifier) {
        SectionTitle("模块版本")
        InfoCard(modifier = Modifier.fillMaxWidth()) {
            BasicComponent(title = "Xposed / 管理 App", summary = "${currentModule.name} · ${currentModule.code}")
            BasicComponent(
                title = "KernelSU",
                summary = when (state.modulePresence) {
                    ModulePresence.ABSENT -> "未安装"
                    ModulePresence.DISABLED -> "已停用"
                    ModulePresence.UNKNOWN -> "未确认"
                    else -> state.native.version?.let { "${it.name} · ${it.code}" } ?: "未确认"
                },
            )
        }
    }
}

@Composable
private fun InfoCard(
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    Card(modifier = modifier) { content() }
}

@Composable
private fun ActionCard(
    title: String,
    explanation: String,
    button: String,
    buttonEnabled: Boolean,
    onClick: () -> Unit,
    message: String?,
    modifier: Modifier = Modifier,
) {
    Card(
        modifier = modifier,
        insideMargin = PaddingValues(16.dp),
    ) {
        Text(title, fontSize = 18.sp, fontWeight = FontWeight.Medium)
        Spacer(Modifier.height(8.dp))
        Caption(explanation)
        Spacer(Modifier.height(14.dp))
        TextButton(
            text = button,
            onClick = onClick,
            enabled = buttonEnabled,
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.textButtonColorsPrimary(),
        )
        if (!message.isNullOrEmpty()) {
            Spacer(Modifier.height(12.dp))
            Text(message, fontSize = 14.sp)
        }
    }
}

@Composable
private fun SectionTitle(title: String) {
    Text(
        text = title,
        modifier = Modifier.padding(start = 4.dp, bottom = 10.dp),
        fontSize = 18.sp,
        fontWeight = FontWeight.SemiBold,
    )
}

@Composable
private fun Caption(
    text: String,
    modifier: Modifier = Modifier,
) {
    Text(
        text = text,
        modifier = modifier,
        fontSize = 13.sp,
        color = MiuixTheme.colorScheme.onSurface.copy(alpha = 0.64f),
        lineHeight = 20.sp,
    )
}

private fun pageWidthModifier(): Modifier = Modifier
    .widthIn(max = 720.dp)
    .fillMaxWidth()

private fun processLabel(state: ProcessState): String = when (state) {
    ProcessState.RUNNING -> "运行中"
    ProcessState.STOPPED -> "未运行"
    ProcessState.UNKNOWN -> "未确认"
}

private fun nativeLabel(state: String): String = when (state) {
    "Running" -> "运行中"
    "Stopped" -> "未运行"
    "Unregistered" -> "未注册"
    else -> "未确认"
}

internal fun formatPackageVersion(versionName: String, versionCode: Long): String =
    "$versionName ($versionCode)"
