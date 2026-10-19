# 注册与服务编排

当前服务模块为 `moseyPLK.service`，与客户端共用 [release.json](../../release.json) 的 0.7.0 / code 21。目录包含自有启动编排、身份与载荷检查、被动状态、事件日志及固定 root 控制协议。

开机 `service.sh` 先启动状态观察器，再持有与交互控制共用的私有锁，进入有界 readiness 路径，核对载荷视图、系统进程、活动应用身份和完整 Binder 列表。启动等待有上限，不加入周期强杀或无限重试。

`control.sh` 仅接受 `capabilities/status/start/stop/restart`。交互修改操作保持独立的严格预检；停止要求本轮所有权记录及完整身份匹配，使用 pidfd 发送 SIGTERM。已有未知来源实例不被自动收养，重启需确认旧实例退出且 Binder 消失。

`Running` 表示准确原生进程身份与 Binder 条件满足；`Unregistered`、`Stopped` 和 `Unknown` 分别保留不同证据含义。状态发布和日志会写入模块自身运行目录，不能作为助手只读采集入口。

安装器仅接受 Android 内的 KernelSU 安装流程。0.7.0 Release 的服务 ZIP 包含七件固定哈希 OxygenOS 供体和原 Fold6 launcher，源码树及源码归档仍排除这些外部原件；项目 Apache-2.0 声明不授予外部载荷的许可。

## 构建与检查

```sh
python3 scripts/generate_compatibility.py
python3 scripts/build_registration.py
```

从项目根执行，先准备本地 COS 配置、限定策略、供体、launcher 和 NDK；完整输入见 [构建说明](../../docs/build.md)。公开源码不携带这些原件，sources ZIP 使用统一公开清单。

主机检查入口为 `scripts/test_registration_startup.py`、`scripts/test_service_control.py`、`scripts/test_module_status.py` 和 [原生注册测试](../../native/registration-compat/README.md)。默认检查见 [测试说明](../../docs/testing.md)。真实 Android 注册、root/SELinux、挂载与收发需要独立验收。
