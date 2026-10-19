# moseyPLK 客户端

客户端为 `moseyPLK.client`，当前 0.7.0 / code 21，版本来自根目录 [release.json](../release.json)。源码包含 Java LSPosed hook、Kotlin Compose/Miuix 管理界面、状态快照和纯主机测试。

管理界面展示分层状态、应用版本、设备公共 Build 字段与目标 getter 的声明信号。Activity 首次进入前台时尝试既有 root 会话，后续静默刷新；下拉动作单独显示刷新动画。Mosey 页只提供原生服务重启确认，GMS 页保留独立确认操作。普通 Activity 不加载 Xposed API，hook 不依赖 Activity root。

GMS 分支使用全版本统一的自动配置语义解析，针对 Nearby `45704091` 的自然 Boolean false→true；Mosey 分支只返回准确的真实 Binder，并有界恢复唯一显式禁用组件。源码不包含 Phenotype 数据库修改器，也不自动授予 `NETWORK_FACTORY`。详细机制见 [架构](../docs/architecture.md) 和 [GMS 配置](../docs/gms-configuration.md)。

界面“已声明”、原生 Running、hook 安装和实际收发是不同状态。快照展示前检查进程和安装身份，过期或缺失记录不能当作 disabled。

## 构建与来源

```sh
python3 scripts/build_client_compat.py --existing-signing
```

从项目根执行，先准备 [构建说明](../docs/build.md) 列出的固定工具、依赖与原有签名。构建缺少原身份时停止，不创建替代签名。正式/测试变体算法一致，测试变体只增加身份标记。所有输出、依赖缓存和签名留在忽略资产目录，sources ZIP 使用统一公开清单。

视觉组件改编自 [GhostLock-App](https://github.com/YuKongA/ghostlock-app) 提交 `3bd95d37e4874821d4143fc7f0fbd85fc2348ee3`，已为本项目修改。Apache-2.0 全文保留于 [third-party/GhostLock-App-Apache-2.0.txt](third-party/GhostLock-App-Apache-2.0.txt)，其余归属见 [第三方说明](../THIRD_PARTY_NOTICES.md)。

测试选择和设备验收边界见 [测试说明](../docs/testing.md)。本目录不包含 APK、依赖 JAR/SO、私钥或设备日志。
