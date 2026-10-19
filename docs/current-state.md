# 当前源码状态

公开源码为 **0.7.0 / versionCode 21**，客户端 ID 为 `moseyPLK.client`，服务模块 ID 为 `moseyPLK.service`。版本由根目录 [release.json](../release.json) 统一提供。

本次版本推进同步客户端、服务和公开源码标识，不新增运行时功能。原 0.6.7 公开整理的验证记录保留为历史，本轮实际检查另行记录。

## 已实现的能力

- 客户端包含 Compose/Miuix 管理界面、按需 root、分层状态、受限服务控制和 GMS 的独立确认操作。
- GMS 使用 rule 3 的自动 Phenotype getter 定位，验证配置来源、类型和唯一性，采用有界等待与 schema 3 内容缓存。目标键为 Nearby `45704091`；其他键的观察与历史规则保留在源码和测试中。
- AirDrop“已声明”表示当前 GMS 进程观察到目标 getter 最终返回 true；它不参与顶部总状态，也不能证明绑定、发现或文件传输。
- Mosey 分支返回校验后的真实 Binder，并通过目标应用自身 Context 有界恢复一个显式禁用的组件。
- 原生源码提供窄范围的 Binder 注册兼容、身份/加载探针、pidfd 控制以及启动、状态与锁定脚本。

## 公开交付边界

公开源码树及源码归档保留自有实现和合成测试，排除供体、参考 launcher、厂商配置原件、签名、数据库或设备日志。旧基线模块打包不受支持；注册与加载探针构建仍需外部输入。客户端缺少原签名时停止构建。

0.7.0 Release 安装交付为同版正式 APK、KernelSU 服务 ZIP 及对应 SHA-256，仓库保持 private。APK 沿用原签名；服务安装 ZIP 包含外部 OxygenOS 供体和原 Fold6 launcher，本项目 Apache-2.0 声明不授予这些外部资源的许可。GitHub tag 的源码附件来自本树的已审查文本集合，外部输入与签名仍由本地另行准备。

构建 provenance 保持 `device_tested=false`。本轮未由助手安装或操作手机，未取得 0.7.0 的实机 hook、绑定、发现或完成收发验收。

当前实现没有 Phenotype 数据库修改器，也不自动授予 `NETWORK_FACTORY`。可公开的键值与数据库分析方法见 [GMS 配置](gms-configuration.md)。

这页描述源码，不宣称已在某台手机安装或验证。实际主机检查见 [验证记录](verification.md)，手机验证条件见 [测试说明](testing.md)。
