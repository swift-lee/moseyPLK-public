# 研究源码

公开研究目录只保存原创脚本、合成模板、测试 stub 和方法说明。真实 APK/DEX、固件、提取物、第三方工具、设备日志和完整分析报告保存在使用者自己的忽略资产目录，不随仓库提供。

| 目录 | 用途 |
| --- | --- |
| [dexkit-probe](dexkit-probe/README.md) | 将 APK/DEX 作为数据做候选定位、局部表达式检查和 APKM 分析 |
| `gms-adaptive-tests/` | 生产 GMS 核心/runtime 的主机测试与 Android/Xposed stub |
| `scripts/` | 主机固件比较、提取所用 protobuf 描述，以及需审阅后使用的早期只读采集脚本 |

研究报告的候选、语义批准、签名身份、实际 hook 和文件收发分别对应不同结论。合成样本不能证明所有未来 GMS 版本受支持；真实 APK 分析也不自动证明其 Android 行为。

数据库的公开方法摘要见 [GMS 配置](../docs/gms-configuration.md)，构建与测试入口见 [构建](../docs/build.md)、[测试](../docs/testing.md)。第三方生成代码的来源和许可见 [第三方说明](../THIRD_PARTY_NOTICES.md)。
