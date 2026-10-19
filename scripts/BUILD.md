# 构建与检查入口

所有命令从项目根运行，只操作主机。完整输入准备、签名和生成路径见 [构建说明](../docs/build.md)，默认无私有资产检查见 [测试说明](../docs/testing.md)。

| 入口 | 前置条件 |
| --- | --- |
| `python3 scripts/check_host.py` | Python、JDK、Linux C 工具；不运行真实 APK 或旧产物矩阵 |
| `python3 scripts/check_harness.py` | 公开文档与本地链接检查 |
| `python3 scripts/extract_firmware.py --check-only --coloros` | 已准备的本地供体、参考文件及 COS 配置 |
| `python3 scripts/generate_compatibility.py` | 本地 COS 配置；输出到忽略的 generated 目录 |
| `python3 scripts/build_registration.py` | 生成兼容检查、本地限定策略、供体、launcher、NDK |
| `python3 scripts/build_load_probe.py` | 同上，用于独立加载探针包 |
| `python3 scripts/build_client_compat.py --existing-signing` | 固定 Android/JDK/Gradle/Xposed/DexKit 输入、依赖缓存、原有签名 |

`build_module.py` 的旧基线打包在公开树中停止。客户端始终要求既有身份，不生成替代签名；联网工具准备和依赖刷新均需显式参数。

项目、资产、build 与 dist 路径统一由 [project_paths.py](project_paths.py) 定义。源码 ZIP 只包含 [publication-files.json](../publication-files.json) 审查清单中的文件，厂商配置、二进制、生成物、密钥和日志不进入归档。实际运行结果见 [验证记录](../docs/verification.md)。
