# 主机构建

构建只操作主机。公开仓库不包含完成 APK 或 KSU ZIP 所需的全部资产；输入缺失或完整性不符时应停止，不替换成空文件或其他版本。

## 本地工作目录

路径统一来自 [project_paths.py](../scripts/project_paths.py)。`moseyPLK-assets/` 整体忽略，包含自行准备的工具、供体、签名和输出。

| 输入 | 用途与位置 |
| --- | --- |
| Python 3.11+、系统主机工具 | 构建编排和检查；不要使用 Python 优化模式绕过现有完整性断言 |
| 固定 Android/JDK/Gradle 工具 | 客户端工具定义在 [client_gradle.py](../scripts/client_gradle.py)、[client_dexkit.py](../scripts/client_dexkit.py) 及构建器中，二进制放 `moseyPLK-assets/tools/` |
| Android NDK | 编译 ARM64 探针、注册兼容和控制辅助程序；构建器支持 `--ndk` |
| 自行取得的 OOS/COS/参考包 | 通过提取入口按白名单准备本地供体与检查输入；不自动下载固件 |
| 原策略文件 | `moseyPLK-assets/restricted-inputs/sepolicy.rule`，须匹配构建器的固定哈希 |
| 生成的兼容检查 | `moseyPLK-assets/build/generated/compatibility.sh`，由本地 COS 配置生成 |
| 已有客户端签名 | 默认 `moseyPLK-assets/signing/client-compat/`；也可用 `--signing-dir` 指定仓库外目录 |

构建前阅读脚本中固定版本、来源和哈希。依赖锁与校验元数据在源码中，工具和依赖缓存不进入公开归档。平台与第三方工具的获取和使用遵循各自条款。

## 客户端

首次准备固定 UI 工具需要显式联网：

```sh
python3 scripts/client_gradle.py --fetch
```

另行准备构建器要求的 Android/Xposed/DexKit 输入和既有签名后，默认使用离线构建：

```sh
python3 scripts/build_client_compat.py --existing-signing
```

`--online` 只在明确需要下载依赖时使用；`--refresh-locks` 只用于主动更新并审阅依赖锁与校验差异。可选 `--proxy` 接受使用者自己的无凭据代理 URL，文档不预设本机地址。

签名目录须包含构建器要求的原 PKCS#12 身份及配套密码文件，并通过已发布证书检查。密码不进入命令参数、日志或源码归档。缺失、无法解锁或证书不符时停止；公开版不创建替代签名。`--adaptive-test` 只改变变体标记，与正式包采用同一自动解析算法。

客户端目标为 API 36 / ARM64，compile SDK 与工具链细节以 Gradle 配置和固定工具定义为准。Xposed API 仅用于编译，不打入产品 APK。

## 注册与加载探针包

先准备提取器要求的本地原件，已有输入可只检查：

```sh
python3 scripts/extract_firmware.py --check-only --coloros
```

需要首次提取时，先阅读 `extract_firmware.py --help`，提供匹配的本地 ZIP 和提取工具。该入口读取主机原件并将白名单文件写入忽略资产目录，不操作手机。

使用本地 COS 配置生成检查脚本，另行准备符合固定哈希的策略输入，再构建：

```sh
python3 scripts/generate_compatibility.py
python3 scripts/build_registration.py
python3 scripts/build_load_probe.py
```

生成器默认输出到忽略的 build 目录；`--output` 也只允许资产目录内的安全路径。注册与加载包在准备载荷前检查上述输入，然后核对 NDK、供体和参考 launcher。它们不会从公开源码虚构厂商文件。

`build_module.py` 的旧基线打包在公开树中明确不受支持。`module-src/` 中保留的公共辅助脚本供当前变体和主机测试复用。

## 输出与归档

产物写入 `moseyPLK-assets/dist/`，中间文件写入 `moseyPLK-assets/build/`。所有 sources ZIP 使用 [publication-files.json](../publication-files.json) 的同一审查清单，排除外部输入、生成配置、签名、日志和二进制。

历史产物和真实 APK 矩阵属于额外回归输入，不随源码发布。实际可运行的主机检查见 [测试说明](testing.md)。构建元数据中的 `device_tested=false` 保留为构建侧边界。
