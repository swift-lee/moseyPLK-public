# moseyPLK

一加 15 国行 PLK110 / Android 16 / ARM64 的 Mosey、Quick Share 兼容研究工程。本仓库公开客户端、管理界面、服务脚本、原生兼容层和主机研究工具的源码，版本为 **0.6.7 / code 20**，统一读取 [release.json](release.json)。

公开版采用 [Apache-2.0](LICENSE)。第三方来源、修改说明和独立许可见 [NOTICE](NOTICE) 与 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。Google、OnePlus 等名称用于说明兼容目标。

## 仓库内容

| 目录 | 内容 |
| --- | --- |
| [client-compat](client-compat/README.md) | LSPosed hook、Compose/Miuix 管理界面、状态与控制逻辑 |
| [experiments/registration-compat](experiments/registration-compat/README.md) | 原生服务的启动检查、注册编排、状态观察与受限控制 |
| [native](native/registration-compat/README.md) | 进程内 Binder 注册兼容、加载探针和 pidfd 控制辅助程序 |
| [module-src](module-src/README.md) | 公开的安装与检查辅助脚本 |
| [research](research/README.md) | DEX 定位、合成夹具和离线分析源码 |
| [scripts](scripts/BUILD.md) | 构建、提取、归档、主机验证和只读采集入口 |

固件、Google/厂商 APK、ELF、参考 launcher、厂商配置原件、数据库、设备日志、工具链二进制和签名身份均需由使用者在本地另行准备，不随仓库提供。统一工作目录为被 Git 忽略的 `moseyPLK-assets/`，路径定义见 [project_paths.py](scripts/project_paths.py)。

这是源码发布。注册包与加载探针包依赖外部供体、参考 launcher、配置和工具；客户端构建始终要求原有签名身份，缺失时停止，不生成替代身份。公开树不支持旧基线模块打包。完整要求见 [构建说明](docs/build.md)。

## 阅读与验证

- [文档导航](docs/README.md)：架构、GMS 配置机制与开发流程。
- [公开范围](docs/publication.md)：文件清单、外部资产和归档边界。
- [测试说明](docs/testing.md)：无需私有资产的主机检查与外部输入回归。
- [本次验证记录](docs/verification.md)：实际运行结果及验证局限。

在仓库根目录运行主机检查：

```sh
python3 scripts/check_host.py
python3 scripts/check_harness.py
git diff --check
```

检查需要本机 Python、JDK、C 编译器等工具，详细依赖见测试说明。默认检查不会连接手机。源码、主机夹具或构建通过不能证明特定手机上的 hook、绑定、无线发现或文件收发可用。
