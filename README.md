# moseyPLK

一加 15 国行 PLK110 / Android 16 / ARM64 的 Mosey、Quick Share 兼容研究工程。本仓库公开客户端、管理界面、服务脚本、原生兼容层和主机研究工具的源码，版本为 **0.7.0 / code 21**，统一读取 [release.json](release.json)。

本项目原创源码采用 [Apache-2.0](LICENSE)。第三方来源、修改说明和独立许可见 [NOTICE](NOTICE) 与 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。Google、OnePlus 等名称用于说明兼容目标。

## 仓库内容

| 目录 | 内容 |
| --- | --- |
| [client-compat](client-compat/README.md) | LSPosed hook、Compose/Miuix 管理界面、状态与控制逻辑 |
| [experiments/registration-compat](experiments/registration-compat/README.md) | 原生服务的启动检查、注册编排、状态观察与受限控制 |
| [native](native/registration-compat/README.md) | 进程内 Binder 注册兼容、加载探针和 pidfd 控制辅助程序 |
| [module-src](module-src/README.md) | 公开的安装与检查辅助脚本 |
| [research](research/README.md) | DEX 定位、合成夹具和离线分析源码 |
| [scripts](scripts/BUILD.md) | 构建、提取、归档、主机验证和只读采集入口 |

固件、Google/厂商 APK、ELF、参考 launcher、厂商配置原件、数据库、设备日志、工具链二进制和签名身份均不进入源码树或源码归档；本地构建所需输入由使用者另行准备。统一工作目录为被 Git 忽略的 `moseyPLK-assets/`，路径定义见 [project_paths.py](scripts/project_paths.py)。

源码树中的注册包与加载探针包构建入口依赖外部供体、参考 launcher、配置和工具；客户端构建始终要求原有签名身份，缺失时停止，不生成替代身份。公开树不支持旧基线模块打包。完整要求见 [构建说明](docs/build.md)。

## 0.7.0 安装产物

`v0.7.0` Release 的安装交付为 `moseyPLK.client-v0.7.0.apk`、`moseyPLK.service-v0.7.0.zip` 及对应 SHA-256。客户端与服务共用 0.7.0 / code 21；正式 APK 沿用原有签名身份，服务 ZIP 的安装器仅接受 KernelSU。GitHub 仓库保持现有 private 可见性。

服务 ZIP 包含外部 OxygenOS 供体及原 Fold6 launcher；这些安装载荷不属于公开源码集合，本项目的 Apache-2.0 声明不授予其许可。源码 tag 对应经审查的文本集合，本地重建仍需准备外部输入和原签名。

本次版本推进不新增运行时功能。构建 provenance 保留 `device_tested=false`；本轮未由助手安装或操作手机，主机检查不代表 0.7.0 的 hook、发现或收发已获实机验收。实际构建与校验结果见 [验证记录](docs/verification.md)。

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
