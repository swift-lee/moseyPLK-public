# 第三方来源与许可

原创项目代码与本文档采用 [Apache-2.0](LICENSE)。这一声明不替代第三方组件的原有许可，也不授予源码树以外的厂商资源的再分发权。

| 随源码保留的部分 | 来源 | 许可与处理 |
| --- | --- | --- |
| 客户端 UI 改编 | [GhostLock-App](https://github.com/YuKongA/ghostlock-app/tree/3bd95d37e4874821d4143fc7f0fbd85fc2348ee3) | Apache-2.0；已为本项目修改，保留来源与许可全文 |
| 客户端 UI 示例改编 | [compose-miuix 示例](https://github.com/compose-miuix-ui/miuix/tree/5c91d5e5ce1a2fc7e8bdc1258a881c555102bbca) | Apache-2.0；Copyright 2025, compose-miuix-ui contributors；已修改 |
| 通用 OTA schema 及生成的 Python 模块 | [payload-dumper-go 中的 schema](https://github.com/ssut/payload-dumper-go/blob/05fe59e21c9f271fba38398c7c040993313ecd04/update_metadata.proto) | Apache-2.0；Copyright (C) 2010 The Android Open Source Project；保留原 schema 版权头；规范尾随空白并补来源注释，消息定义不变 |

Miuix 的构建依赖版本为 0.9.3；上表提交指实际参考的示例源码，二者分别记录。GhostLock 的参考仅涉及 UI，仓库不包含其内核提权实现或二进制。归属摘要见 [NOTICE](NOTICE)，原有 [UI 许可文本](client-compat/third-party/GhostLock-App-Apache-2.0.txt) 继续保留。

[OTA schema](research/scripts/update_metadata.proto) 所用上游原始输入的 SHA-256 为 `11b94f469c3ab3e7093ab26e39277d481d19351bce3e430553e3ffb44a263f05`。其生成模块嵌入的是通用消息描述，不是固件载荷。上游 AOSP 的 [schema 来源](https://android.googlesource.com/platform/system/update_engine/+/refs/heads/main/update_metadata.proto) 可用于查阅接口背景；本仓库固定输入以上表提交为准。

## 只引用、没有随源码树分发的依赖

Gradle 锁、校验元数据及构建脚本引用 Android SDK/NDK、JDK、Xposed API、DexKit、FlatBuffers、Kotlin、AndroidX/Compose、Miuix、libsu、JUnit、JSON 和 protobuf 等依赖。源码树保存版本、来源和校验信息，不保存这些依赖的 JAR、AAR、SO 或工具程序。各依赖继续适用其自身许可；项目的 Apache-2.0 声明不覆盖这些依赖。

构建脚本已有 DexKit Java/Core 许可检查和 APK 内许可材料打包逻辑。自行构建或分发成品时，应沿用该逻辑并核对实际依赖。0.7.0 Release 的安装产物独立于源码集合，其依赖继续适用各自许可；服务 ZIP 含外部 OxygenOS 供体和原 Fold6 launcher，本项目 Apache-2.0 声明不授予这些外部载荷的许可。

## 未纳入的参考内容

Google/一加固件组件、Fold6 launcher、参考策略、原厂配置、反编译原文和设备证据不随源码提供。涉及其接口的名称、文件路径和公开校验摘要仅用作本地输入识别，不能据此认定获得了对应资源的分发许可。具体取舍见 [公开范围](docs/publication.md)。
