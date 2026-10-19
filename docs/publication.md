# 公开范围与维护方式

本目录是经逐文件整理的公开源码集合。源码发布集合由 [publication-files.json](../publication-files.json) 明确列出；所有构建器的源码归档均从这份清单取得文件，不遍历本地资产或追加供体原件。

## 保留与排除

保留项目自有的 Compose 管理 UI、Hook、GMS 自动解析器、原生兼容层、活动注册/控制/状态脚本、主机工具与合成测试夹具。依赖坐标、版本、公开接口名称及输入哈希可以保留。合成 Android/Xposed stub 只用于主机测试，不是厂商实现的副本。

源码树和源码归档明确排除固件、APK/ELF/DEX、第三方工具二进制、数据库、原始设备日志、密钥、密码、成品安装包、历史源码 ZIP、备份及原仓库 Git 元数据。个人主机路径的旧采集器和会在手机创建临时文件的历史采集器也未纳入。

另有三项文本输入未公开：旧基线启动脚本含来源许可未确认的参考改编；参考 SELinux 规则未确认可再分发；原兼容清单含从厂商配置逐行摘取的断言。公开源码保留自有生成器与活动服务实现，缺少外部输入时停止构建。请勿把这些文件补进公开清单，或用空文件绕过检查。

历史调查和版本交付文档已改写为面向使用者的说明，不带私人证据链接、启动标识、实机进程记录或厂商原文。GMS 键值研究和原创适配机制的公开说明见 [GMS 配置研究](gms-configuration.md)。当前代码没有数据库修改器。

## 0.7.0 Release 安装交付

0.7.0 / code 21 的安装交付范围为正式 `moseyPLK.client` APK、`moseyPLK.service` ZIP 及其 SHA-256。仓库保持现有 private 可见性；安装产物作为 Release 资产分发，不加入上述源码清单。正式 APK 沿用原有签名身份，服务 ZIP 的安装器仅接受 KernelSU。

服务 ZIP 包含七件 OxygenOS 供体和原 Fold6 launcher。项目 Apache-2.0 声明仅覆盖原创源码，不授予这些外部资源的许可；相关资源继续按其来源条款处理。源码树的排除规则与安装 ZIP 的载荷范围分别记录。

GitHub 自动生成的源码 ZIP/TAR 来自同版公开源码 tag，只包含该文本树；本地重建需要自行准备外部输入与原签名。Release 的额外附件不包含原生产树生成的源码 ZIP、构建元数据或测试变体。构建 provenance 保持 `device_tested=false`，本次主机发布不代表实机验收。

## 归档与新增文件

- 新增源码或文档时先检查来源、内容和许可，再把相对路径加入清单；清单必须排序、去重且包含自身。
- [公开检查器](../scripts/check_public.py) 拒绝未审核文件、非文本内容、受限路径、符号链接及部分凭证格式。它不会证明所有文本都具有可分发授权，仍需审阅改动。
- 默认检查允许本机忽略的工作资产和缓存存在，但不会将它们加入发布集合；`--strict` 用于检查完全不带工作资产的交付目录。
- [源码归档工具](../scripts/public_sources.py) 只接受清单中的普通 UTF-8 文件，拒绝目录越界和敏感文件类型。生成的源码 ZIP 不附带构建期间生成的配置、签名、依赖或二进制。

在发布或推送前运行：

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/check_public.py --strict
PYTHONDONTWRITEBYTECODE=1 python3 scripts/check_harness.py
git diff --check
git diff --cached --check
```

已加入清单的文本内容变更仍需人工审阅。实际检查结果及未验证范围见 [本次验证](verification.md)。
