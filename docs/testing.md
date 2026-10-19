# 测试与验收

测试分为不需要私有资产的主机检查，以及需要使用者额外提供输入的构建与回归。默认流程不连接手机，不下载固件，也不安装或启停应用。

## 默认主机检查

从根目录运行：

```sh
python3 scripts/check_host.py
python3 scripts/check_harness.py
git diff --check
```

需要 Python 3.11+、可用的 JDK、Linux C 编译器及 `readelf` 等主机工具。ShellCheck 和 BusyBox 对应额外的 shell 检查；具体可用性及实际环境见 [验证记录](verification.md)。不使用 `python -O`。

主机 runner 按顺序运行公开边界和构建输入检查、提取器临时夹具、状态/控制/注册与加载工作流、采集器假命令、hook-state、observer 和两套原生测试。串行执行用于减少有时限夹具之间的负载干扰。所有进程与命令模拟限于主机临时夹具，原生 pidfd 测试只控制测试自身创建的进程。

可用 `check_host.py --busybox PATH` 增加 BusyBox ash 兼容检查，使用 `--logs-dir PATH` 选择新的主机报告目录。前置工具缺失时先补齐主机环境，不自动改用手机工具。

文档变更只需链接与差异检查。相关模块可单独验证，例如：

```sh
python3 scripts/test_module_status.py
python3 scripts/test_service_control.py
python3 scripts/test_hook_state.py
python3 scripts/test_gms_observer.py
python3 scripts/test_gms_startup_collector.py
python3 native/load-probe/test_host.py
python3 native/registration-compat/test_host.py
```

不要用全目录 unittest discovery 代替默认 runner：保留的专项测试包含需要真实 APK、生成 DEX、安装包或旧产物的分支。缺少输入导致的失败/跳过须明确报告。

## 外部输入回归

| 范围 | 前置条件与入口 |
| --- | --- |
| 客户端 UI/JVM 与安装包 | 固定工具、依赖、原签名；按 [构建说明](build.md) 构建，再运行 `scripts/test_client_package.py` |
| GMS DEX 与 resolver | 自行准备合法取得的真实 APK、固定 DexKit/D8 工具和生成夹具；入口为 `test_gms_dex.py`、`test_gms_resolver.py` |
| GMS adaptive runtime | 对应 APK/公共证书和 apksigner 输入；入口为 `test_gms_adaptive.py` |
| KSU 安装包 | 配套供体、launcher、本地策略、生成配置和已构建 ZIP；入口为 `test_registration_package.py`、`test_load_probe.py` |
| DexKit 查询研究 | DexKit 主机 JNI/JAR、D8 与合成 DEX；见 [原型说明](../research/dexkit-probe/README.md) |

旧产物对照和固定哈希样本是独立的历史回归输入，公开树不提供它们。保留的专项测试可能还要求与其预期一致的本地布局；先读代码的输入定义，不自动获取设备文件或伪造通过结果。

安装包检查不会自动触发构建。客户端包、注册包或 DexKit 工具缺失时，对应专项用例可明确跳过；GMS adaptive/resolver 缺少必要 APK 或签名工具时会给出错误。跳过的用例不能记作通过。

## 手机验收

主机模拟不能验证 Android ART、真实 ClassLoader、root profile、SELinux、挂载视图、UI 触控或无线传输。手机上的安装、授权和必要状态变更由用户完成；助手继续遵守 [只读流程](workflow.md)。

验收逐层关联同一启动、用户、版本及进程身份：载荷视图、系统应用身份、原生 Binder、hook 安装、自然 getter、GMS 绑定、双向发现和文件实际完成。对可导出文件可比较哈希；中断或取消不算完成。

报告只写本轮实际检查及限制。当前公开准备的结果由 [验证记录](verification.md) 单独维护，不从旧文档复制测试数字或手机成功结论。
