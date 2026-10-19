# DexKit 主机研究工具

本目录将自行提供的 APK 或 DEX ZIP 作为数据进行离线定位，不加载其中业务类，不调用 ADB。`GmsDexProbe.java` 产生候选与关系摘要，Python 分析器检查报告与允许表达式，合成源模板覆盖改名、歧义、不同表达式和副作用。

候选检索、图可达性和 opcode 相似只能提供局部证据。生产 hook 还需独立验证配置来源、类型、唯一性、签名、实际加载器及运行时机，不能取第一个匹配直接启用。

## 输入与命令

需要自行准备 DexKit 2.2.0 主机 JNI/JAR、相应依赖、JDK 和用于合成夹具的 Android D8/platform 工具。工具放 `moseyPLK-assets/tools/`，运行器核对本地 provenance 与哈希；这些工具和完整报告不进入 Git。

从项目根列出或生成合成案例：

```sh
python3 research/dexkit-probe/fixtures.py --list
python3 research/dexkit-probe/fixtures.py
```

生成器会更新其忽略 build 目录中的夹具，需要保留旧结果时先在本地另存。修改 Java 查询后使用 `run_probe.py --compile` 重新编译；完整参数由 `run_probe.py --help` 提供。输入使用 `--apk`，输出用 `--output` 指向资产目录内尚不存在的新 JSON。

`analyze_apkm.py --input-dir ... --output-dir ...` 需要本地 APKM 和新资产输出目录，检查归档、base 身份与生产 resolver 结果。`ApkSigningAudit.java` 输出已验证的公共签名与轮换谱系，不涉及模块私钥。

## 测试边界

- `test_supplier_semantics.py` 使用纯主机样本，不需真实 APK。
- `test_fixture_discovery.py` 与 `test_report_analysis.py` 需要已生成的合成 DEX、查询报告和对应工具。
- 真实 GMS 输入、工具的获取授权及来源由使用者负责；缺失输入应报告，不自动下载或连接手机。

所有输出留在忽略资产目录。更多测试选择见 [测试说明](../../docs/testing.md)，当前生产配置行为见 [GMS 配置](../../docs/gms-configuration.md)。
