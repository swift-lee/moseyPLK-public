# Resolver 合成夹具

本目录保存项目自行编写的 Java 模板与案例清单，用来生成用于解析的 DEX。模板表达配置工厂、getter、缓存与调用关系，不包含从 Google APK 提取的 DEX、反编译方法或真实数据库记录。

[cases.json](cases.json) 定义预期接受和拒绝的形态，包括整体改名、类型/来源变化、重复 namespace/key、错误返回值、副作用、索引/容量不一致及无关下游变化。`scripts/gms_resolver_fixtures.py` 将模板生成到忽略资产目录，再由固定 D8 工具编译。

夹具预期只用于断言，不作为生产查询的候选答案输入。测试只解析生成的 DEX，不执行夹具业务类。运行 `scripts/test_gms_resolver.py` 还可能要求额外真实 APK 矩阵与工具，前置条件见 [测试说明](../../../docs/testing.md)。
