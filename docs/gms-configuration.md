# GMS 配置与键值研究

公开版保留原创 GMS 适配代码、相关键值和研究方法。当前实现通过进程内 hook 调整一次自然读取的结果，**没有 Phenotype 数据库修改器**，不会主动写入数据库、账号或实验令牌。

## 当前配置 hook

目标为 `com.google.android.gms.nearby` 命名空间中的 `45704091`。解析器以键、配置来源、Boolean 类型和唯一 getter 为依据，校验签名谱系、实际 APK/DEX 内容与单 base 加载来源。已知版本区间只提供提醒，不能单独批准或拒绝 hook。

只有自然调用无异常、参数匹配且结果为 `Boolean.FALSE` 时，hook 才将结果改为 true。自然 true、null、错误类型和异常保持原状。`45830365` 不被修改，当前路径不安装 supplier 兜底。ART 内联、业务缓存和运行时机仍可能影响实际回调。

解析等待有界，超时后本进程跳过安装；后台完成的有效结果可供下一自然进程使用，不迟到安装或自动重启应用。schema 3 缓存身份包含 GMS 内容和 resolver compatibility ID，旧 schema 2 缓存不迁移、不覆盖、不 fallback。

管理界面的 AirDrop“已声明”表示当前 GMS 进程曾观察到该 getter 最终 Boolean true。它接受同一有效进程身份下的当前模块记录和仅模块版本不同的记录，不要求 hook 安装状态为 active。旧启动、旧进程、旧 GMS 安装和无法确认的快照不提供正向声明；该信号不证明实际收发。

## 数据库的公开研究方法

数据库检查应区分 CE 与 DE 的 Phenotype、Gservices，以及配置包、状态/partition 关联、参数记录和覆盖表。数据库中没有某个键，不等于进程返回 false；存储值还可能经过默认值、缓存、服务端配置或进程内 hook。

本项目曾为只读分析编写有界的 SQLite B-tree 页面读取方法：使用 `od` 读取必要页面，由 `awk` 解析记录并在读取端筛选目标命名空间与列，结果保存主机。该方法依赖明确的 schema 和页布局，不是通用 SQLite/WAL 读取器。公开版仅保留方法摘要，不携带设备专用查询脚本、实际参数或数据库副本。

数据完整性需要同时考虑 WAL/journal、读取期间的变化和解析边界。前后哈希相同只能增加一致性证据，不能代替应用级事务快照，也不能证明进程最终读值。数字 ID、单项真假和地区映射均不足以单独认定“AirDrop 总开关”或地区限制。

数据库写入方法属于可以公开讨论的范围，但本仓库没有现成写入实现。其他项目的补丁数据库或覆盖键不属于本项目实现，不能直接当作当前 GMS 已确认读取的配置。

## 代码与验证入口

[GmsAdaptiveResolver.java](../client-compat/src/main/java/moseyPLK/client/GmsAdaptiveResolver.java) 与相关 proof 类负责定位和语义审核，[GmsRegistryEnablement.java](../client-compat/src/main/java/moseyPLK/client/GmsRegistryEnablement.java) 限制允许改值的结果。合成夹具和 [DexKit 主机工具](../research/dexkit-probe/README.md) 将 APK/DEX 作为数据解析，不执行其中业务类。

真实 APK、完整解析报告、数据库和运行日志需要使用者自行保留在忽略资产目录。主机语义批准、hook 安装、自然回调、GMS 绑定、发现和完成传输分别验证。
