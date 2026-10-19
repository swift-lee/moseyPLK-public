# 模块公共辅助脚本

本目录保留原创安装入口、公共函数、启动检查、诊断与卸载辅助脚本，供 [注册变体](../experiments/registration-compat/README.md)、[加载变体](../experiments/load-probe/README.md) 和主机夹具复用。

旧基线的服务脚本、策略文件和从厂商配置生成的兼容脚本不属于公开源码输入，`scripts/build_module.py` 在公开树中明确停止旧基线打包。目录中的历史模块元数据不能代替根目录共同版本，也不能直接压缩成完整安装包。

当前变体从忽略资产目录读取本地限定策略和生成的兼容检查，另需匹配供体与参考 launcher。输入位置及生成方法见 [构建说明](../docs/build.md)。所有 sources ZIP 只包含公开清单中的文件。

模块脚本安装后的运行行为会写入状态或启动进程。助手只读检查不得手动调用 service、Action 或控制入口；见 [工作流程](../docs/workflow.md)。
