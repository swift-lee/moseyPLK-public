# 加载与身份探针

这个独立实验变体用于检查准确原生身份、载荷和预加载环境。脚本与 [原生探针](../../native/load-probe/README.md) 配合，检查真实 executable、进程生命周期、UID/GID/组、能力、SELinux 域与加载标记，并保留有界结果。

变体只运行探针，不启动真实供体业务。service 和 Action 入口仍会执行程序并写诊断状态，不能当作只读采集命令；用户安装后的运行行为与助手的手机只读边界分别处理。

从项目根执行构建：

```sh
python3 scripts/generate_compatibility.py
python3 scripts/build_load_probe.py
```

需要自备 COS 配置、限定策略、配套供体、参考 launcher 与 NDK，详见 [构建说明](../../docs/build.md)。公开树不包含这些原件或已编译探针；源码归档只使用公开清单。

主机工作流检查属于默认 [主机 runner](../../docs/testing.md)，完整产物检查另需已构建 ZIP。主机假命令及加载夹具不能证明 Android 域转换、真实 linker 或业务调用成功。
