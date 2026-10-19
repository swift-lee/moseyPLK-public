# 原生加载与身份探针

`probe.c` 读取进程身份与生命周期，`marker.c` 提供预加载观察标记，`probe_parse.c` 与头文件提供共享的严格结果解析。源码由项目自行实现，不包含供体二进制或厂商反编译正文。

探针输出用于检查 executable、PID/starttime、UID/GID/组、能力、SELinux 域及加载来源。成功需要完整且唯一的结果字段，进程存在或构造函数输出本身不足以判定通过。

```sh
python3 native/load-probe/test_host.py
```

从项目根执行，需 Linux C 编译器。主机测试编译临时夹具验证解析和加载边界；Android ARM64 版本由 [加载构建器](../../scripts/build_load_probe.py) 与 [注册构建器](../../scripts/build_registration.py) 使用 NDK 生成到忽略资产目录。

集成脚本见 [加载变体](../../experiments/load-probe/README.md)，完整前置条件见 [构建说明](../../docs/build.md)。探针的运行会创建进程或输出诊断状态，助手手机只读任务不调用该实验入口。
