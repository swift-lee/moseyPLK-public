# 进程内注册兼容

本目录包含原创 C 兼容层、进程身份校验与 Linux 主机夹具。Android 构建由 [注册构建器](../../scripts/build_registration.py) 使用 NDK 完成，不直接打包系统 libbinder。

兼容层只在准确的供体进程中处理精确服务名、本地 Binder 和准确描述符。它解析并核验平台 API 与来源，在目标第一次发布前调用 `AIBinder_forceDowngradeToSystemStability`，随后调用真实 `AServiceManager_addService`，保留实际错误与返回值。其他服务及非目标进程走透传路径。

作用范围还要求 executable、UID/GID/组、能力、SELinux 域和进程生命周期符合预期。空对象、远端 Binder、缺失/错误符号或错误身份会拒绝目标兼容。该机制只改变目标 Binder 实例的稳定性要求，不更新系统 VINTF 声明，不构建同名替身服务。

## 主机测试

```sh
python3 native/registration-compat/test_host.py
```

从根目录运行，需 Linux C 编译器、动态链接器和 `readelf`。测试在临时目录编译带版本符号的假 Binder 与进程夹具，检查拦截、透传、失败和身份边界，不执行 Android 供体，也不连接手机。

ARM64 构建依赖与原生服务控制关系见 [构建说明](../../docs/build.md)、[架构](../../docs/architecture.md)。主机结果不能替代 Android linker、真实注册、接口事务和回调验收。
