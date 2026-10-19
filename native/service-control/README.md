# 原生控制辅助程序

`control.c` 为固定服务控制协议提供受限的原生操作。停止前读取私有所有权记录，复核启动、PID/starttime、executable、身份、能力和载荷，取得 pidfd 后再次检查，只向匹配实例发送 SIGTERM。

辅助程序拒绝不支持的操作、错误调用者、失效记录及身份变化，不退回按进程名批量终止。启动与等待具有固定目标和时间预算，交互入口由 [注册控制脚本](../../experiments/registration-compat/README.md) 串行化。

主机检查为：

```sh
python3 scripts/test_service_control.py
```

测试只控制其自身创建的主机子进程。Android 程序通过注册构建器使用 NDK 生成，不随源码仓库提供二进制；真实 root、SELinux 与内核 pidfd 行为仍需独立验收。
