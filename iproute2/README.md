# iproute2 扩展

[English](README.en.md) | **简体中文**

仓库中的 `bin/ip` 基于 iproute2 7.1.0，当前是 x86-64 动态链接二进制。其他架构、
不兼容的 C library 环境或需要自行审计工具链时，应重新构建 iproute2 扩展。

将 `iplink_dtun.c` 复制到 iproute2 源码树的 `ip/` 目录，把 `iplink_dtun.o` 加入
其 `IPOBJ` 列表，并将本仓库的 `include/` 加入编译器头文件搜索路径
（例如 `-I/path/to/dtun/include`），然后按该版本 iproute2 的构建流程重新编译。
`iplink_dtun.c` 与内核模块共用 `include/dtun/uapi.h`。完成后可执行：

```sh
ip link add dtun0 type dtun local 192.0.2.10 udp_port 49000 node_id 1 \
  hub 192.0.2.1 hub_port 49000
```

`local`、`udp_port` 和 `node_id` 是必填项；`hub`、`hub_port` 可选，未提供
`hub_port` 时内核使用本地 `udp_port`；探测和超时参数省略时使用 1000/3000 ms。
模块没有复用现有隧道类型的 link 属性，
因此未经修改的 iproute2 无法编码 dtun 的链路配置。
