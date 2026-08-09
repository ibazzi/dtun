# dtun

dtun 支持可选的多 Hub 高可用模式：备 Hub通过一次性 Invite ID在线加入，一主一备
使用 direct-pair 自适应快速接管，三个及以上 Hub使用加权多数派选主。Spoke会动态
学习 Hub列表并在活动 Hub离线后切换。部署步骤见 [docs/guide.md](docs/guide.md)。

[English](README.en.md) | **简体中文**

`dtun` 是面向 Linux 6.6 及更高版本的树外 L3 隧道原型。数据帧可以直接承载于
Raw IPv4 协议 253，也可以承载于 UDP；两种承载使用同一套会话 ID、HMAC 和防重放
格式。C 守护进程 `dtund` 提供 Hub/Spoke 注册、地址分配和直连信息同步。

> [!WARNING]
> 本项目不是生产级 VPN。它只认证载荷，不加密载荷；所有节点共享同一个 PSK，
> 不能提供节点间的身份隔离。不要在不可信网络中传输敏感数据。

## 当前能力

- 内层 IPv4 单播按最长前缀选择 peer；组播复制到所有 peer。默认 MTU 为 1200。
- Raw IP 为首选路径；Raw 不可用时使用已配置的 UDP 端点。
- 有效 UDP 帧通过 HMAC 后可以更新 NAT 映射得到的来源 `IP:port`。
- DTRG 控制面支持轻量 REFRESH、候选代次、分页同步、Hub 状态持久化和 spoke 间 `/32` 直连同步。
- Spoke 直连使用低频状态心跳；Raw 主用时会双向学习备用 UDP 的 NAT 安全周期，认证 UDP 来源变化会重置学习并重新验证 Raw。
- `dtunctl peer list` 自动列出所有 dtun 接口的 peer；peer 命令使用
  `--ifname NAME`并支持 `--format json`。
- Raw 和 UDP 外层发送均进入 IPv4 local-output/netfilter 路径。

当前版本实际上只支持 IPv4 端到端转发，不提供加密、密钥轮换、在线配置重载或
通用的 spoke 间外层 relay。完整边界见[设计参考](docs/dtun-design.md)。

## 项目组成

| 组件 | 用途 |
| --- | --- |
| `dtun.ko` | 内核数据面和 Netlink 接口 |
| `bin/dtund` | Hub/Spoke 控制面守护进程 |
| `bin/dtunctl` | peer、前缀和状态查询 CLI |
| `bin/ip` | 带 dtun link 扩展的预编译 iproute2 工具 |
| `samples/` | Hub 和 Spoke 配置样例 |
| `tests/` | C 单元测试与特权 network namespace 回归 |

`bin/ip` 当前是 x86-64 动态链接二进制。其他架构或不兼容的用户态环境需要按照
[iproute2 扩展说明](iproute2/README.md)重新构建。

## 快速开始

构建需要当前内核对应的 headers/build tree、C 工具链和 OpenSSL libcrypto 开发包：

```sh
make KDIR=/lib/modules/$(uname -r)/build
sudo insmod ./build/dtun.ko
```

如只需编译内核模块，也可以直接执行 `make -C module KDIR=/lib/modules/$(uname -r)/build`；
模块仍输出到 `build/dtun.ko`。

在 Debian/Ubuntu 上也可以构建 DKMS 安装包。安装包不携带打包机编译出的
`dtun.ko`，而是在目标服务器安装时针对当前内核编译：

```sh
make deb
sudo apt install ./build/dtun_*.deb
sudo modprobe dtun
```

目标服务器需要安装与当前内核匹配的 headers；内核升级后，DKMS 会自动重新构建模块。

为 Hub 和 Spoke 分发同一个 32 字节随机 PSK，并限制配置文件权限：

```sh
openssl rand -hex 32
chmod 600 /etc/dtun/*.conf
```

根据 [Hub 样例](samples/dtun-hub.conf)和
[Spoke 样例](samples/dtun-spoke.conf)填写不同主机上的配置，然后分别启动：

```sh
sudo ./bin/dtund -c /etc/dtun/hub.conf
sudo ./bin/dtund -c /etc/dtun/spoke.conf
```

公网或主机防火墙至少需要允许 Hub 的 UDP 注册端口（默认 49001）和数据端口
（默认 49000）。需要 Raw 路径时还要允许双向 IPv4 协议 253；普通 NAT 通常无法
转发该协议。完整配置、转发和运行方式见[部署指南](docs/guide.md)。

## 验证

```sh
make check          # C 单元测试与脚本语法检查，不需要 root
make test           # 双 namespace 数据面回归，需要 root
make p2mp-test      # Hub + 双 Spoke 直连回归，需要 root
sudo bash tests/cdaemon/run-all.sh
tests/ha-real/run.sh root@<PRIMARY_IP> root@<BACKUP1_IP> root@<BACKUP2_IP>
```

特权套件还需要 Python 3、`ping`、`iptables`、`tc`、`tcpdump` 和 `iperf3`。如需针对
多个内核构建树验证编译兼容性：

```sh
make compat-build KDIRS="/lib/modules/6.6.*/build /lib/modules/$(uname -r)/build"
```

项目不保存阶段性测试报告；以当前源码执行上述命令所得结果为准。
