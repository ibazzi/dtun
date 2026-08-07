# dtun 部署与运行指南

[English](guide.en.md) | **简体中文**

本文依据当前 C daemon 和内核模块实现编写。`dtun` 是认证型 L3 隧道原型，不是
加密 VPN；部署前请先阅读[设计参考](dtun-design.md)中的限制与兼容性。

## 1. 规划与依赖

一套基本部署包含一个 Hub 和一个或多个 Spoke：

| 流量 | 默认端口/协议 | 方向 | 用途 |
| --- | --- | --- | --- |
| 注册控制面 | UDP 49001 | Spoke → Hub | DTRG 注册、REFRESH 和候选同步 |
| 数据面 | UDP 49000 | 双向 | NAT 兼容的数据承载与探测 |
| 数据面 | IPv4 协议 253 | 双向 | 优先使用的 Raw IP 承载 |

Hub 需要公网可达的控制地址。UDP 必须可用；Raw IP 253 是可选的性能路径，普通 NAT
通常不会转发它。若希望没有直连候选的 spoke 通过 Hub 的内层路由互通，还需要在
Hub 上启用 IPv4 forwarding，并允许相关 FORWARD 流量。

构建依赖：

- Linux 6.6 或更高版本，以及与目标内核匹配的 headers/build tree；
- GCC/Clang、GNU make 和 OpenSSL libcrypto 开发包；
- 运行时具备 `CAP_NET_ADMIN`，加载模块还需要 `CAP_SYS_MODULE`。

## 2. 构建与加载

```sh
make KDIR=/lib/modules/$(uname -r)/build
sudo insmod ./dtun.ko
```

在 Debian/Ubuntu 上可使用 DKMS 安装包，避免把编译机内核版本绑定进安装包：

```sh
make deb
sudo apt install ./build/dtun_*.deb
sudo modprobe dtun
```

目标机器需要安装与当前内核匹配的 headers。内核升级后，DKMS 会自动重新编译模块。

构建结果包括 `dtun.ko`、`bin/dtund` 和 `bin/dtunctl`。确认模块已加载：

```sh
lsmod | grep '^dtun'
```

仓库中的 `bin/ip` 基于 iproute2 7.1.0，当前为 x86-64 动态链接二进制。若架构或
运行库不兼容，请根据 [iproute2 扩展说明](../iproute2/README.md)自行构建，不要使用
无法编码 dtun link 属性的原版 `ip` 创建接口。

## 3. 密钥与文件权限

生成 32 字节 PSK，并安全分发给同一网络中的 Hub 和所有 Spoke：

```sh
openssl rand -hex 32
sudo install -d -m 0750 /etc/dtun /var/lib/dtun
sudo install -m 0600 samples/dtun-hub.conf /etc/dtun/hub.conf
```

配置中的 `psk` 必须是 64 个十六进制字符。省略 `psk` 时，daemon 会进入零密钥
开发模式：DTRG 使用公开可推导的全零密钥，数据 peer 不校验 HMAC。该模式只能用于
隔离测试，不能部署到真实网络。

Hub 状态文件包含持久化 cookie 密钥、节点和会话分配，应由运行用户独占访问。
daemon 会创建父目录，并通过临时文件、`fflush`、`fsync` 和原子 `rename` 保存，
但最终权限仍受进程 `umask` 和目录权限影响。

## 4. 配置参考

INI 段名用于组织配置；当前解析器按键名读取，下表中的段归属是约定用法。

### `[global]`

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `mode` | 无 | 必填，`hub` 或 `spoke`；也可由 `--mode` 覆盖 |
| `interface` | `dtun0` | daemon 创建和管理的接口名 |
| `local_outer_ip` | `0.0.0.0` | 本机外层 IPv4；为 0 时按每条外层路由自动选择源地址 |
| `data_port` | `49000` | 本地数据面 UDP 端口 |
| `probe_interval_ms` | `1000` | Raw/UDP 路径探测间隔 |
| `path_timeout_ms` | `3000` | 活跃路径失效时间；不得小于两倍探测间隔 |
| `fast_recovery` | `true` | 启用出口变化快速恢复；Spoke 必须绑定 `0.0.0.0` |
| `node_id` | `0` | Hub 必须使用 1（0 会回退为 1）；Spoke 中 0 请求临时自动分配，1 被保留 |
| `address` | `0.0.0.0/24` | 内层 IPv4/CIDR；Spoke 地址为 0 时请求池内动态分配 |
| `psk` | 无 | 32 字节 PSK 的 64 位十六进制表示；省略仅供不安全测试 |
| `raw_transport` | `true` | 设为 `false` 时禁用 Raw IPv4候选，只使用 UDP及 Hub回退；适合 Raw探测假阳性的云网络 |

### `[hub]`

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `bind_address` | `0.0.0.0` | 注册控制 socket 的监听地址 |
| `bind_port` | `49001` | 注册控制 UDP 端口 |
| `pool` | 从 Hub `address` 的网络前缀推导 | Spoke 内层地址池，当前只接受 `/0` 至 `/30`；显式配置时以 `pool` 为准 |
| `state_file` | `/var/lib/dtun/hub.state` | 带版本的二进制持久化状态 |
| `cookie_seconds` | `30` | cookie 时间桶秒数；非正数回退为 30 |
| `peer_timeout` | `60` | 最后一次成功注册后保留 Spoke 的秒数；非正数回退为 60 |
| `identity_retention` | `86400` | 离线节点地址及 tunnel/session ID 保留秒数 |

### `[spoke]`

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `hub_address` | 无 | 必填，Hub 控制面的 IPv4 地址 |
| `hub_port` | `49001` | Hub 控制端口，不是数据端口 |
| `local_port` | `0` | 注册控制 socket 的本地源端口；0 表示临时端口 |
| `interval` | `20` | 每次注册尝试后的重试/刷新间隔；非正数按 1 秒处理 |
| `refresh_interval_ms` | `1000` | 已注册会话的 DTRG 轻量刷新间隔 |
| `timeout` | `5` | 每个控制响应的接收超时；非正数回退为 5 秒 |
| `once` | `false` | 首次尝试后退出；成功时保留接口，失败时返回非零 |
| `spoke_state_file` | `/var/lib/dtun/spoke-ha.state` | 持久化动态发现的 Hub 列表、权重和最高任期 |

### `[ha]`

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `ha_config` | `/etc/dtun/ha/ha.conf` | 仅在使用非默认路径时指定生成的 HA 配置片段 |
| `ha_port` | `49001` | Hub 间认证、复制和选举TCP端口；可与Spoke控制面UDP端口复用端口号 |
| `failover_timeout` | `3` | 活动 Hub连续不可达后开始接管的秒数；回切防抖由独立稳定窗口控制 |
| `failback` | `immediate` | `immediate` 在稳定门槛后回主；`sticky` 保持当前 Hub |
| `recovery_stable_time` | `120` | 原主 Hub连续健康观察时间 |
| `min_backup_active_time` | `300` | 备 Hub接管后的最短驻留时间 |
| `failback_probation_time` | `120` | 回切后的观察期 |
| `failback_backoff` | `300,900,1800` | 连续回切失败后的稳定窗口 |
| `failback_backoff_reset_time` | `1800` | 主 Hub持续稳定后清除退避的时间 |

## 5. 部署 Hub

Hub 的实际 `node_id` 为 1。以下配置使用文档保留地址，请替换外层地址和 PSK：

```ini
[global]
mode = hub
interface = dtun0
local_outer_ip = 192.0.2.1
data_port = 49000
node_id = 1
address = 10.99.0.1/24
psk = REPLACE_WITH_64_HEX_CHARACTERS

[hub]
bind_address = 0.0.0.0
bind_port = 49001
pool = 10.99.0.0/24
state_file = /var/lib/dtun/hub.state
cookie_seconds = 30
```

地址池规则：

- Hub 内层地址必须位于池内，且不能是网络地址或广播地址；
- 网络地址、广播地址、池内第一个可用地址和 Hub 实际地址不会分配给 Spoke；
- 静态 Spoke 地址必须使用池前缀，且不能冲突；
- 同一 node ID 不能改绑到其他地址，node ID 1 仅供 Hub；
- `node_id = 0` 和 `address = 0.0.0.0/<池前缀>` 分别请求自动 ID 和自动地址；
- 最多保存 128 个 Spoke，池耗尽或达到上限时注册会被拒绝。

启动：

```sh
sudo ./bin/dtund -c /etc/dtun/hub.conf
```

状态文件缺失时会初始化；旧版无头 C 状态可自动导入，但这只属于本地状态迁移，
不提供旧控制协议兼容。文件截断、版本不支持、记录冲突或计数越界时，Hub 会拒绝
启动，不会静默清空状态。正常收到 SIGINT、SIGTERM 或 SIGHUP 时，Hub 停止并删除
自己管理的接口；SIGHUP 当前不表示重新加载配置。

## 6. 部署 Spoke

静态地址配置：

```ini
[global]
mode = spoke
interface = dtun0
local_outer_ip = 0.0.0.0
data_port = 49000
node_id = 2
address = 10.99.0.2/24
psk = REPLACE_WITH_64_HEX_CHARACTERS

[spoke]
hub_address = 192.0.2.1
hub_port = 49001
local_port = 0
interval = 20
timeout = 5
once = false
```

需要由 Hub 持久分配地址时，推荐配置一个稳定且唯一的 node ID，只把地址设为 0：

```ini
node_id = 2
address = 0.0.0.0/24
```

`node_id = 0` 也会请求自动 ID，但 Spoke 不会把结果写回配置文件；进程重启后会再次
申请新 ID。该模式只适合短期测试，长期节点必须配置稳定的非 0 node ID。

启动：

```sh
sudo ./bin/dtund -c /etc/dtun/spoke.conf
```

首次成功 ACK 后，Spoke 使用自己的 `data_port` 绑定本地接口，并使用 ACK 返回的 Hub
数据端口配置 Hub peer。常驻进程每个周期生成新 nonce 重新注册：Hub 暂时不可达时
保留已有接口、peer 和路由，恢复后自动协调。正常终止常驻进程会删除接口。

daemon 认为 `interface` 完全归自己管理；创建前会删除同名现有接口。不要让多个进程
共享同一个接口名，也不要把需保留的手工接口交给常驻 daemon。

`once = true` 适合由其他进程接管接口生命周期：第一次注册成功后 daemon 退出并
保留接口；第一次失败则退出且返回非零。

## 6.1 部署高可用 Hub

最小部署为一主一备。两节点中主 Hub超时后唯一备 Hub直接接管；三个及以上正式
Hub 使用多数派选举，权重高的同步候选优先。两节点没有外部见证，因此网络分区时
可能短暂双主，Spoke 通过持久化任期收敛。

主 Hub 初始化：

```sh
sudo dtunctl ha init --hub-id hub-primary
```

默认主配置为 `/etc/dtun/dtun.conf`，生成的 `/etc/dtun/ha/ha.conf` 会被自动加载。
使用非默认路径时才需要传入 `--config`、`--output-dir` 并在主配置中引用覆盖文件。
启动 `dtund` 后创建邀请：

```sh
sudo dtunctl ha invite create --hub-id hub-backup-1 \
  --weight 900 --expires 10m --format plain
```

主 Hub位于云 NAT 后、`local_outer_ip` 是私网地址时，只为 Invite 指定公网引导地址：

```sh
sudo dtunctl ha invite create --hub-id hub-backup-1 --weight 900 \
  --bootstrap-address 203.0.113.10 --format plain
```

该参数不公告或覆盖任何备 Hub地址；备 Hub地址仍由认证连接自动发现。

Invite ID 是短期、单次使用的入群密码。默认输出供人阅读；`--format plain`只输出
Invite ID，`--format json`输出单行结构化数据。备 Hub不需要复制邀请文件：

```sh
sudo dtunctl ha join --config /etc/dtun/dtun.conf
# 在隐藏提示中粘贴 Invite ID
```

备 Hub私钥只在本机生成。加入过程使用 Ed25519 身份、临时 X25519 密钥和 AES-GCM
加密通道下发集群隧道配置。新 Hub先作为 learner 同步，追平后成为 voter。

不配置 `advertise_address`。`local_outer_ip = 0.0.0.0` 时由系统路由选择源地址，活动
Hub 从认证连接和控制/数据探测包自动记录实际端点。不可从其他成员访问的端点不会
获得接管资格。

常用检查和管理命令：

```sh
dtunctl ha status
dtunctl ha members
dtunctl ha invite list
dtunctl ha member set-weight --hub-id hub-backup-1 --weight 950
dtunctl ha failback
```

新增地址、node ID 和 tunnel/session ID 只有同步到备机（多节点时为多数派）后才
确认。备机失联期间已有链路继续工作，但不会确认新的持久分配。

## 7. 直连、Hub 转发与回退

Spoke 始终安装指向 Hub peer 的地址池路由。Hub 为每个 Spoke 安装 `/32`，因此在
Hub 开启 IPv4 forwarding 且防火墙允许时，未建立直连的 spoke 流量可以在内层经过
Hub 转发：

```sh
sudo sysctl -w net.ipv4.ip_forward=1
```

Hub 仅在 `peer-get` 显示另一个 Spoke 的认证 UDP 候选为有效时，才把该节点写入
`SYNC`。接收方为其安装独立双向 tunnel ID 和 `/32`；后续有效 SYNC 中消失的项会
被删除。周期注册让老节点最终获得新节点信息。

Hub 每秒检查一次注册租约。Spoke 超过 `peer_timeout` 未完成有效注册时，Hub 删除其
内核 peer、持久化节点和所有相关直连 session；仍在线的其他 Spoke 会在下一次周期
注册返回的 SYNC 中发现该节点消失并删除直连 peer。通常清理传播时间不超过
`peer_timeout + interval`，应把 `peer_timeout` 配置为明显大于 Spoke 的 `interval`
（建议至少三倍），避免短暂抖动导致误回收。

内核发送路径的实际顺序是：

```text
3 秒内完成往返验证的 Raw 候选 → 3 秒内收到过认证帧的直连 UDP 端点 → 使用 Hub peer 重新封装并转发
```

Hub 同步的 rendezvous 地址只用于打洞；只有直接收到认证包后才设置 `udp_up`。
直连不可用时内核改用 Hub peer 重新封装，因此 tunnel ID/HMAC 与 Hub 会话匹配，
再由 Hub 按内层 IPv4 路由转发。

IPv4 组播包会由发送节点复制到接口上的所有 peer，不需要为 `224.0.0.0/4` 配置 peer
前缀。内核当前不跟踪 IGMP 成员关系，所以所有已配置 peer 都会收到副本；节点较多或
组播流量较大时，需要把这种全量复制产生的外层带宽计入容量规划。应用仍需按常规方式
加入组播组，并确保本机路由把目标组播地址导向 dtun 接口，例如：

```sh
sudo ip route add 239.192.0.0/16 dev dtun0
```

## 8. 运维与排障

```sh
ip -s link show dtun0
ip address show dev dtun0
ip route show dev dtun0
ss -lunp | grep -E '49000|49001'
dmesg | grep -i dtun
```

已知本地 tunnel ID 时可查询候选和活跃状态：

```sh
IFINDEX=$(cat /sys/class/net/dtun0/ifindex)
sudo ./bin/dtunctl peer-get --ifindex "$IFINDEX" --tunnel-id 100
sudo ./bin/dtunctl peer-list --ifindex "$IFINDEX"
sudo ./bin/dtunctl peer-list --ifindex "$IFINDEX" --format json
```

`peer-get` 必须提供本地 tunnel ID；`peer-list` 使用 Netlink multipart dump 返回一致
快照。peer 命令默认输出人类可读信息，自动化应显式使用 `--format json`。
`peer-add`、`peer-set` 和 `peer-del` 在 JSON 模式下也返回带 `success` 和 errno 信息的
结果对象；JSON 地址缺失时使用 `null`。

常见问题：

- Raw 始终不活跃：检查双方公网地址、IPv4 协议 253 的安全组/防火墙以及 NAT；
- UDP 无流量：确认本机 `data_port` 未占用，Hub 数据端口双向可达；
- 注册无 ACK：核对 PSK、控制端口、node ID 和内层地址池规则；
- spoke 间只能直连不能经 Hub：检查 Hub 的 IPv4 forwarding 和 FORWARD 策略；
- 模块无法加载：确认构建所用 headers 与运行内核完全匹配。

## 9. 测试

```sh
make check
make test
make p2mp-test
sudo bash tests/cdaemon/run-all.sh
```

`make test` 和 `make p2mp-test` 会创建临时 network namespace。完整 C daemon 套件还
会使用 `iptables`、`tc netem`、`tcpdump` 和 `iperf3`，日志写入 `/tmp/dtun-test`。
