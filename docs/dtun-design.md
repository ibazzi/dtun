# dtun 设计参考

[English](dtun-design.en.md) | **简体中文**

本文描述当前源码实现，而不是未来规划。数据面线协议版本为 1，注册控制协议为
C-only DTRG v2；旧 C/Python 控制面不受支持，也不能与当前版本混跑。

## 1. 目标与非目标

dtun 将一个无 ARP 的点到点 L3 netdevice 映射到 Raw IPv4 或 UDP 外层承载，并为
每个 peer 提供认证、防重放、候选学习和 IPv4 前缀选择。控制面负责创建接口、注册
节点、分配会话 ID，并通过 Hub 同步 spoke 直连信息。

当前非目标包括：载荷加密、每节点独立凭据、IPv6 路由控制、动态密钥轮换、配置
热重载、通用外层 relay、peer 枚举和生产级高可用。

## 2. 组件与接口

```text
dtund ── RTNL ──> dtun link
  │
  ├── Generic Netlink DTUN ──> peer / prefix / status
  └── UDP 49001 DTRG v2 ──> Hub/Spoke registration and SYNC

inner IPv4 ──> dtun.ko ──> Raw IPv4/253 or UDP data frame
```

内核模块暴露：

- RTNL link type `dtun`；必需属性为 `local`、`udp_port`、`node_id`，可选属性为
  `hub`、`hub_port`；
- Generic Netlink family `DTUN` version 1；实现 `PEER_ADD`、`PEER_SET`、
  `PEER_DEL`、`PEER_GET`、`ROUTE_ADD` 和 `ROUTE_DEL`；
- multicast group `events`，在认证 UDP 来源被观察后发送候选通知。

UAPI 枚举中预留了 `STATS_GET`，但当前没有注册对应操作。接口统计通过标准
netdevice 统计读取。

## 3. 数据帧格式

所有多字节整数使用网络字节序。固定头长 52 字节：

| 偏移 | 字段 | 长度 | 当前语义 |
| ---: | --- | ---: | --- |
| 0 | `version` | 1 B | 数据面版本 1 |
| 1 | `type` | 1 B | 1 DATA、2 PROBE、3 KEEPALIVE |
| 2 | `flags` | 2 B | 发送端固定为 0 |
| 4 | `src_tunnel_id` | 4 B | 发送端本地接收 ID |
| 8 | `dst_tunnel_id` | 4 B | 对端本地接收 ID |
| 12 | `seq` | 8 B | 每 peer 单调递增，从 1 开始 |
| 20 | `src_node` | 8 B | 发送节点 ID |
| 28 | `dst_node` | 8 B | 接收节点 ID |
| 36 | `tag` | 16 B | 截断 HMAC-SHA-256 |

HMAC 覆盖 `tag` 之前的全部头字段和完整内层载荷。每个 peer 使用 2048 包滑动窗口
拒绝序列号 0、重复帧和窗口外旧帧。更新 peer 密钥会清空该 peer 的接收重放状态。

DATA 去除外层头后重新注入对应 dtun netdevice。接收端能识别 IPv4/IPv6 版本位，
但发送路由表只实现 IPv4 最长前缀，因此当前端到端能力按 IPv4 限定。

## 4. 接收认证与候选学习

接收顺序为：检查版本、类型和目标 node → 按本地 `dst_tunnel_id` 查 peer → 校验来源
node → 校验来源/HMAC → 校验重放窗口 → 更新路径状态 → 交付 DATA。

- Raw 帧在 HMAC 前就必须匹配配置的 `raw_addr`，通过认证后刷新 `raw_seen`；
- UDP 允许未知来源端口先进入 HMAC 校验，以支持 NAT 映射变化；认证成功后刷新
  `udp_seen` 并学习来源 `IP:port`；
- 来自接口所配置 Hub 回退端点的 UDP 帧不会覆盖 peer 的直连候选；
- 无 peer HMAC 时，数据面跳过标签验证。这只会发生在 daemon 零密钥开发模式或
  手工创建无 key peer 的场景，不能视为安全配置。

认证 UDP 观察结果同时通过 Generic Netlink `events` multicast group 发布。当前 Hub
daemon 不订阅该事件，而是在生成 SYNC 前调用 `PEER_GET` 获取最新候选。

## 5. 路由、探测与路径选择

发送端仅接受内层 IPv4 skb。单播在所有 peer 前缀中执行最长前缀匹配，没有匹配项
时丢包并增加 `tx_dropped`；IPv4 组播不使用前缀表，而是为当时已配置的每个 peer
复制一份 DATA 帧。设备声明 `IFF_MULTICAST`，但当前不跟踪 IGMP 成员关系，因此这是
全 peer 泛洪；没有 peer 时同样丢包。每份副本使用对应 peer 独立的 tunnel ID、序列号、
HMAC 和路径选择。

每 5 秒的 workqueue 对每个 peer：

- 有 Raw 地址时发送 Raw PROBE；
- 有 UDP `IP:port` 时发送 UDP PROBE；
- 没有 UDP 候选但接口配置了 Hub 时，向 Hub 端点发送 KEEPALIVE。

DATA 的实际选择规则为：

1. `raw_addr` 非零，且 `raw_seen` 距当前不足 15 秒：选择 Raw IPv4 253；
2. 否则只要 `udp_addr` 和 `udp_port` 非零：选择直连 UDP，不检查 `udp_seen`；
3. 否则使用接口的 `hub_addr`/`hub_port`；端点为空时发送失败。

因此 `raw_up` 参与路径选择，而 `udp_up` 当前只是状态输出。所谓 relay 也只是目的
端点回退：原始 node 和 tunnel ID 不变，Hub 不会为任意直连会话解包或重写该帧。
控制面提供的地址池路由配合 Hub 内层 IPv4 forwarding 才是 spoke 间的间接路径。

## 6. 外层发送与生命周期

Raw 发送通过 `ip_route_output_key` 和 `iptunnel_xmit`；UDP 显式构造 UDP/IPv4 头，
通过 `ip_local_out` 输出。`local_outer_ip` 为零时，两条路径都使用外层路由查询选出的
源地址。两条路径都经过 IPv4 local-output/netfilter，且不会在
`ndo_start_xmit` 中调用 `kernel_sendmsg`。

DATA 发送会复制内层 skb 负载，再构造独立外层 skb；路由或分配失败计入发送错误。
UDP 接收复用绑定在 `local_outer_ip:data_port` 的内核 encapsulation socket；Raw
接收通过协议 253 handler 按目标 node 选择 dtun 设备。

peer 使用引用计数保护并发收发与配置更新。删除设备时先禁用 TX、同步取消 probe、
断开 UDP 回调并等待 RCU/network 读侧结束，再释放 peer 和 socket。

## 7. DTRG v2 注册协议

DTRG 运行在 Hub 控制 UDP 端口上。所有消息以 magic `DTRG`、版本 2 和类型开始，
结尾为覆盖整个消息体的 16 字节截断 HMAC-SHA-256。多字节字段为网络字节序。

```text
Spoke                         Hub
  |---- INIT ----------------->|  node/address/raw/nonce
  |<--- CHALLENGE -------------|  回显字段 + 无状态 cookie
  |---- CONFIRM -------------->|  回显 cookie
  |<--- ACK --------------------|  节点、双向 ID、地址、Hub 数据端口
  |<--- SYNC -------------------|  可用的其他 spoke 直连记录
```

| 消息 | 总长度 | 关键字段 |
| --- | ---: | --- |
| INIT | 55 B | node、请求地址/前缀、Raw 声明、16 B nonce |
| CHALLENGE | 87 B | INIT 字段 + 32 B cookie |
| CONFIRM | 87 B | CHALLENGE 回显 |
| ACK | 61 B | node、本地/远端 tunnel ID、地址/前缀、Hub 数据端口、nonce |
| SYNC | `48 + 30 × N` B | node、nonce、数量、N 条定长 peer 记录 |

每条 SYNC peer 记录包含 node ID、本地/远端 tunnel ID、内层 IPv4、Raw IPv4 和 UDP
`IPv4:port`。peer 数量上限为 128，控制包缓冲上限为 8192 字节。解析器严格检查
magic、版本、精确长度、数量和 HMAC。

Spoke 为每次尝试生成新 nonce，并要求 CHALLENGE/ACK 来自配置的 Hub 控制端点且
回显字段匹配。ACK 有效即表示本次注册成功；紧随其后的 SYNC 若缺失或无效会被忽略，
已有直连项保持不变。有效 SYNC 会增量更新，并删除其中不再出现的旧直连项。

cookie 使用 Hub 状态中的随机密钥，绑定注册来源 `IP:port`、node、请求地址/前缀、
Raw 声明、nonce 和时间桶；当前桶及前一时间桶有效。

## 8. Hub 分配、状态与直连同步

Hub 状态 magic 为 `DTS2`、版本为 2，持久化 cookie 密钥、下一个 node/tunnel ID、
最多 128 个节点记录及所有已分配 spoke-pair 会话。每个 Hub↔Spoke 和每个 Spoke 对
都有独立的双向 tunnel ID，分配从 100 开始并持久化。

Hub 每秒根据最后一次成功 CONFIRM 更新的 `last_seen` 检查节点租约。超过
`peer_timeout`（默认 60 秒）后，删除 Hub 内核 peer、节点记录及引用该节点的所有
spoke-pair session，并原子保存状态。仍在线的 Spoke 在下一次周期注册获得不含过期
节点的 SYNC，`apply_sync` 随即删除本地直连 peer。重新注册的过期节点会获得新的
tunnel/session ID。稳定部署仍应配置固定非 0 node ID。

状态以当前 C 结构的二进制布局保存，因此适合同一平台上的 daemon 重启恢复，不应
当作跨架构交换格式。保存使用同目录 `.tmp` 文件、刷新、`fsync` 和原子重命名。
当前无头旧 C 状态可导入；这只是本地状态文件迁移，不表示兼容旧控制协议。非法头、
长度、计数、地址、重复 ID 或悬空会话会导致启动失败，不会自动重置。

Hub 在为某个 Spoke 构造 SYNC 时，只发布其他节点中 `PEER_GET` 显示 `udp_up=true`
且 UDP 候选完整的记录，并将候选 IP 同时作为 Raw 候选。这是 Hub 基于观测结果的
推断，不保证该地址上的 Raw 协议实际可达；内核探测会决定 Raw 是否进入活跃窗口。

## 9. daemon 生命周期

- Hub 启动时读取并验证状态，创建接口；正常信号退出时删除接口。
- Spoke 首次有效 ACK 后创建接口和 Hub peer；其本地 UDP 端口来自自身 `data_port`，
  Hub 目的数据端口来自 ACK。
- 常驻 Spoke 周期重注册。失败时保留现有接口；Hub 状态保留的重启通常能在一个周期
  内恢复。分配地址、node、前缀或 Hub 数据端口变化时，接口可能被重建。
- `once=true` 在第一次尝试后退出：成功则保留接口，失败则返回非零且不保留接口。
- SIGINT、SIGTERM 和 SIGHUP 都表示停止；当前没有配置热重载。
- daemon 创建接口前会删除同名接口，并假定该接口由自身独占管理。

## 10. 限制与兼容性

- 只有认证和防重放，没有加密；全局 PSK 也不能隔离单个 Spoke。
- 省略 PSK 会启用不安全的零密钥开发模式。
- 实际端到端路由仅支持 IPv4。
- Raw IP 253 通常不能穿越 NAT，并可能被运营商或云安全组过滤。
- UDP 选择目前不以 `udp_up` 为门槛，失效端点不会自动跳到通用外层 relay。
- Hub 间接转发依赖宿主 IPv4 forwarding 和 FORWARD 防火墙策略。
- DTRG v2 只支持当前 C Hub/Spoke；旧 C/Python 控制面明确不兼容，升级时必须同步
  替换全部控制面节点。
- Hub 状态是带版本的本地二进制结构，不保证跨 ABI/架构可移植。
- Hub 没有显式注销消息；掉线清理由注册租约超时驱动，通知随其他 Spoke 的周期 SYNC
  传播。
- `dtunctl` 没有 peer-list 或统计命令；预留的 `STATS_GET` 尚未实现。
- 隧道没有拥塞控制、PMTU 发现、分片重组策略或生产级密钥管理。
