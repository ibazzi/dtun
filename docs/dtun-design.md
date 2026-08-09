# dtun 设计参考

[English](dtun-design.en.md) | **简体中文**

本文描述当前源码实现，而不是未来规划。数据面和 DTRG 控制协议均仍在开发中，
只支持当前源码构建出的 Hub/Spoke，旧实现不保证兼容。

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
  └── UDP 49001 DTRG ──> Hub/Spoke registration、REFRESH and SYNC

inner IPv4 ──> dtun.ko ──> Raw IPv4/253 or UDP data frame
```

内核模块暴露：

- RTNL link type `dtun`；必需属性为 `local`、`udp_port`、`node_id`，可选属性为
  `hub`、`hub_port`；
- Generic Netlink family `DTUN` version 1；实现 `PEER_ADD`、`PEER_SET`、
  `PEER_DEL`、`PEER_GET`、`PEER_LIST`、`REBIND`、`ROUTE_ADD` 和 `ROUTE_DEL`；
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

自适应 workqueue 按各路径的 EWMA/RTTVAR 探测周期对每个 peer：

- 有 Raw 地址时发送 Raw PROBE；
- 有 UDP `IP:port` 时发送 UDP PROBE；
- 没有 UDP 候选但接口配置了 Hub 时，向 Hub 端点发送 KEEPALIVE。

DATA 的实际选择规则为：

1. 在动态阈值内完成认证往返的 Raw 地址；
2. 在动态阈值内直接观察到认证来源的 UDP 地址；
3. 否则改用节点 1 的 Hub peer 重新封装，Hub 按内层路由继续转发。

Raw 和直连 UDP 都必须处于活跃窗口。两者失效时使用 Hub peer 的 tunnel ID 和 HMAC
重新封装，Hub 解包后依靠地址池路由及 IPv4 forwarding 转发到目标 Spoke。

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

## 7. DTRG 注册与刷新协议

DTRG 运行在 Hub 控制 UDP 端口上。所有消息以 magic `DTRG` 和类型开始，
结尾为覆盖整个消息体的 16 字节截断 HMAC-SHA-256。多字节字段为网络字节序。

```text
Spoke                         Hub
  |---- INIT ----------------->|  node/address/raw/nonce
  |<--- CHALLENGE -------------|  回显字段 + 无状态 cookie
  |---- CONFIRM -------------->|  回显 cookie
  |<--- ACK --------------------|  节点、双向 ID、地址、lease token、epoch
  |<--- SYNC -------------------|  可用的其他 spoke 直连记录
  |---- REFRESH --------------->|  token、计数器、已应用 epoch、分页偏移
  |<--- REFRESH_ACK ------------|  自身端点、epoch、候选增量/快照页
  |---- LEAVE ----------------->|  lease token、单调计数器
  |<--- LEAVE_ACK --------------|  已持久化主动离线状态
```

| 消息 | 总长度 | 关键字段 |
| --- | ---: | --- |
| INIT | 54 B | node、请求地址/前缀、Raw 声明、16 B nonce |
| CHALLENGE | 86 B | INIT 字段 + 32 B cookie |
| CONFIRM | 86 B | CHALLENGE 回显 |
| ACK | 84 B | node、双向 tunnel ID、地址、端口、nonce、lease token、epoch |
| SYNC | `47 + 39 × N` B | node、nonce、数量、N 条 peer 记录 |
| REFRESH | 63 B | node、lease token、计数器、epoch、分页偏移 |
| REFRESH_ACK | `72 + 39 × N` B | 自身数据端点、epoch、分页标志及候选记录 |
| LEAVE / LEAVE_ACK | 53 B | node、lease token、单调计数器 |

每条 peer 记录包含 node ID、双向 tunnel ID、内层 IPv4、Raw/UDP 候选、generation
和 online/offline/tombstone 标志。online 表示候选可用于打洞，无标志表示节点在线但
候选尚不完整，offline 表示立即移除活跃 peer，tombstone 表示身份保留期结束。
REFRESH_ACK 限制为 1200 字节并分页；解析器严格检查
magic、类型、精确长度、数量和 HMAC。

Spoke 为每次尝试生成新 nonce，并要求 CHALLENGE/ACK 来自配置的 Hub 控制端点且
回显字段匹配。ACK 有效即表示本次注册成功；紧随其后的 SYNC 若缺失或无效会被忽略，
已有直连项保持不变。有效 SYNC 会增量更新，并删除其中不再出现的旧直连项。

cookie 使用 Hub 状态中的随机密钥，绑定注册来源 `IP:port`、node、请求地址/前缀、
Raw 声明、nonce 和时间桶；当前桶及前一时间桶有效。

## 8. Hub 分配、状态与直连同步

Hub 本地状态带 magic 和格式校验，持久化 cookie 密钥、下一个 node/tunnel ID、
最多 128 个节点记录及所有已分配 spoke-pair 会话。每个 Hub↔Spoke 和每个 Spoke 对
都有独立的双向 tunnel ID，分配从 100 开始并持久化。

Hub 根据有效 CONFIRM/REFRESH 更新自适应链路状态。有效 LEAVE 使用当前 lease token
和更新的单调计数器认证；Hub 保存离线状态后幂等回复 LEAVE_ACK。多个独立探测轮次失败并超过
EWMA/RTTVAR 动态阈值后，只移除活跃内核路径并标记离线；地址和 tunnel/session ID
默认继续保留 86400 秒，保留期内相同 node ID 重连会复用原会话。保留期结束后删除
记录并通过 tombstone 传播。
Hub 每次启动都会轮换持久化 lease token；收到旧 token 的认证 REFRESH 时返回
`RE_REGISTER` 标志，但不返回新 token。Spoke 随即完成完整注册，并在这个经过认证的
daemon 生命周期边界重建 Hub peer 和防重放窗口。普通出口候选变化不会重置序列号。

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
- 常驻 Spoke 按自适应周期 REFRESH；失败时保留现有接口。Hub 重启时认证
  `RE_REGISTER` 回复立即触发完整注册并复用持久化身份和 session。分配地址、node、前缀或 Hub
  数据端口变化时，接口可能被重建。
- `once=true` 在第一次尝试后退出：成功则保留接口，失败则返回非零且不保留接口。
- SIGINT、SIGTERM 和 SIGHUP 都表示停止；已注册 Spoke 会在最长 900ms 的自适应窗口内
  重试认证 LEAVE。Hub 不可达时仍会退出，并由存活检测兜底。当前没有配置热重载。
- daemon 创建接口前会删除同名接口，并假定该接口由自身独占管理。

## 10. 限制与兼容性

- 只有认证和防重放，没有加密；全局 PSK 也不能隔离单个 Spoke。
- 省略 PSK 会启用不安全的零密钥开发模式。
- 实际端到端路由仅支持 IPv4。
- Raw IP 253 通常不能穿越 NAT，并可能被运营商或云安全组过滤。
- 直连 UDP 只在收到认证往返后进入选择窗口；失效时会通过 Hub peer 重新封装。
- Hub 间接转发依赖宿主 IPv4 forwarding 和 FORWARD 防火墙策略。
- DTRG 仍在开发中，只支持相同源码版本构建的 C Hub/Spoke；协议调整时必须同步部署
  替换全部控制面节点。
- Hub 状态是带版本的本地二进制结构，不保证跨 ABI/架构可移植。
- 正常信号退出使用显式 LEAVE；崩溃、断网和强制终止仍由自适应探测清理。
- `dtunctl peer list` 通过 Generic Netlink dump 枚举 peer；预留的 `STATS_GET` 尚未实现。
- 隧道没有拥塞控制、PMTU 发现、分片重组策略或生产级密钥管理。
