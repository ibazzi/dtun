# dtun Design Reference

**English** | [简体中文](dtun-design.md)

This document describes the current source implementation rather than future
plans. The registration protocol is C-only DTRG and remains under development;
only Hub and Spoke binaries built from the same source revision are expected to
interoperate.

## 1. Goals and non-goals

dtun maps a point-to-point, no-ARP L3 netdevice onto Raw IPv4 or UDP outer
transport. Each peer has authentication, anti-replay state, candidate learning,
and IPv4 prefix selection. The control plane creates links, registers nodes,
allocates session IDs, and synchronizes direct Spoke information through a Hub.

Current non-goals include payload encryption, per-node credentials, IPv6 route
control, dynamic key rotation, live configuration reload, a general outer
relay, peer enumeration, and production-grade high availability.

## 2. Components and interfaces

```text
dtund ── RTNL ──> dtun link
  │
  ├── Generic Netlink DTUN ──> peer / prefix / status
  └── UDP 49001 DTRG ──> Hub/Spoke registration, REFRESH, and SYNC

inner IPv4 ──> dtun.ko ──> Raw IPv4/253 or UDP data frame
```

The kernel module exposes:

- RTNL link type `dtun`; required attributes are `local`, `udp_port`, and
  `node_id`, with optional `hub` and `hub_port`.
- Generic Netlink family `DTUN` version 1 implementing `PEER_ADD`, `PEER_SET`,
  `PEER_DEL`, `PEER_GET`, `ROUTE_ADD`, and `ROUTE_DEL`.
- Multicast group `events`, which publishes an observed candidate after an
  authenticated UDP source is accepted.

The UAPI enum reserves `STATS_GET`, but no corresponding operation is currently
registered. Interface counters use standard netdevice statistics.

## 3. Data-frame format

All multibyte integers use network byte order. The fixed header is 52 bytes:

| Offset | Field | Length | Current meaning |
| ---: | --- | ---: | --- |
| 0 | `version` | 1 B | Data-plane version 1 |
| 1 | `type` | 1 B | 1 DATA, 2 PROBE, 3 KEEPALIVE |
| 2 | `flags` | 2 B | Always 0 on transmit |
| 4 | `src_tunnel_id` | 4 B | Sender's local receive ID |
| 8 | `dst_tunnel_id` | 4 B | Remote local receive ID |
| 12 | `seq` | 8 B | Per-peer monotonic sequence starting at 1 |
| 20 | `src_node` | 8 B | Sending node ID |
| 28 | `dst_node` | 8 B | Receiving node ID |
| 36 | `tag` | 16 B | Truncated HMAC-SHA-256 |

HMAC covers every header field preceding `tag` plus the complete inner payload.
Each peer has a 2,048-packet sliding window that rejects sequence zero,
duplicates, and old packets outside the window. Updating a peer key clears that
peer's receive replay state.

After removing the dtun header, DATA is reinjected through the corresponding
dtun netdevice. Ingress recognizes both IPv4 and IPv6 version nibbles, but the
transmit route table only implements IPv4 longest-prefix matching, so current
end-to-end support is limited to IPv4.

## 4. Receive authentication and candidate learning

Receive processing checks version, type, and destination node; looks up the
peer by local `dst_tunnel_id`; validates the source node; validates source/HMAC;
checks the replay window; updates path state; and finally delivers DATA.

- A Raw frame must match the configured `raw_addr` before HMAC validation and
  refreshes `raw_seen` after successful authentication.
- UDP allows an unknown source port to reach HMAC validation so a changed NAT
  mapping can be learned. Successful authentication refreshes `udp_seen` and
  updates the source `IP:port`.
- UDP received from the link's configured Hub fallback endpoint does not
  overwrite a peer's direct candidate.
- Without a peer HMAC, the data plane skips tag verification. This occurs only
  in daemon zero-key development mode or for a manually created keyless peer and
  is not a secure configuration.

An authenticated UDP observation is also published through the Generic Netlink
`events` multicast group. The current Hub daemon does not subscribe; it calls
`PEER_GET` before constructing SYNC to retrieve the latest candidate.

## 5. Routing, probes, and path selection

Transmit accepts inner IPv4 skbs only. Unicast performs longest-prefix matching
over all peer prefixes; no match drops the packet and increments `tx_dropped`.
IPv4 multicast bypasses the prefix table and creates one DATA frame for every
currently configured peer. The device advertises `IFF_MULTICAST`, but does not
track IGMP membership, so this is all-peer flooding; multicast is also dropped
when there are no peers. Every copy uses that peer's own tunnel IDs, sequence,
HMAC, and path selection.

At each path's adaptive EWMA/RTTVAR cadence, a workqueue does the following for
each peer:

- sends a Raw PROBE when a Raw address is configured;
- sends a UDP PROBE when a UDP `IP:port` is configured;
- otherwise sends a KEEPALIVE to the Hub endpoint when the link has one.

The actual DATA selection rules are:

1. Choose Raw IPv4 253 after an authenticated Raw round trip within its
   adaptive EWMA/RTTVAR threshold.
2. Otherwise choose a directly observed authenticated UDP endpoint within its
   adaptive threshold.
3. Otherwise re-encapsulate through the node-1 Hub peer; the Hub then forwards
   according to the inner IPv4 route.

## 6. Outer transmission and lifecycle

Raw output uses `ip_route_output_key` and `iptunnel_xmit`. UDP output constructs
UDP/IPv4 headers explicitly and calls `ip_local_out`. When `local_outer_ip` is
zero, both paths use the source selected by the outer route lookup. Both traverse IPv4
local-output/netfilter, and neither calls `kernel_sendmsg` from
`ndo_start_xmit`.

DATA transmission copies the inner skb payload before building an independent
outer skb; route or allocation failures count as transmit errors. UDP receive
uses a kernel encapsulation socket bound to `local_outer_ip:data_port`. Raw
receive uses an IPv4 protocol-253 handler and selects a dtun device by
destination node.

Peer references protect concurrent receive, transmit, and configuration
updates. Device deletion first disables TX, synchronously cancels probes,
disconnects the UDP callback, and waits for RCU/network readers before releasing
peers and the socket.

## 7. DTRG registration and refresh protocol

DTRG runs over the Hub control UDP port. Every message starts with magic `DTRG`
and a type, and ends with a 16-byte truncated HMAC-SHA-256 over the
entire message body. Multibyte fields use network byte order.

```text
Spoke                         Hub
  |---- INIT ----------------->|  node/address/raw/nonce
  |<--- CHALLENGE -------------|  echoed fields + stateless cookie
  |---- CONFIRM -------------->|  echoed cookie
  |<--- ACK --------------------|  node, bidirectional IDs, address, Hub data port
  |<--- SYNC -------------------|  available direct records for other Spokes
  |---- REFRESH --------------->|  lease token, counter, epoch, page offset
  |<--- REFRESH_ACK ------------|  reflected endpoint and candidate delta/page
```

| Message | Total length | Key fields |
| --- | ---: | --- |
| INIT | 54 B | node, requested address/prefix, Raw claim, 16 B nonce |
| CHALLENGE | 86 B | INIT fields + 32 B cookie |
| CONFIRM | 86 B | CHALLENGE echo |
| ACK | 84 B | node, tunnel IDs, address, Hub port, nonce, lease token, epoch |
| SYNC | `47 + 39 × N` B | node, nonce, count, and N peer records |
| REFRESH | 63 B | node, lease token, counter, epoch, page offset |
| REFRESH_ACK | `72 + 39 × N` B | reflected endpoint, epoch, flags, and peer records |

Each peer record contains the node ID, tunnel IDs, inner address, Raw and UDP
candidates, generation, and online/tombstone flags. REFRESH_ACK is capped at
1,200 bytes and paginated. The parser strictly validates
magic, type, exact length, count, and HMAC.

A Spoke generates a fresh nonce for every attempt and requires CHALLENGE and ACK
to come from the configured Hub control endpoint with matching echoed fields. A
valid ACK makes the registration attempt successful. A missing or invalid SYNC
immediately following ACK is ignored and leaves existing direct entries intact;
a valid SYNC incrementally updates them and removes old entries no longer
present.

The cookie uses the random secret in Hub state and binds the registration source
`IP:port`, node, requested address/prefix, Raw claim, nonce, and time bucket. The
current and previous buckets are accepted.

## 8. Hub allocation, state, and direct synchronization

Hub state has a magic value and format validation. It persists the cookie secret, next
node/tunnel IDs, up to 128 node records, and every allocated Spoke-pair session.
Each Hub-to-Spoke and Spoke-pair relationship gets distinct bidirectional tunnel
IDs allocated from 100 and persisted.

The Hub updates adaptive link health after valid CONFIRM and REFRESH messages.
After multiple independent failed probe rounds exceed the EWMA/RTTVAR dynamic
threshold, it removes only the active kernel path and marks the node offline.
Address and tunnel/session allocations remain for `identity_retention` (86,400
seconds by default). Reconnection with the same node ID reuses those sessions.
The Hub rotates persisted lease tokens whenever it starts. An authenticated
REFRESH carrying an old token receives a `RE_REGISTER` flag without disclosing
the new token. The Spoke immediately performs the full registration and rebuilds
the Hub peer and replay window at that authenticated daemon-lifecycle boundary.
Ordinary endpoint candidate changes do not reset sequence numbers.

State is saved using the current C structure's binary layout. It is suitable for
daemon restart recovery on the same platform and should not be treated as a
cross-architecture exchange format. Saving uses a same-directory `.tmp` file,
flush, `fsync`, and atomic rename. The previous unheadered C state can be
imported only as a local state-file migration; this does not provide old wire
protocol compatibility. Invalid headers, lengths, counts, addresses, duplicate
IDs, or dangling sessions cause startup failure instead of an automatic reset.

When constructing SYNC for one Spoke, the Hub publishes only other nodes whose
`PEER_GET` result has `udp_up=true` and a complete UDP candidate. It also uses
the observed candidate IP as the Raw candidate. This is a Hub inference and
does not prove that Raw protocol is reachable at that address; kernel probes
determine whether Raw enters its active window.

## 9. Daemon lifecycle

- The Hub loads and validates state, then creates its interface. A normal signal
  exit removes the interface.
- A Spoke creates its interface and Hub peer after the first valid ACK. Its local
  UDP port comes from its own `data_port`; the Hub destination data port comes
  from ACK.
- A resident Spoke sends REFRESH at its adaptive cadence and keeps the existing
  interface on failure. After a Hub restart, the authenticated `RE_REGISTER`
  reply immediately starts full registration, which reuses the persisted identity
  and session. Changes to the assigned address, node, prefix, or Hub data port
  can cause the interface to be recreated.
- With `once=true`, the daemon exits after the first attempt: success leaves the
  interface in place, while failure returns nonzero with no retained interface.
- SIGINT, SIGTERM, and SIGHUP all mean stop; live configuration reload is not
  implemented.
- Before creating a link, the daemon deletes an existing link with the same name
  and assumes exclusive ownership of it.

## 10. Limitations and compatibility

- Authentication and anti-replay are provided, but not encryption; a global PSK
  also cannot isolate an individual Spoke.
- Omitting the PSK enables insecure zero-key development mode.
- Effective end-to-end routing supports IPv4 only.
- Raw IP 253 generally cannot cross NAT and may be filtered by providers or
  cloud security groups.
- Direct UDP selection requires a recently authenticated source; otherwise
  unicast traffic is re-encapsulated through the Hub peer.
- Indirect Hub forwarding depends on host IPv4 forwarding and the FORWARD
  firewall policy.
- DTRG remains under development and supports only C Hub and Spoke binaries
  built from the same source revision; protocol changes require coordinated deployment.
- Hub state is a versioned local binary structure and is not portable across
  every ABI or architecture.
- There is no explicit deregistration message. Multiple independent probe
  failures beyond the dynamic threshold trigger stale cleanup, and other Spokes
  learn it through periodic SYNC.
- `dtunctl peer-list` dumps peer snapshots; reserved `STATS_GET` remains
  unimplemented.
- The tunnel has no congestion control, PMTU discovery, fragmentation strategy,
  or production-grade key management.
