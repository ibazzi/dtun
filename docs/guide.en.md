# dtun Deployment and Operations Guide

**English** | [简体中文](guide.md)

This guide describes the current C daemon and kernel-module implementation.
`dtun` is an authenticated L3 tunnel prototype, not an encrypted VPN. Review
the limitations and compatibility notes in the
[design reference](dtun-design.en.md) before deployment.

## 1. Planning and dependencies

A basic deployment has one Hub and one or more Spokes:

| Traffic | Default port/protocol | Direction | Purpose |
| --- | --- | --- | --- |
| Registration control | UDP 49001 | Spoke → Hub | DTRG registration, REFRESH, and candidate sync |
| Data plane | UDP 49000 | Bidirectional | NAT-compatible data and probes |
| Data plane | IPv4 protocol 253 | Bidirectional | Preferred Raw IP transport |

The Hub needs a publicly reachable control address. UDP is required; Raw IP 253
is an optional preferred path and ordinary NAT generally does not forward it.
If Spokes without direct candidates should communicate through inner routing on
the Hub, enable IPv4 forwarding there and allow the corresponding FORWARD
traffic.

Build dependencies:

- Linux 6.6 or later and a headers/build tree matching the target kernel;
- GCC or Clang, GNU make, and the OpenSSL libcrypto development package;
- `CAP_NET_ADMIN` at runtime, plus `CAP_SYS_MODULE` to load the module.

## 2. Build and load

```sh
make KDIR=/lib/modules/$(uname -r)/build
sudo insmod ./dtun.ko
```

On Debian/Ubuntu, use the DKMS package to avoid binding the package to the
kernel version of the build host:

```sh
make deb
sudo apt install ./build/dtun_*.deb
sudo modprobe dtun
```

The target machine needs headers matching its running kernel. DKMS will rebuild
the module automatically after a kernel upgrade.

The build produces `dtun.ko`, `bin/dtund`, and `bin/dtunctl`. Confirm that the
module is loaded:

```sh
lsmod | grep '^dtun'
```

The repository's `bin/ip` is based on iproute2 7.1.0 and is currently a
dynamically linked x86-64 binary. If its architecture or libraries are
incompatible, build your own copy using the
[iproute2 extension guide](../iproute2/README.en.md). Unmodified `ip` cannot
encode dtun link attributes.

## 3. Keys and file permissions

Generate a 32-byte PSK and distribute it securely to the Hub and all Spokes in
the same network:

```sh
openssl rand -hex 32
sudo install -d -m 0750 /etc/dtun /var/lib/dtun
sudo install -m 0600 samples/dtun-hub.conf /etc/dtun/hub.conf
```

The configuration `psk` must contain exactly 64 hexadecimal characters. If it
is omitted, the daemon enters a zero-key development mode: DTRG uses a publicly
derivable all-zero key, and data peers do not verify HMAC. This mode is only for
isolated tests and must not be deployed on a real network.

The Hub state file contains the persistent cookie secret, nodes, and session
allocations and should be accessible only to the service account. The daemon
creates parent directories and saves via a temporary file, `fflush`, `fsync`,
and atomic `rename`; final permissions still depend on the process umask and
directory permissions.

## 4. Configuration reference

INI section names organize the file. The current parser reads settings by key
name; the section assignments below are conventions for supported configs.

### `[global]`

| Key | Default | Description |
| --- | --- | --- |
| `mode` | none | Required: `hub` or `spoke`; `--mode` can override it |
| `interface` | `dtun0` | Interface created and managed by the daemon |
| `local_outer_ip` | `0.0.0.0` | Local outer IPv4; zero selects the source from each outer route |
| `data_port` | `49000` | Local data-plane UDP port |
| `probe_interval_ms` | `1000` | Raw/UDP path probe interval |
| `path_timeout_ms` | `3000` | Path liveness timeout; at least twice the probe interval |
| `fast_recovery` | `true` | Enable endpoint-change recovery; Spokes must use a wildcard outer address |
| `node_id` | `0` | A Hub must use 1 (0 falls back to 1); on a Spoke, 0 requests temporary allocation and 1 is reserved |
| `address` | `0.0.0.0/24` | Inner IPv4/CIDR; a zero Spoke address requests pool allocation |
| `psk` | none | 64-hex-digit representation of a 32-byte PSK; omission is insecure test mode |
| `syslog` | `false` | Enable syslog output (can also be enabled via `--syslog` or `-s`) |
| `syslog_ident` | `dtund` | Syslog tag/identifier (can be overridden via `--syslog-ident`) |
| `syslog_facility` | `daemon` | Syslog facility (`daemon`, `user`, `local0`~`local7`, etc.; can be overridden via `--syslog-facility`) |

### `[hub]`

| Key | Default | Description |
| --- | --- | --- |
| `bind_address` | `0.0.0.0` | Registration-control socket listen address |
| `bind_port` | `49001` | Registration-control UDP port |
| `pool` | Derived from the Hub `address` network prefix | Spoke inner-address pool; `/0` through `/30` are accepted, and an explicit `pool` takes precedence |
| `state_file` | `/var/lib/dtun/hub.state` | Versioned binary persistent state |
| `cookie_seconds` | `30` | Cookie time-bucket duration; nonpositive values fall back to 30 |
| `peer_timeout` | `60` | Seconds to retain a Spoke after its last successful registration; nonpositive values fall back to 60 |
| `identity_retention` | `86400` | Seconds to retain offline address and tunnel/session allocations |

### `[spoke]`

| Key | Default | Description |
| --- | --- | --- |
| `hub_address` | none | Required Hub control-plane IPv4 address |
| `hub_port` | `49001` | Hub control port, not the data port |
| `local_port` | `0` | Local registration-control source port; 0 selects an ephemeral port |
| `interval` | `20` | Delay after each registration attempt; nonpositive values act as 1 second |
| `refresh_interval_ms` | `1000` | DTRG lightweight refresh interval after registration |
| `timeout` | `5` | Receive timeout for each control response; nonpositive values fall back to 5 |
| `once` | `false` | Exit after the first attempt; keep the link on success, return nonzero on failure |

## 5. Deploy the Hub

The Hub always operates as node 1. This example uses documentation-only outer
addresses; replace the outer address and PSK:

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

Pool rules:

- The Hub inner address must be inside the pool and cannot be its network or
  broadcast address.
- The network address, broadcast address, first usable address, and actual Hub
  address are never assigned to a Spoke.
- A static Spoke address must use the pool prefix and must not conflict.
- A node ID cannot be rebound to another address, and node ID 1 is Hub-only.
- `node_id = 0` and `address = 0.0.0.0/<pool-prefix>` request automatic ID and
  address allocation respectively.
- The Hub stores at most 128 Spokes; registration is rejected when this limit or
  the address pool is exhausted.

Start the Hub:

```sh
sudo ./bin/dtund -c /etc/dtun/hub.conf
```

A missing state file is initialized, and the previous unheadered C state format
can be imported as a local state migration only; it does not provide old control
protocol compatibility. Truncation, unsupported versions, conflicting records,
or invalid counts cause startup to fail rather than silently resetting state.
On SIGINT, SIGTERM, or SIGHUP, the Hub stops and removes its managed interface.
SIGHUP does not currently reload configuration.

## 6. Deploy a Spoke

Static-address configuration:

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

For a persistent Hub-assigned address, use a stable unique node ID and set only
the address to zero:

```ini
node_id = 2
address = 0.0.0.0/24
```

`node_id = 0` also requests automatic ID allocation, but the Spoke does not
write the result back to its config file. A process restart therefore requests
a new ID. Use this only for short-lived tests; long-lived nodes need a stable,
nonzero node ID.

Start the Spoke:

```sh
sudo ./bin/dtund -c /etc/dtun/spoke.conf
```

After the first valid ACK, the Spoke binds its local interface using its own
`data_port` and configures the Hub peer using the Hub data port returned in ACK.
A resident process registers again with a fresh nonce every cycle. It retains
the current interface, peers, and routes while the Hub is temporarily
unreachable and reconciles automatically after recovery. Normal termination of
a resident process removes the interface.

The daemon treats `interface` as exclusively managed: it deletes an existing
link with the same name before creation. Do not share an interface name between
daemon processes or point a resident daemon at a manually managed link that
must be preserved.

`once = true` is intended for another process to take over interface lifetime:
the daemon exits after the first successful registration and leaves the link in
place; the first failure exits nonzero without retaining a link.

## 7. Direct paths, Hub forwarding, and fallback

A Spoke always installs the pool route through its Hub peer. The Hub installs a
`/32` for every Spoke, so traffic without a direct path can traverse inner
routing on a Hub whose IPv4 forwarding and FORWARD policy allow it:

```sh
sudo sysctl -w net.ipv4.ip_forward=1
```

Before adding another Spoke to `SYNC`, the Hub requires `peer-get` to report a
complete authenticated UDP candidate with `udp_up=true`. The recipient installs
the peer's distinct bidirectional tunnel IDs and `/32`. Entries absent from a
later valid SYNC are removed, and periodic registration eventually informs old
nodes about new ones.

The Hub checks registration leases once per second. When a Spoke has not
completed a valid registration for `peer_timeout` seconds, the Hub removes its
kernel peer, persistent node, and every related direct session. Other online
Spokes learn that it disappeared from the SYNC returned by their next periodic
registration and remove their direct peers. Propagation normally takes no more
than `peer_timeout + interval`. Configure `peer_timeout` comfortably above the
Spoke `interval` (at least three times larger is recommended) to tolerate brief
network disruption.

The kernel's actual transmit order is:

```text
Raw candidate validated within 3 seconds → directly observed authenticated UDP endpoint within 3 seconds → re-encapsulation through the Hub peer
```

Hub-supplied rendezvous candidates are probe-only; `udp_up` is set only after a
peer directly observes an authenticated source. When direct paths fail, the
packet is re-encapsulated with the Hub peer's tunnel ID and HMAC, then forwarded
according to the inner IPv4 route at the Hub.

IPv4 multicast is replicated by the sending node to every peer on the link; no
peer prefix for `224.0.0.0/4` is required. The kernel does not currently track
IGMP membership, so all configured peers receive a copy. Account for the outer
bandwidth created by this full replication on larger deployments or with
high-rate groups. Applications must still join their groups normally, and the
local routing table must direct the group to dtun, for example:

```sh
sudo ip route add 239.192.0.0/16 dev dtun0
```

## 8. Operations and troubleshooting

```sh
ip -s link show dtun0
ip address show dev dtun0
ip route show dev dtun0
ss -lunp | grep -E '49000|49001'
dmesg | grep -i dtun
```

Inspect one peer or dump the interface peer snapshot:

```sh
IFINDEX=$(cat /sys/class/net/dtun0/ifindex)
sudo ./build/dtunctl peer-get --ifindex "$IFINDEX" --tunnel-id 100
sudo ./build/dtunctl peer-list --ifindex "$IFINDEX"
sudo ./build/dtunctl peer-list --ifindex "$IFINDEX" --format json
```

Peer commands default to human-readable output; automation should explicitly
select `--format json`. `raw_up` and `udp_up` use the configured path timeout,
which defaults to three seconds.

Common issues:

- Raw never becomes active: check both public addresses, security-group or
  firewall handling of IPv4 protocol 253, and NAT behavior.
- UDP carries no traffic: verify that the local `data_port` is free and that the
  Hub data port is reachable in both directions.
- Registration gets no ACK: verify the PSK, control port, node ID, and pool
  rules for the requested inner address.
- Spokes work directly but not through the Hub: check Hub IPv4 forwarding and
  the FORWARD firewall policy.
- The module does not load: ensure it was built against headers matching the
  running kernel exactly.

## 9. Tests

```sh
make check
make test
make p2mp-test
sudo bash tests/cdaemon/run-all.sh
```

`make test` and `make p2mp-test` create temporary network namespaces. The full
C-daemon suite also uses `iptables`, `tc netem`, `tcpdump`, and `iperf3`, and
writes logs under `/tmp/dtun-test`.
