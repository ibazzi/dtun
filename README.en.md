# dtun

**English** | [简体中文](README.md)

`dtun` is an out-of-tree L3 tunnel prototype for Linux 6.6 and later. Data
frames can be carried directly over Raw IPv4 protocol 253 or over UDP; both
transports share the same session-ID, HMAC, and anti-replay format. The C daemon
`dtund` provides Hub/Spoke registration, address allocation, and direct-peer
synchronization.

> [!WARNING]
> This project is not a production VPN. It authenticates payloads but does not
> encrypt them, and all nodes share one PSK without per-node identity isolation.
> Do not carry sensitive traffic over untrusted networks.

## Current capabilities

- IPv4 unicast uses longest-prefix peer selection; multicast is replicated to
  every peer. The default MTU is 1200.
- Raw IP as the preferred path, followed by a configured UDP endpoint.
- Authenticated UDP frames can update the source `IP:port` learned through NAT.
- The DTRG control plane supports lightweight refresh, candidate
  generations, persistent Hub
  state, offline lease expiry, and `/32` direct-peer synchronization between
  Spokes.
- C `dtund` and `dtunctl` are the only supported control plane; Python remains
  only in packet-generation test helpers.
- Both Raw and UDP outer output pass through IPv4 local-output/netfilter.
- `dtunctl peer-list` dumps all peers, and peer commands support JSON output.

The current release effectively supports IPv4 forwarding only. It has no
encryption, key rotation, live configuration reload, or general outer-frame
relay between Spokes. See the [design reference](docs/dtun-design.en.md) for the
complete boundaries.

## Repository layout

| Component | Purpose |
| --- | --- |
| `dtun.ko` | Kernel data plane and Netlink interfaces |
| `bin/dtund` | C-only Hub/Spoke control plane |
| `bin/dtunctl` | CLI for peers, prefixes, and peer status |
| `bin/ip` | Prebuilt iproute2 binary with the dtun link extension |
| `samples/` | Hub and Spoke configuration examples |
| `tests/` | C unit tests and privileged network-namespace regressions |

The included `bin/ip` is currently a dynamically linked x86-64 binary. Rebuild
it using the [iproute2 extension guide](iproute2/README.en.md) on other
architectures or incompatible user-space environments.

## Quick start

Building requires the headers/build tree for the running kernel, a C toolchain,
and the OpenSSL libcrypto development package:

```sh
make KDIR=/lib/modules/$(uname -r)/build
sudo insmod ./dtun.ko
```

Distribute the same random 32-byte PSK to the Hub and every Spoke, and restrict
configuration-file permissions:

```sh
openssl rand -hex 32
chmod 600 /etc/dtun/*.conf
```

Adapt the [Hub example](samples/dtun-hub.conf) and
[Spoke example](samples/dtun-spoke.conf) on their respective hosts, then start:

```sh
sudo ./bin/dtund -c /etc/dtun/hub.conf
sudo ./bin/dtund -c /etc/dtun/spoke.conf
```

At minimum, the public or host firewall must allow the Hub registration UDP
port (49001 by default) and data UDP port (49000 by default). To use the Raw
path, also allow IPv4 protocol 253 in both directions; ordinary NAT generally
does not forward it. See the [deployment guide](docs/guide.en.md) for complete
configuration, forwarding, and operations guidance.

## Verification

```sh
make check          # C unit tests and script syntax; no root required
make test           # Two-namespace data-plane regression; root required
make p2mp-test      # Hub + two-Spoke direct-path regression; root required
sudo bash tests/cdaemon/run-all.sh
```

The privileged suites also require Python 3, `ping`, `iptables`, `tc`,
`tcpdump`, and `iperf3`. To compile against several kernel build trees:

```sh
make compat-build KDIRS="/lib/modules/6.6.*/build /lib/modules/$(uname -r)/build"
```

The repository does not retain dated test reports. Treat results from running
the commands above against the current source as authoritative.
