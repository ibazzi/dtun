# iproute2 Extension

**English** | [简体中文](README.md)

The repository's `bin/ip` is based on iproute2 7.1.0 and is currently a
dynamically linked x86-64 binary. Rebuild the extension for other architectures,
incompatible C library environments, or independently audited toolchains.

Copy `iplink_dtun.c` into the `ip/` directory of the iproute2 source tree, add
`iplink_dtun.o` to its `IPOBJ` list, and rebuild using that iproute2 release's
normal build process. The resulting command supports:

```sh
ip link add dtun0 type dtun local 192.0.2.10 udp_port 49000 node_id 1 \
  hub 192.0.2.1 hub_port 49000 probe_interval_ms 1000 path_timeout_ms 3000
```

`local`, `udp_port`, and `node_id` are required. `hub` and `hub_port` are
optional; when `hub_port` is omitted, the kernel uses the local `udp_port`. The
module does not reuse attributes from another tunnel link type, so unmodified
iproute2 cannot encode a dtun link configuration.
