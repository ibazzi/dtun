# Three-Hub real-environment HA test

This directory contains the reusable configuration and test cases for one
primary Hub, two weighted backup Hubs, and three isolated Spokes.  No machine
address, password, Invite ID, PSK, or generated identity is stored here.

## Topology

- primary Hub, weight 1000;
- backup Hub 1, weight 900, plus one Spoke in a network namespace;
- backup Hub 2, weight 800, plus one Spoke in a network namespace;
- one local Spoke in a network namespace.

The suite uses `10.77.0.0/24` only inside the tunnel.  Temporary host-side
namespace networks use `192.168.250.0/24` through `192.168.252.0/24`.
Runtime files, keys, rendered configurations, and SSH control sockets live
under randomly named `/tmp` directories.
Each run generates a fresh control/data PSK in memory and injects it only into
the temporary rendered configurations; the repository templates contain only
the `@PSK@` placeholder.

## Run

From the repository root:

```sh
tests/ha-real/run.sh \
  root@<PRIMARY_IP> \
  root@<BACKUP1_IP> \
  root@<BACKUP2_IP>
```

SSH and local sudo request passwords directly from the terminal with echo
disabled.  The scripts deliberately have no password option and do not use an
inventory file.  SSH multiplexing means each host normally prompts only once.

Requirements on all Hub machines:

- SSH access as the supplied user (the test currently requires root remotely);
- kernel headers matching the running kernel;
- `gcc`, `make`, OpenSSL development files, `ip`, `iptables`, and `systemd-run`;
- TCP 22 and 49001 plus UDP 49000 and 49001 allowed between test machines.

The runner refuses to start if `dtun` is already loaded, so it cannot silently
replace an unrelated running deployment.  It builds and loads only the module
produced from the current worktree.

## Cases

The fixed test sequence verifies:

1. online Invite enrollment without copying or printing an Invite ID;
2. learner-to-voter promotion and three-member quorum mode;
3. three isolated Spoke registrations and cross-Spoke fallback;
4. byte-identical replicated Hub allocation state;
5. primary failure and election of backup 1 by weight;
6. rejection of a new allocation after the active partition loses quorum;
7. member recovery without immediate preferred-primary preemption;
8. failure of backup 1 and election of the highest-weight available primary;
9. convergence of the recovered member.

`raw_transport = false` is intentional in these cloud test templates.  It
forces authenticated UDP Hub paths and UDP/direct-or-Hub Spoke paths, avoiding
cloud networks that accept raw probes but discard actual raw-IP payloads.

## Cleanup

Cleanup runs automatically on success, failure, SIGINT, or SIGTERM.  To clean a
previous interrupted run manually:

```sh
tests/ha-real/cleanup.sh \
  root@<PRIMARY_IP> \
  root@<BACKUP1_IP> \
  root@<BACKUP2_IP>
```

For debugging only, `HA_REAL_KEEP=1` prevents automatic environment cleanup.
This leaves temporary HA private keys on the test hosts and must not be used
where the no-sensitive-state requirement applies.
