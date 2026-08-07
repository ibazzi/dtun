#!/bin/sh
# Shared helpers for dtun C-daemon tests.  Run as root.
set -eu

ROOT=${ROOT:-/home/xu/dev/dtun}
IP=${IP:-"$ROOT/bin/ip"}
CTL=${CTL:-"$ROOT/build/dtunctl"}
DUND=${DUND:-"$ROOT/build/dtund"}
KEY=${KEY:-00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff}
OUT=${OUT:-/tmp/dtun-test}
mkdir -p "$OUT" 2>/dev/null || true

PREFIX=${PREFIX:-dtc}
HUB=${HUB:-${PREFIX}-h}
A=${A:-${PREFIX}-a}
B=${B:-${PREFIX}-b}
BR=${BR:-${PREFIX}-br}

HUB_O=${HUB_O:-172.30.91.1}
A_O=${A_O:-172.30.91.2}
B_O=${B_O:-172.30.91.3}
HUB_I=${HUB_I:-10.99.0.1}
A_I=${A_I:-10.99.0.2}
B_I=${B_I:-10.99.0.3}

PASS=0
FAIL=0

section() { echo; echo "===== $* ====="; }
ok() { PASS=$((PASS+1)); echo "PASS: $*"; }
fail() { FAIL=$((FAIL+1)); echo "FAIL: $*"; }
summary() {
	echo
	echo "----- result: $PASS passed, $FAIL failed -----"
	[ "$FAIL" -eq 0 ]
}

mod_up() {
	if ! lsmod | grep -q '^dtun '; then
		insmod "$ROOT/build/dtun.ko" 2>/dev/null || insmod "$ROOT/dtun.ko"
	fi
}

topo_up() {
	mkdir -p "$OUT"
	ip link add "$BR" type bridge
	ip link set "$BR" up
	# Docker hosts default FORWARD policy to DROP with bridge-nf enabled,
	# which would silently kill bridged test traffic.
	iptables -I FORWARD -i "$BR" -j ACCEPT
	iptables -I FORWARD -o "$BR" -j ACCEPT
	for spec in "$HUB:1" "$A:2" "$B:3"; do
		ns=${spec%:*}; oct=${spec#*:}
		hostv=${ns}v
		ip netns add "$ns"
		ip link add "$hostv" type veth peer name eth0 netns "$ns"
		ip link set "$hostv" master "$BR"
		ip link set "$hostv" up
		ip -n "$ns" link set lo up
		ip -n "$ns" addr add "172.30.91.$oct/24" dev eth0
		ip -n "$ns" link set eth0 up
	done
	# Hub-relayed spoke-to-spoke forwarding needs IP forwarding inside the hub.
	ip netns exec "$HUB" sysctl -qw net.ipv4.ip_forward=1 || true
}

topo_down() {
	for ns in "$HUB" "$A" "$B"; do
		ip netns del "$ns" 2>/dev/null || true
	done
	ip link del "$BR" 2>/dev/null || true
	iptables -D FORWARD -i "$BR" -j ACCEPT 2>/dev/null || true
	iptables -D FORWARD -o "$BR" -j ACCEPT 2>/dev/null || true
	for ns in "$HUB" "$A" "$B"; do
		ip link del "${ns}v" 2>/dev/null || true
	done
}

hub_conf() {
	cat > "$OUT/hub.conf" <<EOF
[global]
mode = hub
interface = dtun0
local_outer_ip = $HUB_O
data_port = 49000
node_id = 1
address = $HUB_I/24
psk = $KEY

[hub]
bind_address = 0.0.0.0
bind_port = 49001
pool = 10.99.0.0/24
state_file = $OUT/hub.state
EOF
}

spoke_conf() { # ns outer inner node [once] [interval]
	ns=$1; outer=$2; inner=$3; node=$4; once=${5:-0}; interval=${6:-5}
	cat > "$OUT/spoke-$ns.conf" <<EOF
[global]
mode = spoke
interface = dtun0
local_outer_ip = 0.0.0.0
data_port = 49000
node_id = $node
address = $inner/24
psk = $KEY

[spoke]
hub_address = $HUB_O
hub_port = 49001
local_port = 0
interval = $interval
timeout = 3
once = $once
EOF
}

start_hub() {
	ip netns exec "$HUB" "$DUND" -c "$OUT/hub.conf" > "$OUT/hub.log" 2>&1 &
	echo $! > "$OUT/hub.pid"
}

start_spoke() { # ns
	ns=$1
	ip netns exec "$ns" "$DUND" -c "$OUT/spoke-$ns.conf" > "$OUT/spoke-$ns.log" 2>&1 &
	echo $! > "$OUT/spoke-$ns.pid"
}

stop_daemon() { # pidfile name
	if [ -f "$OUT/$1.pid" ]; then
		pid=$(cat "$OUT/$1.pid")
		kill -TERM "$pid" 2>/dev/null || true
		for i in $(seq 1 50); do
			kill -0 "$pid" 2>/dev/null || break
			sleep 0.1
		done
		kill -9 "$pid" 2>/dev/null || true
		rm -f "$OUT/$1.pid"
	fi
}

wait_reg() { # ns node [timeout_s]
	ns=$1; node=$2; tmo=${3:-20}
	for i in $(seq 1 "$tmo"); do
		if grep -q "Registration successful! NodeID=$node" "$OUT/spoke-$ns.log" 2>/dev/null; then
			return 0
		fi
		sleep 1
	done
	return 1
}

wait_gone() { # ns
	ns=$1
	for i in $(seq 1 30); do
		if ! ip -n "$ns" link show dtun0 >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.2
	done
	return 1
}

ping_ok() { # ns dst count
	ns=$1; dst=$2; cnt=${3:-3}
	ip netns exec "$ns" ping -c "$cnt" -W 1 "$dst" >/dev/null 2>&1
}

ifindex() { # ns
	ns=$1
	ip -n "$ns" link show dtun0 | sed -n 's/^\([0-9]*\):.*/\1/p'
}

rx_pkts() { # ns
	ns=$1
	ip netns exec "$ns" cat /sys/class/net/dtun0/statistics/rx_packets
}

tx_pkts() { # ns
	ns=$1
	ip netns exec "$ns" cat /sys/class/net/dtun0/statistics/tx_packets
}

tx_err() { # ns
	ns=$1
	ip netns exec "$ns" cat /sys/class/net/dtun0/statistics/tx_errors
}

tx_drop() { # ns
	ns=$1
	ip netns exec "$ns" cat /sys/class/net/dtun0/statistics/tx_dropped
}

peer_get() { # ns tunnel_id
	ns=$1; tid=$2
	ip netns exec "$ns" "$CTL" peer-get --format json --ifindex "$(ifindex "$ns")" --tunnel-id "$tid"
}

ipt_counters() { # ns  (echoes "raw udp")
	ns=$1
	raw=$(ip netns exec "$ns" iptables -L OUTPUT -v -n -x | awk '$4=="253" {print $1}')
	udp=$(ip netns exec "$ns" iptables -L OUTPUT -v -n -x | awk '($4=="17" || $4=="udp") && /dtun-output/ {print $1}')
	echo "${raw:-0} ${udp:-0}"
}

cpu_pct() { # pid  (percent of one core over a 1s sample)
	pid=$1
	[ -r "/proc/$pid/stat" ] || { echo 0; return; }
	s1=$(awk '{print $14+$15}' "/proc/$pid/stat")
	t1=$(date +%s%N)
	sleep 1
	s2=$(awk '{print $14+$15}' "/proc/$pid/stat")
	t2=$(date +%s%N)
	awk -v a="$s1" -v b="$s2" -v t1="$t1" -v t2="$t2" \
		'BEGIN{printf "%.1f", (b-a)*1000/((t2-t1)/1000000)}'
}

netem_on() { # dev args
	dev=$1; shift
	tc qdisc add dev "$dev" root netem "$@"
}

netem_off() { # dev
	tc qdisc del dev "$1" root 2>/dev/null || true
}

block_raw() { # drop protocol 253 in both directions (A <-> hub)
	ip netns exec "$A" iptables -A OUTPUT -p 253 -j DROP
	ip netns exec "$HUB" iptables -A OUTPUT -p 253 -j DROP
}

unblock_raw() {
	ip netns exec "$A" iptables -D OUTPUT -p 253 -j DROP 2>/dev/null || true
	ip netns exec "$HUB" iptables -D OUTPUT -p 253 -j DROP 2>/dev/null || true
}

ping_stats() { # outfile count  -> "received loss_pct"
	f=$1; n=$2
	rec=$(grep -c 'bytes from' "$f" || true)
	awk -v n="$n" -v r="$rec" 'BEGIN{printf "%d %.1f", r, (n-r)*100.0/n}'
}

ping_report() { # ns dst count interval wait  -> "received loss_pct" on stdout
	ns=$1; dst=$2; n=$3; iv=$4; w=$5
	out=$(ip netns exec "$ns" ping -c "$n" -i "$iv" -W "$w" "$dst" 2>&1 || true)
	rec=$(printf '%s\n' "$out" | grep -c 'bytes from' || true)
	awk -v n="$n" -v r="$rec" 'BEGIN{printf "%d %.1f", r, (n-r)*100.0/n}'
}
