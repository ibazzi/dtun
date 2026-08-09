#!/bin/bash
# Performance tests on a dedicated two-namespace veth link: TCP/UDP
# throughput, packet rate, latency, MTU sweep, multi-stream aggregate.
set -eu
cd "$(dirname "$0")/../.."
. tests/cdaemon/lib.sh

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

PA=dtp-a
PB=dtp-b

cleanup() {
	for ns in "$PA" "$PB"; do
		ip netns del "$ns" 2>/dev/null || true
	done
	ip link del pA 2>/dev/null || true
}
trap cleanup EXIT INT TERM

section "perf topology: dtp-a <-> dtp-b veth"
cleanup
mod_up
ip netns add "$PA"; ip netns add "$PB"
ip link add pA type veth peer name pB
ip link set pA netns "$PA"; ip link set pB netns "$PB"
ip -n "$PA" link set lo up; ip -n "$PB" link set lo up
ip -n "$PA" addr add 172.30.93.1/24 dev pA; ip -n "$PB" addr add 172.30.93.2/24 dev pB
ip -n "$PA" link set pA up; ip -n "$PB" link set pB up
ip netns exec "$PA" "$IP" link add dtun0 type dtun local 172.30.93.1 udp_port 49000 node_id 1
ip netns exec "$PB" "$IP" link add dtun0 type dtun local 172.30.93.2 udp_port 49000 node_id 2
ip -n "$PA" addr add 10.99.0.1/24 dev dtun0; ip -n "$PB" addr add 10.99.0.2/24 dev dtun0
ip -n "$PA" link set dtun0 up; ip -n "$PB" link set dtun0 up
IFA=$(ip -n "$PA" link show dtun0 | sed -n 's/^\([0-9]*\):.*/\1/p')
IFB=$(ip -n "$PB" link show dtun0 | sed -n 's/^\([0-9]*\):.*/\1/p')
ip netns exec "$PA" "$CTL" peer add --ifname dtun0 --tunnel-id 100 --node-id 2 \
	--raw 172.30.93.2 --udp 172.30.93.2:49000 --key "$KEY"
ip netns exec "$PB" "$CTL" peer add --ifname dtun0 --tunnel-id 100 --node-id 1 \
	--raw 172.30.93.1 --udp 172.30.93.1:49000 --key "$KEY"
ip netns exec "$PA" "$CTL" route-add --ifindex "$IFA" --tunnel-id 100 --prefix 10.99.0.0/24
ip netns exec "$PB" "$CTL" route-add --ifindex "$IFB" --tunnel-id 100 --prefix 10.99.0.0/24
sleep 6
ip netns exec "$PA" ping -c 3 -W 1 10.99.0.2 >/dev/null 2>&1 && ok "perf link up" || fail "perf link ping"

tcp_test() { # name client_ns server_ns target port extra...
	name=$1; cns=$2; sns=$3; target=$4; port=$5; shift 5
	timeout 20 ip netns exec "$sns" iperf3 -s -p "$port" > "$OUT/perf-$name-srv.log" 2>&1 &
	srv=$!
	sleep 1
	timeout 15 ip netns exec "$cns" iperf3 -c "$target" -p "$port" -t 10 "$@" > "$OUT/perf-$name.log" 2>&1 || true
	kill "$srv" 2>/dev/null || true
	line=$(grep 'receiver' "$OUT/perf-$name.log" | tail -1)
	echo "  $name: $line"
}

udp_test() { # name client_ns server_ns target port bw extra...
	name=$1; cns=$2; sns=$3; target=$4; port=$5; bw=$6; shift 6
	timeout 20 ip netns exec "$sns" iperf3 -s -p "$port" > "$OUT/perf-$name-srv.log" 2>&1 &
	srv=$!
	sleep 1
	timeout 15 ip netns exec "$cns" iperf3 -u -c "$target" -p "$port" -t 10 -b "$bw" "$@" > "$OUT/perf-$name.log" 2>&1 || true
	kill "$srv" 2>/dev/null || true
	line=$(grep 'receiver' "$OUT/perf-$name.log" | tail -1)
	echo "  $name: $line"
}

bidir_tcp_test() { # name seconds port-a port-b
	name=$1; seconds=$2; porta=$3; portb=$4
	timeout $((seconds + 15)) ip netns exec "$PA" iperf3 -s -1 -p "$porta" > "$OUT/perf-$name-srv-a.log" 2>&1 &
	sa=$!
	timeout $((seconds + 15)) ip netns exec "$PB" iperf3 -s -1 -p "$portb" > "$OUT/perf-$name-srv-b.log" 2>&1 &
	sb=$!
	sleep 1
	timeout $((seconds + 10)) ip netns exec "$PA" iperf3 -c 10.99.0.2 -p "$portb" -t "$seconds" > "$OUT/perf-$name-a2b.log" 2>&1 &
	ca=$!
	timeout $((seconds + 10)) ip netns exec "$PB" iperf3 -c 10.99.0.1 -p "$porta" -t "$seconds" > "$OUT/perf-$name-b2a.log" 2>&1 &
	cb=$!
	wait "$ca" || true
	wait "$cb" || true
	wait "$sa" || true
	wait "$sb" || true
	if grep -q receiver "$OUT/perf-$name-a2b.log" &&
	   grep -q receiver "$OUT/perf-$name-b2a.log" &&
	   ip netns exec "$PA" ping -c 1 -W 2 10.99.0.2 >/dev/null 2>&1; then
		ok "$name simultaneous bidirectional TCP completed (${seconds}s)"
	else
		fail "$name simultaneous bidirectional TCP failed"
	fi
}

section "TCP throughput (raw preferred)"
tcp_test tcp-a2b "$PA" "$PB" 10.99.0.2 5201
tcp_test tcp-b2a "$PB" "$PA" 10.99.0.1 5202

section "simultaneous bidirectional TCP (raw preferred)"
bidir_tcp_test bidir-raw 30 5210 5211
if [ "${DTUN_LONG_SOAK:-0}" = 1 ]; then
	bidir_tcp_test bidir-raw-soak 300 5212 5213
fi

section "UDP throughput/loss (raw preferred)"
udp_test udp-1g-a2b "$PA" "$PB" 10.99.0.2 5204 1G -l 1200
udp_test udp-1g-b2a "$PB" "$PA" 10.99.0.1 5205 1G -l 1200

section "UDP small-packet rate (pps)"
udp_test udp-pps "$PA" "$PB" 10.99.0.2 5206 0 -l 100

section "UDP-only path (raw cleared) throughput"
ip netns exec "$PA" "$CTL" peer set --ifname dtun0 --tunnel-id 100 --raw 0.0.0.0 --udp 172.30.93.2:49000
ip netns exec "$PB" "$CTL" peer set --ifname dtun0 --tunnel-id 100 --raw 0.0.0.0 --udp 172.30.93.1:49000
sleep 1
udp_test udp-only-500m-a2b "$PA" "$PB" 10.99.0.2 5207 500M -l 1200
tcp_test tcp-udp-only-a2b "$PA" "$PB" 10.99.0.2 5208
bidir_tcp_test bidir-udp 30 5214 5215
if [ "${DTUN_LONG_SOAK:-0}" = 1 ]; then
	bidir_tcp_test bidir-udp-soak 300 5216 5217
fi
ip netns exec "$PA" "$CTL" peer set --ifname dtun0 --tunnel-id 100 --raw 172.30.93.2 --udp 172.30.93.2:49000
ip netns exec "$PB" "$CTL" peer set --ifname dtun0 --tunnel-id 100 --raw 172.30.93.1 --udp 172.30.93.1:49000
sleep 1

section "latency idle"
ip netns exec "$PA" ping -c 200 -i 0.02 -W 1 10.99.0.2 > "$OUT/perf-lat-idle.out" 2>&1 || true
tail -1 "$OUT/perf-lat-idle.out"

section "latency under UDP load (500Mbit/s)"
ip netns exec "$PB" iperf3 -s -p 5209 > "$OUT/perf-lat-srv.log" 2>&1 &
srv=$!
sleep 1
ip netns exec "$PA" iperf3 -u -c 10.99.0.2 -p 5209 -t 15 -b 500M -l 1200 > "$OUT/perf-lat-load.log" 2>&1 &
load=$!
sleep 3
ip netns exec "$PA" ping -c 100 -i 0.02 -W 1 10.99.0.2 > "$OUT/perf-lat-load.out" 2>&1 || true
wait "$load" || true
kill "$srv" 2>/dev/null || true
tail -1 "$OUT/perf-lat-load.out"

section "MTU sweep at default 1200 and raised 1400"
allok=1
for size in 64 500 1000 1172; do
	ip netns exec "$PA" ping -M do -c 1 -W 1 -s "$size" 10.99.0.2 >/dev/null 2>&1 || allok=0
done
ip netns exec "$PA" ping -M do -c 1 -W 1 -s 1173 10.99.0.2 >/dev/null 2>&1 && allok=0
[ "$allok" = 1 ] && ok "MTU 1200: payloads <=1172 pass, 1173 rejected" || fail "MTU 1200 sweep"
ip -n "$PA" link set mtu 1400 dev dtun0
ip -n "$PB" link set mtu 1400 dev dtun0
allok=1
for size in 1000 1372; do
	ip netns exec "$PA" ping -M do -c 1 -W 1 -s "$size" 10.99.0.2 >/dev/null 2>&1 || allok=0
done
ip netns exec "$PA" ping -M do -c 1 -W 1 -s 1373 10.99.0.2 >/dev/null 2>&1 && allok=0
[ "$allok" = 1 ] && ok "MTU 1400: payloads <=1372 pass, 1373 rejected" || fail "MTU 1400 sweep"

summary
