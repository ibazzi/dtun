#!/bin/sh
# Privileged regression suite.  Requires an ip binary built with iplink_dtun.c.
set -eu

IP=${IP:-ip}
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CTL=${CTL:-"$ROOT/build/dtunctl"}
FRAME=${FRAME:-"$ROOT/tests/send_frame.py"}
RECEIVER=${RECEIVER:-"$ROOT/tests/receive_frame.py"}
KEY=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff

cleanup() {
	$IP netns del dtun-a 2>/dev/null || true
	$IP netns del dtun-b 2>/dev/null || true
}
fail() {
	echo "dtun test: $*" >&2
	exit 1
}
rx_packets() {
	$IP netns exec dtun-a cat /sys/class/net/dtun0/statistics/rx_packets
}
send_frame() {
	$IP netns exec dtun-b python3 "$FRAME" --destination 172.31.0.1:49000 \
		--source 172.31.0.2 "$@"
}

trap cleanup EXIT INT TERM

[ "$(id -u)" = 0 ] || fail "run as root"
[ -e "$ROOT/build/dtun.ko" ] || [ -e "$ROOT/dtun.ko" ] || fail "build dtun.ko first"
command -v "$IP" >/dev/null 2>&1 || fail "IP command not found: $IP"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"
command -v ping >/dev/null 2>&1 || fail "ping is required"
if ! lsmod | grep -q '^dtun '; then
	modprobe dtun 2>/dev/null || insmod "$ROOT/build/dtun.ko" 2>/dev/null || insmod "$ROOT/dtun.ko"
fi

$IP netns add dtun-a
$IP netns add dtun-b
$IP link add da type veth peer name db
$IP link set da netns dtun-a
$IP link set db netns dtun-b
$IP -n dtun-a addr add 172.31.0.1/24 dev da
$IP -n dtun-b addr add 172.31.0.2/24 dev db
$IP -n dtun-a link set lo up
$IP -n dtun-b link set lo up
$IP -n dtun-a link set da up
$IP -n dtun-b link set db up

# A zero local address must use the source selected by the outer route.  This
# is the daemon default and keeps simple configurations interface-independent.
$IP netns exec dtun-a $IP link add dtun0 type dtun local 0.0.0.0 udp_port 49000 node_id 1
$IP netns exec dtun-b $IP link add dtun0 type dtun local 0.0.0.0 udp_port 49000 node_id 2
$IP -n dtun-a addr add 10.20.0.1/24 dev dtun0
$IP -n dtun-b addr add 10.20.0.2/24 dev dtun0
$IP -n dtun-a link set dtun0 up
$IP -n dtun-b link set dtun0 up

IFA=$($IP netns exec dtun-a cat /sys/class/net/dtun0/ifindex)
IFB=$($IP netns exec dtun-b cat /sys/class/net/dtun0/ifindex)
$IP netns exec dtun-a "$CTL" peer-add --ifname dtun0 --tunnel-id 100 --node-id 2 --raw 172.31.0.2 --udp 172.31.0.2:49000 --key "$KEY"
$IP netns exec dtun-b "$CTL" peer-add --ifname dtun0 --tunnel-id 100 --node-id 1 --raw 172.31.0.1 --udp 172.31.0.1:49000 --key "$KEY"
$IP netns exec dtun-a "$CTL" route-add --ifindex "$IFA" --tunnel-id 100 --prefix 10.20.0.0/24
$IP netns exec dtun-b "$CTL" route-add --ifindex "$IFB" --tunnel-id 100 --prefix 10.20.0.0/24

# Generic Netlink multipart peer dump and both CLI formats.
$IP netns exec dtun-a "$CTL" peer-list --ifname dtun0 | grep -q '^IFNAME' || \
	fail "peer-list human output missing table header"
$IP netns exec dtun-a "$CTL" peer-list --ifname dtun0 --format json | \
	grep -q '^\[{"ifname":"dtun0","tunnel_id":100' || fail "peer-list JSON output missing peer"
$IP netns exec dtun-a $IP link add dtun1 type dtun local 0.0.0.0 udp_port 49100 node_id 9
$IP -n dtun-a link set dtun1 up
$IP netns exec dtun-a "$CTL" peer-add --ifname dtun1 --tunnel-id 200 \
	--node-id 10 --raw 172.31.0.2 --udp 172.31.0.2:49100 --key "$KEY"
$IP netns exec dtun-a "$CTL" peer-list --format json | \
	python3 -c 'import json,sys; p=json.load(sys.stdin); assert [(x["ifname"],x["tunnel_id"]) for x in p] == [("dtun0",100),("dtun1",200)]' || \
	fail "peer-list did not merge and sort all dtun interfaces"
$IP -n dtun-a link del dtun1

# Initial probes make both transports healthy; Raw is then the preferred path.
sleep 6
$IP netns exec dtun-a ping -c 3 -W 1 10.20.0.2
$IP netns exec dtun-a ping -M do -c 3 -W 1 -s 1100 10.20.0.2

# A more-specific route must win over the existing /24 route.  Give peer 101 a
# distinct UDP port and inspect an actual DATA frame rather than inferring the
# selected peer from a transmit-error counter.
$IP netns exec dtun-a "$CTL" peer-add --ifname dtun0 --tunnel-id 101 --node-id 3 --raw 0.0.0.0 --udp 172.31.0.2:49001 --key "$KEY"
$IP netns exec dtun-a "$CTL" route-add --ifindex "$IFA" --tunnel-id 101 --prefix 10.20.0.2/32
$IP netns exec dtun-b python3 "$RECEIVER" --bind 172.31.0.2:49001 \
	--dst-node 3 --key "$KEY" > /tmp/dtun-lpm.out &
receiver_pid=$!
sleep 2
$IP netns exec dtun-a ping -c 1 -W 1 10.20.0.2 >/dev/null 2>&1 || true
wait "$receiver_pid" || fail "longest-prefix DATA frame was not observed"
[ "$(cat /tmp/dtun-lpm.out)" = 3 ] || fail "longest-prefix route selected the wrong peer"
rm -f /tmp/dtun-lpm.out
$IP netns exec dtun-a "$CTL" route-del --ifindex "$IFA" --tunnel-id 101 --prefix 10.20.0.2/32
$IP netns exec dtun-a "$CTL" peer-del --ifname dtun0 --tunnel-id 101

# A destination without a configured prefix must be dropped by dtun rather than
# sent to an arbitrary peer.
$IP -n dtun-a route add 10.21.0.0/24 dev dtun0
before_drop=$($IP netns exec dtun-a cat /sys/class/net/dtun0/statistics/tx_dropped)
$IP netns exec dtun-a ping -c 1 -W 1 10.21.0.1 >/dev/null 2>&1 || true
after_drop=$($IP netns exec dtun-a cat /sys/class/net/dtun0/statistics/tx_dropped)
[ "$after_drop" -gt "$before_drop" ] || fail "unmatched prefix was not dropped"

# Clear Raw candidates to force UDP, then restore them and allow the regular
# probes to mark Raw healthy again.  This avoids relying on netfilter ordering
# relative to the IPv4 protocol handler.
$IP netns exec dtun-a "$CTL" peer-set --ifname dtun0 --tunnel-id 100 --raw 0.0.0.0 --udp 172.31.0.2:49000
$IP netns exec dtun-b "$CTL" peer-set --ifname dtun0 --tunnel-id 100 --raw 0.0.0.0 --udp 172.31.0.1:49000
sleep 6
if [ "${DEBUG:-0}" = 1 ]; then
	$IP netns exec dtun-a "$CTL" peer-get --ifname dtun0 --tunnel-id 100
	$IP netns exec dtun-b "$CTL" peer-get --ifname dtun0 --tunnel-id 100
fi
$IP netns exec dtun-a ping -c 3 -W 1 10.20.0.2
$IP netns exec dtun-a "$CTL" peer-set --ifname dtun0 --tunnel-id 100 --raw 172.31.0.2 --udp 172.31.0.2:49000
$IP netns exec dtun-b "$CTL" peer-set --ifname dtun0 --tunnel-id 100 --raw 172.31.0.1 --udp 172.31.0.1:49000
sleep 6
$IP netns exec dtun-a ping -c 3 -W 1 10.20.0.2

# Point A's expected UDP candidate at a spare source port so crafted frames can
# exercise ingress validation without colliding with B's dtun UDP socket.
$IP netns exec dtun-a "$CTL" peer-set --ifname dtun0 --tunnel-id 100 --udp 172.31.0.2:49001
before_rx=$(rx_packets)
send_frame --source-port 49001 --tunnel-id 100 --src-node 2 --dst-node 1 --bad-tag --key "$KEY"
send_frame --source-port 49001 --tunnel-id 101 --src-node 2 --dst-node 1 --key "$KEY"
send_frame --source-port 49001 --tunnel-id 100 --src-node 2 --dst-node 9 --key "$KEY"
send_frame --source-port 49001 --truncated --tunnel-id 100 --src-node 2 --dst-node 1 --key "$KEY"
sleep 1
[ "$(rx_packets)" = "$before_rx" ] || fail "invalid frame reached dtun device"

# A valid HMAC from a changed UDP source port is accepted and becomes the new
# authenticated candidate.
send_frame --source-port 49002 --tunnel-id 100 --src-node 2 --dst-node 1 --seq 90000 --key "$KEY"
sleep 1
learn_rx=$(rx_packets)
[ "$learn_rx" -eq $((before_rx + 1)) ] || fail "authenticated candidate update was not delivered"
$IP netns exec dtun-a "$CTL" peer-get --format json --ifname dtun0 --tunnel-id 100 | \
	grep -q '"direct_udp":"172.31.0.2:49002"' || fail "authenticated UDP source port was not learned"

# Two advancing frames are delivered; their duplicate is rejected by the
# receive replay window.
send_frame --source-port 49002 --tunnel-id 100 --src-node 2 --dst-node 1 --seq 100000 --key "$KEY"
send_frame --source-port 49002 --tunnel-id 100 --src-node 2 --dst-node 1 --seq 100100 --key "$KEY"
send_frame --source-port 49002 --tunnel-id 100 --src-node 2 --dst-node 1 --seq 100000 --key "$KEY"
sleep 1
after_rx=$(rx_packets)
[ "$after_rx" -eq $((learn_rx + 2)) ] || fail "replay-window validation failed"

echo "dtun privileged netns regression test passed"
