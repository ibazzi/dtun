#!/bin/bash
# Data-plane tests: MTU behaviour, path selection and failover (raw -> UDP ->
# relay -> raw recovery), route drops, malformed/replayed frame rejection.
set -eu
cd "$(dirname "$0")/../.."
. tests/cdaemon/lib.sh

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

cleanup() {
	stop_daemon hub; stop_daemon spoke-$A; stop_daemon spoke-$B
	ip netns del dtc-h2 2>/dev/null || true
	ip netns del dtc-r 2>/dev/null || true
	ip link del dtc-rv 2>/dev/null || true
	ip link del dtc-h2v 2>/dev/null || true
	topo_down
}
trap cleanup EXIT INT TERM

section "setup: hub + spoke A (+ B only as frame sender)"
topo_down
mod_up
rm -f "$OUT/hub.state"
topo_up
hub_conf
start_hub
sleep 1
# Keep periodic registration out of manual candidate/path manipulation below.
spoke_conf "$A" "$A_O" "$A_I" 2 0 300
start_spoke "$A"
wait_reg "$A" 2 && ok "spoke A registered" || fail "spoke A registration"

section "MTU enforcement (default 1200)"
allok=1
for size in 64 500 1000 1100 1172; do
	if ping_ok "$A" "$HUB_I" 1 && ip netns exec "$A" ping -M do -c 1 -W 1 -s "$size" "$HUB_I" >/dev/null 2>&1; then
		:
	else
		allok=0
		echo "  payload $size failed"
	fi
done
[ "$allok" = 1 ] && ok "ping -M do payloads up to 1172 pass (MTU 1200)" || fail "MTU sweep"
if ip netns exec "$A" ping -M do -c 1 -W 1 -s 1173 "$HUB_I" >/dev/null 2>&1; then
	fail "payload 1173 unexpectedly passed (MTU should be 1200)"
else
	ok "payload 1173 rejected (frag needed), MTU 1200 enforced"
fi

section "path selection: raw preferred when healthy"
ip netns exec "$A" iptables -A OUTPUT -p 253 -j ACCEPT
ip netns exec "$A" iptables -A OUTPUT -p udp -m comment --comment dtun-output -j ACCEPT
ip netns exec "$A" iptables -A OUTPUT -p udp --dport 49000 -j ACCEPT
sleep 1
for i in $(seq 1 20); do
	peer_get "$A" 100 | grep -q '"raw_up":true' && break
	sleep 1
done
peer_get "$A" 100 | grep -q '"raw_up":true' && ok "raw_up true after probes" || fail "raw_up never became true"
before=$(ipt_counters "$A")
ip netns exec "$A" ping -c 20 -i 0.2 -W 1 "$HUB_I" >/dev/null 2>&1 || true
after=$(ipt_counters "$A")
set -- $before; br=$1; bu=$2
set -- $after; ar=$1; au=$2
echo "  raw counter: $br -> $ar, udp counter: $bu -> $au"
[ $((ar - br)) -ge 15 ] && ok "data carried on raw protocol 253" || fail "raw not used for data"

section "UDP fallback after clearing raw candidate"
ip netns exec "$A" "$CTL" peer-set --ifindex "$(ifindex "$A")" --tunnel-id 100 \
	--raw 0.0.0.0 --udp 172.30.91.1:49000
# Path health is per side: the hub keeps replying over raw until its own
# raw_seen for A expires (path_timeout_ms defaults to 3s), and A rejects those raw
# replies because its raw candidate is now 0.0.0.0.  Wait for the hub side
# to go stale before asserting UDP-only data.
stale=0
for i in $(seq 1 20); do
	if ip netns exec "$HUB" "$CTL" peer-get --ifindex "$(ifindex "$HUB")" \
		--format json --tunnel-id 101 2>/dev/null | grep -q '"raw_up":false'; then
		stale=1
		break
	fi
	sleep 1
done
[ "$stale" = 1 ] && ok "hub raw path to A went stale after clearing A raw (${i}s)" || fail "hub raw path never went stale"
timeout 8 tcpdump -i "${A}v" -nn 'udp and dst port 49000' > "$OUT/udp-fallback-cap.txt" 2>&1 &
tp=$!
sleep 1
before=$(ipt_counters "$A")
ip netns exec "$A" ping -c 20 -i 0.2 -W 1 "$HUB_I" >/dev/null 2>&1 || true
after=$(ipt_counters "$A")
wait "$tp" || true
udp_n=$(grep -c 'UDP' "$OUT/udp-fallback-cap.txt" || true)
echo "  UDP frames to/from port 49000 captured: ${udp_n:-0}"
[ "${udp_n:-0}" -ge 15 ] && ok "data carried on UDP 49000 after raw cleared" || fail "UDP fallback not used"
set -- $before; bu=$2
set -- $after; au=$2
if [ $((au - bu)) -ge 15 ]; then
	ok "UDP tunnel traffic traversed netfilter OUTPUT"
else
	ip netns exec "$A" iptables -L OUTPUT -v -n -x
	fail "UDP tunnel traffic bypassed netfilter OUTPUT"
fi
peer_get "$A" 100 | grep -q '"raw_up":false' && ok "raw_up false" || fail "raw_up not false"

section "raw recovery after restoring candidate"
ip netns exec "$A" "$CTL" peer-set --ifindex "$(ifindex "$A")" --tunnel-id 100 \
	--raw 172.30.91.1 --udp 172.30.91.1:49000
recovered=0
for i in $(seq 1 25); do
	if peer_get "$A" 100 | grep -q '"raw_up":true'; then
		recovered=1
		break
	fi
	sleep 1
done
[ "$recovered" = 1 ] && ok "raw_up recovered after restoring candidate (${i}s)" || fail "raw never recovered"
before=$(ipt_counters "$A")
ip netns exec "$A" ping -c 20 -i 0.2 -W 1 "$HUB_I" >/dev/null 2>&1 || true
after=$(ipt_counters "$A")
set -- $before; br=$1; bu=$2
set -- $after; ar=$1; au=$2
echo "  raw counter: $br -> $ar, udp counter: $bu -> $au"
[ $((ar - br)) -ge 15 ] && ok "data back on raw after recovery" || fail "raw not preferred after recovery"

section "daemon-configured Hub fallback with direct candidates cleared"
ip netns exec "$A" "$CTL" peer-set --ifindex "$(ifindex "$A")" --tunnel-id 100 \
	--raw 0.0.0.0 --udp 0.0.0.0:0
# The Hub must reply over UDP while the spoke exercises its configured
# fallback; a still-healthy Raw reply would be rejected by the cleared spoke
# candidate before the Hub-side path timeout expires.
ip netns exec "$HUB" "$CTL" peer-set --ifindex "$(ifindex "$HUB")" --tunnel-id 101 \
	--raw 0.0.0.0 --udp 172.30.91.2:49000
if ping_ok "$A" "$HUB_I" 5; then
	ok "Hub fallback carried traffic after peer candidates were cleared"
else
	fail "daemon-configured Hub fallback did not carry traffic"
fi
ip netns exec "$A" "$CTL" peer-set --ifindex "$(ifindex "$A")" --tunnel-id 100 \
	--raw 172.30.91.1 --udp 172.30.91.1:49000

section "relay path (spoke with no raw/UDP candidate, hub address configured)"
ip netns add dtc-h2
ip netns add dtc-r
ip link add dtc-h2v type veth peer name dtc-rv
ip link set dtc-h2v netns dtc-h2
ip link set dtc-rv netns dtc-r
ip -n dtc-h2 link set dtc-h2v name eth0
ip -n dtc-r link set dtc-rv name eth0
ip -n dtc-h2 link set lo up; ip -n dtc-r link set lo up
ip -n dtc-h2 addr add 172.30.92.1/24 dev eth0; ip -n dtc-r addr add 172.30.92.2/24 dev eth0
ip -n dtc-h2 link set eth0 up; ip -n dtc-r link set eth0 up
ip netns exec dtc-h2 "$IP" link add dtun0 type dtun local 172.30.92.1 udp_port 49000 node_id 1
ip netns exec dtc-r "$IP" link add dtun0 type dtun local 172.30.92.2 udp_port 49000 node_id 5 \
	hub 172.30.92.1 hub_port 49000
ip -n dtc-h2 addr add 10.99.0.1/24 dev dtun0
ip -n dtc-r addr add 10.99.0.5/24 dev dtun0
ip -n dtc-h2 link set dtun0 up; ip -n dtc-r link set dtun0 up
IFH2=$(ip -n dtc-h2 link show dtun0 | sed -n 's/^\([0-9]*\):.*/\1/p')
IFR=$(ip -n dtc-r link show dtun0 | sed -n 's/^\([0-9]*\):.*/\1/p')
ip netns exec dtc-h2 "$CTL" peer-add --ifindex "$IFH2" --tunnel-id 100 --remote-tunnel-id 101 \
	--node-id 5 --raw 172.30.92.2 --udp 172.30.92.2:49000 --key "$KEY"
ip netns exec dtc-r "$CTL" peer-add --ifindex "$IFR" --tunnel-id 101 --remote-tunnel-id 100 \
	--node-id 1 --raw 0.0.0.0 --udp 0.0.0.0:0 --key "$KEY"
ip netns exec dtc-h2 "$CTL" route-add --ifindex "$IFH2" --tunnel-id 100 --prefix 10.99.0.5/32
ip netns exec dtc-r "$CTL" route-add --ifindex "$IFR" --tunnel-id 101 --prefix 10.99.0.1/32
ip netns exec dtc-r iptables -A OUTPUT -p udp --dport 49000 -j ACCEPT
sleep 1
timeout 8 ip netns exec dtc-r tcpdump -i eth0 -nn 'udp port 49000' > "$OUT/relay-cap.txt" 2>&1 &
tp=$!
sleep 1
if ip netns exec dtc-r ping -c 5 -W 1 10.99.0.1 >/dev/null 2>&1; then
	ok "relay-path ping works (spoke -> hub via configured hub relay)"
else
	fail "relay-path ping failed"
fi
wait "$tp" || true
relay_n=$(grep -c 'UDP' "$OUT/relay-cap.txt" || true)
[ "${relay_n:-0}" -ge 3 ] && ok "relay frames observed on UDP 49000 ($relay_n)" || fail "no relay frames seen"

section "no-route drop"
ip -n "$A" route add 10.21.0.0/24 dev dtun0
before=$(tx_drop "$A")
ip netns exec "$A" ping -c 1 -W 1 10.21.0.1 >/dev/null 2>&1 || true
after=$(tx_drop "$A")
[ "$after" -gt "$before" ] && ok "unmatched prefix dropped at device (tx_dropped $before -> $after)" || fail "no-route drop not observed"
ip -n "$A" route del 10.21.0.0/24 dev dtun0

section "malformed and replayed frame rejection"
# Point A's UDP candidate at B's spare port so crafted frames exercise ingress
# validation without colliding with the real data path.
ip netns exec "$A" "$CTL" peer-set --ifindex "$(ifindex "$A")" --tunnel-id 100 \
	--raw 0.0.0.0 --udp 172.30.91.3:49001
sleep 1
before_rx=$(rx_pkts "$A")
send() { # extra args
	ip netns exec "$B" python3 "$ROOT/tests/send_frame.py" \
		--destination 172.30.91.2:49000 --source 172.30.91.3 --source-port 49001 \
		--tunnel-id 100 --src-node 1 --dst-node 2 --key "$KEY" "$@"
}
send --bad-tag
send --tunnel-id 101
send --dst-node 9
send --truncated
sleep 1
mid_rx=$(rx_pkts "$A")
[ "$mid_rx" = "$before_rx" ] && ok "invalid frames rejected (rx unchanged)" || fail "invalid frames delivered (rx $before_rx -> $mid_rx)"
# Current design: UDP sources are not pinned pre-authentication; a frame with a
# valid HMAC from a new source port is accepted and its candidate is learned.
send --source-port 49002
sleep 1
learn_rx=$(rx_pkts "$A")
[ $((learn_rx - mid_rx)) -eq 1 ] && ok "changed UDP source port with valid HMAC accepted (candidate learning)" || fail "candidate-learning behaviour changed (rx $mid_rx -> $learn_rx)"
send --seq 100000
send --seq 100000
send --seq 100100
sleep 1
after_rx=$(rx_pkts "$A")
[ $((after_rx - learn_rx)) -eq 2 ] && ok "replay window: duplicates rejected, advancing seqs accepted" || fail "replay window unexpected (rx $learn_rx -> $after_rx)"

summary
