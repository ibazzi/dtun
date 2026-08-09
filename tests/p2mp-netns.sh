#!/bin/sh
# Isolated C Hub + two-spoke direct-path regression. Run as root.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IP=${IP:-"$ROOT/bin/ip"}
DUND=${DUND:-"$ROOT/build/dtund"}
CTL=${CTL:-"$ROOT/build/dtunctl"}
MULTICAST=${MULTICAST:-"$ROOT/tests/multicast.py"}
KEY=${KEY:-00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff}
PREFIX=dtunp2
HUB=${PREFIX}h
A=${PREFIX}a
B=${PREFIX}b
BR=${PREFIX}br
OUT=/tmp/dtun-p2mp
RAW_TRANSPORT=${RAW_TRANSPORT:-false}
CALIBRATION_SMOKE=${CALIBRATION_SMOKE:-0}

fail() {
	echo "dtun p2mp test: $*" >&2
	exit 1
}

stop_pid() {
	file=$1
	if [ -f "$file" ]; then
		kill -TERM "$(cat "$file")" 2>/dev/null || true
		wait "$(cat "$file")" 2>/dev/null || true
		rm -f "$file"
	fi
}

cleanup() {
	stop_pid "$OUT/heartbeat.pid"
	stop_pid "$OUT/mcast-hub.pid"
	stop_pid "$OUT/mcast-b.pid"
	stop_pid "$OUT/a.pid"
	stop_pid "$OUT/b.pid"
	stop_pid "$OUT/hub.pid"
	ip netns del "$HUB" 2>/dev/null || true
	ip netns del "$A" 2>/dev/null || true
	ip netns del "$B" 2>/dev/null || true
	ip link del "$BR" 2>/dev/null || true
	iptables -D FORWARD -i "$BR" -j ACCEPT 2>/dev/null || true
	iptables -D FORWARD -o "$BR" -j ACCEPT 2>/dev/null || true
	ip link del "${HUB}v" 2>/dev/null || true
	ip link del "${A}v" 2>/dev/null || true
	ip link del "${B}v" 2>/dev/null || true
	[ "${KEEP:-0}" = 1 ] || rm -rf "$OUT"
}
trap cleanup EXIT INT TERM
cleanup
mkdir -p "$OUT"
if ! lsmod | grep -q '^dtun '; then
	modprobe dtun 2>/dev/null || insmod "$ROOT/build/dtun.ko"
fi

ip link add "$BR" type bridge
ip link set "$BR" up
iptables -I FORWARD -i "$BR" -j ACCEPT
iptables -I FORWARD -o "$BR" -j ACCEPT
for spec in "$HUB:1" "$A:2" "$B:3"; do
	ns=${spec%:*}; octet=${spec#*:}; hostv=${ns}v
	ip netns add "$ns"
	ip link add "$hostv" type veth peer name eth0 netns "$ns"
	ip link set "$hostv" master "$BR"
	ip link set "$hostv" up
	ip -n "$ns" link set lo up
	ip -n "$ns" addr add "172.30.90.$octet/24" dev eth0
	ip -n "$ns" link set eth0 up
done
ip netns exec "$HUB" sysctl -qw net.ipv4.ip_forward=1

cat > "$OUT/no-ha.conf" <<EOF
[ha]
enabled = false
EOF

cat > "$OUT/hub.conf" <<EOF
[global]
mode = hub
interface = dtun0
local_outer_ip = 172.30.90.1
raw_transport = false
data_port = 49000
node_id = 1
address = 10.99.0.1/24
psk = $KEY
ha_config = $OUT/no-ha.conf
[hub]
bind_address = 0.0.0.0
bind_port = 49001
pool = 10.99.0.0/24
state_file = $OUT/hub.state
EOF

spoke_config() {
	name=$1; outer=$2; node=$3; inner=$4
	cat > "$OUT/$name.conf" <<EOF
[global]
mode = spoke
interface = dtun0
local_outer_ip = 0.0.0.0
raw_transport = $RAW_TRANSPORT
data_port = 49000
node_id = $node
address = $inner/24
psk = $KEY
[spoke]
hub_address = 172.30.90.1
hub_port = 49001
local_port = 0
timeout = 2
once = false
EOF
}

spoke_config a 172.30.90.2 2 10.99.0.2
spoke_config b 172.30.90.3 3 10.99.0.3
ip netns exec "$HUB" "$DUND" -c "$OUT/hub.conf" > "$OUT/hub.log" 2>&1 &
echo $! > "$OUT/hub.pid"
sleep 1
ip netns exec "$A" "$DUND" -c "$OUT/a.conf" > "$OUT/a.log" 2>&1 &
echo $! > "$OUT/a.pid"
ip netns exec "$B" "$DUND" -c "$OUT/b.conf" > "$OUT/b.log" 2>&1 &
echo $! > "$OUT/b.pid"

for i in $(seq 1 20); do
	grep -q 'Registration successful! NodeID=2' "$OUT/a.log" 2>/dev/null &&
	grep -q 'Registration successful! NodeID=3' "$OUT/b.log" 2>/dev/null && break
	sleep 1
done
grep -q 'Registration successful! NodeID=2' "$OUT/a.log"
grep -q 'Registration successful! NodeID=3' "$OUT/b.log"

direct=0
for i in $(seq 1 25); do
	ifa=$(ip -n "$A" link show dtun0 2>/dev/null | sed -n 's/^\([0-9]*\):.*/\1/p')
	ifb=$(ip -n "$B" link show dtun0 2>/dev/null | sed -n 's/^\([0-9]*\):.*/\1/p')
	if [ -n "$ifa" ] && [ -n "$ifb" ] &&
	   ip netns exec "$A" "$CTL" peer get --format json --ifname dtun0 --tunnel-id 104 2>/dev/null | grep -q '"node_id":3' &&
	   ip netns exec "$B" "$CTL" peer get --format json --ifname dtun0 --tunnel-id 105 2>/dev/null | grep -q '"node_id":2'; then
		direct=1
		break
	fi
	sleep 1
done
[ "$direct" = 1 ] || { echo "direct peers not installed" >&2; exit 1; }

expected_path=udp
[ "$CALIBRATION_SMOKE" = 1 ] && expected_path=raw
for i in $(seq 1 20); do
	if ip netns exec "$A" "$CTL" peer get --format json --ifname dtun0 \
		--tunnel-id 104 2>/dev/null | grep -q "\"selected_path\":\"$expected_path\"" &&
	   ip netns exec "$B" "$CTL" peer get --format json --ifname dtun0 \
		--tunnel-id 105 2>/dev/null | grep -q "\"selected_path\":\"$expected_path\""; then
		direct=2
		break
	fi
	sleep 1
done
[ "$direct" = 2 ] || fail "authenticated $expected_path direct path did not become active"
grep -q 'Hole punching started for NodeID=3' "$OUT/a.log" ||
	fail "Spoke A did not log UDP hole punching"

if [ "$CALIBRATION_SMOKE" = 1 ]; then
	udp_standby=0
	for i in $(seq 1 40); do
		if ip netns exec "$A" "$CTL" peer get --format json --ifname dtun0 \
			--tunnel-id 104 2>/dev/null | grep -q '"udp_up":true' &&
		   ip netns exec "$B" "$CTL" peer get --format json --ifname dtun0 \
			--tunnel-id 105 2>/dev/null | grep -q '"udp_up":true'; then
			udp_standby=1
			break
		fi
		sleep 0.1
	done
	[ "$udp_standby" = 1 ] || fail "standby UDP did not authenticate"
	command -v tcpdump >/dev/null 2>&1 || fail "tcpdump is required"
	calibration_started=$(date +%s.%N)
	tcpdump -ni "$BR" -w "$OUT/calibration.pcap" \
		'udp port 49000 and host 172.30.90.2 and host 172.30.90.3' \
		> "$OUT/calibration.log" 2>&1 &
	echo $! > "$OUT/heartbeat.pid"
	ip netns exec "$A" ping -c 20 -i 0.5 -W 1 10.99.0.3 >/dev/null
	sleep 3
	calibration_ended=$(date +%s.%N)
	kill -INT "$(cat "$OUT/heartbeat.pid")" 2>/dev/null || true
	wait "$(cat "$OUT/heartbeat.pid")" 2>/dev/null || true
	rm -f "$OUT/heartbeat.pid"
	calibration_packets=$(tcpdump -nr "$OUT/calibration.pcap" 2>/dev/null | wc -l)
	[ "$calibration_packets" -ge 2 ] || fail "calibration BEGIN/ACK not captured"
	calibration_gap=$(tcpdump -tt -nr "$OUT/calibration.pcap" 2>/dev/null | \
		awk -v started="$calibration_started" -v ended="$calibration_ended" \
		'NR == 1 { previous=$1; maximum=previous-started; next }
		 { gap=$1-previous; if (gap > maximum) maximum=gap; previous=$1 }
		 END { gap=ended-previous; if (gap > maximum) maximum=gap; printf "%.3f", maximum+0 }')
	awk -v gap="$calibration_gap" 'BEGIN { exit !(gap >= 4.0) }' ||
		fail "standby UDP did not enter the 5s calibration silence: ${calibration_gap}s"
	echo "dtun NAT calibration smoke passed; maximum standby UDP silence ${calibration_gap}s"
	exit 0
fi

grep -Eq 'Direct UDP established for|Direct path recovered for.*Direct UDP' \
	"$OUT/a.log" || fail "Spoke A did not log UDP direct establishment"

# A selected UDP path needs only its 1--1.25 second state heartbeat.  Count
# only direct A<->B traffic so the independent Hub liveness stream is excluded.
if command -v tcpdump >/dev/null 2>&1; then
	tcpdump -ni "$BR" -w "$OUT/heartbeat.pcap" \
		'udp port 49000 and host 172.30.90.2 and host 172.30.90.3' \
		> "$OUT/heartbeat.log" 2>&1 &
	echo $! > "$OUT/heartbeat.pid"
	sleep 30
	kill -INT "$(cat "$OUT/heartbeat.pid")" 2>/dev/null || true
	wait "$(cat "$OUT/heartbeat.pid")" 2>/dev/null || true
	rm -f "$OUT/heartbeat.pid"
	heartbeat_packets=$(tcpdump -nr "$OUT/heartbeat.pcap" 2>/dev/null | wc -l)
	[ "$heartbeat_packets" -ge 60 ] ||
		fail "too few direct heartbeat packets: $heartbeat_packets"
	[ "$heartbeat_packets" -le 180 ] ||
		fail "direct heartbeat rate was not reduced: $heartbeat_packets packets/30s"
	echo "dtun selected UDP heartbeat count: $heartbeat_packets packets/30s"
else
	echo "dtun p2mp test: tcpdump unavailable; heartbeat packet count skipped" >&2
fi

# Disable inner forwarding: /32 direct routes must continue to work without it.
ip netns exec "$HUB" sysctl -qw net.ipv4.ip_forward=0
ip netns exec "$A" ping -c 3 -W 2 10.99.0.3
ip netns exec "$B" ping -c 3 -W 2 10.99.0.2

# Block only the two direct rendezvous endpoints.  Hub forwarding must remain
# available, then removing the rules must recover authenticated UDP direct.
ip netns exec "$HUB" sysctl -qw net.ipv4.ip_forward=1
ip netns exec "$A" iptables -I OUTPUT -p udp -d 172.30.90.3 --dport 49000 -j DROP
ip netns exec "$B" iptables -I OUTPUT -p udp -d 172.30.90.2 --dport 49000 -j DROP
fallback=0
for i in $(seq 1 30); do
	if ip netns exec "$A" "$CTL" peer get --format json --ifname dtun0 \
		--tunnel-id 104 2>/dev/null | grep -q '"selected_path":"hub"'; then
		fallback=1
		break
	fi
	sleep 0.1
done
[ "$fallback" = 1 ] || fail "direct path did not fall back to Hub"
ip netns exec "$A" ping -c 2 -W 2 10.99.0.3
for i in $(seq 1 20); do
	grep -q 'Falling back to Hub for NodeID=3' "$OUT/a.log" && break
	sleep 0.1
done
grep -q 'Falling back to Hub for NodeID=3' "$OUT/a.log" ||
	fail "Spoke A did not log Hub fallback"
ip netns exec "$A" iptables -D OUTPUT -p udp -d 172.30.90.3 --dport 49000 -j DROP
ip netns exec "$B" iptables -D OUTPUT -p udp -d 172.30.90.2 --dport 49000 -j DROP
recovered=0
for i in $(seq 1 30); do
	if ip netns exec "$A" "$CTL" peer get --format json --ifname dtun0 \
		--tunnel-id 104 2>/dev/null | grep -q '"selected_path":"udp"'; then
		recovered=1
		break
	fi
	sleep 0.1
done
[ "$recovered" = 1 ] || fail "UDP direct path did not recover"
for i in $(seq 1 20); do
	grep -q 'Direct path recovered for NodeID=3 via Direct UDP' "$OUT/a.log" &&
		break
	sleep 0.1
done
grep -q 'Direct path recovered for NodeID=3 via Direct UDP' "$OUT/a.log" ||
	fail "Spoke A did not log direct recovery"

# Multicast does not have a single prefix owner.  One packet from A must be
# replicated to both its Hub peer and its direct B peer.
ip -n "$A" route add 239.192.0.1/32 dev dtun0
ip netns exec "$HUB" python3 "$MULTICAST" receive --group 239.192.0.1 \
	--interface 10.99.0.1 --port 50000 --message dtun-multicast \
	> "$OUT/mcast-hub.out" &
echo $! > "$OUT/mcast-hub.pid"
ip netns exec "$B" python3 "$MULTICAST" receive --group 239.192.0.1 \
	--interface 10.99.0.3 --port 50000 --message dtun-multicast \
	> "$OUT/mcast-b.out" &
echo $! > "$OUT/mcast-b.pid"
sleep 1
ip netns exec "$A" python3 "$MULTICAST" send --group 239.192.0.1 \
	--interface 10.99.0.2 --port 50000 --message dtun-multicast
wait "$(cat "$OUT/mcast-hub.pid")" || {
	rm -f "$OUT/mcast-hub.pid"
	fail "Hub did not receive multicast"
}
rm -f "$OUT/mcast-hub.pid"
wait "$(cat "$OUT/mcast-b.pid")" || {
	rm -f "$OUT/mcast-b.pid"
	fail "Spoke did not receive multicast"
}
rm -f "$OUT/mcast-b.pid"
grep -qx 'dtun-multicast' "$OUT/mcast-hub.out" || fail "Hub multicast payload mismatch"
grep -qx 'dtun-multicast' "$OUT/mcast-b.out" || fail "Spoke multicast payload mismatch"

# A graceful stop removes the Spoke from the Hub and informs surviving Spokes
# immediately.  Stable identity and session allocations remain persisted.
hub_b_tunnel=$(ip netns exec "$HUB" "$CTL" peer list --format json \
	--ifname dtun0 | python3 -c \
	'import json,sys; print(next(p["tunnel_id"] for p in json.load(sys.stdin) if p["node_id"] == 3))')
leave_started=$(date +%s%3N)
stop_pid "$OUT/b.pid"
expired=0
for i in $(seq 1 40); do
	if ! ip netns exec "$HUB" "$CTL" peer get --ifname dtun0 \
			--tunnel-id "$hub_b_tunnel" >/dev/null 2>&1 &&
	   ! ip netns exec "$A" "$CTL" peer get --ifname dtun0 \
		--tunnel-id 104 >/dev/null 2>&1; then
		expired=1
		break
	fi
	sleep 0.05
done
[ "$expired" = 1 ] || fail "offline Spoke was not removed from Hub active paths"
leave_elapsed=$(( $(date +%s%3N) - leave_started ))
[ "$leave_elapsed" -le 2000 ] || fail "graceful offline propagation exceeded 2000ms"
grep -q 'Marked Spoke NodeID=3.*authenticated graceful LEAVE' "$OUT/hub.log" ||
	fail "Hub did not log authenticated graceful offline"
grep -q 'Hub acknowledged graceful offline for NodeID=3' "$OUT/b.log" ||
	fail "Spoke B did not receive graceful offline acknowledgement"
grep -q 'Peer NodeID=3 is offline; removing direct peer' "$OUT/a.log" ||
	fail "Spoke A did not apply explicit offline state"

# Re-registering with the retained identity reinstalls the same pair session.
ip netns exec "$B" "$DUND" -c "$OUT/b.conf" >> "$OUT/b.log" 2>&1 &
echo $! > "$OUT/b.pid"
reused=0
for i in $(seq 1 40); do
	if ip netns exec "$A" "$CTL" peer get --format json --ifname dtun0 \
		--tunnel-id 104 2>/dev/null | grep -q '"node_id":3'; then
		reused=1
		break
	fi
	sleep 0.1
done
[ "$reused" = 1 ] || fail "retained Spoke identity/session was not reused"
echo "dtun C point-to-multipoint netns regression passed"
