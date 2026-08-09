#!/bin/bash
# Real-internet test: local C spoke -> caller-supplied remote public C hub.
# Conservative public-WAN traffic profile: short directional TCP/UDP runs and
# a modest single-direction UDP soak, avoiding unnecessary provider egress.
set -eu
cd "$(dirname "$0")/../.."
. tests/cdaemon/lib.sh

HUB_PUB=${1:-${HUB_PUB:-}}
case $HUB_PUB in
	''|*[!0-9.]*) echo "usage: $0 HUB_PUBLIC_IPV4" >&2; exit 2 ;;
esac
OUT=/tmp/dtun-real
mkdir -p "$OUT"

cleanup() {
	stop_daemon spoke-real
	if ip link show dtun0 >/dev/null 2>&1; then
		ip link del dtun0 2>/dev/null || true
	fi
}
trap cleanup EXIT INT TERM

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

section "local module + spoke setup"
mod_up
cat > "$OUT/spoke-real.conf" <<EOF
[global]
mode = spoke
interface = dtun0
local_outer_ip = 0.0.0.0
data_port = 49000
node_id = 2
address = 10.99.0.2/24
psk = $KEY

[spoke]
hub_address = $HUB_PUB
hub_port = 49001
local_port = 0
timeout = 4
once = 0
EOF
start_spoke_real() {
	"$DUND" -c "$OUT/spoke-real.conf" > "$OUT/spoke-real.log" 2>&1 &
	echo $! > "$OUT/spoke-real.pid"
}
start_spoke_real
registered=0
for i in $(seq 1 30); do
	if grep -q "Registration successful! NodeID=2" "$OUT/spoke-real.log" 2>/dev/null; then
		registered=1
		break
	fi
	sleep 1
done
if [ "$registered" = 1 ]; then
	ok "local spoke registered with remote hub"
	grep "Registration successful" "$OUT/spoke-real.log" | tail -1
else
	fail "spoke registration timed out"
	tail -10 "$OUT/spoke-real.log"
fi

section "peer state (remote hub session)"
IFACE=$(cat /sys/class/net/dtun0/ifindex 2>/dev/null || echo "")
if [ -n "$IFACE" ]; then
	peer=$("$CTL" peer get --format json --ifname dtun0 --tunnel-id 100 2>/dev/null || true)
	echo "$peer"
	echo "$peer" | grep -q '"udp_up":true' && ok "hub UDP candidate up" || fail "hub UDP candidate down"
else
	fail "no dtun0 interface"
fi

section "ping hub inner address (jitter/MTU)"
if ping -c 20 -W 1 10.99.0.1 >/dev/null 2>&1; then
	ok "ping 10.99.0.1 works"
else
	fail "ping 10.99.0.1"
fi
ping -c 30 -i 0.2 -W 1 10.99.0.1 > "$OUT/ping.out" 2>&1 || true
tail -3 "$OUT/ping.out"

section "MTU sweep over real internet"
allok=1
for size in 64 500 1000 1172; do
	ping -M do -c 1 -W 1 -s "$size" 10.99.0.1 >/dev/null 2>&1 || allok=0
done
ping -M do -c 1 -W 1 -s 1173 10.99.0.1 >/dev/null 2>&1 && allok=0
[ "$allok" = 1 ] && ok "MTU 1200 enforced over real internet" || fail "MTU sweep failed"

section "TCP spoke -> hub (15s, single direction)"
timeout 25 iperf3 -c 10.99.0.1 -t 15 > "$OUT/tcp-s2h.log" 2>&1 || true
grep 'receiver' "$OUT/tcp-s2h.log" | tail -1 || echo "no receiver line"

section "TCP hub -> spoke (15s, single direction)"
timeout 25 iperf3 -c 10.99.0.1 -t 15 -R > "$OUT/tcp-h2s.log" 2>&1 || true
grep 'receiver' "$OUT/tcp-h2s.log" | tail -1 || echo "no receiver line"

section "UDP spoke -> hub (20s @ 20M)"
timeout 30 iperf3 -u -c 10.99.0.1 -t 20 -b 20M -l 1200 > "$OUT/udp-s2h.log" 2>&1 || true
grep 'receiver' "$OUT/udp-s2h.log" | tail -1 || echo "no receiver line"

section "UDP hub -> spoke (20s @ 20M)"
timeout 30 iperf3 -u -c 10.99.0.1 -t 20 -b 20M -l 1200 -R > "$OUT/udp-h2s.log" 2>&1 || true
grep 'receiver' "$OUT/udp-h2s.log" | tail -1 || echo "no receiver line"

section "single-direction UDP soak (300s @ 10M) with ping monitor"
timeout 320 iperf3 -u -c 10.99.0.1 -t 300 -b 10M -l 1200 > "$OUT/soak.log" 2>&1 &
soak=$!
( i=0; while [ $i -lt 150 ]; do
	ping -c 1 -W 1 10.99.0.1 >/dev/null 2>&1 && echo OK >> "$OUT/soak-ping.log" || echo LOSS >> "$OUT/soak-ping.log"
	sleep 2; i=$((i+1))
done ) &
mon=$!
wait "$soak" || true
wait "$mon" || true
ping -c 3 -W 1 10.99.0.1 >/dev/null 2>&1 || true
grep 'receiver' "$OUT/soak.log" | tail -1 || echo "no receiver line"
pk=$(grep -c OK "$OUT/soak-ping.log" || true)
pl=$(grep -c LOSS "$OUT/soak-ping.log" || true)
echo "  soak pings: $pk ok, $pl loss"
[ "$pl" -le 10 ] && ok "soak ping loss acceptable" || fail "soak ping loss $pl"

section "spoke daemon CPU/RSS during soak"
pid=$(cat "$OUT/spoke-real.pid")
echo "  spoke: cpu $(cpu_pct "$pid")%  rss $(awk '/VmRSS/{print $2}' /proc/$pid/status)kB"

summary
