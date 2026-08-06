#!/bin/bash
# Stability tests under network impairment, path failover timing, sustained
# bidirectional load, link flaps and full module reload.
set -eu
cd "$(dirname "$0")/../.."
. tests/cdaemon/lib.sh

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

cleanup() {
	unblock_raw
	stop_daemon hub; stop_daemon spoke-$A
	topo_down
}
trap cleanup EXIT INT TERM

section "setup: hub + spoke A"
topo_down
mod_up
rm -f "$OUT/hub.state"
topo_up
hub_conf
start_hub
sleep 1
spoke_conf "$A" "$A_O" "$A_I" 2
start_spoke "$A"
wait_reg "$A" 2 && ok "spoke A registered" || fail "spoke A registration"
ping_ok "$A" "$HUB_I" 3

section "packet loss 1% (both directions)"
netem_on dtc-hv loss 1%
netem_on dtc-av loss 1%
sleep 1
read rec loss <<< "$(ping_report "$A" "$HUB_I" 100 0.2 1)"
echo "  received $rec/100, loss ${loss}%"
[ "$rec" -ge 96 ] && ok "1% netem loss: tunnel functional (loss ${loss}%)" || fail "1% loss: excessive loss ${loss}%"
netem_off dtc-hv; netem_off dtc-av

section "packet loss 5% (both directions)"
netem_on dtc-hv loss 5%
netem_on dtc-av loss 5%
sleep 1
read rec loss <<< "$(ping_report "$A" "$HUB_I" 100 0.2 1)"
echo "  received $rec/100, loss ${loss}%"
[ "$rec" -ge 85 ] && ok "5% netem loss: tunnel functional (loss ${loss}%)" || fail "5% loss: excessive loss ${loss}%"
netem_off dtc-hv; netem_off dtc-av

section "latency 50ms +/-10ms (both directions)"
netem_on dtc-hv delay 50ms 10ms
netem_on dtc-av delay 50ms 10ms
sleep 1
delay_out=$(ip netns exec "$A" ping -c 30 -i 0.2 -W 1 "$HUB_I" 2>&1 || true)
printf '%s\n' "$delay_out" | tail -2 | head -1
avg=$(printf '%s\n' "$delay_out" | sed -n 's/.*= [0-9.]*\/\([0-9.]*\)\/.*/\1/p')
echo "  avg RTT: ${avg}ms (expected ~100ms, one-way 50ms each direction)"
awk -v a="$avg" 'BEGIN{exit !(a>80 && a<130)}' && ok "delay budget respected (avg ${avg}ms)" || fail "delay budget off (avg ${avg}ms)"
netem_off dtc-hv; netem_off dtc-av

section "packet reorder 25% (delay 20ms + reorder 25%)"
netem_on dtc-hv delay 20ms reorder 25%
netem_on dtc-av delay 20ms reorder 25%
sleep 1
read rec loss <<< "$(ping_report "$A" "$HUB_I" 50 0.2 2)"
echo "  received $rec/50, loss ${loss}%"
[ "$rec" -ge 40 ] && ok "reorder 25%: tunnel survives" || fail "reorder 25%: loss ${loss}%"
netem_off dtc-hv; netem_off dtc-av

section "duplication 10% (replay window must absorb dups)"
netem_on dtc-hv dup 10%
netem_on dtc-av dup 10%
sleep 1
read rec loss <<< "$(ping_report "$A" "$HUB_I" 50 0.2 1)"
echo "  received $rec/50, loss ${loss}%"
[ "$rec" -ge 48 ] && ok "duplication 10%: replay window rejects dups cleanly" || fail "dup 10%: loss ${loss}%"
netem_off dtc-hv; netem_off dtc-av

section "path failover timing: raw blocked for 25s, then restored"
unblock_raw
sleep 2
ip netns exec "$A" ping -c 260 -i 0.2 -W 1 "$HUB_I" > "$OUT/failover.out" 2>&1 &
pingpid=$!
sleep 10
block_raw
echo "  raw blocked at t=10s"
sleep 25
unblock_raw
echo "  raw restored at t=35s"
wait "$pingpid" || true
python3 - "$OUT/failover.out" <<'EOF'
import re, sys
seqs = [int(m) for m in re.findall(r"icmp_seq=(\d+)", open(sys.argv[1]).read())]
gaps = []
prev = 0
for s in seqs:
    if s - prev > 1:
        gaps.append((prev + 1, s - 1, (s - prev - 1) * 0.2))
    prev = s
recv = len(seqs)
print(f"  received {recv}/260")
for g in gaps:
    print(f"  gap seq {g[0]}..{g[1]} = ~{g[2]:.1f}s")
big = [g for g in gaps if g[2] >= 5]
print("  gaps>=5s:", len(big))
sys.exit(0 if len(big) >= 1 and len(big) <= 3 and recv >= 150 else 1)
EOF
if [ $? -eq 0 ]; then
	ok "failover: traffic recovered via UDP during raw outage, then resumed"
else
	fail "failover timing unexpected (see gaps above)"
fi

section "TCP continuity through raw-path outage"
ip netns exec "$A" iperf3 -s -p 5201 > "$OUT/iperf-server.log" 2>&1 &
srvpid=$!
sleep 1
ip netns exec "$HUB" iperf3 -c 10.99.0.2 -p 5201 -t 60 > "$OUT/iperf-failover.log" 2>&1 &
cli=$!
sleep 15
block_raw
sleep 25
unblock_raw
wait "$cli" || true
kill "$srvpid" 2>/dev/null || true
rate=$(grep 'receiver' "$OUT/iperf-failover.log" | tail -1 | awk '{for(i=1;i<=NF;i++) if($i=="Mbits/sec"||$i=="Gbits/sec") print $(i-1), $i}')
echo "  TCP iperf receiver: ${rate:-n/a}"
if grep -q 'receiver' "$OUT/iperf-failover.log"; then
	ok "TCP completed through raw outage (rate $rate)"
else
	fail "TCP did not complete through raw outage"
fi

section "link flaps during traffic"
ip netns exec "$A" iperf3 -s -p 5202 > "$OUT/iperf-flap-server.log" 2>&1 &
srv2=$!
sleep 1
ip netns exec "$HUB" iperf3 -c 10.99.0.2 -p 5202 -t 40 > "$OUT/iperf-flap.log" 2>&1 &
cli2=$!
last=0
for t in 10 15 20; do
	sleep $((t - last))
	last=$t
	ip -n "$A" link set dtun0 down
	sleep 1
	ip -n "$A" link set dtun0 up
done
wait "$cli2" || true
kill "$srv2" 2>/dev/null || true
grep -q 'receiver' "$OUT/iperf-flap.log" && ok "TCP survived 3 link flaps" || fail "TCP failed across link flaps"

section "sustained bidirectional soak (300s) with monitoring"
ip netns exec "$A" iperf3 -s -p 5203 > "$OUT/soak-srv-a.log" 2>&1 &
soak_srv_a=$!
ip netns exec "$HUB" iperf3 -s -p 5204 > "$OUT/soak-srv-h.log" 2>&1 &
soak_srv_h=$!
sleep 1
ip netns exec "$HUB" iperf3 -c 10.99.0.2 -p 5203 -t 300 > "$OUT/soak-h2a.log" 2>&1 &
ip netns exec "$A" iperf3 -c 10.99.0.1 -p 5204 -t 300 > "$OUT/soak-a2h.log" 2>&1 &
( i=0; while [ $i -lt 150 ]; do
	ip netns exec "$A" ping -c 1 -W 1 "$HUB_I" >/dev/null 2>&1 && echo OK >> "$OUT/soak-ping.log" || echo LOSS >> "$OUT/soak-ping.log"
	sleep 2; i=$((i+1))
done ) &
monpid=$!
hubpid=$(cat "$OUT/hub.pid"); apid=$(cat "$OUT/spoke-$A.pid")
sleep 2
before_tx=$(tx_pkts "$A"); before_rx=$(rx_pkts "$A")
before_te=$(tx_err "$A"); before_td=$(tx_drop "$A")
echo "  time tx_pkts rx_pkts tx_err tx_drop cpu_hub% cpu_spoke%" > "$OUT/soak-monitor.log"
for i in $(seq 1 20); do
	sleep 15
	tx=$(tx_pkts "$A"); rx=$(rx_pkts "$A"); te=$(tx_err "$A"); td=$(tx_drop "$A")
	ch=$(cpu_pct "$hubpid"); ca=$(cpu_pct "$apid")
	echo "  $((i*15))s $tx $rx $te $td $ch $ca" >> "$OUT/soak-monitor.log"
done
wait "$monpid" || true
after_tx=$(tx_pkts "$A"); after_rx=$(rx_pkts "$A")
after_te=$(tx_err "$A"); after_td=$(tx_drop "$A")
echo "  tx_pkts $before_tx -> $after_tx, rx_pkts $before_rx -> $after_rx"
echo "  tx_errors $before_te -> $after_te, tx_dropped $before_td -> $after_td"
for f in soak-h2a soak-a2h; do
	line=$(grep 'receiver' "$OUT/$f.log" | tail -1)
	echo "  $f: $line"
done
ping_ok "$A" "$HUB_I" 3
[ "$after_te" = "$before_te" ] && [ "$after_td" = "$before_td" ] \
	&& ok "soak: no tx_errors or tx_dropped growth" || fail "soak: error counters grew"
kill "$soak_srv_a" "$soak_srv_h" 2>/dev/null || true

section "daemon CPU and memory during soak"
hubpid=$(cat "$OUT/hub.pid"); apid=$(cat "$OUT/spoke-$A.pid")
echo "  hub: cpu $(cpu_pct "$hubpid")%  rss $(awk '/VmRSS/{print $2}' /proc/$hubpid/status)kB"
echo "  spoke: cpu $(cpu_pct "$apid")%  rss $(awk '/VmRSS/{print $2}' /proc/$apid/status)kB"

section "full module reload cycle"
stop_daemon hub; stop_daemon spoke-$A
wait_gone "$A" && ok "spoke link removed on stop" || fail "spoke link not removed"
wait_gone "$HUB" && ok "hub link removed on stop" || fail "hub link not removed"
rmmod dtun && ok "module unloaded (refcnt 0)" || fail "rmmod failed"
mod_up
echo "  module reloaded: $(lsmod | grep '^dtun')"
start_hub
sleep 1
start_spoke "$A"
wait_reg "$A" 2 && ok "spoke re-registered after module reload" || fail "re-registration after module reload"
ping_ok "$A" "$HUB_I" 5 && ok "ping after full module reload" || fail "ping after module reload"

section "kernel log check"
dtun_msgs=$(dmesg | grep -iE '\] dtun(:|[0-9]+:)' | tail -20)
echo "$dtun_msgs" | grep -qi 'error\|bug\|warning' && fail "dtun kernel log contains errors/warnings" || ok "no dtun errors/warnings in dmesg"

summary
