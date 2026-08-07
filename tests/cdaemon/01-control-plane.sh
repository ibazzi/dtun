#!/bin/bash
# Control-plane tests for the C daemon: registration, persistence, restart
# behaviour, --once semantics, pool validation, cookie/PSK rejection.
set -eu
cd "$(dirname "$0")/../.."
. tests/cdaemon/lib.sh

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

cleanup() { stop_daemon hub; stop_daemon spoke-$A; stop_daemon spoke-$B; topo_down; }
trap cleanup EXIT INT TERM

section "setup: hub + spoke A + spoke B"
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
ping_ok "$A" "$HUB_I" 5 && ok "A -> hub ping" || fail "A -> hub ping"

section "spoke B registration and hub-relayed spoke-to-spoke"
spoke_conf "$B" "$B_O" "$B_I" 3
start_spoke "$B"
wait_reg "$B" 3 && ok "spoke B registered" || fail "spoke B registration"
sleep 2
ping_ok "$A" "$B_I" 5 && ok "A -> B (hub relay) ping" || fail "A -> B ping"
ping_ok "$B" "$A_I" 5 && ok "B -> A (hub relay) ping" || fail "B -> A ping"

section "periodic SYNC installs direct spoke sessions"
direct=0
for i in $(seq 1 20); do
	if peer_get "$A" 104 2>/dev/null | grep -q '"node_id":3' &&
	   peer_get "$B" 105 2>/dev/null | grep -q '"node_id":2'; then
		direct=1
		break
	fi
	sleep 1
done
[ "$direct" = 1 ] && ok "both spokes installed persisted direct peer IDs" || fail "direct SYNC peers were not installed"

section "hub clean restart: spokes re-register automatically"
stop_daemon hub
wait_gone "$HUB" && ok "hub link removed on SIGTERM" || fail "hub link still present"
start_hub
recovered=0
for i in $(seq 1 20); do
	if ping_ok "$A" "$HUB_I" 1; then recovered=1; break; fi
	sleep 1
done
[ "$recovered" = 1 ] && ok "A recovered automatically after Hub restart (${i}s)" || fail "A did not auto-recover"

section "unclean hub death (SIGKILL): link left behind, restart recovers"
if [ -f "$OUT/hub.pid" ]; then
	kill -9 "$(cat "$OUT/hub.pid")" 2>/dev/null || true
	rm -f "$OUT/hub.pid"
	sleep 1
fi
if ip -n "$HUB" link show dtun0 >/dev/null 2>&1; then
	ok "dtun0 remains after SIGKILL (no cleanup hook)"
else
	fail "dtun0 disappeared after SIGKILL"
fi
start_hub
sleep 1
recovered=0
for i in $(seq 1 20); do
	if ping_ok "$A" "$HUB_I" 1; then recovered=1; break; fi
	sleep 1
done
[ "$recovered" = 1 ] && ok "spoke auto-recovered after SIGKILL restart (${i}s)" || fail "re-registration after SIGKILL"

section "--once semantics: interface remains after successful registration"
stop_daemon spoke-$B
spoke_conf "$B" "$B_O" "$B_I" 3 1
start_spoke "$B"
if wait_reg "$B" 3; then
	ok "spoke B registered with --once"
	sleep 1
	if ip -n "$B" link show dtun0 >/dev/null 2>&1; then
		ok "--once left dtun0 in place"
	else
		fail "--once deleted dtun0"
	fi
else
	fail "spoke B --once registration"
fi

section "pool and ownership validation"
spoke_conf "$B" "$B_O" "192.168.5.5" 7 1
start_spoke "$B"
if wait_reg "$B" 7 5; then
	fail "hub accepted out-of-pool address 192.168.5.5/24"
else
	ok "hub rejected out-of-pool address 192.168.5.5/24"
fi
stop_daemon spoke-$B
sleep 1
spoke_conf "$B" "$B_O" "$HUB_I" 8 1
start_spoke "$B"
if wait_reg "$B" 8 5; then
	fail "hub accepted claim of Hub address $HUB_I"
else
	ok "hub rejected claim of Hub address $HUB_I"
fi
stop_daemon spoke-$B

section "authentication rejection: bad PSK and tampered cookie"
rc=$(ip netns exec "$B" python3 "$ROOT/tests/cdaemon/reg_client.py" --hub "$HUB_O" \
	--node-id 9 --key "$KEY" --bad-init-key)
[ "$rc" = "NO_CHALLENGE" ] && ok "INIT with wrong PSK gets no CHALLENGE" || fail "wrong-PSK INIT got: $rc"
rc=$(ip netns exec "$B" python3 "$ROOT/tests/cdaemon/reg_client.py" --hub "$HUB_O" \
	--node-id 9 --key "$KEY" --bad-cookie)
[ "$rc" = "NO_ACK" ] && ok "CONFIRM with tampered cookie gets no ACK" || fail "tampered cookie got: $rc"
rc=$(ip netns exec "$B" python3 "$ROOT/tests/cdaemon/reg_client.py" --hub "$HUB_O" \
	--node-id 9 --key "$KEY" --address 10.99.0.9/24)
[ "$rc" = "ACK" ] && ok "valid registration round-trip works" || fail "valid round-trip got: $rc"

section "hub state persistence: tunnel IDs and inner IP survive restart"
stop_daemon hub
start_hub
for i in $(seq 1 20); do
	ping_ok "$A" "$HUB_I" 1 && break
	sleep 1
done
peer=$(peer_get "$A" 100)
echo "$peer"
echo "$peer" | grep -q '"tunnel_id": 100' && ok "tunnel_id persisted (100)" || fail "tunnel_id changed"
echo "$peer" | grep -q '"remote_tunnel_id": 101' && ok "remote_tunnel_id persisted (101)" || fail "remote_tunnel_id changed"
echo "$peer" | grep -q '"node_id":1' && ok "hub node id persisted" || fail "hub node id changed"

summary
