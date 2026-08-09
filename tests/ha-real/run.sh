#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
CONFIG="$ROOT/tests/ha-real/config"
[[ $# -eq 3 ]] || {
    echo "usage: $0 PRIMARY_USER@IP BACKUP1_USER@IP BACKUP2_USER@IP" >&2
    echo "Passwords are requested by ssh/sudo and are never accepted as arguments." >&2
    exit 2
}
HOSTS=("$1" "$2" "$3")
LOCAL_HOST_MODE=${HA_REAL_LOCAL_HOST:-0}
DIRECT_ONLY=${HA_REAL_DIRECT_ONLY:-0}
ALLOW_LOADED=${HA_REAL_ALLOW_LOADED:-0}
[[ $LOCAL_HOST_MODE =~ ^[01]$ && $DIRECT_ONLY =~ ^[01]$ &&
   $ALLOW_LOADED =~ ^[01]$ ]] || {
    echo "HA_REAL_LOCAL_HOST, HA_REAL_DIRECT_ONLY, and HA_REAL_ALLOW_LOADED must be 0 or 1" >&2
    exit 2
}
for host in "${HOSTS[@]}"; do
    [[ $host =~ ^[^[:space:]@]+@([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || {
        echo "host must be USER@IPv4: $host" >&2; exit 2;
    }
done

PRIMARY_IP=${HOSTS[0]##*@}
B1_IP=${HOSTS[1]##*@}
B2_IP=${HOSTS[2]##*@}
RUN=$(mktemp -d /tmp/dtun-ha-real-run-XXXXXX)
chmod 700 "$RUN"
TEST_PSK=$(openssl rand -hex 32)
KNOWN="$RUN/known_hosts"
SOCKETS=()
CLEANUP_READY=0

section() { echo; echo "===== $* ====="; }
pass() { echo "PASS: $*"; }
die() {
    echo "FAIL: $*" >&2
    if [[ $CLEANUP_READY -eq 1 && ${#SOCKETS[@]} -eq 3 ]]; then
        collect_diagnostics || true
    fi
    exit 1
}

close_masters() {
    local i
    for i in "${!SOCKETS[@]}"; do
        ssh -o ControlPath="${SOCKETS[$i]}" -O exit "${HOSTS[$i]}" >/dev/null 2>&1 || true
    done
}

remote() {
    local index=$1
    shift
    ssh -o ControlPath="${SOCKETS[$index]}" "${HOSTS[$index]}" "$@"
}

collect_diagnostics() {
    local i unit
    echo "===== Sanitized diagnostics =====" >&2
    for i in 0 1 2; do
        case $i in
            0) unit=dtun-ha-real-primary.service ;;
            1) unit=dtun-ha-real-backup-1.service ;;
            2) unit=dtun-ha-real-backup-2.service ;;
        esac
        echo "--- ${HOSTS[$i]} $unit" >&2
        remote "$i" "systemctl --no-pager --full status '$unit' 2>/dev/null | tail -n 20; journalctl -u '$unit' --since '10 minutes ago' --no-pager -o cat 2>/dev/null | tail -n 40" >&2 || true
        if ((i > 0)); then
            echo "--- ${HOSTS[$i]} netns Spoke" >&2
            remote "$i" "journalctl -u 'dtun-ha-real-spoke-$i.service' --since '10 minutes ago' --no-pager -o cat 2>/dev/null | tail -n 40; ip netns exec 'dtun-ha-real-s$i' ip route 2>/dev/null; ip netns exec 'dtun-ha-real-s$i' /tmp/dtun-ha-real-src/build/dtunctl peer list --ifname dtun-ha0 2>/dev/null" >&2 || true
        fi
    done
    echo "--- local Spoke" >&2
    sudo journalctl -u dtun-ha-real-local-spoke.service --since "10 minutes ago" --no-pager -o cat 2>/dev/null | tail -n 40 >&2 || true
}

cleanup_active() {
    local local_out b1_out b2_out
    [[ $CLEANUP_READY -eq 1 ]] || return 0
    set +e
    local_out=$(ip route get "$PRIMARY_IP" 2>/dev/null | awk '/ dev / {for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')
    b1_out=$(remote 1 "ip route get '$PRIMARY_IP' | awk '/ dev / {for(i=1;i<=NF;i++)if(\$i==\"dev\"){print \$(i+1);exit}}'" 2>/dev/null)
    b2_out=$(remote 2 "ip route get '$PRIMARY_IP' | awk '/ dev / {for(i=1;i<=NF;i++)if(\$i==\"dev\"){print \$(i+1);exit}}'" 2>/dev/null)
    remote 1 "systemctl stop dtun-ha-real-spoke-1.service dtun-ha-real-backup-1.service 2>/dev/null || true; bash /tmp/dtun-ha-real-src/tests/ha-real/node-netns.sh cleanup dtun-ha-real-s1 dthar1 192.168.251.0/24 '${b1_out:-eth0}' '$B1_IP' 2>/dev/null || true; test ! -e /tmp/dtun-ha-real/module.loaded || rmmod dtun; rm -rf /tmp/dtun-ha-real /tmp/dtun-ha-real-src /tmp/dtun-ha-real-src.tar.gz /tmp/dtun-ha-real-backup-1.conf /tmp/dtun-ha-real-spoke-1.conf /tmp/dtun-ha-real-spoke-new.conf" >/dev/null 2>&1
    remote 2 "systemctl stop dtun-ha-real-spoke-2.service dtun-ha-real-backup-2.service 2>/dev/null || true; bash /tmp/dtun-ha-real-src/tests/ha-real/node-netns.sh cleanup dtun-ha-real-s2 dthar2 192.168.252.0/24 '${b2_out:-eth0}' '$B2_IP' 2>/dev/null || true; test ! -e /tmp/dtun-ha-real/module.loaded || rmmod dtun; rm -rf /tmp/dtun-ha-real /tmp/dtun-ha-real-src /tmp/dtun-ha-real-src.tar.gz /tmp/dtun-ha-real-backup-2.conf /tmp/dtun-ha-real-spoke-2.conf" >/dev/null 2>&1
    remote 0 "systemctl stop dtun-ha-real-primary.service 2>/dev/null || true; test ! -e /tmp/dtun-ha-real/module.loaded || rmmod dtun; rm -rf /tmp/dtun-ha-real /tmp/dtun-ha-real-src /tmp/dtun-ha-real-primary.conf" >/dev/null 2>&1
    sudo systemctl stop dtun-ha-real-local-spoke.service >/dev/null 2>&1 || true
    if [[ $LOCAL_HOST_MODE -eq 0 ]]; then
        sudo bash "$ROOT/tests/ha-real/node-netns.sh" cleanup dtun-ha-real-local dtharl 192.168.250.0/24 "${local_out:-eth0}" >/dev/null 2>&1 || true
    fi
    [[ ! -e /tmp/dtun-ha-real/module.loaded ]] || sudo rmmod dtun >/dev/null 2>&1
    sudo rm -rf /tmp/dtun-ha-real /tmp/dtun-ha-real-local-spoke.conf
    set -e
}

local_spoke_exec() {
    if [[ $LOCAL_HOST_MODE -eq 1 ]]; then
        sudo "$@"
    else
        sudo ip netns exec dtun-ha-real-local "$@"
    fi
}

finish() {
    status=$?
    if [[ ${HA_REAL_KEEP:-0} != 1 ]]; then cleanup_active; fi
    close_masters
    rm -rf "$RUN"
    exit "$status"
}
trap finish EXIT INT TERM

wait_remote() {
    local index=$1 description=$2 command=$3 timeout=${4:-30}
    local i
    for ((i=0; i<timeout; i++)); do
        if remote "$index" "$command" >/dev/null 2>&1; then pass "$description"; return 0; fi
        sleep 1
    done
    die "$description"
}

wait_local_log() {
    local unit=$1 pattern=$2 timeout=${3:-30} i invocation
    invocation=$(sudo systemctl show -p InvocationID --value "$unit")
    [[ -n $invocation ]] || return 1
    for ((i=0; i<timeout; i++)); do
        if sudo journalctl "_SYSTEMD_INVOCATION_ID=$invocation" --no-pager -o cat 2>/dev/null | grep -q "$pattern"; then return 0; fi
        sleep 1
    done
    return 1
}

wait_remote_log() {
    local index=$1 description=$2 unit=$3 pattern=$4 timeout=${5:-30}
    local invocation
    invocation=$(remote "$index" "systemctl show -p InvocationID --value '$unit'")
    [[ -n $invocation ]] || die "$description"
    wait_remote "$index" "$description" "journalctl '_SYSTEMD_INVOCATION_ID=$invocation' --no-pager -o cat | grep -q '$pattern'" "$timeout"
}

render_config() {
    sed -e "s/@PRIMARY_IP@/$PRIMARY_IP/g" -e "s/@PSK@/$TEST_PSK/g" "$1" > "$2"
    chmod 600 "$2"
}

section "Authentication"
sudo -v
for i in 0 1 2; do
    socket="$RUN/ssh-$i.sock"
    SOCKETS+=("$socket")
    ssh -MNf -o ControlMaster=yes -o ControlPersist=600 \
        -o ControlPath="$socket" -o UserKnownHostsFile="$KNOWN" \
        -o StrictHostKeyChecking=accept-new "${HOSTS[$i]}"
done
CLEANUP_READY=1

if [[ $ALLOW_LOADED -eq 0 ]] && grep -q '^dtun ' /proc/modules; then
    die "local dtun module is already loaded; clean it before testing"
fi
if ip -details link show type dtun 2>/dev/null | grep -q 'dtun'; then
    die "local dtun interface already exists"
fi
for i in 0 1 2; do
    if [[ $ALLOW_LOADED -eq 0 ]]; then
        remote "$i" "! grep -q '^dtun ' /proc/modules" || die "dtun module already loaded on ${HOSTS[$i]}"
    fi
    remote "$i" "! ip -details link show type dtun 2>/dev/null | grep -q 'dtun'" ||
        die "dtun interface already exists on ${HOSTS[$i]}"
done

section "Build and deploy"
tar --exclude=.git --exclude=build --exclude='*.ko' -czf "$RUN/src.tar.gz" -C "$ROOT" .
rsync -a --exclude=.git --exclude=build -e "ssh -o ControlPath=${SOCKETS[0]}" "$ROOT/" "${HOSTS[0]}:/tmp/dtun-ha-real-src/"
for i in 1 2; do
    scp -o ControlPath="${SOCKETS[$i]}" "$RUN/src.tar.gz" "${HOSTS[$i]}:/tmp/dtun-ha-real-src.tar.gz"
    remote "$i" "rm -rf /tmp/dtun-ha-real-src; mkdir -p /tmp/dtun-ha-real-src; tar -xzf /tmp/dtun-ha-real-src.tar.gz -C /tmp/dtun-ha-real-src; make -C /tmp/dtun-ha-real-src -j4 all module"
done
remote 0 "make -C /tmp/dtun-ha-real-src -j4 all module"
make -C "$ROOT" -j4 all

render_config "$CONFIG/spoke-local.conf.in" "$RUN/spoke-local.conf"
render_config "$CONFIG/spoke-backup-1.conf.in" "$RUN/spoke-1.conf"
render_config "$CONFIG/spoke-backup-2.conf.in" "$RUN/spoke-2.conf"
render_config "$CONFIG/hub-primary.conf" "$RUN/hub-primary.conf"
render_config "$CONFIG/hub-backup-1.conf" "$RUN/hub-backup-1.conf"
render_config "$CONFIG/hub-backup-2.conf" "$RUN/hub-backup-2.conf"
scp -o ControlPath="${SOCKETS[0]}" "$RUN/hub-primary.conf" "${HOSTS[0]}:/tmp/dtun-ha-real-primary.conf"
scp -o ControlPath="${SOCKETS[1]}" "$RUN/hub-backup-1.conf" "$RUN/spoke-1.conf" "${HOSTS[1]}:/tmp/"
scp -o ControlPath="${SOCKETS[2]}" "$RUN/hub-backup-2.conf" "$RUN/spoke-2.conf" "${HOSTS[2]}:/tmp/"
remote 1 "mv /tmp/hub-backup-1.conf /tmp/dtun-ha-real-backup-1.conf; mv /tmp/spoke-1.conf /tmp/dtun-ha-real-spoke-1.conf"
remote 2 "mv /tmp/hub-backup-2.conf /tmp/dtun-ha-real-backup-2.conf; mv /tmp/spoke-2.conf /tmp/dtun-ha-real-spoke-2.conf"
sudo cp "$RUN/spoke-local.conf" /tmp/dtun-ha-real-local-spoke.conf

sudo mkdir -p /tmp/dtun-ha-real
if ! grep -q '^dtun ' /proc/modules; then
    sudo insmod "$ROOT/build/dtun.ko"
    sudo touch /tmp/dtun-ha-real/module.loaded
fi
for i in 0 1 2; do
    remote "$i" "mkdir -p /tmp/dtun-ha-real; if ! grep -q '^dtun ' /proc/modules; then insmod /tmp/dtun-ha-real-src/build/dtun.ko; touch /tmp/dtun-ha-real/module.loaded; fi"
done

section "Initialize and enroll"
remote 0 "/tmp/dtun-ha-real-src/build/dtunctl ha init --config /tmp/dtun-ha-real-primary.conf --hub-id hub-primary --output-dir /tmp/dtun-ha-real/ha --state-file /tmp/dtun-ha-real/ha/state"
remote 0 "systemd-run --unit=dtun-ha-real-primary --collect /tmp/dtun-ha-real-src/build/dtund -c /tmp/dtun-ha-real-primary.conf"

enroll() {
    local index=$1 id=$2 weight=$3 config=$4 invite attempt enrolled=0
    invite=$(remote 0 "/tmp/dtun-ha-real-src/build/dtunctl ha invite create --hub-id '$id' --weight '$weight' --expires 10m --bootstrap-address '$PRIMARY_IP' --format plain --state-file /tmp/dtun-ha-real/ha/state --identity-key /tmp/dtun-ha-real/ha/identity.key")
    [[ -n $invite ]] || die "failed to create Invite for $id"
    for attempt in 1 2 3; do
        if printf '%s\n' "$invite" | ssh -T -o ControlPath="${SOCKETS[$index]}" "${HOSTS[$index]}" "/tmp/dtun-ha-real-src/build/dtunctl ha join --config '$config' --output-dir /tmp/dtun-ha-real/ha --state-file /tmp/dtun-ha-real/ha/state --invite-id-stdin"; then
            enrolled=1
            break
        fi
        sleep 1
    done
    unset invite
    [[ $enrolled -eq 1 ]] || die "failed to enroll $id"
}

enroll 1 hub-backup-1 900 /tmp/dtun-ha-real-backup-1.conf
remote 1 "systemd-run --unit=dtun-ha-real-backup-1 --collect /tmp/dtun-ha-real-src/build/dtund -c /tmp/dtun-ha-real-backup-1.conf"
wait_remote 1 "backup-1 promoted to voter" "/tmp/dtun-ha-real-src/build/dtunctl ha status --state-file /tmp/dtun-ha-real/ha/state | grep -q 'hub-backup-1.*role=voter'"
enroll 2 hub-backup-2 800 /tmp/dtun-ha-real-backup-2.conf
remote 2 "systemd-run --unit=dtun-ha-real-backup-2 --collect /tmp/dtun-ha-real-src/build/dtund -c /tmp/dtun-ha-real-backup-2.conf"
wait_remote 2 "three-node quorum formed" "/tmp/dtun-ha-real-src/build/dtunctl ha status --state-file /tmp/dtun-ha-real/ha/state | grep -q 'Mode: quorum'"

section "Create isolated Spokes"
LOCAL_OUT=$(ip route get "$PRIMARY_IP" | awk '/ dev / {for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')
B1_OUT=$(remote 1 "ip route get '$PRIMARY_IP' | awk '/ dev / {for(i=1;i<=NF;i++)if(\$i==\"dev\"){print \$(i+1);exit}}'")
B2_OUT=$(remote 2 "ip route get '$PRIMARY_IP' | awk '/ dev / {for(i=1;i<=NF;i++)if(\$i==\"dev\"){print \$(i+1);exit}}'")
if [[ $LOCAL_HOST_MODE -eq 0 ]]; then
    sudo bash "$ROOT/tests/ha-real/node-netns.sh" setup dtun-ha-real-local dtharl 192.168.250.0/24 "$LOCAL_OUT"
fi
remote 1 "bash /tmp/dtun-ha-real-src/tests/ha-real/node-netns.sh setup dtun-ha-real-s1 dthar1 192.168.251.0/24 '$B1_OUT' '$B1_IP'"
remote 2 "bash /tmp/dtun-ha-real-src/tests/ha-real/node-netns.sh setup dtun-ha-real-s2 dthar2 192.168.252.0/24 '$B2_OUT' '$B2_IP'"

if [[ $LOCAL_HOST_MODE -eq 1 ]]; then
    sudo systemd-run --unit=dtun-ha-real-local-spoke --collect "$ROOT/build/dtund" -c /tmp/dtun-ha-real-local-spoke.conf
else
    sudo systemd-run --unit=dtun-ha-real-local-spoke --collect /usr/sbin/ip netns exec dtun-ha-real-local "$ROOT/build/dtund" -c /tmp/dtun-ha-real-local-spoke.conf
fi
remote 1 "systemd-run --unit=dtun-ha-real-spoke-1 --collect /usr/sbin/ip netns exec dtun-ha-real-s1 /tmp/dtun-ha-real-src/build/dtund -c /tmp/dtun-ha-real-spoke-1.conf"
remote 2 "systemd-run --unit=dtun-ha-real-spoke-2 --collect /usr/sbin/ip netns exec dtun-ha-real-s2 /tmp/dtun-ha-real-src/build/dtund -c /tmp/dtun-ha-real-spoke-2.conf"
wait_local_log dtun-ha-real-local-spoke.service 'Registration successful! NodeID=2' || die "local Spoke registration"
wait_remote_log 1 "backup-1 netns Spoke registered" dtun-ha-real-spoke-1.service 'Registration successful! NodeID=3'
wait_remote_log 2 "backup-2 netns Spoke registered" dtun-ha-real-spoke-2.service 'Registration successful! NodeID=4'

section "Data plane and replication"
local_spoke_exec ping -c 3 -W 2 10.77.0.1 >/dev/null || die "local Spoke to Hub"
remote 1 "ip netns exec dtun-ha-real-s1 ping -c 3 -W 2 10.77.0.1 >/dev/null" || die "Spoke-1 to Hub"
remote 2 "ip netns exec dtun-ha-real-s2 ping -c 3 -W 2 10.77.0.1 >/dev/null" || die "Spoke-2 to Hub"
pass "all Spokes reach active Hub"
local_spoke_exec ping -c 3 -W 2 10.77.0.3 >/dev/null || die "local to Spoke-1 relay"
remote 1 "ip netns exec dtun-ha-real-s1 ping -c 3 -W 2 10.77.0.4 >/dev/null" || die "Spoke-1 to Spoke-2 relay"
remote 2 "ip netns exec dtun-ha-real-s2 ping -c 3 -W 2 10.77.0.2 >/dev/null" || die "Spoke-2 to local relay"
pass "cross-Spoke UDP/Hub fallback works"

section "Local host to backup-2 netns direct path"
DIRECT_READY=0
for ((i=0; i<60; i++)); do
    LOCAL_PEERS=$(local_spoke_exec "$ROOT/build/dtunctl" peer list --format json --ifname dtun-ha0 2>/dev/null || true)
    B2_PEERS=$(remote 2 "ip netns exec dtun-ha-real-s2 /tmp/dtun-ha-real-src/build/dtunctl peer list --format json --ifname dtun-ha0" 2>/dev/null || true)
    if grep -q '"node_id":4.*"selected_path":"udp"' <<<"$LOCAL_PEERS" &&
       grep -q '"node_id":2.*"selected_path":"udp"' <<<"$B2_PEERS"; then
        DIRECT_READY=1
        break
    fi
    sleep 0.25
done
if [[ $DIRECT_READY -ne 1 ]]; then
    echo "Local peer state: $LOCAL_PEERS" >&2
    echo "Backup-2 netns peer state: $B2_PEERS" >&2
    echo "Local UDP capture:" >&2
    local_spoke_exec timeout 3 tcpdump -ni any -c 30 'udp port 49000' >&2 || true
    echo "Backup-2 host UDP capture:" >&2
    remote 2 "timeout 3 tcpdump -ni any -c 30 'udp port 49000'" >&2 || true
    echo "Backup-2 netns UDP capture:" >&2
    remote 2 "ip netns exec dtun-ha-real-s2 timeout 3 tcpdump -ni any -c 30 'udp port 49000'" >&2 || true
    if [[ $DIRECT_ONLY -eq 0 ]]; then
        die "local host and backup-2 netns Spoke did not establish direct UDP"
    fi
    pass "direct UDP blocked outside the netns; Hub fallback remains active"
else
    local_spoke_exec ping -c 3 -W 2 10.77.0.4 >/dev/null ||
        die "local host to backup-2 netns direct data path"
    pass "local host and backup-2 netns selected authenticated UDP direct"
fi

if [[ $DIRECT_ONLY -eq 1 ]]; then
    LOCAL_INVOCATION=$(sudo systemctl show -p InvocationID --value dtun-ha-real-local-spoke.service)
    LEAVE_STARTED_MS=$(date +%s%3N)
    sudo systemctl stop dtun-ha-real-local-spoke.service
    OFFLINE_PROPAGATED=0
    for ((i=0; i<40; i++)); do
        PRIMARY_PEERS=$(remote 0 "/tmp/dtun-ha-real-src/build/dtunctl peer list --format json --ifname dtun-ha0" 2>/dev/null || true)
        B2_PEERS=$(remote 2 "ip netns exec dtun-ha-real-s2 /tmp/dtun-ha-real-src/build/dtunctl peer list --format json --ifname dtun-ha0" 2>/dev/null || true)
        if ! grep -q '"node_id":2' <<<"$PRIMARY_PEERS" &&
           ! grep -q '"node_id":2' <<<"$B2_PEERS"; then
            OFFLINE_PROPAGATED=1
            break
        fi
        sleep 0.05
    done
    LEAVE_ELAPSED_MS=$(( $(date +%s%3N) - LEAVE_STARTED_MS ))
    [[ $OFFLINE_PROPAGATED -eq 1 && $LEAVE_ELAPSED_MS -le 2000 ]] ||
        die "graceful offline propagation exceeded 2000ms"
    sudo journalctl "_SYSTEMD_INVOCATION_ID=$LOCAL_INVOCATION" --no-pager -o cat |
        grep -q 'Hub acknowledged graceful offline for NodeID=2' ||
        die "local Spoke did not receive LEAVE_ACK"
    wait_remote_log 0 "primary recorded authenticated graceful leave" \
        dtun-ha-real-primary.service \
        'Marked Spoke NodeID=2.*authenticated graceful LEAVE' 3
    pass "graceful offline propagated in ${LEAVE_ELAPSED_MS}ms"
    pass "direct-path diagnostic suite complete"
    exit 0
fi

for ((i=0; i<15; i++)); do
    H0=$(remote 0 "sha256sum /tmp/dtun-ha-real/primary-hub.state | awk '{print \$1}'")
    H1=$(remote 1 "sha256sum /tmp/dtun-ha-real/backup-1-hub.state | awk '{print \$1}'")
    H2=$(remote 2 "sha256sum /tmp/dtun-ha-real/backup-2-hub.state | awk '{print \$1}'")
    [[ $H0 == "$H1" && $H1 == "$H2" ]] && break
    sleep 1
done
[[ $H0 == "$H1" && $H1 == "$H2" ]] || die "Hub state replicas differ"
pass "three Hub state replicas match"

section "Weighted quorum failover"
FAILOVER_START_MS=$(date +%s%3N)
remote 0 "systemctl stop dtun-ha-real-primary.service"
MIGRATION_MS=
while (( $(date +%s%3N) - FAILOVER_START_MS <= 2000 )); do
    if local_spoke_exec timeout 0.2s ping -c 1 -W 1 10.77.0.1 \
        >/dev/null 2>&1; then
        MIGRATION_MS=$(( $(date +%s%3N) - FAILOVER_START_MS ))
        break
    fi
    sleep 0.05
done
[[ -n $MIGRATION_MS ]] || die "local Spoke migration exceeded 2000ms"
pass "local Spoke data plane migrated in ${MIGRATION_MS}ms"
wait_remote 1 "backup-1 elected by weight" "/tmp/dtun-ha-real-src/build/dtunctl ha status --state-file /tmp/dtun-ha-real/ha/state | grep -q 'Leader: hub-backup-1'" 20
local_spoke_exec ping -c 3 -W 2 10.77.0.1 >/dev/null || die "local Spoke did not migrate"
remote 1 "ip netns exec dtun-ha-real-s1 ping -c 3 -W 2 10.77.0.1 >/dev/null" || die "Spoke-1 did not migrate"
remote 2 "ip netns exec dtun-ha-real-s2 ping -c 3 -W 2 10.77.0.1 >/dev/null" || die "Spoke-2 did not migrate"
pass "all Spokes migrated to backup-1"

section "Minority allocation guard"
remote 2 "systemctl stop dtun-ha-real-backup-2.service dtun-ha-real-spoke-2.service; cp /tmp/dtun-ha-real-spoke-2.conf /tmp/dtun-ha-real-spoke-new.conf; sed -i 's/node_id = 4/node_id = 5/; s/address = 10.77.0.4\/24/address = 10.77.0.5\/24/; s/hub_address = .*/hub_address = $B1_IP/; s#spoke-backup-2.state#spoke-new.state#; /timeout = 2/a once = true' /tmp/dtun-ha-real-spoke-new.conf"
set +e
remote 2 "ip netns exec dtun-ha-real-s2 /tmp/dtun-ha-real-src/build/dtund -c /tmp/dtun-ha-real-spoke-new.conf"
NEW_RC=$?
set -e
[[ $NEW_RC -ne 0 ]] || die "minority accepted a new persistent allocation"
pass "minority rejected new NodeID=5 allocation"
remote 2 "systemd-run --unit=dtun-ha-real-backup-2 --collect /tmp/dtun-ha-real-src/build/dtund -c /tmp/dtun-ha-real-backup-2.conf; systemd-run --unit=dtun-ha-real-spoke-2 --collect /usr/sbin/ip netns exec dtun-ha-real-s2 /tmp/dtun-ha-real-src/build/dtund -c /tmp/dtun-ha-real-spoke-2.conf"
sleep 8

section "Recovery and next weighted election"
remote 0 "systemd-run --unit=dtun-ha-real-primary --collect /tmp/dtun-ha-real-src/build/dtund -c /tmp/dtun-ha-real-primary.conf"
wait_remote 0 "primary recovered as standby" "/tmp/dtun-ha-real-src/build/dtunctl ha status --state-file /tmp/dtun-ha-real/ha/state | grep -q 'Leader: hub-backup-1'" 20
remote 1 "systemctl stop dtun-ha-real-backup-1.service"
wait_remote 0 "highest-weight primary elected" "/tmp/dtun-ha-real-src/build/dtunctl ha status --state-file /tmp/dtun-ha-real/ha/state | grep -q 'Leader: hub-primary'" 25
sleep 6
local_spoke_exec ping -c 3 -W 2 10.77.0.1 >/dev/null || die "local Spoke after second election"
remote 1 "ip netns exec dtun-ha-real-s1 ping -c 3 -W 2 10.77.0.1 >/dev/null" || die "Spoke-1 after second election"
remote 2 "ip netns exec dtun-ha-real-s2 ping -c 3 -W 2 10.77.0.1 >/dev/null" || die "Spoke-2 after second election"
remote 1 "systemd-run --unit=dtun-ha-real-backup-1 --collect /tmp/dtun-ha-real-src/build/dtund -c /tmp/dtun-ha-real-backup-1.conf"
wait_remote 1 "backup-1 converged after recovery" "/tmp/dtun-ha-real-src/build/dtunctl ha status --state-file /tmp/dtun-ha-real/ha/state | grep -q 'Leader: hub-primary'" 20

section "Result"
unset TEST_PSK
echo "All real-environment HA cases passed."
