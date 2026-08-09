#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
CONFIG="$ROOT/tests/ha-real/config"
[[ $# -eq 2 ]] || {
    echo "usage: $0 PRIMARY_USER@IP BACKUP_USER@IP" >&2
    exit 2
}
HOSTS=("$1" "$2")
for host in "${HOSTS[@]}"; do
    [[ $host =~ ^[^[:space:]@]+@([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || {
        echo "host must be USER@IPv4: $host" >&2
        exit 2
    }
done
PRIMARY_IP=${HOSTS[0]##*@}
BACKUP_IP=${HOSTS[1]##*@}
RUN=$(mktemp -d /tmp/dtun-ha-direct-run-XXXXXX)
chmod 700 "$RUN"
TEST_PSK=$(openssl rand -hex 32)
KNOWN="$RUN/known_hosts"
SOCKETS=()
CLEANUP_READY=0

section() { echo; echo "===== $* ====="; }
pass() { echo "PASS: $*"; }
die() { echo "FAIL: $*" >&2; exit 1; }
remote() {
    local index=$1
    shift
    ssh -o ControlPath="${SOCKETS[$index]}" "${HOSTS[$index]}" "$@"
}
close_masters() {
    local i
    for i in "${!SOCKETS[@]}"; do
        ssh -o ControlPath="${SOCKETS[$i]}" -O exit "${HOSTS[$i]}" \
            >/dev/null 2>&1 || true
    done
}
cleanup_active() {
    [[ $CLEANUP_READY -eq 1 ]] || return 0
    set +e
    local local_out backup_out
    local_out=$(ip route get "$PRIMARY_IP" 2>/dev/null | awk '/ dev / {for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')
    backup_out=$(remote 1 "ip route get '$PRIMARY_IP' | awk '/ dev / {for(i=1;i<=NF;i++)if(\$i==\"dev\"){print \$(i+1);exit}}'" 2>/dev/null)
    remote 1 "systemctl stop dtun-ha-direct-spoke.service dtun-ha-direct-backup.service 2>/dev/null || true; bash /tmp/dtun-ha-direct-src/tests/ha-real/node-netns.sh cleanup dtun-ha-direct-remote dthad1 192.168.251.0/24 '${backup_out:-eth0}' '$BACKUP_IP' 2>/dev/null || true; test ! -e /tmp/dtun-ha-direct/module.loaded || rmmod dtun; rm -rf /tmp/dtun-ha-direct /tmp/dtun-ha-direct-src /tmp/dtun-ha-direct-src.tar.gz /tmp/dtun-ha-direct-backup.conf /tmp/dtun-ha-direct-spoke.conf /tmp/dtun-ha-direct-new.conf" >/dev/null 2>&1
    remote 0 "systemctl stop dtun-ha-direct-primary.service 2>/dev/null || true; test ! -e /tmp/dtun-ha-direct/module.loaded || rmmod dtun; rm -rf /tmp/dtun-ha-direct /tmp/dtun-ha-direct-src /tmp/dtun-ha-direct-primary.conf" >/dev/null 2>&1
    sudo systemctl stop dtun-ha-direct-local-spoke.service >/dev/null 2>&1 || true
    sudo bash "$ROOT/tests/ha-real/node-netns.sh" cleanup dtun-ha-direct-local dthadl 192.168.250.0/24 "${local_out:-eth0}" >/dev/null 2>&1 || true
    [[ ! -e /tmp/dtun-ha-direct/module.loaded ]] || sudo rmmod dtun >/dev/null 2>&1
    sudo rm -rf /tmp/dtun-ha-direct /tmp/dtun-ha-direct-local.conf
    set -e
}
finish() {
    local status=$?
    cleanup_active
    close_masters
    rm -rf "$RUN"
    exit "$status"
}
trap finish EXIT INT TERM

wait_remote() {
    local index=$1 description=$2 command=$3 attempts=${4:-40}
    local i
    for ((i=0; i<attempts; i++)); do
        if remote "$index" "$command" >/dev/null 2>&1; then
            pass "$description"
            return 0
        fi
        sleep 0.25
    done
    die "$description"
}
wait_log() {
    local local_or_remote=$1 unit=$2 pattern=$3 i invocation
    if [[ $local_or_remote == local ]]; then
        invocation=$(sudo systemctl show -p InvocationID --value "$unit")
        for ((i=0; i<120; i++)); do
            sudo journalctl "_SYSTEMD_INVOCATION_ID=$invocation" --no-pager -o cat 2>/dev/null | grep -q "$pattern" && return 0
            sleep 0.25
        done
    else
        invocation=$(remote 1 "systemctl show -p InvocationID --value '$unit'")
        for ((i=0; i<120; i++)); do
            remote 1 "journalctl '_SYSTEMD_INVOCATION_ID=$invocation' --no-pager -o cat | grep -q '$pattern'" >/dev/null 2>&1 && return 0
            sleep 0.25
        done
    fi
    return 1
}
render() {
    sed -e "s/@PRIMARY_IP@/$PRIMARY_IP/g" -e "s/@PSK@/$TEST_PSK/g" \
        -e 's#/tmp/dtun-ha-real#/tmp/dtun-ha-direct#g' "$1" >"$2"
    chmod 600 "$2"
}

section "Authentication"
sudo -v
for i in 0 1; do
    socket="$RUN/ssh-$i.sock"
    SOCKETS+=("$socket")
    if [[ -n ${DTUN_TEST_PASSWORD:-} ]]; then
        SSHPASS=$DTUN_TEST_PASSWORD sshpass -e ssh -MNf \
            -o ControlMaster=yes -o ControlPersist=600 \
            -o ControlPath="$socket" -o UserKnownHostsFile="$KNOWN" \
            -o StrictHostKeyChecking=accept-new "${HOSTS[$i]}"
    else
        ssh -MNf -o ControlMaster=yes -o ControlPersist=600 \
            -o ControlPath="$socket" -o UserKnownHostsFile="$KNOWN" \
            -o StrictHostKeyChecking=accept-new "${HOSTS[$i]}"
    fi
done
CLEANUP_READY=1
if lsmod | grep -q '^dtun '; then die "local dtun module is already loaded"; fi
for i in 0 1; do
    remote "$i" "! lsmod | grep -q '^dtun '" || die "dtun is already loaded on ${HOSTS[$i]}"
done

section "Build and deploy"
tar --exclude=.git --exclude=build --exclude='*.ko' -czf "$RUN/src.tar.gz" -C "$ROOT" .
rsync -a --exclude=.git --exclude=build -e "ssh -o ControlPath=${SOCKETS[0]}" "$ROOT/" "${HOSTS[0]}:/tmp/dtun-ha-direct-src/"
scp -o ControlPath="${SOCKETS[1]}" "$RUN/src.tar.gz" "${HOSTS[1]}:/tmp/dtun-ha-direct-src.tar.gz"
remote 1 "rm -rf /tmp/dtun-ha-direct-src; mkdir -p /tmp/dtun-ha-direct-src; tar -xzf /tmp/dtun-ha-direct-src.tar.gz -C /tmp/dtun-ha-direct-src; make -C /tmp/dtun-ha-direct-src -j4 all module"
remote 0 "make -C /tmp/dtun-ha-direct-src -j4 all module"
make -C "$ROOT" -j4 all

render "$CONFIG/hub-primary.conf" "$RUN/primary.conf"
render "$CONFIG/hub-backup-1.conf" "$RUN/backup.conf"
render "$CONFIG/spoke-local.conf.in" "$RUN/local.conf"
render "$CONFIG/spoke-backup-1.conf.in" "$RUN/remote-spoke.conf"
scp -o ControlPath="${SOCKETS[0]}" "$RUN/primary.conf" "${HOSTS[0]}:/tmp/dtun-ha-direct-primary.conf"
scp -o ControlPath="${SOCKETS[1]}" "$RUN/backup.conf" "$RUN/remote-spoke.conf" "${HOSTS[1]}:/tmp/"
remote 1 "mv /tmp/backup.conf /tmp/dtun-ha-direct-backup.conf; mv /tmp/remote-spoke.conf /tmp/dtun-ha-direct-spoke.conf"
sudo cp "$RUN/local.conf" /tmp/dtun-ha-direct-local.conf
sudo mkdir -p /tmp/dtun-ha-direct
sudo insmod "$ROOT/build/dtun.ko"
sudo touch /tmp/dtun-ha-direct/module.loaded
for i in 0 1; do
    remote "$i" "mkdir -p /tmp/dtun-ha-direct; insmod /tmp/dtun-ha-direct-src/build/dtun.ko; touch /tmp/dtun-ha-direct/module.loaded"
done

section "Initialize direct pair"
remote 0 "/tmp/dtun-ha-direct-src/build/dtunctl ha init --config /tmp/dtun-ha-direct-primary.conf --hub-id hub-primary --output-dir /tmp/dtun-ha-direct/ha --state-file /tmp/dtun-ha-direct/ha/state"
remote 0 "systemd-run --unit=dtun-ha-direct-primary --collect /tmp/dtun-ha-direct-src/build/dtund -c /tmp/dtun-ha-direct-primary.conf"
invite=$(remote 0 "/tmp/dtun-ha-direct-src/build/dtunctl ha invite create --hub-id hub-backup-1 --weight 900 --expires 10m --bootstrap-address '$PRIMARY_IP' --format plain --state-file /tmp/dtun-ha-direct/ha/state --identity-key /tmp/dtun-ha-direct/ha/identity.key")
printf '%s\n' "$invite" | ssh -T -o ControlPath="${SOCKETS[1]}" "${HOSTS[1]}" "/tmp/dtun-ha-direct-src/build/dtunctl ha join --config /tmp/dtun-ha-direct-backup.conf --output-dir /tmp/dtun-ha-direct/ha --state-file /tmp/dtun-ha-direct/ha/state --invite-id-stdin"
unset invite
remote 1 "systemd-run --unit=dtun-ha-direct-backup --collect /tmp/dtun-ha-direct-src/build/dtund -c /tmp/dtun-ha-direct-backup.conf"
wait_remote 1 "backup promoted to voter" "/tmp/dtun-ha-direct-src/build/dtunctl ha status --state-file /tmp/dtun-ha-direct/ha/state | grep -q 'hub-backup-1.*role=voter'"
wait_remote 1 "direct-pair mode active" "/tmp/dtun-ha-direct-src/build/dtunctl ha status --state-file /tmp/dtun-ha-direct/ha/state | grep -q 'Mode: direct-pair'"

section "Create Spokes"
LOCAL_OUT=$(ip route get "$PRIMARY_IP" | awk '/ dev / {for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')
BACKUP_OUT=$(remote 1 "ip route get '$PRIMARY_IP' | awk '/ dev / {for(i=1;i<=NF;i++)if(\$i==\"dev\"){print \$(i+1);exit}}'")
sudo bash "$ROOT/tests/ha-real/node-netns.sh" setup dtun-ha-direct-local dthadl 192.168.250.0/24 "$LOCAL_OUT"
remote 1 "bash /tmp/dtun-ha-direct-src/tests/ha-real/node-netns.sh setup dtun-ha-direct-remote dthad1 192.168.251.0/24 '$BACKUP_OUT' '$BACKUP_IP'"
sudo systemd-run --unit=dtun-ha-direct-local-spoke --collect /usr/sbin/ip netns exec dtun-ha-direct-local "$ROOT/build/dtund" -c /tmp/dtun-ha-direct-local.conf
remote 1 "systemd-run --unit=dtun-ha-direct-spoke --collect /usr/sbin/ip netns exec dtun-ha-direct-remote /tmp/dtun-ha-direct-src/build/dtund -c /tmp/dtun-ha-direct-spoke.conf"
wait_log local dtun-ha-direct-local-spoke.service 'Registration successful! NodeID=2' || die "local Spoke registration"
wait_log remote dtun-ha-direct-spoke.service 'Registration successful! NodeID=3' || die "remote Spoke registration"
sudo ip netns exec dtun-ha-direct-local ping -c 3 -W 2 10.77.0.3 >/dev/null || die "cross-Spoke forwarding"
pass "direct-pair Spokes registered and forwarding"

for ((i=0; i<40; i++)); do
    H0=$(remote 0 "sha256sum /tmp/dtun-ha-direct/primary-hub.state | awk '{print \$1}'")
    H1=$(remote 1 "sha256sum /tmp/dtun-ha-direct/backup-1-hub.state | awk '{print \$1}'")
    [[ $H0 == "$H1" ]] && break
    sleep 0.25
done
[[ $H0 == "$H1" ]] || die "direct-pair state replicas differ"
pass "direct-pair state replicated"

section "Direct-pair failover latency"
START_MS=$(date +%s%3N)
remote 0 "systemctl stop dtun-ha-direct-primary.service"
MIGRATION_MS=
while (( $(date +%s%3N) - START_MS <= 2000 )); do
    if sudo timeout 0.2s ip netns exec dtun-ha-direct-local ping -c 1 -W 1 10.77.0.1 >/dev/null 2>&1; then
        MIGRATION_MS=$(( $(date +%s%3N) - START_MS ))
        break
    fi
    sleep 0.05
done
[[ -n $MIGRATION_MS ]] || die "direct-pair migration exceeded 2000ms"
pass "local Spoke data plane migrated in ${MIGRATION_MS}ms"
wait_remote 1 "backup became direct-pair leader" "/tmp/dtun-ha-direct-src/build/dtunctl ha status --state-file /tmp/dtun-ha-direct/ha/state | grep -q 'Leader: hub-backup-1'"
remote 1 "ip netns exec dtun-ha-direct-remote ping -c 3 -W 2 10.77.0.1 >/dev/null" || die "remote Spoke migration"

section "Isolated allocation guard"
remote 1 "systemctl stop dtun-ha-direct-spoke.service; cp /tmp/dtun-ha-direct-spoke.conf /tmp/dtun-ha-direct-new.conf; sed -i 's/node_id = 3/node_id = 4/; s/address = 10.77.0.3\/24/address = 10.77.0.4\/24/; s/hub_address = .*/hub_address = $BACKUP_IP/; /timeout = 2/a once = true' /tmp/dtun-ha-direct-new.conf"
if remote 1 "ip netns exec dtun-ha-direct-remote /tmp/dtun-ha-direct-src/build/dtund -c /tmp/dtun-ha-direct-new.conf"; then
    die "isolated direct-pair accepted a new allocation"
fi
pass "isolated direct-pair rejected new allocation"

section "Recovery"
remote 0 "systemd-run --unit=dtun-ha-direct-primary --collect /tmp/dtun-ha-direct-src/build/dtund -c /tmp/dtun-ha-direct-primary.conf"
wait_remote 0 "primary recovered as standby" "/tmp/dtun-ha-direct-src/build/dtunctl ha status --state-file /tmp/dtun-ha-direct/ha/state | grep -q 'Leader: hub-backup-1'" 80
pass "direct-pair term and leader converged"

section "Result"
echo "All direct-pair real-environment cases passed."
