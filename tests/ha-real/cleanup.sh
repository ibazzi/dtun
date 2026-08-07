#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
[[ $# -eq 3 ]] || {
    echo "usage: $0 PRIMARY_USER@IP BACKUP1_USER@IP BACKUP2_USER@IP" >&2
    exit 2
}
HOSTS=("$1" "$2" "$3")
TMP=$(mktemp -d /tmp/dtun-ha-cleanup-XXXXXX)
KNOWN="$TMP/known_hosts"
SOCKETS=()

close_masters() {
    local i
    for i in "${!SOCKETS[@]}"; do
        ssh -o ControlPath="${SOCKETS[$i]}" -O exit "${HOSTS[$i]}" >/dev/null 2>&1 || true
    done
    rm -rf "$TMP"
}
trap close_masters EXIT

for i in 0 1 2; do
    socket="$TMP/ssh-$i.sock"
    SOCKETS+=("$socket")
    ssh -MNf -o ControlMaster=yes -o ControlPersist=600 \
        -o ControlPath="$socket" -o UserKnownHostsFile="$KNOWN" \
        -o StrictHostKeyChecking=accept-new "${HOSTS[$i]}"
done

remote() {
    local index=$1
    shift
    ssh -o ControlPath="${SOCKETS[$index]}" "${HOSTS[$index]}" "$@"
}

for i in 1 2; do
    scp -o ControlPath="${SOCKETS[$i]}" "$ROOT/tests/ha-real/node-netns.sh" \
        "${HOSTS[$i]}:/tmp/dtun-ha-real-node-netns.sh"
done

PRIMARY_IP=${HOSTS[0]##*@}
B1_IP=${HOSTS[1]##*@}
B2_IP=${HOSTS[2]##*@}
B1_OUT=$(remote 1 "ip route get '$PRIMARY_IP' | awk '/ dev / {for(i=1;i<=NF;i++)if(\$i==\"dev\"){print \$(i+1);exit}}'")
B2_OUT=$(remote 2 "ip route get '$PRIMARY_IP' | awk '/ dev / {for(i=1;i<=NF;i++)if(\$i==\"dev\"){print \$(i+1);exit}}'")
LOCAL_OUT=$(ip route get "$PRIMARY_IP" | awk '/ dev / {for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')

remote 1 "systemctl stop dtun-ha-real-spoke-1.service dtun-ha-real-backup-1.service 2>/dev/null || true; bash /tmp/dtun-ha-real-node-netns.sh cleanup dtun-ha-real-s1 dthar1 192.168.251.0/24 '$B1_OUT' '$B1_IP'; test ! -e /tmp/dtun-ha-real/module.loaded || rmmod dtun; rm -rf /tmp/dtun-ha-real /tmp/dtun-ha-real-src /tmp/dtun-ha-real-src.tar.gz /tmp/dtun-ha-real-node-netns.sh /tmp/dtun-ha-real-backup-1.conf /tmp/dtun-ha-real-spoke-1.conf"
remote 2 "systemctl stop dtun-ha-real-spoke-2.service dtun-ha-real-backup-2.service 2>/dev/null || true; bash /tmp/dtun-ha-real-node-netns.sh cleanup dtun-ha-real-s2 dthar2 192.168.252.0/24 '$B2_OUT' '$B2_IP'; test ! -e /tmp/dtun-ha-real/module.loaded || rmmod dtun; rm -rf /tmp/dtun-ha-real /tmp/dtun-ha-real-src /tmp/dtun-ha-real-src.tar.gz /tmp/dtun-ha-real-node-netns.sh /tmp/dtun-ha-real-backup-2.conf /tmp/dtun-ha-real-spoke-2.conf /tmp/dtun-ha-real-spoke-new.conf"
remote 0 "systemctl stop dtun-ha-real-primary.service 2>/dev/null || true; test ! -e /tmp/dtun-ha-real/module.loaded || rmmod dtun; rm -rf /tmp/dtun-ha-real /tmp/dtun-ha-real-src /tmp/dtun-ha-real-primary.conf"

sudo systemctl stop dtun-ha-real-local-spoke.service 2>/dev/null || true
sudo bash "$ROOT/tests/ha-real/node-netns.sh" cleanup dtun-ha-real-local dtharl 192.168.250.0/24 "$LOCAL_OUT"
if [[ -e /tmp/dtun-ha-real/module.loaded ]]; then sudo rmmod dtun; fi
sudo rm -rf /tmp/dtun-ha-real /tmp/dtun-ha-real-local-spoke.conf

echo "HA real-environment test assets removed."
