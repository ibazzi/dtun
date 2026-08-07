#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
    echo "usage: $0 setup|cleanup NS VETH SUBNET OUT_IF [PUBLIC_IP]" >&2
    exit 2
}

[[ $# -ge 5 && $# -le 6 ]] || usage
ACTION=$1
NS=$2
VETH=$3
SUBNET=$4
OUT_IF=$5
PUBLIC_IP=${6:-}
STATE="/tmp/dtun-ha-real-net-${NS}.state"

[[ $NS =~ ^[a-zA-Z0-9_-]+$ && $VETH =~ ^[a-zA-Z0-9_-]+$ ]] || usage
[[ $SUBNET =~ ^192\.168\.[0-9]+\.0/24$ ]] || usage
[[ $OUT_IF =~ ^[a-zA-Z0-9_.:-]+$ ]] || usage
[[ -z $PUBLIC_IP || $PUBLIC_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || usage

OCTET=${SUBNET#192.168.}
OCTET=${OCTET%%.*}
HOST_ADDR="192.168.${OCTET}.1"
NS_ADDR="192.168.${OCTET}.2"

cleanup() {
    local original_forward=1
    [[ -f $STATE ]] && read -r original_forward < "$STATE"
    iptables -t nat -D POSTROUTING -s "$SUBNET" -o "$OUT_IF" -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -i "$OUT_IF" -o "$VETH" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "$VETH" -o "$OUT_IF" -j ACCEPT 2>/dev/null || true
    if [[ -n $PUBLIC_IP ]]; then
        iptables -t nat -D PREROUTING -i "$VETH" -p udp -d "$PUBLIC_IP" --dport 49001 -j DNAT --to-destination "$HOST_ADDR" 2>/dev/null || true
        iptables -t nat -D PREROUTING -i "$VETH" -p udp -d "$PUBLIC_IP" --dport 49000 -j DNAT --to-destination "$HOST_ADDR" 2>/dev/null || true
        iptables -t nat -D POSTROUTING -o "$VETH" -p udp --sport 49001 -d "$NS_ADDR" -j SNAT --to-source "$PUBLIC_IP" 2>/dev/null || true
        iptables -t nat -D POSTROUTING -o "$VETH" -p udp --sport 49000 -d "$NS_ADDR" -j SNAT --to-source "$PUBLIC_IP" 2>/dev/null || true
    fi
    ip netns del "$NS" 2>/dev/null || true
    ip link del "$VETH" 2>/dev/null || true
    sysctl -qw "net.ipv4.ip_forward=${original_forward}" || true
    rm -f "$STATE"
}

case $ACTION in
cleanup)
    cleanup
    ;;
setup)
    [[ ! -e $STATE ]] || { echo "network state already exists: $STATE" >&2; exit 1; }
    cat /proc/sys/net/ipv4/ip_forward > "$STATE"
    trap 'cleanup' ERR
    sysctl -qw net.ipv4.ip_forward=1
    ip netns add "$NS"
    ip link add "$VETH" type veth peer name eth0 netns "$NS"
    ip addr add "$HOST_ADDR/24" dev "$VETH"
    ip link set "$VETH" up
    ip -n "$NS" link set lo up
    ip -n "$NS" addr add "$NS_ADDR/24" dev eth0
    ip -n "$NS" link set eth0 up
    ip -n "$NS" route add default via "$HOST_ADDR"
    iptables -I FORWARD 1 -i "$VETH" -o "$OUT_IF" -j ACCEPT
    iptables -I FORWARD 1 -i "$OUT_IF" -o "$VETH" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$OUT_IF" -j MASQUERADE
    if [[ -n $PUBLIC_IP ]]; then
        # Cloud public addresses are commonly 1:1 NAT mappings and are not
        # assigned to a local interface.  A co-located namespace must still
        # exercise the advertised public endpoint, so provide explicit
        # hairpin DNAT while preserving that public source on replies.
        iptables -t nat -A PREROUTING -i "$VETH" -p udp -d "$PUBLIC_IP" --dport 49001 -j DNAT --to-destination "$HOST_ADDR"
        iptables -t nat -A PREROUTING -i "$VETH" -p udp -d "$PUBLIC_IP" --dport 49000 -j DNAT --to-destination "$HOST_ADDR"
        iptables -t nat -A POSTROUTING -o "$VETH" -p udp --sport 49001 -d "$NS_ADDR" -j SNAT --to-source "$PUBLIC_IP"
        iptables -t nat -A POSTROUTING -o "$VETH" -p udp --sport 49000 -d "$NS_ADDR" -j SNAT --to-source "$PUBLIC_IP"
    fi
    trap - ERR
    ;;
*)
    usage
    ;;
esac
