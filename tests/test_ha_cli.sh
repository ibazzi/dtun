#!/bin/sh
set -eu
CTL=${CTL:-./build/dtunctl}
TMP=$(mktemp -d /tmp/dtun-ha-cli-XXXXXX)
trap 'rm -rf "$TMP"' EXIT INT TERM

cat >"$TMP/hub.conf" <<EOF
[global]
mode = hub
local_outer_ip = 192.0.2.1
address = 10.99.0.1/24
data_port = 49000
psk = 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
[hub]
bind_port = 49001
pool = 10.99.0.0/24
[ha]
ha_config = $TMP/ha/ha.conf
EOF

"$CTL" ha init --config "$TMP/hub.conf" --hub-id hub-primary \
    --output-dir "$TMP/ha" --state-file "$TMP/state" >"$TMP/init.out"
test -s "$TMP/ha/ha.conf"
test -s "$TMP/ha/identity.key"
test "$(stat -c %a "$TMP/ha/identity.key")" = 600

"$CTL" ha invite create --hub-id hub-backup-1 --weight 900 \
    --expires 10m --state-file "$TMP/state" \
    --identity-key "$TMP/ha/identity.key" >"$TMP/invite.out"
grep -q '^Invite ID: dtun-ha1:' "$TMP/invite.out"

"$CTL" ha invite create --hub-id hub-backup-2 --weight 800 \
    --expires 10m --format plain --state-file "$TMP/state" \
    --identity-key "$TMP/ha/identity.key" >"$TMP/invite.plain"
test "$(wc -l <"$TMP/invite.plain")" -eq 1
grep -Eq '^dtun-ha1:[A-Za-z0-9_-]+$' "$TMP/invite.plain"

"$CTL" ha invite create --hub-id hub-backup-3 --weight 700 \
    --expires 10m --format=json --state-file "$TMP/state" \
    --identity-key "$TMP/ha/identity.key" >"$TMP/invite.json"
test "$(wc -l <"$TMP/invite.json")" -eq 1
grep -Eq '^\{"invite_id":"dtun-ha1:[A-Za-z0-9_-]+","hub_id":"hub-backup-3","weight":700,"expires_at":[0-9]+,"id_prefix":"[0-9a-f]{12}"\}$' "$TMP/invite.json"

if "$CTL" ha invite create --hub-id invalid-output --weight 1 \
    --format yaml --state-file "$TMP/state" \
    --identity-key "$TMP/ha/identity.key" >"$TMP/error.out" 2>"$TMP/error.err"; then
    echo "invalid Invite output format was accepted" >&2
    exit 1
fi
test ! -s "$TMP/error.out"
grep -q 'invalid --format' "$TMP/error.err"
"$CTL" ha status --state-file "$TMP/state" | grep -q 'Mode: bootstrap'
"$CTL" ha invite list --state-file "$TMP/state" | grep -q 'hub=hub-backup-1 weight=900 status=unused'

echo "dtunctl HA configuration tests passed"
