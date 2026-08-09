#!/bin/sh
set -eu

CTL=${CTL:-./build/dtunctl}
TMPDIR_TEST=$(mktemp -d /tmp/dtun-cli-test.XXXXXX)
trap 'rm -rf "$TMPDIR_TEST"' EXIT INT TERM

expect_rc() {
	expected=$1
	shift
	set +e
	"$@" >"$TMPDIR_TEST/out" 2>"$TMPDIR_TEST/err"
	actual=$?
	set -e
	[ "$actual" -eq "$expected" ] || {
		echo "expected rc=$expected, got rc=$actual: $*" >&2
		exit 1
	}
}

expect_rc 2 "$CTL" peer-get --ifname dtun0 --tunnel-id 1 --format yaml
expect_rc 1 "$CTL" route-add --format json --ifindex 4294967295 --tunnel-id 1 --prefix 10.0.0.0/24

set +e
json=$($CTL peer-get --format=json --ifname missing-dtun --tunnel-id 1 2>/dev/null)
rc=$?
set -e
[ "$rc" -ne 0 ]
printf '%s\n' "$json" | grep -Eq '^\{"action":"peer-get","success":false,.*\}$'

echo "dtunctl format tests passed"
