#!/bin/bash
# Run the whole local C-daemon test campaign and log everything.
set -eu
cd "$(dirname "$0")/../.."
OUT=/tmp/dtun-test
mkdir -p "$OUT"

for t in 01-control-plane 02-data-plane 03-stability 04-perf; do
	echo
	echo "########## $t ##########"
	bash "tests/cdaemon/$t.sh" 2>&1 | tee "$OUT/$t.log"
done

echo
echo "All logs under $OUT/"
