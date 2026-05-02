#!/bin/sh
#  be-get-overlay-real.sh — `be get T1` from a wt at T2 with `a.txt`
#  dirty.  T1 and T2 differ in `a.txt`, so the dirty path is in the
#  diff set.  Phase 2: instead of refusing, the dirty file goes
#  through graf's weave-merge (wt-on-T2 vs T1's history) and the
#  merged bytes are written back.

. "$(dirname "$0")/verbcheck.sh"
. "$(dirname "$0")/setup-primitives.sh"

vc_step "setup: T1 (a v1, b stable), T2 (a v2, b stable); wt at T2 with a.txt dirty"
vc_fresh_wt
echo "a v1" > a.txt
echo "b stable" > b.txt
"$BE" post 'v1 msg' >/dev/null
T1=$(sp_head_hex)

sleep 0.1
echo "a v2" > a.txt
"$BE" post 'v2 msg' >/dev/null
T2=$(sp_head_hex)

sleep 0.1
echo "a user edit $(date +%N)" >> a.txt

vc_step "be get $T1 — a.txt dirty AND in the diff set → weave-merged"
vc_run merge "$BE" get "$T1"

vc_assert_exit 0
vc_assert_stderr merge "weave-merged"
vc_assert_stderr merge "checkout done"
[ -f a.txt ] || { echo "FAIL: a.txt missing after merge GET" >&2; exit 1; }

echo "=== be-get-overlay-real: OK ==="
