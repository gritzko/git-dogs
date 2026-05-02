#!/bin/sh
#  be-get-overlay-delete-dirty.sh — `be get T2` from a wt at T1 where
#  T2 has removed `d.txt`, and the wt copy of `d.txt` is dirty.
#  Phase 2: the path goes through graf's weave-merge with tgt's
#  history empty for d.txt — the wt's local edit survives in the
#  merge output.  GET succeeds; d.txt remains on disk with the
#  user's edit preserved.

. "$(dirname "$0")/verbcheck.sh"
. "$(dirname "$0")/setup-primitives.sh"

vc_step "setup: T1 (d.txt + k.txt), T2 (k.txt only); wt at T1 with d.txt dirty"
vc_fresh_wt
echo "k stable" > k.txt
echo "d v1"     > d.txt
"$BE" post 'v1 msg' >/dev/null
T1=$(sp_head_hex)

#  Drop d.txt and post: T2 has only k.txt.
sleep 0.1
"$BE" delete d.txt >/dev/null
"$BE" post 'v2 msg' >/dev/null
T2=$(sp_head_hex)

#  Switch back to T1 so the wt has d.txt again, then dirty it.
"$BE" get "$T1" >/dev/null
sleep 0.1
echo "d user edit $(date +%N)" >> d.txt

vc_step "be get $T2 — dirty d.txt → weave-merged (tgt-empty side preserves wt edit)"
vc_run delete_dirty "$BE" get "$T2"

vc_assert_exit 0
vc_assert_stderr delete_dirty "weave-merged"
[ -f d.txt ] || { echo "FAIL: d.txt removed despite dirty edit" >&2; exit 1; }

echo "=== be-get-overlay-delete-dirty: OK ==="
