#!/bin/sh
#  be-get-dirty-overlap.sh — same-branch `be get T1` from a wt at T2
#  with x.txt dirty.  Phase 2: instead of refusing, sniff hands the
#  dirty path to graf for a weave-merge (wt as an implicit edit on
#  baseline) and writes the merged bytes back.  GET succeeds; the
#  baseline + .sniff move to T1.

. "$(dirname "$0")/verbcheck.sh"
. "$(dirname "$0")/setup-primitives.sh"

vc_step "setup: two trunk tips; wt at T2 with dirty x.txt"
vc_fresh_wt
sp_seed_two_tips          # exports T1, T2 (wt now at T2)
sp_make_dirty x.txt

vc_step "be get $T1 — dirty x.txt → weave-merged in place"
vc_run merge "$BE" get "$T1"

vc_assert_exit 0
vc_assert_stderr merge "weave-merged"
vc_assert_stderr merge "checkout done"
#  x.txt remains on disk (not unlinked / not refused-and-rolled-back).
[ -f x.txt ] || { echo "FAIL: x.txt missing after merge GET" >&2; exit 1; }

echo "=== be-get-dirty-overlap: OK ==="
