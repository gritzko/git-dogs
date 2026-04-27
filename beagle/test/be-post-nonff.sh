#!/bin/sh
#  be-post-nonff.sh — `be post msg` refuses with SNIFFNOFF when the
#  target's REFS tip is on an unrelated lineage (GRAFLca returns 0,
#  so it's not an ancestor of wt.base).  Simulated by appending a
#  fake `?#deadbeef…` row to .dogs/refs.

. "$(dirname "$0")/verbcheck.sh"
. "$(dirname "$0")/setup-primitives.sh"

vc_step "setup: two trunk tips; poison REFS with unrelated tip"
vc_fresh_wt
sp_seed_two_tips
sp_poison_refs "?"        # trunk now has a fake unrelated tip

vc_snapshot before

vc_step "be post v3 — non-ff against unrelated REFS tip → refused"
usleep 10000
echo "x v3" > x.txt
vc_run nonff "$BE" post v3

vc_snapshot after

vc_assert_exit nonzero
vc_assert_stderr nonff "non-ff"
vc_assert_unchanged sniff
vc_assert_unchanged refs
vc_assert_unchanged baseline

echo "=== be-post-nonff: OK ==="
