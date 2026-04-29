#!/bin/sh
#  be-patch-clean.sh — patch a sibling branch into trunk.  Per
#  VERBS.md §PATCH and Invariant 2 (linear branches, single-parent
#  commits), PATCH erases provenance: the baseline stays single-tip
#  and the next POST emits a single-parent commit on cur.

. "$(dirname "$0")/verbcheck.sh"
. "$(dirname "$0")/setup-primitives.sh"

vc_step "setup: trunk + ?feat with divergent commits"
vc_fresh_wt
sp_seed_trunk             # T1 on trunk
sp_label_feat             # ?feat at T1
sp_switch_feat            # wt on feat
sleep 0.1
echo "y" > y.txt
"$BE" put y.txt >/dev/null
"$BE" post add y on feat >/dev/null
FEAT_HEAD=$(awk -F'\t' '$2=="post"{h=$3;sub(/^[^#]*#/,"",h);last=h} END{print last}' .sniff)

"$BE" get "?" >/dev/null  # back on trunk
sleep 0.1
echo "x v2" > x.txt
"$BE" post v2 on trunk >/dev/null

vc_snapshot before

vc_step "be patch ?feat — pull feat into wt"
vc_run patch "$BE" patch "?feat"

vc_snapshot after_patch

vc_assert_exit 0
vc_assert_appended sniff "^patch	" before after_patch
#  Per spec, PATCH leaves the baseline single-tip — no `&<theirs>`
#  appended, so patch_parents (= number of `&` in baseline query)
#  stays at 0.  Provenance is erased.
b=$(vc_section after_patch baseline)
pp=$(printf '%s\n' "$b" | awk -F= '$1=="patch_parents"{print $2}')
[ "$pp" = "0" ] || vc_fail "patch_parents=$pp (want 0; PATCH erases provenance)"
vc_note ".sniff baseline single-tip after PATCH (history erased)"

vc_step "be post merge feat — emit a single-parent commit on cur"
vc_run merge "$BE" post merge feat

vc_snapshot after_post

vc_assert_exit 0

#  Verify the new commit has exactly 1 parent (cur's prior tip).
#  Per VERBS.md §PATCH, PATCH never produces a merge commit.
SQUASH=$(vc_section after_post sniff | awk '$1=="post"{last=$2} END{
    h=last; sub(/^[^#]*#/, "", h); print h
}')
PARENTS=$(keeper get ".#$SQUASH" 2>/dev/null | awk '/^parent / {print $2}' | wc -l)
[ "$PARENTS" = "1" ] \
    || vc_fail "merge commit has $PARENTS parents, want 1 (single-parent)"
vc_note "merge commit has 1 parent (single-parent absorb confirmed)"

#  Baseline still single-tip after POST.
b=$(vc_section after_post baseline)
pp=$(printf '%s\n' "$b" | awk -F= '$1=="patch_parents"{print $2}')
[ "$pp" = "0" ] || vc_fail "patch_parents=$pp after POST (want 0)"
vc_note "baseline single-tip after POST"

echo "=== be-patch-clean: OK ==="
