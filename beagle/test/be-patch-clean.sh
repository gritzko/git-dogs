#!/bin/sh
#  be-patch-clean.sh — patch a sibling branch into trunk.  PATCH
#  appends one `patch` row carrying the source tip; subsequent POST
#  drains it into a real multi-parent commit.

. "$(dirname "$0")/verbcheck.sh"
. "$(dirname "$0")/setup-primitives.sh"

vc_step "setup: trunk + ?feat with divergent commits"
vc_fresh_wt
sp_seed_trunk             # T1 on trunk
sp_label_feat             # ?feat at T1
sp_switch_feat            # wt on feat
usleep 10000
echo "y" > y.txt
"$BE" put y.txt >/dev/null
"$BE" post add y on feat >/dev/null
FEAT_HEAD=$(awk -F'\t' '$2=="post"{h=$3;sub(/^[^#]*#/,"",h);last=h} END{print last}' .sniff)

"$BE" get "?" >/dev/null  # back on trunk
usleep 10000
echo "x v2" > x.txt
"$BE" post v2 on trunk >/dev/null

vc_snapshot before

vc_step "be patch ?feat — pull feat into wt"
vc_run patch "$BE" patch "?feat"

vc_snapshot after_patch

vc_assert_exit 0
vc_assert_appended sniff "^patch	" before after_patch
#  After PATCH, baseline.patch_parents should be 1 (one extra parent
#  recorded in the query).
b=$(vc_section after_patch baseline)
pp=$(printf '%s\n' "$b" | awk -F= '$1=="patch_parents"{print $2}')
[ "$pp" = "1" ] || vc_fail "patch_parents=$pp (want 1)"
vc_note ".sniff baseline now has 1 patch parent"

vc_step "be post merge feat — drain the patch parent into a real commit"
vc_run merge "$BE" post merge feat

vc_snapshot after_post

vc_assert_exit 0

#  Verify the new commit has 2 parents.  Latest post row's fragment
#  is the new commit sha; query the keeper.
SQUASH=$(vc_section after_post sniff | awk '$1=="post"{last=$2} END{
    h=last; sub(/^[^#]*#/, "", h); print h
}')
PARENTS=$(keeper get ".#$SQUASH" 2>/dev/null | awk '/^parent / {print $2}' | wc -l)
[ "$PARENTS" = "2" ] \
    || vc_fail "merge commit has $PARENTS parents, want 2"
vc_note "merge commit has 2 parents (multi-parent drain confirmed)"

#  Patch parents reset to 0 after POST drains them.
b=$(vc_section after_post baseline)
pp=$(printf '%s\n' "$b" | awk -F= '$1=="patch_parents"{print $2}')
[ "$pp" = "0" ] || vc_fail "patch_parents=$pp after POST (want 0)"
vc_note "baseline reset (patch_parents=0)"

echo "=== be-patch-clean: OK ==="
