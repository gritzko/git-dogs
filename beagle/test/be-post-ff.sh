#!/bin/sh
#  be-post-ff.sh — clean same-branch POST: edit a tracked file, then
#  `be post msg`.  Sniff +1 `post`; refs row for trunk advances; wt
#  content-shape changes (new sha for the edited file); baseline
#  branch unchanged (still trunk), tip moves to the new commit.

. "$(dirname "$0")/verbcheck.sh"
. "$(dirname "$0")/setup-primitives.sh"

vc_step "setup: trunk + one commit"
vc_fresh_wt
sp_seed_trunk             # T1, wt on trunk

vc_step "edit x.txt; snapshot before; be post"
usleep 10000
echo "x v2" > x.txt

vc_snapshot before

vc_run ffpost "$BE" post v2

vc_snapshot after

vc_assert_exit 0
vc_assert_appended sniff "^post	\\?#"
#  Trunk row in [refs] should have moved.  Verify by checking that
#  the BEFORE and AFTER trunk-row tips differ.
trunk_before=$(vc_section before refs | awk -F'\t' '$1=="?"{print $2}')
trunk_after=$(vc_section after  refs | awk -F'\t' '$1=="?"{print $2}')
[ -n "$trunk_before" ] && [ -n "$trunk_after" ] \
    || vc_fail "couldn't read trunk row in refs"
[ "$trunk_before" != "$trunk_after" ] \
    || vc_fail "trunk REFS didn't advance ($trunk_before)"
vc_note "trunk REFS advanced $trunk_before -> $trunk_after"

#  baseline.branch stays "" (trunk); tip = new commit = trunk_after.
vc_assert_baseline "" "$trunk_after"

echo "=== be-post-ff: OK ==="
