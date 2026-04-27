#!/bin/sh
#  be-post-cross-create.sh — `be post ?feat msg` from a wt on trunk,
#  where ?feat doesn't exist yet, lands the new commit on ?feat
#  only.  Trunk's REFS tip is unchanged; ?feat is born at the new
#  commit; baseline switches to feat.

. "$(dirname "$0")/verbcheck.sh"
. "$(dirname "$0")/setup-primitives.sh"

vc_step "setup: trunk + one post (T1)"
vc_fresh_wt
sp_seed_trunk             # exports T1; wt on trunk

vc_snapshot before

vc_step "be post ?feat feat work — cross-branch create"
usleep 10000
echo "x feat" > x.txt     # actual change so POST isn't empty
vc_run xpost "$BE" post "?feat" feat work

vc_snapshot after

vc_assert_exit 0
vc_assert_appended sniff "^post	\\?feat#"
vc_assert_appended refs  "^\\?feat	"
#  Trunk REFS tip is unchanged — confirm by checking the trunk row
#  has not moved between before and after.
trunk_before=$(vc_section before refs | awk -F'\t' '$1=="?"{print $2}')
trunk_after=$(vc_section after  refs | awk -F'\t' '$1=="?"{print $2}')
[ "$trunk_before" = "$trunk_after" ] \
    || vc_fail "trunk REFS moved: $trunk_before -> $trunk_after"
vc_note "trunk REFS unchanged at $trunk_before"

vc_assert_baseline "feat" ""    # tip changed; not asserting exact sha

echo "=== be-post-cross-create: OK ==="
