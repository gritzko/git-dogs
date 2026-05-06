#!/bin/sh
#  02-single-file-overwrite — `be get file.c?feat` overwrites one wt
#  file from another branch's tip without staging.  Build trunk with
#  `lib.c = "trunk\n"`, fork ?feat, change `lib.c = "feat\n"` and
#  commit.  Switch back to trunk; wt has the trunk version.  Then
#  `be get lib.c?feat` overwrites lib.c with the feat-side blob; the
#  baseline branch (cur) stays trunk and `.sniff` does NOT grow a
#  `get` row (no staging — VERBS.md §GET).

. "$(dirname "$0")/../../lib/case.sh"

# T0 trunk baseline
sleep 0.02; cp "$CASE/01.lib.trunk.c" lib.c
"$BE" put lib.c     > /dev/null
"$BE" post '#trunk' > /dev/null

# Fork + switch to ?feat
"$BE" put '?./feat' > /dev/null
"$BE" get '?feat'   > /dev/null

# F1: feat-side commit replaces lib.c
sleep 0.02; cp "$CASE/02.lib.feat.c" lib.c
"$BE" put lib.c     > /dev/null
"$BE" post '#feat'  > /dev/null

# Back to trunk
"$BE" get '?..' > /dev/null

# Sanity: wt is at trunk version.
match "$CASE/01.lib.trunk.c" lib.c

# Snapshot .sniff length so we can assert no new row is appended.
ROWS_BEFORE=$(wc -l < .sniff)

# THE TEST: single-file overwrite from ?feat.
"$BE" get 'lib.c?feat' > 03.get.got.out 2> 03.get.got.err
match_re "$CASE/03.get.err.txt" 03.get.got.err

# wt now holds the feat-side blob bytes.
match "$CASE/02.lib.feat.c" lib.c

# `.sniff` did NOT grow — overwrite is no-staging (no `get` row).
ROWS_AFTER=$(wc -l < .sniff)
[ "$ROWS_BEFORE" = "$ROWS_AFTER" ] || {
    echo "single-file get appended a .sniff row (was $ROWS_BEFORE, now $ROWS_AFTER)" >&2
    exit 1
}
