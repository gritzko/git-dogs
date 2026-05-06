#!/bin/sh
#  03-subtree-overlay — `be get src/?feat` (trailing slash) overlays
#  every leaf under `src/` from feat's tip into the wt.  Trunk and
#  feat both have `src/`; feat differs in two existing files and
#  adds a new one.  After the overlay, all three feat-side files
#  land in the wt; files outside `src/` (here `common.txt`) and the
#  baseline (cur stays on trunk) are untouched.  No `.sniff` row
#  is appended (no staging — VERBS.md §GET).

. "$(dirname "$0")/../../lib/case.sh"

# T0 trunk baseline: src/x.c, src/y.c, common.txt
mkdir -p src
sleep 0.02; cp "$CASE/01.x.trunk.c"  src/x.c
sleep 0.02; cp "$CASE/02.y.trunk.c"  src/y.c
sleep 0.02; cp "$CASE/03.common.txt" common.txt
"$BE" put src/x.c src/y.c common.txt > /dev/null
sleep 0.02   # let wallclock catch up to the 3-row put tail-ts ratchet
"$BE" post '#trunk'                    > /dev/null

# Fork ?feat
"$BE" put '?./feat' > /dev/null
"$BE" get '?feat'   > /dev/null

# F1: feat-side rewrites x.c, y.c and adds z.c (but does not touch common.txt)
sleep 0.02; cp "$CASE/04.x.feat.c" src/x.c
sleep 0.02; cp "$CASE/05.y.feat.c" src/y.c
sleep 0.02; cp "$CASE/06.z.feat.c" src/z.c
"$BE" put src/x.c src/y.c src/z.c > /dev/null
sleep 0.02   # ratchet catch-up (see above)
"$BE" post '#feat'                  > /dev/null

# Back to trunk
"$BE" get '?..' > /dev/null

# Sanity: wt is at trunk version (no z.c, x/y are trunk-side).
match "$CASE/01.x.trunk.c"  src/x.c
match "$CASE/02.y.trunk.c"  src/y.c
match "$CASE/03.common.txt" common.txt
[ ! -f src/z.c ] || { echo "src/z.c should not exist on trunk" >&2; exit 1; }

# Snapshot .sniff length to assert no new row appended.
ROWS_BEFORE=$(wc -l < .sniff)

# THE TEST: subtree overlay from ?feat.
"$BE" get 'src/?feat' > 07.get.got.out 2> 07.get.got.err
match_re "$CASE/07.get.err.txt" 07.get.got.err

# wt now holds feat's src/* leaves; common.txt stays put.
match "$CASE/04.x.feat.c"  src/x.c
match "$CASE/05.y.feat.c"  src/y.c
match "$CASE/06.z.feat.c"  src/z.c
match "$CASE/03.common.txt" common.txt

# `.sniff` did NOT grow.
ROWS_AFTER=$(wc -l < .sniff)
[ "$ROWS_BEFORE" = "$ROWS_AFTER" ] || {
    echo "subtree get appended a .sniff row (was $ROWS_BEFORE, now $ROWS_AFTER)" >&2
    exit 1
}
