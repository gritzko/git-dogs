#!/bin/sh
#  diff/02-divergent-children — two child branches diverge from trunk
#  with disjoint edits to foo.c; check `be get diff:foo.c?fix1..fix2`
#  and the reverse direction emit the expected token-level
#  unified-diff between the two siblings.
#
#  NOTE on label form: unlike the v1/v2/v3 case where bare labels need
#  explicit `?tags/<name>` refs, child branches created via
#  `be post ?./fix1` ARE first-class branch labels and resolve directly
#  in `?fix1..fix2`.  No SHA fallback needed.

. "$(dirname "$0")/../../lib/case.sh"

#  --- trunk baseline -----------------------------------------------
sleep 0.02; cp "$CASE/01.foo.c" foo.c
touch -d "2026-04-20 12:01:00" foo.c
"$BE" put foo.c >/dev/null
"$BE" post 'baseline msg' >/dev/null

#  --- create + switch to ?fix1, edit, post --------------------------
"$BE" put '?./fix1' >/dev/null
"$BE" get  '?fix1'   >/dev/null
sleep 0.02; cp "$CASE/02.foo.fix1.c" foo.c
touch -d "2026-04-20 12:02:00" foo.c
"$BE" put foo.c >/dev/null
"$BE" post 'c1 msg' >/dev/null

#  --- back to trunk, create + switch to ?fix2, edit, post -----------
"$BE" get  '?..'     >/dev/null
"$BE" put '?./fix2' >/dev/null
"$BE" get  '?fix2'   >/dev/null
sleep 0.02; cp "$CASE/03.foo.fix2.c" foo.c
touch -d "2026-04-20 12:03:00" foo.c
"$BE" put foo.c >/dev/null
"$BE" post 'c1 msg' >/dev/null

#  --- diff fix1..fix2 (forward) -------------------------------------
"$BE" get 'diff:foo.c?fix1#fix2' \
    >04.diff_fix1_fix2.got.out 2>04.diff_fix1_fix2.got.err
match "$CASE/04.diff_fix1_fix2.want.txt" 04.diff_fix1_fix2.got.out
empty 04.diff_fix1_fix2.got.err

#  --- diff fix2..fix1 (reverse) -------------------------------------
"$BE" get 'diff:foo.c?fix2#fix1' \
    >05.diff_fix2_fix1.got.out 2>05.diff_fix2_fix1.got.err
match "$CASE/05.diff_fix2_fix1.want.txt" 05.diff_fix2_fix1.got.out
empty 05.diff_fix2_fix1.got.err
