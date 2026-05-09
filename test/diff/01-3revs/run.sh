#!/bin/sh
#  diff/01-3revs — three-revision history; check `diff:` projector
#  emits the expected token-level unified-diff for v1..v2 and v2..v3.
#
#  NOTE on label form: the bare `?v1..v2` URI does NOT resolve — `be
#  post v1` only stamps the commit message, not a ref label.  Refs
#  must be created explicitly with `be post -m <msg> '?tags/v1'`,
#  matching the convention used by graf/test/toy.sh and
#  beagle/test/be-diff-projector.sh.  We use that form below.

. "$(dirname "$0")/../../lib/case.sh"

#  --- v1 ------------------------------------------------------------
sleep 0.02; cp "$CASE/01.foo.c" foo.c
touch -d "2026-04-20 12:01:00" foo.c
"$BE" put foo.c >/dev/null
"$BE" post -m v1 '?tags/v1' >/dev/null

#  --- v2 ------------------------------------------------------------
sleep 0.02; cp "$CASE/02.foo.c" foo.c
touch -d "2026-04-20 12:02:00" foo.c
"$BE" put foo.c >/dev/null
"$BE" post -m v2 '?tags/v2' >/dev/null

#  --- v3 ------------------------------------------------------------
sleep 0.02; cp "$CASE/03.foo.c" foo.c
touch -d "2026-04-20 12:03:00" foo.c
"$BE" put foo.c >/dev/null
"$BE" post -m v3 '?tags/v3' >/dev/null

#  --- diff v1..v2 ---------------------------------------------------
"$BE" get 'diff:foo.c?tags/v1#tags/v2' \
    >04.diff_v1_v2.got.out 2>04.diff_v1_v2.got.err
match "$CASE/04.diff_v1_v2.want.txt" 04.diff_v1_v2.got.out
empty 04.diff_v1_v2.got.err

#  --- diff v2..v3 ---------------------------------------------------
"$BE" get 'diff:foo.c?tags/v2#tags/v3' \
    >05.diff_v2_v3.got.out 2>05.diff_v2_v3.got.err
match "$CASE/05.diff_v2_v3.want.txt" 05.diff_v2_v3.got.out
empty 05.diff_v2_v3.got.err
