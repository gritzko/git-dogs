#!/bin/sh
#  diff/03-stock-context — repro for the "Stock" splice bug.
#
#  The OLD and NEW versions of `foo.h` share the line:
#      //  Stock comparators for `u8cssHeapZ`.  Each peeks the head row of
#  verbatim — every byte and every token identical, including the
#  `Stock` identifier.  The NEW version inserts a multi-line comment
#  block above this line.
#
#  Expected behaviour: the shared `//  Stock comparators ...` line
#  appears as ONE context line (leading space prefix) in the unified
#  diff output.  `Stock` should appear exactly once in the merged
#  hunk text and never under a `+` or `-` prefix.
#
#  Observed behaviour (BUG): with `be diff:?from#to` going through the
#  WEAVE 2-layer engine, NEIL kills small EQs around the comment-block
#  insertion and the renderer emits a partial `+//  Stock` (truncated
#  insert) plus a full `-//  Stock comparators for ...` (deletion),
#  duplicating the shared identifier across both `+` and `-` lines.
#
#  This test asserts the correct behaviour and fails until the WEAVE/
#  NEIL pipeline preserves the shared `Stock` line as context.

. "$(dirname "$0")/../../lib/case.sh"

OUT="$SCRATCH/../out"
mkdir -p "$OUT"

#  Two commits of foo.h — the OLD content from the user's repro plus
#  the NEW content with the inserted comment block.  Same blob bytes
#  the original `dog/ULOG.h` had at commits 4806969 and 1861cb6.
sleep 0.02; cp "$CASE/01.foo.old.h" foo.h
"$BE" put  foo.h    >/dev/null
"$BE" post 'v1 msg'       >/dev/null
OLD_SHA=$(grep -oE '#[0-9a-f]{40}' .sniff | tail -1 | tr -d '#')

sleep 0.02; cp "$CASE/02.foo.new.h" foo.h
"$BE" put  foo.h    >/dev/null
"$BE" post 'v2 msg'       >/dev/null
NEW_SHA=$(grep -oE '#[0-9a-f]{40}' .sniff | tail -1 | tr -d '#')

"$BE" "diff:foo.h?${OLD_SHA}#${NEW_SHA}" \
    >"$OUT/diff.got.out" 2>"$OUT/diff.got.err" || true

#  Pull the slice around the Stock line out for inspection.
grep -B1 -A4 'Stock' "$OUT/diff.got.out" >"$OUT/stock.got" 2>/dev/null || true

FAIL=0

#  No `+//  Stock` (partial-insert duplicate of the shared line).
if grep -qE '^\+.*//[[:space:]]*Stock' "$OUT/diff.got.out"; then
    echo "FAIL: '+//  Stock' present (Stock incorrectly tagged INS)" >&2
    FAIL=$((FAIL + 1))
fi

#  No `-//  Stock` (paired deletion of the same shared line).
if grep -qE '^-.*//[[:space:]]*Stock' "$OUT/diff.got.out"; then
    echo "FAIL: '-//  Stock' present (Stock incorrectly tagged DEL)" >&2
    FAIL=$((FAIL + 1))
fi

#  And the line must appear as context exactly once.
if [ "$(grep -cE '^[[:space:]]//[[:space:]]*Stock comparators' "$OUT/diff.got.out")" != "1" ]; then
    echo "FAIL: shared '//  Stock comparators' should appear as context exactly once" >&2
    FAIL=$((FAIL + 1))
fi

if [ "$FAIL" != "0" ]; then
    echo "=== diff output around Stock ===" >&2
    cat "$OUT/stock.got" >&2 || true
    echo "=== full diff (first 60 lines) ===" >&2
    head -60 "$OUT/diff.got.out" >&2 || true
    exit 1
fi
