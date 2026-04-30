#!/bin/sh
#  be-map-projector.sh — VERBS.md `map:` projector.
#
#  Builds a 4-branch layout, each with its own commit so every
#  branch shows up as a distinct row in the map output:
#
#       trunk      (commit: t1)
#       ├── feat   (commit: f1)
#       │   └── feat/sub  (commit: s1)
#       └── docs   (commit: d1)
#
#  And verifies `be map:` filters per the spec:
#    wt on ?feat/sub  → trunk, ?feat, ?feat/sub  (ancestors + self)
#    wt on trunk      → trunk, ?feat, ?feat/sub, ?docs  (all descendants)
#    wt on ?feat      → trunk, ?feat, ?feat/sub        (sibling ?docs out)
#
set -eu

BIN=${BIN:-$(dirname "$(command -v be)")}
BIN=$(cd "$BIN" && pwd)
export PATH="$BIN:$PATH"

TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-be-map-projector}
T=$TMP/$TEST_ID
rm -rf "$T"
mkdir -p "$T"
trap 'rm -rf "$T"; rmdir "${TMP}" 2>/dev/null || true' EXIT INT TERM

FAIL=0
CASE=0
fail() { echo "FAIL [$CASE]: $*" >&2; FAIL=$((FAIL + 1)); }
pass() { echo "PASS [$CASE]: $*"; }

want_grep() {
    out=$1; pat=$2
    grep -qE "$pat" "$out" || { fail "missing /$pat/ in $out"; cat "$out"; return; }
    pass "matched /$pat/"
}

want_no_grep() {
    out=$1; pat=$2
    grep -qE "$pat" "$out" && { fail "unwanted /$pat/ in $out"; cat "$out"; return; }
    pass "absent /$pat/"
}

# --- 4 branches each with one own commit ----------------------------
R=$T/repo; mkdir -p "$R"; cd "$R"
sniff init >/dev/null

echo "trunk content" > base.txt
be post -m "trunk-c1" >/dev/null

be post '?./feat' >/dev/null
be get '?feat' >/dev/null 2>&1
echo feat-content > feat.txt
be put feat.txt >/dev/null
be post -m "feat-c1" >/dev/null

be post '?./sub' >/dev/null
be get '?feat/sub' >/dev/null 2>&1
echo sub-content > sub.txt
be put sub.txt >/dev/null
be post -m "sub-c1" >/dev/null

be get '?' >/dev/null 2>&1
be post '?./docs' >/dev/null
be get '?docs' >/dev/null 2>&1
echo docs-content > docs.txt
be put docs.txt >/dev/null
be post -m "docs-c1" >/dev/null

# --- Case A: wt on ?feat/sub ---------------------------------------
CASE=A
be get '?feat/sub' >/dev/null 2>&1
be 'map:' > "$T/A.out" 2>&1
want_grep    "$T/A.out" 'sub-c1'
want_grep    "$T/A.out" 'feat-c1'
want_grep    "$T/A.out" 'trunk-c1'
want_no_grep "$T/A.out" 'docs-c1'
want_no_grep "$T/A.out" '\?docs'

# --- Case B: wt on trunk -------------------------------------------
CASE=B
be get '?' >/dev/null 2>&1
be 'map:' > "$T/B.out" 2>&1
want_grep "$T/B.out" 'trunk-c1'
want_grep "$T/B.out" 'feat-c1'
want_grep "$T/B.out" 'sub-c1'
want_grep "$T/B.out" 'docs-c1'

# --- Case C: wt on ?feat (sibling-exclusion) ------------------------
CASE=C
be get '?feat' >/dev/null 2>&1
be 'map:' > "$T/C.out" 2>&1
want_grep    "$T/C.out" 'trunk-c1'
want_grep    "$T/C.out" 'feat-c1'
want_grep    "$T/C.out" 'sub-c1'
want_no_grep "$T/C.out" 'docs-c1'
want_no_grep "$T/C.out" '\?docs'

# --- Summary --------------------------------------------------------
echo ""
if [ "$FAIL" = "0" ]; then
    echo "=== be-map-projector OK (3 cases) ==="
else
    echo "=== be-map-projector FAIL ($FAIL case(s)) ==="
    exit 1
fi
