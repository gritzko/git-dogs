#!/bin/sh
#  be-map-projector.sh — VERBS.md `map:` projector.
#
#  Builds a 4-branch layout:
#       trunk
#       ├── feat
#       │   └── feat/sub
#       └── docs               (sibling of ?feat)
#
#  And verifies `be map:` filters per the spec:
#    wt on ?feat/sub  → trunk, ?feat, ?feat/sub  (ancestors + self)
#    wt on trunk      → trunk, ?feat, ?feat/sub, ?docs  (all descendants)
#    wt on ?feat      → trunk, ?feat, ?feat/sub  (ancestor + self + desc;
#                                                  ?docs is a sibling — out)
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

# --- Build the 4-branch layout ---------------------------------------
R=$T/repo; mkdir -p "$R"; cd "$R"
sniff init >/dev/null

# Trunk: one commit
echo "trunk content" > base.txt
be post -m "trunk-c1" >/dev/null

# ?feat at trunk's tip
be post '?feat' >/dev/null

# Switch to ?feat, advance, fork ?feat/sub
be get '?feat' >/dev/null 2>&1
be post '?./sub' >/dev/null

# ?docs: sibling of ?feat (root-level branch off trunk)
be get '?' >/dev/null 2>&1
be post '?docs' >/dev/null

# --- Case A: wt on ?feat/sub -----------------------------------------
CASE=A
be get '?feat/sub' >/dev/null 2>&1
be 'map:' > "$T/A.out" 2>&1
want_grep    "$T/A.out" '\*feat/sub'                    # current marker
want_grep    "$T/A.out" '^\?feat[[:space:]]'            # ancestor row
want_grep    "$T/A.out" '^\?[[:space:]]'                # trunk row
want_no_grep "$T/A.out" '\?docs'                        # sibling out

# --- Case B: wt on trunk ----------------------------------------------
CASE=B
be get '?' >/dev/null 2>&1
be 'map:' > "$T/B.out" 2>&1
want_grep "$T/B.out" '^\*[[:space:]]'                   # trunk current
want_grep "$T/B.out" '\?feat'                           # descendant
want_grep "$T/B.out" 'feat/sub'                         # nested descendant
want_grep "$T/B.out" '\?docs'                           # sibling-of-feat is descendant of trunk

# --- Case C: wt on ?feat (sibling-exclusion) -------------------------
CASE=C
be get '?feat' >/dev/null 2>&1
be 'map:' > "$T/C.out" 2>&1
want_grep    "$T/C.out" '\*feat[[:space:]]'             # current
want_grep    "$T/C.out" '^\?[[:space:]]'                # trunk ancestor
want_grep    "$T/C.out" 'feat/sub'                      # descendant
want_no_grep "$T/C.out" '\?docs'                        # sibling out

# --- Summary ---------------------------------------------------------
echo ""
if [ "$FAIL" = "0" ]; then
    echo "=== be-map-projector OK (3 cases) ==="
else
    echo "=== be-map-projector FAIL ($FAIL case(s)) ==="
    exit 1
fi
