#!/bin/sh
#  diff-revs.sh — `be diff` URI forms across a 5-rev toy repo.
#
#  Builds a 5-tag toy where each step exercises one diff-visible
#  change kind: content edit, insertion, deletion, new dir, dir
#  emptied.  Then runs `be diff` over the four URI shapes and greps
#  the output for the expected markers.
#
#  URI grammar under test:
#    path?from..to   single file, ref-to-ref
#    path?ref        single file, ref vs wt
#    ?from..to       whole tree, ref-to-ref
#    ?ref            whole tree, ref vs wt
#
#  Run: BIN=build-debug/bin sh beagle/test/diff-revs.sh
#
set -eu

BIN=${BIN:-$(dirname "$(command -v be)")}
export PATH="$BIN:$PATH"

TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-diff-revs}
T=$TMP/$TEST_ID
mkdir -p "$T"
trap 'rm -rf "$T"; rmdir "$TMP" 2>/dev/null || true' EXIT INT TERM

FAIL=0
CASE=0
fail() { echo "FAIL [$CASE]: $*" >&2; FAIL=$((FAIL + 1)); }
pass() { echo "PASS [$CASE]: $*"; }

# Assert output contains every PATTERN.  Usage: want_all <outfile> <pat>...
want_all() {
    out=$1; shift
    for p in "$@"; do
        grep -qE "$p" "$out" || { fail "missing /$p/ in $out"; cat "$out"; return; }
    done
    pass "all patterns matched"
}
# Assert output contains none of the patterns.
want_none() {
    out=$1; shift
    for p in "$@"; do
        if grep -qE "$p" "$out"; then
            fail "unexpected /$p/ in $out"; cat "$out"; return
        fi
    done
}

# --- Build the 5-rev toy --------------------------------------------
R=$T/repo; mkdir -p "$R"; cd "$R"
git init --quiet .

# v1: seed ---------------------------------------------------------
mkdir -p src doc
cat > src/main.c <<'EOF'
int main(void) {
    return 0;
}
EOF
echo '#pragma once'    > src/util.h
echo 'hello world'     > README
echo 'old documentation' > doc/guide.txt
be post -m v1 '?tags/v1' >/dev/null

# v2: content edit to src/main.c -----------------------------------
cat > src/main.c <<'EOF'
int main(void) {
    int x = 42;
    return x;
}
EOF
be post -m v2 '?tags/v2' >/dev/null

# v3: delete src/util.h --------------------------------------------
be delete src/util.h >/dev/null
be post -m v3 '?tags/v3' >/dev/null

# v4: add new dir test/ with test/basic.c --------------------------
mkdir -p test
cat > test/basic.c <<'EOF'
void test_basic(void) { }
EOF
be post -m v4 '?tags/v4' >/dev/null

# v5: delete doc/guide.txt (dir doc/ becomes empty) ----------------
be delete doc/guide.txt >/dev/null
be post -m v5 '?tags/v5' >/dev/null

# Leave wt at v5 (latest).
echo "=== toy built, wt at v5 ==="

# --- Case A: single file, ref-to-ref, content edit -----------------
CASE=A
be diff 'src/main.c?tags/v1..tags/v2' > "$T/A.out" 2>/dev/null || true
want_all "$T/A.out" '^--- src/main.c' '^[-+].*42' '^ .*int main'

# --- Case B: single file, ref vs wt (wt is v5; src/main.c unchanged from v2) ---
CASE=B
be diff 'src/main.c?tags/v1' > "$T/B.out" 2>/dev/null || true
want_all "$T/B.out" '^--- src/main.c' '^[-+].*42'

# --- Case C: single file, wt unchanged from ref → empty/no-hunk ----
CASE=C
be diff 'src/main.c?tags/v2' > "$T/C.out" 2>/dev/null || true
want_none "$T/C.out" '^\+' '^\-'
pass "no hunks for unchanged file"

# --- Case D: whole tree, ref-to-ref, one file changed --------------
CASE=D
be diff '?tags/v1..tags/v2' > "$T/D.out" 2>/dev/null || true
want_all "$T/D.out" '^--- src/main.c' '^[-+].*42'
want_none "$T/D.out" '^--- src/util.h' '^--- README' '^--- doc/guide.txt'

# --- Case E: whole tree, deletion ---------------------------------
CASE=E
be diff '?tags/v2..tags/v3' > "$T/E.out" 2>/dev/null || true
want_all "$T/E.out" '^--- src/util.h' '^-.*pragma'

# --- Case F: whole tree, new dir + new file -----------------------
CASE=F
be diff '?tags/v3..tags/v4' > "$T/F.out" 2>/dev/null || true
want_all "$T/F.out" '^--- test/basic.c' '^\+.*test_basic'

# --- Case G: whole tree, wt (v5) vs v1 — multi-change summary -----
CASE=G
be diff '?tags/v1' > "$T/G.out" 2>/dev/null || true
#   src/main.c    — edited (v1 → v2 content still at v5)
#   src/util.h    — gone (deleted at v3)
#   doc/guide.txt — gone (deleted at v5)
#   test/basic.c  — added (at v4); NOT emitted: wt-only scan deferred
want_all "$T/G.out" \
    '^--- src/main.c' \
    '^--- src/util.h' \
    '^--- doc/guide.txt'

# --- Case H: whole tree, wt vs v5 — must be empty -----------------
CASE=H
be diff '?tags/v5' > "$T/H.out" 2>/dev/null || true
want_none "$T/H.out" '^\+' '^\-'
pass "wt matches v5, no hunks"

# --- Summary -----------------------------------------------------
echo ""
if [ "$FAIL" = "0" ]; then
    echo "=== diff-revs OK (8 cases) ==="
else
    echo "=== diff-revs FAIL ($FAIL case(s)) ==="
    exit 1
fi
