#!/bin/sh
#  be-diff-projector.sh — VERBS.md `diff:` projector.
#
#  Per VERBS.md the right-hand-side is always *ours* (the changed state):
#
#    diff:                 → wt vs base    (whole tree)
#    diff:file.c           → wt vs base    (single file)
#    diff:?branch          → branch vs base (whole tree, ref-to-ref)
#    diff:file.c?branch    → branch vs base (single file, ref-to-ref)
#    diff:?from#to         → from vs to    (whole tree, explicit)
#    diff:file.c?from#to   → from vs to    (single file, explicit)
#
#  Output is unified-diff-shape; we don't assert exact bytes — graf's
#  diff is token-level and its renderer evolves.
#
#  Run: BIN=build-asan/bin sh beagle/test/be-diff-projector.sh
#
set -eu

BIN=${BIN:-$(dirname "$(command -v be)")}
BIN=$(cd "$BIN" && pwd)
export PATH="$BIN:$PATH"

TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-be-diff-projector}
T=$TMP/$TEST_ID/$$
mkdir -p "$T"
trap 'rm -rf "$T"; rmdir "${T%/*}" 2>/dev/null || true; rmdir "$TMP" 2>/dev/null || true' EXIT INT TERM

FAIL=0
CASE=0
fail() { echo "FAIL [$CASE]: $*" >&2; FAIL=$((FAIL + 1)); }
pass() { echo "PASS [$CASE]: $*"; }

# Assert the file contains every PATTERN.
want_all() {
    out=$1; shift
    for p in "$@"; do
        grep -qE "$p" "$out" || { fail "missing /$p/ in $out"; cat "$out"; return; }
    done
    pass "all patterns matched"
}

# --- Build a tiny 2-tag repo + 2 files + a wt edit -------------------
#
#  Layout designed so each diff form has a distinct, predictable token
#  delta we can grep for:
#
#                v1                v2 (= cur/base)        wt
#  a.txt    hello world         hello world           hello universe
#           goodnight moon      goodbye moon          goodbye moon
#  b.txt    one                 one two               one two
#                                                     one two three
#
#  v1↔v2: a.txt: 'goodnight'→'goodbye'; b.txt: append ' two'
#  base↔wt: a.txt: 'world'→'universe'; b.txt: append ' three'
#
R=$T/repo; mkdir -p "$R"; cd "$R"
sniff init >/dev/null

cat > a.txt <<'EOF'
hello world
goodnight moon
EOF
echo 'one' > b.txt
be post -m v1 '?tags/v1' >/dev/null

cat > a.txt <<'EOF'
hello world
goodbye moon
EOF
echo 'one two' > b.txt
be post -m v2 '?tags/v2' >/dev/null

# wt drift on top of v2
cat > a.txt <<'EOF'
hello universe
goodbye moon
EOF
cat > b.txt <<'EOF'
one two
one two three
EOF

# --- Case A: file wt-vs-base — `diff:<path>` -----------------------
#  Empty query → from=base (v2 cur), to=wt.
#  a.txt diff: -'world' / +'universe' (line-1).
CASE=A
be 'diff:a.txt' > "$T/A.out" 2>&1 || true
want_all "$T/A.out" '^--- a/a\.txt$' '\-hello world' '\+hello universe'
# wt-vs-base for a SINGLE file should not mention b.txt
grep -q 'b\.txt' "$T/A.out" && fail "A.out shouldn't mention b.txt"

# --- Case B: tree wt-vs-base — `diff:` -----------------------------
#  Both files in the base tree get a per-file weave diff vs wt.
CASE=B
be 'diff:' > "$T/B.out" 2>&1 || true
want_all "$T/B.out" '^--- a/a\.txt$' '\+hello universe' \
                    '^--- a/b\.txt$' '\+one two three'

# --- Case C: file branch-vs-base — `diff:<path>?<branch>` ----------
#  from=v1, to=v2 (cur).  a.txt: -goodnight / +goodbye.
#  No 'universe' should appear (wt is excluded from this comparison).
CASE=C
be get 'diff:a.txt?tags/v1' > "$T/C.out" 2>&1 || true
want_all "$T/C.out" '^--- a/a\.txt$' '\-goodnight moon' '\+goodbye moon'
grep -q 'universe' "$T/C.out" && fail "C.out should NOT mention 'universe' (wt excluded)"

# --- Case D: tree branch-vs-base — `diff:?<branch>` ----------------
#  b.txt v1→v2 = `one\n` → `one two\n`: pure-INS within the line,
#  so the line-based renderer emits `+one two` only (no paired `-old`
#  — that's reconstructed only when a line has both INS and DEL spans).
CASE=D
be get 'diff:?tags/v1' > "$T/D.out" 2>&1 || true
want_all "$T/D.out" '^--- a/a\.txt$' '\-goodnight moon' '\+goodbye moon' \
                    '^--- a/b\.txt$' '\+one two'
grep -q 'universe' "$T/D.out" && fail "D.out should NOT mention 'universe'"

# --- Case E: file ref-to-ref range — `diff:<path>?<from>#<to>` ------
CASE=E
be get 'diff:a.txt?tags/v1#tags/v2' > "$T/E.out" 2>&1 || true
want_all "$T/E.out" '^--- a/a\.txt$' '\-goodnight moon' '\+goodbye moon'
grep -q 'universe' "$T/E.out" && fail "E.out should NOT mention 'universe'"

# --- Case F: tree ref-to-ref range — `diff:?<from>#<to>` ------------
CASE=F
be get 'diff:?tags/v1#tags/v2' > "$T/F.out" 2>&1 || true
want_all "$T/F.out" '^--- a/a\.txt$' '\-goodnight moon' '\+goodbye moon' \
                    '^--- a/b\.txt$' '\+one two'
grep -q 'universe' "$T/F.out" && fail "F.out should NOT mention 'universe'"

# --- Case G: verb-less projector — `be diff:<path>?<branch>` -------
#  The verb-less form (no `get`) routes through the same projector
#  pipeline — sanity check that BE.cli.c doesn't mistake `diff:` for
#  a search/view URI.
CASE=G
be 'diff:a.txt?tags/v1' > "$T/G.out" 2>&1 || true
want_all "$T/G.out" '^--- a/a\.txt$' '\-goodnight' '\+goodbye'

# --- Case H: untracked files are excluded from `diff:` -------------
#  Drop a never-staged file alongside the tracked ones; whole-tree
#  `diff:` must NOT mention it (no baseline → nothing to diff).
CASE=H
echo 'random scratch bytes' > scratch.txt
be 'diff:' > "$T/H.out" 2>&1 || true
grep -q 'scratch\.txt' "$T/H.out" \
    && fail "H.out should NOT mention untracked scratch.txt"
# But the tracked diffs must still be there.
want_all "$T/H.out" '^--- a/a\.txt$' '\+hello universe' \
                    '^--- a/b\.txt$' '\+one two three'
rm -f scratch.txt

# --- Summary -----------------------------------------------------
echo ""
if [ "$FAIL" = "0" ]; then
    echo "=== be-diff-projector OK (8 cases) ==="
else
    echo "=== be-diff-projector FAIL ($FAIL case(s)) ==="
    exit 1
fi
