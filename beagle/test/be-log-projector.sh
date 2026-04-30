#!/bin/sh
#  be-log-projector.sh — VERBS.md `log:` projector.
#
#  Wires `be log:?<ref>[#N]` (branch history) and
#  `be log:./<path>?<ref>[#N]` (file history) through to graf's LOG
#  routine, which walks graf's DAG index (COMMIT_PARENT for branch
#  history, PATH_VER for file history) and prints one commit per line.
#
#  Run: BIN=build-asan/bin sh beagle/test/be-log-projector.sh
#
set -eu

BIN=${BIN:-$(dirname "$(command -v be)")}
BIN=$(cd "$BIN" && pwd)
export PATH="$BIN:$PATH"

TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-be-log-projector}
T=$TMP/$TEST_ID
mkdir -p "$T"
trap 'rm -rf "$T"; rmdir "$TMP" 2>/dev/null || true' EXIT INT TERM

FAIL=0
CASE=0
fail() { echo "FAIL [$CASE]: $*" >&2; FAIL=$((FAIL + 1)); }
pass() { echo "PASS [$CASE]: $*"; }

want_lines() {
    out=$1; n=$2
    got=$(grep -cE '^[0-9a-f]{7} ' "$out" || true)
    [ "$got" = "$n" ] || { fail "want $n commit-rows, got $got in $out"; cat "$out"; return; }
    pass "$n commit-rows"
}

want_grep() {
    out=$1; pat=$2
    grep -qE "$pat" "$out" || { fail "missing /$pat/ in $out"; cat "$out"; return; }
    pass "matched /$pat/"
}

# --- Build a 4-commit repo: a.txt touched in c1/c3, b.txt only in c2/c4
R=$T/repo; mkdir -p "$R"; cd "$R"
sniff init >/dev/null

echo a1 > a.txt
be post -m c1 '?tags/v1' >/dev/null

echo b2 > b.txt
be put b.txt >/dev/null
be post -m c2 >/dev/null

echo a3 >> a.txt
be put a.txt >/dev/null
be post -m c3 >/dev/null

echo b4 >> b.txt
be put b.txt >/dev/null
be post -m c4 '?tags/v4' >/dev/null

# --- Case A: full branch log via tip tag (tags/v4 = c4) ----------
CASE=A
be 'log:?tags/v4#10' > "$T/A.out" 2>&1 || true
want_lines "$T/A.out" 4
want_grep  "$T/A.out" 'c4'
want_grep  "$T/A.out" 'c1'

# --- Case B: branch log truncated by #N --------------------------
CASE=B
be 'log:?tags/v4#2' > "$T/B.out" 2>&1 || true
want_lines "$T/B.out" 2
want_grep  "$T/B.out" 'c4'
want_grep  "$T/B.out" 'c3'

# --- Case C: file log of a.txt — only c1 + c3 touched it ---------
CASE=C
be 'log:./a.txt?tags/v4#10' > "$T/C.out" 2>&1 || true
want_lines "$T/C.out" 2
want_grep  "$T/C.out" 'c3'
want_grep  "$T/C.out" 'c1'

# --- Case D: file log of b.txt — only c2 + c4 touched it ---------
CASE=D
be 'log:./b.txt?tags/v4#10' > "$T/D.out" 2>&1 || true
want_lines "$T/D.out" 2
want_grep  "$T/D.out" 'c4'
want_grep  "$T/D.out" 'c2'

# --- Case E: file log truncated by #N ----------------------------
CASE=E
be 'log:./a.txt?tags/v4#1' > "$T/E.out" 2>&1 || true
want_lines "$T/E.out" 1
want_grep  "$T/E.out" 'c3'

# --- Summary -----------------------------------------------------
echo ""
if [ "$FAIL" = "0" ]; then
    echo "=== be-log-projector OK (5 cases) ==="
else
    echo "=== be-log-projector FAIL ($FAIL case(s)) ==="
    exit 1
fi
