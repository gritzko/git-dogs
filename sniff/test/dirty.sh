#!/bin/sh
#  dirty.sh — sniff GET pre-flight tests for dirty-wt refuse paths.
#
#  Verifies the post-Phase-1 GET semantics:
#    * cross-branch GET refused on any unattributed-mtime wt file
#      (SNIFFDRTY); .sniff and the wt are unchanged on refusal,
#    * cross-branch GET allowed on a clean wt,
#    * same-branch GET refused when a target-tree file overlaps a
#      dirty wt file (SNIFFOVRL),
#    * same-branch GET allowed when the dirty wt file is untracked
#      (not in the target tree).
#
#  Run: BIN=build-debug/bin sh sniff/test/dirty.sh
set -eu

BIN=${BIN:-$(dirname "$0")/../../build-debug/bin}
export PATH="$BIN:$PATH"
export ASAN_OPTIONS="${ASAN_OPTIONS:-}:detect_leaks=0"

TMP=${TMP:-$HOME/tmp}
TEST_ID=${TEST_ID:-SNIFFdirty}
TMP=$TMP/$$/$TEST_ID
trap 'rm -rf "$TMP"' EXIT INT TERM
mkdir -p "$TMP"

fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "  - $*"; }

#  Tail-row sha helper — same shape as workflow.sh / squash.sh.
head_hex() {
    awk -F'\t' '$2=="post" || $2=="get" || $2=="patch" { last=$3 }
                END {
                    h = last
                    sub(/^[^#]*#/, "", h)
                    if (length(h) == 40 && h ~ /^[0-9a-f]+$/) print h
                }' .sniff
}

#  Last meaningful (verb + uri) row.  Skips any trailing pad bytes
#  left behind by FILEBook page-align if SNIFFClose's trim fails
#  to run on an early-fail (rw open without subsequent write — see
#  the get pre-flight refuse paths).
last_row() {
    awk -F'\t' 'NF >= 2 && $2 != "" { last=$0 } END { print last }' .sniff
}

# ====================================================================
# Scenario 1 — clean cross-branch GET succeeds.
# ====================================================================
echo "=== 1. clean cross-branch GET succeeds ==="
WT="$TMP/wt1"
mkdir -p "$WT"; cd "$WT"
echo "a v1" > a.txt
echo "b v1" > b.txt
sniff post -m "trunk base" >/dev/null
TRUNK=$(head_hex)
note "trunk base = $TRUNK"

#  Label `?feat` at trunk tip (zero-change post on `?feat`).
sniff post "?feat" >/dev/null
sniff get "?feat" >/dev/null
note "switched to ?feat (clean)"
[ -f a.txt ] || fail "a.txt missing after clean cross-branch GET"

# ====================================================================
# Scenario 2 — cross-branch GET refused on dirty wt.
# ====================================================================
echo "=== 2. cross-branch GET refused on dirty wt ==="
WT="$TMP/wt2"
mkdir -p "$WT"; cd "$WT"
echo "a v1" > a.txt
echo "b v1" > b.txt
sniff post -m "trunk base" >/dev/null
sniff post "?feat" >/dev/null            # label feat at this tip
sleep 1
echo "a v1 (uncommitted)" > a.txt        # dirty edit on trunk
note "edited a.txt without committing"

before_tail=$(last_row)
before_a=$(cat a.txt)

if sniff get "?feat" 2>/tmp/dirty.err; then
    cat /tmp/dirty.err
    fail "cross-branch GET should have refused on dirty wt"
fi
grep -q "cross-branch GET refused" /tmp/dirty.err \
    || fail "expected refusal message; got: $(cat /tmp/dirty.err)"
note "cross-branch GET refused as expected"

#  Rollback: .sniff unchanged, a.txt unchanged.
[ "$(last_row)" = "$before_tail" ] \
    || fail ".sniff tail row changed after refused GET"
[ "$(cat a.txt)" = "$before_a" ] \
    || fail "a.txt mutated after refused GET"
note ".sniff and wt left untouched (all-or-nothing rollback)"

# ====================================================================
# Scenario 3 — same-branch GET refused on dirty overlap with target.
# ====================================================================
echo "=== 3. same-branch GET refused on dirty overlap ==="
WT="$TMP/wt3"
mkdir -p "$WT"; cd "$WT"
echo "a v1" > a.txt
sniff post -m "v1" >/dev/null
T1=$(head_hex)
sleep 1
echo "a v2" > a.txt
sniff post -m "v2" >/dev/null
T2=$(head_hex)
[ "$T1" != "$T2" ] || fail "tips collapsed"
note "two trunk tips: T1=$T1 T2=$T2"

#  User-edit a.txt on top of T2 — file is now dirty (mtime ∉
#  stamp-set).  Trying to GET T1 (same branch, different tip) must
#  refuse because a.txt is in T1's tree and would clobber the dirty.
sleep 1
echo "a uncommitted" > a.txt
before_tail=$(last_row)
before_a=$(cat a.txt)

if sniff get "$T1" 2>/tmp/dirty.err; then
    cat /tmp/dirty.err
    fail "same-branch overlap GET should have refused"
fi
grep -q "GET refused" /tmp/dirty.err \
    || fail "expected refusal message; got: $(cat /tmp/dirty.err)"
note "same-branch overlap GET refused as expected"

[ "$(last_row)" = "$before_tail" ] \
    || fail ".sniff tail row changed after refused GET"
[ "$(cat a.txt)" = "$before_a" ] \
    || fail "a.txt mutated after refused GET"
note ".sniff and a.txt unchanged after refusal"

# ====================================================================
# Scenario 4 — same-branch GET allowed when the dirty file is
#              untracked (not in the target tree).
# ====================================================================
echo "=== 4. same-branch GET ignores untracked-only dirt ==="
WT="$TMP/wt4"
mkdir -p "$WT"; cd "$WT"
echo "a v1" > a.txt
sniff post -m "v1" >/dev/null
T1=$(head_hex)
sleep 1
echo "a v2" > a.txt
sniff post -m "v2" >/dev/null
T2=$(head_hex)

#  Drop an untracked, never-stamped file alongside the tracked tree;
#  GET'ing back to T1 must NOT refuse because untracked.txt isn't in
#  T1's target tree.
sleep 1
echo "scratch" > untracked.txt
sniff get "$T1" >/dev/null \
    || fail "same-branch GET refused despite untracked-only dirt"
[ -f untracked.txt ] \
    || fail "untracked.txt removed across same-branch GET"
note "untracked-only dirt did not block the GET"

echo "=== all dirty-refuse scenarios passed ==="
