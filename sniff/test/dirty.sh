#!/bin/sh
#  dirty.sh — sniff GET pre-flight tests.
#
#  Verifies the post-Phase-2 GET semantics:
#    * cross-branch GET refused on any unattributed-mtime wt file
#      (SNIFFDRTY); .be/wtlog and the wt are unchanged on refusal,
#    * cross-branch GET allowed on a clean wt,
#    * same-branch GET on a dirty target-tree overlap is now
#      weave-merged (wt as an implicit edit on baseline, merged
#      against tgt's history); GET succeeds and the file stays,
#    * same-branch GET allowed when the dirty wt file is untracked
#      (not in the target tree).
#
#  Run: BIN=build-debug/bin sh sniff/test/dirty.sh
set -eu

BIN=${BIN:-$(dirname "$(command -v be)")}
export PATH="$BIN:$PATH"
export ASAN_OPTIONS="${ASAN_OPTIONS:-}:detect_leaks=0"

TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-SNIFFdirty}
TMP=$TMP/$TEST_ID/$$
trap 'rm -rf "$TMP"; rmdir "${TMP%/*}" 2>/dev/null || true; rmdir "${TMP%/*/*}" 2>/dev/null || true' EXIT INT TERM
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
                }' .be/wtlog
}

#  Last meaningful (verb + uri) row.  Skips any trailing pad bytes
#  left behind by FILEBook page-align if SNIFFClose's trim fails
#  to run on an early-fail (rw open without subsequent write — see
#  the get pre-flight refuse paths).
last_row() {
    awk -F'\t' 'NF >= 2 && $2 != "" { last=$0 } END { print last }' .be/wtlog
}

# ====================================================================
# Scenario 1 — clean cross-branch GET succeeds.
# ====================================================================
echo "=== 1. clean cross-branch GET succeeds ==="
WT="$TMP/wt1"
mkdir -p "$WT/.be"; cd "$WT"
echo "a v1" > a.txt
echo "b v1" > b.txt
sniff post -m "trunk base" >/dev/null
TRUNK=$(head_hex)
note "trunk base = $TRUNK"

#  Label `?feat` at trunk tip (zero-change post on `?feat`).
sniff put "?feat" >/dev/null
sniff get "?feat" >/dev/null
note "switched to ?feat (clean)"
[ -f a.txt ] || fail "a.txt missing after clean cross-branch GET"

# ====================================================================
# Scenario 2 — cross-branch GET refused on dirty wt.
# ====================================================================
echo "=== 2. cross-branch GET refused on dirty wt ==="
WT="$TMP/wt2"
mkdir -p "$WT/.be"; cd "$WT"
echo "a v1" > a.txt
echo "b v1" > b.txt
sniff post -m "trunk base" >/dev/null
sniff put "?feat" >/dev/null            # label feat at this tip
sleep 0.1
echo "a v1 (uncommitted)" > a.txt        # dirty edit on trunk
note "edited a.txt without committing"

before_tail=$(last_row)
before_a=$(cat a.txt)

if sniff get "?feat" 2>$TMP/dirty.err; then
    cat $TMP/dirty.err
    fail "cross-branch GET should have refused on dirty wt"
fi
grep -q "cross-branch GET refused" $TMP/dirty.err \
    || fail "expected refusal message; got: $(cat $TMP/dirty.err)"
note "cross-branch GET refused as expected"

#  Rollback: .be/wtlog unchanged, a.txt unchanged.
[ "$(last_row)" = "$before_tail" ] \
    || fail ".be/wtlog tail row changed after refused GET"
[ "$(cat a.txt)" = "$before_a" ] \
    || fail "a.txt mutated after refused GET"
note ".be/wtlog and wt left untouched (all-or-nothing rollback)"

# ====================================================================
# Scenario 3 — same-branch GET weave-merges dirty overlap with target.
# ====================================================================
echo "=== 3. same-branch GET weave-merges dirty overlap ==="
WT="$TMP/wt3"
mkdir -p "$WT/.be"; cd "$WT"
echo "a v1" > a.txt
sniff post -m "v1" >/dev/null
T1=$(head_hex)
sleep 0.1
echo "a v2" > a.txt
sniff post -m "v2" >/dev/null
T2=$(head_hex)
[ "$T1" != "$T2" ] || fail "tips collapsed"
note "two trunk tips: T1=$T1 T2=$T2"

#  User-edit a.txt on top of T2 — file is now dirty (mtime ∉
#  stamp-set).  GET T1 routes the dirty path through graf's
#  weave-merge instead of refusing; the merged bytes land in a.txt.
sleep 0.1
echo "a uncommitted" > a.txt

if ! sniff get "$T1" 2>$TMP/dirty.err; then
    cat $TMP/dirty.err
    fail "same-branch overlap GET should have weave-merged, not refused"
fi
grep -q "weave-merged" $TMP/dirty.err \
    || fail "expected 'weave-merged' notice; got: $(cat $TMP/dirty.err)"
[ -f a.txt ] || fail "a.txt vanished across merge GET"
note "same-branch overlap GET weave-merged as expected"

#  Merged bytes are a user edit, not clean baseline — `be`-status
#  must classify a.txt as mod/dirty so the user notices the merge
#  result before the next post.
sniff status >$TMP/dirty.status 2>&1 \
    || fail "sniff status failed after weave-merge GET"
grep -E "[[:space:]](mod|new)[[:space:]]+a\.txt" $TMP/dirty.status \
    >/dev/null \
    || fail "weave-merged a.txt should appear dirty; status: $(cat $TMP/dirty.status)"
note "weave-merged a.txt is reported dirty by sniff status"

# ====================================================================
# Scenario 4 — same-branch GET allowed when the dirty file is
#              untracked (not in the target tree).
# ====================================================================
echo "=== 4. same-branch GET ignores untracked-only dirt ==="
WT="$TMP/wt4"
mkdir -p "$WT/.be"; cd "$WT"
echo "a v1" > a.txt
sniff post -m "v1" >/dev/null
T1=$(head_hex)
sleep 0.1
echo "a v2" > a.txt
sniff post -m "v2" >/dev/null
T2=$(head_hex)

#  Drop an untracked, never-stamped file alongside the tracked tree;
#  GET'ing back to T1 must NOT refuse because untracked.txt isn't in
#  T1's target tree.
sleep 0.1
echo "scratch" > untracked.txt
sniff get "$T1" >/dev/null \
    || fail "same-branch GET refused despite untracked-only dirt"
[ -f untracked.txt ] \
    || fail "untracked.txt removed across same-branch GET"
note "untracked-only dirt did not block the GET"

echo "=== all dirty-refuse scenarios passed ==="
