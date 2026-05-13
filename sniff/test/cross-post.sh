#!/bin/sh
#  cross-post.sh — `sniff post -m "msg" ?<target>` lands a commit on
#  the target branch without modifying the wt's other branches.
#
#  Verifies:
#    * cross-branch POST (`be post -m msg ?feat/` from trunk wt)
#      creates a commit on feat with first-parent = trunk's tip,
#      switches the wt's recorded branch to feat,
#      leaves trunk's REFS tip unchanged.
#      (Trailing slash is the "new branch" marker — see VERBS.md
#      §"Ref kinds" / dog/DOG.h §DOGRefIsBranch.)
#    * non-ff cross-branch POST refused (target on unrelated lineage).
#
#  Run: BIN=build-debug/bin sh sniff/test/cross-post.sh
set -eu

BIN=${BIN:-$(dirname "$(command -v be)")}
export PATH="$BIN:$PATH"
export ASAN_OPTIONS="${ASAN_OPTIONS:-}:detect_leaks=0"

TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-SNIFFcrosspost}
TMP=$TMP/$TEST_ID/$$
trap 'rm -rf "$TMP"; rmdir "${TMP%/*}" 2>/dev/null || true; rmdir "${TMP%/*/*}" 2>/dev/null || true' EXIT INT TERM
mkdir -p "$TMP"

fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "  - $*"; }

cur_branch() {
    awk -F'\t' '$2=="post" || $2=="get" || $2=="patch" { last=$3 }
                END {
                    q = last
                    sub(/#.*/, "", q); sub(/^\?/, "", q)
                    print q
                }' .be/wtlog
}

head_hex() {
    awk -F'\t' '$2=="post" || $2=="get" || $2=="patch" { last=$3 }
                END {
                    h = last; sub(/^[^#]*#/, "", h)
                    if (length(h) == 40 && h ~ /^[0-9a-f]+$/) print h
                }' .be/wtlog
}

ref_tip() {
    keeper refs 2>/dev/null | awk -v k="$1" '
        { sub(/^[[:space:]]+/, "")
          tab = index($0, "\t")
          if (tab == 0) next
          kf = substr($0, 1, tab - 1)
          if (kf != k) next
          n = split($0, toks, /[[:space:]]+/)
          v = toks[n]; sub(/^\?/, "", v); print v; exit }'
}

parent_of() {
    keeper get ".#$1" 2>/dev/null | awk '/^parent / { print $2; exit }'
}

# ====================================================================
# Scenario 1 — cross-branch POST: commit on ?feat from trunk wt.
# ====================================================================
echo "=== 1. cross-branch post commits on target ==="
WT="$TMP/wt1"
mkdir -p "$WT/.be"; cd "$WT"
echo "x" > x.txt
sniff post -m "trunk base" >/dev/null
TRUNK_BASE=$(head_hex)
note "trunk base = $TRUNK_BASE"

#  Cross-branch POST: wt is on trunk; commit goes on feat.  feat
#  doesn't exist yet, so this is a create-on-miss path (no ff check).
#  Idiomatic syntax: URI first, message words follow and fold into
#  the URI's #fragment.
sleep 0.1
echo "x feat" > x.txt
sniff post "?feat/" 'feat work' >/dev/null

#  feat now has the new commit; trunk should NOT have advanced.
TRUNK_REF=$(ref_tip "?")
FEAT_REF=$(ref_tip "?feat")
NEW_TIP=$(head_hex)

[ "$TRUNK_REF" = "$TRUNK_BASE" ] \
    || fail "trunk advanced unexpectedly: $TRUNK_REF != $TRUNK_BASE"
note "trunk REFS tip unchanged at $TRUNK_BASE"

[ -n "$FEAT_REF" ] || fail "feat REFS missing"
[ "$FEAT_REF" = "$NEW_TIP" ] \
    || fail "feat REFS != new commit ($FEAT_REF != $NEW_TIP)"
note "feat REFS at $NEW_TIP"

#  First-parent of new commit must be the trunk base.
PAR=$(parent_of "$NEW_TIP")
[ "$PAR" = "$TRUNK_BASE" ] \
    || fail "new commit's first parent is $PAR, want $TRUNK_BASE"
note "new commit's first parent = trunk base ($TRUNK_BASE)"

#  wt's recorded branch should now be feat (POST switches to target).
[ "$(cur_branch)" = "feat" ] \
    || fail "wt branch '$(cur_branch)' should be 'feat'"
note "wt switched to feat"

# ====================================================================
# Scenario 2 — cross-branch POST onto an unrelated tip refuses.
# ====================================================================
echo "=== 2. cross-branch non-ff refused ==="
WT="$TMP/wt2"
mkdir -p "$WT/.be"; cd "$WT"
echo "x" > x.txt
sniff post -m "trunk base" >/dev/null
sniff put "?feat" >/dev/null              # label feat at trunk's tip

#  Poison feat's REFS with an unrelated sha so the ff check fires.
FAKE="deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
TS=$(awk 'END { print $1 }' .be/refs)
printf '%sz\tpost\t?feat#%s\n' "$TS" "$FAKE" >> .be/refs

sleep 0.1
echo "x v2" > x.txt
if sniff post "?feat/" 'should fail' 2>$TMP/cross.err; then
    cat $TMP/cross.err
    fail "non-ff cross-branch POST should have been refused"
fi
grep -q "rebase aborted" $TMP/cross.err \
    || fail "expected rebase aborted message; got: $(cat $TMP/cross.err)"
note "non-ff cross-branch POST refused"

echo "=== all cross-post scenarios passed ==="
