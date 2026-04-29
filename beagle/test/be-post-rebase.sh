#!/bin/sh
#  be-post-rebase.sh — same-branch rebase: two worktrees share one
#  keeper store; WT1 advances trunk to T2 out-of-band; WT2 (still
#  rooted at T1) edits a *different* file and `be post`s.  Stage 2
#  phase-2 promote rebases WT2's new commit onto T2 and CAS-advances
#  REFS.  No conflict since the two edits touch disjoint files.
#
#  Verifies:
#    * rebase POST succeeds (exit 0),
#    * REFS trunk tip advances past T2 (rebased commit lands on top),
#    * the rebased commit's first parent is T2 (not T1).

set -eu

BIN=${BIN:-$(dirname "$(command -v be)")}
BIN=$(cd "$BIN" && pwd)
BE="$BIN/be"
KEEPER="$BIN/keeper"
export PATH="$BIN:$PATH"
export ASAN_OPTIONS="${ASAN_OPTIONS:-}:detect_leaks=0"

TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-be-post-rebase}
TMP=$TMP/$TEST_ID
mkdir -p "$TMP"
trap 'rm -rf "$TMP"; rmdir "${TMP%/*}" 2>/dev/null || true' EXIT INT TERM

fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "  - $*"; }

head_hex() {
    awk -F'\t' '$2=="post"||$2=="get"||$2=="patch" { last=$3 }
                END {
                    h = last; sub(/^[^#]*#/, "", h)
                    if (length(h) == 40 && h ~ /^[0-9a-f]+$/) print h
                }' .sniff
}

ref_tip() {
    "$KEEPER" refs 2>/dev/null | awk -v k="$1" '
        { sub(/^[[:space:]]+/, "")
          tab = index($0, "\t"); if (tab == 0) next
          kf = substr($0, 1, tab - 1); if (kf != k) next
          n = split($0, toks, /[[:space:]]+/)
          v = toks[n]; sub(/^\?/, "", v); print v; exit
        }'
}

parent_of() {
    "$KEEPER" get ".#$1" 2>/dev/null | awk '/^parent / { print $2; exit }'
}

# ------------------------------------------------------------------
# 1. seed WT1 with one commit on trunk
# ------------------------------------------------------------------
echo "=== 1. WT1 seed: T1 ==="
WT1="$TMP/wt1"
mkdir -p "$WT1"; cd "$WT1"
echo "x v1" > x.txt
"$BE" post v1 >/dev/null
T1=$(head_hex)
[ -n "$T1" ] || fail "WT1: no T1 after first post"
note "T1=$T1"

# ------------------------------------------------------------------
# 2. WT2 attaches to the same .dogs (clone via shared keeper store).
#    Cheap simulation: copy the wt + its .dogs into WT2 BEFORE WT1
#    advances; both wts then race on the same .dogs in cwd.
#    Real use case is two checkouts of one repo; here we use a hard
#    symlink to keep both wts pointing at the same keeper.
# ------------------------------------------------------------------
echo "=== 2. WT2 forks off the same store at T1 ==="
WT2="$TMP/wt2"
mkdir -p "$WT2"; cd "$WT2"
ln -s "$WT1/.dogs" .dogs
cp "$WT1/x.txt" x.txt
cp "$WT1/.sniff" .sniff
sleep 0.1
T1_wt2=$(head_hex)
[ "$T1_wt2" = "$T1" ] || fail "WT2 not at T1 (got $T1_wt2)"

# ------------------------------------------------------------------
# 3. WT1 advances trunk: edit + post → T2
# ------------------------------------------------------------------
echo "=== 3. WT1 advances trunk to T2 ==="
cd "$WT1"
sleep 0.1
echo "y v1" > y.txt
"$BE" put y.txt >/dev/null \
    || fail "WT1: be put y.txt failed"
"$BE" post v2 >/dev/null
T2=$(head_hex)
[ -n "$T2" ] && [ "$T2" != "$T1" ] || fail "T2 didn't advance"
note "T2=$T2"

# ------------------------------------------------------------------
# 4. WT2 edits a different file and posts.  WT2 still thinks parent
#    is T1, but REFS is now at T2.  Same-branch divergence ⇒ rebase.
# ------------------------------------------------------------------
echo "=== 4. WT2 posts on top of stale T1 → rebase onto T2 ==="
cd "$WT2"
sleep 0.1
echo "z v1" > z.txt
"$BE" put z.txt >/dev/null \
    || fail "WT2: be put z.txt failed"
"$BE" post wt2-z 2>"$TMP/post.err" >/dev/null \
    || { cat "$TMP/post.err"; fail "WT2: be post should have rebased"; }
T3=$(head_hex)
[ -n "$T3" ] || fail "WT2: no tip after rebase post"
[ "$T3" != "$T1" ] && [ "$T3" != "$T2" ] \
    || fail "WT2: rebased tip $T3 must differ from T1=$T1 and T2=$T2"
note "WT2 rebased onto T2; new tip T3=$T3"

# ------------------------------------------------------------------
# 5. verify REFS advanced to T3 and T3's first parent is T2
# ------------------------------------------------------------------
echo "=== 5. verify ==="
TRUNK_REF=$(ref_tip "?")
[ "$TRUNK_REF" = "$T3" ] \
    || fail "trunk REFS at $TRUNK_REF; want T3=$T3"
PAR=$(parent_of "$T3")
[ "$PAR" = "$T2" ] \
    || fail "T3's parent is $PAR; want T2=$T2 (rebased correctly)"
note "REFS at T3; T3.parent = T2 (rebase landed on top of T2)"

echo "=== be-post-rebase: OK ==="
