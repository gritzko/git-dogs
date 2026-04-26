#!/bin/sh
#  squash.sh — squash a side branch's multiple commits into one
#  linear commit on trunk.
#
#  Workflow exercised:
#    1. Fresh repo; initial commit on trunk (?) touching a+b.
#    2. Label that tip as `?feat` (a side-branch pointer).
#    3. Switch to feat via `sniff get ?feat`; two "turbulent"
#       commits (modify a, add c).
#    4. Switch back to trunk; make a concurrent commit (modify b).
#    5. From trunk: `sniff patch ?feat` does a 3-way merge
#       (ours=trunk tip, theirs=feat tip, lca=initial).
#    6. `sniff post -m "squash feat"` lands the merged wt as ONE new
#       commit on trunk whose parent is trunk's concurrent tip.
#
#  Verifies:
#    * The squash commit includes every expected file (a modified by
#      feat, b modified by trunk, c added by feat).
#    * The squash commit's parent is master's concurrent tip, not the
#      base — i.e. trunk history stays linear and we haven't lost the
#      concurrent work.
#    * Master's REFS advances to the new squash commit.
#
#  Run: BIN=build-debug/bin sh sniff/test/squash.sh
set -eu

BIN=${BIN:-$(dirname "$0")/../../build-debug/bin}
export PATH="$BIN:$PATH"
export ASAN_OPTIONS="${ASAN_OPTIONS:-}:detect_leaks=0"

TMP=${TMP:-$HOME/tmp}
TEST_ID=${TEST_ID:-SNIFFsquash}
TMP=$TMP/$$/$TEST_ID
trap 'rm -rf "$TMP"' EXIT INT TERM
mkdir -p "$TMP"

fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "  - $*"; }

WT="$TMP/wt"
mkdir -p "$WT"
cd "$WT"

#  Current commit recorded in .sniff — `?<branch>#<curhash>` shape:
#  fragment of the most recent get/post/patch row holds the sha.
head_hex() {
    awk -F'\t' '$2=="post" || $2=="get" || $2=="patch" { last=$3 }
                END {
                    h = last
                    sub(/^[^#]*#/, "", h)
                    if (length(h) == 40 && h ~ /^[0-9a-f]+$/) print h
                }' .sniff
}

#  Parent sha of a given commit, via `keeper get .#<hex>`.
parent_of() {
    hex=$1
    keeper get ".#$hex" 2>/dev/null \
        | awk '/^parent / { print $2; exit }'
}

#  Every parent sha of a commit, in order (first parent first).
parents_of() {
    hex=$1
    keeper get ".#$hex" 2>/dev/null \
        | awk '/^parent / { print $2 }'
}

#  Tip of a local ref via keeper refs.  Output lines look like
#  `  <key>\t→ ?<40-hex>`; grep the line, take the last token, strip
#  the leading `?`.
ref_tip() {
    key=$1
    keeper refs 2>/dev/null | awk -v k="$key" '
        {
            sub(/^[[:space:]]+/, "")
            tab = index($0, "\t")
            if (tab == 0) next
            kf = substr($0, 1, tab - 1)
            if (kf != k) next
            n = split($0, toks, /[[:space:]]+/)
            v = toks[n]
            sub(/^\?/, "", v)
            print v
            exit
        }'
}

# --- step 1: base commit on trunk ------------------------------------
echo "=== 1. base commit on trunk ==="
echo "a line 1" > a.txt
echo "b line 1" > b.txt
sniff post -m "base" >/dev/null
BASE=$(head_hex)
[ -n "$BASE" ] || fail "no base sha"
note "trunk BASE=$BASE"

# --- step 2: label same tip as ?feat (side branch) -------------------
echo "=== 2. label ?feat at BASE ==="
sniff post "?feat" >/dev/null
FEAT_REF=$(ref_tip "?feat")
[ "$FEAT_REF" = "$BASE" ] || fail "feat ref not at BASE (got=$FEAT_REF)"
note "?feat -> $FEAT_REF"

# --- step 3: switch to feat, two turbulent commits --------------------
echo "=== 3. feat branch: modify a, then add c ==="
sniff get "?feat" >/dev/null
sleep 1
echo "a line 1 (feat mod)" > a.txt
sniff post -m "feat: rewrite a" >/dev/null
FEAT1=$(head_hex)
note "feat tip after rewrite=$FEAT1"

sleep 1
echo "c line 1" > c.txt
#  c.txt is untracked — implicit `sniff post -m` skips strangers
#  once a baseline exists.  Stage it explicitly.
sniff put c.txt >/dev/null
sniff post -m "feat: add c" >/dev/null
FEAT2=$(head_hex)
[ "$FEAT2" != "$FEAT1" ] || fail "feat tip didn't advance"
note "feat tip after add c=$FEAT2"

# --- step 4: switch back to trunk, concurrent commit -----------------
echo "=== 4. trunk: concurrent modify b ==="
sniff get "?" >/dev/null
#  After this get the wt reflects trunk tip (a=base, b=base, c=gone).
[ -f a.txt ] || fail "a.txt missing after switch to trunk"
[ ! -f c.txt ] || fail "c.txt should be pruned on switch to trunk"
grep -qF 'a line 1' a.txt || fail "a.txt not base content on trunk"

sleep 1
echo "b line 1 (trunk mod)" > b.txt
sniff post -m "trunk: rewrite b" >/dev/null
TRUNK1=$(head_hex)
[ "$TRUNK1" != "$BASE" ] || fail "trunk tip didn't advance"
note "trunk tip after rewrite b=$TRUNK1"

# --- step 5: squash feat into trunk ----------------------------------
echo "=== 5. patch feat into trunk wt ==="
sniff patch "?feat" 2>&1 | sed 's/^/  | /'
[ -f c.txt ] || fail "patch did not bring in c.txt from feat"
grep -qF '(feat mod)'  a.txt || fail "patch did not merge feat's a"
grep -qF '(trunk mod)' b.txt || fail "patch clobbered trunk's b"
grep -qF 'c line 1'    c.txt || fail "patch's c.txt has wrong content"
! grep -qF '<<<<' a.txt b.txt c.txt \
    || fail "unexpected conflict markers on disjoint edits"
note "merged wt: a(feat), b(trunk), c(feat)"

echo "=== 6. squash commit on trunk ==="
sniff post -m "squash feat into trunk" >/dev/null
SQUASH=$(head_hex)
[ "$SQUASH" != "$TRUNK1" ] || fail "no new commit after squash post"
note "squash commit=$SQUASH"

TRUNK_REF=$(ref_tip "?")
[ "$TRUNK_REF" = "$SQUASH" ] \
    || fail "trunk not advanced to squash ($TRUNK_REF vs $SQUASH)"
note "trunk -> $SQUASH"

#  History check: squash's first parent must be trunk's concurrent
#  tip, and the second parent must be the feat tip the PATCH brought
#  in (.sniff `patch` row → POST drained).
SQUASH_PARENTS=$(parents_of "$SQUASH")
SQUASH_NPAR=$(echo "$SQUASH_PARENTS" | wc -l)
[ "$SQUASH_NPAR" = "2" ] \
    || fail "squash has $SQUASH_NPAR parents, expected 2 (PATCH+POST)"
SQUASH_P1=$(echo "$SQUASH_PARENTS" | sed -n '1p')
SQUASH_P2=$(echo "$SQUASH_PARENTS" | sed -n '2p')
[ "$SQUASH_P1" = "$TRUNK1" ] \
    || fail "squash 1st parent is $SQUASH_P1, expected TRUNK1=$TRUNK1"
[ "$SQUASH_P2" = "$FEAT2" ] \
    || fail "squash 2nd parent is $SQUASH_P2, expected FEAT2=$FEAT2"
note "squash parents = TRUNK1, FEAT2 (multi-parent merge commit)"

#  A fresh checkout of the squash tip should materialise the merged
#  tree (a=feat, b=trunk, c=feat).
echo "=== 7. fresh checkout verifies squash tree ==="
WT2="$TMP/wt2"
mkdir -p "$WT2"
cp -r "$WT/.dogs" "$WT2/"
cd "$WT2"
sniff get "$SQUASH" >/dev/null
grep -qF '(feat mod)'  a.txt || fail "checkout: a.txt not feat-modified"
grep -qF '(trunk mod)' b.txt || fail "checkout: b.txt not trunk-modified"
grep -qF 'c line 1'    c.txt || fail "checkout: c.txt missing"
note "fresh wt reflects squashed tree"

echo
echo "=== sniff squash: OK ==="
