#!/bin/sh
#  relref.sh — end-to-end check that `?./X`, `?../X`, and `?..` are
#  resolved through the dispatcher to the absolute branch path,
#  using the wt's current branch from `.sniff` baseline.
#
#  Covered today:
#    * `sniff post ?./feat`  labels child branch (creates feat).
#    * `sniff get  ?feat`    switches to feat (absolute).
#    * `sniff get  ?..`      switches back to trunk (parent of feat).
#    * `sniff post ?../sib`  labels sibling branch off trunk.
#
#  Not covered (follow-up): `sniff get ?./X` create-on-miss when X
#  is not yet labelled — today GET refuses on KEEPNONE.
#
#  Run: BIN=build-debug/bin sh sniff/test/relref.sh
set -eu

BIN=${BIN:-$(dirname "$(command -v be)")}
export PATH="$BIN:$PATH"
export ASAN_OPTIONS="${ASAN_OPTIONS:-}:detect_leaks=0"

TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-SNIFFrelref}
TMP=$TMP/$TEST_ID
trap 'rm -rf "$TMP"; rmdir "${TMP%/*}" 2>/dev/null || true' EXIT INT TERM
mkdir -p "$TMP"

fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "  - $*"; }

#  Branch path the wt currently records (the latest get/post/patch
#  row's URI ?query — strip the leading `?`).
cur_branch() {
    awk -F'\t' '$2=="post" || $2=="get" || $2=="patch" { last=$3 }
                END {
                    q = last
                    sub(/#.*/, "", q)        # drop fragment
                    sub(/^\?/, "", q)        # drop leading ?
                    print q
                }' .sniff
}

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

WT="$TMP/wt"
mkdir -p "$WT"; cd "$WT"

# --- step 1: trunk base -----------------------------------------------
echo "=== 1. base commit on trunk ==="
echo "x" > x.txt
sniff post -m "base" >/dev/null
[ "$(cur_branch)" = "" ] || fail "post wrote a non-trunk branch"
note "trunk baseline established"

# --- step 2: ?./feat from trunk creates child label ------------------
echo "=== 2. ?./feat from trunk ==="
sniff post "?./feat" >/dev/null
TIP_FEAT=$(ref_tip "?feat")
[ -n "$TIP_FEAT" ] \
    || fail "?./feat from trunk did not create root-level feat"
note "feat labelled at $TIP_FEAT (./feat from trunk → feat)"

# --- step 3: switch to feat, then back via ?.. ------------------------
echo "=== 3. ?.. switches feat → trunk ==="
sniff get "?feat" >/dev/null
[ "$(cur_branch)" = "feat" ] || fail "wt not on feat after get ?feat"
sniff get "?.." >/dev/null
[ "$(cur_branch)" = "" ] \
    || fail "?.. from feat should resolve to trunk (got '$(cur_branch)')"
note "?.. resolves feat → trunk"

# --- step 4: ?../sib from feat creates sibling label off trunk -------
echo "=== 4. ?../sib from feat ==="
sniff get "?feat" >/dev/null
[ "$(cur_branch)" = "feat" ] || fail "couldn't return to feat"
sniff post "?../sib" >/dev/null
TIP_SIB=$(ref_tip "?sib")
[ -n "$TIP_SIB" ] \
    || fail "?../sib from feat did not create root-level sib"
note "sib labelled at $TIP_SIB (../sib from feat → sib)"

# --- step 5: get ?./X create-on-miss forks a new child branch --------
echo "=== 5. get ?./X create-on-miss ==="
sniff get "?feat" >/dev/null
[ "$(cur_branch)" = "feat" ] || fail "couldn't return to feat"
#  feat/sub doesn't exist yet; `sniff get ?./sub` should fork it at
#  feat's current tip and switch the wt onto the new label.
sniff get "?./sub" >/dev/null
[ "$(cur_branch)" = "feat/sub" ] \
    || fail "wt not on feat/sub after get ?./sub (got '$(cur_branch)')"
TIP_SUB=$(ref_tip "?feat/sub")
[ -n "$TIP_SUB" ] || fail "feat/sub not registered in REFS"
note "feat/sub forked at $TIP_SUB"

# --- step 6: bare ?A (absolute) on miss must NOT create --------------
echo "=== 6. get ?ghost (absolute miss) errors ==="
if sniff get "?ghost" 2>/dev/null; then
    fail "absolute ?ghost should NOT auto-create on miss"
fi
note "absolute lookup on miss errors as expected"

echo "=== all relref scenarios passed ==="
