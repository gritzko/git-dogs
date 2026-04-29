#!/bin/sh
#  worktree.sh — worktree clone + commit-from-worktree flow.
#
#    * Primary repo holds `<repo>/.dogs/` (store: keeper packs + indexes,
#      graf, spot) and `<repo>/.sniff` (the primary's ULOG).
#    * `be get <primary>` in a fresh dir creates the secondary wt as:
#        <wt>/.dogs  — symlink to <primary>/.dogs/
#        <wt>/.sniff — local ULOG file for this wt's state
#    * Both wts share the entire object store; each keeps its own
#      HEAD in its local `.sniff` file.
#
set -eu

BIN=${BIN:-$(dirname "$(command -v be)")}
BIN=$(cd "$BIN" && pwd)
BE="$BIN/be"
KEEPER="$BIN/keeper"

TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-BEworktree}
TMP=$TMP/$TEST_ID
mkdir -p "$TMP"; echo "Running in $PWD"
trap 'rm -rf "$TMP"; rmdir "${TMP%/*}" 2>/dev/null || true' EXIT INT TERM

fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "  - $*"; }

# Tail SHA of a worktree's .sniff ULOG.  Rows are
# `<ts>\t<verb>\t<uri>`; the latest `post` row's URI carries the
# commit sha as the `#fragment` (canonical `?<branch>#<curhash>`).
head_hex_of() {
    awk -F'\t' '$2 == "post" { last = $3 } END {
        h = last
        sub(/^[^#]*#/, "", h)
        if (length(h) == 40 && h ~ /^[0-9a-f]+$/) print h
    }' "$1/.sniff"
}

# --- 1. primary ------------------------------------------------------
echo "=== 1. primary: seed commit ==="
PRIM="$TMP/prim"; mkdir -p "$PRIM"; cd "$PRIM"
echo hello > README
"$BE" post --seq -m "seed" >/dev/null
SEED_HEAD=$(head_hex_of "$PRIM")
[ -n "$SEED_HEAD" ] || fail "primary HEAD empty after post"
note "primary HEAD=$SEED_HEAD"
[ -d "$PRIM/.dogs" ] || fail "primary missing .dogs/"
[ -f "$PRIM/.sniff" ] || fail "primary missing .sniff"
ls "$PRIM/.dogs"/*.keeper >/dev/null 2>&1 \
    || fail "primary missing .dogs/*.keeper"

# --- 2. worktree from primary ---------------------------------------
echo "=== 2. be get <primary> creates worktree ==="
WT="$TMP/wt"; mkdir -p "$WT"; cd "$WT"
"$BE" get --seq "$PRIM" >/dev/null 2>/dev/null || true
[ -L "$WT/.dogs" ] || fail ".dogs should be a symlink"
tgt=$(readlink "$WT/.dogs")
[ "$tgt" = "$PRIM/.dogs" ] \
    || fail ".dogs -> $tgt, expected $PRIM/.dogs"
[ -f "$WT/.sniff" ] && [ ! -L "$WT/.sniff" ] \
    || fail ".sniff should be a local file"
note "wt: .dogs -> primary, .sniff local"

# --- 3. shared store reachable through the symlink ------------------
echo "=== 3. worktree sees primary's objects ==="
"$KEEPER" verify ".#$SEED_HEAD" 2>&1 | grep -q '0 failed' \
    || fail "seed commit not reachable through symlinked .dogs"
note "seed commit reachable via symlink"

# --- 4. put / delete / post from the worktree -----------------------
echo "=== 4. put/del/post from worktree ==="
"$BE" get --seq "?$SEED_HEAD" >/dev/null 2>&1 \
    || fail "be get ?HEAD failed in worktree"
[ -f README ] || fail "README not checked out in worktree"
note "worktree checkout OK"

echo goodbye > CHANGES
"$BE" put --seq CHANGES >/dev/null
"$BE" delete --seq README >/dev/null
"$BE" post --seq -m "worktree edit" >/dev/null

WT_HEAD=$(head_hex_of "$WT")
[ -n "$WT_HEAD" ] || fail "worktree HEAD empty after post"
[ "$WT_HEAD" != "$SEED_HEAD" ] || fail "worktree HEAD did not advance"
note "worktree HEAD=$WT_HEAD"

# The new commit lives in the shared store.
cd "$PRIM" && "$KEEPER" verify ".#$WT_HEAD" 2>&1 | grep -q '0 failed' \
    || fail "new commit missing from shared store"
cd "$WT"
note "new commit in shared store"

# Primary's local at.log (.sniff/at.log) is untouched — per-wt state
# stays isolated even though the object store is shared.
PRIM_HEAD=$(head_hex_of "$PRIM")
[ "$PRIM_HEAD" = "$SEED_HEAD" ] \
    || fail "primary HEAD moved ($PRIM_HEAD, was $SEED_HEAD)"
note "primary HEAD still at seed (per-wt sniff state respected)"

echo "=== worktree OK ==="
