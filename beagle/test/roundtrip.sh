#!/bin/sh
#  roundtrip.sh — full git <-> be round-trip through ssh localhost.
#
#    1. Seed a bare git origin + a working tree with one commit.
#    2. `be get ssh://localhost:<origin>?master` — clone via git-upload-pack.
#    3. `be get <clone>` in a fresh dir — make a worktree off the clone.
#    4. Edit in both the clone and the worktree.
#    5. `be post msg` in the worktree (local commit).
#    6. `be post ssh://localhost:<origin>?master` (push the commit).
#    7. Fetch origin into a fresh git clone and diff against our worktree.
#
#  Requires passwordless ssh to localhost (same as POSTtest did).
set -eu

BIN=${BIN:-$(dirname "$0")/../../build-debug/bin}
BIN=$(cd "$BIN" && pwd)
BE="$BIN/be"
KEEPER="$BIN/keeper"

#  Keeper treats URI paths in `//host/path` as remote-HOME-relative
#  (see keeper/KEEP.exe.c) so the working tmp dir must live under
#  $HOME, not /tmp.  ssh ${USER}@localhost git-upload-pack 'be-…'
#  only finds it if it's a sibling of the remote login's $HOME.
TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-BEroundtrip}
TMP=$TMP/$TEST_ID
REL=${TMP#$HOME/}                       # $TMP relative to $HOME
mkdir -p "$TMP"; echo "Running in $PWD"
trap 'rm -rf "$TMP"; rmdir "${TMP%/*}" 2>/dev/null || true' EXIT INT TERM

fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "  - $*"; }

ORIGIN="$TMP/origin.git"
REL_ORIGIN="$REL/origin.git"            # HOME-relative form for ssh URIs
SEED="$TMP/seed"
CLONE="$TMP/clone"
WT="$TMP/wt"
VERIFY="$TMP/verify"

# --- 1. seed origin with a single commit ---
echo "=== 1. seed origin ==="
git init --bare "$ORIGIN" >/dev/null 2>&1
git init "$SEED" >/dev/null 2>&1
git -C "$SEED" config user.email t@t
git -C "$SEED" config user.name  Test
git -C "$SEED" checkout -b master >/dev/null 2>&1 || true
echo alpha > "$SEED/a.txt"
echo bravo > "$SEED/b.txt"
git -C "$SEED" add .
git -C "$SEED" commit -m seed >/dev/null
git -C "$SEED" push "$ORIGIN" master:master 2>/dev/null
SEED_SHA=$(git --git-dir="$ORIGIN" rev-parse master)
note "seed=$SEED_SHA"

# --- 2. be get via ssh ---
echo "=== 2. be get ssh://localhost:<origin>?master ==="
mkdir -p "$CLONE"; cd "$CLONE"
"$BE" get --seq "ssh://localhost/$REL_ORIGIN?master" >/dev/null 2>&1 \
    || fail "be get (clone) failed"
[ -f a.txt ] && [ -f b.txt ] || fail "clone missing seed files"
note "clone has a.txt, b.txt"

# --- 3. be get <clone> → worktree ---
echo "=== 3. be get <clone> (worktree) ==="
mkdir -p "$WT"; cd "$WT"
"$BE" get --seq "$CLONE" >/dev/null 2>&1 || true
[ -L "$WT/.dogs" ] || fail "worktree .dogs not a symlink"
[ -f "$WT/.sniff" ] && [ ! -L "$WT/.sniff" ] \
    || fail "worktree .sniff should be a real file"
[ -f a.txt ] && [ -f b.txt ] || fail "worktree missing checked-out files"
note "worktree has .dogs symlink + local .sniff + checked-out files"

# --- 4. edits in clone and worktree ---
echo "=== 4. edits ==="
usleep 10000                                 # ensure mtime differs from checkout
echo alpha-CLONE > "$CLONE/a.txt"
echo charlie > "$WT/c.txt"
echo bravo-WT > "$WT/b.txt"
rm -f "$WT/a.txt"
note "clone edited a.txt; worktree adds c.txt, modifies b.txt, removes a.txt"

# --- 5. be post in the worktree (msg in fragment) ---
echo "=== 5. be post (local commit) ==="
cd "$WT"
"$BE" post --seq worktree commit >/dev/null 2>&1 \
    || fail "be post failed"
# Read the committed SHA from the tail of .sniff.  Rows are
# `<ts>\t<verb>\t<uri>`; the canonical format is `?<branch>#<sha>` —
# 40-hex commit lives in the URI fragment.
WT_SHA=$(awk -F'\t' '$2 == "post" { last = $3 } END {
    h = last; sub(/^[^#]*#/, "", h)
    if (length(h) == 40 && h ~ /^[0-9a-f]+$/) print h
}' "$WT/.sniff")
[ ${#WT_SHA} -eq 40 ] || fail "no 40-hex worktree commit recorded"
[ "$WT_SHA" != "$SEED_SHA" ] || fail "worktree commit didn't advance"
note "worktree commit=$WT_SHA"

# --- 6. be post ssh://... → push ---
echo "=== 6. be post ssh://localhost:<origin>?master ==="
"$BE" post --seq "ssh://localhost/$REL_ORIGIN?master" 2>&1 \
    | grep -q "keeper: pushed" || fail "keeper push didn't happen"
note "push reported"

# --- 7. verify origin matches worktree ---
echo "=== 7. verify ==="
ORIGIN_SHA=$(git --git-dir="$ORIGIN" rev-parse master)
[ "$ORIGIN_SHA" = "$WT_SHA" ] \
    || fail "origin master=$ORIGIN_SHA != worktree=$WT_SHA"
note "origin master == worktree commit"

# Fresh git checkout of origin, diff against our worktree.
git clone -q "$ORIGIN" "$VERIFY"
# Compare just the tracked files, not .git vs .dogs.
( cd "$VERIFY" && git ls-files ) | sort > "$TMP/git.list"
( cd "$WT" && find . -type f \
    -not -path './.dogs/*' -not -name '.sniff' -not -name '.be' \
    | sed 's|^\./||' ) | sort > "$TMP/wt.list"
diff -u "$TMP/git.list" "$TMP/wt.list" || fail "file sets differ"
while IFS= read -r f; do
    diff "$VERIFY/$f" "$WT/$f" \
        || fail "content differs: $f"
done < "$TMP/git.list"
note "all tracked files match"

echo "=== roundtrip OK ==="
