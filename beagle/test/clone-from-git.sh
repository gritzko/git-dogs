#!/bin/sh
#  clone-from-git.sh — keeper and git each clone a toy git repo.
#
#  Builds a 3-commit, 2-tag toy git repo (rev1@v1, rev2@v2, rev3@master),
#  clones it with `git clone ssh://localhost/...` and `be get
#  //localhost/...` (ssh:// = git protocol; bare //host = git protocol;
#  per-protocol scheme convention is ssh:// for git, be:// for keeper),
#  then rsync-compares the worktrees.
#
#  Run: BIN=build-debug/bin sh beagle/test/clone-from-git.sh

set -eu

BIN=${BIN:-$(dirname "$(command -v be)")}
BIN=$(cd "$BIN" && pwd)
TESTDIR=$(cd "$(dirname "$0")" && pwd)
export PATH="$BIN:$PATH"
export DOG_REMOTE_PATH="$BIN"

TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-clone-from-git}
TMP=$TMP/$TEST_ID
TMP_REL=${TMP#$HOME/}
mkdir -p "$TMP"; echo "Running in $PWD"
trap 'rm -rf "$TMP"; rmdir "${TMP%/*}" 2>/dev/null || true' EXIT

# --- 1. toy git source: 3 revs, v1, v2 tags, master tip ---
SRC=$TMP/src
git init --quiet --bare "$SRC"

W=$(mktemp -d)
git -c init.defaultBranch=master init --quiet "$W"
git -C "$W" config user.email t@t
git -C "$W" config user.name t
git -C "$W" remote add origin "$SRC"

echo rev1 >"$W/f.txt"
git -C "$W" add f.txt
git -C "$W" commit --quiet -m "rev 1"
git -C "$W" tag v1
echo rev2 >"$W/f.txt"
git -C "$W" commit --quiet -am "rev 2"
git -C "$W" tag v2
echo rev3 >"$W/f.txt"
git -C "$W" commit --quiet -am "rev 3"
git -C "$W" push --quiet origin master --tags
rm -rf "$W"

SRC_REL=${SRC#$HOME/}

# --- 2. git clones from git (control) ---
git clone --quiet "ssh://localhost/$SRC" "$TMP/git-clone"

# --- 3. keeper clones from git ---
mkdir -p "$TMP/be-clone"
cd "$TMP/be-clone"
git init --quiet .
mkdir -p .dogs/keeper
be get "//localhost/$SRC_REL"

# --- 4. compare worktrees ---
RDIFF=$(rsync -rlcni --delete \
    --exclude='/.git/' --exclude='/.dogs/' --exclude='/.sniff' \
    "$TMP/git-clone/" "$TMP/be-clone/" 2>&1)
if [ -n "$RDIFF" ]; then
    echo "FAIL: clone-from-git: worktrees differ"
    echo "$RDIFF" | head -10
    exit 1
fi

# --- 5. canonical refs check ---
VERIFY="$TESTDIR/verify-canonical-refs.sh"
sh "$VERIFY" "$TMP/be-clone" || { echo "FAIL: be-clone refs not canonical"; exit 1; }

# --- 6. idempotency: a repeat `be get` must leave .dogs bit-identical.
#         Per keeper/LOG.md: the log is append-of-packs; a no-op fetch
#         produces zero file changes (no new .keeper, no new .idx, no
#         append to existing ones).
snapshot_dogs() { (cd "$1/.dogs" && find . -type f -not -name '.lock' \
    | sort | xargs sha256sum); }
SNAP1=$(snapshot_dogs "$TMP/be-clone")
be get "//localhost/$SRC_REL"
SNAP2=$(snapshot_dogs "$TMP/be-clone")
if [ "$SNAP1" != "$SNAP2" ]; then
    echo "FAIL: repeat be get changed files in .dogs"
    diff <(printf '%s\n' "$SNAP1") <(printf '%s\n' "$SNAP2") | head -20
    exit 1
fi

echo "PASS: clone-from-git"
