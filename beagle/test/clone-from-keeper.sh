#!/bin/sh
#  clone-from-keeper.sh — keeper and git each clone a toy keeper repo.
#
#  Builds a 3-commit, 2-tag toy git repo, seeds it into a keeper-managed
#  mirror via `be get`, then clones that mirror two ways:
#    - `be get be://localhost/...`       (keeper protocol, our client)
#    - `git clone --upload-pack='keeper upload-pack' ssh://localhost/...`
#      (git protocol, but server-side binary is keeper)
#  rsync-compares the resulting worktrees.
#
#  Run: BIN=build-debug/bin sh beagle/test/clone-from-keeper.sh

set -eu

BIN=${DOG_BIN_DIR:-$(dirname "$(command -v be)")}
BIN=$(cd "$BIN" && pwd)
TESTDIR=$(cd "$(dirname "$0")" && pwd)
export PATH="$BIN:$PATH"
export DOG_REMOTE_PATH="$BIN"

TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-clone-from-keeper}
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

# --- 2. seed keeper mirror by cloning the toy git into it ---
KSRV=$TMP/keeper-srv
mkdir -p "$KSRV"
cd "$KSRV"
git init --quiet .
mkdir -p .dogs/keeper
be get "//localhost/$SRC_REL"
KSRV_REL=${KSRV#$HOME/}

# --- 3. git clones from the keeper mirror via upload-pack override ---
#  The remote ssh login shell won't have BIN in PATH, so prepend it in
#  the upload-pack command itself — git passes this string verbatim to
#  the remote sh, which then evaluates the PATH= assignment before
#  exec'ing keeper.
git clone --quiet --upload-pack="PATH='$BIN':\$PATH keeper upload-pack" \
    "ssh://localhost/$KSRV" "$TMP/git-clone"

# --- 4. keeper clones from the keeper mirror ---
mkdir -p "$TMP/be-clone"
cd "$TMP/be-clone"
git init --quiet .
mkdir -p .dogs/keeper
be get "be://localhost/$KSRV_REL"

# --- 5. compare worktrees ---
RDIFF=$(rsync -rlcni --delete \
    --exclude='/.git/' --exclude='/.dogs/' --exclude='/.sniff' \
    "$TMP/git-clone/" "$TMP/be-clone/" 2>&1)
if [ -n "$RDIFF" ]; then
    echo "FAIL: clone-from-keeper: worktrees differ"
    echo "$RDIFF" | head -10
    exit 1
fi

# --- 6. canonical refs check: no `refs/`, no trunk aliases, no
#         `remotes/*`, no `#?<sha>` fragment form.
VERIFY="$TESTDIR/verify-canonical-refs.sh"
sh "$VERIFY" "$KSRV"         || { echo "FAIL: keeper mirror refs not canonical"; exit 1; }
sh "$VERIFY" "$TMP/be-clone" || { echo "FAIL: be-clone refs not canonical";    exit 1; }

# --- 7. idempotency: a repeat `be get` against the keeper mirror must
#         leave .dogs bit-identical.  Per keeper/LOG.md: the log is
#         append-of-packs; a no-op fetch produces zero file changes.
snapshot_dogs() { (cd "$1/.dogs" && find . -type f -not -name '.lock' \
    | sort | xargs sha256sum); }
SNAP1=$(snapshot_dogs "$TMP/be-clone")
be get "be://localhost/$KSRV_REL"
SNAP2=$(snapshot_dogs "$TMP/be-clone")
if [ "$SNAP1" != "$SNAP2" ]; then
    echo "FAIL: repeat be get changed files in .dogs"
    diff <(printf '%s\n' "$SNAP1") <(printf '%s\n' "$SNAP2") | head -20
    exit 1
fi

echo "PASS: clone-from-keeper"
