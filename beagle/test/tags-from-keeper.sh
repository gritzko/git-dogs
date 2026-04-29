#!/bin/sh
#  tags-from-keeper.sh — keeper and git each iterate v1 → v2 → master
#  from a toy keeper repo, comparing worktrees at every step.
#
#  Builds the toy git repo, seeds it into a keeper mirror, then iterates
#  v1 → v2 → master, fetching each ref into:
#    - a be-clone via `be get be://localhost/...?<ref>`
#    - a git-clone via `git fetch --upload-pack='keeper upload-pack' ...`
#  rsync-comparing worktrees at every step.
#
#  Run: BIN=build-debug/bin sh beagle/test/tags-from-keeper.sh

set -eu

BIN=${DOG_BIN_DIR:-$(dirname "$(command -v be)")}
BIN=$(cd "$BIN" && pwd)
export PATH="$BIN:$PATH"
export DOG_REMOTE_PATH="$BIN"

TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-tags-from-keeper}
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

# --- 2. seed keeper mirror ---
#  `be get //origin` with no query only fetches HEAD; fetch each ref
#  explicitly so the mirror carries master + both tags (the consumer
#  tests below want every ref present in the mirror).
KSRV=$TMP/keeper-srv
mkdir -p "$KSRV"
cd "$KSRV"
git init --quiet .
mkdir -p .dogs/keeper
for REF in refs/heads/master refs/tags/v1 refs/tags/v2; do
    be get "//localhost/$SRC_REL?$REF" >/dev/null
done
KSRV_REL=${KSRV#$HOME/}

# --- 3. init both consumer roots ---
mkdir -p "$TMP/be-clone"
cd "$TMP/be-clone"
git init --quiet .
mkdir -p .dogs/keeper

#  Reuse the bare git source for the git-clone's worktree shape, but
#  point its `origin` at the keeper mirror with the upload-pack override
#  so every fetch goes through `keeper upload-pack`.  PATH= prefix
#  injects the test BIN dir into the remote ssh's non-interactive shell.
git clone --quiet --no-checkout --upload-pack="PATH='$BIN':\$PATH keeper upload-pack" \
    "ssh://localhost/$KSRV" "$TMP/git-clone"

# --- 4. iterate v1 → v2 → master ---
FAIL=0
for STEP in "v1 refs/tags/v1" "v2 refs/tags/v2" "master refs/heads/master"; do
    NAME=${STEP%% *}
    REF=${STEP##* }

    cd "$TMP/be-clone"
    be get "be://localhost/$KSRV_REL?$REF" >/dev/null

    git -C "$TMP/git-clone" \
        fetch --quiet --no-tags \
        --upload-pack="PATH='$BIN':\$PATH keeper upload-pack" \
        origin "$REF:refs/keep/$NAME"
    git -C "$TMP/git-clone" checkout --quiet "refs/keep/$NAME"

    RDIFF=$(rsync -rlcni --delete \
        --exclude='/.git/' --exclude='/.dogs/' --exclude='/.sniff' \
        "$TMP/git-clone/" "$TMP/be-clone/" 2>&1)
    if [ -n "$RDIFF" ]; then
        echo "FAIL: tags-from-keeper $NAME"
        echo "$RDIFF" | head -10
        FAIL=$((FAIL + 1))
    else
        echo "PASS: tags-from-keeper $NAME"
    fi
done

exit $FAIL
