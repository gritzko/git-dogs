#!/bin/sh
#  mill-tags.sh — incremental tag-by-tag treadmill
#
#  Clones ~/src/git at v2.8.4, checks out, then updates through
#  each subsequent tag, comparing worktrees with git at each step.
#
#  Run: BIN=build-debug/bin sh beagle/test/mill-tags.sh
#
set -e

BIN=${BIN:-$(dirname "$(command -v be)")}
BIN=$(cd "$BIN" && pwd)
export PATH="$BIN:$PATH"

TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-mill-tags}
TMILL=${TMILL:-$TMP/$TEST_ID/$$}
REPO=${REPO:-$HOME/src/git}
NTAGS=${NTAGS:-12}
#  Keeper URI paths are $HOME-relative: //host/src/git → $HOME/src/git.
REPO_REL=${REPO_REL:-${REPO#$HOME/}}
HOST=${HOST:-localhost}
trap 'rm -rf "$TMILL"; rmdir "${TMILL%/*}" 2>/dev/null || true; rmdir "$TMP" 2>/dev/null || true' EXIT

TAGS=${TAGS:-$(git -C "$REPO" tag --sort=creatordate | tail -n "$NTAGS")}

mkdir -p "$TMILL/be01" "$TMILL/git01"

# --- Init dogs repo ---
cd "$TMILL/be01"
git init --quiet .
mkdir -p .dogs/keeper

# --- Init git reference repo ---
git clone --quiet --no-checkout "$REPO" "$TMILL/git01"

FAIL=0
TOTAL=0
for TAG in $TAGS; do
    TOTAL=$((TOTAL + 1))
    echo ""
    echo "=== $TAG ==="

    cd "$TMILL/be01"
    #  3-min timeout: a clean clone of ~/src/git takes ~1 min; anything
    #  past 3x that is hung indexing, not slow IO.
    #  Serialized: concurrent `git checkout` in git01 races against
    #  be's ssh pipe to git-upload-pack and triggers keeper SIGPIPE
    #  (exit 149).  Run be first, git reference checkout after.
    BE_LOG="$TMILL/be-${TAG}.log"
    set +e
    #  10-min ceiling: the full chain is keeper fetch + sniff checkout
    #  + spot reindex.  Spot's first-tag full reindex of ~3k git source
    #  files is the slow leg; later tags are incremental.
    timeout 600 be get "//${HOST}/${REPO_REL}?tags/${TAG}" > "$BE_LOG" 2>&1
    BE_STATUS=$?
    set -e
    grep -v "^keeper: round" "$BE_LOG" || true
    if [ "$BE_STATUS" -eq 124 ]; then
        echo "FAIL: $TAG (be get timed out after 600s)"
        FAIL=$((FAIL + 1))
        continue
    fi
    if [ "$BE_STATUS" -ne 0 ]; then
        echo "FAIL: $TAG (be get exit $BE_STATUS)"
        FAIL=$((FAIL + 1))
        continue
    fi

    git -C "$TMILL/git01" checkout --quiet "refs/tags/${TAG}"

    # --- rsync dry-run: full content comparison ---
    RDIFF=$(rsync -rlcni --delete \
        --exclude='/.git/' --exclude='/.dogs/' --exclude='/.sniff' \
        "$TMILL/git01/" "$TMILL/be01/" 2>&1)

    BE_N=$(find "$TMILL/be01" -not -path '*/.dogs/*' -not -path '*/.git/*' -type f | wc -l)

    if [ -z "$RDIFF" ]; then
        echo "PASS: $TAG ($BE_N files)"
    else
        echo "FAIL: $TAG"
        echo "$RDIFF" | head -10
        FAIL=$((FAIL + 1))
    fi
done

echo ""
echo "=== $TOTAL tags, $FAIL failures ==="
test "$FAIL" = "0"
