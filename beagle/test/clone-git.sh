#!/bin/sh
#  clone-git.sh — clone localhost:$HOME/src/git via `be get`, compare
#  the resulting worktree with a reference `git clone` of the same repo.
#
#  Run: BIN=build-debug/bin sh beagle/test/clone-git.sh
#
#  Uses three scratch dirs under $HOME/tmp/clone/:
#    git01 — dogs clone (be get)
#    git02 — git reference clone (git clone --no-checkout + checkout HEAD)
#    git03 — reserved for a second dogs clone at a different ref (optional)

set -e

BIN=${BIN:-$(dirname "$(command -v be)")}
BIN=$(cd "$BIN" && pwd)
export PATH="$BIN:$PATH"
TESTDIR=$(cd "$(dirname "$0")" && pwd)

REPO=${REPO:-$HOME/src/git}
TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-clone-git}
CLONE=${CLONE:-$TMP/$TEST_ID}
REF=${REF:-HEAD}
NAME=${NAME:-$(basename "$REPO" .git)}

DOGS_DIR="$CLONE/$NAME"
GIT_DIR="$CLONE/$NAME.git-ref"

rm -rf "$DOGS_DIR" "$GIT_DIR"
mkdir -p "$DOGS_DIR"
trap 'rm -rf "$CLONE"; rmdir "$TMP" 2>/dev/null || true' EXIT INT TERM

# --- git reference clone ---
echo "=== git clone reference ==="
git clone --quiet --no-checkout "$REPO" "$GIT_DIR"
if [ "$REF" = "HEAD" ]; then
    git -C "$GIT_DIR" checkout --quiet
else
    git -C "$GIT_DIR" checkout --quiet "$REF"
fi

# --- dogs clone via be get ---
echo "=== be get ==="
cd "$DOGS_DIR"
mkdir -p .dogs/keeper

if [ "$REF" = "HEAD" ]; then
    be get "ssh://localhost${REPO}" 2>&1 | grep -v "^keeper: round" || true
else
    be get "ssh://localhost${REPO}?${REF}" 2>&1 | grep -v "^keeper: round" || true
fi

# --- compare worktrees (rsync dry-run) ---
echo "=== diff ==="
RDIFF=$(rsync -rlcni --delete \
    --exclude='/.git/' --exclude='/.dogs/' \
    "$GIT_DIR/" "$DOGS_DIR/" 2>&1)

G1=$(find "$DOGS_DIR" -not -path '*/.dogs/*' -not -path '*/.git/*' -type f | wc -l)
G2=$(find "$GIT_DIR" -not -path '*/.git/*' -type f | wc -l)
echo "$DOGS_DIR (be get): $G1 files"
echo "$GIT_DIR (git):    $G2 files"

if [ -n "$RDIFF" ]; then
    echo "FAIL: worktrees differ"
    echo "$RDIFF" | head -20
    exit 1
fi

# --- canonical refs check ---
VERIFY="$TESTDIR/verify-canonical-refs.sh"
sh "$VERIFY" "$DOGS_DIR" || { echo "FAIL: refs not canonical"; exit 1; }

echo "PASS: worktrees identical at $REF"
exit 0
