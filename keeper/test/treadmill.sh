#!/bin/bash
# Treadmill: clone → update → verify cycle for keeper.
#
# Usage: treadmill.sh <remote> [keeper-binary]
#
# Connects to remote, gets tag list, clones oldest of 10 tags,
# incrementally updates to each newer tag, verifies each.

REMOTE="${1:?usage: treadmill.sh <remote> [keeper-binary]}"
KEEPER="${2:-keeper}"
TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-keeper-treadmill}
WORKDIR="${WORKDIR:-$TMP/$TEST_ID}"
mkdir -p "$WORKDIR"
trap 'rm -rf "$WORKDIR"; rmdir "$TMP" 2>/dev/null || true' EXIT INT TERM
HOST="${REMOTE%% *}"
REPO="${REMOTE#* }"

echo "=== treadmill: remote=$REMOTE workdir=$WORKDIR ==="

mkdir -p "$WORKDIR/.dogs/keeper"

# Get tags via git-upload-pack ref advertisement
echo "--- listing tags ---"
REFS=$(echo | ssh "$HOST" git-upload-pack "$REPO" 2>/dev/null | \
       strings | grep -oE '[0-9a-f]{40} refs/tags/v[0-9][^ ]*' | \
       grep -v '\^{}' | sort -t/ -k3 -V)

# Extract tag name → SHA pairs, take last 10
TAGS=""
while IFS= read -r line; do
    SHA=${line:0:40}
    TAG=${line#* refs/tags/}
    TAGS="$TAGS$TAG $SHA"$'\n'
done <<< "$REFS"

TAGS=$(echo "$TAGS" | grep -v '^$' | tail -10)
NTAGS=$(echo "$TAGS" | wc -l)
echo "found $NTAGS tags"
echo "$TAGS" | awk '{print "  " $1}'

if [ "$NTAGS" -lt 2 ]; then
    echo "FAIL: need at least 2 tags"
    exit 1
fi

cd "$WORKDIR"

PREV_SHA=""
PREV_TAG=""
STEP=0
PASS=0
FAIL=0

while IFS= read -r line; do
    [ -z "$line" ] && continue
    TAG=$(echo "$line" | awk '{print $1}')
    SHA=$(echo "$line" | awk '{print $2}')
    STEP=$((STEP + 1))

    echo ""
    echo "=== step $STEP: $TAG (${SHA:0:12}) ==="

    if [ -z "$PREV_SHA" ]; then
        echo "--- clone $TAG ---"
        "$KEEPER" -u "$REMOTE" --want "$SHA" 2>&1 | grep "keeper:" || true
    else
        echo "--- update $PREV_TAG → $TAG ---"
        "$KEEPER" -u "$REMOTE" --want "$SHA" --have "$PREV_SHA" 2>&1 | grep "keeper:" || true
    fi

    echo "--- verify $TAG ---"
    VOUT=$("$KEEPER" --verify "$SHA" 2>&1)
    VFAILED=$(echo "$VOUT" | grep "failed" | tail -1)
    echo "  $VFAILED"
    if echo "$VFAILED" | grep -q " 0 failed"; then
        PASS=$((PASS + 1))
    else
        echo "  FAIL"
        echo "$VOUT" | grep -E "MISS|MISMATCH" | head -5
        FAIL=$((FAIL + 1))
    fi

    PREV_SHA="$SHA"
    PREV_TAG="$TAG"
done <<< "$TAGS"

echo ""
echo "=== treadmill: $PASS passed, $FAIL failed out of $STEP ==="
echo "=== $("$KEEPER" -s 2>&1) ==="

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
