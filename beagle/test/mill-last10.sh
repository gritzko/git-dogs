#!/bin/bash
#  mill-last10.sh — incremental treadmill over the 10 most-recent v* tags
#  of $HOME/src/git (or REPO).  At each tag:
#
#    1. `be get …?refs/tags/TAG`  — fetch + checkout (timed)
#    2. `git checkout TAG`         — in a parallel reference clone (timed)
#    3. rsync --dry-run comparison of the two worktrees
#
#  Run: BIN=build-debug/bin bash beagle/test/mill-last10.sh
#
set -eu

BIN=${BIN:-$(dirname "$0")/../../build-debug/bin}
BIN=$(cd "$BIN" && pwd)
export PATH="$BIN:$PATH"
BE="$(command -v be || echo $BIN/be)"

REPO=${REPO:-$HOME/src/git}
#  Repo path as HOME-relative (keeper URI convention).
REPO_REL=${REPO#$HOME/}
HOST=${HOST:-localhost}
#  TMILL: workdir.  If caller provided a fixed path, preserve it on exit
#  (useful for inspecting the clone); otherwise mktemp + cleanup on exit.
if [ -n "${TMILL:-}" ]; then
    KEEP_ON_EXIT=1
    TMP=
else
    TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
    TEST_ID=${TEST_ID:-mill-last10}
    TMILL=$TMP/$TEST_ID
    KEEP_ON_EXIT=
fi
trap '[ -z "$KEEP_ON_EXIT" ] && { rm -rf "$TMILL"; [ -n "$TMP" ] && rmdir "$TMP" 2>/dev/null || true; }; echo "workdir: $TMILL${KEEP_ON_EXIT:+ (kept)}"' EXIT
mkdir -p "$TMILL/be01" "$TMILL/git01"

#  Dynamically pick the N most-recent v* tags (NTAGS, default 10).
NTAGS_WANT=${NTAGS:-10}
TAGS=$(cd "$REPO" && \
    git for-each-ref 'refs/tags/v*' --sort=version:refname \
        --format='%(refname:short)' | tail -"$NTAGS_WANT")
NTAGS=$(echo "$TAGS" | wc -l)
echo "=== mill-last10: host=$HOST repo=$REPO_REL workdir=$TMILL ==="
echo "--- tags ($NTAGS):"
echo "$TAGS" | sed 's/^/    /'

#  be side: bare-ish dogs repo.
cd "$TMILL/be01"
git init -q .
mkdir -p .dogs/keeper

#  git side: ssh-backed empty repo, no pre-fetch.  Each tag's fetch
#  goes over ssh for an apples-to-apples comparison with `be`.
git init -q "$TMILL/git01"
git -C "$TMILL/git01" remote add origin "$HOST:$REPO_REL"

FAIL=0
TOTAL=0
PREV_BE=""
PREV_GIT=""
printf "\n%-20s  %-25s  %-25s  %s\n" "tag" "be (fetch+checkout)" "git (fetch+checkout)" "worktree"
printf "%-20s  %-25s  %-25s  %s\n"  "---" "------------------" "--------------------" "--------"
for TAG in $TAGS; do
    TOTAL=$((TOTAL + 1))

    #  be: fetch + checkout
    cd "$TMILL/be01"
    T0=$(date +%s)
    "$BE" get "//$HOST/$REPO_REL?refs/tags/$TAG" 2>&1 \
        | grep -Ev '^keeper:|^sniff:|^spot:|^graf-dag:' || true
    BE_T=$(( $(date +%s) - T0 ))

    #  git: fetch (of the specific tag, to mirror incremental behavior)
    #  + checkout
    T0=$(date +%s)
    git -C "$TMILL/git01" fetch --no-tags -q origin \
        "refs/tags/$TAG:refs/keep/$TAG" 2>&1 >/dev/null || true
    git -C "$TMILL/git01" checkout -q "refs/keep/$TAG"
    GIT_T=$(( $(date +%s) - T0 ))

    #  rsync dry-run: reports any file content/mode/presence difference.
    RDIFF=$(rsync -rlcni --delete \
        --exclude='/.git/' --exclude='/.dogs/' \
        "$TMILL/git01/" "$TMILL/be01/" 2>&1)
    BE_N=$(find "$TMILL/be01" -not -path '*/.dogs/*' -not -path '*/.git/*' \
           -type f | wc -l)

    if [ -z "$RDIFF" ]; then
        printf "%-20s  be=%3ds  git=%3ds                       %s files, identical\n" \
            "$TAG" "$BE_T" "$GIT_T" "$BE_N"
    else
        printf "%-20s  be=%3ds  git=%3ds                       DIFF:\n" \
            "$TAG" "$BE_T" "$GIT_T"
        echo "$RDIFF" | head -10 | sed 's/^/    /'
        FAIL=$((FAIL + 1))
        # Preserve workdir on failure
        trap - EXIT
        echo "workdir kept at $TMILL"
    fi
done

echo
echo "=== mill-last10: $((TOTAL - FAIL))/$TOTAL passed ==="
test "$FAIL" = "0"
