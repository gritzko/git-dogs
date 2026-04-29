#!/bin/bash
#  mill-toy.sh — treadmill smoke test over a synthesized toy repo.
#
#  Builds a toy git repo with 10 files, 10 commits, 10 tags (v0.0.1..10)
#  under $TMILL/src.  Then runs the mill-last10 loop: for each tag, `be
#  get` into be01, `git fetch+checkout` into git01, rsync-diff worktrees.
#
#  Run: BIN=build-debug/bin bash beagle/test/mill-toy.sh
#
set -eu

BIN=${DOG_BIN_DIR:-$(dirname "$(command -v be)")}
BIN=$(cd "$BIN" && pwd)
export PATH="$BIN:$PATH"
#  Resolve `be` once to a fully-qualified path to rule out lookup oddities.
BE="$(command -v be || echo $BIN/be)"
echo "# BE=$BE"

TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-mill-toy}
TMILL=${TMILL:-$TMP/$TEST_ID}
HOST=${HOST:-localhost}

KEEP_WORK=""
trap '[ -z "$KEEP_WORK" ] && { rm -rf "$TMILL"; rmdir "$TMP" 2>/dev/null || true; }; echo; echo "workdir: $TMILL${KEEP_WORK:+ (kept)}"' EXIT
mkdir -p "$TMILL/src" "$TMILL/be01" "$TMILL/git01"

#  --- Build toy source repo ---
cd "$TMILL/src"
git init -q .
git config user.email 't@t'
git config user.name t
for i in 1 2 3 4 5 6 7 8 9 10; do
    for j in 1 2 3 4 5 6 7 8 9 10; do
        #  Each file evolves slightly at each tag.  Ensures the set of
        #  reachable blobs across 10 tags has deltable siblings, so the
        #  server produces thin packs with REF_DELTAs on fetch-by-tag.
        printf 'file%d @ v0.0.%d line %d\n' "$j" "$i" $j > "f$j.txt"
    done
    git add -A
    git commit -q -m "c$i"
    git tag "v0.0.$i"
done

#  Repo path is HOME-relative for the keeper URI convention.
REPO_REL=${TMILL#$HOME/}/src

echo "=== mill-toy: host=$HOST repo=$REPO_REL workdir=$TMILL ==="
echo "--- source tags:"
git -C "$TMILL/src" tag | sort -V | sed 's/^/    /'

#  --- Init be + git consumer roots ---
cd "$TMILL/be01"
git init -q .
mkdir -p .dogs/keeper
git clone -q --no-checkout "$TMILL/src" "$TMILL/git01"

#  --- Per-tag loop ---
TAGS=$(git -C "$TMILL/src" tag | sort -V)
FAIL=0
TOTAL=0
printf "\n%-12s  %-22s  %-22s  %s\n" "tag" "be (fetch+checkout)" "git (fetch+checkout)" "worktree"
printf   "%-12s  %-22s  %-22s  %s\n" "---" "-------------------" "--------------------" "--------"
for TAG in $TAGS; do
    TOTAL=$((TOTAL + 1))
    cd "$TMILL/be01"

    T0=$(date +%s)
    timeout 10 "$BE" get "//$HOST/$REPO_REL?refs/tags/$TAG" 2>&1 \
        | grep -Ev '^keeper:|^sniff:|^spot:|^graf-dag:' || true
    BE_T=$(( $(date +%s) - T0 ))
    if [ "$BE_T" -ge 10 ]; then
        echo "    TIMEOUT: be get >$BE_T s for $TAG"
        KEEP_WORK=1; FAIL=$((FAIL + 1)); continue
    fi
    if [ "$BE_T" -ge 10 ]; then
        echo "    TIMEOUT: be get >$BE_T s for $TAG"
        KEEP_WORK=1; FAIL=$((FAIL + 1)); continue
    fi

    T0=$(date +%s)
    git -C "$TMILL/git01" fetch --no-tags -q origin \
        "refs/tags/$TAG:refs/keep/$TAG" 2>&1
    git -C "$TMILL/git01" checkout -q "refs/keep/$TAG"
    GIT_T=$(( $(date +%s) - T0 ))

    RDIFF=$(rsync -rlcni --delete \
        --exclude='/.git/' --exclude='/.dogs/' \
        "$TMILL/git01/" "$TMILL/be01/" 2>&1)
    BE_N=$(find "$TMILL/be01" -not -path '*/.dogs/*' -not -path '*/.git/*' \
           -type f | wc -l)

    if [ -z "$RDIFF" ]; then
        printf "%-12s  be=%2ds                   git=%2ds                   %s files, identical\n" \
            "$TAG" "$BE_T" "$GIT_T" "$BE_N"
    else
        printf "%-12s  be=%2ds                   git=%2ds                   DIFF:\n" \
            "$TAG" "$BE_T" "$GIT_T"
        echo "$RDIFF" | head -8 | sed 's/^/    /'
        FAIL=$((FAIL + 1))
        KEEP_WORK=1
    fi
done

echo
echo "=== mill-toy: $((TOTAL - FAIL))/$TOTAL passed ==="
[ "$FAIL" -eq 0 ]
