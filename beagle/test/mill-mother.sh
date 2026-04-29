#!/bin/bash
#  mill-mother.sh — the "mother of all treadmills".
#
#  Seeds a dog repo from a git source one tag at a time, keeper-clones
#  the dog repo, then walks every tag in the git source, dog01 and
#  dog02 and rsync-compares the three worktrees.
#
#  Phase 1 (seed dog01):
#    for TAG in last-N tags of $REPO:
#      git -C src01 checkout TAG
#      rsync src01/ -> dog01/   (preserving dog01/.git and dog01/.dogs)
#      be post -m TAG ?tags/TAG  (inside dog01 — commits + marks)
#
#  Phase 2 (keeper -> keeper clone):
#    be get be://$HOST/<dog01-home-rel>   (into dog02)
#
#  Phase 3 (verify):
#    for TAG in same tag list:
#      git -C git01 checkout TAG
#      be get ?tags/TAG  in dog01
#      be get ?tags/TAG  in dog02
#      rsync-diff git01 vs dog01 and git01 vs dog02
#
#  Env:
#    REPO   path to a git source repo (default: a 10-commit toy repo
#           built under $TMILL/src — good for the first smoke run)
#    NTAGS  how many of the most-recent v* tags to walk (default 10)
#    HOST   keeper host used for the keeper->keeper clone (default localhost)
#    BIN    where `be` lives (default ../../build-debug/bin)
#
#  Run (toy):     BIN=build-debug/bin bash beagle/test/mill-mother.sh
#  Run (src/git): REPO=$HOME/src/git NTAGS=5 \
#                 BIN=build-debug/bin bash beagle/test/mill-mother.sh

set -eu

BIN=${BIN:-$(dirname "$(command -v be)")}
#  Absolute path — `be` gets invoked from several different cwds below.
BIN=$(cd "$BIN" && pwd)
export PATH="$BIN:$PATH"
#  The keeper->keeper clone ssh'es to $HOST and the remote login shell
#  won't have $BIN in PATH; this env var tells `be` where keeper lives
#  on the other side.  Same trick as clone-from-keeper.sh.
export DOG_REMOTE_PATH="$BIN"
BE="$BIN/be"

TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-mill-mother}
TMILL=${TMILL:-$TMP/$TEST_ID}
HOST=${HOST:-localhost}
NTAGS_WANT=${NTAGS:-10}

KEEP_WORK=${KEEP_WORK:-}
trap '[ -z "$KEEP_WORK" ] && { rm -rf "$TMILL"; rmdir "$TMP" 2>/dev/null || true; }; echo; echo "workdir: $TMILL${KEEP_WORK:+ (kept)}"' EXIT
mkdir -p "$TMILL"

#  --- Source git repo: caller-supplied, or a fresh toy one. ---
if [ -n "${REPO:-}" ]; then
    SRC="$REPO"
    [ -d "$SRC/.git" ] || [ -d "$SRC/refs" ] \
        || { echo "REPO=$SRC is not a git repo"; exit 2; }
else
    SRC="$TMILL/src"
    git init -q "$SRC"
    git -C "$SRC" config user.email 't@t'
    git -C "$SRC" config user.name  t

    #  Ten versions that actually exercise adds, edits, renames,
    #  deletes, new dirs, nuked dirs and nested subtrees.  Each step
    #  is a `git add -A && git commit && git tag` checkpoint so the
    #  treadmill can walk them in order.
    tag() {
        git -C "$SRC" add -A
        git -C "$SRC" commit -q -m "$1"
        git -C "$SRC" tag "$1"
    }

    # v0.0.1 — baseline: README, src/, include/, docs/.
    mkdir -p "$SRC/src" "$SRC/include" "$SRC/docs"
    echo 'toy project v1'          > "$SRC/README.md"
    echo 'int main(){return 0;}'   > "$SRC/src/main.c"
    echo 'int util(){return 1;}'   > "$SRC/src/util.c"
    echo 'int util(void);'         > "$SRC/include/util.h"
    echo 'intro docs'              > "$SRC/docs/intro.md"
    tag v0.0.1

    # v0.0.2 — edit README, add lib/ subtree.
    echo 'toy project v2 (lib)'    > "$SRC/README.md"
    mkdir -p "$SRC/lib"
    echo 'int helper(){return 2;}' > "$SRC/lib/helper.c"
    echo 'int helper(void);'       > "$SRC/lib/helper.h"
    tag v0.0.2

    # v0.0.3 — rename util -> core, drop intro, add api docs.
    git -C "$SRC" mv src/util.c       src/core.c
    git -C "$SRC" mv include/util.h   include/core.h
    echo 'int core(){return 1;}'   > "$SRC/src/core.c"
    echo 'int core(void);'         > "$SRC/include/core.h"
    echo '#include "core.h"'       > "$SRC/src/main.c"
    git -C "$SRC" rm -q docs/intro.md
    mkdir -p "$SRC/docs"
    echo 'api reference'           > "$SRC/docs/api.md"
    tag v0.0.3

    # v0.0.4 — add a test/ subtree.
    mkdir -p "$SRC/test"
    echo 'main test'               > "$SRC/test/test_main.c"
    echo 'core test'               > "$SRC/test/test_core.c"
    tag v0.0.4

    # v0.0.5 — nuke lib/, replace with lib/v2/ (directory rename-ish).
    git -C "$SRC" rm -qr lib
    mkdir -p "$SRC/lib/v2"
    echo 'int helper2(){return 22;}' > "$SRC/lib/v2/helper.c"
    echo 'int helper2(void);'        > "$SRC/lib/v2/helper.h"
    tag v0.0.5

    # v0.0.6 — broad edits + new top-level file.
    echo 'toy project v6'          > "$SRC/README.md"
    echo '# Changelog'             > "$SRC/CHANGELOG.md"
    echo 'int core(){return 6;}'   > "$SRC/src/core.c"
    tag v0.0.6

    # v0.0.7 — delete a test, add a test, edit main.
    git -C "$SRC" rm -q test/test_main.c
    echo 'helper test'             > "$SRC/test/test_helper.c"
    echo 'int main(){return 7;}'   > "$SRC/src/main.c"
    tag v0.0.7

    # v0.0.8 — nested subtree: src/platform/{linux,mac}.c.
    mkdir -p "$SRC/src/platform"
    echo 'int plat_linux(){return 0;}' > "$SRC/src/platform/linux.c"
    echo 'int plat_mac(){return 0;}'   > "$SRC/src/platform/mac.c"
    tag v0.0.8

    # v0.0.9 — rename include/ -> inc/ (whole-dir rename).
    git -C "$SRC" mv include inc
    tag v0.0.9

    # v0.0.10 — final polish: edit README, add a README under test/.
    echo 'toy project v10 (final)' > "$SRC/README.md"
    echo 'tests live here'         > "$SRC/test/README.md"
    tag v0.0.10
fi

TAGS=$(git -C "$SRC" for-each-ref 'refs/tags/v*' \
    --sort=version:refname --format='%(refname:short)' | tail -"$NTAGS_WANT")
[ -n "$TAGS" ] || { echo "no v* tags in $SRC"; exit 2; }
NTAGS=$(echo "$TAGS" | wc -l)

echo "=== mill-mother: repo=$SRC ntags=$NTAGS workdir=$TMILL ==="
echo "--- tags:"
echo "$TAGS" | sed 's/^/    /'

#  --- Worktrees ---
#  src01  seeding worktree (git checkout drives the tag order)
#  git01  reference worktree used during verification
#  dog01  primary dog repo (seeded via be post)
#  dog02  secondary dog repo (keeper->keeper clone of dog01)
git clone -q --no-checkout "$SRC" "$TMILL/src01"
git clone -q --no-checkout "$SRC" "$TMILL/git01"

#  dog01 is a bare worktree.  `be post` creates .dogs/ on first commit.
#  (Don't `git init` here — we don't need a host git repo, and an empty
#  .git/ would be scanned and committed if SNIFFSkipMeta didn't skip it.)
mkdir -p "$TMILL/dog01"

FAIL=0
TOTAL=0

#  --- Phase 1: seed dog01 tag by tag ---
echo
echo "=== Phase 1: seed dog01 ==="
printf "%-20s  %s\n" "tag" "post"
printf "%-20s  %s\n" "---" "----"
for TAG in $TAGS; do
    TOTAL=$((TOTAL + 1))
    git -C "$TMILL/src01" checkout -q "refs/tags/$TAG"
    #  Mirror src01 onto dog01, preserving dog01's own meta dirs.
    #  `-c` forces checksum compare: git checkout preserves mtimes
    #  from the tree, so mtime+size quick-check can miss
    #  same-size/same-mtime content changes across tags.
    rsync -rlc --delete \
        --exclude='/.git/' --exclude='/.dogs/' --exclude='/.sniff*' \
        "$TMILL/src01/" "$TMILL/dog01/"
    cd "$TMILL/dog01"
    T0=$(date +%s)
    if "$BE" post -m "$TAG" "?tags/$TAG" >"$TMILL/be-post-$TAG.log" 2>&1; then
        POST_T=$(( $(date +%s) - T0 ))
        printf "%-20s  be post=%2ds\n" "$TAG" "$POST_T"
    else
        printf "%-20s  FAIL (be post exit $?)\n" "$TAG"
        head -20 "$TMILL/be-post-$TAG.log" | sed 's/^/    /'
        FAIL=$((FAIL + 1))
        KEEP_WORK=1
    fi
done

[ "$FAIL" -eq 0 ] || {
    echo
    echo "=== mill-mother: Phase 1 failed, stopping ==="
    exit 1
}

#  --- Phase 2: keeper -> keeper clone ---
echo
echo "=== Phase 2: keeper->keeper clone dog01 -> dog02 ==="
#  dog01 path must be $HOME-relative for the be:// URI convention.
case "$TMILL/dog01" in
    "$HOME"/*) DOG01_REL=${TMILL#$HOME/}/dog01 ;;
    *) echo "TMILL must live under \$HOME for be:// URIs (TMILL=$TMILL)"; exit 2 ;;
esac

mkdir -p "$TMILL/dog02"
cd "$TMILL/dog02"
T0=$(date +%s)
#  `be get be://.../` without a query fetches the peer's HEAD only
#  (by design — mirrors `git clone`).  Walk every tag explicitly so
#  Phase 3 can check dog02 at each one.
for TAG in $TAGS; do
    "$BE" get "be://$HOST/$DOG01_REL?tags/$TAG" 2>&1 \
        | grep -Ev '^(keeper|sniff|spot|graf-dag|sync):|^(GURIDBG|GETDBG|KEEPLDBG|WALKDBG|REFSDBG|POSTDBG)\b' || true
done
CLONE_T=$(( $(date +%s) - T0 ))
echo "clone: ${CLONE_T}s (iterated ${NTAGS} tag(s))"

#  --- Phase 3: checkout each tag in git01/dog01/dog02, rsync-compare ---
echo
echo "=== Phase 3: verify ==="
printf "%-20s  %s\n" "tag" "result"
printf "%-20s  %s\n" "---" "------"
for TAG in $TAGS; do
    git -C "$TMILL/git01" checkout -q "refs/tags/$TAG"

    #  Track dog01 and dog02 independently — a broken keeper->keeper
    #  clone shouldn't hide a working dog01 round-trip (or vice
    #  versa).  `-i` on rsync is required: without it dry-run stays
    #  silent even with missing files.
    #  sniff prunes files but leaves empty dirs on disk across
    #  checkouts; git does the same.  Strip empties before comparing
    #  so we don't flag dir-only differences that carry no file state.
    prune_empty() { find "$1" -depth -type d -empty \
                         -not -path "$1" -delete 2>/dev/null || true; }

    D1="dog01 be get failed"
    if ( cd "$TMILL/dog01" && "$BE" get "?tags/$TAG" >/dev/null 2>&1 ); then
        prune_empty "$TMILL/dog01"
        prune_empty "$TMILL/git01"
        D1=$(rsync -rlcni --delete \
            --exclude='/.git/' --exclude='/.dogs/' --exclude='/.sniff*' \
            "$TMILL/git01/" "$TMILL/dog01/" 2>&1)
    fi
    D2="dog02 be get failed"
    if ( cd "$TMILL/dog02" && "$BE" get "?tags/$TAG" >/dev/null 2>&1 ); then
        prune_empty "$TMILL/dog02"
        D2=$(rsync -rlcni --delete \
            --exclude='/.git/' --exclude='/.dogs/' --exclude='/.sniff*' \
            "$TMILL/git01/" "$TMILL/dog02/" 2>&1)
    fi

    r1=$([ -z "$D1" ] && echo OK || echo FAIL)
    r2=$([ -z "$D2" ] && echo OK || echo FAIL)
    N=$(find "$TMILL/dog01" -not -path '*/.dogs/*' -not -path '*/.git/*' \
        -not -path '*/.sniff*' -type f | wc -l)
    if [ "$r1" = OK ] && [ "$r2" = OK ]; then
        printf "%-20s  PASS  (%s files, git==dog01==dog02)\n" "$TAG" "$N"
    else
        printf "%-20s  FAIL  (dog01=%s dog02=%s)\n" "$TAG" "$r1" "$r2"
        [ "$r1" = FAIL ] && { echo "    git vs dog01:"; echo "$D1" | head -6 | sed 's/^/      /'; }
        [ "$r2" = FAIL ] && { echo "    git vs dog02:"; echo "$D2" | head -6 | sed 's/^/      /'; }
        FAIL=$((FAIL + 1))
        KEEP_WORK=1
    fi
done

echo
echo "=== mill-mother: $((TOTAL - FAIL))/$TOTAL passed ==="
[ "$FAIL" -eq 0 ]
