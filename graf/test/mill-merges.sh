#!/bin/sh
#  mill-merges.sh — 3-way blob-merge treadmill for `graf get`.
#
#  Pick N recent CLEAN 2-parent merges from ~/src/git (selected
#  offline so `git merge-tree --write-tree P1 P2` agrees with the
#  committed merge tree — i.e. the merge was auto-resolved, no
#  manual edits).  For each merge M with parents P1, P2:
#
#    1. keeper fetches P1 and P2 via ssh localhost on ~/src/git,
#       using recent release tags that cover the reachable history.
#       The indexer fan-out populates graf's DAG.
#    2. For every file both sides touched (vs LCA): run
#         graf get <file>?<P1>&<P2>
#       and compare bytes to `git show <M>:<file>`.  Under the
#       CLEAN-merge invariant the git side is exactly the 3-way
#       merge, so the two outputs should agree for files where
#       graf's token-level merge aligns with git's line-level one.
#
#  Merges + expected overlap were picked by inspecting
#  `git log --merges` against master; change MERGES if the repo
#  tip advances past them.
#
#  Run: BIN=build-debug/bin sh graf/test/mill-merges.sh

set -eu

BIN=${BIN:-$(dirname "$(command -v be)")}
export PATH="$BIN:$PATH"
export DOG_REMOTE_PATH="$BIN"
export ASAN_OPTIONS="${ASAN_OPTIONS:-}:detect_leaks=0"

REPO=${REPO:-$HOME/src/git}
REPO_REL=${REPO#$HOME/}
HOST=${HOST:-localhost}

TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-GRAFmillMerges}
TMILL=$TMP/$TEST_ID
mkdir -p "$TMILL/client/.dogs"
trap 'rm -rf "$TMILL"; rmdir "$TMP" 2>/dev/null || true' EXIT

#  Curated merges: 2-parent, file-overlapping, and CLEAN under
#  `git merge-tree --write-tree P1 P2`.  Small ones first so a
#  diff-only tip catches obvious regressions early; the 11-file
#  `http-rate-limit-retries` at the end is the stress case.
MERGES=${MERGES:-"\
949f59e963 \
5032e70fc2 \
18396dc97d \
a1d7a8fef1 \
0a39ec283c"}

#  One tag whose reachable closure covers every merge above — a
#  single keeper fetch primes the store for all of them.  2.54-rc0
#  is the tip when the test was written; bump if it drops out of
#  the test box's fetchable refs.
SEED_REF=${SEED_REF:-heads/master}

# --- 1. Seed the keeper client with the repo's reachable history. ---
echo "=== seed keeper with //$HOST/$REPO_REL?$SEED_REF ==="
cd "$TMILL/client"
keeper get "//$HOST/$REPO_REL?$SEED_REF" >/dev/null
STATUS=$(graf status 2>&1)
echo "  $STATUS"
case "$STATUS" in
    *" 0 entries"*) echo "FAIL: graf index empty"; exit 1;;
esac

# --- 2. Per-merge treadmill. ---

TOTAL=0
FAIL=0

for M in $MERGES; do
    P1=$(git -C "$REPO" rev-parse "${M}^1")
    P2=$(git -C "$REPO" rev-parse "${M}^2")
    A=$(git -C "$REPO" merge-base "$P1" "$P2")
    SUBJ=$(git -C "$REPO" log -1 --format=%s "$M")

    L="$TMILL/left.$$"
    R="$TMILL/right.$$"
    git -C "$REPO" diff --name-only "$A" "$P1" | sort > "$L"
    git -C "$REPO" diff --name-only "$A" "$P2" | sort > "$R"
    BOTH=$(comm -12 "$L" "$R")
    rm -f "$L" "$R"

    echo ""
    echo "=== $M  $SUBJ ==="
    echo "  P1=$P1"
    echo "  P2=$P2"
    echo "  LCA=$A"

    for F in $BOTH; do
        TOTAL=$((TOTAL + 1))

        GIT_OUT="$TMILL/git.$TOTAL"
        GRAF_OUT="$TMILL/graf.$TOTAL"
        git -C "$REPO" show "$M:$F" > "$GIT_OUT" 2>/dev/null || {
            printf "SKIP:  %s @ %s (git show failed)\n" "$F" "$M"
            continue
        }
        if ! (cd "$TMILL/client" && \
              graf get "$F?$P1&$P2" > "$GRAF_OUT" 2>/dev/null); then
            printf "FAIL:  %s @ %s (graf get exit %d)\n" "$F" "$M" $?
            FAIL=$((FAIL + 1))
            continue
        fi

        if cmp -s "$GIT_OUT" "$GRAF_OUT"; then
            printf "PASS:  %s @ %s (%s bytes)\n" \
                "$F" "$M" "$(wc -c < "$GIT_OUT")"
        else
            DIFF_BYTES=$(cmp -l "$GIT_OUT" "$GRAF_OUT" 2>/dev/null | wc -l)
            printf "FAIL:  %s @ %s (byte diff: %s)\n" \
                "$F" "$M" "$DIFF_BYTES"
            FAIL=$((FAIL + 1))
        fi
    done
done

echo ""
echo "=== PASS1: $TOTAL merge/file cases, $FAIL failures ==="

# --- 3. Pass 2: drive `be patch` into real worktrees and compare -----
#
#  Per curated merge M:
#      wt  ← `be get ?<P1>`    (sniff checks P1 out)
#      wt  ← `be patch ?<P2>`  (3-way merge P2's tip, via graf)
#      ref ← `git checkout <M>` in a reference no-checkout clone
#  Then rsync -c compares wt against the reference tree
#  (excluding .dogs/ + .git/).  Any diff = FAIL.  The git side is
#  the authoritative 3-way result under the CLEAN-merge selection,
#  so exact content agreement is the target.
#
#  Runs only when `be` is available; skipped otherwise so the
#  script can be executed against older builds that pre-date
#  `be patch` wiring.

BE_BIN="$BIN/be"
if [ ! -x "$BE_BIN" ]; then
    echo "=== PASS2 skipped (no $BE_BIN) ==="
    test "$FAIL" = 0
    exit $?
fi

echo ""
echo "=== PASS2: be get ?P1 + be patch ?P2 vs git checkout <M> ==="

#  Reference clone: a no-checkout full mirror, switched to each M.
REFCLONE="$TMILL/git-ref"
git clone --quiet --no-checkout "$REPO" "$REFCLONE" >/dev/null 2>&1 \
    || git clone --quiet --no-checkout "ssh://$HOST/$REPO_REL" "$REFCLONE"

PATCH_TOTAL=0
PATCH_FAIL=0
for M in $MERGES; do
    P1=$(git -C "$REPO" rev-parse "${M}^1")
    P2=$(git -C "$REPO" rev-parse "${M}^2")
    SUBJ=$(git -C "$REPO" log -1 --format=%s "$M")
    PATCH_TOTAL=$((PATCH_TOTAL + 1))

    WT="$TMILL/wt.$M"
    mkdir -p "$WT/.dogs"

    echo ""
    echo "=== $M  $SUBJ ==="

    set +e
    #  Seed this wt's .dogs with the same ref Pass 1 used — the curated
    #  merges are all reachable from it, so the follow-up `be get ?<sha>`
    #  can resolve locally (git upload-pack rejects `want <sha>` without
    #  allow-reachable-sha1-in-want).
    (cd "$WT" && be get "//$HOST/$REPO_REL?$SEED_REF" >/dev/null 2>&1)
    SEED_RC=$?
    if [ "$SEED_RC" -ne 0 ]; then
        printf "FAIL: be get ?%s (seed) exit %d\n" "$SEED_REF" "$SEED_RC"
        PATCH_FAIL=$((PATCH_FAIL + 1))
        set -e
        continue
    fi
    (cd "$WT" && be get "//$HOST/$REPO_REL?$P1" >/dev/null 2>&1)
    GET_RC=$?
    if [ "$GET_RC" -ne 0 ]; then
        printf "FAIL: be get ?P1 exit %d\n" "$GET_RC"
        PATCH_FAIL=$((PATCH_FAIL + 1))
        set -e
        continue
    fi
    (cd "$WT" && be patch "?$P2" > "$TMILL/patch.log.$M" 2>&1)
    PATCH_RC=$?
    set -e

    #  `be patch` exits non-zero on conflict.  That's only a failure
    #  for the treadmill when we picked CLEAN merges — mark it as
    #  unexpected.
    if [ "$PATCH_RC" -ne 0 ]; then
        printf "FAIL: be patch ?P2 exit %d (log: %s)\n" \
            "$PATCH_RC" "$TMILL/patch.log.$M"
        sed 's/^/    | /' < "$TMILL/patch.log.$M" | head -6
        PATCH_FAIL=$((PATCH_FAIL + 1))
        continue
    fi

    git -C "$REFCLONE" checkout --quiet --force "$M"

    RDIFF=$(rsync -rlcni --delete \
        --exclude='/.git/' --exclude='/.dogs/' --exclude='/.sniff' \
        "$REFCLONE/" "$WT/" 2>&1)

    if [ -z "$RDIFF" ]; then
        N=$(find "$WT" -not -path '*/.dogs/*' -not -name '.sniff' \
            -type f | wc -l)
        printf "PASS: %s (%s files match git checkout)\n" "$M" "$N"
    else
        printf "FAIL: %s wt differs from git checkout\n" "$M"
        echo "$RDIFF" | head -6 | sed 's/^/    | /'
        PATCH_FAIL=$((PATCH_FAIL + 1))
    fi
done

echo ""
echo "=== PASS2: $PATCH_TOTAL merges, $PATCH_FAIL failures ==="

# --- 4. Pass 3: be log:<path> vs git log <path> -----------------------
#
#  The keeper at $TMILL/client has the full history reachable from
#  $SEED_REF in $REPO; the DAG index was populated by `keeper get`
#  during the seed step.  Walk a few representative paths via
#  `be log:<path>#<seed-sha>` and compare the SHA list to
#  `git log <seed-sha> -- <path>`.  Pinning to the resolved seed SHA
#  (not the moving ref) keeps both sides walking the same tip
#  even if upstream advances mid-test.
#
#  Paths chosen for breadth, not depth: README.md (~tens of commits),
#  Makefile (~thousands), Documentation/git.txt (~hundreds, exercises
#  a multi-component path).  Override with LOG_PATHS=… to widen.
#
#  Was prohibitively slow before LOG.c switched to leaf-SHA
#  comparison + reusable tree-walk scratch — `be log:Makefile` over
#  ~80k commits used to drown in mmap/munmap of the per-call 1MB
#  blob buffer.

echo ""
echo "=== PASS3: be log:<path> vs git log <path> ==="

LOG_PATHS=${LOG_PATHS:-"README.md Makefile Documentation/git.txt"}
SEED_SHA=$(git -C "$REPO" rev-parse "$SEED_REF")
echo "  seed=$SEED_SHA"

LOG_TOTAL=0
LOG_FAIL=0
for F in $LOG_PATHS; do
    LOG_TOTAL=$((LOG_TOTAL + 1))
    GIT_OUT="$TMILL/git.log.$LOG_TOTAL"
    BE_OUT="$TMILL/be.log.$LOG_TOTAL"

    git -C "$REPO" log --format=%h "$SEED_SHA" -- "$F" > "$GIT_OUT"

    #  `be log:` output: 1-line title ("--- log:… ---") then
    #  "<sha7> <date> <subject> (<author>)" rows, then a trailing
    #  blank from HUNK formatting.  Strip the title and the blank,
    #  keep the leading sha7 column.
    T0=$(date +%s)
    (cd "$TMILL/client" && \
        be log:"$F"\#"$SEED_SHA" 2>/dev/null) \
        | awk 'NR>1 && NF>0 {print $1}' > "$BE_OUT"
    T1=$(date +%s)

    if cmp -s "$BE_OUT" "$GIT_OUT"; then
        printf "PASS:  %s (%s commits, %ss)\n" \
            "$F" "$(wc -l < "$GIT_OUT")" "$((T1 - T0))"
    else
        BE_N=$(wc -l < "$BE_OUT")
        GIT_N=$(wc -l < "$GIT_OUT")
        printf "FAIL:  %s (be=%s git=%s, %ss)\n" \
            "$F" "$BE_N" "$GIT_N" "$((T1 - T0))"
        diff "$GIT_OUT" "$BE_OUT" | head -8 | sed 's/^/    | /'
        LOG_FAIL=$((LOG_FAIL + 1))
    fi
done

echo ""
echo "=== PASS3: $LOG_TOTAL paths, $LOG_FAIL failures ==="
echo "=== TOTAL: pass1=$FAIL pass2=$PATCH_FAIL pass3=$LOG_FAIL ==="
test "$FAIL" = 0 && test "$PATCH_FAIL" = 0 && test "$LOG_FAIL" = 0
