#!/bin/sh
#  tag-blobs-from-keeper.sh — incremental tag fetch from a keeper-served
#  toy, with byte-level blob assertion at each step + negative
#  assertion that not-yet-fetched newer tags' blobs stay invisible.
#
#  Flow:
#    1. Build toy git (3 commits, v1, v2, master).
#    2. Seed keeper mirror from git (sniff-free; pure keeper get).
#    3. Stand up a no-worktree git oracle: full no-checkout clone, used
#       as the byte truth for every (path, ref) pair.
#    4. Fresh keeper client.  For each step in v1 → v2 → master:
#       a. `keeper get be://localhost/<KSRV_REL>?<ref>`   (fetch one tag)
#       b. For every path in the toy: assert
#            `keeper get <path>?<ref>` bytes == `git show <ref>:<path>`.
#       c. For every later step's ref: assert
#            `keeper get <path>?<later-ref>` FAILS (ref not yet in REFS,
#            so the projector cannot resolve a tree to walk).
#
#  No worktrees, no sniff.  Verifies that the keeper protocol over ssh
#  delivers exactly the requested ref's reachable closure and nothing
#  more — newer-tag blobs only become available after their own fetch.
#
#  Run: BIN=build-debug/bin sh beagle/test/tag-blobs-from-keeper.sh

set -eu

BIN=${BIN:-$(dirname "$0")/../../build-debug/bin}
BIN=$(cd "$BIN" && pwd)
export PATH="$BIN:$PATH"
export DOG_REMOTE_PATH="$BIN"

TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-tag-blobs-from-keeper}
TMP=$TMP/$TEST_ID
TMP_REL=${TMP#$HOME/}
mkdir -p "$TMP"; echo "Running in $PWD"
trap 'rm -rf "$TMP"; rmdir "${TMP%/*}" 2>/dev/null || true' EXIT

# --- 1. toy git source: 3 revs, two files, v1+v2 tags, master tip ---
SRC=$TMP/src
git init --quiet --bare "$SRC"

W=$(mktemp -d)
git -c init.defaultBranch=master init --quiet "$W"
git -C "$W" config user.email t@t
git -C "$W" config user.name t
git -C "$W" remote add origin "$SRC"

echo rev1 >"$W/f.txt"
echo gA   >"$W/g.txt"
git -C "$W" add f.txt g.txt
git -C "$W" commit --quiet -m "rev 1"
git -C "$W" tag v1
echo rev2 >"$W/f.txt"
git -C "$W" commit --quiet -am "rev 2"
git -C "$W" tag v2
echo rev3 >"$W/f.txt"
echo gB   >"$W/g.txt"
git -C "$W" commit --quiet -am "rev 3"
git -C "$W" push --quiet origin master --tags
rm -rf "$W"

SRC_REL=${SRC#$HOME/}

# --- 2. seed keeper mirror (server side); sniff-free. ---
KSRV=$TMP/keeper-srv
mkdir -p "$KSRV/.dogs/keeper"
cd "$KSRV"
for REF in refs/tags/v1 refs/tags/v2 refs/heads/master; do
    keeper get "//localhost/$SRC_REL?$REF" >/dev/null
done
KSRV_REL=${KSRV#$HOME/}

# --- 3. git oracle: full no-checkout clone (truth for blob bytes) ---
git clone --quiet --no-checkout "ssh://localhost/$SRC" "$TMP/git-oracle"

# --- 4. fresh keeper client; iterate v1 → v2 → master ---
mkdir -p "$TMP/be-client/.dogs/keeper"

#  Step table: <name> <git-ref> <keeper-fetch-ref> <keeper-projector-ref>
#  - git-ref       : how git names the ref (`git show <git-ref>:<path>`)
#  - fetch-ref     : how WIREFetch wants it (refs/tags/X — git wire form)
#  - projector-ref : how keeper REFS stores it (tags/X — see keeper/REF.md)
STEPS="v1:v1:refs/tags/v1:tags/v1
v2:v2:refs/tags/v2:tags/v2
master:master:refs/heads/master:heads/master"
PATHS="f.txt g.txt"

FAIL=0
PREV=""
for LINE in $STEPS; do
    NAME=$(echo "$LINE" | cut -d: -f1)
    GREF=$(echo "$LINE" | cut -d: -f2)
    FREF=$(echo "$LINE" | cut -d: -f3)
    PREF=$(echo "$LINE" | cut -d: -f4)

    cd "$TMP/be-client"
    keeper get "be://localhost/$KSRV_REL?$FREF" >/dev/null

    #  Positive: every path's blob at <NAME> must match git oracle.
    for P in $PATHS; do
        GBYTES=$(git -C "$TMP/git-oracle" show "$GREF:$P")
        KBYTES=$(cd "$TMP/be-client" && keeper get "$P?$PREF" 2>/dev/null || echo MISSING)
        if [ "$GBYTES" = "$KBYTES" ]; then
            printf "PASS: %s @ %-7s\n" "$P" "$NAME"
        else
            printf "FAIL: %s @ %-7s\n  git    : %s\n  keeper : %s\n" \
                "$P" "$NAME" "$GBYTES" "$KBYTES"
            FAIL=$((FAIL + 1))
        fi
    done

    #  Negative: every later step's blobs must be unavailable in keeper
    #  (their ref hasn't been fetched yet, so the projector cannot
    #  resolve a tree to walk).
    SAW_SELF=NO
    for LATER in $STEPS; do
        L_NAME=$(echo "$LATER" | cut -d: -f1)
        L_PREF=$(echo "$LATER" | cut -d: -f4)
        if [ "$L_NAME" = "$NAME" ]; then
            SAW_SELF=YES
            continue
        fi
        [ "$SAW_SELF" = NO ] && continue   # earlier step, skip
        for P in $PATHS; do
            if (cd "$TMP/be-client" && \
                keeper get "$P?$L_PREF" >/dev/null 2>&1); then
                printf "FAIL: %s @ %-7s leaked at step %s\n" \
                    "$P" "$L_NAME" "$NAME"
                FAIL=$((FAIL + 1))
            else
                printf "PASS: %s @ %-7s absent at step %s (negative)\n" \
                    "$P" "$L_NAME" "$NAME"
            fi
        done
    done

    PREV=$NAME
done

exit $FAIL
