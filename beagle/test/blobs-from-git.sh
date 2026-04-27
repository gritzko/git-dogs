#!/bin/sh
#  blobs-from-git.sh — no-checkout clone by keeper and git from a toy
#  git repo, then byte-level blob comparison via each side's CLI.
#
#  No worktrees are compared.  Both sides clone object-only:
#    git    : git clone --no-checkout ssh://localhost/SRC
#    keeper : keeper get //localhost/SRC?<ref>   (per ref; no sniff,
#             no checkout — pure object download via WIREFetch)
#
#  For every (path, ref) tuple in the toy, we read the blob through the
#  projector verb and diff bytes:
#    git    : git show <ref>:<path>
#    keeper : keeper get <path>?<ref>
#
#  Run: BIN=build-debug/bin sh beagle/test/blobs-from-git.sh

set -eu

BIN=${BIN:-$(dirname "$0")/../../build-debug/bin}
BIN=$(cd "$BIN" && pwd)
export PATH="$BIN:$PATH"
export DOG_REMOTE_PATH="$BIN"

TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-blobs-from-git}
TMP=$TMP/$TEST_ID
TMP_REL=${TMP#$HOME/}
mkdir -p "$TMP"; echo "Running in $PWD"
trap 'rm -rf "$TMP"; rmdir "${TMP%/*}" 2>/dev/null || true' EXIT

# --- 1. toy git source: 3 revs, two files, v1+v2 tags, master tip ---
#  f.txt evolves at every commit; g.txt only changes at master.  Six
#  (path, ref) blobs total to verify (3 refs × 2 paths).
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

# --- 2. git clones, no checkout ---
git clone --quiet --no-checkout "ssh://localhost/$SRC" "$TMP/git-clone"

# --- 3. keeper fetches objects for each ref (sniff-free path) ---
mkdir -p "$TMP/be-clone/.dogs/keeper"
cd "$TMP/be-clone"
for REF in refs/tags/v1 refs/tags/v2 refs/heads/master; do
    keeper get "//localhost/$SRC_REL?$REF" >/dev/null
done

# --- 4. byte-level blob comparison via each side's projector CLI ---
#  keeper REFS strips the `refs/` prefix per keeper/REF.md, so the
#  projector ref form is `tags/v1` / `heads/master`, not `refs/...`.
FAIL=0
for ENTRY in \
    "f.txt v1     tags/v1" \
    "f.txt v2     tags/v2" \
    "f.txt master heads/master" \
    "g.txt v1     tags/v1" \
    "g.txt v2     tags/v2" \
    "g.txt master heads/master"
do
    set -- $ENTRY
    PATH_=$1
    NAME=$2
    REF=$3

    GBYTES=$(git -C "$TMP/git-clone" show "$NAME:$PATH_")
    KBYTES=$(cd "$TMP/be-clone" && keeper get "$PATH_?$REF")

    if [ "$GBYTES" = "$KBYTES" ]; then
        printf "PASS: %s @ %-7s  %s\n" "$PATH_" "$NAME" "$(echo "$GBYTES" | head -1)"
    else
        printf "FAIL: %s @ %-7s\n  git    : %q\n  keeper : %q\n" \
            "$PATH_" "$NAME" "$GBYTES" "$KBYTES"
        FAIL=$((FAIL + 1))
    fi
done

exit $FAIL
