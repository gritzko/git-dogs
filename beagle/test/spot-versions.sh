#!/bin/bash
#  spot-versions.sh — spot search across the four modes at a URI ?ref.
#
#  Builds a 4-tag toy repo where the symbol $SYMBOL appears 0, 1, 2, 3
#  times across v0.0.1..v0.0.4.  Clones into be01 once (worktree parked
#  at v0.0.4) — every historical query is then driven by URI:
#
#      spot -g $SYMBOL '//<host>/<repo>?refs/tags/vN' .c
#
#  Spot opens keeper, resolves the ref, walks the tree via KEEPLsFiles,
#  and greps each blob — so the counts track the ref, not the on-disk
#  worktree.  Stdout is piped → HUNKu8sFeedText (no bro pager fork).
#
#  Tested search forms, expected hit counts per version:
#
#      mode        v0.0.1  v0.0.2  v0.0.3  v0.0.4
#      -g  grep       0       1       2       3       (MarkerXYZ tokens)
#      -p  pcre       0       1       2       3       (Marker\w+)
#      -s  snippet    0       0       1       2       (MarkerXYZ() calls)
#
#  A final `-s … -r …` replacement runs on the be01 worktree (v0.0.4)
#  and expects 3 rewrites.
#
#  Run: BIN=build-debug/bin bash beagle/test/spot-versions.sh
#
set -eu

BIN=${BIN:-$(dirname "$0")/../../build-debug/bin}
BIN=$(cd "$BIN" && pwd)
export PATH="$BIN:$PATH"
BE="$(command -v be   || echo $BIN/be)"
SPOT="$(command -v spot || echo $BIN/spot)"

TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-spot-versions}
TMP=$TMP/$TEST_ID
HOST=${HOST:-localhost}
SYMBOL=${SYMBOL:-MarkerXYZ}
RENAMED=${RENAMED:-RenamedABC}

KEEP_WORK=""
trap '[ -z "$KEEP_WORK" ] && { rm -rf "$TMP"; rmdir "${TMP%/*}" 2>/dev/null || true; }; \
      echo; echo "workdir: $TMP${KEEP_WORK:+ (kept)}"' EXIT
mkdir -p "$TMP/src" "$TMP/be01"

#  --- Build source repo ----------------------------------------------
cd "$TMP/src"
git init -q .
git config user.email t@t
git config user.name  t

#  Each version places $SYMBOL occurrences on lines separated by ≥5
#  blank lines, so the default context (3) doesn't merge hunks.

#  v0.0.1 — 0 occurrences.
cat > main.c <<EOF
#include <stdio.h>

int main(void) {
    return 0;
}
EOF
git add -A; git commit -q -m c1; git tag v0.0.1

#  v0.0.2 — 1 occurrence: definition, no calls.
cat > main.c <<EOF
#include <stdio.h>

void $SYMBOL(void) { return; }

int main(void) { return 0; }
EOF
git add -A; git commit -q -m c2; git tag v0.0.2

#  v0.0.3 — 2 occurrences: definition + 1 call.
cat > main.c <<EOF
#include <stdio.h>

void $SYMBOL(void) { return; }






void call_once(void) { $SYMBOL(); }






int main(void) { return 0; }
EOF
git add -A; git commit -q -m c3; git tag v0.0.3

#  v0.0.4 — 3 occurrences: definition + 2 calls.
cat > main.c <<EOF
#include <stdio.h>

void $SYMBOL(void) { return; }






void call_a(void) { $SYMBOL(); }






void call_b(void) { $SYMBOL(); }






int main(void) { return 0; }
EOF
git add -A; git commit -q -m c4; git tag v0.0.4

REPO_REL=${TMP#$HOME/}/src
REPO_URI="//$HOST/$REPO_REL"

echo "=== spot-versions: host=$HOST repo=$REPO_REL symbol=$SYMBOL ==="
git -C "$TMP/src" tag | sort -V | sed 's/^/    /'

#  --- Init be01 consumer, fetch v0.0.4 into worktree ------------------
cd "$TMP/be01"
git init -q .
mkdir -p .dogs/keeper
timeout 10 "$BE" get "$REPO_URI?refs/tags/v0.0.4" 2>&1 \
    | grep -Ev '^keeper:|^sniff:|^spot:|^graf-dag:' || true

#  Common count helper: expected and got.
FAIL=0
TOTAL=0
report() {
    TOTAL=$((TOTAL + 1))
    local tag=$1 mode=$2 expect=$3 got=$4
    if [ "$got" = "$expect" ]; then
        printf "  %s %-10s expect=%d got=%d  ok\n" "$mode" "$tag" "$expect" "$got"
    else
        printf "  %s %-10s expect=%d got=%d  FAIL\n" "$mode" "$tag" "$expect" "$got"
        FAIL=$((FAIL + 1))
        KEEP_WORK=1
    fi
}

#  --- grep (-g) — substring, -C 0 so each hit is its own hunk ---------
echo
echo "--- mode: grep (-g) — substring across all AST leaves ---"
for n in 1 2 3 4; do
    TAG="v0.0.$n"
    EXPECT=$((n - 1))
    URI="$REPO_URI?refs/tags/$TAG"
    GOT=$("$SPOT" -g "$SYMBOL" -C 0 "$URI" .c 2>/dev/null \
            | grep -c '^---' || true)
    report "$TAG" "grep   " "$EXPECT" "$GOT"
done

#  --- pcre (-p) — regex, same counts as grep on Marker\w+ -------------
echo
echo "--- mode: pcre (-p) — Thompson NFA regex ---"
for n in 1 2 3 4; do
    TAG="v0.0.$n"
    EXPECT=$((n - 1))
    URI="$REPO_URI?refs/tags/$TAG"
    GOT=$("$SPOT" -p 'Marker\w+' -C 0 "$URI" .c 2>/dev/null \
            | grep -c '^---' || true)
    report "$TAG" "pcre   " "$EXPECT" "$GOT"
done

#  --- snippet (-s) — structural: matches calls `$SYMBOL()` only -------
echo
echo "--- mode: snippet (-s) — structural pattern '$SYMBOL()' ---"
#  v0.0.1 has no symbol, v0.0.2 has only the def (no calls),
#  v0.0.3 has 1 call, v0.0.4 has 2 calls.
SNIPPET_EXPECT=(0 0 1 2)
for n in 1 2 3 4; do
    TAG="v0.0.$n"
    EXPECT=${SNIPPET_EXPECT[$((n - 1))]}
    URI="$REPO_URI?refs/tags/$TAG"
    GOT=$("$SPOT" -s "$SYMBOL()" "$URI" .c 2>/dev/null \
            | grep -c '^---' || true)
    report "$TAG" "snippet" "$EXPECT" "$GOT"
done

#  --- replace (-s … -r …) — worktree only (v0.0.4 = 3 tokens) ---------
#  Historic replace is refused by CAPOSpot; this variant exercises the
#  on-disk path: worktree → rewrite → verify.
echo
echo "--- mode: replace (-s $SYMBOL -r $RENAMED) — worktree (v0.0.4) ---"
cd "$TMP/be01"
#  Pre-check: worktree is on v0.0.4 (3 tokens).
PRE=$(grep -c "$SYMBOL" main.c || true)
report "v0.0.4" "pre-rep" 3 "$PRE"

REP_OUT=$("$SPOT" -s "$SYMBOL" -r "$RENAMED" .c 2>&1 || true)
echo "$REP_OUT" | sed 's/^/    /'

#  Verify: file on disk now has 0 $SYMBOL and 3 $RENAMED.
POST_OLD=$(grep -c "$SYMBOL"  main.c || true)
POST_NEW=$(grep -c "$RENAMED" main.c || true)
report "v0.0.4" "post-old" 0 "$POST_OLD"
report "v0.0.4" "post-new" 3 "$POST_NEW"

echo
echo "=== spot-versions: $((TOTAL - FAIL))/$TOTAL passed ==="
[ "$FAIL" -eq 0 ]
