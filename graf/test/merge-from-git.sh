#!/bin/sh
#  merge-from-git.sh — two-branch concurrent-edit merge via `graf get`.
#
#  Flow (mirrors beagle/test/blobs-from-git.sh for the git→keeper
#  seeding half):
#    1. Toy git source: one base commit on master, two feature
#       branches forked off master, each editing the same .c files
#       with disjoint additions.
#    2. Keeper client fetches each branch via ssh localhost.  The
#       indexer fan-out in `keeper get` forwards every resolved
#       object through `GRAFUpdate`, so graf's DAG index is built
#       as a side effect — no separate `graf index` call needed.
#    3. For each file, run `graf get <path>?<tip_a>&<tip_b>` and
#       assert both branches' additions survive the merge, and the
#       common body is preserved.
#
#  Two files, two branches, concurrent disjoint edits — the minimal
#  repro for true 3-way token-level merging via the DAG LCA.
#
#  Run: BIN=build-debug/bin sh graf/test/merge-from-git.sh

set -eu

BIN=${BIN:-$(dirname "$(command -v be)")}
export PATH="$BIN:$PATH"
export DOG_REMOTE_PATH="$BIN"
export ASAN_OPTIONS="${ASAN_OPTIONS:-}:detect_leaks=0"

TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-GRAFmergeFromGit}
TMP=$TMP/$TEST_ID
TMP_REL=${TMP#$HOME/}
mkdir -p "$TMP"
trap 'rm -rf "$TMP"; rmdir "${TMP%/*}" 2>/dev/null || true' EXIT

# --- 1. toy git source: base + feat-a + feat-b, concurrent edits ----

SRC=$TMP/src
git init --quiet --bare "$SRC"

W=$(mktemp -d)
git -c init.defaultBranch=master init --quiet "$W"
git -C "$W" config user.email t@t
git -C "$W" config user.name t
git -C "$W" remote add origin "$SRC"

cat >"$W/f.c" <<'EOF'
int f(int x) {
    return x + 1;
}
EOF
cat >"$W/g.c" <<'EOF'
int g(int y) {
    return y * 2;
}
EOF
git -C "$W" add f.c g.c
git -C "$W" commit --quiet -m "base"
git -C "$W" push --quiet origin master

#  feat-a inserts its addition BEFORE the base function, feat-b AFTER.
#  Disjoint insertion points keep JOIN's lockstep walk from
#  coalescing shared prefix tokens (both inserts at the same base
#  position would otherwise merge identical `int ` prefixes into
#  one emission).
git -C "$W" checkout --quiet -b feat-a master
cat >"$W/f.c" <<'EOF'
int foo(int a) {
    return a - 7;
}
int f(int x) {
    return x + 1;
}
EOF
cat >"$W/g.c" <<'EOF'
int goo(int b) {
    return b + 11;
}
int g(int y) {
    return y * 2;
}
EOF
git -C "$W" commit --quiet -am "feat-a: prepend foo/goo"
git -C "$W" push --quiet origin feat-a
TIP_A=$(git -C "$W" rev-parse HEAD)

git -C "$W" checkout --quiet -b feat-b master
cat >"$W/f.c" <<'EOF'
int f(int x) {
    return x + 1;
}
int bar(int c) {
    return c * 13;
}
EOF
cat >"$W/g.c" <<'EOF'
int g(int y) {
    return y * 2;
}
int gab(int d) {
    return d - 17;
}
EOF
git -C "$W" commit --quiet -am "feat-b: append bar/gab"
git -C "$W" push --quiet origin feat-b
TIP_B=$(git -C "$W" rev-parse HEAD)

rm -rf "$W"
SRC_REL=${SRC#$HOME/}

# --- 2. keeper client fetches every branch; indexer fan-out feeds
#        graf's DAG in the same call. ---

CLI=$TMP/client
mkdir -p "$CLI/.dogs"
cd "$CLI"
for REF in refs/heads/master refs/heads/feat-a refs/heads/feat-b; do
    keeper get "//localhost/$SRC_REL?$REF" >/dev/null
done

#  Sanity: graf's index must have entries — otherwise there was no
#  fan-out and we're about to silently test nothing.
STATUS=$(graf status 2>&1)
echo "  $STATUS"
case "$STATUS" in
    *" 0 entries"*) echo "FAIL: graf index empty after keeper fetch"; exit 1;;
esac

# --- 3. three-way merge per file --------------------------------------

FAIL=0
check_merge() {
    P=$1
    WANT_A=$2
    WANT_B=$3
    WANT_BASE=$4

    OUT=$(graf get "$P?$TIP_A&$TIP_B")
    echo "---- $P ? $TIP_A & $TIP_B ----"
    echo "$OUT" | sed 's/^/  | /'

    for TOK in "$WANT_A" "$WANT_B" "$WANT_BASE"; do
        if echo "$OUT" | grep -qF "$TOK"; then
            printf "PASS: %s contains '%s'\n" "$P" "$TOK"
        else
            printf "FAIL: %s missing '%s'\n" "$P" "$TOK"
            FAIL=$((FAIL + 1))
        fi
    done
}

check_merge f.c 'int foo('     'int bar('     'return x + 1'
check_merge g.c 'int goo('     'int gab('     'return y * 2'

exit $FAIL
