#!/bin/sh
#  history.sh — stage/commit a sequence of versions, label each with
#  a tag, then retrieve every version back into the worktree and
#  verify that files that appear/disappear do so correctly.
#
#  Flow:
#    1. `be post ?tags/v0.0.1 v1`  — seed: hello.txt + other.txt
#    2. `be delete hello.txt`
#       `be post ?tags/v0.0.2 v2`  — drop hello.txt
#    3. edit other.txt
#       `be post ?tags/v0.0.3 v3`  — other.txt changed, plus add
#                                    extra.txt
#    4. for each tag, `be get ?tags/v<n>` and check the worktree
#       matches the expected snapshot (files present/absent +
#       content).
#
set -eu

#  CMake sets BIN to the current build's bin dir via ENVIRONMENT (see
#  beagle/test/CMakeLists.txt).  Out-of-ctest default = build-debug.
BIN=${BIN:-$(dirname "$(command -v be)")}
BIN=$(cd "$BIN" && pwd)
BE="$BIN/be"

TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-BEhistory}
TMP=$TMP/$TEST_ID
mkdir -p "$TMP"; echo "Running in $PWD"
trap 'rm -rf "$TMP"; rmdir "${TMP%/*}" 2>/dev/null || true' EXIT INT TERM

fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "  - $*"; }

# Assert file exists with exact content.
want_file() {
    path="$1"; body="$2"
    [ -f "$path" ] || fail "$path: missing"
    got=$(cat "$path")
    [ "$got" = "$body" ] || fail "$path: want [$body] got [$got]"
}
# Assert file is gone.
want_gone() { [ ! -e "$1" ] || fail "$1: should be gone"; }

# --- 1. v1 (seed) -----------------------------------------------------
echo "=== 1. seed commit tagged v0.0.1 ==="
R="$TMP/r"; mkdir -p "$R"; cd "$R"
git init --quiet .
echo "alpha v1" > hello.txt
echo "stable"   > other.txt
"$BE" post "?tags/v0.0.1" v1 >/dev/null
note "v0.0.1 labeled"

# --- 2. v2 (delete hello.txt) ----------------------------------------
echo "=== 2. delete hello.txt, tag v0.0.2 ==="
"$BE" delete hello.txt >/dev/null
"$BE" post "?tags/v0.0.2" v2 >/dev/null
note "v0.0.2 labeled"

# --- 3. v3 (edit other.txt + add extra.txt) --------------------------
echo "=== 3. edit + add, tag v0.0.3 ==="
echo "beta v3"  > other.txt
echo "new file" > extra.txt
#  Selective mode: any explicit put/delete row puts POST in
#  selective mode, where only files named by put rows land in the
#  commit (per VERBS.md §POST classification).  Both files have to
#  be put-staged or the modification gets ignored.
"$BE" put other.txt >/dev/null
"$BE" put extra.txt >/dev/null
"$BE" post "?tags/v0.0.3" v3 >/dev/null
note "v0.0.3 labeled"

# --- 4. verify each version -------------------------------------------
echo "=== 4. get each tag, verify worktree contents ==="

"$BE" get "?tags/v0.0.1" >/dev/null
want_file hello.txt "alpha v1"
want_file other.txt "stable"
want_gone extra.txt
note "v0.0.1 ok (hello.txt + other.txt stable, no extra)"

"$BE" get "?tags/v0.0.2" >/dev/null
want_gone hello.txt
want_file other.txt "stable"
want_gone extra.txt
note "v0.0.2 ok (hello.txt gone, other.txt unchanged)"

"$BE" get "?tags/v0.0.3" >/dev/null
want_gone hello.txt
want_file other.txt "beta v3"
want_file extra.txt "new file"
note "v0.0.3 ok (other.txt edited, extra.txt appeared)"

# Round-trip back to v0.0.1 one more time to confirm reverse traversal
# restores a file that was added and then removed.
"$BE" get "?tags/v0.0.1" >/dev/null
want_file hello.txt "alpha v1"
want_file other.txt "stable"
want_gone extra.txt
note "v0.0.1 restored after v0.0.3 (extra.txt disappeared again)"

echo "=== history OK ==="
