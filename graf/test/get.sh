#!/bin/bash
#  get.sh — smoke test for `graf get <uri>`.
#
#  Builds a tiny 3-commit history via `be post`, then exercises the
#  URI-driven `graf get` entry point:
#    - `path?<sha>`           single-tip blob read at commit
#    - `dir/?<sha>`           single-tip tree read at commit
#  Multi-tip merge URIs (`path?A&B...`) and tree merge URIs are no
#  longer supported — 3-way merge is PATCH territory (use
#  `be patch ?<branch>` instead).
#
#  Run:     BIN=build-debug/bin bash graf/test/get.sh
#  CTest:   registered by graf/test/CMakeLists.txt.
#
set -eu

BIN=${BIN:-$(dirname "$(command -v be)")}
BE="$BIN/be"
GRAF="$BIN/graf"

export ASAN_OPTIONS="${ASAN_OPTIONS:-}:detect_leaks=0"

for tool in "$BE" "$GRAF"; do
    [ -x "$tool" ] || { echo "FAIL: $tool not executable"; exit 1; }
done

TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-GRAFget}
TMP=$TMP/$TEST_ID/$$
mkdir -p "$TMP/.be"
trap '_rc=$?; [ "$_rc" -eq 0 ] && { rm -rf "$TMP"; rmdir "${TMP%/*}" 2>/dev/null || true; rmdir "${TMP%/*/*}" 2>/dev/null || true; }' EXIT INT TERM

fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "  - $*"; }

echo "=== 1. seed 3 commits ==="
R="$TMP/repo"; mkdir -p "$R/.be"; cd "$R"
git init --quiet -b main .
git config user.email t@t
git config user.name  t

for V in 1 2 3; do
    cat > f.c <<EOF
int f(int x) { return x + ${V}; }
int h${V}(int y) { return y * ${V}; }
EOF
    touch -d "2026-04-20 12:0${V}:00" f.c
    "$BE" post -m "v${V}" "?v0.0.${V}" >/dev/null 2>&1
    note "v0.0.${V} posted"
done

#  Ref rows are `<ts>\tset\t<key>#<40-hex-sha>`; grab the 40-hex
#  after the `#` separator.
awk_sha='/v0\.0\.'"X"'/ { n = index($3, "#"); if (n) print substr($3, n + 1) }'
SHA1=$(awk -F'\t' "${awk_sha/X/1}" .be/refs)
SHA2=$(awk -F'\t' "${awk_sha/X/2}" .be/refs)
SHA3=$(awk -F'\t' "${awk_sha/X/3}" .be/refs)
[ -n "$SHA1" ] && [ -n "$SHA2" ] && [ -n "$SHA3" ] \
    || fail "could not read commit shas from .be/refs"
note "shas: $SHA1 $SHA2 $SHA3"

echo "=== 2. graf index (force synchronous ingest) ==="
"$GRAF" index >/dev/null 2>&1 || fail "graf index failed"

echo "=== 3. graf get f.c?<sha_v1>  (single-tip identity) ==="
OUT=$("$GRAF" get "f.c?$SHA1")
echo "$OUT" | sed 's/^/    /'
echo "$OUT" | grep -qF 'x + 1' || fail "single-tip: expected v1 content"
echo "$OUT" | grep -qF 'h1'    || fail "single-tip: expected h1 helper"

echo "=== 4. graf get f.c?<sha_v3>  (single-tip identity, tip) ==="
OUT=$("$GRAF" get "f.c?$SHA3")
echo "$OUT" | sed 's/^/    /'
echo "$OUT" | grep -qF 'x + 3' || fail "single-tip tip: expected v3 content"
echo "$OUT" | grep -qF 'h3'    || fail "single-tip tip: expected h3"

echo "=== 5. graf get /?<sha3>  (root tree, single tip) ==="
#  Tree output is binary: "<mode> <name>\0<20-byte sha>" entries.
#  Must be non-empty and contain at least one f.c entry.
"$GRAF" get "/?$SHA3" > "$TMP/tree_single.bin"
[ -s "$TMP/tree_single.bin" ] || fail "root tree: empty output"
grep -qF 'f.c' "$TMP/tree_single.bin" \
    || fail "root tree single: f.c not found"
note "single-tip root tree size $(wc -c < "$TMP/tree_single.bin") bytes"

echo "=== 6. multi-tip merge URIs must be rejected ==="
#  `path?A&B...` and tree merge URIs are no longer accepted — merge
#  is PATCH territory now.  The CLI should fail (non-zero exit).
if "$GRAF" get "f.c?$SHA1&$SHA3" >/dev/null 2>&1; then
    fail "graf get f.c?sha1&sha3 should have failed (merge URI retired)"
fi
note "graf get f.c?A&B correctly rejected"

echo
echo "=== graf get: OK ==="
