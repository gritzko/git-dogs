#!/bin/bash
#  get.sh — smoke test for `graf get <uri>`.
#
#  Builds a tiny 3-commit history via `be post`, then exercises the
#  URI-driven `graf get` entry point:
#    - `path?<sha>`           single-tip identity (blob at commit)
#    - `path?<sha1>&<sha2>`   multi-tip weave replay
#  over a linear history, the N-tip call must converge to the tip
#  blob (weave projection keeps only tokens alive at the last fed
#  gen).
#
#  Run:     BIN=build-debug/bin bash graf/test/get.sh
#  CTest:   registered by graf/test/CMakeLists.txt.
#
set -eu

BIN=${BIN:-$(dirname "$0")/../../build-debug/bin}
BE="$BIN/be"
GRAF="$BIN/graf"

export ASAN_OPTIONS="${ASAN_OPTIONS:-}:detect_leaks=0"

for tool in "$BE" "$GRAF"; do
    [ -x "$tool" ] || { echo "FAIL: $tool not executable"; exit 1; }
done

TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-GRAFget}
TMP=$TMP/$TEST_ID
mkdir -p "$TMP"
trap 'rm -rf "$TMP"; rmdir "${TMP%/*}" 2>/dev/null || true' EXIT INT TERM

fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "  - $*"; }

echo "=== 1. seed 3 commits ==="
R="$TMP/repo"; mkdir -p "$R"; cd "$R"
git init --quiet -b main .
git config user.email t@t
git config user.name  t

for V in 1 2 3; do
    cat > f.c <<EOF
int f(int x) { return x + ${V}; }
int h${V}(int y) { return y * ${V}; }
EOF
    touch -d "2026-04-20 12:0${V}:00" f.c
    "$BE" post -m "v${V}" "?tags/v0.0.${V}" >/dev/null 2>&1
    note "v0.0.${V} posted"
done

#  Ref rows are `<ts>\tset\t<key>#<40-hex-sha>`; grab the 40-hex
#  after the `#` separator.
awk_sha='/v0\.0\.'"X"'/ { n = index($3, "#"); if (n) print substr($3, n + 1) }'
SHA1=$(awk -F'\t' "${awk_sha/X/1}" .dogs/refs)
SHA2=$(awk -F'\t' "${awk_sha/X/2}" .dogs/refs)
SHA3=$(awk -F'\t' "${awk_sha/X/3}" .dogs/refs)
[ -n "$SHA1" ] && [ -n "$SHA2" ] && [ -n "$SHA3" ] \
    || fail "could not read commit shas from .dogs/refs"
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

echo "=== 5. graf get f.c?<sha1>&<sha3>  (multi-tip linear) ==="
OUT=$("$GRAF" get "f.c?$SHA1&$SHA3")
echo "$OUT" | sed 's/^/    /'
#  Linear history v1 → v2 → v3: weave projection converges to the
#  latest-fed gen, i.e. v3's content.  A diverged-branch scenario
#  would produce richer merge output but needs branch support in
#  be/sniff first.
echo "$OUT" | grep -qF 'x + 3' || fail "multi-tip: expected v3 content"
echo "$OUT" | grep -qF 'h3'    || fail "multi-tip: expected h3"

echo "=== 6. graf get f.c?<sha1>&<sha2>&<sha3>  (3-way linear) ==="
OUT=$("$GRAF" get "f.c?$SHA1&$SHA2&$SHA3")
echo "$OUT" | sed 's/^/    /'
echo "$OUT" | grep -qF 'x + 3' || fail "3-way: expected v3 content"

echo "=== 7. graf get /?<sha3>  (root tree, single tip) ==="
#  Tree output is binary: "<mode> <name>\0<20-byte sha>" entries.
#  Must be non-empty and contain at least one f.c entry.
"$GRAF" get "/?$SHA3" > "$TMP/tree_single.bin"
[ -s "$TMP/tree_single.bin" ] || fail "root tree: empty output"
grep -qF 'f.c' "$TMP/tree_single.bin" \
    || fail "root tree single: f.c not found"
note "single-tip root tree size $(wc -c < "$TMP/tree_single.bin") bytes"

echo "=== 8. graf get /?<sha1>&<sha3>  (root tree, linear merge) ==="
"$GRAF" get "/?$SHA1&$SHA3" > "$TMP/tree_merge.bin"
[ -s "$TMP/tree_merge.bin" ] || fail "root tree merge: empty output"
#  Entries that didn't change between v1 and v3 (sniff's flat `.git/…`
#  ingestion) carry matching shas on both sides and pass through.
#  f.c's blob changed between v1 and v3, so its entry's sha must be
#  the 20-byte zero marker (unresolvable — caller re-fetches via
#  graf with the same child URI).  Byte-for-byte v3 equality must
#  therefore FAIL.
if cmp -s "$TMP/tree_single.bin" "$TMP/tree_merge.bin"; then
    fail "root tree merge: did not emit zero sha for disagreeing f.c"
fi
note "merged root tree differs from v3 (f.c's sha zeroed on disagreement)"
#  The f.c entry must sit at `100644 f.c\0` + 20 NUL bytes.
#  POSIX-friendly: dump to hex, scan for the literal pattern.
HEX=$(xxd -p -c 999999 "$TMP/tree_merge.bin" | tr -d '\n')
#  "100644 f.c\0" = 31 30 30 36 34 34 20 66 2e 63 00
#  Followed by 40 hex chars of zero = the 20-byte zero sha.
PAT='31303036343420662e6300'$(printf '0%.0s' $(seq 1 40))
case "$HEX" in
    *"$PAT"*) note "f.c entry carries a zero sha as expected" ;;
    *)        fail "f.c sha not zeroed (expected 100644 f.c\\0<20 NULs>)" ;;
esac

echo
echo "=== graf get: OK ==="
