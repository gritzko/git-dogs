#!/bin/sh
#  ls.sh — `sniff ls:` / `be ls:` smoke test (verbless per VERBS.md
#  §"View projectors").  Exercises wt, subdir, tree-at-ref modes in
#  both plain-text and TLV output, and confirms `be ls:...` does NOT
#  fall through to a destructive sniff-get checkout.
set -eu

BIN=${BIN:-$(dirname "$0")/../../build-debug/bin}
export PATH="$BIN:$PATH"
export ASAN_OPTIONS="${ASAN_OPTIONS:-}:detect_leaks=0"

TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-SNIFFls}
TMP=$TMP/$TEST_ID
trap 'rm -rf "$TMP"; rmdir "${TMP%/*}" 2>/dev/null || true' EXIT INT TERM
mkdir -p "$TMP"

fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "  - $*"; }

WT="$TMP/wt"
mkdir -p "$WT/sub"
cd "$WT"
echo "a line"     > a.txt
echo "sub file 1" > sub/s1.txt
echo "sub file 2" > sub/s2.txt
sniff post -m "base" >/dev/null
note "base commit staged"

# --- plain-text modes (verb-less, per VERBS.md §View projectors) ------
echo "=== 1. sniff ls: (wt) ==="
out=$(sniff 'ls:' 2>/dev/null | sort)
echo "$out" | grep -qx 'a.txt'       || fail "wt list missing a.txt"
echo "$out" | grep -qx 'sub/s1.txt'  || fail "wt list missing sub/s1.txt"
echo "$out" | grep -qx 'sub/s2.txt'  || fail "wt list missing sub/s2.txt"
note "wt list ok (a.txt, sub/s1.txt, sub/s2.txt present)"

echo "=== 2. sniff ls:sub/ (subdir) ==="
out=$(sniff 'ls:sub/' 2>/dev/null | sort)
echo "$out" | grep -qF 'sub/'        || fail "subdir list missing prefix match"
echo "$out" | grep -qF 's1.txt'      || fail "subdir list missing s1.txt"
echo "$out" | grep -vq '^a\.txt$'    || fail "subdir list should not include a.txt"
note "subdir list ok"

echo "=== 3. sniff ls:? (tip tree) ==="
out=$(sniff 'ls:?' 2>/dev/null)
echo "$out" | grep -qx 'a.txt'       || fail "tip tree missing a.txt"
echo "$out" | grep -qx 'sub/'        || fail "tip tree missing sub/"
echo "$out" | grep -qx 'sub/s1.txt'  || fail "tip tree missing sub/s1.txt"
note "tip-tree list ok"

echo "=== 4. sniff ls:sub/? (subtree at tip) ==="
out=$(sniff 'ls:sub/?' 2>/dev/null)
echo "$out" | grep -qx 'sub/s1.txt'  || fail "subtree@tip missing sub/s1.txt"
echo "$out" | grep -qvx 'a.txt'      || fail "subtree@tip leaked a.txt"
note "subtree-at-tip ok"

# --- TLV mode ---------------------------------------------------------
echo "=== 5. sniff --tlv ls:? produces HUNK-framed output ==="
#  First byte of a HUNK record is the tag letter 'H'.  abc/TLV emits
#  one of two variants: long-form 'H' (0x48) for records >255 bytes,
#  or short-form 'H' | TLVaA = 'h' (0x68) for compact records.  Accept
#  either — both are valid and HUNKu8sDrain transparently handles them.
head_byte=$(sniff --tlv 'ls:?' 2>/dev/null | head -c1 | od -An -v -tx1 \
            | tr -d ' ')
case "$head_byte" in
    48|68) ;;
    *) fail "--tlv: bad first byte '$head_byte' (want 48 'H' or 68 'h')" ;;
esac
tlv_bytes=$(sniff --tlv 'ls:?' 2>/dev/null | wc -c)
[ "$tlv_bytes" -gt 20 ] || fail "--tlv: output too small ($tlv_bytes bytes)"
note "--tlv frame ok (first byte = H/h, $tlv_bytes bytes total)"

# --- be wiring --------------------------------------------------------
echo "=== 6. be ls:? (verbless) is non-destructive ==="
#  Capture mtime of a known tracked file, run `be ls:?`, confirm
#  nothing changed on disk.  Non-TTY in CI => be falls back to plain
#  text output; we only care that the wt is untouched.
mtime_before=$(stat -c %Y a.txt 2>/dev/null \
               || stat -f %m a.txt)
out=$(be 'ls:?' 2>/dev/null | sort)
mtime_after=$(stat -c %Y a.txt 2>/dev/null \
              || stat -f %m a.txt)
[ "$mtime_before" = "$mtime_after" ] \
    || fail "be ls:? touched a.txt (mtime changed)"
echo "$out" | grep -qx 'a.txt'       || fail "be ls:? missing a.txt"
echo "$out" | grep -qx 'sub/s1.txt'  || fail "be ls:? missing sub/s1.txt"
note "be ls:? non-destructive and correct"

echo
echo "=== sniff ls: OK ==="
