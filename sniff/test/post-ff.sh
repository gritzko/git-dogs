#!/bin/sh
#  post-ff.sh — POST pre-flight tests:
#    * empty POST refused (no changes since baseline → SNIFFNOOP),
#    * non-ff POST refused (REFS tip differs from .sniff base
#      → SNIFFNOFF) and `.sniff` left untouched.
#
#  Run: BIN=build-debug/bin sh sniff/test/post-ff.sh
set -eu

BIN=${BIN:-$(dirname "$0")/../../build-debug/bin}
export PATH="$BIN:$PATH"
export ASAN_OPTIONS="${ASAN_OPTIONS:-}:detect_leaks=0"

TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-SNIFFpostff}
TMP=$TMP/$TEST_ID
trap 'rm -rf "$TMP"; rmdir "${TMP%/*}" 2>/dev/null || true' EXIT INT TERM
mkdir -p "$TMP"

fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "  - $*"; }

last_row() {
    awk -F'\t' 'NF >= 2 && $2 != "" { last=$0 } END { print last }' .sniff
}

head_hex() {
    awk -F'\t' '$2=="post" || $2=="get" || $2=="patch" { last=$3 }
                END {
                    h = last
                    sub(/^[^#]*#/, "", h)
                    if (length(h) == 40 && h ~ /^[0-9a-f]+$/) print h
                }' .sniff
}

# ====================================================================
# Scenario 1 — empty POST refused.
# ====================================================================
echo "=== 1. empty POST refused ==="
WT="$TMP/wt1"
mkdir -p "$WT"; cd "$WT"
echo "hello" > a.txt
sniff post -m "v1" >/dev/null
T1=$(head_hex)
note "v1 = $T1"

before_tail=$(last_row)
if sniff post -m "noop" 2>/tmp/postff.err; then
    cat /tmp/postff.err
    fail "empty POST should have been refused"
fi
grep -q "no changes since base" /tmp/postff.err \
    || fail "expected SNIFFNOOP message; got: $(cat /tmp/postff.err)"
[ "$(last_row)" = "$before_tail" ] \
    || fail ".sniff tail row changed after refused empty POST"
note "empty POST refused; .sniff intact"

# ====================================================================
# Scenario 2 — non-ff POST refused (REFS tip on an unrelated lineage).
#
# The Phase-1 ff check uses GRAFLca, so simply rewinding REFS to an
# *ancestor* of wt.base still classifies as a fast-forward (correctly
# — that's what ff means).  Real non-ff requires REFS to point at a
# sha that's *not* in wt.base's ancestry.  Easiest in-wt simulation:
# advance the wt to v2, then poison REFS with a fake unrelated sha
# (deadbeef…); GRAFLca returns zeroed for unrelated histories so the
# check fires.
# ====================================================================
echo "=== 2. non-ff POST refused (unrelated tip) ==="
WT="$TMP/wt2"
mkdir -p "$WT"; cd "$WT"
echo "x" > x.txt
sniff post -m "v1" >/dev/null
T1=$(head_hex)

sleep 1
echo "x v2" > x.txt
sniff post -m "v2" >/dev/null
T2=$(head_hex)
[ "$T1" != "$T2" ] || fail "T2 didn't advance"
note "v2 = $T2 (wt.base)"

#  Append a `post ?#<fake-sha>` row to REFS so REFSResolve returns
#  the fake as the trunk tip.  GRAFLca(v2, deadbeef…) → 0 (unrelated
#  histories) — the ff guard sees lca != tip and refuses.
FAKE="deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
TS=$(awk 'END { print $1 }' .dogs/refs)
printf '%sz\tpost\t?#%s\n' "$TS" "$FAKE" >> .dogs/refs
note "REFS poisoned with unrelated tip $FAKE; wt.base still $T2"

before_tail=$(last_row)
sleep 1
echo "x v3" > x.txt
if sniff post -m "should fail" 2>/tmp/postff.err; then
    cat /tmp/postff.err
    fail "non-ff POST should have been refused"
fi
grep -q "non-ff" /tmp/postff.err \
    || fail "expected non-ff message; got: $(cat /tmp/postff.err)"
[ "$(last_row)" = "$before_tail" ] \
    || fail ".sniff tail row changed after refused non-ff POST"
note "non-ff POST refused; .sniff intact"

echo "=== all post-ff scenarios passed ==="
