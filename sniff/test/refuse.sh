#!/bin/sh
#  refuse.sh — coverage for the new refusal codes introduced by the
#  per-file-stamp model:
#
#    * SNIFFPUTNONE — `be put <path>` on a baseline-clean file
#    * SNIFFPUTNONE — bare `be put` with nothing dirty
#    * SNIFFDELDIRTY — `be delete <path>` on a user-edited file
#
#  CLOCKBAD is not exercised here (would need date(1) with `--set` or
#  a mock).  The other invariants are reachable from a fresh repo.
#
#  Run: BIN=build-debug/bin sh sniff/test/refuse.sh
set -eu

BIN=${BIN:-$(dirname "$(command -v be)")}
export PATH="$BIN:$PATH"
export ASAN_OPTIONS="${ASAN_OPTIONS:-}:detect_leaks=0"

TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-SNIFFrefuse}
TMP=$TMP/$TEST_ID/$$
trap 'rm -rf "$TMP"; rmdir "${TMP%/*}" 2>/dev/null || true; rmdir "${TMP%/*/*}" 2>/dev/null || true' EXIT INT TERM
mkdir -p "$TMP"

SNIFF="$BIN/sniff"

fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "  - $*"; }

#  Run a sniff command expected to fail; capture stderr and rc.  Pass
#  if rc != 0 AND stderr contains the expected substring.
expect_refuse() {
    needle=$1; shift
    out=$("$@" 2>&1) && {
        echo "FAIL: command was supposed to refuse:"
        echo "  $*"
        echo "  output: $out"
        exit 1
    }
    case "$out" in
        *"$needle"*) ;;
        *) echo "FAIL: expected '$needle' in stderr, got:"
           echo "  $out"; exit 1 ;;
    esac
}

# ====================================================================
# Setup: tiny repo with one file committed.
# ====================================================================
mkdir -p "$TMP/r/.be"
cd "$TMP/r"
echo "alpha" > a.txt
"$SNIFF" post -m "init" >/dev/null

# ====================================================================
# Scenario 1 — `be put` on a baseline-clean file is refused (PUTNONE).
# ====================================================================
echo "=== 1. put on clean baseline file ==="
expect_refuse "is unchanged" "$SNIFF" put a.txt
note "PUTNONE on clean baseline file"

# ====================================================================
# Scenario 2 — bare `be put` with nothing dirty is refused (PUTNONE).
# ====================================================================
echo "=== 2. bare put with nothing dirty ==="
expect_refuse "no changes" "$SNIFF" put
note "PUTNONE on bare put with empty wt-dirty set"

# ====================================================================
# Scenario 3 — `be delete` on a user-edited file is refused (DELDIRTY).
# ====================================================================
echo "=== 3. delete on user-edited file ==="
echo "edited" > a.txt
expect_refuse "unstamped changes" "$SNIFF" delete a.txt
[ -f a.txt ] || fail "a.txt should still exist after refused delete"
note "DELDIRTY on user-edited file; file preserved"

# ====================================================================
# Scenario 4 — `be put` (bare) after edit then `be delete` succeeds.
# ====================================================================
echo "=== 4. put-then-delete on edited file ==="
"$SNIFF" put >/dev/null  || fail "bare put should succeed when something is dirty"
"$SNIFF" delete a.txt >/dev/null \
    || fail "delete after put should succeed (file is now stamped)"
[ -f a.txt ] && fail "a.txt should be gone after delete"
note "delete succeeds after put re-stamps the file"

echo "=== sniff refuse: OK ==="
