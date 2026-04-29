#!/bin/sh
#  branchdel.sh — `sniff delete ?branch` writes a tombstone REFS row
#  (`post ?branch#0000…0`) and the safety checks refuse the unsafe
#  cases.  Resurrection works: a subsequent `sniff post ?branch`
#  re-introduces the label.
#
#  Run: BIN=build-debug/bin sh sniff/test/branchdel.sh
set -eu

BIN=${DOG_BIN_DIR:-$(dirname "$(command -v be)")}
export PATH="$BIN:$PATH"
export ASAN_OPTIONS="${ASAN_OPTIONS:-}:detect_leaks=0"

TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-SNIFFbranchdel}
TMP=$TMP/$TEST_ID
trap 'rm -rf "$TMP"; rmdir "${TMP%/*}" 2>/dev/null || true' EXIT INT TERM
mkdir -p "$TMP"

fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "  - $*"; }

ref_present() {
    keeper refs 2>/dev/null | awk -v k="$1" '
        { sub(/^[[:space:]]+/, "")
          tab = index($0, "\t")
          if (tab == 0) next
          kf = substr($0, 1, tab - 1)
          if (kf == k) { found=1 }
        }
        END { exit found ? 0 : 1 }'
}

# ====================================================================
# Scenario 1 — basic delete: label feat, drop feat, REFS no longer
# advertises it.
# ====================================================================
echo "=== 1. basic delete + REFS hides tombstone ==="
WT="$TMP/wt1"
mkdir -p "$WT"; cd "$WT"
echo "x" > x.txt
sniff post -m "base" >/dev/null
sniff post "?feat" >/dev/null
ref_present "?feat" || fail "?feat not present after post"
note "?feat present"

sniff delete "?feat" >/dev/null
if ref_present "?feat"; then
    fail "?feat still in REFS after delete (tombstone not honoured)"
fi
note "?feat hidden by tombstone"

#  Internal: the delete row IS in the refs ULOG; just not advertised.
grep -F '?feat#0000000000000000000000000000000000000000' .dogs/refs \
    >/dev/null || fail "no tombstone row in .dogs/refs"
note "tombstone row recorded in .dogs/refs"

# ====================================================================
# Scenario 2 — refuse to delete the wt's current branch.
# ====================================================================
echo "=== 2. delete ?<current> refused ==="
WT="$TMP/wt2"
mkdir -p "$WT"; cd "$WT"
echo "x" > x.txt
sniff post -m "base" >/dev/null
sniff post "?feat" >/dev/null
sniff get "?feat" >/dev/null

if sniff delete "?feat" 2>/tmp/bd.err; then
    cat /tmp/bd.err
    fail "delete ?<current-branch> should have been refused"
fi
grep -q "wt is on" /tmp/bd.err \
    || fail "expected 'wt is on' refusal; got: $(cat /tmp/bd.err)"
ref_present "?feat" \
    || fail "?feat removed despite refusal"
note "delete ?feat refused while wt is on feat"

# ====================================================================
# Scenario 3 — refuse when descendants exist.
# ====================================================================
echo "=== 3. delete ?parent with active descendant refused ==="
WT="$TMP/wt3"
mkdir -p "$WT"; cd "$WT"
echo "x" > x.txt
sniff post -m "base" >/dev/null
sniff post "?parent" >/dev/null
sniff post "?parent/child" >/dev/null

if sniff delete "?parent" 2>/tmp/bd.err; then
    cat /tmp/bd.err
    fail "delete ?parent should have been refused (descendants)"
fi
grep -q "active descendant" /tmp/bd.err \
    || fail "expected descendant refusal; got: $(cat /tmp/bd.err)"
ref_present "?parent" || fail "?parent removed despite refusal"
note "delete ?parent refused; tombstone descendants first"

#  Tombstone the descendant; now ?parent should be deletable.
sniff delete "?parent/child" >/dev/null
sniff delete "?parent" >/dev/null
if ref_present "?parent"; then
    fail "?parent still present after descendant cleared"
fi
note "?parent deletable once descendant tombstoned"

# ====================================================================
# Scenario 4 — resurrection: post the deleted branch again.
# ====================================================================
echo "=== 4. resurrection via post ==="
WT="$TMP/wt4"
mkdir -p "$WT"; cd "$WT"
echo "x" > x.txt
sniff post -m "base" >/dev/null
sniff post "?feat" >/dev/null
sniff delete "?feat" >/dev/null
ref_present "?feat" && fail "?feat still present after delete"

sniff post "?feat" >/dev/null
ref_present "?feat" \
    || fail "?feat not resurrected by subsequent post"
note "post ?feat after delete resurrects the branch"

echo "=== all branchdel scenarios passed ==="
