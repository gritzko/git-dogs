#!/bin/sh
#  workflow.sh — sniff standalone get/put/post/delete integration test.
#
#  Drives the `sniff` CLI against a toy worktree with no remote.  Each
#  scenario verifies a ULOG + tree-walk commit cycle in the
#  post-migration model:
#
#    * `sniff put <path>` / `sniff delete <path>` only append rows to
#      `.sniff`; no staging pack, no tree object written yet.
#    * `sniff post -m ...` walks the baseline + wt, applies the
#      change-set rules (explicit put/delete, or implicit mtime-dirty),
#      and emits one keeper pack `commit → trees → blobs`.
#    * `sniff get <sha>` materialises the target tree and prunes
#      anything on disk that was sniff-stamped but isn't in the new
#      tree (files appear and disappear cleanly across checkouts).
#
#  Run:
#      BIN=build-debug/bin sh sniff/test/workflow.sh
#
set -eu

BIN=${BIN:-$(dirname "$0")/../../build-debug/bin}
SNIFF="$BIN/sniff"
KEEPER="$BIN/keeper"

TMP=${TMP:-$HOME/tmp}
TEST_ID=${TEST_ID:-SNIFFworkflow}
TMP=$TMP/$$/$TEST_ID
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT INT TERM

fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "  - $*"; }

want_file() {
    path=$1; want=$2
    [ -f "$path" ] || fail "$path missing"
    got=$(cat "$path")
    [ "$got" = "$want" ] || fail "$path: want [$want] got [$got]"
}

want_missing() {
    [ ! -e "$1" ] || fail "$1 should be gone"
}

#  Current worktree commit = the `#fragment` of the latest `post`
#  row (canonical `?<branch>#<curhash>` shape).  Rows are
#  `<ron60-ts>\t<verb>\t<uri>`.
head_hex() {
    awk -F'\t' '$2 == "post" { last = $3 } END {
        h = last
        sub(/^[^#]*#/, "", h)
        if (length(h) == 40 && h ~ /^[0-9a-f]+$/) print h
    }' .sniff
}

# ------------------------------------------------------------------
# Scenario 1: empty dir -> write file -> post auto-stages -> commit
# ------------------------------------------------------------------
echo "=== 1. initial post auto-stages worktree ==="
D1="$TMP/r1"
mkdir -p "$D1"; cd "$D1"
echo "hello" > README.md
"$SNIFF" post initial >/dev/null
H1=$(head_hex)
[ -n "$H1" ] || fail "HEAD unset after post"
note "HEAD=$H1"

# .sniff must be trimmed to actual content on close — FILEBook
# page-aligns on open, ULOGClose's FILETrimBook reverses it.
sz=$(wc -c < .sniff)
content_sz=$(awk 'END{print c} {c+=length($0)+1}' .sniff)
[ "$sz" = "$content_sz" ] \
    || fail ".sniff not trimmed: file=$sz content=$content_sz"
note ".sniff trimmed to $sz bytes"

# Bare `sniff post` (dry run) must NOT grow .sniff either —
# RO open path keeps the file at its existing length.
"$SNIFF" post >/dev/null
sz2=$(wc -c < .sniff)
[ "$sz2" = "$sz" ] \
    || fail "dry-run post grew .sniff: was=$sz now=$sz2"
note "dry-run post left .sniff at $sz2 bytes"

# ------------------------------------------------------------------
# Scenario 2: checkout the commit into a fresh dir, files reappear
# ------------------------------------------------------------------
echo "=== 2. get on a wiped worktree restores files ==="
rm -f README.md
"$SNIFF" get "$H1" >/dev/null
want_file README.md "hello"
note "README.md restored from $H1"

# ------------------------------------------------------------------
# Scenario 3: two PUT rows accumulate, POST commits the change-set
# ------------------------------------------------------------------
echo "=== 3. put a; put b; post ==="
D3="$TMP/r3"
mkdir -p "$D3"; cd "$D3"
echo alpha > a.txt
echo bravo > b.txt

"$SNIFF" put a.txt >/dev/null
awk -F'\t' '$2 == "put" && $3 == "a.txt"' .sniff | grep -q . \
    || fail "no `put a.txt` row in ULOG"
"$SNIFF" put b.txt >/dev/null
awk -F'\t' '$2 == "put" && $3 == "b.txt"' .sniff | grep -q . \
    || fail "no `put b.txt` row in ULOG"
note "ULOG records two put rows"

"$SNIFF" post a plus b >/dev/null
C3=$(head_hex)
[ -n "$C3" ] || fail "HEAD unset"
note "HEAD after post=$C3"

#  Checkout into a fresh dir — both files must land.
D3b="$TMP/r3b"
mkdir -p "$D3b"; cd "$D3b"
cp -r "$D3/.dogs" .
"$SNIFF" get "$C3" >/dev/null
want_file a.txt "alpha"
want_file b.txt "bravo"
note "both files present after get"

# ------------------------------------------------------------------
# Scenario 4: bare `sniff put` is a no-op; bare `sniff post` commits
# the implicit change-set (mtime ∉ stamp-set).
# ------------------------------------------------------------------
echo "=== 4. implicit all-dirty via bare post ==="
cd "$D3b"
sleep 1                                 # force a distinct mtime
echo alpha-two > a.txt                  # modify
"$SNIFF" put >/dev/null                 # no-op: no args
#  No new put/delete rows since the last post → POST falls into
#  implicit mode: every mtime-dirty file is rewritten.
"$SNIFF" post modify a >/dev/null
C4=$(head_hex)
[ "$C4" != "$C3" ] || fail "HEAD unchanged after modify+post"
note "new HEAD=$C4"

D4b="$TMP/r4b"; mkdir -p "$D4b"; cd "$D4b"
cp -r "$D3b/.dogs" .
"$SNIFF" get "$C4" >/dev/null
want_file a.txt "alpha-two"
want_file b.txt "bravo"
note "modified content on disk after get"

# ------------------------------------------------------------------
# Scenario 5: `sniff delete foo` drops only foo; POST unlinks the
# file from disk and the subsequent get confirms it's gone.
# ------------------------------------------------------------------
echo "=== 5. delete a.txt ==="
cd "$D4b"
"$SNIFF" delete a.txt >/dev/null
awk -F'\t' '$2 == "delete" && $3 == "a.txt"' .sniff | grep -q . \
    || fail "no \`delete a.txt\` row in ULOG"
"$SNIFF" post drop a >/dev/null
want_missing a.txt                      # POST must unlink
C5=$(head_hex)
note "HEAD after delete=$C5"

D5b="$TMP/r5b"; mkdir -p "$D5b"; cd "$D5b"
cp -r "$D4b/.dogs" .
"$SNIFF" get "$C5" >/dev/null
want_missing a.txt
want_file b.txt "bravo"
note "a.txt pruned, b.txt preserved"

# ------------------------------------------------------------------
# Scenario 6: bare `sniff delete` is a no-op; hand-unlinking a tracked
# file and a bare POST picks it up via the implicit rule (a missing
# tracked file is a deletion).
# ------------------------------------------------------------------
echo "=== 6. implicit delete via vanished file ==="
cd "$D5b"
"$SNIFF" get "$C3" >/dev/null           # restore two-file state
want_file a.txt "alpha"
want_file b.txt "bravo"
rm a.txt                                # vanish one without a `delete` row
"$SNIFF" delete >/dev/null              # no-op (bare); sweep happens at post
"$SNIFF" post auto delete >/dev/null
C6=$(head_hex)

D6b="$TMP/r6b"; mkdir -p "$D6b"; cd "$D6b"
cp -r "$D5b/.dogs" .
"$SNIFF" get "$C6" >/dev/null
want_missing a.txt
want_file b.txt "bravo"
note "a.txt removed by implicit-delete sweep"

# ------------------------------------------------------------------
# Scenario 7: pre-seeded `.dogs/config` supplies the commit author —
# `[user] name`/`email` end up in the commit object as
# `<name> <<email>>`, not the bland `sniff <sniff@dogs>` fallback.
# ------------------------------------------------------------------
echo "=== 7. .dogs/config drives the commit author ==="
D7="$TMP/r7"; mkdir -p "$D7/.dogs"; cd "$D7"
cat > .dogs/config <<'EOF'
[user]
name = "Test User"
email = "test@example.com"
EOF
echo hello > README.md
"$SNIFF" post config author >/dev/null
C7=$(head_hex)
[ -n "$C7" ] || fail "HEAD unset after post"
body=$("$KEEPER" get ".#$C7" 2>/dev/null)
echo "$body" | grep -q '^author Test User <test@example.com> ' \
    || fail "author line missing identity from .dogs/config (got: $(echo "$body" | grep ^author))"
echo "$body" | grep -q '^committer Test User <test@example.com> ' \
    || fail "committer line missing identity from .dogs/config"
note "commit author = Test User <test@example.com>"

echo "=== all workflow scenarios passed ==="
