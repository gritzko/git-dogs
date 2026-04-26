#!/bin/sh
#  workflow.sh — be-frontend dispatch test.
#
#  Mirrors sniff/test/workflow.sh but drives every verb through the
#  `be` dispatcher so we also exercise the keeper/spot/graf pipeline
#  wiring (a sniff-only green doesn't catch a missing keeper push or
#  a stale spot index).  Test semantics match the new ULOG-only model:
#  put/delete only append rows, POST walks baseline + wt and applies
#  the change-set rules, GET prunes stamped files no longer in tree.
#
#      BIN=build-debug/bin sh beagle/test/workflow.sh
#
set -eu

BIN=${BIN:-$(dirname "$0")/../../build-debug/bin}
BIN=$(cd "$BIN" && pwd)
BE="$BIN/be"
export PATH="$BIN:$PATH"

TMP=${TMP:-$HOME/tmp}
TEST_ID=${TEST_ID:-BEworkflow}
TMP=$TMP/$$-$TEST_ID
mkdir -p "$TMP"; echo "Running in $PWD"
trap 'rm -rf "$TMP"' EXIT INT TERM

fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "  - $*"; }

want_file() {
    path=$1; want=$2
    [ -f "$path" ] || fail "$path missing"
    got=$(cat "$path")
    [ "$got" = "$want" ] || fail "$path: want [$want] got [$got]"
}
want_missing() { [ ! -e "$1" ] || fail "$1 should be gone"; }

#  Latest `post` row's URI carries the HEAD sha as the `#fragment`
#  (canonical `?<branch>#<curhash>` shape).
head_hex() {
    awk -F'\t' '$2 == "post" { last = $3 } END {
        h = last
        sub(/^[^#]*#/, "", h)
        if (length(h) == 40 && h ~ /^[0-9a-f]+$/) print h
    }' .sniff
}

# ------------------------------------------------------------------
# Scenario 1: be post on a fresh dir auto-stages the single file
# ------------------------------------------------------------------
echo "=== 1. be post (auto-stage) on a fresh worktree ==="
D1="$TMP/r1"; mkdir -p "$D1"; cd "$D1"
echo hello > README
"$BE" post initial >/dev/null
H1=$(head_hex)
[ -n "$H1" ] || fail "HEAD unset after be post"
note "HEAD=$H1"

# ------------------------------------------------------------------
# Scenario 2: be get rebuilds a wiped worktree
# ------------------------------------------------------------------
echo "=== 2. be get on a wiped worktree ==="
rm -f README
"$BE" get "$H1" >/dev/null
want_file README "hello"
note "README restored by be get"

# ------------------------------------------------------------------
# Scenario 3: be put a; be put b; be post — explicit rows in ULOG
# ------------------------------------------------------------------
echo "=== 3. be put a; be put b; be post ==="
D3="$TMP/r3"; mkdir -p "$D3"; cd "$D3"
echo alpha > a.txt
echo bravo > b.txt

"$BE" put a.txt >/dev/null
awk -F'\t' '$2 == "put" && $3 == "a.txt"' .sniff | grep -q . \
    || fail "no \`put a.txt\` row in ULOG"
"$BE" put b.txt >/dev/null
awk -F'\t' '$2 == "put" && $3 == "b.txt"' .sniff | grep -q . \
    || fail "no \`put b.txt\` row in ULOG"
note "ULOG records two put rows"

"$BE" post a plus b >/dev/null
C3=$(head_hex)
note "HEAD=$C3"

# Verify: fresh worktree + be get restores both files.
D3b="$TMP/r3b"; mkdir -p "$D3b"; cd "$D3b"
cp -r "$D3/.dogs" .
"$BE" get "$C3" >/dev/null
want_file a.txt "alpha"
want_file b.txt "bravo"
note "both files present after be get"

# ------------------------------------------------------------------
# Scenario 4: implicit-all-dirty via bare post (no put/delete rows)
# ------------------------------------------------------------------
echo "=== 4. modify + bare be post (implicit all-dirty) ==="
cd "$D3b"
sleep 1                               # force distinct mtime
echo alpha-v2 > a.txt
"$BE" post a v2 >/dev/null
C4=$(head_hex)
[ "$C4" != "$C3" ] || fail "HEAD unchanged after modify + post"
note "HEAD=$C4"

D4b="$TMP/r4b"; mkdir -p "$D4b"; cd "$D4b"
cp -r "$D3b/.dogs" .
"$BE" get "$C4" >/dev/null
want_file a.txt "alpha-v2"
want_file b.txt "bravo"
note "a.txt updated on disk after be get"

# ------------------------------------------------------------------
# Scenario 5: be delete <file> drops just that path (POST unlinks it)
# ------------------------------------------------------------------
echo "=== 5. be delete a.txt ==="
cd "$D4b"
"$BE" delete a.txt >/dev/null
"$BE" post drop a >/dev/null
want_missing a.txt                    # POST must unlink explicit deletes
C5=$(head_hex)

D5b="$TMP/r5b"; mkdir -p "$D5b"; cd "$D5b"
cp -r "$D4b/.dogs" .
"$BE" get "$C5" >/dev/null
want_missing a.txt
want_file b.txt "bravo"
note "a.txt removed, b.txt preserved"

# ------------------------------------------------------------------
# Scenario 6: implicit-delete via vanished tracked file
# ------------------------------------------------------------------
echo "=== 6. bare be delete (implicit sweep via missing file) ==="
cd "$D5b"
"$BE" get "$C3" >/dev/null            # restore two-file state
want_file a.txt "alpha"
want_file b.txt "bravo"
rm a.txt                              # vanish one without a `delete` row
"$BE" delete >/dev/null               # no-op (bare); sweep happens at post
"$BE" post auto delete >/dev/null
C6=$(head_hex)

D6b="$TMP/r6b"; mkdir -p "$D6b"; cd "$D6b"
cp -r "$D5b/.dogs" .
"$BE" get "$C6" >/dev/null
want_missing a.txt
want_file b.txt "bravo"
note "auto-delete took out a.txt"

# ------------------------------------------------------------------
# Scenario 7: be put dir/ — recursive stage of a nested subtree
#
#   Fresh repo, `be put lib/` must pull every file under lib/ into the
#   commit (lib/a.txt and lib/sub/b.txt), while a sibling file at the
#   root that was NOT put stays out (selective mode: only explicit
#   targets are included on the first commit).
# ------------------------------------------------------------------
echo "=== 7. be put dir/ recurses into nested subtree ==="
D7="$TMP/r7"; mkdir -p "$D7/lib/sub"; cd "$D7"
echo alpha    > lib/a.txt
echo bravo    > lib/sub/b.txt
echo untracked > top.txt                 # not put → should not appear

"$BE" put lib/ >/dev/null
"$BE" post put lib >/dev/null
C7=$(head_hex)
[ -n "$C7" ] || fail "HEAD unset after be post"
note "HEAD=$C7"

D7b="$TMP/r7b"; mkdir -p "$D7b"; cd "$D7b"
cp -r "$D7/.dogs" .
"$BE" get "$C7" >/dev/null
want_file lib/a.txt     "alpha"
want_file lib/sub/b.txt "bravo"
want_missing top.txt
note "nested subtree present, root-level non-put file absent"

# ------------------------------------------------------------------
# Scenario 8: be put new_dir/ respects the wt-root .gitignore (IGNO)
#
#   The dir-expansion pass reads a single `.gitignore` from the wt root
#   (no nested cascade). Here `*.tmp` at the root must filter `*.tmp`
#   files that `be put mk/` would otherwise include, at every depth.
# ------------------------------------------------------------------
echo "=== 8. be put new_dir/ skips wt-root .gitignore matches ==="
D8="$TMP/r8"; mkdir -p "$D8/mk/sub"; cd "$D8"
printf '*.tmp\n' > .gitignore            # wt-root — the only one read
echo keep       > mk/keep.txt
echo gone       > mk/ignored.tmp
echo deep       > mk/sub/inner.txt
echo deep-gone  > mk/sub/inner.tmp

"$BE" put mk/ >/dev/null
"$BE" post put mk with igno >/dev/null
C8=$(head_hex)
note "HEAD=$C8"

D8b="$TMP/r8b"; mkdir -p "$D8b"; cd "$D8b"
cp -r "$D8/.dogs" .
"$BE" get "$C8" >/dev/null
want_file    mk/keep.txt     "keep"
want_file    mk/sub/inner.txt "deep"
want_missing mk/ignored.tmp
want_missing mk/sub/inner.tmp
#  .gitignore lives at the wt root, not under mk/, so it isn't pulled
#  in by `be put mk/` (different prefix) — nothing to assert about it
#  here.
note "*.tmp patterns honoured at every depth under mk/"

# ------------------------------------------------------------------
# Scenario 9: be put existing_dir/ stages only tracked files
#
#   Starting from a commit that has `src/foo.c`, modify foo.c and add a
#   brand-new untracked `src/bar.c`.  `be put src/` must rewrite foo.c
#   (tracked ⇒ part of the base tree) and leave bar.c out (untracked
#   on disk ⇒ not in baseline ⇒ skipped).
# ------------------------------------------------------------------
echo "=== 9. be put existing_dir/ commits tracked files only ==="
D9="$TMP/r9"; mkdir -p "$D9/src"; cd "$D9"
echo v1 > src/foo.c
echo top > README
"$BE" put src/foo.c >/dev/null           # baseline: just src/foo.c
"$BE" put README   >/dev/null
"$BE" post baseline >/dev/null
C9a=$(head_hex)
note "baseline HEAD=$C9a"

sleep 1
echo v2 > src/foo.c                      # modify tracked
echo stray > src/bar.c                   # add untracked
"$BE" put src/ >/dev/null
"$BE" post tracked only src >/dev/null
C9b=$(head_hex)
[ "$C9b" != "$C9a" ] || fail "HEAD unchanged after modify+put dir"
note "updated HEAD=$C9b"

D9c="$TMP/r9c"; mkdir -p "$D9c"; cd "$D9c"
cp -r "$D9/.dogs" .
"$BE" get "$C9b" >/dev/null
want_file    src/foo.c "v2"
want_file    README    "top"
want_missing src/bar.c
note "modified tracked file rewritten, untracked sibling stayed out"

# ------------------------------------------------------------------
# Scenario 10: be delete dir/ drops the entire subtree
#
#   Base commit has dd/a.txt, dd/inner/b.txt, and a sibling keep.txt.
#   `be delete dd/` must drop every file under dd/ from the new commit
#   AND unlink them from disk (POST already does that for explicit
#   deletes of single paths — same contract for a dir target).
# ------------------------------------------------------------------
echo "=== 10. be delete dir/ prunes nested subtree ==="
D10="$TMP/r10"; mkdir -p "$D10/dd/inner"; cd "$D10"
echo a > dd/a.txt
echo b > dd/inner/b.txt
echo k > keep.txt
"$BE" post seed dd >/dev/null       # implicit: all three land
C10a=$(head_hex)
note "baseline HEAD=$C10a"

"$BE" delete dd/ >/dev/null
"$BE" post drop dd >/dev/null
C10b=$(head_hex)
[ "$C10b" != "$C10a" ] || fail "HEAD unchanged after delete dir"
want_missing dd/a.txt
want_missing dd/inner/b.txt
note "dd/ unlinked from worktree"

D10c="$TMP/r10c"; mkdir -p "$D10c"; cd "$D10c"
cp -r "$D10/.dogs" .
"$BE" get "$C10b" >/dev/null
want_file    keep.txt "k"
want_missing dd/a.txt
want_missing dd/inner/b.txt
note "commit tree excludes the deleted subtree"

echo "=== all be-dispatch scenarios passed ==="
