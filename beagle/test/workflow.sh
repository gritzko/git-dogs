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

TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-BEworkflow}
TMP=$TMP/$TEST_ID
mkdir -p "$TMP"; echo "Running in $PWD"
trap 'rm -rf "$TMP"; rmdir "${TMP%/*}" 2>/dev/null || true' EXIT INT TERM

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
# Scenario 3: be put a; be put b; be post — explicit rows in ULOG.
#
# An untracked non-gitignored sibling (`stray.txt`) sits in the wt
# the entire time and must NOT end up in either put row's URI nor
# the resulting commit's tree.  Selective mode (any put rows in
# scope) is supposed to ignore untracked-without-put paths.
# ------------------------------------------------------------------
echo "=== 3. be put a; be put b; be post (untracked stray must stay out) ==="
D3="$TMP/r3"; mkdir -p "$D3"; cd "$D3"
echo alpha > a.txt
echo bravo > b.txt
echo stray > stray.txt                   # untracked, never put-ed

"$BE" put a.txt >/dev/null
awk -F'\t' '$2 == "put" && $3 == "a.txt"' .sniff | grep -q . \
    || fail "no \`put a.txt\` row in ULOG"
awk -F'\t' '$2 == "put" && $3 == "stray.txt"' .sniff | grep -q . \
    && fail "stray.txt should not be in any put row"
"$BE" put b.txt >/dev/null
awk -F'\t' '$2 == "put" && $3 == "b.txt"' .sniff | grep -q . \
    || fail "no \`put b.txt\` row in ULOG"
awk -F'\t' '$2 == "put" && $3 == "stray.txt"' .sniff | grep -q . \
    && fail "stray.txt should not be in any put row"
note "ULOG records two put rows; stray.txt absent from both"

# A second untracked file appears AFTER the put rows are written —
# this is the timing the user-reported leak hit.  It must also stay
# out of the commit's tree.
echo late > late.txt
mkdir -p side/inner
echo nested > side/inner/n.txt

"$BE" post a plus b >/dev/null
C3=$(head_hex)
note "HEAD=$C3"

# Verify: fresh worktree + be get restores both files; stray.txt and
# late.txt + side/ were never committed.
D3b="$TMP/r3b"; mkdir -p "$D3b"; cd "$D3b"
cp -r "$D3/.dogs" .
"$BE" get "$C3" >/dev/null
want_file a.txt "alpha"
want_file b.txt "bravo"
want_missing stray.txt
want_missing late.txt
want_missing side/inner/n.txt
want_missing side
note "both put-staged files present; pre-put + post-put untracked all absent"

# ------------------------------------------------------------------
# Scenario 4: implicit-all-dirty via bare post (no put/delete rows)
# ------------------------------------------------------------------
echo "=== 4. modify + bare be post (implicit all-dirty) ==="
cd "$D3b"
usleep 10000                          # force distinct mtime
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

usleep 10000
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

# ------------------------------------------------------------------
# Scenario 11: bare `be put` is tracked-only — repro for the
# untracked-leak bug.
#
#   Baseline carries `lib/foo.c`.  Modify foo.c and add an untracked
#   sibling subtree `side/inner/n.txt`.  Bare `be put` must walk the
#   baseline tree (tracked-only) and emit a row for foo.c only —
#   never for any path under `side/`.  POST then commits foo.c only;
#   side/ stays out of the tree.
#
#   The earlier bug: bare put walked the wt via stamp-set membership
#   (any mtime ∉ stamp-set), which silently picked up untracked
#   subtrees and committed them under "selective mode".  See
#   sniff/PUT.c §"Bare-walk callback (baseline-tree visitor)".
# ------------------------------------------------------------------
echo "=== 11. bare be put stages tracked-only (no untracked leak) ==="
D11="$TMP/r11"; mkdir -p "$D11/lib"; cd "$D11"
echo v1 > lib/foo.c
"$BE" post seed lib >/dev/null
C11a=$(head_hex)
note "baseline HEAD=$C11a"

usleep 10000
echo v2 > lib/foo.c                       # modify tracked
mkdir -p side/inner
echo nested > side/inner/n.txt            # untracked subtree
echo top    > top.txt                     # untracked top-level

"$BE" put >/dev/null                      # bare put — tracked-only
awk -F'\t' '$2 == "put" && $3 == "lib/foo.c"' .sniff | grep -q . \
    || fail "bare put did not stage lib/foo.c"
awk -F'\t' '$2 == "put" && $3 ~ /^side\//' .sniff | grep -q . \
    && fail "bare put leaked an untracked side/ path into the ULOG"
awk -F'\t' '$2 == "put" && $3 == "top.txt"' .sniff | grep -q . \
    && fail "bare put leaked untracked top.txt into the ULOG"
note "bare put staged lib/foo.c only; untracked side/ + top.txt absent from ULOG"

"$BE" post tracked-only modify >/dev/null
C11b=$(head_hex)
[ "$C11b" != "$C11a" ] || fail "HEAD unchanged after bare-put + post"
note "updated HEAD=$C11b"

D11c="$TMP/r11c"; mkdir -p "$D11c"; cd "$D11c"
cp -r "$D11/.dogs" .
"$BE" get "$C11b" >/dev/null
want_file    lib/foo.c        "v2"
want_missing side
want_missing side/inner/n.txt
want_missing top.txt
note "commit tree carries the modified tracked file; untracked subtree stayed out"

# ------------------------------------------------------------------
# Scenario 12: bare `be put` is content-driven, not stamp-set-driven.
#
#   After a successful bare put, the staged files carry put-row stamps
#   (mtime ∈ stamp-set).  But their content still differs from the
#   baseline blob — they are not "clean".  Running bare put a second
#   time without any further changes must NOT report "no changes":
#   the right answer is either re-emit (idempotent) or recognise
#   "already staged".  "no changes" is wrong because mtime is just an
#   optimization; SHA-1 vs baseline is the actual dirtiness criterion.
#
#   Repro for the user-reported bug where the fast path skipped on any
#   stamp-set hit, so put-stamped files were misclassified as baseline-
#   clean and a second bare put returned PUTNONE.
# ------------------------------------------------------------------
echo "=== 12. bare be put is content-driven (mtime is just an optimization) ==="
D12="$TMP/r12"; mkdir -p "$D12"; cd "$D12"
echo v1 > foo.c
"$BE" post seed >/dev/null
C12a=$(head_hex)
note "baseline HEAD=$C12a"

usleep 10000
echo v2 > foo.c                            # modify tracked
"$BE" put >/dev/null
awk -F'\t' '$2 == "put" && $3 == "foo.c"' .sniff | grep -q . \
    || fail "first bare put did not stage foo.c"
note "first bare put staged foo.c (now put-stamped, content != baseline)"

# Second bare put with no further wt changes.  foo.c is still dirty
# vs baseline (sha differs).  The put-stamp mtime is an optimization
# only — the operation must verify content via SHA-1 and either
# re-emit the put row or report "already staged", but NEVER claim
# "no changes" while a tracked file's content differs from baseline.
out=$("$BE" put 2>&1) || true
echo "$out" | grep -q 'no changes' && \
    fail "second bare put falsely reported 'no changes' (foo.c is still dirty vs baseline)"
note "second bare put correctly avoided false-clean refusal"

# ------------------------------------------------------------------
# Scenario 13: be post leaves untouched files alone (incl. mtime).
#
#   Two-file baseline.  Modify only `b.txt` and post.  `a.txt` was not
#   put, not deleted, content unchanged — POST has no business
#   touching it.  The current implementation re-stamps every surviving
#   file with the post ts; after the decision-list refactor, only
#   `add` rows get stamped.  This test pins down the desired end-state:
#   KEEP files retain their old mtime + content byte-for-byte.
# ------------------------------------------------------------------
echo "=== 13. be post leaves untouched files alone (mtime + bytes) ==="
D13="$TMP/r13"; mkdir -p "$D13"; cd "$D13"
echo a-v1 > a.txt
echo b-v1 > b.txt
"$BE" post seed two >/dev/null
C13a=$(head_hex)
note "baseline HEAD=$C13a"

#  %.Y is seconds.nanoseconds — captures the millisecond-resolution
#  mtime that POST writes via futimens, so a re-stamp shows up here
#  even when the post happens within the same wall-clock second.
a_mtime_before=$(stat -c %.Y a.txt)
a_bytes_before=$(cat a.txt)

usleep 10000
echo b-v2 > b.txt                          # modify only b.txt
"$BE" post b only >/dev/null
C13b=$(head_hex)
[ "$C13b" != "$C13a" ] || fail "HEAD unchanged after b.txt modify"

a_mtime_after=$(stat -c %.Y a.txt)
a_bytes_after=$(cat a.txt)

[ "$a_mtime_before" = "$a_mtime_after" ] \
    || fail "post re-stamped a.txt (mtime $a_mtime_before → $a_mtime_after); KEEP files should retain their stamp"
[ "$a_bytes_before" = "$a_bytes_after" ] \
    || fail "a.txt bytes changed across post"
note "untouched a.txt: mtime + bytes preserved across post"

# ------------------------------------------------------------------
# Scenario 14: rename keeps the file searchable by content.
#
#   spot's posting list is keyed by (trigram, path_hash).  A rename
#   produces a new (blob, path) pair — the Close-pass tree walk must
#   tokenise the blob under the new path so its trigrams gain
#   postings under the new path's hash.  Searching for a content
#   substring after the rename must find the file at its new name.
# ------------------------------------------------------------------
echo "=== 14. rename keeps content searchable at the new path ==="
D14="$TMP/r14"; mkdir -p "$D14"; cd "$D14"
printf 'int rendezvous_alpha(void) { return 42; }\n' > old_name.c
"$BE" post seed >/dev/null
mv old_name.c new_name.c
#  Sniff's PUT refuses a content-unchanged-but-renamed file, so
#  perturb the byte-stream slightly to force a fresh commit.  The
#  symbol we search for is unchanged, which is the point.
printf 'int rendezvous_alpha(void) { return 43; }\n' > new_name.c
"$BE" put new_name.c >/dev/null
"$BE" post rename >/dev/null

# spot finds the symbol; output must mention the new path.
hits=$("$BE" '#rendezvous_alpha' 2>/dev/null || true)
echo "$hits" | grep -q new_name.c \
    || fail "rename: spot did not locate rendezvous_alpha at new_name.c (got: $hits)"
note "rename: rendezvous_alpha found at new_name.c"

echo "=== all be-dispatch scenarios passed ==="
