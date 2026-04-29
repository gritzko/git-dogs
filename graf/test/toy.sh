#!/bin/bash
#  toy.sh — end-to-end smoke test for graf on a tiny throwaway repo.
#
#  Exercises graf's full public surface against a 3-commit repo:
#    - `graf diff`   : token-level diff of two files on disk
#    - `graf merge`  : 3-way merge of base/ours/theirs
#    - streaming ingest (dog/DOG.md §8):
#        `be post` drives sniff→spot→graf.  The `graf get` step pulls
#        every keeper object through `GRAFUpdate(obj_type, blob, path)`
#        (COMMIT → TREE → BLOB → GRAFDagFinish).  In `be post` that
#        step is backgrounded, so we follow the three posts with an
#        explicit synchronous `graf index` to converge the LSM.
#    - `graf status` : run/entry counts on the LSM
#    - `graf blame`  : walks PATH_VER entries, pulls blobs by hashlet,
#                      builds a weave, emits annotated lines
#
#  No git CLI is ever invoked past `git init` (which sniff needs as a
#  working-dir marker).  Keeper is the single source of object truth.
#
#  Run:     BIN=build-debug/bin bash graf/test/toy.sh
#  CTest:   registered by graf/test/CMakeLists.txt (no env needed).
#
set -eu

BIN=${DOG_BIN_DIR:-$(dirname "$(command -v be)")}
BE="$BIN/be"
GRAF="$BIN/graf"

#  ASan-built binaries leak on some startup paths unrelated to graf;
#  suppress so the test reflects functional behavior only.
export ASAN_OPTIONS="${ASAN_OPTIONS:-}:detect_leaks=0"

for tool in "$BE" "$GRAF"; do
    [ -x "$tool" ] || { echo "FAIL: $tool not executable"; exit 1; }
done

TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-GRAFtoy}
TMP=$TMP/$TEST_ID
mkdir -p "$TMP"
trap 'rm -rf "$TMP"; rmdir "${TMP%/*}" 2>/dev/null || true' EXIT INT TERM

fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "  - $*"; }

# ------------------------------------------------------------------
#  1.  Build a 3-commit history via `be post`.
# ------------------------------------------------------------------
echo "=== 1. seed history via be post ==="

R="$TMP/repo"; mkdir -p "$R"; cd "$R"
git init --quiet -b main .
git config user.email t@t
git config user.name  t

#  Keep each version small and distinctive so blame output is easy
#  to reason about.  Sniff writes a pack to keeper on every post.
#
#  NOTE: sniff's change detection is mtime-based, so three writes in
#  the same second can coalesce into one indexed state.  Bump the
#  mtime explicitly with `touch -d` to simulate commits happening at
#  distinct moments without a real 1-second sleep between them.
for V in 1 2 3; do
    cat > "$TMP/v${V}.c" <<EOF
int f(int x) {
    return x + ${V};
}
int h${V}(int y) { return y * ${V}; }
EOF
    cp "$TMP/v${V}.c" f.c
    touch -d "2026-04-20 12:0${V}:00" f.c
    "$BE" post -m "v${V}" "?tags/v0.0.${V}" >/dev/null 2>&1
    note "v0.0.${V} committed"
done

# ------------------------------------------------------------------
#  2.  Converge the index.  `be post` backgrounds graf, so the LSM
#      the last post wrote may still be stale at this point — an
#      explicit `graf index` pulls every keeper object through the
#      DOG.md §8 streaming contract and waits for the write.
# ------------------------------------------------------------------
echo "=== 2. graf index (force synchronous ingest) ==="

"$GRAF" index >/dev/null 2>&1 \
    || fail "index: command failed"

SOUT=$("$GRAF" status 2>&1)
echo "$SOUT" | sed 's/^/    /'
echo "$SOUT" | grep -qE '^graf: [0-9]+ index run\(s\), [0-9]+ entries$' \
    || fail "status: unexpected output shape — $SOUT"

#  After three commits the LSM must contain at least:
#    3 COMMIT_GEN + 2 COMMIT_PARENT + 3 COMMIT_TREE + 1 PATH_VER for f.c
#    (sniff also stages a handful of siblings → more PATH_VERs).
#  Be lenient on the exact count; require ≥ 9 as a sanity floor.
ENTRIES=$(echo "$SOUT" | sed -n 's/.*run(s), \([0-9]*\) entries.*/\1/p')
[ "$ENTRIES" -ge 9 ] \
    || fail "status: only ${ENTRIES} entries after 3 commits (want ≥ 9)"
note "index holds ${ENTRIES} entries across 3 commits"

# ------------------------------------------------------------------
#  2a.  Indexes on disk — both graf and spot must have persisted
#       index files under .dogs/ after three `be post`s + `graf index`.
#       The lock file alone doesn't count; require ≥1 *.idx.
# ------------------------------------------------------------------
GRAF_IDX_N=$(find "$R/.dogs/graf" -maxdepth 1 -name '*.idx' 2>/dev/null | wc -l)
[ "$GRAF_IDX_N" -ge 1 ] \
    || fail "graf: no .idx under .dogs/graf/ (found only: $(ls -A "$R/.dogs/graf" 2>/dev/null | tr '\n' ' '))"
note "graf has $GRAF_IDX_N index run(s) on disk"

SPOT_IDX_N=$(find "$R/.dogs/spot" -maxdepth 1 -name '*.idx' 2>/dev/null | wc -l)
[ "$SPOT_IDX_N" -ge 1 ] \
    || fail "spot: no .idx under .dogs/spot/ (found only: $(ls -A "$R/.dogs/spot" 2>/dev/null | tr '\n' ' '))"
note "spot has $SPOT_IDX_N index run(s) on disk"

# ------------------------------------------------------------------
#  3.  graf diff — token-level colored diff between v1 and v3.
# ------------------------------------------------------------------
echo "=== 3. graf diff v1.c v3.c ==="

OUT=$("$GRAF" diff "$TMP/v1.c" "$TMP/v3.c" 2>&1 | perl -pe 's/\e\[[0-9;]*m//g')
echo "$OUT" | sed 's/^/    /'

echo "$OUT" | grep -q 'return' || fail "diff: no 'return' in output"
echo "$OUT" | grep -q '^+'      || fail "diff: no insertion markers"
echo "$OUT" | grep -q '^-'      || fail "diff: no deletion markers"
note "diff produced additions, deletions, and shared context"

# ------------------------------------------------------------------
#  4.  graf merge — 3-way merge of divergent edits from a common base.
# ------------------------------------------------------------------
echo "=== 4. graf merge ==="

cat > "$TMP/base.c" <<'BASE'
int f(int x) {
    return x + 1;
}
BASE
cat > "$TMP/ours.c" <<'OURS'
int f(int x) {
    return x + 100;
}
OURS
cat > "$TMP/theirs.c" <<'THEIRS'
int f(int x) {
    return x + 1;
}
int g(int x) {
    return x - 1;
}
THEIRS

M=$("$GRAF" merge "$TMP/base.c" "$TMP/ours.c" "$TMP/theirs.c" 2>&1)
echo "$M" | sed 's/^/    /'

echo "$M" | grep -qF 'x + 100'    || fail "merge: lost ours' edit"
echo "$M" | grep -qF 'int g(int x)' || fail "merge: lost theirs' addition"
note "merge combined both sides' non-conflicting edits"

# ------------------------------------------------------------------
#  5.  graf blame — walks PATH_VER for f.c, pulls each version's
#      blob via keeper, builds a weave, annotates surviving tokens.
# ------------------------------------------------------------------
echo "=== 5. graf blame f.c ==="

cd "$R"
BOUT=$("$GRAF" blame f.c 2>&1 | perl -pe 's/\e\[[0-9;]*m//g')
echo "$BOUT" | sed 's/^/    /'

#  The final surviving content must be v3's (the tip).  Whatever the
#  author-column widths are, the body has to include "x + 3" and the
#  helper renamed to h3.
echo "$BOUT" | grep -qF 'x + 3' \
    || fail "blame: tip content missing — did not see 'x + 3'"
echo "$BOUT" | grep -qF 'h3' \
    || fail "blame: tip helper missing — did not see 'h3'"
#  The header row carries a commit hashlet + author + date prefix.
echo "$BOUT" | grep -qE '^[0-9a-f]{7}' \
    || fail "blame: no commit-hashlet prefix on annotated line"
note "blame emitted v3 content with commit/author/date prefix"

# ------------------------------------------------------------------
#  Done.
# ------------------------------------------------------------------
echo
echo "=== graf toy: OK ==="
