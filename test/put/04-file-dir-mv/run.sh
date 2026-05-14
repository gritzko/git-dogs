#!/bin/sh
#  put/04-file-dir-mv — `be put` move-form: explicit `<old>#<new>` and
#  bare-put auto-pair by content sha.
#
#  Pinned behaviour (VERBS.md §PUT "Move form", sniff/AT.md "Move-form
#  put rows"):
#
#    * `be put <old>#<new>`  — perform rename(2), write one `put` row
#      with URI `<old>#<new>`.  Trailing `/` on `<new>` is treated as
#      a directory target: basename(<old>) gets appended.
#    * `be put` (bare)        — also auto-detects system `mv`: when
#      exactly one tracked path is missing and exactly one untracked
#      path has identical blob sha, emit one `put <old>#<new>` row.
#      Multi-match either way refuses PUTAMBIG without writing rows.
#    * `be put <old>#<new>` "claim" — when src is already absent and
#      dst already on disk (user ran `mv` themselves), record the row
#      without re-renaming.  Used to disambiguate PUTAMBIG manually.
#    * `be post` consumes the move row as drop-old + add-new in the
#      new tree.  Bare `be` (status) renders the pair as one `mov`
#      line — never as `mis` + `unk`.
#
#  Refusal codes:
#    PUTNOSRC   — source path nowhere (neither in wt nor on disk)
#    PUTDSTBAD  — destination already exists / dest is a dir / both
#                 sides present
#    PUTNODIR   — destination parent dir missing (no implicit mkdir -p)
#    PUTAMBIG   — bare auto-pair cannot resolve to a unique 1:1 pairing

. "$(dirname "$0")/../../lib/case.sh"

# --- 1. seed: two tracked files with distinct content -------------
echo "alpha bytes" > a.txt
echo "beta  bytes" > b.txt
mkdir sub
echo "in sub"      > sub/keep.txt
"$BE" put a.txt b.txt sub/keep.txt >/dev/null
"$BE" post 'seed'                  >/dev/null

# --- 2. explicit file -> file rename ------------------------------
"$BE" put 'a.txt#a2.txt' >/dev/null \
    || { echo "FAIL: explicit a.txt#a2.txt failed" >&2; exit 1; }
[ ! -e a.txt ] || { echo "FAIL: a.txt still on disk after rename" >&2; exit 1; }
[   -e a2.txt ] || { echo "FAIL: a2.txt missing after rename" >&2; exit 1; }
"$BE" 2>&1 | grep -qE 'mov[[:space:]]+a\.txt -> a2\.txt' \
    || { echo "FAIL: status missing 'mov a.txt -> a2.txt'" >&2;
         "$BE" 2>&1 >&2; exit 1; }

"$BE" post 'rename a' >/dev/null
[ ! -e a.txt ] || { echo "FAIL: a.txt resurrected by post" >&2; exit 1; }

# --- 3. explicit file -> dir/ keeps basename ----------------------
"$BE" put 'b.txt#sub/' >/dev/null \
    || { echo "FAIL: explicit b.txt#sub/ failed" >&2; exit 1; }
[ ! -e b.txt ]      || { echo "FAIL: b.txt still on disk" >&2; exit 1; }
[   -e sub/b.txt ]  || { echo "FAIL: sub/b.txt missing after dir rename" >&2; exit 1; }
"$BE" 2>&1 | grep -qE 'mov[[:space:]]+b\.txt -> sub/b\.txt' \
    || { echo "FAIL: status missing 'mov b.txt -> sub/b.txt'" >&2;
         "$BE" 2>&1 >&2; exit 1; }
"$BE" post 'b into sub' >/dev/null

# --- 4. bare auto-pair after system `mv` --------------------------
mv a2.txt renamed.txt
"$BE" put >/dev/null \
    || { echo "FAIL: bare auto-pair failed" >&2; exit 1; }
"$BE" 2>&1 | grep -qE 'mov[[:space:]]+a2\.txt -> renamed\.txt' \
    || { echo "FAIL: bare auto-pair did not emit mov row" >&2;
         "$BE" 2>&1 >&2; exit 1; }
"$BE" post 'auto-pair' >/dev/null

# --- 5. ambiguous bare auto-pair — refuse PUTAMBIG ----------------
echo same > x.txt
echo same > y.txt
"$BE" put x.txt y.txt >/dev/null
"$BE" post 'two same' >/dev/null
mv x.txt p.txt
mv y.txt q.txt
#  Bare put cannot pair {x,y} → {p,q} uniquely by sha.
"$BE" put 2>err && { echo "FAIL: ambiguous bare put unexpectedly succeeded" >&2;
                     cat err >&2; exit 1; }
grep -q PUTAMBIG err \
    || { echo "FAIL: expected PUTAMBIG, got:" >&2; cat err >&2; exit 1; }
#  Critically: no rows written — status still shows them as mis/unk.
"$BE" 2>&1 | grep -q 'mov[[:space:]]' && {
    echo "FAIL: PUTAMBIG path wrote a mov row" >&2;
    "$BE" 2>&1 >&2; exit 1; }

# --- 6. explicit-form "claim" disambiguates the ambiguous case ----
"$BE" put 'x.txt#p.txt' 'y.txt#q.txt' >/dev/null \
    || { echo "FAIL: explicit claim failed" >&2; exit 1; }
"$BE" 2>&1 | grep -qE 'mov[[:space:]]+x\.txt -> p\.txt' \
    || { echo "FAIL: claim did not emit mov x->p" >&2;
         "$BE" 2>&1 >&2; exit 1; }
"$BE" 2>&1 | grep -qE 'mov[[:space:]]+y\.txt -> q\.txt' \
    || { echo "FAIL: claim did not emit mov y->q" >&2;
         "$BE" 2>&1 >&2; exit 1; }
"$BE" post 'two renames' >/dev/null

# --- 7. refusal codes ---------------------------------------------
#  PUTNOSRC — neither side on disk.
"$BE" put 'nope.txt#elsewhere.txt' 2>err && {
    echo "FAIL: PUTNOSRC missing-src succeeded" >&2; exit 1; }
grep -q PUTNOSRC err \
    || { echo "FAIL: expected PUTNOSRC, got:" >&2; cat err >&2; exit 1; }

#  PUTDSTBAD — both src and dst on disk.
echo first > foo.txt
echo other > bar.txt
"$BE" put foo.txt bar.txt >/dev/null
"$BE" post 'foo+bar' >/dev/null
"$BE" put 'foo.txt#bar.txt' 2>err && {
    echo "FAIL: PUTDSTBAD both-present succeeded" >&2; exit 1; }
grep -q PUTDSTBAD err \
    || { echo "FAIL: expected PUTDSTBAD, got:" >&2; cat err >&2; exit 1; }

#  PUTNODIR — dest parent dir missing (no implicit mkdir -p).
"$BE" put 'foo.txt#nodir/whatever.txt' 2>err && {
    echo "FAIL: PUTNODIR missing-parent succeeded" >&2; exit 1; }
grep -q PUTNODIR err \
    || { echo "FAIL: expected PUTNODIR, got:" >&2; cat err >&2; exit 1; }

# --- 8. final tree sanity — moved paths landed, originals gone ----
ls renamed.txt sub/b.txt p.txt q.txt foo.txt bar.txt sub/keep.txt >/dev/null 2>&1 \
    || { echo "FAIL: expected post-move tree missing some path" >&2;
         ls -R >&2; exit 1; }
for gone in a.txt a2.txt b.txt x.txt y.txt; do
    [ ! -e "$gone" ] || {
        echo "FAIL: $gone unexpectedly survived" >&2; exit 1; }
done
