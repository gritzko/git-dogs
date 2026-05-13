#!/bin/sh
#  03-multi-edit-merge — exercise the WEAVE-driven content merge.
#
#  Earlier shape of this test only made one-sided edits per file
#  (parent-only or child-only), so `patch_walk` always classified
#  via tree-entry sha equality (`take theirs` / `noop`) and never
#  invoked `fetch_merge`.  That's a tree-shape test, not a merge
#  test.  This rewrite makes BOTH parent and child stacks edit
#  `lib.c` at distinct, non-overlapping regions, so the patch's
#  3-way classification at the leaf hits
#    `!o_eq_l && !t_eq_l && !o_eq_t`
#  → `fetch_merge` → graf's WEAVE engine.  The resulting bytes must
#  carry every change from both branches with NO conflict markers.
#
#  Topology (fork at T0; both stacks 2 commits):
#
#     T0 ── T1 ── T2          ←── parent / cur after step 4
#       \
#        C1 ── C2              ?child stack
#
#  Per-commit edits.  Parent edits modify EXISTING lines; child edits
#  INSERT new lines.  Insertion points are not the same spine line as
#  any of parent's modifications, so WEAVE can integrate cleanly with
#  no conflict markers.
#
#    T1 parent: edit  sub body  → `{ int r = x - y; return r; }`
#    T2 parent: edit  greet     → "Hello"
#               insert info("hi") inside main
#    C1 child : insert mul       (after sub)
#               edit   bye        → "Goodbye"
#    C2 child : insert debug_    (after info)
#
#  After `be patch ?./child` from cur=T2 the wt's lib.c must hold ALL
#  four parent + three child edits interleaved (06.lib.want.c).

. "$(dirname "$0")/../../lib/case.sh"

OUT="$SCRATCH/../out"
mkdir -p "$OUT"

# T0 baseline on parent (= trunk).
sleep 0.02; cp "$CASE/01.lib.t0.c" lib.c
"$BE" put lib.c >/dev/null
"$BE" post 't0 baseline' >/dev/null

# Fork ?child off T0 (cur stays on parent).
"$BE" put '?./child' >/dev/null

# T1 parent.
sleep 0.02; cp "$CASE/02.lib.t1.c" lib.c
"$BE" put lib.c >/dev/null
"$BE" post 't1 parent: edit sub body' >/dev/null

# T2 parent.
sleep 0.02; cp "$CASE/03.lib.t2.c" lib.c
"$BE" put lib.c >/dev/null
"$BE" post 't2 parent: greet=Hello, info call in main' >/dev/null

# Switch to child branch.
"$BE" get '?child' >/dev/null

# C1 child.
sleep 0.02; cp "$CASE/04.lib.c1.c" lib.c
"$BE" put lib.c >/dev/null
"$BE" post 'c1 child: insert mul, bye=Goodbye' >/dev/null

# C2 child.
sleep 0.02; cp "$CASE/05.lib.c2.c" lib.c
"$BE" put lib.c >/dev/null
"$BE" post 'c2 child: insert debug_' >/dev/null

# Back to parent (trunk) at T2.
"$BE" get '?..' >/dev/null

# THE TEST: 3-way merge with all three blob shas distinct →
# patch_walk must hit the merge arm and invoke WEAVE via fetch_merge.
"$BE" patch '?./child' >"$OUT/patch.out" 2>"$OUT/patch.err"

# wt must carry the integrated result; no conflict markers anywhere.
match "$CASE/06.lib.want.c" lib.c
if grep -E '^(<<<<|>>>>|\|\|\|\|)' lib.c >/dev/null 2>&1; then
    echo "FAIL: conflict markers leaked into lib.c after merge:" >&2
    cat lib.c >&2
    exit 1
fi

# Patch stats must show at least one merged path.
grep -q 'merged=[1-9]' "$OUT/patch.err" || {
    echo "FAIL: patch did not invoke a merge (merged=0) — patch_walk"  \
         "never reached the !o_eq_l && !t_eq_l && !o_eq_t arm" >&2
    cat "$OUT/patch.err" >&2
    exit 1
}
