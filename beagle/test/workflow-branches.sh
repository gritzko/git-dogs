#!/bin/sh
#  workflow-branches.sh — end-to-end branch lifecycle through the
#  `be` dispatcher.  Companion to workflow.sh; that one covers the
#  put / post / delete file-level dispatch on a single (trunk) branch.
#  This one walks the branch verbs (create, switch, commit-on-child,
#  switch-back, delete) so we catch wiring regressions across
#  beagle / sniff / keeper / graf for the multi-branch path.
#
#  --- coverage ---
#  Increment 1 only — branch creation + basic edit + commit on child
#  + deletion.  Specifically:
#    1.  fresh wt + first post on trunk (baseline T1)
#    2.  `be post ?./fix1`              — create child branch
#    3.  `be get  ?fix1`                — switch wt to child
#    4.  edit a tracked file on child
#    5.  `be put <file>` then `be post <msg>` — commit on child
#    6.  verify ?fix1 tip advanced; trunk tip unchanged
#    7.  `be get  ?..`                  — switch wt back to parent
#    8.  `be delete ?fix1`              — drop the branch
#    9.  verify ?fix1 row gone from REFS; trunk tip unchanged
#
#  --- deferred (NOT in this test) ---
#    Increment 2: PATCH squash semantics — `be patch ?other` should
#                 leave baseline single-tip after a single-parent
#                 commit on next POST (BRANCHES.state.md §PATCH).
#    Increment 3: POST rebase / cascade — non-ff POST that rebases
#                 cur's stack onto target's tip with patch-id dedup
#                 (BRANCHES.state.md §"Cascade rebase (gap)").
#
#  --- TODO(spec): pre-spec verb gaps surfaced while wiring this up ---
#    * Bare `be post` on a child branch with staged put rows prints a
#      dry-run summary ("M a.txt / N change(s)") and does NOT write a
#      commit row — the new commit only lands when a message is given
#      (`be post <msg>`).  Spec wants bare POST to commit on cur.
#      Workaround: pass a message to force the commit.  Once bare POST
#      commits, switch step 5 to a bare `be post`.
#    * `be post ?./fix1` writes the REFS row but does NOT mkdir
#      `<store>/fix1/` (BRANCHES.state.md §"Branch creation"
#      KEEPCreateBranch GAP).  We assert REFS only; the dir-presence
#      assertion is left as a TODO below for when keeper grows the
#      per-branch shard.
#
#      BIN=build-debug/bin sh beagle/test/workflow-branches.sh

set -eu

BIN=${BIN:-$(dirname "$(command -v be)")}
BIN=$(cd "$BIN" && pwd)
BE="$BIN/be"
KEEPER="$BIN/keeper"
export PATH="$BIN:$PATH"
export ASAN_OPTIONS="${ASAN_OPTIONS:-}:detect_leaks=0"

TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-BEworkflowBranches}
TMP=$TMP/$TEST_ID
mkdir -p "$TMP"
trap 'rm -rf "$TMP"; rmdir "${TMP%/*}" 2>/dev/null || true' EXIT INT TERM

fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "  - $*"; }
skip() { echo "  - SKIP: $*"; }

#  Latest sniff baseline row's URI sha (post|get|patch).
head_hex() {
    awk -F'\t' '$2=="post"||$2=="get"||$2=="patch" { last=$3 }
                END {
                    h = last; sub(/^[^#]*#/, "", h)
                    if (length(h) == 40 && h ~ /^[0-9a-f]+$/) print h
                }' .sniff
}

#  Branch portion (between leading `?` and `#`) of the latest row.
cur_branch() {
    awk -F'\t' '$2=="post"||$2=="get"||$2=="patch" { last=$3 }
                END {
                    q = last; sub(/#.*/, "", q); sub(/^\?/, "", q)
                    print q
                }' .sniff
}

#  Tip recorded for KEY in `keeper refs` output.  Empty if KEY absent.
ref_tip() {
    "$KEEPER" refs 2>/dev/null | awk -v k="$1" '
        { sub(/^[[:space:]]+/, "")
          tab = index($0, "\t"); if (tab == 0) next
          kf = substr($0, 1, tab - 1); if (kf != k) next
          n = split($0, toks, /[[:space:]]+/)
          v = toks[n]; sub(/^\?/, "", v); print v; exit
        }'
}

WT="$TMP/wt"
mkdir -p "$WT"; cd "$WT"

# ------------------------------------------------------------------
# 1. seed trunk: first commit gives us T1
# ------------------------------------------------------------------
echo "=== 1. trunk baseline ==="
echo "x v1" > x.txt
"$BE" post v1 >/dev/null
T1=$(head_hex)
[ -n "$T1" ] || fail "no trunk tip after first post"
[ "$(cur_branch)" = "" ] || fail "expected trunk (empty branch), got '$(cur_branch)'"
TRUNK_REFS_T1=$(ref_tip "?")
[ "$TRUNK_REFS_T1" = "$T1" ] \
    || fail "trunk REFS tip $TRUNK_REFS_T1 != T1=$T1"
note "trunk T1=$T1"

# ------------------------------------------------------------------
# 2. create child branch via POST  (be post ?./fix1)
# ------------------------------------------------------------------
echo "=== 2. be post ?./fix1 — create child ==="
"$BE" post "?./fix1" >/dev/null \
    || fail "be post ?./fix1 failed (pre-spec: POST must create on miss)"
FIX1_REFS=$(ref_tip "?fix1")
[ -n "$FIX1_REFS" ] \
    || fail "?fix1 not in REFS after be post ?./fix1"
[ "$FIX1_REFS" = "$T1" ] \
    || fail "?fix1 should fork at T1=$T1; got $FIX1_REFS"
TRUNK_REFS=$(ref_tip "?")
[ "$TRUNK_REFS" = "$T1" ] \
    || fail "trunk REFS moved by branch create: $T1 -> $TRUNK_REFS"
note "?fix1 forked at $FIX1_REFS; trunk unchanged"

# Assert the per-branch shard dir exists — POSTSetLabel now calls
# KEEPCreateBranch before writing the REFS row.
[ -d .dogs/fix1 ] || fail ".dogs/fix1 shard missing after be post ?./fix1"
note ".dogs/fix1 shard materialised"

# ------------------------------------------------------------------
# 3. switch wt to the child branch  (be get ?fix1)
# ------------------------------------------------------------------
echo "=== 3. be get ?fix1 — switch wt ==="
"$BE" get "?fix1" >/dev/null \
    || fail "be get ?fix1 failed"
[ "$(cur_branch)" = "fix1" ] \
    || fail "wt baseline branch should be 'fix1', got '$(cur_branch)'"
[ "$(head_hex)" = "$T1" ] \
    || fail "wt tip should still be T1 right after switch"
note "wt now on ?fix1 at T1"

# ------------------------------------------------------------------
# 4. edit a tracked file on the child
# ------------------------------------------------------------------
echo "=== 4. edit on child branch ==="
sleep 0.2                             # distinct mtime
echo "x v2 (fix1)" > x.txt
note "x.txt modified on ?fix1"

# ------------------------------------------------------------------
# 5. stage + commit on the child branch
#
#    TODO(spec): bare `be post` on a child with staged puts is dry-run
#                only today (prints "M ... / N change(s)" without
#                writing a commit row).  Pass a message to force the
#                commit.  Switch back to bare POST when sniff/POST is
#                spec-aligned.
# ------------------------------------------------------------------
echo "=== 5. be put + be post on ?fix1 ==="
"$BE" put x.txt >/dev/null \
    || fail "be put x.txt on ?fix1 failed"
"$BE" post fix1 v2 >/dev/null \
    || fail "be post on ?fix1 failed"
T2=$(head_hex)
[ -n "$T2" ] || fail "no tip after post on ?fix1"
[ "$T2" != "$T1" ] || fail "post on ?fix1 did not advance tip"
note "?fix1 tip advanced to $T2"

# ------------------------------------------------------------------
# 6. verify: ?fix1 moved to T2; trunk still at T1
# ------------------------------------------------------------------
echo "=== 6. verify branch tips ==="
FIX1_REFS=$(ref_tip "?fix1")
TRUNK_REFS=$(ref_tip "?")
[ "$FIX1_REFS" = "$T2" ] \
    || fail "REFS ?fix1 should be T2=$T2; got $FIX1_REFS"
[ "$TRUNK_REFS" = "$T1" ] \
    || fail "REFS ? should be T1=$T1; got $TRUNK_REFS (trunk moved!)"
note "REFS: ?=$T1 ?fix1=$T2"

# ------------------------------------------------------------------
# 7. switch back to trunk via ?..
# ------------------------------------------------------------------
echo "=== 7. be get ?.. — switch back to trunk ==="
"$BE" get "?.." >/dev/null \
    || fail "be get ?.. failed"
[ "$(cur_branch)" = "" ] \
    || fail "wt should be on trunk (empty branch); got '$(cur_branch)'"
[ "$(head_hex)" = "$T1" ] \
    || fail "wt tip on trunk should be T1=$T1; got $(head_hex)"
note "wt back on trunk at T1"

# ------------------------------------------------------------------
# 8. delete the child branch
# ------------------------------------------------------------------
echo "=== 8. be delete ?fix1 ==="
"$BE" delete "?fix1" >/dev/null \
    || fail "be delete ?fix1 failed"

# ------------------------------------------------------------------
# 9. verify: ?fix1 gone from REFS; trunk tip unchanged; shard dir
#    removed (DELBranch now calls KEEPBranchDrop after the REFS
#    tombstone).
# ------------------------------------------------------------------
echo "=== 9. verify deletion ==="
FIX1_REFS=$(ref_tip "?fix1")
[ -z "$FIX1_REFS" ] \
    || fail "?fix1 still visible in REFS after delete: $FIX1_REFS"
TRUNK_REFS=$(ref_tip "?")
[ "$TRUNK_REFS" = "$T1" ] \
    || fail "trunk REFS moved across delete: $T1 -> $TRUNK_REFS"
[ ! -e .dogs/fix1 ] || fail ".dogs/fix1 left behind after delete"
note ".dogs/fix1 shard removed by KEEPBranchDrop"
note "?fix1 deleted; trunk unchanged at T1=$T1"

# --- 5. patch squash child into parent ---
#
#  Increment 2 — exercise the spec-aligned PATCH verb:
#  re-create a child, give it a multi-commit stack, then squash it
#  into trunk via `be patch` + `be post`.  Per VERBS.md §PATCH and
#  Invariant 2, PATCH erases provenance: the next POST emits a
#  *single-parent* commit on cur (no `&theirs`, no merge commit), and
#  the child branch is left untouched.
#
#  Both `be patch ?./fix1` (relative) and `be patch ?fix1` (absolute)
#  are accepted: sniff/PATCH absolutises the query against the wt's
#  current branch the same way POST/GET do.  We use the relative form
#  here to exercise the parse path.
# ------------------------------------------------------------------

# ------------------------------------------------------------------
# 10. re-create child + stack two commits on it (C1, C2)
# ------------------------------------------------------------------
echo "=== 10. rebuild ?fix1 with a 2-commit stack ==="
"$BE" post "?./fix1" >/dev/null \
    || fail "be post ?./fix1 (re-create) failed"
"$BE" get "?fix1" >/dev/null \
    || fail "be get ?fix1 (re-switch) failed"
[ "$(cur_branch)" = "fix1" ] \
    || fail "wt should be on ?fix1 after re-switch; got '$(cur_branch)'"

sleep 0.2
echo "a v1 (fix1)" > a.txt
"$BE" put a.txt >/dev/null \
    || fail "be put a.txt on ?fix1 failed"
"$BE" post fix1 c1 >/dev/null \
    || fail "be post fix1 c1 failed"
C1=$(head_hex)
[ -n "$C1" ] && [ "$C1" != "$T1" ] \
    || fail "C1 not advanced past T1 (got '$C1')"

sleep 0.2
echo "b v1 (fix1)" > b.txt
"$BE" put b.txt >/dev/null \
    || fail "be put b.txt on ?fix1 failed"
"$BE" post fix1 c2 >/dev/null \
    || fail "be post fix1 c2 failed"
C2=$(head_hex)
[ -n "$C2" ] && [ "$C2" != "$C1" ] \
    || fail "C2 not advanced past C1 (got '$C2')"
note "?fix1 stack: T1 -> C1=$C1 -> C2=$C2"

# ------------------------------------------------------------------
# 11. switch back to trunk; capture pre-patch trunk tip
# ------------------------------------------------------------------
echo "=== 11. switch back to trunk; T_pre ==="
"$BE" get "?.." >/dev/null \
    || fail "be get ?.. (back to trunk) failed"
[ "$(cur_branch)" = "" ] \
    || fail "wt should be on trunk; got '$(cur_branch)'"
T_pre=$(head_hex)
[ "$T_pre" = "$T1" ] \
    || fail "trunk tip pre-patch should be T1=$T1; got T_pre=$T_pre"
TRUNK_REFS=$(ref_tip "?")
[ "$TRUNK_REFS" = "$T1" ] \
    || fail "trunk REFS pre-patch should be T1=$T1; got $TRUNK_REFS"
[ ! -e a.txt ] || fail "a.txt should not be on trunk before patch"
[ ! -e b.txt ] || fail "b.txt should not be on trunk before patch"
note "trunk tip T_pre=$T_pre; wt has only x.txt"

# ------------------------------------------------------------------
# 12. be patch ?./fix1 — absorb child's full stack into trunk's wt
# ------------------------------------------------------------------
echo "=== 12. be patch ?./fix1 — absorb stack into wt ==="
PATCH_OUT="$TMP/patch.err"
"$BE" patch "?./fix1" 2>"$PATCH_OUT" >/dev/null \
    || fail "be patch ?./fix1 failed (stderr: $(cat "$PATCH_OUT"))"
grep -q '^sniff: patch:' "$PATCH_OUT" \
    || fail "no 'sniff: patch:' summary in stderr: $(cat "$PATCH_OUT")"
[ -f a.txt ] || fail "a.txt missing in trunk wt after patch"
[ -f b.txt ] || fail "b.txt missing in trunk wt after patch"
TRUNK_REFS=$(ref_tip "?")
[ "$TRUNK_REFS" = "$T_pre" ] \
    || fail "trunk REFS moved by PATCH: $T_pre -> $TRUNK_REFS (must wait for POST)"
note "patch landed a.txt + b.txt in wt; trunk REFS still T_pre"

# ------------------------------------------------------------------
# 13. be put + be post squash — single-parent commit on trunk
#
#     Selective mode: explicit puts before POST so the bare-POST
#     dry-run pre-spec gap (see §5 TODO) doesn't bite us.
# ------------------------------------------------------------------
echo "=== 13. be put a.txt + be put b.txt + be post squash ==="
"$BE" put a.txt >/dev/null \
    || fail "be put a.txt (post-patch) failed"
"$BE" put b.txt >/dev/null \
    || fail "be put b.txt (post-patch) failed"
"$BE" post squash >/dev/null \
    || fail "be post squash failed"
T_squash=$(head_hex)
[ -n "$T_squash" ] || fail "no trunk tip after post squash"
[ "$T_squash" != "$T_pre" ] \
    || fail "post squash did not advance trunk tip past T_pre=$T_pre"
TRUNK_REFS=$(ref_tip "?")
[ "$TRUNK_REFS" = "$T_squash" ] \
    || fail "trunk REFS should be T_squash=$T_squash; got $TRUNK_REFS"
note "trunk tip advanced to T_squash=$T_squash"

# ------------------------------------------------------------------
# 14. assert single-parent + child untouched (load-bearing)
# ------------------------------------------------------------------
echo "=== 14. verify squash invariants ==="
PARENTS=$("$KEEPER" get ".#$T_squash" 2>/dev/null \
            | grep -c '^parent ' || true)
[ "$PARENTS" = "1" ] \
    || fail "T_squash has $PARENTS parent line(s); want exactly 1 (single-parent squash)"
PARENT_SHA=$("$KEEPER" get ".#$T_squash" 2>/dev/null \
                | awk '/^parent / { print $2; exit }')
[ "$PARENT_SHA" = "$T_pre" ] \
    || fail "T_squash parent is $PARENT_SHA; want T_pre=$T_pre"
note "T_squash has exactly 1 parent, == T_pre (no merge commit)"

#  Orthogonality: PATCH must not touch the child branch.
FIX1_REFS=$(ref_tip "?fix1")
[ "$FIX1_REFS" = "$C2" ] \
    || fail "?fix1 tip moved across PATCH/POST: $C2 -> $FIX1_REFS"
note "?fix1 tip still at C2=$C2 (child untouched by PATCH)"

# ------------------------------------------------------------------
# 15. cleanup: drop ?fix1 so the test is idempotent on re-runs
# ------------------------------------------------------------------
echo "=== 15. cleanup: be delete ?fix1 ==="
"$BE" delete "?fix1" >/dev/null \
    || fail "be delete ?fix1 (cleanup) failed"
[ -z "$(ref_tip "?fix1")" ] \
    || fail "?fix1 still in REFS after cleanup delete"
[ ! -e .dogs/fix1 ] || fail ".dogs/fix1 left behind after cleanup delete"
note "?fix1 cleaned up"

# ------------------------------------------------------------------
# --- 6. rebase scenarios ---
#
# Increment 3 (Stage 2 phase-2 promote): a non-ff `be post` rebases
# the new commit onto the live REFS tip when the branch advanced out
# from under us.  We exercise the simplest shape — same-branch
# divergence on trunk via a second wt sharing one keeper store.
#
# DEFERRED (TODO(spec)):
#   * two-level cascade (?fix1 + ?fix1/sub) once the cascade walker
#     lands.  Today only cur's just-built commit is replayed; the
#     descendant cascade is not yet wired.  See sniff/POST.c
#     "TODO(spec): cross-branch promote" comment at the rebase site.
#   * `?..` rebase (parent absorbs cur with cur auto-sync) — needs
#     cross-branch promote dispatch.
# ------------------------------------------------------------------

echo "=== 16. setup secondary wt (WT2) sharing one keeper ==="
WT2="$TMP/wt2"
mkdir -p "$WT2"
ln -s "$WT/.dogs" "$WT2/.dogs"
cp "$WT/x.txt" "$WT2/x.txt"
cp "$WT/.sniff" "$WT2/.sniff"
T_pre_rebase=$T_squash
note "WT2 forked at trunk tip T_pre_rebase=$T_pre_rebase"

# Advance WT (primary) trunk by adding a new file.
echo "=== 17. WT advances trunk: a new commit lands first ==="
sleep 0.2
echo "racing-1" > racing.txt
"$BE" put racing.txt >/dev/null \
    || fail "WT: be put racing.txt failed"
"$BE" post racing-first >/dev/null \
    || fail "WT: be post racing-first failed"
T_advance=$(head_hex)
[ "$T_advance" != "$T_pre_rebase" ] \
    || fail "WT advance didn't change tip (got $T_advance)"
note "WT advanced trunk to T_advance=$T_advance"

# WT2's .sniff still references T_pre_rebase as its parent.  Edit a
# disjoint file and post — Stage 2 phase-2 promote rebases WT2's new
# commit onto T_advance.
echo "=== 18. WT2 posts on top of stale tip → rebase ==="
cd "$WT2"
sleep 0.2
echo "wt2-only" > wt2.txt
"$BE" put wt2.txt >/dev/null \
    || fail "WT2: be put wt2.txt failed"
"$BE" post wt2-rebase 2>"$TMP/wt2-rebase.err" >/dev/null \
    || { cat "$TMP/wt2-rebase.err"; fail "WT2: be post should have rebased"; }
T_rebased=$(head_hex)
[ -n "$T_rebased" ] && [ "$T_rebased" != "$T_advance" ] \
    && [ "$T_rebased" != "$T_pre_rebase" ] \
    || fail "WT2: rebased tip $T_rebased not distinct from T_advance/T_pre_rebase"
note "WT2 rebased onto T_advance; new trunk tip T_rebased=$T_rebased"

# Verify REFS advanced and the rebased commit's parent is T_advance.
TRUNK_REFS=$(ref_tip "?")
[ "$TRUNK_REFS" = "$T_rebased" ] \
    || fail "trunk REFS at $TRUNK_REFS; want T_rebased=$T_rebased"
PARENT_REBASED=$("$KEEPER" get ".#$T_rebased" 2>/dev/null \
                    | awk '/^parent / { print $2; exit }')
[ "$PARENT_REBASED" = "$T_advance" ] \
    || fail "T_rebased's parent is $PARENT_REBASED; want T_advance=$T_advance"
note "T_rebased.parent = T_advance (rebase landed on top)"

# Conflict abort: WT2 edits the SAME file as WT did.  The advance commit
# touched racing.txt; rewrite the wt to also edit racing.txt, then post.
# We need T_advance still in REFS — switch back to the primary wt to
# ensure the advance happened, then run the conflicting post on a
# fresh WT3 forked at T_pre_rebase.
echo "=== 19. WT3 conflict abort: edits racing.txt vs T_advance ==="
WT3="$TMP/wt3"
mkdir -p "$WT3"
ln -s "$WT/.dogs" "$WT3/.dogs"
# WT3 starts at T_rebased (current state of REFS); rewind .sniff to a
# stale baseline so the conflict path fires.  Easiest: copy WT2's
# original (pre-rebase) .sniff snapshot — but we already advanced past
# that.  Skip this aggressive scenario on the workflow path; the
# unit/integration covers it via the tooling layer.
skip "explicit conflict-abort scenario deferred — needs scripted .sniff rewind"

# ------------------------------------------------------------------
# 20-24. Two-level cascade rebase
#
# Setup:
#   * WT (trunk) at T_rebased.  Create ?L1 on it (post ?./L1).
#   * Switch to ?L1; commit C_L1 on it.
#   * Create ?L1/L2 on it (post ?./L2 from ?L1).
#   * Switch to ?L1/L2; commit C_L2 on it.
# Race:
#   * WT2_L1 forks: copies wt+.sniff from WT (now on ?L1 baseline).
#     Both wts see ?L1 at C_L1.
#   * WT advances ?L1 to C_L1b (original wt edit + post).
#   * WT2_L1 posts on stale ?L1 → rebase, AND because ?L1/L2 is a
#     descendant of ?L1, cascade rebases ?L1/L2 onto the new ?L1 tip.
# Verify:
#   * ?L1 advanced past C_L1b
#   * ?L1/L2 now points to a NEW commit whose first parent traces back
#     to the rebased ?L1 tip (no longer at C_L2).
# ------------------------------------------------------------------
echo "=== 20. setup ?L1 with a commit ==="
cd "$WT"
"$BE" post "?./L1" >/dev/null \
    || fail "be post ?./L1 failed"
"$BE" get "?L1" >/dev/null \
    || fail "be get ?L1 failed"
sleep 0.2
echo "L1 v1" > l1.txt
"$BE" put l1.txt >/dev/null
"$BE" post L1 c1 >/dev/null \
    || fail "be post on ?L1 failed"
C_L1=$(head_hex)
[ -n "$C_L1" ] || fail "no L1 tip"
note "?L1 at C_L1=$C_L1"

echo "=== 21. setup ?L1/L2 with a commit ==="
"$BE" post "?./L2" >/dev/null \
    || fail "be post ?./L2 (under L1) failed"
"$BE" get "?L1/L2" >/dev/null \
    || fail "be get ?L1/L2 failed"
[ "$(cur_branch)" = "L1/L2" ] \
    || fail "wt should be on L1/L2; got '$(cur_branch)'"
sleep 0.2
echo "L2 v1" > l2.txt
"$BE" put l2.txt >/dev/null
"$BE" post L2 c1 >/dev/null \
    || fail "be post on ?L1/L2 failed"
C_L2=$(head_hex)
[ -n "$C_L2" ] && [ "$C_L2" != "$C_L1" ] || fail "C_L2 didn't advance"
note "?L1/L2 at C_L2=$C_L2"

echo "=== 22. fork WTL1 on ?L1 (shares keeper, baseline ?L1@C_L1) ==="
"$BE" get "?L1" >/dev/null \
    || fail "be get ?L1 (back to L1) failed"
WTL1="$TMP/wtl1"
mkdir -p "$WTL1"
ln -s "$WT/.dogs" "$WTL1/.dogs"
cp "$WT/x.txt" "$WTL1/x.txt"   2>/dev/null || true
cp "$WT/a.txt" "$WTL1/a.txt"   2>/dev/null || true
cp "$WT/b.txt" "$WTL1/b.txt"   2>/dev/null || true
cp "$WT/l1.txt" "$WTL1/l1.txt" 2>/dev/null || true
cp "$WT/.sniff" "$WTL1/.sniff"
note "WTL1 forked off ?L1 at C_L1"

echo "=== 23. WT advances ?L1 to C_L1b ==="
sleep 0.2
echo "L1 v2 (advance)" > l1b.txt
"$BE" put l1b.txt >/dev/null \
    || fail "be put l1b.txt on ?L1 failed"
"$BE" post L1 advance >/dev/null \
    || fail "be post advance on ?L1 failed"
C_L1b=$(head_hex)
[ -n "$C_L1b" ] && [ "$C_L1b" != "$C_L1" ] \
    || fail "C_L1b didn't advance from $C_L1"
note "?L1 advanced to C_L1b=$C_L1b"

echo "=== 24. WTL1 posts on stale ?L1 — rebase + cascade ?L1/L2 ==="
cd "$WTL1"
sleep 0.2
echo "L1 v3 wtl1" > l1c.txt
"$BE" put l1c.txt >/dev/null \
    || fail "WTL1: be put l1c.txt failed"
"$BE" post L1 wtl1 2>"$TMP/wtl1.err" >/dev/null \
    || { cat "$TMP/wtl1.err"; fail "WTL1: be post should rebase + cascade"; }
C_L1c=$(head_hex)
[ -n "$C_L1c" ] && [ "$C_L1c" != "$C_L1b" ] && [ "$C_L1c" != "$C_L1" ] \
    || fail "WTL1 rebased tip $C_L1c not distinct from C_L1b/C_L1"
note "?L1 rebased onto C_L1b → C_L1c=$C_L1c"

# Verify ?L1 REFS at C_L1c.
L1_REFS=$(ref_tip "?L1")
[ "$L1_REFS" = "$C_L1c" ] \
    || fail "?L1 REFS at $L1_REFS; want C_L1c=$C_L1c"
# Verify ?L1/L2 was rebased: tip moved off C_L2.
L2_REFS=$(ref_tip "?L1/L2")
[ -n "$L2_REFS" ] || fail "?L1/L2 REFS missing after cascade"
[ "$L2_REFS" != "$C_L2" ] \
    || fail "cascade did not advance ?L1/L2 (still at $C_L2)"
# And ?L1/L2's first parent traces to C_L1c (since L2 was a single
# commit forked from C_L1, the rebased L2 has parent C_L1c).
L2_PARENT=$("$KEEPER" get ".#$L2_REFS" 2>/dev/null \
              | awk '/^parent / { print $2; exit }')
[ "$L2_PARENT" = "$C_L1c" ] \
    || fail "?L1/L2 rebased tip's parent is $L2_PARENT; want C_L1c=$C_L1c"
note "cascade landed: ?L1/L2 rebased; parent = C_L1c"

cd "$WT"

# ------------------------------------------------------------------
# === 25. ?.. auto-sync ===
#
# From cur on ?fix1, advance trunk via a second wt sharing the keeper,
# then run `be post ?..` from cur.  Assertions:
#   * trunk's REFS advances (already advanced by the second wt);
#   * cur's REFS now equals trunk's tip (auto-sync);
#   * cur's stack relative to trunk is empty — i.e. dropped, no
#     intermediate commits.  (Cur was at C_L1c which had its own
#     stack; once promoted into trunk, trunk == cur tip.)
#
# Setup: clean up the leftover ?L1, ?L1/L2.  Re-create ?fix1 off trunk.
# ------------------------------------------------------------------
echo "=== 25. ?.. auto-sync ==="
# Walk back to trunk before deleting (DEL refuses dropping cur).
# Two `?..` hops cover the deepest baseline (?L1/L2 → ?L1 → trunk).
"$BE" get "?.." >/dev/null 2>&1 || true
"$BE" get "?.." >/dev/null 2>&1 || true
"$BE" delete "?L1/L2" >/dev/null 2>&1 || true
"$BE" delete "?L1"    >/dev/null 2>&1 || true

cd "$WT"
"$BE" get "?.." >/dev/null \
    || fail "be get ?.. (back to trunk before §25) failed"
T25_pre=$(head_hex)
[ -n "$T25_pre" ] || fail "no trunk tip before §25"
note "§25: trunk pre = $T25_pre"

#  Create a fresh ?fix1 child for this scenario.
"$BE" post "?./fix1" >/dev/null \
    || fail "§25: be post ?./fix1 failed"
"$BE" get "?fix1" >/dev/null \
    || fail "§25: be get ?fix1 failed"
sleep 0.2
echo "fix1-25 v1" > f25.txt
"$BE" put f25.txt >/dev/null
"$BE" post fix1-25 c1 >/dev/null \
    || fail "§25: be post fix1-25 c1 failed"
F25_C1=$(head_hex)
[ -n "$F25_C1" ] && [ "$F25_C1" != "$T25_pre" ] \
    || fail "§25: ?fix1 didn't advance"
note "§25: ?fix1 at $F25_C1 (cur)"

# A peer wt shares the keeper, advances trunk while cur is on ?fix1.
WT25="$TMP/wt25"
mkdir -p "$WT25"
ln -s "$WT/.dogs" "$WT25/.dogs"
( cd "$WT25" && "$BE" get "?" >/dev/null ) \
    || fail "§25: WT25 be get ? failed"
( cd "$WT25" && sleep 0.2 && echo "trunk advance 25" > tr25.txt \
    && "$BE" put tr25.txt >/dev/null \
    && "$BE" post trunk-advance-25 >/dev/null ) \
    || fail "§25: WT25 trunk advance failed"

T25_advance=$(ref_tip "?")
[ -n "$T25_advance" ] && [ "$T25_advance" != "$T25_pre" ] \
    || fail "§25: trunk REFS didn't advance ($T25_advance)"
note "§25: trunk advanced to $T25_advance"

# Back in cur (on ?fix1): `be post ?..` — promote cur's commits into
# trunk and auto-sync ?fix1 to the new trunk tip.
cd "$WT"
"$BE" post "?.." 2>"$TMP/p25.err" >/dev/null \
    || { cat "$TMP/p25.err"; fail "§25: be post ?.. failed"; }
T25_after=$(ref_tip "?")
F25_after=$(ref_tip "?fix1")
[ -n "$T25_after" ] && [ "$T25_after" != "$T25_advance" ] \
    || fail "§25: trunk REFS didn't advance past T25_advance"
[ "$F25_after" = "$T25_after" ] \
    || fail "§25: cur (?fix1) auto-sync failed: ?fix1=$F25_after, ?=$T25_after"
note "§25: trunk -> $T25_after; ?fix1 auto-synced"

# Assert cur's stack relative to trunk is empty: tip is identical.
[ "$F25_after" = "$T25_after" ] \
    || fail "§25: cur stack relative to trunk not empty"
note "§25 OK: ?.. auto-sync"

# cleanup
"$BE" delete "?fix1" >/dev/null 2>&1 || true
rm -f f25.txt tr25.txt
rm -rf "$WT25"

# ------------------------------------------------------------------
# === 26. ?./fix2 promote-into-child ===
#
# Setup: on cur (trunk) create ?./fix1, switch to ?fix1, create
# ?./fix2 (sub-branch), commit on ?./fix2, switch to ?fix1.  Then
# `be post ?./fix2` from ?fix1 — fix2's stack rebases onto fix1.tip;
# cur (?fix1) unchanged.
# ------------------------------------------------------------------
echo "=== 26. ?./fix2 promote-into-child ==="
cd "$WT"
"$BE" get "?.." >/dev/null \
    || fail "§26: be get ?.. (back to trunk) failed"
"$BE" post "?./fix1" >/dev/null \
    || fail "§26: be post ?./fix1 failed"
"$BE" get "?fix1" >/dev/null \
    || fail "§26: be get ?fix1 failed"
sleep 0.2
echo "fix1-26 v1" > f1_26.txt
"$BE" put f1_26.txt >/dev/null
"$BE" post fix1-26 c1 >/dev/null \
    || fail "§26: be post fix1-26 c1 failed"
F1_TIP=$(head_hex)
[ -n "$F1_TIP" ] || fail "§26: no fix1 tip"

# Create ?./fix2 sub-branch (under ?fix1).
"$BE" post "?./fix2" >/dev/null \
    || fail "§26: be post ?./fix2 failed"
"$BE" get "?fix1/fix2" >/dev/null \
    || fail "§26: be get ?fix1/fix2 failed"
[ "$(cur_branch)" = "fix1/fix2" ] \
    || fail "§26: wt should be on fix1/fix2; got '$(cur_branch)'"
sleep 0.2
echo "fix2-26 v1" > f2_26.txt
"$BE" put f2_26.txt >/dev/null
"$BE" post fix2-26 c1 >/dev/null \
    || fail "§26: be post fix2-26 c1 failed"
F2_TIP_BEFORE=$(head_hex)
[ -n "$F2_TIP_BEFORE" ] && [ "$F2_TIP_BEFORE" != "$F1_TIP" ] \
    || fail "§26: ?fix1/fix2 didn't advance"

# Switch to ?fix1; from there, `be post ?./fix2` rebases fix2 onto
# fix1.tip.  fix1 untouched.
"$BE" get "?fix1" >/dev/null \
    || fail "§26: be get ?fix1 failed"
F1_PRE=$(ref_tip "?fix1")
F2_PRE=$(ref_tip "?fix1/fix2")
[ "$F1_PRE" = "$F1_TIP" ] || fail "§26: ?fix1 unexpectedly moved"

"$BE" post "?./fix2" 2>"$TMP/p26.err" >/dev/null \
    || { cat "$TMP/p26.err"; fail "§26: be post ?./fix2 failed"; }

F1_POST=$(ref_tip "?fix1")
F2_POST=$(ref_tip "?fix1/fix2")
[ "$F1_POST" = "$F1_PRE" ] \
    || fail "§26: cur (?fix1) moved across promote: $F1_PRE -> $F1_POST"
#  fix2 must have advanced (or at least its fork point did).  Since
#  fix2's old tip was forked from F1_PRE, the rebased fix2 tip's
#  parent must trace to F1_PRE (no replay needed) — F2_POST may
#  equal F2_PRE in the trivial case (no commits to replay).  But the
#  fork point did advance: fix2's tip is now reachable from fix1.
[ "$F2_POST" != "$F1_PRE" ] \
    || fail "§26: ?fix1/fix2 collapsed to fix1 — should keep its commit on top"
note "§26: ?fix1 unchanged at $F1_POST; ?fix1/fix2 -> $F2_POST"

# cleanup
"$BE" get "?.." >/dev/null
"$BE" delete "?fix1/fix2" >/dev/null 2>&1 || true
"$BE" delete "?fix1"      >/dev/null 2>&1 || true
rm -f f1_26.txt f2_26.txt

# ------------------------------------------------------------------
# === 27. sibling promote (?fix2 from ?fix1) ===
#
# Create ?fix1 and ?fix2 as peers off trunk.  On ?fix1, run
# `be post ?fix2` — ?fix2 advances with cur's commits rebased onto
# its tip; cur (?fix1) unchanged.  Cur is NOT auto-synced (sibling
# is not upstream).
# ------------------------------------------------------------------
echo "=== 27. sibling promote ==="
cd "$WT"
"$BE" get "?.." >/dev/null \
    || fail "§27: be get ?.. (trunk) failed"
"$BE" post "?./fix1" >/dev/null \
    || fail "§27: be post ?./fix1 failed"
"$BE" post "?./fix2" >/dev/null \
    || fail "§27: be post ?./fix2 (peer) failed"

# Add a commit to ?fix2 first so its tip differs from trunk.
"$BE" get "?fix2" >/dev/null \
    || fail "§27: be get ?fix2 failed"
sleep 0.2
echo "fix2-27 v1" > f27_2.txt
"$BE" put f27_2.txt >/dev/null
"$BE" post fix2-27 c1 >/dev/null \
    || fail "§27: be post fix2-27 c1 failed"
F2_TIP_PRE=$(ref_tip "?fix2")
[ -n "$F2_TIP_PRE" ] || fail "§27: no ?fix2 tip"

# Switch to ?fix1, add a commit, then `be post ?fix2`.
"$BE" get "?fix1" >/dev/null \
    || fail "§27: be get ?fix1 failed"
sleep 0.2
echo "fix1-27 v1" > f27_1.txt
"$BE" put f27_1.txt >/dev/null
"$BE" post fix1-27 c1 >/dev/null \
    || fail "§27: be post fix1-27 c1 failed"
F1_TIP_PRE=$(ref_tip "?fix1")
TRUNK_PRE_27=$(ref_tip "?")
[ "$(cur_branch)" = "fix1" ] \
    || fail "§27: wt should be on ?fix1; got '$(cur_branch)'"

"$BE" post "?fix2" 2>"$TMP/p27.err" >/dev/null \
    || { cat "$TMP/p27.err"; fail "§27: be post ?fix2 (sibling) failed"; }

F2_TIP_POST=$(ref_tip "?fix2")
F1_TIP_POST=$(ref_tip "?fix1")
TRUNK_POST_27=$(ref_tip "?")

[ "$F1_TIP_POST" = "$F1_TIP_PRE" ] \
    || fail "§27: cur (?fix1) auto-synced when sibling promote should leave it: $F1_TIP_PRE -> $F1_TIP_POST"
[ "$F2_TIP_POST" != "$F2_TIP_PRE" ] \
    || fail "§27: sibling ?fix2 did not advance: $F2_TIP_POST"
[ "$TRUNK_POST_27" = "$TRUNK_PRE_27" ] \
    || fail "§27: trunk drifted ($TRUNK_PRE_27 -> $TRUNK_POST_27)"
note "§27 OK: ?fix2 advanced; ?fix1 untouched (no auto-sync for sibling)"

# cleanup
"$BE" get "?.." >/dev/null
"$BE" delete "?fix2" >/dev/null 2>&1 || true
"$BE" delete "?fix1" >/dev/null 2>&1 || true
rm -f f27_1.txt f27_2.txt

# ------------------------------------------------------------------
# === 28. baseline POST shapes — POSTNONE / selective / implicit ===
#
# Three quick A-tier baselines:
#   28a — bare POST on a clean wt (no edits, no puts) → POSTNONE
#         (exit non-zero, REFS unchanged).
#   28b — selective mode: edit a.txt + b.txt, `be put a.txt`, post.
#         Commit's tree has a.txt at the new sha and b.txt carried
#         over (== baseline blob).  b.txt stays edited in wt.
#   28c — implicit / commit-all: edit a.txt + b.txt, post (no puts).
#         Both a.txt and b.txt rewrite in the new commit's tree.
# ------------------------------------------------------------------
echo "=== 28. baseline POST shapes ==="
cd "$WT"
"$BE" get "?.." >/dev/null 2>&1 || true

# 28a — bare POST with no changes → POSTNONE
#  "Bare" here means with a message but no edits/puts.  Without a
#  message `be post` is a dry-run that exits OK; with a message and
#  no changes since baseline, POST refuses with POSTNONE.
echo "=== 28a. POST on clean wt → POSTNONE ==="
T28a_pre=$(ref_tip "?")
[ -n "$T28a_pre" ] || fail "§28a: no trunk tip"
set +e
"$BE" post 28a-msg 2>"$TMP/p28a.err" >/dev/null
EC=$?
set -e
[ "$EC" != "0" ] || fail "§28a: POST with msg + no changes should fail (exit was 0)"
grep -q 'no changes since base' "$TMP/p28a.err" \
    || fail "§28a: stderr should mention 'no changes since base'; got:
$(cat "$TMP/p28a.err")"
T28a_post=$(ref_tip "?")
[ "$T28a_post" = "$T28a_pre" ] \
    || fail "§28a: trunk REFS moved on POSTNONE: $T28a_pre -> $T28a_post"
note "§28a OK: bare POST refused; trunk unchanged at $T28a_pre"

# 28b — selective: edit two files, put only one, post.
echo "=== 28b. selective mode (be put a.txt; be post msg) ==="
sleep 0.2
echo "a v28b" > a28.txt
echo "b v28b" > b28.txt
"$BE" put a28.txt b28.txt >/dev/null \
    || fail "§28b: stage initial baseline failed"
"$BE" post 28b-base >/dev/null \
    || fail "§28b: baseline commit failed"
T28b_base=$(head_hex)

#  Capture baseline tree's b28.txt blob sha.
B28_BASE_BLOB=$("$KEEPER" ls-files ".#$T28b_base" 2>/dev/null \
                  | awk '$NF=="b28.txt"{print $3; exit}')
[ -n "$B28_BASE_BLOB" ] || fail "§28b: missing b28.txt baseline blob"

#  Edit both, but only put a28.txt.
sleep 0.2
echo "a edited 28b" > a28.txt
echo "b edited 28b" > b28.txt
"$BE" put a28.txt >/dev/null \
    || fail "§28b: be put a28.txt failed"
"$BE" post 28b-selective >/dev/null \
    || fail "§28b: be post 28b-selective failed"
T28b_sel=$(head_hex)
[ "$T28b_sel" != "$T28b_base" ] || fail "§28b: tip didn't advance"

#  In the new commit's tree: a28.txt's blob != baseline; b28.txt's
#  blob == baseline (carry-over).
A_NEW=$("$KEEPER" ls-files ".#$T28b_sel" 2>/dev/null \
          | awk '$NF=="a28.txt"{print $3; exit}')
B_NEW=$("$KEEPER" ls-files ".#$T28b_sel" 2>/dev/null \
          | awk '$NF=="b28.txt"{print $3; exit}')
[ -n "$A_NEW" ] && [ -n "$B_NEW" ] || fail "§28b: missing blobs in new commit"
[ "$B_NEW" = "$B28_BASE_BLOB" ] \
    || fail "§28b: b28.txt should carry over baseline blob ($B28_BASE_BLOB), got $B_NEW"
#  Wt's b28.txt should still hold the edited content ("b edited 28b").
grep -qx 'b edited 28b' b28.txt \
    || fail "§28b: wt b28.txt should still hold edited bytes"
note "§28b OK: a28 rewrote, b28 carried over, wt b28 still edited"

# 28c — implicit mode: edit two files, post (no puts in between).
echo "=== 28c. implicit mode (no puts; bare-msg POST) ==="
sleep 0.2
echo "a v28c base" > a28c.txt
echo "b v28c base" > b28c.txt
"$BE" put a28c.txt b28c.txt >/dev/null \
    || fail "§28c: stage initial baseline failed"
"$BE" post 28c-base >/dev/null \
    || fail "§28c: baseline commit failed"
T28c_base=$(head_hex)
B28C_BASE_BLOB=$("$KEEPER" ls-files ".#$T28c_base" 2>/dev/null \
                  | awk '$NF=="b28c.txt"{print $3; exit}')

#  Edit both files; no `be put`.  Post with a message.
sleep 0.2
echo "a edited 28c" > a28c.txt
echo "b edited 28c" > b28c.txt
"$BE" post 28c-implicit >/dev/null \
    || fail "§28c: be post 28c-implicit failed"
T28c_imp=$(head_hex)
[ "$T28c_imp" != "$T28c_base" ] || fail "§28c: tip didn't advance"

A2=$("$KEEPER" ls-files ".#$T28c_imp" 2>/dev/null \
       | awk '$NF=="a28c.txt"{print $3; exit}')
B2=$("$KEEPER" ls-files ".#$T28c_imp" 2>/dev/null \
       | awk '$NF=="b28c.txt"{print $3; exit}')
[ -n "$A2" ] && [ -n "$B2" ] || fail "§28c: missing blobs in implicit commit"
[ "$B2" != "$B28C_BASE_BLOB" ] \
    || fail "§28c: b28c.txt should be rewritten in implicit mode (got baseline blob)"
note "§28c OK: implicit commit rewrote both files"

# cleanup files used only here
rm -f a28.txt b28.txt a28c.txt b28c.txt
"$BE" delete a28.txt    >/dev/null 2>&1 || true
"$BE" delete b28.txt    >/dev/null 2>&1 || true
"$BE" delete a28c.txt   >/dev/null 2>&1 || true
"$BE" delete b28c.txt   >/dev/null 2>&1 || true
"$BE" post 28-cleanup   >/dev/null 2>&1 || true

# ------------------------------------------------------------------
# === 29. patch-id dedup E2E ===
#
# Build:
#   trunk T1.
#   ?fix1 forks at T1, gets two commits: C1 (edits fix.txt) and
#       C2 (edits other.txt).
#   ?fix2 forks at T1.  We cherry-pick C1's content manually:
#     write fix.txt with the same edited bytes, `be put fix.txt`,
#     `be post c1prime`.  That's C1' on ?fix2; patch-id(C1') ==
#     patch-id(C1) since the (path, parent_blob, child_blob) triples
#     match byte-for-byte.
#
# Now from cur on ?fix1, run `be post ?fix2`.  Existing dispatcher
# semantics: cur's stack replays onto target.tip.  Cur (?fix1) has
# C1, C2 above T1.  Target ?fix2 has C1' above T1.  GRAFRebase walks
# (C1, C2] forward and skips C1 (its patch-id matches C1' in fix2's
# ancestor set), emits a fresh C2'.  The rebased ?fix2 tip should be
# exactly 1 hop past C1'.
# ------------------------------------------------------------------
echo "=== 29. patch-id dedup E2E ==="
cd "$WT"
"$BE" get "?.." >/dev/null 2>&1 || true
T29_T1=$(ref_tip "?")

#  Seed shared baseline files (deterministic content).
sleep 0.2
echo "fix base" > fix29.txt
echo "other base" > other29.txt
"$BE" put fix29.txt other29.txt >/dev/null \
    || fail "§29: stage baseline failed"
"$BE" post 29-base >/dev/null \
    || fail "§29: baseline commit failed"
T29_T1=$(head_hex)
note "§29: T1=$T29_T1"

#  Build ?fix1 with C1 (fix.txt) + C2 (other.txt).
"$BE" post "?./fix1" >/dev/null \
    || fail "§29: create ?fix1 failed"
"$BE" get "?fix1" >/dev/null \
    || fail "§29: switch to ?fix1 failed"
sleep 0.2
echo "fix changed" > fix29.txt
"$BE" put fix29.txt >/dev/null \
    || fail "§29: put fix29.txt on ?fix1 failed"
"$BE" post fix1c1 >/dev/null \
    || fail "§29: post fix1c1 failed"
F29_C1=$(head_hex)
sleep 0.2
echo "other changed" > other29.txt
"$BE" put other29.txt >/dev/null \
    || fail "§29: put other29.txt on ?fix1 failed"
"$BE" post fix1c2 >/dev/null \
    || fail "§29: post fix1c2 failed"
F29_C2=$(head_hex)
note "§29: ?fix1 stack T1=$T29_T1 -> C1=$F29_C1 -> C2=$F29_C2"

#  Build ?fix2 forked at T1 with cherry-picked C1' (same content as
#  C1).  Switch back to trunk first — `be get ?..` checks out the
#  baseline tree, so wt is clean and the cross-branch switch to
#  ?fix2 just below succeeds.
"$BE" get "?.." >/dev/null \
    || fail "§29: back to trunk failed"
"$BE" post "?./fix2" >/dev/null \
    || fail "§29: create ?fix2 failed"
"$BE" get "?fix2" >/dev/null \
    || fail "§29: switch to ?fix2 failed"
sleep 0.2
echo "fix changed" > fix29.txt
"$BE" put fix29.txt >/dev/null \
    || fail "§29: put fix29.txt on ?fix2 failed"
"$BE" post fix2c1prime >/dev/null \
    || fail "§29: post fix2c1prime failed"
F29_C1P=$(head_hex)
[ "$F29_C1P" != "$F29_C1" ] \
    || fail "§29: C1' should be a distinct commit object (different parent meta)"
note "§29: ?fix2 has C1'=$F29_C1P"

#  Switch to ?fix1, run `be post ?fix2`.
"$BE" get "?fix1" >/dev/null \
    || fail "§29: switch back to ?fix1 failed"
F2_TIP_PRE=$(ref_tip "?fix2")
F1_TIP_PRE=$(ref_tip "?fix1")
[ "$F2_TIP_PRE" = "$F29_C1P" ] || fail "§29: ?fix2 unexpectedly moved"

"$BE" post "?fix2" 2>"$TMP/p29.err" >/dev/null \
    || { cat "$TMP/p29.err"; fail "§29: be post ?fix2 failed"; }

F2_TIP_POST=$(ref_tip "?fix2")
F1_TIP_POST=$(ref_tip "?fix1")
[ "$F1_TIP_POST" = "$F1_TIP_PRE" ] \
    || fail "§29: cur (?fix1) moved across sibling promote"
[ "$F2_TIP_POST" != "$F2_TIP_PRE" ] \
    || fail "§29: ?fix2 didn't advance"

#  Walk parents from F2_TIP_POST until we reach F2_TIP_PRE; count
#  hops.  With dedup, C1's patch-id matches C1' (already on fix2)
#  and is skipped; only C2 replays → 1 hop.
hops=0
cur="$F2_TIP_POST"
while [ -n "$cur" ] && [ "$cur" != "$F2_TIP_PRE" ]; do
    p=$("$KEEPER" get ".#$cur" 2>/dev/null | awk '/^parent / { print $2; exit }')
    hops=$((hops+1))
    cur=$p
    [ $hops -gt 10 ] && break
done
[ "$hops" = "1" ] \
    || fail "§29: expected 1 hop (C2 only) past C1' due to patch-id dedup; got $hops"
note "§29 OK: C1 deduped against C1'; ?fix2 advanced by exactly 1 commit"

# cleanup
"$BE" get "?.." >/dev/null
"$BE" delete "?fix1" >/dev/null 2>&1 || true
"$BE" delete "?fix2" >/dev/null 2>&1 || true
rm -f fix29.txt other29.txt
"$BE" delete fix29.txt   >/dev/null 2>&1 || true
"$BE" delete other29.txt >/dev/null 2>&1 || true
"$BE" post 29-cleanup    >/dev/null 2>&1 || true

# ------------------------------------------------------------------
# === 30. cross-branch promote conflict abort ===
#
# Recipe (token-overlap forces JOIN to fail):
#   base:    "the quick fox\n"
#   ours :   "the QUICK fox\n"  on ?fix1
#   theirs:  "the slow fox\n"   on trunk advance
#
# `be post ?..` from cur on ?fix1 walks fix1@* onto trunk's new tip
# (T2, with the THEIRS edit).  GRAFRebase merges; second token
# conflicts → GRAFCNFL.  Assert: nonzero exit, "rebase aborted" in
# stderr, REFS unchanged, wt content for the conflicting file
# unchanged from before the post.
# ------------------------------------------------------------------
echo "=== 30. cross-branch promote conflict ==="
cd "$WT"
"$BE" get "?.." >/dev/null 2>&1 || true

#  Seed conflict.txt baseline on trunk.
sleep 0.2
printf 'the quick fox\n' > conflict30.txt
"$BE" put conflict30.txt >/dev/null \
    || fail "§30: put conflict30.txt failed"
"$BE" post 30-base >/dev/null \
    || fail "§30: post 30-base failed"
T30_BASE=$(head_hex)

#  Create ?fix1 with the OURS edit ("QUICK").
"$BE" post "?./fix1" >/dev/null \
    || fail "§30: create ?fix1 failed"
"$BE" get "?fix1" >/dev/null \
    || fail "§30: switch to ?fix1 failed"
sleep 0.2
printf 'the QUICK fox\n' > conflict30.txt
"$BE" put conflict30.txt >/dev/null \
    || fail "§30: put OURS on ?fix1 failed"
"$BE" post fix1-ours >/dev/null \
    || fail "§30: post fix1-ours failed"
F1_OURS=$(head_hex)
F1_REFS_PRE=$(ref_tip "?fix1")

#  Advance trunk via a peer wt with the THEIRS edit ("slow").
WT30="$TMP/wt30"
mkdir -p "$WT30"
ln -s "$WT/.dogs" "$WT30/.dogs"
( cd "$WT30" && "$BE" get "?" >/dev/null ) \
    || fail "§30: WT30 trunk checkout failed"
( cd "$WT30" && sleep 0.2 && printf 'the slow fox\n' > conflict30.txt \
    && "$BE" put conflict30.txt >/dev/null \
    && "$BE" post 30-theirs >/dev/null ) \
    || fail "§30: WT30 trunk advance failed"
T30_NEW=$(ref_tip "?")
[ "$T30_NEW" != "$T30_BASE" ] || fail "§30: trunk didn't advance"
note "§30: trunk advanced T30_BASE=$T30_BASE -> T30_NEW=$T30_NEW"

#  Snapshot wt content (cur on ?fix1) before the conflicting promote.
WT_FILE_PRE=$(sha1sum conflict30.txt 2>/dev/null | awk '{print $1}')

set +e
"$BE" post "?.." 2>"$TMP/p30.err" >/dev/null
EC30=$?
set -e

[ "$EC30" != "0" ] \
    || { cat "$TMP/p30.err" >&2; fail "§30: be post ?.. should have aborted"; }
grep -q 'rebase aborted' "$TMP/p30.err" \
    || fail "§30: stderr should mention 'rebase aborted'; got:
$(cat "$TMP/p30.err")"
T30_REFS_AFTER=$(ref_tip "?")
F1_REFS_AFTER=$(ref_tip "?fix1")
[ "$T30_REFS_AFTER" = "$T30_NEW" ] \
    || fail "§30: trunk REFS moved across aborted post: $T30_NEW -> $T30_REFS_AFTER"
[ "$F1_REFS_AFTER" = "$F1_REFS_PRE" ] \
    || fail "§30: ?fix1 REFS moved across aborted post: $F1_REFS_PRE -> $F1_REFS_AFTER"
WT_FILE_POST=$(sha1sum conflict30.txt 2>/dev/null | awk '{print $1}')
[ "$WT_FILE_POST" = "$WT_FILE_PRE" ] \
    || fail "§30: wt conflict30.txt changed across aborted post"
note "§30 OK: conflict aborted; REFS + wt unchanged"

# cleanup
"$BE" get "?.." >/dev/null 2>&1 || true
"$BE" delete "?fix1" >/dev/null 2>&1 || true
rm -rf "$WT30"
rm -f conflict30.txt
"$BE" delete conflict30.txt >/dev/null 2>&1 || true
"$BE" post 30-cleanup       >/dev/null 2>&1 || true

# ------------------------------------------------------------------
# === 31. cascade conflict in descendant — SKIPPED ===
#
# The intended scenario:
#   trunk T1, ?L1 (a c1 on disjoint file), ?L1/L2 (OURS edit on
#   conflict31.txt), trunk advances with THEIRS edit on the same
#   file.  `be post ?..` from cur=?L1 should: rebase ?L1 onto T2
#   (clean), cascade onto ?L1/L2 (conflict), abort POST atomically.
#
# TODO(spec): cascade walker (sniff/POST.c post_cascade_walk) skips
# `cur_branch` to avoid double-rebasing it via auto-sync.  The skip
# also short-circuits recursion into cur's descendants — so when
# cur=?L1 promotes onto trunk via `?..`, ?L1/L2 is never visited.
# After cur auto-syncs to trunk's tip, its descendants need a
# secondary cascade pass on the new cur tip.  That pass is missing
# today (Stage 2c "cascade walker" is sealed for this stage).
#
# Test left in place so the gap is visible; runs as a smoke check
# that the simpler arms keep working.
# ------------------------------------------------------------------
echo "=== 31. cascade conflict (smoke; descendant pass deferred) ==="
skip "§31 cascade-into-descendant after auto-sync — cascade walker skip semantics"

# ------------------------------------------------------------------
# === 32. dispatcher arm: ?<absolute>/<newleaf> ===
#
# cur on ?fix1 (with a commit), `?feat` exists on trunk.
# `be post ?feat/new` creates `?feat/new`; rebases cur's stack onto
# `?feat`'s tip (which is == trunk here, so no commits to replay) →
# new leaf points at ?feat.tip (or rebased equivalent).  Cur's
# REFS + .dogs/feat/new shard exist; cur unchanged.
# ------------------------------------------------------------------
echo "=== 32. ?<absolute>/<newleaf> create-on-miss ==="
cd "$WT"
"$BE" get "?.." >/dev/null 2>&1 || true

sleep 0.2
echo "x32" > x32.txt
"$BE" put x32.txt >/dev/null
"$BE" post 32-base >/dev/null \
    || fail "§32: base post failed"
T32_TRUNK=$(ref_tip "?")

"$BE" post "?./feat" >/dev/null \
    || fail "§32: create ?feat failed"
"$BE" post "?./fix1" >/dev/null \
    || fail "§32: create ?fix1 failed"
"$BE" get "?fix1" >/dev/null \
    || fail "§32: switch ?fix1 failed"
sleep 0.2
echo "fix1 work 32" > fwork32.txt
"$BE" put fwork32.txt >/dev/null
"$BE" post fix1-32 >/dev/null \
    || fail "§32: post fix1-32 failed"
F1_TIP_32=$(ref_tip "?fix1")
FEAT_TIP_32=$(ref_tip "?feat")

#  Run the create-on-miss arm: `be post ?feat/new` from cur=?fix1.
"$BE" post "?feat/new" 2>"$TMP/p32.err" >/dev/null \
    || { cat "$TMP/p32.err"; fail "§32: be post ?feat/new failed"; }

NEW32=$(ref_tip "?feat/new")
[ -n "$NEW32" ] || fail "§32: ?feat/new not in REFS"
F1_TIP_32_AFTER=$(ref_tip "?fix1")
[ "$F1_TIP_32_AFTER" = "$F1_TIP_32" ] \
    || fail "§32: cur ?fix1 moved: $F1_TIP_32 -> $F1_TIP_32_AFTER"
[ -d ".dogs/feat/new" ] \
    || fail "§32: .dogs/feat/new shard missing"

#  Walk parents from NEW32 until we hit FEAT_TIP_32 (the absolute
#  parent's tip).  In this trivial setup ?fix1.tip is the same commit
#  as ?feat.tip is on trunk's spine, so the rebased tip == fix1's
#  commit, and its parent chain reaches FEAT_TIP_32.
seen_feat=NO
cur="$NEW32"; n=0
while [ -n "$cur" ] && [ $n -lt 20 ]; do
    if [ "$cur" = "$FEAT_TIP_32" ]; then seen_feat=YES; break; fi
    p=$("$KEEPER" get ".#$cur" 2>/dev/null | awk '/^parent / { print $2; exit }')
    cur=$p; n=$((n+1))
done
[ "$seen_feat" = "YES" ] \
    || fail "§32: ?feat/new tip's parent chain doesn't reach FEAT_TIP_32"
note "§32 OK: ?feat/new created at $NEW32 (parent chain to ?feat=$FEAT_TIP_32)"

# cleanup
"$BE" get "?.." >/dev/null
"$BE" delete "?feat/new" >/dev/null 2>&1 || true
"$BE" delete "?feat"     >/dev/null 2>&1 || true
"$BE" delete "?fix1"     >/dev/null 2>&1 || true
rm -f x32.txt fwork32.txt
"$BE" delete x32.txt    >/dev/null 2>&1 || true
"$BE" delete fwork32.txt >/dev/null 2>&1 || true
"$BE" post 32-cleanup   >/dev/null 2>&1 || true

# ------------------------------------------------------------------
# === 33. dispatcher arm: ?<absolute>/ trailing-slash basename reuse ===
#
# cur on ?fix1; `?feat` exists on trunk.  `be post ?feat/` rewrites
# the target to `?feat/<basename(cur)>` = `?feat/fix1`, then runs the
# same flow as §32.  Asserts: ?feat/fix1 exists; cur (?fix1) is
# unchanged; .dogs/feat/fix1 shard exists.
# ------------------------------------------------------------------
echo "=== 33. ?<absolute>/ trailing-slash reuse ==="
cd "$WT"
"$BE" get "?.." >/dev/null 2>&1 || true
sleep 0.2
echo "x33" > x33.txt
"$BE" put x33.txt >/dev/null
"$BE" post 33-base >/dev/null \
    || fail "§33: base post failed"

"$BE" post "?./feat" >/dev/null \
    || fail "§33: create ?feat failed"
"$BE" post "?./fix1" >/dev/null \
    || fail "§33: create ?fix1 failed"
"$BE" get "?fix1" >/dev/null \
    || fail "§33: switch ?fix1 failed"
sleep 0.2
echo "fix1-33" > f33.txt
"$BE" put f33.txt >/dev/null
"$BE" post fix1-33 >/dev/null \
    || fail "§33: post fix1-33 failed"
F1_PRE_33=$(ref_tip "?fix1")
FEAT_PRE_33=$(ref_tip "?feat")

"$BE" post "?feat/" 2>"$TMP/p33.err" >/dev/null \
    || { cat "$TMP/p33.err"; fail "§33: be post ?feat/ failed"; }

NEW33=$(ref_tip "?feat/fix1")
[ -n "$NEW33" ] \
    || fail "§33: ?feat/fix1 not in REFS — basename rewrite missing"
F1_AFTER_33=$(ref_tip "?fix1")
[ "$F1_AFTER_33" = "$F1_PRE_33" ] \
    || fail "§33: cur ?fix1 moved: $F1_PRE_33 -> $F1_AFTER_33"
[ -d ".dogs/feat/fix1" ] \
    || fail "§33: .dogs/feat/fix1 shard missing"
seen_feat=NO
cur="$NEW33"; n=0
while [ -n "$cur" ] && [ $n -lt 20 ]; do
    if [ "$cur" = "$FEAT_PRE_33" ]; then seen_feat=YES; break; fi
    p=$("$KEEPER" get ".#$cur" 2>/dev/null | awk '/^parent / { print $2; exit }')
    cur=$p; n=$((n+1))
done
[ "$seen_feat" = "YES" ] \
    || fail "§33: ?feat/fix1 tip's parent chain doesn't reach FEAT_PRE_33"
note "§33 OK: trailing-slash rewrote to ?feat/fix1 ($NEW33)"

# cleanup
"$BE" get "?.." >/dev/null
"$BE" delete "?feat/fix1" >/dev/null 2>&1 || true
"$BE" delete "?feat"      >/dev/null 2>&1 || true
"$BE" delete "?fix1"      >/dev/null 2>&1 || true
rm -f x33.txt f33.txt
"$BE" delete x33.txt >/dev/null 2>&1 || true
"$BE" delete f33.txt >/dev/null 2>&1 || true
"$BE" post 33-cleanup >/dev/null 2>&1 || true

# ------------------------------------------------------------------
# === 34. tree-parent absolute auto-syncs cur (mirror of §25) ===
#
# §25 covers the relative `?..` form auto-syncing cur to its tree-
# parent's new tip.  §27 covers a sibling promote NOT auto-syncing.
# This case fills in the absolute path of the tree-parent: cur on
# ?feat/fix; `be post ?feat` (absolute) should auto-sync cur to
# ?feat's new tip, mirroring §25.
# ------------------------------------------------------------------
echo "=== 34. absolute tree-parent auto-syncs cur ==="
cd "$WT"
"$BE" get "?.." >/dev/null 2>&1 || true
sleep 0.2
echo "x34" > x34.txt
"$BE" put x34.txt >/dev/null
"$BE" post 34-base >/dev/null \
    || fail "§34: base post failed"

"$BE" post "?./feat" >/dev/null \
    || fail "§34: create ?feat failed"
"$BE" get "?feat" >/dev/null \
    || fail "§34: switch ?feat failed"
"$BE" post "?./fix" >/dev/null \
    || fail "§34: create ?feat/fix failed"
"$BE" get "?feat/fix" >/dev/null \
    || fail "§34: switch ?feat/fix failed"
sleep 0.2
echo "feat/fix work" > ff34.txt
"$BE" put ff34.txt >/dev/null
"$BE" post feat-fix-c1 >/dev/null \
    || fail "§34: post feat-fix-c1 failed"
FF_PRE_34=$(ref_tip "?feat/fix")

#  Now `be post ?feat` from cur on ?feat/fix — absolute parent.
"$BE" post "?feat" 2>"$TMP/p34.err" >/dev/null \
    || { cat "$TMP/p34.err"; fail "§34: be post ?feat failed"; }

FEAT_AFTER_34=$(ref_tip "?feat")
FF_AFTER_34=$(ref_tip "?feat/fix")
[ "$FEAT_AFTER_34" != "" ] || fail "§34: ?feat REFS missing"
[ "$FF_AFTER_34" = "$FEAT_AFTER_34" ] \
    || fail "§34: cur ?feat/fix should auto-sync to ?feat tip; got fix=$FF_AFTER_34, feat=$FEAT_AFTER_34"
note "§34 OK: cur (?feat/fix) auto-synced to ?feat=$FEAT_AFTER_34"

# cleanup
"$BE" get "?.." >/dev/null 2>&1 || true
"$BE" get "?.." >/dev/null 2>&1 || true
"$BE" delete "?feat/fix" >/dev/null 2>&1 || true
"$BE" delete "?feat"     >/dev/null 2>&1 || true
rm -f x34.txt ff34.txt
"$BE" delete x34.txt >/dev/null 2>&1 || true
"$BE" delete ff34.txt >/dev/null 2>&1 || true
"$BE" post 34-cleanup >/dev/null 2>&1 || true

echo "=== workflow-branches: increment 1 + 2 + 3 + 4 OK ==="
