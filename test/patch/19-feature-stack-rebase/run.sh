#!/bin/sh
#  19-feature-stack-rebase — sub-branch fork plus partial cherry-pick
#  plus iterated rebase, with edits living on every link kind in the
#  ancestor graph.
#
#  Topology timeline:
#       T0 ── T1 ── T2 ──── CP1 ── T3 ──── R1 ── R2 ── R3      ← trunk
#         \                                                       (fosters
#          F1 ── F2 ──────────────────── F3            ← ?feature   F1, F2, F3)
#                  \
#                   FixA ── FixB ── FixC               ← ?feature/fix
#
#       trunk: T0 → T1 → T2 (two commits) → cherry-pick FixA → CP1
#              → T3 (one more commit) → rebase ?feature# x3.
#       feature: F1 → F2 (parallel to trunk's T1/T2).
#       fix: FixA → FixB → FixC, only FixA is cherry-picked; FixB lands
#            on ?fix before the cherry, FixC lands AFTER trunk has
#            advanced through CP1+T3.
#
#  Initially every per-zone declaration in lib.c is "= 0".  Each commit
#  flips its own zone to "= 1" — the minimum line edit needed for the
#  commit to be non-empty.  The tests pin two things:
#
#    * topology — parent / foster / picked headers in each commit body
#      reflect the ?feature# rebase chain (foster F1, F2, F3 in order;
#      picked: FixA on CP1; no leakage from FixB, FixC into trunk),
#    * content — final R3 has every trunk + feature + FixA zone bumped
#      to 1; FB and FC stay 0 (?fix's tail never reaches trunk).
#
#  Edits beyond the bare zone bump get layered iteration by iteration
#  (block insertions, line edits to numbers, fn renames, …) — each
#  iteration adds one edit to one commit + propagates the new bytes to
#  every later fixture that inherits that commit's content, then re-runs
#  the test.

. "$(dirname "$0")/../../lib/branches.sh"

# --- T0 trunk seed ----------------------------------------------------
cp "$CASE/01.lib.t0.c" lib.c
"$BE" put lib.c >/dev/null
"$BE" post 't0' >/dev/null
T0=$(head_hex)

# Fork ?feature at T0.
"$BE" put '?./feature' >/dev/null

# --- T1, T2 on trunk (BEFORE cherry-pick) -----------------------------
sleep 0.02; cp "$CASE/02.lib.t1.c" lib.c
"$BE" put lib.c >/dev/null
"$BE" post 't1 zone t1=1' >/dev/null
T1=$(head_hex)

sleep 0.02; cp "$CASE/03.lib.t2.c" lib.c
"$BE" put lib.c >/dev/null
"$BE" post 't2 zone t2=1' >/dev/null
T2=$(head_hex)

# --- F1, F2 on feature ------------------------------------------------
"$BE" get '?feature' >/dev/null
[ "$(head_hex)" = "$T0" ] || fail "feature should fork at T0; head=$(head_hex)"

sleep 0.02; cp "$CASE/04.lib.f1.c" lib.c
"$BE" put lib.c >/dev/null
"$BE" post 'f1 zone f1=1' >/dev/null
F1=$(head_hex)

sleep 0.02; cp "$CASE/05.lib.f2.c" lib.c
"$BE" put lib.c >/dev/null
"$BE" post 'f2 zone f2=1' >/dev/null
F2=$(head_hex)

# --- ?feature/fix at F2; FixA, FixB on fix ----------------------------
"$BE" put '?./fix' >/dev/null
"$BE" get '?feature/fix' >/dev/null
[ "$(head_hex)" = "$F2" ] || fail "fix should fork at F2; head=$(head_hex)"

sleep 0.02; cp "$CASE/07.lib.fixA.c" lib.c
"$BE" put lib.c >/dev/null
"$BE" post 'fixA zone fa=1' >/dev/null
FIXA=$(head_hex)

sleep 0.02; cp "$CASE/08.lib.fixB.c" lib.c
"$BE" put lib.c >/dev/null
"$BE" post 'fixB zone fb=1 (NOT cherry-picked)' >/dev/null
FIXB=$(head_hex)

# --- Trunk: cherry-pick FixA on T2 → CP1 ------------------------------
"$BE" get '?' >/dev/null
[ "$(head_hex)" = "$T2" ] || fail "trunk should be at T2; head=$(head_hex)"

sleep 0.02
"$BE" patch "#$FIXA" >"$ETMP/cp.out" 2>"$ETMP/cp.err" \
    || fail "cherry-pick FixA failed: $(cat $ETMP/cp.err)"
match "$CASE/10.lib.cp1.c" lib.c

"$BE" post >/dev/null \
    || fail "post (cherry FixA, msg-reuse) failed"
CP1=$(head_hex)

BODY=$("$KEEPER" get ".#$CP1" 2>/dev/null) || fail "keeper get .#$CP1 failed"
echo "$BODY" | grep -q "^parent $T2$" \
    || fail "CP1 first parent != T2 ($T2); body:\n$BODY"
echo "$BODY" | grep -q "^picked: $FIXA$" \
    || fail "CP1 missing 'picked: $FIXA' trailer; body:\n$BODY"
echo "$BODY" | grep -q '^foster ' \
    && fail "CP1 carries unexpected foster header; body:\n$BODY"

# --- Trunk: T3 (AFTER cherry-pick, BEFORE rebase) ---------------------
sleep 0.02; cp "$CASE/11.lib.t3.c" lib.c
"$BE" put lib.c >/dev/null
"$BE" post 't3 zone t3=1' >/dev/null
T3=$(head_hex)

# --- ?fix: FixC after CP1 (must NOT leak into trunk) ------------------
"$BE" get '?feature/fix' >/dev/null
[ "$(head_hex)" = "$FIXB" ] || fail "fix head should still be FixB; head=$(head_hex)"
sleep 0.02; cp "$CASE/09.lib.fixC.c" lib.c
"$BE" put lib.c >/dev/null
"$BE" post 'fixC zone fc=1 (NOT cherry-picked)' >/dev/null
FIXC=$(head_hex)

# --- Feature: F3 (parallel to trunk's CP1+T3) -------------------------
"$BE" get '?feature' >/dev/null
[ "$(head_hex)" = "$F2" ] || fail "feature head should still be F2; head=$(head_hex)"
sleep 0.02; cp "$CASE/06.lib.f3.c" lib.c
"$BE" put lib.c >/dev/null
"$BE" post 'f3 zone f3=1' >/dev/null
F3=$(head_hex)

# --- Trunk: rebase ?feature# x3 ---------------------------------------
"$BE" get '?' >/dev/null
[ "$(head_hex)" = "$T3" ] || fail "trunk should be at T3; head=$(head_hex)"

sleep 0.02
"$BE" patch '?feature#' >"$ETMP/r1.out" 2>"$ETMP/r1.err" \
    || fail "rebase iter 1 failed: $(cat $ETMP/r1.err)"
match "$CASE/12.lib.r1.c" lib.c

"$BE" post >/dev/null || fail "post iter 1 failed"
R1=$(head_hex)

BODY=$("$KEEPER" get ".#$R1" 2>/dev/null) || fail "keeper get .#$R1 failed"
echo "$BODY" | grep -q "^parent $T3$" \
    || fail "R1 first parent != T3 ($T3); body:\n$BODY"
echo "$BODY" | grep -q "^foster $F1$" \
    || fail "R1 missing foster $F1; body:\n$BODY"
echo "$BODY" | grep -q "^foster $FIXA$" \
    && fail "R1 leaked FixA into foster; body:\n$BODY"

sleep 0.02
"$BE" patch '?feature#' >"$ETMP/r2.out" 2>"$ETMP/r2.err" \
    || fail "rebase iter 2 failed: $(cat $ETMP/r2.err)"
match "$CASE/13.lib.r2.c" lib.c

"$BE" post >/dev/null || fail "post iter 2 failed"
R2=$(head_hex)

BODY=$("$KEEPER" get ".#$R2" 2>/dev/null) || fail "keeper get .#$R2 failed"
echo "$BODY" | grep -q "^parent $R1$" \
    || fail "R2 first parent != R1; body:\n$BODY"
echo "$BODY" | grep -q "^foster $F2$" \
    || fail "R2 missing foster $F2; body:\n$BODY"
echo "$BODY" | grep -q "^foster $F1$" \
    && fail "R2 carries foster F1 — already absorbed via R1; body:\n$BODY"
echo "$BODY" | grep -q "^foster $FIXB$" \
    && fail "R2 leaked FixB into foster; body:\n$BODY"

sleep 0.02
"$BE" patch '?feature#' >"$ETMP/r3.out" 2>"$ETMP/r3.err" \
    || fail "rebase iter 3 failed: $(cat $ETMP/r3.err)"
match "$CASE/14.lib.r3.c" lib.c

"$BE" post >/dev/null || fail "post iter 3 failed"
R3=$(head_hex)

BODY=$("$KEEPER" get ".#$R3" 2>/dev/null) || fail "keeper get .#$R3 failed"
echo "$BODY" | grep -q "^parent $R2$" \
    || fail "R3 first parent != R2; body:\n$BODY"
echo "$BODY" | grep -q "^foster $F3$" \
    || fail "R3 missing foster $F3; body:\n$BODY"
echo "$BODY" | grep -q "^foster $F2$" \
    && fail "R3 carries foster F2 — already absorbed; body:\n$BODY"
echo "$BODY" | grep -q "^foster $FIXC$" \
    && fail "R3 leaked FixC into foster; body:\n$BODY"

# Pin: FB and FC stayed at 0 (no fix-tail leak).
grep -q '^int fb=0;$' lib.c || fail "fb regressed away from 0 — fix-branch leak"
grep -q '^int fc=0;$' lib.c || fail "fc regressed away from 0 — fix-branch leak"

note "step 0: zone bumps only; topology + content match"
echo "=== patch/19-feature-stack-rebase: OK ==="
