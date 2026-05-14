#!/bin/sh
#  08-sibling-ff-migrate — `be post ?<branch>` (no msg) FF-promotes
#  the target label to cur.tip and copies the missing commit/tree/
#  blob objects from cur's shard into the target's shard via
#  KEEPMoveCommits (keeper/MIGRATE.c).  Cur stays put; only the
#  named ref moves and only its pack log grows.
#
#  Topology built without any remote / git fixture:
#
#       T1 ─ T2 (trunk: a,b,c,d added; T2 inline-edits a, adds e)
#                \
#                 ?fix1, ?fix2 forked at T2
#
#       on ?fix1: C1 (inline edit b.c), C2 (block edit c.c + rm d.c)
#       be post ?fix2          → ?fix2 FF to C2; objects migrate
#                                into .be/fix2/
#       switch to ?fix2 — wt at C2 state
#       on ?fix2: C3 (add f.c)
#       be post ?fix1          → ?fix1 FF to C3; objects migrate
#                                into .be/fix1/
#       switch to ?fix1 — wt at C3 state
#       switch to trunk — still at T2; wt has the original four files
#       switch back to ?fix1
#       be post ?..            → trunk FF to C3; objects migrate
#                                into .be/
#       switch to trunk — wt at C3; log T1..C3 is complete
#
#  Asserts:
#    * cur (the promoting branch) never moves on `be post ?<other>`.
#    * Target REFS advance to cur.tip.
#    * Target's shard dir grows new pack files after each promote
#      (proves KEEPMoveCommits copied objects, not just labels).
#    * wt content matches expectations on every switch.
#    * First-parent chain on trunk after final FF reaches T1 via
#      C3 → C2 → C1 → T2 → T1.

. "$(dirname "$0")/../../lib/case.sh"

KEEPER=${KEEPER:-${BIN:+$BIN/keeper}}
KEEPER=${KEEPER:-$(command -v keeper || true)}
[ -n "$KEEPER" ] && [ -x "$KEEPER" ] || {
    echo "run.sh: cannot locate \`keeper\`" >&2
    exit 2
}

LOGS=$(cd .. && pwd)/logs-$NAME
rm -rf "$LOGS"; mkdir -p "$LOGS"

#  Latest sniff baseline row's URI sha (post|get|patch).
head_hex() {
    awk -F'\t' '$2=="post"||$2=="get"||$2=="patch" { last=$3 }
                END {
                    h = last; sub(/^[^#]*#/, "", h)
                    if (length(h) == 40 && h ~ /^[0-9a-f]+$/) print h
                }' .be/wtlog
}

#  Tip recorded for KEY in `keeper refs` output.  Empty if absent.
ref_tip() {
    "$KEEPER" refs 2>/dev/null | awk -v k="$1" '
        { sub(/^[[:space:]]+/, "")
          tab = index($0, "\t"); if (tab == 0) next
          kf = substr($0, 1, tab - 1); if (kf != k) next
          n = split($0, toks, /[[:space:]]+/)
          v = toks[n]; sub(/^\?/, "", v); print v; exit
        }'
}

#  Total bytes across *.keeper pack files in a shard dir (0 if
#  missing).  KEEPPackOpen appends to the tail pack rather than
#  creating a new file (keeper/KEEP.c §KEEPPackOpen), so file count
#  is invariant across promotes — bytes are not.
pack_bytes() {
    _dir=$1
    [ -d "$_dir" ] || { echo 0; return; }
    _total=0
    for _f in "$_dir"/*.keeper; do
        [ -f "$_f" ] || continue
        _sz=$(wc -c < "$_f" | tr -d ' ')
        _total=$((_total + _sz))
    done
    echo "$_total"
}

# ------------------------------------------------------------------
# 1. T1 baseline on trunk — add a.c, b.c, c.c, d.c.
# ------------------------------------------------------------------
sleep 0.02
cp "$CASE/01.a.t1.c" a.c
cp "$CASE/02.b.t1.c" b.c
cp "$CASE/03.c.t1.c" c.c
cp "$CASE/04.d.t1.c" d.c
must "$BE" put a.c b.c c.c d.c \
    > "$LOGS/01.put.out" 2> "$LOGS/01.put.err"
must "$BE" post 't1 baseline' \
    > "$LOGS/02.post.out" 2> "$LOGS/02.post.err"
T1=$(head_hex)
[ -n "$T1" ] || { echo "no T1 after baseline" >&2; exit 1; }

# ------------------------------------------------------------------
# 2. T2 on trunk — inline edit a.c, add e.c.
# ------------------------------------------------------------------
sleep 0.2
cp "$CASE/05.a.t2.c" a.c
cp "$CASE/06.e.t2.c" e.c
must "$BE" put a.c e.c \
    > "$LOGS/03.put.out" 2> "$LOGS/03.put.err"
must "$BE" post 't2 advance' \
    > "$LOGS/04.post.out" 2> "$LOGS/04.post.err"
T2=$(head_hex)
[ -n "$T2" ] && [ "$T2" != "$T1" ] \
    || { echo "trunk T2 didn't advance past T1=$T1" >&2; exit 1; }

# ------------------------------------------------------------------
# 3. Fork siblings ?fix1 and ?fix2 at T2.
# ------------------------------------------------------------------
must "$BE" put '?./fix1' \
    > "$LOGS/05.put-fix1.out" 2> "$LOGS/05.put-fix1.err"
must "$BE" put '?./fix2' \
    > "$LOGS/06.put-fix2.out" 2> "$LOGS/06.put-fix2.err"
[ "$(ref_tip '?fix1')" = "$T2" ] \
    || { echo "?fix1 not at T2=$T2" >&2; exit 1; }
[ "$(ref_tip '?fix2')" = "$T2" ] \
    || { echo "?fix2 not at T2=$T2" >&2; exit 1; }

# ------------------------------------------------------------------
# 4. Switch to ?fix1.
# ------------------------------------------------------------------
must "$BE" get '?fix1' \
    > "$LOGS/07.get-fix1.out" 2> "$LOGS/07.get-fix1.err"

# ------------------------------------------------------------------
# 5. C1 on ?fix1 — inline edit b.c.
# ------------------------------------------------------------------
sleep 0.2
cp "$CASE/07.b.c1.c" b.c
must "$BE" put b.c \
    > "$LOGS/08.put.out" 2> "$LOGS/08.put.err"
must "$BE" post 'c1 b inline' \
    > "$LOGS/09.post.out" 2> "$LOGS/09.post.err"
C1=$(head_hex)
[ -n "$C1" ] && [ "$C1" != "$T2" ] \
    || { echo "?fix1 didn't advance past T2 for C1" >&2; exit 1; }

# ------------------------------------------------------------------
# 6. C2 on ?fix1 — block edit c.c, remove d.c.
# ------------------------------------------------------------------
sleep 0.2
cp "$CASE/08.c.c2.c" c.c
must "$BE" put c.c \
    > "$LOGS/10.put.out" 2> "$LOGS/10.put.err"
must "$BE" delete d.c \
    > "$LOGS/11.delete.out" 2> "$LOGS/11.delete.err"
must "$BE" post 'c2 block + rm' \
    > "$LOGS/12.post.out" 2> "$LOGS/12.post.err"
C2=$(head_hex)
[ -n "$C2" ] && [ "$C2" != "$C1" ] \
    || { echo "?fix1 didn't advance past C1 for C2" >&2; exit 1; }

# ------------------------------------------------------------------
# 7. `be post ?fix2` — FF ?fix2 to C2, migrate objects into .be/fix2/.
#    Cur stays on ?fix1.  This is the cross-shard copy under test.
# ------------------------------------------------------------------
PRE_FIX2_PACKS=$(pack_bytes .be/fix2)
sleep 0.2
must "$BE" post '?fix2' \
    > "$LOGS/13.promote-fix2.out" 2> "$LOGS/13.promote-fix2.err"

FIX1_AFTER=$(ref_tip '?fix1')
FIX2_AFTER=$(ref_tip '?fix2')
[ "$FIX1_AFTER" = "$C2" ] \
    || { echo "?fix1 (cur) drifted: want $C2 got $FIX1_AFTER" >&2; exit 1; }
[ "$FIX2_AFTER" = "$C2" ] \
    || { echo "?fix2 didn't FF to C2=$C2 (got $FIX2_AFTER)" >&2; exit 1; }

POST_FIX2_PACKS=$(pack_bytes .be/fix2)
[ "$POST_FIX2_PACKS" -gt "$PRE_FIX2_PACKS" ] \
    || { echo "?fix2 shard pack bytes didn't grow (was $PRE_FIX2_PACKS, now $POST_FIX2_PACKS); KEEPMoveCommits didn't copy" >&2
         ls -la .be/fix2/ >&2 2>/dev/null
         exit 1; }

# ------------------------------------------------------------------
# 8. Switch to ?fix2.  Wt resets to C2 state.
# ------------------------------------------------------------------
sleep 0.2
must "$BE" get '?fix2' \
    > "$LOGS/14.get-fix2.out" 2> "$LOGS/14.get-fix2.err"
match "$CASE/05.a.t2.c" a.c
match "$CASE/07.b.c1.c" b.c
match "$CASE/08.c.c2.c" c.c
[ ! -e d.c ] || { echo "d.c should be removed at C2" >&2; exit 1; }
match "$CASE/06.e.t2.c" e.c

#  Spot + graf index sanity on ?fix2's shard: the trigram index must
#  cover the migrated blobs (b@C1 + c@C2 bodies) and the commit log
#  must reach T1 through C1 and C2.
"$BE" 'spot:#sub.c' \
    > "$LOGS/14b.spot-sub.out" 2> "$LOGS/14b.spot-sub.err"
grep -q '^--- b.c' "$LOGS/14b.spot-sub.out" \
    || { echo "?fix2: spot should find 'sub' in b.c (C1's edit)" >&2
         cat "$LOGS/14b.spot-sub.out" >&2; exit 1; }
"$BE" 'spot:#mul.c' \
    > "$LOGS/14c.spot-mul.out" 2> "$LOGS/14c.spot-mul.err"
grep -q '^--- c.c' "$LOGS/14c.spot-mul.out" \
    || { echo "?fix2: spot should find 'mul' in c.c (C2's edit)" >&2
         cat "$LOGS/14c.spot-mul.out" >&2; exit 1; }
"$BE" 'log:#10' \
    > "$LOGS/14d.log.out" 2> "$LOGS/14d.log.err"
grep -q 'c2 block + rm' "$LOGS/14d.log.out" \
    || { echo "?fix2: log missing 'c2 block + rm' commit" >&2
         cat "$LOGS/14d.log.out" >&2; exit 1; }
grep -q 'c1 b inline' "$LOGS/14d.log.out" \
    || { echo "?fix2: log missing 'c1 b inline' commit" >&2
         cat "$LOGS/14d.log.out" >&2; exit 1; }
grep -q 't1 baseline' "$LOGS/14d.log.out" \
    || { echo "?fix2: log missing 't1 baseline' commit" >&2
         cat "$LOGS/14d.log.out" >&2; exit 1; }

# ------------------------------------------------------------------
# 9. C3 on ?fix2 — add f.c.
# ------------------------------------------------------------------
sleep 0.2
cp "$CASE/09.f.c3.c" f.c
must "$BE" put f.c \
    > "$LOGS/15.put.out" 2> "$LOGS/15.put.err"
must "$BE" post 'c3 add f' \
    > "$LOGS/16.post.out" 2> "$LOGS/16.post.err"
C3=$(head_hex)
[ -n "$C3" ] && [ "$C3" != "$C2" ] \
    || { echo "?fix2 didn't advance past C2 for C3" >&2; exit 1; }

# ------------------------------------------------------------------
# 10. `be post ?fix1` — FF ?fix1 to C3, migrate objects into
#     .be/fix1/.  Cur stays on ?fix2.
# ------------------------------------------------------------------
PRE_FIX1_PACKS=$(pack_bytes .be/fix1)
sleep 0.2
must "$BE" post '?fix1' \
    > "$LOGS/17.promote-fix1.out" 2> "$LOGS/17.promote-fix1.err"

FIX2_AFTER2=$(ref_tip '?fix2')
FIX1_AFTER2=$(ref_tip '?fix1')
[ "$FIX2_AFTER2" = "$C3" ] \
    || { echo "?fix2 (cur) drifted: want $C3 got $FIX2_AFTER2" >&2; exit 1; }
[ "$FIX1_AFTER2" = "$C3" ] \
    || { echo "?fix1 didn't FF to C3=$C3 (got $FIX1_AFTER2)" >&2; exit 1; }

POST_FIX1_PACKS=$(pack_bytes .be/fix1)
[ "$POST_FIX1_PACKS" -gt "$PRE_FIX1_PACKS" ] \
    || { echo "?fix1 shard pack bytes didn't grow after promote-back (was $PRE_FIX1_PACKS, now $POST_FIX1_PACKS)" >&2
         ls -la .be/fix1/ >&2 2>/dev/null
         exit 1; }

# ------------------------------------------------------------------
# 11. Switch to ?fix1.  Wt resets to C3 state (all five files,
#     d.c absent).
# ------------------------------------------------------------------
sleep 0.2
must "$BE" get '?fix1' \
    > "$LOGS/18.get-fix1.out" 2> "$LOGS/18.get-fix1.err"
match "$CASE/05.a.t2.c" a.c
match "$CASE/07.b.c1.c" b.c
match "$CASE/08.c.c2.c" c.c
[ ! -e d.c ] || { echo "?fix1@C3 should not have d.c" >&2; exit 1; }
match "$CASE/06.e.t2.c" e.c
match "$CASE/09.f.c3.c" f.c

#  Spot index on ?fix1: must see the new symbol `neg` from f.c (C3,
#  authored on ?fix2, migrated here via promote-back) and lose `dbl`
#  (d.c was deleted at C2).  Graf index: log walks the full chain.
"$BE" 'spot:#neg.c' \
    > "$LOGS/18b.spot-neg.out" 2> "$LOGS/18b.spot-neg.err"
grep -q '^--- f.c' "$LOGS/18b.spot-neg.out" \
    || { echo "?fix1: spot should find 'neg' in f.c (migrated from ?fix2)" >&2
         cat "$LOGS/18b.spot-neg.out" >&2; exit 1; }
"$BE" 'spot:#dbl.c' \
    > "$LOGS/18c.spot-dbl.out" 2> "$LOGS/18c.spot-dbl.err"
[ ! -s "$LOGS/18c.spot-dbl.out" ] \
    || { echo "?fix1: spot should not find 'dbl' (d.c removed at C2)" >&2
         cat "$LOGS/18c.spot-dbl.out" >&2; exit 1; }
"$BE" 'log:#10' \
    > "$LOGS/18d.log.out" 2> "$LOGS/18d.log.err"
grep -q 'c3 add f' "$LOGS/18d.log.out" \
    || { echo "?fix1: log missing 'c3 add f'" >&2
         cat "$LOGS/18d.log.out" >&2; exit 1; }

# ------------------------------------------------------------------
# 12. Switch to trunk.  Trunk stayed at T2; wt resets to T2's tree
#     (a@T2, b@T1, c@T1, d@T1, e@T2 — no f.c).
# ------------------------------------------------------------------
sleep 0.2
must "$BE" get '?..' \
    > "$LOGS/19.get-trunk.out" 2> "$LOGS/19.get-trunk.err"
TRUNK_TIP_NOW=$(ref_tip '?')
[ "$TRUNK_TIP_NOW" = "$T2" ] \
    || { echo "trunk drifted from T2=$T2 to $TRUNK_TIP_NOW" >&2; exit 1; }
match "$CASE/05.a.t2.c" a.c
match "$CASE/02.b.t1.c" b.c
match "$CASE/03.c.t1.c" c.c
match "$CASE/04.d.t1.c" d.c
match "$CASE/06.e.t2.c" e.c
[ ! -e f.c ] || { echo "trunk@T2 should not have f.c" >&2; exit 1; }

# ------------------------------------------------------------------
# 13. Switch back to ?fix1, `be post ?..` — FF trunk to C3 with
#     object migration into .be/ (trunk's own shard).
# ------------------------------------------------------------------
sleep 0.2
must "$BE" get '?fix1' \
    > "$LOGS/20.get-fix1.out" 2> "$LOGS/20.get-fix1.err"
PRE_TRUNK_PACKS=$(pack_bytes .be)
sleep 0.2
must "$BE" post '?..' \
    > "$LOGS/21.promote-trunk.out" 2> "$LOGS/21.promote-trunk.err"

TRUNK_TIP_FF=$(ref_tip '?')
[ "$TRUNK_TIP_FF" = "$C3" ] \
    || { echo "trunk didn't FF to C3=$C3 (got $TRUNK_TIP_FF)" >&2; exit 1; }
[ "$(ref_tip '?fix1')" = "$C3" ] \
    || { echo "?fix1 (cur) drifted after post ?.." >&2; exit 1; }

POST_TRUNK_PACKS=$(pack_bytes .be)
[ "$POST_TRUNK_PACKS" -gt "$PRE_TRUNK_PACKS" ] \
    || { echo "trunk shard pack bytes didn't grow after promote (was $PRE_TRUNK_PACKS, now $POST_TRUNK_PACKS)" >&2
         ls -la .be/ >&2 2>/dev/null
         exit 1; }

# ------------------------------------------------------------------
# 14. Switch to trunk.  Wt resets to C3 state; trunk now carries
#     every change.
# ------------------------------------------------------------------
sleep 0.2
must "$BE" get '?..' \
    > "$LOGS/22.get-trunk.out" 2> "$LOGS/22.get-trunk.err"
match "$CASE/05.a.t2.c" a.c
match "$CASE/07.b.c1.c" b.c
match "$CASE/08.c.c2.c" c.c
[ ! -e d.c ] || { echo "trunk@C3 should not have d.c" >&2; exit 1; }
match "$CASE/06.e.t2.c" e.c
match "$CASE/09.f.c3.c" f.c

#  Spot + graf indexes on trunk's shard: every symbol introduced
#  across the ping-pong (add, sub, mul, sq, neg) must be searchable
#  here, dbl must not (d.c removed at C2), and log must walk the full
#  T1 → T2 → C1 → C2 → C3 chain.
for sym in add sub mul sq neg; do
    "$BE" "spot:#$sym.c" \
        > "$LOGS/22b.spot-$sym.out" 2> "$LOGS/22b.spot-$sym.err"
    [ -s "$LOGS/22b.spot-$sym.out" ] \
        || { echo "trunk: spot should find '$sym' after final promote" >&2
             exit 1; }
done
"$BE" 'spot:#dbl.c' \
    > "$LOGS/22c.spot-dbl.out" 2> "$LOGS/22c.spot-dbl.err"
[ ! -s "$LOGS/22c.spot-dbl.out" ] \
    || { echo "trunk: spot should not find 'dbl' (d.c removed at C2)" >&2
         cat "$LOGS/22c.spot-dbl.out" >&2; exit 1; }
"$BE" 'log:#10' \
    > "$LOGS/22d.log.out" 2> "$LOGS/22d.log.err"
for msg in 't1 baseline' 't2 advance' 'c1 b inline' 'c2 block + rm' 'c3 add f'; do
    grep -q "$msg" "$LOGS/22d.log.out" \
        || { echo "trunk: log missing '$msg' commit" >&2
             cat "$LOGS/22d.log.out" >&2; exit 1; }
done

# ------------------------------------------------------------------
# 15. Commit log: walk first-parent chain C3 → C2 → C1 → T2 → T1.
#     Each link's parent must be the previous sha, proving the
#     migrated commit objects on trunk carry the correct chain.
# ------------------------------------------------------------------
"$KEEPER" get "?#$C3" \
    > "$LOGS/23.c3.out" 2> "$LOGS/23.c3.err" \
    || { echo "keeper get .#C3 failed" >&2
         cat "$LOGS/23.c3.err" >&2; exit 1; }
PARENT_C3=$(awk '/^parent / { print $2; exit }' "$LOGS/23.c3.out")
[ "$PARENT_C3" = "$C2" ] \
    || { echo "C3.parent=$PARENT_C3; want C2=$C2" >&2; exit 1; }

"$KEEPER" get "?#$C2" \
    > "$LOGS/24.c2.out" 2> "$LOGS/24.c2.err"
PARENT_C2=$(awk '/^parent / { print $2; exit }' "$LOGS/24.c2.out")
[ "$PARENT_C2" = "$C1" ] \
    || { echo "C2.parent=$PARENT_C2; want C1=$C1" >&2; exit 1; }

"$KEEPER" get "?#$C1" \
    > "$LOGS/25.c1.out" 2> "$LOGS/25.c1.err"
PARENT_C1=$(awk '/^parent / { print $2; exit }' "$LOGS/25.c1.out")
[ "$PARENT_C1" = "$T2" ] \
    || { echo "C1.parent=$PARENT_C1; want T2=$T2" >&2; exit 1; }

"$KEEPER" get "?#$T2" \
    > "$LOGS/26.t2.out" 2> "$LOGS/26.t2.err"
PARENT_T2=$(awk '/^parent / { print $2; exit }' "$LOGS/26.t2.out")
[ "$PARENT_T2" = "$T1" ] \
    || { echo "T2.parent=$PARENT_T2; want T1=$T1" >&2; exit 1; }

#  All assertions passed.
rm -rf "$LOGS"
