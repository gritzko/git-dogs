#!/bin/sh
. "$(dirname "$0")/../../lib/case.sh"

# Two child branches forked off trunk, each with two commits editing
# disjoint files.  From fix1, `be post ?fix2` rebases fix1's stack onto
# fix2's tip — fix1 advances to a tip that carries both edits.  Per
# VERBS.md §POST, only cur (?fix1) moves; trunk and ?fix2 are read-only.

OUT="$SCRATCH/../out"
mkdir -p "$OUT"

# Step 1: trunk baseline — a.txt + b.txt
sleep 0.02; cp "$CASE/01.a.txt" a.txt
sleep 0.02; cp "$CASE/02.b.txt" b.txt
"$BE" put a.txt b.txt >/dev/null
"$BE" post 'baseline msg'   >/dev/null

# Step 2: fork ?fix1 (cur stays on trunk)
"$BE" put '?./fix1' >/dev/null

# Step 3: switch to fix1, two commits editing a.txt
"$BE" get '?fix1' >/dev/null
sleep 0.02; cp "$CASE/03.a-fix1-c1.txt" a.txt
"$BE" put a.txt >/dev/null
"$BE" post 'c1 msg'   >/dev/null
sleep 0.02; cp "$CASE/04.a-fix1-c2.txt" a.txt
"$BE" put a.txt >/dev/null
"$BE" post 'c2 msg'   >/dev/null

# Step 4: back to trunk, fork ?fix2
"$BE" get '?..'      >/dev/null
"$BE" put '?./fix2' >/dev/null

# Step 5: switch to fix2, two commits editing b.txt
"$BE" get '?fix2' >/dev/null
sleep 0.02; cp "$CASE/05.b-fix2-c1.txt" b.txt
"$BE" put b.txt >/dev/null
"$BE" post 'c1 msg'   >/dev/null
sleep 0.02; cp "$CASE/06.b-fix2-c2.txt" b.txt
"$BE" put b.txt >/dev/null
"$BE" post 'c2 msg'   >/dev/null

# Step 6: switch to fix1, then rebase it onto ?fix2's tip via
# `be post ?fix2`.  fix1's a-edit stack replays on top of fix2's
# b-edit, so fix1.tip carries both file edits.
"$BE" get '?fix1' >/dev/null
must "$BE" post '?fix2' >/dev/null

# Final assertion: cur (?fix1) wt has both edits.
match "$CASE/07.a.want.txt" a.txt
match "$CASE/08.b.want.txt" b.txt
