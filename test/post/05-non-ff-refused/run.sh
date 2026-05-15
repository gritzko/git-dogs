#!/bin/sh
#  post/05-non-ff-refused — `be post //origin` refuses when cur is
#  not a fast-forward of the remote's counterpart.  Per VERBS.md §POST
#  POST is commit-and/or-FF only (never rebase); divergent remotes are
#  reconciled with `be patch //origin?` + `be post`, not by POST alone.
#
#  Setup (matches the canonical "we diverged from origin" scenario):
#    A  — origin's seed.
#    B  — origin advances (server-side commit on top of A).
#    C  — client commits locally on top of A (parent = A).
#  cur is at C; origin's tip is B; both share A as the fork point.
#  cur is NOT a descendant of B, so `be post //origin` must refuse.
#
#  Asserts:
#    * `be post //localhost` exits non-zero.
#    * stderr carries the receive-pack "non-fast-forward" reason.
#    * hello.c is left untouched (still C's bytes — POST didn't rebase,
#      didn't merge, didn't reset).
#
#  Requires passwordless ssh to localhost (gated under WITH_SSH).

. "$(dirname "$0")/../../lib/case.sh"

[ -n "${HOME:-}" ] || { echo "post/05: \$HOME unset" >&2; exit 1; }
case "$SCRATCH" in
    "$HOME"/*) ;;
    *) echo "post/05: SCRATCH=$SCRATCH not under \$HOME=$HOME" >&2
       echo "         keeper's ssh-side path resolution requires it" >&2
       exit 1;;
esac
REL_SCRATCH=${SCRATCH#$HOME/}

ORIGIN="$SCRATCH/origin.git"
SEED="$SCRATCH/seed"
REL_ORIGIN="$REL_SCRATCH/origin.git"

cd "$SCRATCH"

# ====================================================================
# 1. seed origin with version A on master
# ====================================================================
git init --bare "$ORIGIN" >/dev/null
git init "$SEED" >/dev/null
git -C "$SEED" config user.email t@t
git -C "$SEED" config user.name  T
git -C "$SEED" checkout -b master >/dev/null || true
sleep 0.02; cp "$CASE/01.A.hello.c" "$SEED/hello.c"
git -C "$SEED" add . >/dev/null
git -C "$SEED" commit -qm A
git -C "$SEED" push -q "$ORIGIN" master:master

# ====================================================================
# 2. clone into wt via ssh
# ====================================================================
mkdir wt && cd wt
"$BE" get "ssh://localhost/$REL_ORIGIN?master" \
    >01.clone.got.out 2>01.clone.got.err
match "$CASE/01.A.hello.c" hello.c

# ====================================================================
# 3. advance origin to version B (one commit on top of A)
# ====================================================================
cd ..
sleep 0.02; cp "$CASE/02.B.hello.c" "$SEED/hello.c"
git -C "$SEED" add . >/dev/null
git -C "$SEED" commit -qm B
git -C "$SEED" push -q "$ORIGIN" master:master

# ====================================================================
# 4. local commit on cur (parent = A) — version C
# ====================================================================
cd wt
sleep 0.02; cp "$CASE/03.client.hello.c" hello.c
"$BE" post 'client edits' >02.post.got.out 2>02.post.got.err
match "$CASE/03.client.hello.c" hello.c

# ====================================================================
# 5. fetch via HEAD so the cache knows origin advanced to B
# ====================================================================
"$BE" head "ssh://localhost/$REL_ORIGIN" \
    >03.head.got.out 2>03.head.got.err

# ====================================================================
# 6. `be post //localhost` — cur(C) is NOT a descendant of remote(B);
#    POST is commit-or-FF only, so this MUST refuse.
# ====================================================================
mustnt "$BE" post "//localhost" >04.post.got.out 2>04.post.got.err
grep -q 'non-fast-forward' 04.post.got.err || {
    echo "post/05: expected 'non-fast-forward' in stderr, got:" >&2
    cat 04.post.got.err >&2
    exit 1
}

# ====================================================================
# 7. wt's hello.c must be UNTOUCHED — POST didn't rebase, didn't merge,
#    didn't reset.  The client's local commit (C) is still the wt state.
# ====================================================================
match "$CASE/03.client.hello.c" hello.c
