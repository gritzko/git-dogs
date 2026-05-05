#include "GRAF.h"

#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "abc/FILE.h"
#include "abc/PATH.h"
#include "abc/PRO.h"
#include "dog/DPATH.h"
#include "dog/DOG.h"
#include "dog/HOME.h"
#include "dog/HUNK.h"

// --- Producer-side staging state (legacy globals) ---
Bu8          graf_arena   = {};
int          graf_out_fd  = -1;
graf_emit_fn graf_emit    = NULL;

// --- Singleton ---

graf GRAF = {};

static b8 graf_is_open(void) { return GRAF.h != NULL; }
static b8 graf_is_rw = NO;

// --- GRAFOpenBranch / GRAFOpen / GRAFClose ---

#define GRAF_DIR_S       ".dogs"
#define GRAF_IDX_EXT     ".graf.idx"
#define GRAF_LOCK_S      ".lock.graf"
#define GRAF_LEAF_BRANCH_MAX 1024

//  Compose `<root>/.dogs/graf/<branch>` (with `<branch>` empty for
//  trunk).  `branch` is the canonical leaf-branch (trailing '/' if
//  non-empty).  `out` is NUL-terminated.
static ok64 graf_branch_dir(path8b out, home *h, u8cs branch) {
    sane(h && out);
    u8bReset(out);
    a_dup(u8c, root_s, u8bDataC(h->root));
    call(PATHu8bFeed, out, root_s);
    a_cstr(rel, GRAF_DIR_S);
    call(PATHu8bAdd, out, rel);
    if ($ok(branch) && !u8csEmpty(branch)) {
        a_dup(u8c, br, branch);
        //  Strip trailing '/' from canonical branch path before
        //  PATHu8bAdd (which inserts its own separator).
        if (!$empty(br) && *u8csLast(br) == '/') u8csShed1(br);
        if (!$empty(br)) call(PATHu8bAdd, out, br);
    }
    call(PATHu8bTerm, out);
    done;
}

//  YES iff `path` (NUL-terminated u8b) is an existing directory.
static b8 graf_dir_exists(path8s path) {
    struct stat st = {};
    if (FILEStat(&st, path) != OK) return NO;
    return (st.st_mode & S_IFMT) == S_IFDIR;
}

//  Walk one branch path component at a time, calling `cb` per prefix
//  dir (trunk first → leaf last).  `cb` receives a freshly-built
//  NUL-terminated path slice for each prefix dir.  Stops at first
//  non-OK return.
typedef ok64 (*graf_dir_cb)(graf *g, u8cs dir, void0p ctx);

static ok64 graf_walk_branch(graf *g, u8cs leaf, graf_dir_cb cb,
                              void0p ctx) {
    sane(g && cb);
    a_pad(u8, gdir, FILE_PATH_MAX_LEN);
    a_dup(u8c, root_s, u8bDataC(g->h->root));
    call(PATHu8bFeed, gdir, root_s);
    a_cstr(rel, GRAF_DIR_S);
    call(PATHu8bAdd, gdir, rel);
    call(PATHu8bTerm, gdir);

    //  Trunk first.
    {
        a_pad(u8, d, FILE_PATH_MAX_LEN);
        a_dup(u8c, gd, u8bDataC(gdir));
        call(PATHu8bFeed, d, gd);
        call(PATHu8bTerm, d);
        call(cb, g, $path(d), ctx);
    }
    if (u8csEmpty(leaf)) done;

    //  Each '/'-separated component, accumulating.
    a_pad(u8, d, FILE_PATH_MAX_LEN);
    a_dup(u8c, gd, u8bDataC(gdir));
    call(PATHu8bFeed, d, gd);
    u8cp p = leaf[0];
    u8cp seg_start = p;
    while (p <= leaf[1]) {
        b8 at_end = (p == leaf[1]);
        if (at_end || *p == '/') {
            if (p > seg_start) {
                u8cs seg = {seg_start, p};
                call(PATHu8bPush, d, seg);
                call(PATHu8bTerm, d);
                call(cb, g, $path(d), ctx);
                //  Drop the terminator byte we just appended so the
                //  next PATHu8bPush rebuilds correctly.
                ((u8 **)d)[2]--;
            }
            seg_start = p + 1;
        }
        p++;
    }
    done;
}

static ok64 graf_open_dir_cb(graf *g, u8cs dir, void0p ctx) {
    (void)ctx;
    if (!graf_dir_exists(dir)) return GRAFNOPATH;
    a_cstr(ext, GRAF_IDX_EXT);
    return DOGPupOpenAll(g->puppies, dir, ext);
}

void GRAFRefreshView(void) {
    graf *g = &GRAF;
    g->runs_n = 0;
    u32 n = DOGPupCount(g->puppies);
    for (u32 i = 0; i < n && g->runs_n < MSET_MAX_LEVELS; i++) {
        u8cs raw = {};
        DOGPupData(raw, g->puppies, i);
        if (raw[0] == NULL) continue;
        wh128cp base = (wh128cp)raw[0];
        size_t bytes = (size_t)(raw[1] - raw[0]);
        g->runs[g->runs_n][0] = base;
        g->runs[g->runs_n][1] = base + bytes / sizeof(wh128);
        g->runs_n++;
    }
}

void GRAFRuns(wh128cssp out) {
    out[0] = GRAF.runs;
    out[1] = GRAF.runs + GRAF.runs_n;
}

ok64 GRAFOpenBranch(home *h, u8cs branch, b8 rw) {
    sane(h != NULL && $ok(branch));

    //  Already open?  Compatible if the existing mode is at least as
    //  strong as the request.  Same conflict rule as KEEPOpenBranch.
    if (graf_is_open()) {
        if (rw && !graf_is_rw) return GRAFOPENRO;
        return GRAFOPEN;
    }

    //  Normalize the branch: trunk aliases (empty / main / master /
    //  trunk + `heads/` variants) → empty; non-trunk gains trailing
    //  '/'.  Mirrors KEEPOpenBranch.
    a_pad(u8, nb, GRAF_LEAF_BRANCH_MAX);
    call(DPATHBranchNormFeed, nb, branch);
    a_dup(u8c, norm, u8bDataC(nb));

    //  Register on the home singleton (idempotent re-opens absorbed).
    {
        ok64 o = HOMEOpenBranch(h, branch, rw);
        if (o != OK && o != HOMEOPEN && o != HOMEROBR && o != HOMEMAX)
            return o;
    }

    graf *g = &GRAF;
    zerop(g);
    g->h = h;
    g->lock_fd = -1;
    g->out_fd = -1;
    graf_is_rw = rw;

    call(kv32bAllocate, g->puppies, FILE_MAX_OPEN);

    //  Stash the canonical leaf-branch bytes in graf-owned storage.
    if (u8csLen(norm) >= GRAF_LEAF_BRANCH_MAX) return GRAFFAIL;
    call(u8bAllocate, g->leaf_branch, GRAF_LEAF_BRANCH_MAX);
    call(PATHu8bTerm, g->leaf_branch);
    if (!u8csEmpty(norm)) call(PATHu8bFeed, g->leaf_branch, norm);

    //  Trunk dir always exists after this — first writer creates it.
    a_pad(u8, trunkdir, FILE_PATH_MAX_LEN);
    {
        u8cs empty = {};
        ok64 to = graf_branch_dir(trunkdir, h, empty);
        if (to != OK) {
            DOGPupClose(g->puppies);
            u8bFree(g->leaf_branch);
            zerop(g); graf_is_rw = NO;
            return to;
        }
    }
    call(FILEMakeDirP, $path(trunkdir));

    //  Walk trunk → leaf, scanning each branch dir for `<seqno>.graf.idx`.
    {
        a_dup(u8c, leaf, u8bDataC(g->leaf_branch));
        ok64 wo = graf_walk_branch(g, leaf, graf_open_dir_cb, NULL);
        if (wo != OK) {
            DOGPupClose(g->puppies);
            u8bFree(g->leaf_branch);
            zerop(g); graf_is_rw = NO;
            return wo;
        }
    }

    GRAFRefreshView();

    //  Worktree sharing: lock the LEAF dir (writes only land in the
    //  deepest dir).  For trunk leaf this is `<.dogs/graf>/.lock`.
    //  Readers open lockless — runs are immutable (tmp+rename
    //  publication) and DOGPupOpenAll retries on ENOENT.
    if (rw) {
        a_pad(u8, leafdir, FILE_PATH_MAX_LEN);
        a_dup(u8c, leaf, u8bDataC(g->leaf_branch));
        call(graf_branch_dir, leafdir, h, leaf);
        a_pad(u8, lockpath, FILE_PATH_MAX_LEN);
        a_dup(u8c, lds, u8bDataC(leafdir));
        call(PATHu8bFeed, lockpath, lds);
        a_cstr(lockrel, GRAF_LOCK_S);
        call(PATHu8bAdd, lockpath, lockrel);
        call(PATHu8bTerm, lockpath);
        call(FILECreate, &g->lock_fd, $path(lockpath));
        call(FILELock,   &g->lock_fd, rw);
    }

    call(u8bMap, g->arena, GRAF_ARENA_SIZE);

    done;
}

ok64 GRAFOpen(home *h, b8 rw) {
    static u8c const _zero = 0;
    u8cs trunk = {(u8cp)&_zero, (u8cp)&_zero};
    return GRAFOpenBranch(h, trunk, rw);
}

ok64 GRAFClose(void) {
    sane(1);
    if (!graf_is_open()) return OK;
    graf *g = &GRAF;
    // Flush any pending ingest (runs the finish walk + compaction).
    if (g->ing) GRAFDagFinish();
    if (!BNULL(g->puppies))     DOGPupClose(g->puppies);
    if (!BNULL(g->leaf_branch)) u8bFree(g->leaf_branch);
    if (g->arena[0]) u8bUnMap(g->arena);
    if (g->lock_fd >= 0) FILEClose(&g->lock_fd);
    g->runs_n = 0;
    g->out_fd = -1;
    g->emit = NULL;
    g->h = NULL;
    graf_is_rw = NO;
    done;
}

ok64 GRAFArenaInit(void) {
    if (graf_arena[0] != NULL) {
        ((u8 **)graf_arena)[2] = graf_arena[1];  // reset idle to start
        return OK;
    }
    return u8bMap(graf_arena, GRAF_ARENA_SIZE);
}

void GRAFArenaCleanup(void) {
    if (graf_arena[0] != NULL)
        ((u8 **)graf_arena)[2] = graf_arena[1];
}

ok64 GRAFHunkEmit(hunk const *hk, void *ctx) {
    sane(hk != NULL);
    (void)ctx;
    if (graf_emit == NULL || graf_out_fd < 0) return OK;

    // Reuse the trailing portion of graf_arena as TLV scratch.
    range64 mark;
    Bu8mark(graf_arena, &mark);
    u8cp start = u8bIdleHead(graf_arena);
    if (graf_emit(u8bIdle(graf_arena), hk) != OK) {
        Bu8rewind(graf_arena, mark);
        return OK;
    }

    u8cs ser = {start, u8bIdleHead(graf_arena)};
    while (!$empty(ser)) {
        ssize_t w = write(graf_out_fd, ser[0], $len(ser));
        if (w < 0) {
            if (errno == EINTR) continue;
            //  Pager exited — close our end so subsequent emits early-
            //  return at the top guard.  Streaming producers (LOG.c)
            //  poll graf_out_fd to break their walk.
            if (errno == EPIPE) graf_out_fd = -1;
            break;
        }
        if (w == 0) break;
        u8csFed(ser, (size_t)w);
    }

    Bu8rewind(graf_arena, mark);
    return OK;
}
