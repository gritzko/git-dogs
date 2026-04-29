#include "GRAF.h"

#include <string.h>
#include <unistd.h>

#include "abc/FILE.h"
#include "abc/PATH.h"
#include "abc/PRO.h"
#include "dog/DPATH.h"
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

// --- GRAFOpen / GRAFClose ---

ok64 GRAFOpenBranch(home *h, u8cs branch, b8 rw) {
    sane(h != NULL && $ok(branch));
    a_pad(u8, nb, 256);
    call(DPATHBranchNormFeed, nb, branch);
    if (u8bDataLen(nb) != 0) return GRAFNOBR;
    ok64 o = HOMEOpenBranch(h, branch, rw);
    if (o != OK && o != HOMEOPEN) return o;
    return GRAFOpen(h, rw);
}

ok64 GRAFOpen(home *h, b8 rw) {
    sane(h);

    if (graf_is_open()) {
        if (rw && !graf_is_rw) return GRAFOPENRO;
        return GRAFOPEN;
    }

    graf *g = &GRAF;
    zerop(g);
    g->h = h;
    g->lock_fd = -1;
    g->out_fd = -1;
    graf_is_rw = rw;

    // Compose <root>/.dogs/graf on demand.
    a_dup(u8c, root_s, u8bDataC(h->root));
    a_cstr(rel, ".dogs/graf");
    a_path(dir, root_s, rel);

    // Worktree sharing: `.dogs/graf` may be a symlink into a shared
    // repo.  flock serializes writers only.  Readers open lockless
    // — DAG index runs are immutable once published (dag_index_write
    // uses tmp → rename) and dag_stack_open retries on ENOENT to
    // ride out compaction unlinks, so a reader never has to wait
    // for a writer.
    call(FILEMakeDirP, $path(dir));
    if (rw) {
        a_cstr(lockrel, ".lock");
        a_path(lockpath, $path(dir), lockrel);
        call(FILECreate, &g->lock_fd, $path(lockpath));
        call(FILELock, &g->lock_fd, rw);
    }

    call(dag_stack_open, &g->idx, $path(dir));

    call(u8bMap, g->arena, GRAF_ARENA_SIZE);

    done;
}

// --- Update: feed a single object (commit/tree/blob) into graf's DAG index ---

ok64 GRAFUpdate(u8 obj_type, sha1 const *sha, u8cs blob) {
    sane(1);
    return GRAFDagUpdate(obj_type, sha, blob);
}

ok64 GRAFClose(void) {
    sane(1);
    if (!graf_is_open()) return OK;
    graf *g = &GRAF;
    // Flush any pending ingest (runs the finish walk + compaction).
    if (g->ing) GRAFDagFinish();
    dag_stack_close(&g->idx);
    if (g->arena[0]) u8bUnMap(g->arena);
    if (g->lock_fd >= 0) FILEClose(&g->lock_fd);
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
        if (w <= 0) break;
        u8csFed(ser, (size_t)w);
    }

    Bu8rewind(graf_arena, mark);
    return OK;
}
