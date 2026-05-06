//  UNPK: single-pass packfile indexer.  See UNPK.h for the contract.
//
//  Phase 1 (serial) — scan the pack, record `(offset, type)` per
//  object, build the OFS_DELTA forest by linking each delta to its
//  parent's offset, slot REF_DELTA waiters into a sha-keyed list.
//
//  Phase A (serial) — resolve every base object: inflate, hash, emit
//  one wh128 entry, drain waiters.
//
//  Phase B (parallel via fork) — DFS each base's subtree applying
//  deltas.  Round-robin roots across `nproc` workers; per-worker
//  scratch bufs are allocated pre-fork so each child gets a COW-
//  private copy of `buf_a` / `buf_b` and its own resolved[] view.
//  No locks needed: each child mutates its own COW pages of nodes/
//  resolved, and emits go to a per-worker SHARED-mmap'd slab so
//  the parent can collect them after waitpid.
//
//  Phase C (serial) — thin-pack REF_DELTA fallback for waiters whose
//  base lives in an earlier pack.
#include "UNPK.h"

#include "DELT.h"
#include "PACK.h"
#include "ZINF.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "abc/PRO.h"

// wh128 sort/dedup templates
#define X(M, name) M##wh128##name
#include "abc/QSORTx.h"
#undef X

#define UNPK_MAX_CHAIN 64
#define UNPK_MAX_WORKERS 32
#define UNPK_WORKER_BUFSZ (1ULL << 30)   //  1 GB per worker per buf, anon-mmap COW

//  DFS node for the delta forest.
//  nodes[] is 1-based; index 0 is sentinel.
typedef struct { u64 offset; u32 child; u32 sibling; } unpk_node;

//  Waiter: REF_DELTA indexed by sha8 of its base.
//  val = 1-based index into nodes[].
static void unpk_drain_waiters(wh128cs waiters, unpk_node *nodes,
                               b8 *resolved, u64 sha_key, u32 parent_idx) {
    wh128cp wbuf = waiters[0];
    size_t wlen = (size_t)(waiters[1] - waiters[0]);
    size_t lo = 0, hi = wlen;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (wbuf[mid].key < sha_key) lo = mid + 1;
        else hi = mid;
    }
    for (size_t j = lo; j < wlen && wbuf[j].key == sha_key; j++) {
        u32 w = (u32)wbuf[j].val;
        if (resolved[w]) continue;
        nodes[w].sibling = nodes[parent_idx].child;
        nodes[parent_idx].child = w;
    }
}

//  Emit one wh128 entry for a resolved object at `obj_off` in the log.
static ok64 unpk_emit(Bwh128 out, u32 file_id,
                       u8 type, sha1 const *sha, u64 obj_off) {
    wh128 e = {
        .key = keepKeyPack(type, WHIFFHashlet60(sha)),
        .val = wh64Pack(KEEP_VAL_FLAGS, file_id, obj_off),
    };
    return wh128bPush(out, &e);
}

//  Fire the per-object emit callback with `(type, sha, content)`.
//  No path derivation — consumers that need a path parse trees on
//  their own at Close-pass time.
static void unpk_dispatch(unpk_in const *in,
                           u8 type, sha1 const *sha, u8cs content) {
    if (!in->emit) return;
    in->emit(in->emit_ctx, type, sha, content);
}

//  Per-worker shared region (MAP_SHARED|MAP_ANONYMOUS).  The child's
//  writes here survive its `_exit(0)`; the parent reads after wait.
//  Layout: nemit (count of entries written) + 8-byte pad to align
//  the wh128 flexible array (16-byte alignment), then entries[].
typedef struct {
    u64   nemit;
    u64   _pad;
    wh128 entries[];
} unpk_shared;

typedef struct {
    u8cp     packbase;
    u64      packlen;
    u32      file_id;
    u32      worker_id;
    u32      nworkers;
    u32      count;
    u64     *offsets;
    u8      *types;
    unpk_node *nodes;
    b8      *resolved;
    wh128cs  waiters;
    unpk_in const *in;
    Bu8      buf_a;       // private (COW per fork)
    Bu8      buf_b;       // private (COW per fork)
    unpk_shared *shared;  // shared mmap (parent reads post-wait)
    size_t   shared_bytes;
    u32      entries_cap;
} unpk_worker;

//  Append one resolved entry to the worker's shared slab.  No
//  Bwh128 wrapper here — direct array index + counter; the parent
//  reads `shared->nemit` after waitpid to know how many entries
//  the child wrote.  Returns 0 on overflow (silent drop, mirrors
//  the prior `wh128bPush != OK ⇒ skipped++` behaviour).
static b8 unpk_worker_emit(unpk_worker *w, u32 file_id,
                            u8 type, sha1 const *sha, u64 obj_off) {
    if (w->shared->nemit >= w->entries_cap) return 0;
    wh128 *slot = &w->shared->entries[w->shared->nemit++];
    slot->key = keepKeyPack(type, WHIFFHashlet60(sha));
    slot->val = wh64Pack(KEEP_VAL_FLAGS, file_id, obj_off);
    return 1;
}

//  Per-worker DFS over its slice of root indices (round-robin
//  `worker_id` modulo `nworkers`).  Same algorithm as the original
//  serial phase B — just operates on the worker's own scratch
//  buffers (private/COW) and a shared emit slab the parent will
//  drain post-wait.  Each worker only mutates nodes within its own
//  subtrees, so concurrent runs are race-free.
static void unpk_worker_main(unpk_worker *w) {
    u8cp packbase = w->packbase;
    u64  packlen  = w->packlen;
    u64 *offsets  = w->offsets;
    u8  *types    = w->types;
    unpk_node *nodes = w->nodes;
    b8  *resolved = w->resolved;
    wh128cs waiters = {w->waiters[0], w->waiters[1]};

    struct { u8p d_start; u8p d_end; u32 node; u8 base_type; }
        stk[UNPK_MAX_CHAIN];

    for (u32 root_idx = 1 + w->worker_id;
         root_idx <= w->count;
         root_idx += w->nworkers) {
        if (!nodes[root_idx].child) continue;
        if (!resolved[root_idx]) continue;
        if (types[root_idx - 1] < 1 || types[root_idx - 1] > 4) continue;

        u8 root_type = types[root_idx - 1];
        u8bReset(w->buf_a);
        pack_obj robj = {};
        u8cs rfrom = {packbase + offsets[root_idx - 1], packbase + packlen};
        if (PACKDrainObjHdr(rfrom, &robj) != OK) continue;
        if (robj.size > u8bIdleLen(w->buf_a)) continue;
        u8p rs = u8bIdleHead(w->buf_a);
        u8s rinto = {rs, u8bTerm(w->buf_a)};
        if (PACKInflate(rfrom, rinto, robj.size) != OK) continue;
        u8bFed(w->buf_a, robj.size);

        int top = 0;
        stk[0].d_start = rs;
        stk[0].d_end = rs + robj.size;
        stk[0].node = root_idx;
        stk[0].base_type = root_type;

        while (top >= 0) {
            u32 cur = stk[top].node;
            u32 child = nodes[cur].child;
            if (!child) {
                if (top > 0) ((u8**)w->buf_a)[2] = stk[top].d_start;
                top--;
                continue;
            }
            nodes[cur].child = nodes[child].sibling;

            if (top + 1 >= UNPK_MAX_CHAIN) continue;

            u8p  base_s  = stk[top].d_start;
            u64  base_sz = (u64)(stk[top].d_end - stk[top].d_start);

            pack_obj dobj = {};
            u8cs dfrom = {packbase + offsets[child - 1], packbase + packlen};
            if (PACKDrainObjHdr(dfrom, &dobj) != OK) continue;
            if (dobj.size > u8bIdleLen(w->buf_b)) continue;

            u8bReset(w->buf_b);
            u8s dinto = {u8bIdleHead(w->buf_b), u8bTerm(w->buf_b)};
            if (PACKInflate(dfrom, dinto, dobj.size) != OK) continue;

            u8cs delta_sl = {u8bIdleHead(w->buf_b), u8bIdleHead(w->buf_b) + dobj.size};
            u8cs base_sl  = {base_s, base_s + base_sz};
            u8p rstart = u8bIdleHead(w->buf_a);
            u8g aout = {rstart, rstart, u8bTerm(w->buf_a)};
            if (DELTApply(delta_sl, base_sl, aout) != OK) continue;
            u64 rsz = u8gLeftLen(aout);
            u8bFed(w->buf_a, rsz);

            sha1 sha = {};
            u8csc content = {rstart, rstart + rsz};
            KEEPObjSha(&sha, stk[0].base_type, content);
            if (!unpk_worker_emit(w, w->file_id, stk[0].base_type,
                                  &sha, offsets[child - 1])) continue;
            resolved[child] = YES;

            {
                u8cs dct = {rstart, rstart + rsz};
                unpk_dispatch(w->in, stk[0].base_type, &sha, dct);
            }

            u64 sha_key = 0;
            memcpy(&sha_key, sha.data, 8);
            unpk_drain_waiters(waiters, nodes, resolved, sha_key, child);

            top++;
            stk[top].d_start = rstart;
            stk[top].d_end = rstart + rsz;
            stk[top].node = child;
            stk[top].base_type = stk[0].base_type;
        }
    }
}

ok64 UNPKIndex(keeper *k, unpk_in const *in,
               Bwh128 out, unpk_stats *stats) {
    sane(k && in && out);

    u8cp packbase = in->pack[0];
    if (in->pack[1] < packbase) return UNPKBADFMT;
    u64 packlen = (u64)(in->pack[1] - packbase);
    if (in->scan_start > packlen || in->scan_end > packlen ||
        in->scan_start > in->scan_end) return UNPKBADFMT;

    u32 count = in->count;
    u32 file_id = in->file_id;

    unpk_stats st = {};

    //  Pre-scan: record (offset, type) per object.  Inflates each
    //  object into k->buf1 purely to advance the read cursor past
    //  compressed bytes.
    u64 *offsets = calloc(count, sizeof(u64));
    u8  *types   = calloc(count, 1);
    if (!offsets || !types) { free(offsets); free(types); return UNPKNOROOM; }

    u8cs scan = {packbase + in->scan_start, packbase + in->scan_end};
    u32 scanned = 0;
    for (u32 i = 0; i < count; i++) {
        offsets[i] = (u64)(scan[0] - packbase);
        pack_obj obj = {};
        if (PACKDrainObjHdr(scan, &obj) != OK) break;
        types[i] = obj.type;
        u8bReset(k->buf1);
        if (ZINFInflate(u8bIdle(k->buf1), scan) != OK) break;
        scanned++;
    }
    if (scanned < count) {
        fprintf(stderr, "unpk: scan incomplete %u/%u\n", scanned, count);
    }

    //  Forest: link OFS_DELTA -> parent by offset, stash REF_DELTA waiters.
    unpk_node *nodes = calloc((size_t)count + 1, sizeof(unpk_node));
    b8 *resolved = calloc((size_t)count + 1, 1);
    Bwh128 waiters_buf = {};
    wh128bAllocate(waiters_buf, count ? count : 1);
    if (!nodes || !resolved) {
        free(nodes); free(resolved); free(offsets); free(types);
        wh128bFree(waiters_buf);
        return UNPKNOROOM;
    }
    for (u32 i = 0; i < count; i++) nodes[i + 1].offset = offsets[i];

    //  OFS_DELTA edges
    for (u32 i = 0; i < count; i++) {
        if (types[i] != PACK_OBJ_OFS_DELTA) continue;
        pack_obj obj = {};
        u8cs from = {packbase + offsets[i], packbase + packlen};
        if (PACKDrainObjHdr(from, &obj) != OK) continue;
        if (obj.ofs_delta > offsets[i]) continue;
        u64 base_off = offsets[i] - obj.ofs_delta;
        u32 lo = 0, hi = count;
        while (lo < hi) {
            u32 mid = lo + (hi - lo) / 2;
            if (offsets[mid] < base_off) lo = mid + 1;
            else hi = mid;
        }
        if (lo < count && offsets[lo] == base_off) {
            u32 parent = lo + 1, me = i + 1;
            nodes[me].sibling = nodes[parent].child;
            nodes[parent].child = me;
        }
    }

    //  REF_DELTA waiters keyed by sha8 of base
    for (u32 i = 0; i < count; i++) {
        if (types[i] != PACK_OBJ_REF_DELTA) continue;
        pack_obj obj = {};
        u8cs from = {packbase + offsets[i], packbase + packlen};
        if (PACKDrainObjHdr(from, &obj) != OK) { st.skipped++; continue; }
        u64 sha_key = 0;
        memcpy(&sha_key, obj.ref_delta[0], 8);
        wh128 w = { .key = sha_key, .val = i + 1 };
        wh128bPush(waiters_buf, &w);
    }
    a_dup(wh128, wsorted, wh128bData(waiters_buf));
    wh128sSort(wsorted);
    wh128cs waiters = {wsorted[0], wsorted[1]};

    //  Resolve base objects; drain waiters on each base's sha.
    u8bReset(k->buf1);
    for (u32 i = 0; i < count; i++) {
        if (types[i] < 1 || types[i] > 4) continue;
        pack_obj obj = {};
        u8cs from = {packbase + offsets[i], packbase + packlen};
        if (PACKDrainObjHdr(from, &obj) != OK) { st.skipped++; continue; }
        if (obj.size > u8bIdleLen(k->buf1)) { st.skipped++; continue; }
        u8p cs = u8bIdleHead(k->buf1);
        u8s into = {cs, u8bTerm(k->buf1)};
        if (PACKInflate(from, into, obj.size) != OK) { st.skipped++; continue; }

        sha1 sha = {};
        u8csc content = {cs, cs + obj.size};
        KEEPObjSha(&sha, obj.type, content);
        if (unpk_emit(out, file_id, types[i], &sha, offsets[i]) != OK) {
            st.skipped++; continue;
        }
        st.indexed++;
        st.base_count++;
        resolved[i + 1] = YES;

        {
            u8cs dct = {cs, cs + obj.size};
            unpk_dispatch(in, types[i], &sha, dct);
        }

        u64 sha_key = 0;
        memcpy(&sha_key, sha.data, 8);
        unpk_drain_waiters(waiters, nodes, resolved, sha_key, i + 1);
        //  keep buf1 contents for the DFS walk below
    }

    //  Phase B — parallel DFS through each base's subtree.  Round-
    //  robin roots across nproc workers; each worker has its own
    //  apply-stack scratch (buf_a holds the live base-and-children
    //  resolved bytes, buf_b is the per-delta inflate scratch) and
    //  its own wh128 emit buffer.  Resolved[] / nodes[].child writes
    //  stay race-free because each worker only touches nodes within
    //  the subtrees it owns (workers process disjoint root sets).
    //
    //  drain_waiters mutates parent.child for late-arriving REF_DELTA
    //  waiters — that parent is the worker's own current node, so
    //  same-thread, no lock needed.
    //  Worker count: scale with pack size, not just nproc.  Each
    //  worker pays a fixed cost (pthread create + 2× 1 GB anon mmap
    //  for buf_a/buf_b) which only amortises when the worker has
    //  real work to do.  Toy-repo tests (a few KB) and small
    //  refspec deltas should run single-threaded; multi-MB packs
    //  scale up to nproc.
    //
    //  Threshold = `UNPK_MB_PER_WORKER` MB per worker (default 16),
    //  capped at `_SC_NPROCESSORS_ONLN` and UNPK_MAX_WORKERS.
    //  `UNPK_THREADS=N` env override wins for ad-hoc benchmarking.
    u64 packbytes = packlen;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu < 1) ncpu = 1;
    u64 mb_per_worker = 16;
    char const *mbpw_env = getenv("UNPK_MB_PER_WORKER");
    if (mbpw_env != NULL && *mbpw_env) {
        u64 m = (u64)atol(mbpw_env);
        if (m > 0) mb_per_worker = m;
    }
    u64 nw_by_size = packbytes / (mb_per_worker << 20);
    if (nw_by_size < 1) nw_by_size = 1;
    long nw_l = (long)nw_by_size;
    if (nw_l > ncpu) nw_l = ncpu;
    char const *thr_env = getenv("UNPK_THREADS");
    if (thr_env != NULL && *thr_env) {
        long t = atol(thr_env);
        if (t >= 1) nw_l = t;
    }
    if (nw_l > UNPK_MAX_WORKERS) nw_l = UNPK_MAX_WORKERS;
    if (nw_l < 1) nw_l = 1;
    u32 nw = (u32)nw_l;

    unpk_worker workers[UNPK_MAX_WORKERS] = {};
    pid_t       pids[UNPK_MAX_WORKERS]    = {};
    b8          buf_a_ok[UNPK_MAX_WORKERS] = {};
    b8          buf_b_ok[UNPK_MAX_WORKERS] = {};
    b8          shared_ok[UNPK_MAX_WORKERS] = {};

    //  Each worker's emit slab caps at `count` (worst case every
    //  resolved object lands in one worker).  MAP_SHARED|ANON pages
    //  are demand-faulted, so the unused tail costs no RAM.
    u32 entries_cap = (count ? count : 1);
    size_t shared_bytes = sizeof(unpk_shared) +
                          (size_t)entries_cap * sizeof(wh128);

    for (u32 w = 0; w < nw; w++) {
        workers[w] = (unpk_worker){
            .packbase  = packbase,
            .packlen   = packlen,
            .file_id   = file_id,
            .worker_id = w,
            .nworkers  = nw,
            .count     = count,
            .offsets   = offsets,
            .types     = types,
            .nodes     = nodes,
            .resolved  = resolved,
            .in        = in,
            .entries_cap = entries_cap,
            .shared_bytes = shared_bytes,
        };
        workers[w].waiters[0] = waiters[0];
        workers[w].waiters[1] = waiters[1];
        if (u8bMap(workers[w].buf_a, UNPK_WORKER_BUFSZ) != OK) goto worker_alloc_fail;
        buf_a_ok[w] = YES;
        if (u8bMap(workers[w].buf_b, UNPK_WORKER_BUFSZ) != OK) goto worker_alloc_fail;
        buf_b_ok[w] = YES;
        void *p = mmap(NULL, shared_bytes,
                       PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) goto worker_alloc_fail;
        workers[w].shared = (unpk_shared *)p;
        workers[w].shared->nemit = 0;
        shared_ok[w] = YES;
    }
    goto worker_alloc_ok;
worker_alloc_fail:
    for (u32 w = 0; w < nw; w++) {
        if (buf_a_ok[w])  u8bUnMap(workers[w].buf_a);
        if (buf_b_ok[w])  u8bUnMap(workers[w].buf_b);
        if (shared_ok[w]) munmap(workers[w].shared, workers[w].shared_bytes);
    }
    wh128bFree(waiters_buf);
    free(resolved); free(nodes); free(offsets); free(types);
    return UNPKNOROOM;
worker_alloc_ok:;

    //  Spawn workers 1..nw-1 via fork(); the parent runs worker 0
    //  in-place so the common nproc=1 case has no fork overhead.
    //  Each child inherits keeper's mmaps + a COW-private copy of
    //  buf_a / buf_b, writes its emits into the shared slab, and
    //  _exit(0)s.  Parent reads back via the shared mmap.
    for (u32 w = 1; w < nw; w++) {
        pid_t pid = fork();
        if (pid < 0) {
            //  Fork failed — run this worker inline in the parent.
            pids[w] = 0;
            unpk_worker_main(&workers[w]);
            continue;
        }
        if (pid == 0) {
            unpk_worker_main(&workers[w]);
            _exit(0);
        }
        pids[w] = pid;
    }
    unpk_worker_main(&workers[0]);
    for (u32 w = 1; w < nw; w++) {
        if (pids[w] > 0) {
            int status = 0;
            (void)waitpid(pids[w], &status, 0);
        }
    }

    //  Merge per-worker output into the caller's `out` buffer.
    //  Phase B's `indexed` count = sum of per-worker `nemit`s.
    for (u32 w = 0; w < nw; w++) {
        u64 nemit = workers[w].shared->nemit;
        wh128 const *src = workers[w].shared->entries;
        for (u64 i = 0; i < nemit; i++) {
            if (wh128bPush(out, &src[i]) != OK) { st.skipped++; break; }
        }
        st.indexed += (u32)nemit;
        u8bUnMap(workers[w].buf_a);
        u8bUnMap(workers[w].buf_b);
        munmap(workers[w].shared, workers[w].shared_bytes);
    }

    //  Thin-pack fallback: REF_DELTAs whose base lives in an earlier
    //  pack.  KEEPGet pulls the base into k->buf3; delta inflates to
    //  k->buf4; apply into k->buf1.
    for (u32 i = 0; i < count; i++) {
        if (resolved[i + 1]) continue;
        if (types[i] != PACK_OBJ_REF_DELTA) continue;

        pack_obj obj = {};
        u8cs from = {packbase + offsets[i], packbase + packlen};
        if (PACKDrainObjHdr(from, &obj) != OK) { st.skipped++; continue; }

        u64 base_hashlet = WHIFFHashlet60((sha1cp)obj.ref_delta[0]);
        u8 base_type = 0;
        u8bReset(k->buf3);
        if (KEEPGet(k, base_hashlet, 15, k->buf3, &base_type) != OK) {
            st.skipped++; continue;
        }

        u8bReset(k->buf4);
        u64 idle_before = u8bIdleLen(k->buf4);
        if (ZINFInflate(u8bIdle(k->buf4), from) != OK) { st.skipped++; continue; }
        u64 produced = idle_before - u8bIdleLen(k->buf4);
        if (produced == 0) { st.skipped++; continue; }
        u8bFed(k->buf4, produced);

        u8bReset(k->buf1);
        a_dup(u8c, delta_sl, u8bDataC(k->buf4));
        a_dup(u8c, base_sl, u8bData(k->buf3));
        u8p rstart = u8bIdleHead(k->buf1);
        u8g aout = {rstart, rstart, u8bTerm(k->buf1)};
        if (DELTApply(delta_sl, base_sl, aout) != OK) { st.skipped++; continue; }
        u64 rsz = u8gLeftLen(aout);

        sha1 sha = {};
        u8csc content = {rstart, rstart + rsz};
        KEEPObjSha(&sha, base_type, content);
        if (unpk_emit(out, file_id, base_type, &sha, offsets[i]) != OK) {
            st.skipped++; continue;
        }
        st.indexed++;
        st.cross++;
        resolved[i + 1] = YES;

        {
            u8cs dct = {rstart, rstart + rsz};
            unpk_dispatch(in, base_type, &sha, dct);
        }
    }

    wh128bFree(waiters_buf);
    free(resolved);
    free(nodes);
    free(offsets);
    free(types);

    if (stats) *stats = st;
    done;
}
