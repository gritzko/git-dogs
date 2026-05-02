//  DAG: graf's commit-graph index, streaming ingest.
//
//  Fed via GRAFUpdate one COMMIT object at a time (TREE/BLOB
//  callbacks are accepted but ignored — only commit→parent and
//  commit→tree edges are recorded).  Finish flushes the pending
//  batch and triggers compaction.  No historical keeper lookups.
//
//  Layout:
//      .dogs/graf/0000000001.idx   sorted wh128 runs (LSM)
//
#include "DAG.h"
#include "GRAF.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "abc/FILE.h"
#include "abc/HEX.h"
#include "abc/KV.h"
#include "abc/PATH.h"
#include "abc/PRO.h"
#include "abc/RAP.h"
#include "abc/RON.h"
#include "dog/DPATH.h"
#include "dog/SHA1.h"
#include "keeper/GIT.h"

// Resolve a 40-bit object hashlet.  Prefer the caller-supplied SHA
// (the UNPK hot path has it) — falls back to computing it from the
// object body for callers that don't (e.g. `graf index`'s manual
// reindex walk at graf/INDEX.c).
static u64 dag_obj_hashlet(u8 obj_type, sha1 const *sha, u8cs body) {
    if (sha) return WHIFFHashlet60(sha);

    char hdr[32];
    char const *tn = "blob";
    switch (obj_type) {
        case DOG_OBJ_COMMIT: tn = "commit"; break;
        case DOG_OBJ_TREE:   tn = "tree";   break;
        case DOG_OBJ_BLOB:   tn = "blob";   break;
        case DOG_OBJ_TAG:    tn = "tag";    break;
    }
    int hlen = snprintf(hdr, sizeof(hdr), "%s %zu",
                        tn, (size_t)u8csLen(body));
    if (hlen < 0 || (size_t)hlen >= sizeof(hdr)) return 0;

    SHA1state st;
    SHA1Open(&st);
    u8cs hs = {(u8cp)hdr, (u8cp)hdr + hlen + 1};  // include trailing NUL
    SHA1Feed(&st, hs);
    SHA1Feed(&st, body);
    sha1 out = {};
    SHA1DCFinal(out.data, &st);
    return WHIFFHashlet60(&out);
}

// --- Template instantiations for wh128 (sort, merge, hash).
// Bx.h already instantiated via dog/WHIFF.h.
#define X(M, name) M##wh128##name
#include "abc/QSORTx.h"
#include "abc/HITx.h"
#include "abc/HASHx.h"
#undef X

// --- Constants ---

#define DAG_DIR         ".dogs"
#define GRAF_IDX_EXT    ".graf.idx"
#define DAG_SEQNO_W     10
#define DAG_BATCH       (1 << 18)   // 256K entries per flush

// --- Ingest state (opaque to callers) ---

struct dag_ingest {
    wh128  *batch;          // emit buffer
    size_t  batch_len;
    size_t  batch_cap;
    u8      finished;
};

// --- COMMIT bookmark dir existence helpers ---

static b8 dag_is_hex_sha(char const *s, size_t len) {
    if (len < 40) return NO;
    for (int i = 0; i < 40; i++) {
        u8 c = (u8)s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return NO;
    }
    return YES;
}

// --- LSM file I/O ---
//
//  Reads come from `GRAF.puppies` (set up by `GRAFOpenBranch` walking
//  trunk → … → leaf).  Writes go to the leaf branch dir via
//  `DOGPupCreate`; compaction uses `DOGPupThinTail` + `DOGPupCreate`
//  (matches keeper's `KEEPCompact`).  No more hand-rolled
//  `<seqno>.idx` scanning here — the puppy stack is the source of
//  truth, and `GRAFRefreshView` keeps the typed `wh128cs` view in
//  sync.

//  Compose the leaf branch dir for `<root>/.dogs/graf/<leaf>` and
//  feed it into `out` (NUL-terminated).  Mirrors `keep_branch_dir`.
static ok64 graf_leaf_dir(path8b out, home *h, u8cs leaf_branch) {
    sane(h && $ok(leaf_branch) && out);
    u8bReset(out);
    a_dup(u8c, root_s, u8bDataC(h->root));
    call(PATHu8bFeed, out, root_s);
    a_cstr(rel, ".dogs");
    call(PATHu8bAdd, out, rel);
    if (!u8csEmpty(leaf_branch)) {
        a_dup(u8c, br, leaf_branch);
        if (!$empty(br) && *u8csLast(br) == '/') u8csShed1(br);
        if (!$empty(br)) call(PATHu8bAdd, out, br);
    }
    call(PATHu8bTerm, out);
    done;
}

//  Append `run` as a new puppy under the leaf branch dir.  Refreshes
//  GRAF's typed view so subsequent lookups see the new run.
static ok64 dag_index_write_leaf(graf *g, wh128cs run) {
    sane(g);
    if ($empty(run)) done;
    a_pad(u8, leafdir, FILE_PATH_MAX_LEN);
    a_dup(u8c, leaf, u8bDataC(g->leaf_branch));
    call(graf_leaf_dir, leafdir, g->h, leaf);
    call(FILEMakeDirP, $path(leafdir));
    a_cstr(ext, GRAF_IDX_EXT);
    size_t bytes = $len(run) * sizeof(wh128);
    u8cs data = {(u8cp)run[0], (u8cp)run[0] + bytes};
    call(DOGPupCreate, g->puppies, $path(leafdir), ext, data);
    GRAFRefreshView();
    done;
}

// --- Graph-navigation primitives ---

ok64 DAGRange(wh128css hits, wh128css runs, wh64 key) {
    sane(hits);
    a_dup(wh128cs, scan, runs);
    $for(wh128cs, run, scan) {
        wh128cp base = (*run)[0];
        size_t  len  = (size_t)((*run)[1] - base);
        size_t  lo   = 0, hi = len;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            if (base[mid].key < key) lo = mid + 1;
            else hi = mid;
        }
        size_t end = lo;
        while (end < len && base[end].key == key) end++;
        if (end > lo) {
            wh128cs hit = {base + lo, base + end};
            if (wh128cssFeed1(hits, hit) != OK) return DAGNOROOM;
        }
    }
    done;
}

u64 DAGCommitTree(wh128css runs, u64 commit_h) {
    wh128cs slots[MSET_MAX_LEVELS] = {};
    wh128css hits = {slots, slots + MSET_MAX_LEVELS};
    wh128cs *base = hits[0];
    if (DAGRange(hits, runs, DAGPack(DAG_T_COMMIT, commit_h)) != OK) return 0;
    for (wh128cs *r = base; r < hits[0]; r++) {
        for (wh128cp e = (*r)[0]; e < (*r)[1]; e++) {
            if (DAGType(e->val) == DAG_T_TREE) return DAGHashlet(e->val);
        }
    }
    return 0;
}

ok64 DAGParents(wh128css index, wh64s parents, wh64 commit_h) {
    sane(parents);
    wh128cs slots[MSET_MAX_LEVELS] = {};
    wh128css hits = {slots, slots + MSET_MAX_LEVELS};
    wh128cs *base = hits[0];
    call(DAGRange, hits, index, commit_h);
    for (wh128cs *r = base; r < hits[0]; r++) {
        for (wh128cp e = (*r)[0]; e < (*r)[1]; e++) {
            if (DAGType(e->val) != DAG_T_COMMIT) continue;
            if (wh64sFeed1(parents, e->val) != OK) return DAGNOROOM;
        }
    }
    done;
}

ok64 dag_anc_put(Bwh128 set, u64 commit_h) {
    wh128 rec = {.key = DAGPack(0, commit_h), .val = 0};
    wh128s tab = {wh128bHead(set), wh128bTerm(set)};
    return HASHwh128Put(tab, &rec);
}

b8 DAGAncestorsHas(Bwh128 set, u64 commit_h) {
    wh128 probe = {.key = DAGPack(0, commit_h), .val = 0};
    wh128s tab = {wh128bHead(set), wh128bTerm(set)};
    return HASHwh128Get(&probe, tab) == OK;
}

ok64 DAGAncestors(Bwh128 set, wh128css runs, u64 tip) {
    sane(set);
    if (tip == 0) done;

    // BFS queue sized to match the set's capacity (the queue never
    // outgrows the set — every queue entry also lives in the set).
    size_t cap = (size_t)(wh128bTerm(set) - wh128bHead(set));
    if (cap == 0) return DAGFAIL;

    Bwh128 queue = {};
    call(wh128bMap, queue, cap);

    dag_anc_put(set, tip);
    wh128 q0 = { .key = DAGPack(0, tip), .val = 0 };
    wh128bFeed1(queue, q0);

    size_t head = 0;
    wh64 par_buf[16];
    while (head < wh128bDataLen(queue)) {
        wh128cp cur = wh128bDataHead(queue) + head;
        u64 c = DAGHashlet(cur->key);
        head++;

        wh64s parents = {par_buf, par_buf + 16};
        wh64 *pbase = parents[0];
        DAGParents(runs, parents, DAGPack(DAG_T_COMMIT, c));
        for (wh64 *p = pbase; p < parents[0]; p++) {
            u64 ph = DAGHashlet(*p);
            if (DAGAncestorsHas(set, ph)) continue;
            if (dag_anc_put(set, ph) != OK) continue;
            wh128 qr = { .key = DAGPack(0, ph), .val = 0 };
            if (wh128bFeed1(queue, qr) != OK) break;
        }
    }

    wh128bUnMap(queue);
    done;
}

ok64 DAGAncestorsOfMany(Bwh128 set, wh128css runs,
                        u64 const *tips, u32 n) {
    sane(set);
    for (u32 i = 0; i < n; i++) {
        if (tips[i] == 0) continue;
        call(DAGAncestors, set, runs, tips[i]);
    }
    done;
}

ok64 DAGAllCommits(Bwh128 set, wh128css runs) {
    sane(set);
    //  Each commit has exactly one (COMMIT, TREE) edge — use it as a
    //  unique-per-commit witness while skipping (COMMIT, COMMIT)
    //  parent edges and the new (TREE, *) child edges.
    a_dup(wh128cs, scan, runs);
    $for(wh128cs, run, scan) {
        wh128cp base = (*run)[0];
        wh128cp end  = (*run)[1];
        for (wh128cp p = base; p < end; p++) {
            if (DAGType(p->key) != DAG_T_COMMIT) continue;
            if (DAGType(p->val) != DAG_T_TREE)   continue;
            dag_anc_put(set, DAGHashlet(p->key));
        }
    }
    done;
}

// --- Topological sort over a hashlet set ---
//
//  Iterative DFS post-order: descend into parents that are inside
//  `set`; emit a commit when all its in-set parents have been emitted.
//  Result: parents-before-children for arbitrary topology, no gen field
//  required.

#define DAG_TOPO_MAX_PARENTS 16

typedef struct {
    u64 c;
    u32 par_i;       // next parent slot to explore
    u32 npar;
    u64 pars[DAG_TOPO_MAX_PARENTS];
} topo_frame;

//  Thin wrapper: DAGParents (wh64s feed) → u64[] of hashlets, the
//  shape topo_frame stores.  Capped at `cap` slots.
static u32 topo_parents_of(wh128css runs, u64 commit_h,
                           u64 *out, u32 cap) {
    wh64 buf[DAG_TOPO_MAX_PARENTS];
    wh64s parents = {buf, buf + DAG_TOPO_MAX_PARENTS};
    wh64 *base = parents[0];
    DAGParents(runs, parents, DAGPack(DAG_T_COMMIT, commit_h));
    u32 n = (u32)(parents[0] - base);
    if (n > cap) n = cap;
    for (u32 i = 0; i < n; i++) out[i] = DAGHashlet(base[i]);
    return n;
}

u32 DAGTopoSort(u64 *out, u32 cap,
                Bwh128 set, wh128css runs) {
    if (cap == 0 || !out) return 0;

    size_t set_cap = (size_t)(wh128bTerm(set) - wh128bHead(set));
    if (set_cap == 0) return 0;

    Bwh128 visited = {};
    if (wh128bMap(visited, set_cap) != OK) return 0;

    //  Stack capacity = set capacity is overkill but safe (a DFS stack
    //  is bounded by the longest chain in the subgraph, which never
    //  exceeds the number of nodes).
    Bu8 stk_buf = {};
    if (u8bMap(stk_buf, set_cap * sizeof(topo_frame)) != OK) {
        wh128bUnMap(visited);
        return 0;
    }
    topo_frame *stack = (topo_frame *)u8bDataHead(stk_buf);
    u32 stack_max = (u32)set_cap;

    u32 written = 0;
    wh128cp set_head = wh128bHead(set);
    wh128cp set_term = wh128bTerm(set);

    for (wh128cp p = set_head; p < set_term && written < cap; p++) {
        if (p->key == 0) continue;            // empty hash slot
        u64 root = DAGHashlet(p->key);
        if (DAGAncestorsHas(visited, root)) continue;
        if (1 > stack_max) goto outta_room;

        u32 sp = 0;
        stack[sp].c = root;
        stack[sp].par_i = 0;
        stack[sp].npar = topo_parents_of(runs, root, stack[sp].pars,
                                       DAG_TOPO_MAX_PARENTS);
        if (stack[sp].npar > DAG_TOPO_MAX_PARENTS)
            stack[sp].npar = DAG_TOPO_MAX_PARENTS;
        sp++;
        dag_anc_put(visited, root);

        while (sp > 0) {
            topo_frame *t = &stack[sp - 1];
            b8 descended = NO;
            while (t->par_i < t->npar) {
                u64 par = t->pars[t->par_i++];
                if (par == 0) continue;
                if (!DAGAncestorsHas(set, par)) continue;
                if (DAGAncestorsHas(visited, par)) continue;
                if (sp >= stack_max) goto outta_room;

                stack[sp].c = par;
                stack[sp].par_i = 0;
                stack[sp].npar = topo_parents_of(runs, par, stack[sp].pars,
                                                 DAG_TOPO_MAX_PARENTS);
                if (stack[sp].npar > DAG_TOPO_MAX_PARENTS)
                    stack[sp].npar = DAG_TOPO_MAX_PARENTS;
                sp++;
                dag_anc_put(visited, par);
                descended = YES;
                break;
            }
            if (!descended) {
                if (written < cap) out[written++] = t->c;
                sp--;
            }
        }
    }

outta_room:
    u8bUnMap(stk_buf);
    wh128bUnMap(visited);
    return written;
}

// --- Compaction (merges multiple runs when newer is large vs older) ---
//
//  Mirrors keeper's `KEEPCompact`: builds a typed `wh128cs[]` view
//  over GRAF.puppies, runs `HITwh128Compact`, then `DOGPupThinTail`
//  + `DOGPupCreate` against the leaf branch dir.  Refreshes the view
//  so subsequent lookups see the merged run.  No-op when the stack
//  already satisfies the 1/8 size-tiered invariant.
static ok64 dag_compact(graf *g) {
    sane(g);

    u32 nfiles = DOGPupCount(g->puppies);
    if (nfiles < 2) done;

    //  Build typed view from puppy data slices.
    wh128cs runs[MSET_MAX_LEVELS] = {};
    u32 nview = 0;
    for (u32 i = 0; i < nfiles && nview < MSET_MAX_LEVELS; i++) {
        u8cs raw = {};
        DOGPupData(raw, g->puppies, i);
        if (raw[0] == NULL) continue;
        runs[nview][0] = (wh128cp)raw[0];
        runs[nview][1] = (wh128cp)raw[1];
        nview++;
    }
    wh128css stack = {runs, runs + nview};

    if (HITwh128IsCompact(stack)) done;

    size_t total = 0;
    for (u32 i = 0; i < nview; i++)
        total += (size_t)(runs[i][1] - runs[i][0]);

    Bwh128 cbuf = {};
    call(wh128bAllocate, cbuf, total);
    wh128 *base = cbuf[0];
    wh128s into = {cbuf[0], cbuf[3]};
    size_t before_len = $len(stack);
    call(HITwh128Compact, stack, into);
    size_t m = before_len - $len(stack) + 1;
    if (m < 2) { wh128bFree(cbuf); done; }

    a_pad(u8, leafdir, FILE_PATH_MAX_LEN);
    a_dup(u8c, leaf, u8bDataC(g->leaf_branch));
    call(graf_leaf_dir, leafdir, g->h, leaf);
    a_cstr(ext, GRAF_IDX_EXT);
    u8cs merged = {(u8cp)base, (u8cp)(into[0])};
    call(DOGPupThinTail, g->puppies, $path(leafdir), ext, (u32)m);
    call(DOGPupCreate,   g->puppies, $path(leafdir), ext, merged);

    GRAFRefreshView();
    wh128bFree(cbuf);
    done;
}

// --- Ingest state management ---
//
//  Seqno is owned by the puppy stack — DOGPupCreate picks
//  max(seqno)+1 internally — so the ingest struct no longer carries
//  one.  `dagdir`/`dagdir_buf` are also gone: writes always land in
//  the leaf branch dir resolved on-demand from `GRAF.leaf_branch`.

static ok64 dag_ingest_alloc(dag_ingest **out) {
    sane(out);
    *out = NULL;

    dag_ingest *g = calloc(1, sizeof(*g));
    if (!g) return DAGFAIL;

    g->batch_cap = DAG_BATCH;
    g->batch = calloc(g->batch_cap, sizeof(wh128));
    if (!g->batch) { free(g); return DAGFAIL; }

    *out = g;
    done;
}

static void dag_ingest_free(dag_ingest *g) {
    if (!g) return;
    free(g->batch);
    free(g);
}

// --- Emit helpers ---

static void dag_emit(dag_ingest *g,
                     u8 ktype, u64 khash,
                     u8 vtype, u64 vhash) {
    if (g->batch_len >= g->batch_cap) return;  // overflow; handled by flush
    g->batch[g->batch_len++] = DAGEntry(ktype, khash, vtype, vhash);
}

static ok64 dag_flush_batch(dag_ingest *g) {
    sane(g);
    if (g->batch_len == 0) done;
    wh128s d = {g->batch, g->batch + g->batch_len};
    wh128sSort(d);
    wh128sDedup(d);
    g->batch_len = (size_t)(d[1] - d[0]);
    wh128cs run = {g->batch, g->batch + g->batch_len};
    call(dag_index_write_leaf, &GRAF, run);
    g->batch_len = 0;
    done;
}

static void dag_batch_maybe_flush(dag_ingest *g) {
    if (g->batch_len + 64 >= g->batch_cap) dag_flush_batch(g);
}

// --- Finish: flush pending records, compact runs. ---

static ok64 dag_finish(dag_ingest *g) {
    sane(g);
    if (g->finished) done;
    call(dag_flush_batch, g);
    dag_compact(&GRAF);
    g->finished = 1;
    done;
}

// ============================================================
// Public entry: GRAFUpdate
// ============================================================

// This is the real meat the GRAFUpdate wrapper calls into.  `state`
// is graf's own state (struct graf from GRAF.h).  We reach into
// state->ing to lazily allocate the ingest context.  Forward-decl
// of struct graf comes from GRAF.h include above.

ok64 GRAFDagUpdate(u8 obj_type, sha1 const *sha, u8cs blob) {
    sane(1);
    graf *state = &GRAF;

    // Lazy allocate ingest state on first call.  Writes target the
    // leaf branch dir (resolved via GRAF.leaf_branch); no longer
    // carry a dagdir copy — `dag_index_write_leaf` re-derives it.
    if (!state->ing) {
        call(dag_ingest_alloc, &state->ing);
    }

    dag_ingest *g = state->ing;

    switch (obj_type) {
    case DOG_OBJ_COMMIT: {
        // Parse commit header for tree_h and parents[].
        a_dup(u8c, scan, blob);
        u8cs field = {}, value = {};
        sha1 tree_sha = {};
        sha1 parents[16] = {};
        u32 npar = 0;
        b8 got_tree = NO;
        while (GITu8sDrainCommit(scan, field, value) == OK) {
            if (u8csEmpty(field)) break;
            a_cstr(ft, "tree");
            a_cstr(fp, "parent");
            if ($eq(field, ft) && u8csLen(value) >= 40) {
                DAGsha1FromHex(&tree_sha, (char const *)value[0]);
                got_tree = YES;
            } else if ($eq(field, fp) && u8csLen(value) >= 40 && npar < 16) {
                DAGsha1FromHex(&parents[npar], (char const *)value[0]);
                npar++;
            }
        }
        if (!got_tree) return DAGFAIL;

        u64 commit_h = dag_obj_hashlet(DOG_OBJ_COMMIT, sha, blob);

        u64 tree_h = WHIFFHashlet60(&tree_sha);

        //  (COMMIT, commit_h) → (TREE,   tree_h)    root-tree edge
        //  (COMMIT, commit_h) → (COMMIT, parent_h)  one per parent
        dag_emit(g, DAG_T_COMMIT, commit_h,
                    DAG_T_TREE,   tree_h);
        for (u32 i = 0; i < npar; i++) {
            u64 parent_h = WHIFFHashlet60(&parents[i]);
            dag_emit(g, DAG_T_COMMIT, commit_h,
                        DAG_T_COMMIT, parent_h);
        }

        dag_batch_maybe_flush(g);
        done;
    }

    case DOG_OBJ_TREE: {
        //  Fan out (TREE, tree_h ^ seg_h) → (kind, child_h) one per
        //  entry, where kind comes from the git mode:
        //    040000          → TREE
        //    160000          → COMMIT (gitlink/submodule)
        //    100644/100755/120000 → BLOB
        //  Unknown modes are skipped — better an absent index entry
        //  than a wrong-typed one (the keeper-verified scan side will
        //  fall back to walking the tree blob anyway).
        u64 tree_h = dag_obj_hashlet(DOG_OBJ_TREE, sha, blob);
        if (tree_h == 0) done;

        a_dup(u8c, scan, blob);
        u8cs file = {}, esha = {};
        u32 mode = 0;
        while (GITu8sDrainTree(scan, file, esha, &mode) == OK) {
            //  Split "<mode> <name>" → name slice.
            u8cs fscan = {file[0], file[1]};
            if (u8csFind(fscan, ' ') != OK) continue;
            u8cs name = {fscan[0] + 1, file[1]};
            if ($empty(name) || u8csLen(esha) != 20) continue;

            u8 kind = 0;
            switch (mode) {
                case 040000:  kind = DAG_T_TREE;   break;
                case 0160000: kind = DAG_T_COMMIT; break;
                case 0100644: case 0100755: case 0120000:
                              kind = DAG_T_BLOB;   break;
                default:      continue;
            }

            sha1 child_sha = {};
            memcpy(child_sha.data, esha[0], 20);
            u64 child_h = WHIFFHashlet60(&child_sha);
            u64 seg_h   = RAPHashSeed(name, GRAF_SEG_SEED) & DAG_HL_MASK;

            dag_emit(g, DAG_T_TREE, tree_h ^ seg_h,
                        kind,       child_h);
            dag_batch_maybe_flush(g);
        }
        done;
    }

    case DOG_OBJ_BLOB:
    default:
        done;  // blob payloads carry no graph edges.
    }
}

// ============================================================
// Tree-child lookup
// ============================================================

ok64 DAGTreeChildren(wh128css runs, u64 tree_h, u8cs name,
                     DAGChildCb cb, void *ctx) {
    sane(cb && $ok(name));
    u64 seg_h = RAPHashSeed(name, GRAF_SEG_SEED) & DAG_HL_MASK;
    wh128cs slots[MSET_MAX_LEVELS] = {};
    wh128css hits = {slots, slots + MSET_MAX_LEVELS};
    wh128cs *base = hits[0];
    call(DAGRange, hits, runs, DAGPack(DAG_T_TREE, tree_h ^ seg_h));
    for (wh128cs *r = base; r < hits[0]; r++) {
        for (wh128cp e = (*r)[0]; e < (*r)[1]; e++) {
            ok64 rc = cb(ctx, DAGHashlet(e->val), DAGType(e->val));
            if (rc != OK) return rc;
        }
    }
    done;
}

// ============================================================
// Path-walk through the tree-shape index
// ============================================================

//  Find one match for (tree_h, name) preferring `prefer_kind`; falls
//  back to first hit of any kind.  Returns the val wh64 (kind +
//  hashlet) or 0 on miss.  Used by DAGCommitPathHashlet — for
//  intermediate segments we want a TREE; for leaves we accept any.
//
//  The "kind preference" matters only when a 60-bit hash collision
//  produces multiple distinct matches — then we route through the
//  TREE-kind candidate to keep descending.  In the no-collision case
//  there's exactly one hit and prefer_kind is moot.
typedef struct {
    u8  prefer_kind;     // 0 = no preference (leaf walk)
    wh64 hit;            // 0 if none yet, non-zero = wh64 val
} path_hit;

static ok64 path_collect(void *ctx, u64 child_h, u8 kind) {
    path_hit *p = (path_hit *)ctx;
    wh64 v = DAGPack(kind, child_h);
    //  Always remember the first hit (fallback).
    if (p->hit == 0) p->hit = v;
    //  Promote to a preferred-kind hit if we see one.
    if (p->prefer_kind != 0 && kind == p->prefer_kind) {
        p->hit = v;
        return DAGFAIL;   // signal "found preferred" — abort iteration
    }
    return OK;
}

wh64 DAGCommitPathHashlet(wh128css index, wh64 commit_h, u8cs path) {
    //  Anchor at the commit's root tree.
    u64 tree_h = DAGCommitTree(index, DAGHashlet(commit_h));
    if (tree_h == 0) return 0;

    //  Empty (or all-trailing-slash) path → root tree wh64.
    a_dup(u8c, rest, path);
    while (!$empty(rest) && *rest[0] == '/') u8csUsed1(rest);
    if ($empty(rest)) return DAGPack(DAG_T_TREE, tree_h);

    //  Descend segment by segment.  Each non-final segment must
    //  resolve to a TREE; the final one yields whatever kind is
    //  recorded (BLOB / TREE / COMMIT-gitlink).
    while (!$empty(rest)) {
        u8cp slash = rest[0];
        while (slash < rest[1] && *slash != '/') slash++;
        u8cs seg = {rest[0], slash};

        //  Skip empty segments (//, trailing /).
        if ($empty(seg)) {
            if (slash < rest[1]) rest[0] = slash + 1;
            else rest[0] = slash;
            continue;
        }

        b8 is_last = NO;
        {
            u8cp probe = (slash < rest[1]) ? slash + 1 : slash;
            while (probe < rest[1] && *probe == '/') probe++;
            if (probe >= rest[1]) is_last = YES;
        }

        path_hit ph = { .prefer_kind = is_last ? 0 : DAG_T_TREE, .hit = 0 };
        ok64 rc = DAGTreeChildren(index, tree_h, seg, path_collect, &ph);
        //  DAGFAIL from path_collect means "found preferred kind, stop"
        //  — that's success here.  Any other non-OK is fatal.
        if (rc != OK && rc != DAGFAIL) return 0;
        if (ph.hit == 0) return 0;

        if (is_last) return ph.hit;
        if (DAGType(ph.hit) != DAG_T_TREE) return 0;
        tree_h = DAGHashlet(ph.hit);

        rest[0] = (slash < rest[1]) ? slash + 1 : slash;
    }

    //  All segments consumed without hitting `is_last` — only happens
    //  on degenerate inputs we already trimmed; defensive zero.
    return 0;
}

ok64 GRAFDagFinish(void) {
    sane(1);
    graf *state = &GRAF;
    if (!state->ing) done;
    ok64 r = dag_finish(state->ing);
    dag_ingest_free(state->ing);
    state->ing = NULL;
    return r;
}
