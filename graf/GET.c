//  GET: URI-driven single-tip blob/tree READ.
//
//  `path?<sha>`   → blob bytes at commit `<sha>`.
//  `dir/?<sha>`   → tree object body at commit `<sha>`.
//  Multi-tip merge URIs (`path?A&B...`) are retired — merge is PATCH
//  territory.  Callers use `GRAFMergeWtFileTunable` directly.
//
//  This file also hosts the WEAVE-based merge helpers
//  (`GRAFMergeWtFile`, `GRAFMergeWtFileTunable`, `GRAFMerge3Bytes`)
//  that PATCH / REBASE drive.  Layered here for shared use of
//  `build_tip_weave_tunable` and `emit_alive_bytes`.
//
#include "GRAF.h"

#include <string.h>

#include "BLOB.h"
#include "DAG.h"
#include "WEAVE.h"

#include "abc/FILE.h"
#include "abc/PATH.h"
#include "abc/PRO.h"
#include "abc/RAP.h"
#include "abc/URI.h"
#include "dog/DOG.h"
#include "dog/HUNK.h"
#include "dog/QURY.h"
#include "dog/WHIFF.h"
#include "keeper/GIT.h"
#include "keeper/KEEP.h"

con ok64 GETFAIL   = 0x1039d3ca495;
con ok64 GETBAD    = 0x40e74b28d;
con ok64 GETNOTIPS = 0x1039d5d875265c;

#define GET_MAX_TIPS   8
#define GET_MAX_VERS   200000
#define GET_ANC_SIZE   (1u << 18)     // 256K slots
#define GET_BLOB_MAX   (16UL << 20)   // 16 MB / blob
#define GET_TREE_MAX_ENTRIES 4096
#define GET_TREE_ARENA (1UL << 20)    // 1 MB for interned names/modes

typedef struct {
    sha1 sha;         // full commit sha
    u64  h40;         // 40-bit hashlet
    u32  gen;         // DAG generation (0 if not indexed)
} get_tip;

// --- Resolve one qref to (sha, h40, gen) ---
//
//  Phase 1: SHA-form tips only.  A `QURY_REF` entry will round-trip
//  through `REFSResolve` in a later pass; for now the CLI always
//  hands graf hex shas.
static ok64 get_resolve_qref(get_tip *out, qref const *q) {
    sane(out && q);
    if (q->type != QURY_SHA) return GETBAD;

    u64 h60 = WHIFFHexHashlet60(q->body);
    size_t hexlen = u8csLen(q->body);
    if (hexlen < HASH_MIN_HEX) return GETBAD;
    if (hexlen > 15) hexlen = 15;

    Bu8 cbuf = {};
    call(u8bAllocate, cbuf, 1UL << 20);
    u8 ct = 0;
    ok64 o = KEEPGet(&KEEP, h60, hexlen, cbuf, &ct);
    if (o != OK || ct != DOG_OBJ_COMMIT) { u8bFree(cbuf); return GETFAIL; }

    //  Compute the canonical 20-byte sha from the fetched body so
    //  short-prefix inputs resolve to a unique hashlet.  KEEPObjSha
    //  rebuilds "<type> <len>\0<body>" then hashes.
    a_dup(u8c, body, u8bData(cbuf));
    KEEPObjSha(&out->sha, DOG_OBJ_COMMIT, body);
    u8bFree(cbuf);

    out->h40 = WHIFFHashlet60(&out->sha);
    out->gen = 0;            //  gen is no longer indexed
    done;
}

// --- Drain a URI into (path, tips[]) ---
//
//  Accepts the two shapes in VERBS.md:
//      file.c?sha1&sha2          blob merge
//      dir/?sha1&sha2            tree merge  (is_tree = YES)
//  Also accepts the degenerate `path` (no `?`) as a single-tip lookup
//  resolved later by the caller.
static ok64 get_drain_uri(u8cs path_out,
                          get_tip *tips, u32 *ntips, u32 maxtips,
                          b8 *is_tree,
                          u8csc uri) {
    sane(path_out && tips && ntips && is_tree);
    *ntips = 0;
    *is_tree = NO;

    u8cs data = {uri[0], uri[1]};

    //  Split on `?`.  URIs in this surface don't carry scheme /
    //  authority / fragment — keep the parser trivial.
    u8cp q = data[0];
    while (q < data[1] && *q != '?') q++;

    path_out[0] = data[0];
    path_out[1] = q;
    if ($len(path_out) > 0 && path_out[1][-1] == '/') *is_tree = YES;

    if (q >= data[1]) done;  // path only; caller handles

    u8cs query = {q + 1, data[1]};
    while (!$empty(query)) {
        if (*ntips >= maxtips) return GETBAD;
        qref qr = {};
        call(QURYu8sDrain, query, &qr);
        if (qr.type == QURY_NONE) break;
        call(get_resolve_qref, &tips[*ntips], &qr);
        (*ntips)++;
    }
    done;
}

// --- Byte-append a full blob fetched by (commit_h40, path) ---

static ok64 get_append_blob_at(u8b into, u64 commit_h40, u8cs path) {
    sane(into);
    Bu8 blob = {};
    call(u8bMap, blob, GET_BLOB_MAX);
    ok64 o = GRAFBlobAtCommit(blob, &KEEP, commit_h40, path);
    if (o != OK) { u8bUnMap(blob); return o; }
    a_dup(u8c, bdata, u8bData(blob));
    o = u8bFeed(into, bdata);
    u8bUnMap(blob);
    return o;
}

// --- LCA of two commits in the DAG -----------------------------------
//
//  Intersects each tip's ancestor set; returns the deepest member of
//  the intersection (the LCA closest to the tips).  Without gen we
//  topologically sort the intersection and pick the *last* commit —
//  in DFS post-order over parent edges, the last-emitted node is the
//  one farthest from the roots.
//
//  Returns 0 when:
//    * the DAG index is empty (graf hasn't indexed yet), or
//    * the two tips share no ancestors.

static u64 get_lca(u64 a_h40, u64 b_h40) {
    if (a_h40 == 0 || b_h40 == 0) return 0;

    Bwh128 set_a = {}, set_b = {}, set_c = {};
    if (wh128bAllocate(set_a, GET_ANC_SIZE) != OK) return 0;
    if (wh128bAllocate(set_b, GET_ANC_SIZE) != OK) {
        wh128bFree(set_a); return 0;
    }
    if (wh128bAllocate(set_c, GET_ANC_SIZE) != OK) {
        wh128bFree(set_a); wh128bFree(set_b); return 0;
    }

    wh128css runs = {NULL, NULL};
    GRAFRuns(runs);
    ok64 oa = DAGAncestors(set_a, runs, a_h40);
    ok64 ob = DAGAncestors(set_b, runs, b_h40);
    if (oa != OK || ob != OK) {
        wh128bFree(set_a); wh128bFree(set_b); wh128bFree(set_c);
        return 0;
    }

    //  Build the intersection (common ancestors).
    wh128cp cells = wh128bHead(set_a);
    wh128cp cells_end = wh128bTerm(set_a);
    for (wh128cp c = cells; c < cells_end; c++) {
        u64 h = DAGHashlet(c->key);
        if (h == 0) continue;
        if (!DAGAncestorsHas(set_b, h)) continue;
        dag_anc_put(set_c, h);
    }

    //  Topo-sort the intersection; LCA = last (deepest) entry.
    u64 best = 0;
    size_t cap = (size_t)(wh128bTerm(set_c) - wh128bHead(set_c));
    Bu8 ord_buf = {};
    if (cap > 0 && u8bMap(ord_buf, cap * sizeof(u64)) == OK) {
        u64 *ordered = (u64 *)u8bDataHead(ord_buf);
        u32 nord = DAGTopoSort(ordered, (u32)cap, set_c, runs);
        if (nord > 0) best = ordered[nord - 1];
        u8bUnMap(ord_buf);
    }

    wh128bFree(set_a);
    wh128bFree(set_b);
    wh128bFree(set_c);
    return best;
}

// Public wrapper: `sha1 *` in/out for callers outside graf (sniff's
// PATCH uses this to classify modify/delete cases).  Returns OK with
// `*out` all-zero when no shared ancestor is indexed.
ok64 GRAFLca(sha1 *out, sha1 const *a, sha1 const *b) {
    sane(out && a && b);
    memset(out->data, 0, sizeof(out->data));

    u64 a_h40 = WHIFFHashlet60(a);
    u64 b_h40 = WHIFFHashlet60(b);
    u64 lca_h = get_lca(a_h40, b_h40);
    if (lca_h == 0) done;   // unrelated histories — leave out zero

    //  Recover the full sha by fetching the commit body from keeper
    //  and rehashing (identical to the trick `get_resolve_qref`
    //  uses — KEEPObjSha("commit <len>\0<body>") is canonical).
    Bu8 cbuf = {};
    call(u8bAllocate, cbuf, 1UL << 20);
    u8 ct = 0;
    ok64 o = KEEPGet(&KEEP, lca_h,
                     DAG_H60_HEXLEN, cbuf, &ct);
    if (o != OK || ct != DOG_OBJ_COMMIT) { u8bFree(cbuf); done; }

    a_dup(u8c, body, u8bData(cbuf));
    KEEPObjSha(out, DOG_OBJ_COMMIT, body);
    u8bFree(cbuf);
    done;
}

// --- 2-way blob merge via WEAVE -------------------------------------

//  Forward decls — implementations live further down with
//  `get_weave_union`'s helpers.
static ok64 build_tip_weave(weave *out, u8cs path, u8cs ext,
                            u64 const *tip_hs, u32 ntips);
static ok64 build_tip_weave_with_ids(weave *out, u8cs path, u8cs ext,
                                     u64 const *tip_hs, u32 ntips,
                                     Bu32 out_ids);
static ok64 build_tip_weave_tunable(weave *out, u8cs path, u8cs ext,
                                    u64 const *tip_hs, u32 ntips,
                                    u32 edges,
                                    u64 const *skip_hl, u32 nskip,
                                    Bu32 out_ids);
static ok64 emit_alive_bytes(u8b into, weave const *w);

//  Per-side membership predicate for `WEAVEEmitMerged`.  Backed by a
//  Bu32 of `sc` values used during `build_tip_weave_with_ids` (and
//  optionally augmented with WEAVE_WT_SRC for the wt-folded side).
typedef struct {
    u32cp ids;     // u32 array of in-stamps reachable via this side
    u32   n;
} merge_id_set;

static b8 merge_id_set_has(u32 in, void *vctx) {
    merge_id_set *s = (merge_id_set *)vctx;
    if (!s) return NO;
    for (u32 i = 0; i < s->n; i++)
        if (s->ids[i] == in) return YES;
    return NO;
}

//  Fold the wt-on-disk bytes for `path` (relative to `reporoot`) into
//  the weave `cur` as a final WEAVE_WT_SRC layer, writing the result
//  into `next` and reporting via `*used_next` whether the fold ran
//  (NO when the file is missing or byte-identical to the prior layer
//  — caller keeps `cur`).  `nu_scratch` is used for the WEAVEFromBlob
//  intermediate.
static ok64 graf_fold_wt_layer(weave *next, b8 *used_next,
                               weave const *cur, weave *nu_scratch,
                               u8cs path, u8cs ext, u8cs reporoot) {
    sane(next && cur && nu_scratch && used_next);
    *used_next = NO;
    if (!$ok(reporoot)) done;

    a_path(wt_path, reporoot, path);
    u8bp wt_mapped = NULL;
    ok64 mo = FILEMapRO(&wt_mapped, $path(wt_path));
    if (mo != OK || !wt_mapped) done;       // missing-file → skip silently

    u8cs wt_data = {u8bDataHead(wt_mapped),
                    u8bDataHead(wt_mapped) + u8bDataLen(wt_mapped)};
    ok64 ret = WEAVEFromBlob(nu_scratch, wt_data, ext, WEAVE_WT_SRC);
    if (ret == OK) {
        ret = WEAVEDiff(next, cur, nu_scratch, WEAVE_WT_SRC);
        if (ret == OK) *used_next = YES;
    }
    FILEUnMap(wt_mapped);
    return ret;
}

//  Weave-merge a single file across two commits, treating the wt's
//  on-disk bytes for `path` as an implicit edit attached to `base`.
//  Builds the ancestor-closure weave for each tip, folds the wt
//  bytes as a final WEAVE_WT_SRC layer on the base side, runs
//  WEAVEMerge, and emits the alive-token bytes into `out` —
//  framing divergent regions with `<<<<` / `||||` / `>>>>` when the
//  two sides' inserts collide (see `WEAVEEmitMerged`).
//
//  Returns OK on success.  GRAFFAIL on history-empty-on-both-sides.
//  Caller writes `out` to disk and stamps the new mtime.
ok64 GRAFMergeWtFileTunable(u8cs path, u8cs reporoot,
                            sha1 const *base, sha1 const *tgt,
                            u32 edges,
                            u64 const *skip_hl, u32 nskip,
                            u8b out) {
    //  Empty reporoot is allowed — callers that don't have a wt
    //  (keeper-side merges) skip the wt-fold layer entirely.
    sane($ok(path) && base && tgt && out);
    u8bReset(out);

    u64 base_h40 = WHIFFHashlet60(base);
    u64 tgt_h40  = WHIFFHashlet60(tgt);

    u8cs ext = {};
    PATHu8sExt(ext, path);

    weave wbase = {}, wbase_wt = {}, wnu = {};
    weave wtgt = {}, wmerge = {};
    Bu32 base_ids = {}, tgt_ids = {};
    ok64 ret = OK;
    if ((ret = WEAVEInit(&wbase))    != OK) return ret;
    if ((ret = WEAVEInit(&wbase_wt)) != OK) goto cleanup;
    if ((ret = WEAVEInit(&wnu))      != OK) goto cleanup;
    if ((ret = WEAVEInit(&wtgt))     != OK) goto cleanup;
    if ((ret = WEAVEInit(&wmerge))   != OK) goto cleanup;
    if ((ret = u32bMap(base_ids, 4096)) != OK) goto cleanup;
    if ((ret = u32bMap(tgt_ids,  4096)) != OK) goto cleanup;

    //  Base side: ancestor closure of base commit, plus wt layer.
    ret = build_tip_weave_tunable(&wbase, path, ext, &base_h40, 1,
                                  edges, skip_hl, nskip, base_ids);
    if (ret != OK) goto cleanup;

    weave const *wcur = &wbase;
    b8 wt_layered = NO;
    ret = graf_fold_wt_layer(&wbase_wt, &wt_layered, &wbase, &wnu,
                             path, ext, reporoot);
    if (ret != OK) goto cleanup;
    if (wt_layered) {
        wcur = &wbase_wt;
        (void)u32bFeed1(base_ids, WEAVE_WT_SRC);
    }

    //  Target side: ancestor closure of tgt commit (same edges + skip).
    ret = build_tip_weave_tunable(&wtgt, path, ext, &tgt_h40, 1,
                                  edges, skip_hl, nskip, tgt_ids);
    if (ret != OK) goto cleanup;

    //  Empty-side degeneracy.
    u32 base_n = (u32)((u32cp)wcur->toks[2] - (u32cp)wcur->toks[1]);
    u32 tgt_n  = (u32)((u32cp)wtgt.toks[2]  - (u32cp)wtgt.toks[1]);
    if (base_n == 0 && tgt_n == 0) { ret = GRAFFAIL; goto cleanup; }
    if (base_n == 0) { ret = emit_alive_bytes(out, &wtgt); goto cleanup; }
    if (tgt_n == 0)  { ret = emit_alive_bytes(out, wcur);  goto cleanup; }

    ret = WEAVEMerge(&wmerge, wcur, &wtgt);
    if (ret != OK) goto cleanup;

    //  Build per-side predicates and render with conflict markers.
    merge_id_set base_set = {
        .ids = (u32cp)u32bDataHead(base_ids),
        .n   = (u32)u32bDataLen(base_ids),
    };
    merge_id_set tgt_set = {
        .ids = (u32cp)u32bDataHead(tgt_ids),
        .n   = (u32)u32bDataLen(tgt_ids),
    };
    WEAVEsetfn preds[2] = { merge_id_set_has, merge_id_set_has };
    void *ctxs[2] = { &base_set, &tgt_set };

    ret = WEAVEEmitMerged(&wmerge, preds, ctxs, 2, out);

cleanup:
    if (tgt_ids[0])  u32bUnMap(tgt_ids);
    if (base_ids[0]) u32bUnMap(base_ids);
    WEAVEFree(&wmerge);
    WEAVEFree(&wtgt);
    WEAVEFree(&wnu);
    WEAVEFree(&wbase_wt);
    WEAVEFree(&wbase);
    return ret;
}

ok64 GRAFMergeWtFile(u8cs path, u8cs reporoot,
                     sha1 const *base, sha1 const *tgt,
                     u8b out) {
    //  Default to parent-only reachability — historic shape, kept so
    //  call sites that haven't migrated to the tunable variant get
    //  identical behaviour.  PATCH.c uses the tunable form directly
    //  with `parent | foster` to handle absorbed-via-foster history.
    return GRAFMergeWtFileTunable(path, reporoot, base, tgt,
                                  DAG_EDGE_PARENT, NULL, 0, out);
}

// --- Blob-only 3-way WEAVE merge ----------------------------------
//
//  Three-way merge from raw blob bytes (no keeper / no DAG walk).
//  Pipeline:  WEAVEFromBlob ×3 → WEAVEDiff ×2 → WEAVEMerge →
//  WEAVEEmitMerged.  Marker shape is the WEAVE convention
//  (`<<<<` / `||||` / `>>>>`), with the 1/4-line realignment pass
//  applied automatically by WEAVEEmitMerged.
//
//  Empty `base` is allowed (no common ancestor); empty `ours` or
//  `theirs` short-circuits to the other side's bytes.  `out` is
//  reset on entry.

#define MERGE3_BASE_SRC   0u           // spine (WEAVEEmitMerged: in==0)
#define MERGE3_OURS_SRC   0xA5A5A5A5u
#define MERGE3_THEIRS_SRC 0x5A5A5A5Au

static b8 merge3_pred(u32 in, void *vctx) {
    return in == *(u32 *)vctx;
}

ok64 GRAFMerge3Bytes(u8cs base, u8cs ours, u8cs theirs,
                     u8cs ext, u8b out) {
    sane(out);
    u8bReset(out);

    //  Empty-side degeneracies — match get_merge_2way's prior shape.
    if ($empty(ours) && $empty(theirs)) return OK;
    if ($empty(ours))  return u8bFeed(out, theirs);
    if ($empty(theirs)) return u8bFeed(out, ours);

    weave wbase = {}, wours_n = {}, wthrs_n = {};
    weave wours = {}, wthrs = {}, wmerge = {};
    ok64 ret = OK;
    if ((ret = WEAVEInit(&wbase))   != OK) return ret;
    if ((ret = WEAVEInit(&wours_n)) != OK) goto cleanup;
    if ((ret = WEAVEInit(&wthrs_n)) != OK) goto cleanup;
    if ((ret = WEAVEInit(&wours))   != OK) goto cleanup;
    if ((ret = WEAVEInit(&wthrs))   != OK) goto cleanup;
    if ((ret = WEAVEInit(&wmerge))  != OK) goto cleanup;

    //  Base may be empty: WEAVEFromBlob on empty data yields a
    //  zero-token weave, which WEAVEDiff handles as "everything is
    //  INS on the nu side".
    if ((ret = WEAVEFromBlob(&wbase,   base,   ext, MERGE3_BASE_SRC)) != OK) goto cleanup;
    if ((ret = WEAVEFromBlob(&wours_n, ours,   ext, MERGE3_BASE_SRC)) != OK) goto cleanup;
    if ((ret = WEAVEFromBlob(&wthrs_n, theirs, ext, MERGE3_BASE_SRC)) != OK) goto cleanup;
    if ((ret = WEAVEDiff(&wours, &wbase, &wours_n, MERGE3_OURS_SRC))   != OK) goto cleanup;
    if ((ret = WEAVEDiff(&wthrs, &wbase, &wthrs_n, MERGE3_THEIRS_SRC)) != OK) goto cleanup;
    if ((ret = WEAVEMerge(&wmerge, &wours, &wthrs))                    != OK) goto cleanup;

    u32 ours_src = MERGE3_OURS_SRC, theirs_src = MERGE3_THEIRS_SRC;
    WEAVEsetfn preds[2] = { merge3_pred, merge3_pred };
    void *ctxs[2]       = { &ours_src, &theirs_src };
    ret = WEAVEEmitMerged(&wmerge, preds, ctxs, 2, out);

cleanup:
    WEAVEFree(&wmerge);
    WEAVEFree(&wthrs);
    WEAVEFree(&wours);
    WEAVEFree(&wthrs_n);
    WEAVEFree(&wours_n);
    WEAVEFree(&wbase);
    return ret;
}

// --- Weave-replay helpers: shared by N-tip union and 2-way merge ---

//  Build a weave by replaying `path`'s blob versions across the
//  ancestor union of `tip_hs[0..ntips)` in topo order.  The result
//  weave's inrm carries provenance per token; alive tokens reproduce
//  the path's content at the most recent ancestor where it was last
//  written.  Caller owns `out` (must be inited and reset).
//
//  This is a first-pass approximation for histories with multi-parent
//  commits — they're treated as linear WEAVEDiff steps off whatever
//  came before in topo order, not recursive WEAVEReplay.  Good enough
//  for case-A merges where both sides feed into WEAVEMerge; correct
//  case-B (importing a multi-parent commit) is a follow-up that swaps
//  the per-step WEAVEDiff for WEAVEReplay when the topo step has >1
//  parent.
//
//  When `out_ids` is non-NULL, every 32-bit `sc` value passed to
//  `WEAVEDiff` is appended to `*out_ids` in walk order.  Callers
//  driving `WEAVEEmitMerged` use these to build per-side membership
//  predicates over token `inrm.in` values.
static ok64 build_tip_weave_with_ids(weave *out, u8cs path, u8cs ext,
                                     u64 const *tip_hs, u32 ntips,
                                     Bu32 out_ids) {
    return build_tip_weave_tunable(out, path, ext, tip_hs, ntips,
                                   DAG_EDGE_PARENT, NULL, 0, out_ids);
}

static ok64 build_tip_weave(weave *out, u8cs path, u8cs ext,
                            u64 const *tip_hs, u32 ntips) {
    Bu32 noids = {};
    return build_tip_weave_with_ids(out, path, ext, tip_hs, ntips, noids);
}

static ok64 build_tip_weave_tunable(weave *out, u8cs path, u8cs ext,
                                    u64 const *tip_hs, u32 ntips,
                                    u32 edges,
                                    u64 const *skip_hl, u32 nskip,
                                    Bu32 out_ids) {
    sane(out && ntips > 0);

    //  Ancestor union across the supplied tips with the caller's
    //  edge-kind selector + skip set.  edges = DAG_EDGE_PARENT
    //  reproduces the legacy behaviour exactly.
    Bwh128 anc = {};
    call(wh128bAllocate, anc, GET_ANC_SIZE);
    wh128css runs = {NULL, NULL};
    GRAFRuns(runs);
    ok64 ao = DAGAncestorsOfManyTunable(anc, runs, tip_hs, ntips,
                                        edges, skip_hl, nskip);
    if (ao != OK) { wh128bFree(anc); return ao; }

    //  Topo-sort using the SAME edge bitmask as the ancestor walk so
    //  foster-attached commits sit before the carrying commit in the
    //  replay order.  Without that, ours's WEAVEDiff stamps the
    //  attached commit's tokens with the carrying commit's sc, and
    //  WEAVEMerge can't align them with theirs's still-original-sc
    //  tokens.  Picked targets aren't given an ordering edge (they're
    //  reachability-set leaves with no replay step).
    u32 nvers = 0;
    u64 *vers = NULL;
    size_t anc_cap = (size_t)(wh128bTerm(anc) - wh128bHead(anc));
    Bu8 ord_buf = {};
    if (anc_cap > 0 && u8bMap(ord_buf, anc_cap * sizeof(u64)) == OK) {
        u64 *ordered = (u64 *)u8bDataHead(ord_buf);
        u32 topo_edges = edges & ~DAG_EDGE_PICKED;
        u32 nord = DAGTopoSortTunable(ordered, (u32)anc_cap, anc, runs,
                                      topo_edges);
        if (nord > GET_MAX_VERS) nord = GET_MAX_VERS;
        vers = ordered;
        nvers = nord;
    }
    wh128bFree(anc);

    //  No DAG entries (fresh import without GRAFIndex, isolated blob
    //  URI): fall back to the tip's own blob bytes as a single-version
    //  weave so callers still get something sensible.
    if (nvers == 0) {
        Bu8 fallback = {};
        call(u8bMap, fallback, GET_BLOB_MAX);
        ok64 fo = get_append_blob_at(fallback, tip_hs[0], path);
        if (fo == OK) {
            a_dup(u8c, fb, u8bData(fallback));
            fo = WEAVEFromBlob(out, fb, ext, (u32)tip_hs[0]);
        }
        u8bUnMap(fallback);
        return fo;
    }

    //  Three weave instances: src accumulates history, dst receives
    //  each WEAVEDiff, nu is rebuilt fresh per blob version.  After
    //  WEAVEDiff we swap so src always carries the latest state.
    weave wA = {}, wB = {}, wnu = {};
    ok64 r = OK;
    if ((r = WEAVEInit(&wA))  != OK) { goto out; }
    if ((r = WEAVEInit(&wB))  != OK) { WEAVEFree(&wA); goto out; }
    if ((r = WEAVEInit(&wnu)) != OK) { WEAVEFree(&wA); WEAVEFree(&wB); goto out; }
    weave *wsrc = &wA, *wdst = &wB;

    Bu8 blob_a = {}, blob_b = {};
    if ((r = u8bMap(blob_a, GET_BLOB_MAX)) != OK) goto cleanup_w;
    if ((r = u8bMap(blob_b, GET_BLOB_MAX)) != OK) { u8bUnMap(blob_a); goto cleanup_w; }
    Bu8 *cur = &blob_a, *prev = &blob_b;

    b8 have_prev = NO;
    for (u32 i = 0; i < nvers; i++) {
        u64 commit_h = vers[i];
        u8bReset(*cur);
        ok64 fo = GRAFBlobAtCommit(*cur, &KEEP, commit_h, path);
        if (fo != OK) continue;

        if (have_prev) {
            a_dup(u8c, cur_data,  u8bDataC(*cur));
            a_dup(u8c, prev_data, u8bDataC(*prev));
            if (u8csEq(cur_data, prev_data)) continue;
        }

        a_dup(u8c, new_data, u8bDataC(*cur));
        u32 sc = (u32)commit_h;
        ok64 fbo = WEAVEFromBlob(&wnu, new_data, ext, sc);
        if (fbo == OK) {
            ok64 dfo = WEAVEDiff(wdst, wsrc, &wnu, sc);
            if (dfo == OK) {
                weave *wtmp = wsrc; wsrc = wdst; wdst = wtmp;
                if (out_ids[0]) (void)u32bFeed1(out_ids, sc);
            }
        }

        Bu8 *tmp = cur; cur = prev; prev = tmp;
        have_prev = YES;
    }

    //  Move wsrc's contents into out (caller's buffer).  Cheapest
    //  route: copy the four buffer headers; wsrc's mappings now
    //  belong to out, and we replace wsrc/wdst before freeing so we
    //  don't double-free.
    if (wsrc == &wA) {
        memcpy(out, &wA, sizeof(weave));
        memset(&wA, 0, sizeof(weave));
    } else {
        memcpy(out, &wB, sizeof(weave));
        memset(&wB, 0, sizeof(weave));
    }

    u8bUnMap(blob_a);
    u8bUnMap(blob_b);
cleanup_w:
    WEAVEFree(&wA);
    WEAVEFree(&wB);
    WEAVEFree(&wnu);
out:
    if (u8bOK(ord_buf)) u8bUnMap(ord_buf);
    return r;
}

//  Render `w`'s alive tokens into `into` in weave order.
static ok64 emit_alive_bytes(u8b into, weave const *w) {
    sane(into && w);
    u32cp toks   = (u32cp)w->toks[1];
    u32cp toks_e = (u32cp)w->toks[2];
    u32   ntok   = (u32)(toks_e - toks);
    inrmcp irm   = (inrmcp)w->inrm[1];
    u8cp   text  = (u8cp)w->text[1];
    for (u32 i = 0; i < ntok; i++) {
        if (irm[i].rm != 0) continue;
        u32 lo = (i == 0) ? 0 : tok32Offset(toks[i - 1]);
        u32 hi = tok32Offset(toks[i]);
        u8cs ts = {text + lo, text + hi};
        call(u8bFeed, into, ts);
    }
    done;
}


// --- Resolve commit_h40 + dir-path → tree object body ---
//
//  Mirrors GRAFBlobAtCommit but stops on the last path segment (or
//  the root tree if `path` is empty) instead of recursing into a
//  blob.  Emits the tree object's raw body into `into`.
static ok64 get_tree_at(u8b into, keeper *k, u64 commit_h40, u8cs path) {
    sane(into && k);

    Bu8 cbuf = {};
    call(u8bAllocate, cbuf, 1UL << 20);
    u8 ct = 0;
    ok64 o = KEEPGet(k, commit_h40, DAG_H60_HEXLEN, cbuf, &ct);
    if (o != OK || ct != DOG_OBJ_COMMIT) { u8bFree(cbuf); return KEEPNONE; }

    sha1 cur = {};
    b8 got_tree = NO;
    {
        a_dup(u8c, scan, u8bDataC(cbuf));
        u8cs field = {}, value = {};
        while (GITu8sDrainCommit(scan, field, value) == OK) {
            if (u8csEmpty(field)) break;
            if (u8csEq(field, GIT_FIELD_TREE) && u8csLen(value) >= 40) {
                DAGsha1FromHex(&cur, (char const *)value[0]);
                got_tree = YES;
                break;
            }
        }
    }
    u8bFree(cbuf);
    if (!got_tree) return KEEPNONE;

    //  Walk into `path` one segment at a time.  Empty path = root tree.
    u8cs rest = {path[0], path[1]};
    while (!$empty(rest)) {
        u8cp slash = rest[0];
        while (slash < rest[1] && *slash != '/') slash++;
        u8cs name = {rest[0], slash};
        if (!$empty(name)) {
            ok64 s = GRAFTreeStep(k, &cur, name);
            if (s != OK) return s;
        }
        rest[0] = (slash < rest[1]) ? slash + 1 : slash;
    }

    Bu8 tbuf = {};
    call(u8bAllocate, tbuf, 1UL << 20);
    u8 ot = 0;
    ok64 ko = KEEPGetExact(k, &cur, tbuf, &ot);
    if (ko == OK && ot == DOG_OBJ_TREE) {
        a_dup(u8c, tb, u8bData(tbuf));
        ko = u8bFeed(into, tb);
    } else if (ko == OK) {
        ko = KEEPFAIL;
    }
    u8bFree(tbuf);
    return ko;
}

// --- Public entry ---
//
//  Single-tip blob/tree read.  Multi-tip merge URIs (`path?A&B...`)
//  are no longer accepted — merge is PATCH territory.  Callers in
//  need of a 3-way merge use `GRAFMergeWtFileTunable` (DAG-aware,
//  takes commit shas) directly.

ok64 GRAFGet(u8b into, u8csc uri) {
    sane(into && uri);

    u8cs path = {};
    get_tip tips[GET_MAX_TIPS] = {};
    u32 ntips = 0;
    b8 is_tree = NO;
    a_dup(u8c, uri_in, uri);
    call(get_drain_uri, path, tips, &ntips, GET_MAX_TIPS,
         &is_tree, uri_in);

    if (ntips == 0)  return GETNOTIPS;
    if (ntips != 1)  return GETBAD;   // multi-tip merge URIs retired

    if (is_tree) {
        //  Strip the trailing '/' so the path reads as a dir name.
        if ($len(path) > 0 && path[1][-1] == '/') path[1]--;
        return get_tree_at(into, &KEEP, tips[0].h40, path);
    }

    return get_append_blob_at(into, tips[0].h40, path);
}
