//  GET: URI-driven deterministic blob merge.
//
//  `path?sha1&sha2&...&shaN` → weave-merged bytes appended to `into`.
//  See graf/GET.md for the full surface.
//
#include "GRAF.h"

#include <string.h>

#include "BLOB.h"
#include "DAG.h"
#include "JOIN.h"
#include "WEAVE.h"

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
#define GET_MAX_VERS   512
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

    out->h40 = WHIFFHashlet40(&out->sha);
    out->gen = DAGCommitGen(&GRAF.idx, out->h40);
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
//  Intersects each tip's ancestor set and returns the member with
//  the highest `gen`.  Returns 0 when:
//    * the DAG index is empty (graf hasn't indexed yet), or
//    * the two tips share no ancestors (unlikely for a real repo,
//      but tolerated — callers fall back to `ours`).
//
//  Iteration peeks at the raw hash-table slots: DAGAncestors inserts
//  with `key = wh64Pack(0, 0, h40)`, so any slot whose 40-bit hashlet
//  bits (`DAGHashlet`) are non-zero is an occupied entry.

static u64 get_lca(u64 a_h40, u64 b_h40) {
    if (a_h40 == 0 || b_h40 == 0) return 0;

    Bwh128 set_a = {}, set_b = {};
    if (wh128bAllocate(set_a, GET_ANC_SIZE) != OK) return 0;
    if (wh128bAllocate(set_b, GET_ANC_SIZE) != OK) {
        wh128bFree(set_a); return 0;
    }

    ok64 oa = DAGAncestors(set_a, &GRAF.idx, a_h40, 0);
    ok64 ob = DAGAncestors(set_b, &GRAF.idx, b_h40, 0);
    if (oa != OK || ob != OK) {
        wh128bFree(set_a); wh128bFree(set_b);
        return 0;
    }

    u64 best = 0;
    u32 best_gen = 0;
    wh128cp cells = wh128bHead(set_a);
    wh128cp cells_end = wh128bTerm(set_a);
    for (wh128cp c = cells; c < cells_end; c++) {
        u64 h = DAGHashlet(c->key);
        if (h == 0) continue;
        if (!DAGAncestorsHas(set_b, h)) continue;
        u32 g = DAGCommitGen(&GRAF.idx, h);
        if (g > best_gen) { best_gen = g; best = h; }
    }

    wh128bFree(set_a);
    wh128bFree(set_b);
    return best;
}

// Public wrapper: `sha1 *` in/out for callers outside graf (sniff's
// PATCH uses this to classify modify/delete cases).  Returns OK with
// `*out` all-zero when no shared ancestor is indexed.
ok64 GRAFLca(sha1 *out, sha1 const *a, sha1 const *b) {
    sane(out && a && b);
    memset(out->data, 0, sizeof(out->data));

    u64 a_h40 = WHIFFHashlet40(a);
    u64 b_h40 = WHIFFHashlet40(b);
    u64 lca_h = get_lca(a_h40, b_h40);
    if (lca_h == 0) done;   // unrelated histories — leave out zero

    //  Recover the full sha by fetching the commit body from keeper
    //  and rehashing (identical to the trick `get_resolve_qref`
    //  uses — KEEPObjSha("commit <len>\0<body>") is canonical).
    Bu8 cbuf = {};
    call(u8bAllocate, cbuf, 1UL << 20);
    u8 ct = 0;
    ok64 o = KEEPGet(&KEEP, DAGh40ToKeeperPrefix(lca_h),
                     DAG_H40_HEXLEN, cbuf, &ct);
    if (o != OK || ct != DOG_OBJ_COMMIT) { u8bFree(cbuf); done; }

    a_dup(u8c, body, u8bData(cbuf));
    KEEPObjSha(out, DOG_OBJ_COMMIT, body);
    u8bFree(cbuf);
    done;
}

// --- 2-way blob merge via JOIN (3-way with LCA as base) --------------

static ok64 get_merge_2way(u8b into, u8cs path, get_tip const *tips) {
    sane(into && tips);

    u64 lca_h = get_lca(tips[0].h40, tips[1].h40);

    //  Tokenizer extension from the file's name.
    u8cs ext = {};
    PATHu8sExt(ext, path);

    Bu8 bbuf = {}, obuf = {}, tbuf = {};
    call(u8bMap, bbuf, GET_BLOB_MAX);
    call(u8bMap, obuf, GET_BLOB_MAX);
    call(u8bMap, tbuf, GET_BLOB_MAX);

    //  Fetch base: missing path at LCA (file new on both branches)
    //  leaves `bbuf` empty — JOINMerge handles that by degenerating
    //  to "take ours", which is the best we can do without history.
    if (lca_h != 0) GRAFBlobAtCommit(bbuf, &KEEP, lca_h, path);

    ok64 oo = GRAFBlobAtCommit(obuf, &KEEP, tips[0].h40, path);
    ok64 to = GRAFBlobAtCommit(tbuf, &KEEP, tips[1].h40, path);

    ok64 ret = OK;
    if (oo != OK && to != OK) {
        ret = GETFAIL;
    } else if (oo != OK) {
        //  path present only at tips[1] — emit its bytes.
        a_dup(u8c, tb, u8bData(tbuf));
        ret = u8bFeed(into, tb);
    } else if (to != OK) {
        //  path present only at tips[0] — emit its bytes.
        a_dup(u8c, ob, u8bData(obuf));
        ret = u8bFeed(into, ob);
    } else {
        //  Full 3-way: tokenize base/ours/theirs and run JOIN.
        JOINfile bjf = {}, ojf = {}, tjf = {};
        a_dup(u8c, bdata, u8bData(bbuf));
        a_dup(u8c, odata, u8bData(obuf));
        a_dup(u8c, tdata, u8bData(tbuf));

        ret = JOINTokenize(&bjf, bdata, ext);
        if (ret == OK) ret = JOINTokenize(&ojf, odata, ext);
        if (ret == OK) ret = JOINTokenize(&tjf, tdata, ext);
        if (ret == OK) ret = JOINMerge(into, &bjf, &ojf, &tjf);

        JOINFree(&bjf);
        JOINFree(&ojf);
        JOINFree(&tjf);
    }

    u8bUnMap(bbuf);
    u8bUnMap(obuf);
    u8bUnMap(tbuf);
    return ret;
}

// --- Weave-replay the path history over the ancestor union ---

static ok64 get_weave_union(u8b into, u8cs path,
                            get_tip const *tips, u32 ntips) {
    sane(into && ntips > 0);

    //  Ancestor union across all tips.
    Bwh128 anc = {};
    call(wh128bAllocate, anc, GET_ANC_SIZE);

    u64 tip_hs[GET_MAX_TIPS] = {};
    for (u32 i = 0; i < ntips; i++) tip_hs[i] = tips[i].h40;
    ok64 ao = DAGAncestorsOfMany(anc, &GRAF.idx, tip_hs, ntips);
    if (ao != OK) { wh128bFree(anc); return ao; }

    //  Per-path PATH_VER hits inside the union (newest-first).
    graf_pathver vers[GET_MAX_VERS];
    u32 nvers = DAGPathVers(vers, GET_MAX_VERS, &GRAF.idx, path, anc);
    wh128bFree(anc);

    //  Fall-back: no DAG entries — fetch the blob at the first tip
    //  directly.  Covers freshly-imported repos where GRAFIndex
    //  hasn't run, and isolated blob-URI cases.
    if (nvers == 0) {
        return get_append_blob_at(into, tips[0].h40, path);
    }

    //  Reverse to oldest-first (gen ascending).
    for (u32 i = 0; i < nvers / 2; i++) {
        graf_pathver tmp = vers[i];
        vers[i] = vers[nvers - 1 - i];
        vers[nvers - 1 - i] = tmp;
    }

    //  Tokenizer extension driven by path's suffix — trailing '/'
    //  already routed to tree mode, so path ends on a file name.
    u8cs ext = {};
    PATHu8sExt(ext, path);

    weave wv = {};
    call(WEAVEInit, &wv, 0);

    //  Two blob buffers swapped per version; `prev` holds the most
    //  recently fed content for WEAVEAdd's diff basis.
    Bu8 blob_a = {}, blob_b = {};
    call(u8bMap, blob_a, GET_BLOB_MAX);
    call(u8bMap, blob_b, GET_BLOB_MAX);
    Bu8 *cur = &blob_a, *prev = &blob_b;

    b8 have_prev = NO;
    for (u32 i = 0; i < nvers; i++) {
        u8bReset(*cur);
        ok64 fo = GRAFBlobAtCommit(*cur, &KEEP,
                                   vers[i].commit_hashlet, path);
        if (fo != OK) continue;

        //  Byte-level dedup: skip versions whose bytes match the
        //  immediately previous kept version.
        if (have_prev) {
            size_t cl = u8bDataLen(*cur);
            size_t pl = u8bDataLen(*prev);
            if (cl == pl && (cl == 0 ||
                memcmp(u8bDataHead(*cur),
                       u8bDataHead(*prev), cl) == 0))
                continue;
        }

        u8cs old_data = {};
        if (have_prev) {
            old_data[0] = u8bDataHead(*prev);
            old_data[1] = u8bDataHead(*prev) + u8bDataLen(*prev);
        }
        u8cs new_data = {u8bDataHead(*cur),
                         u8bDataHead(*cur) + u8bDataLen(*cur)};

        WEAVEAdd(&wv, old_data, new_data, ext, vers[i].gen);

        Bu8 *tmp = cur; cur = prev; prev = tmp;
        have_prev = YES;
    }
    u8bUnMap(blob_a);
    u8bUnMap(blob_b);

    //  Projection: token alive iff del_gen == 0.  Every fed gen
    //  lives in the ancestor union by construction, so "still alive
    //  at the end of the linear replay" is the union projection for
    //  linear histories; for diverged branches this is a first-pass
    //  approximation — correctness of true octopus merges lands in
    //  follow-up work (see graf/GET.md).
    u32 wlen = WEAVELen(&wv);
    wtokcp wtoks = WEAVETokens(&wv);
    for (u32 i = 0; i < wlen; i++) {
        if (wtoks[i].del_gen != 0) continue;
        a_dup(u8c, ts, wtoks[i].tok);
        ok64 o = u8bFeed(into, ts);
        if (o != OK) { WEAVEFree(&wv); return o; }
    }

    WEAVEFree(&wv);
    done;
}

// --- Resolve commit_h40 + dir-path → tree sha ---
//
//  Mirrors GRAFBlobAtCommit but stops on the last path segment (or
//  the root tree if `path` is empty) instead of resolving a blob.
//  `path` is the repo-relative dir path with no trailing '/'.
static ok64 get_tree_at(sha1 *tree_out, keeper *k,
                        u64 commit_h40, u8cs path) {
    sane(tree_out && k);

    Bu8 cbuf = {};
    call(u8bAllocate, cbuf, 1UL << 20);
    u8 ct = 0;
    ok64 o = KEEPGet(k, DAGh40ToKeeperPrefix(commit_h40),
                     DAG_H40_HEXLEN, cbuf, &ct);
    if (o != OK || ct != DOG_OBJ_COMMIT) { u8bFree(cbuf); return KEEPNONE; }

    sha1 cur = {};
    b8 got = NO;
    {
        a_dup(u8c, scan, u8bDataC(cbuf));
        u8cs field = {}, value = {};
        while (GITu8sDrainCommit(scan, field, value) == OK) {
            if (u8csEmpty(field)) break;
            a_cstr(ft, "tree");
            if ($eq(field, ft) && u8csLen(value) >= 40) {
                DAGsha1FromHex(&cur, (char const *)value[0]);
                got = YES;
                break;
            }
        }
    }
    u8bFree(cbuf);
    if (!got) return KEEPNONE;

    //  Descend each non-empty segment.  Empty `path` = root tree.
    u8cs rest = {path[0], path[1]};
    while (!$empty(rest)) {
        u8cp slash = rest[0];
        while (slash < rest[1] && *slash != '/') slash++;
        u8cs name = {rest[0], slash};
        if (!$empty(name)) {
            call(GRAFTreeStep, k, &cur, name);
        }
        rest[0] = (slash < rest[1]) ? slash + 1 : slash;
    }

    *tree_out = cur;
    done;
}

// --- Union-merge of N trees at `path`, emits git-tree-format bytes ---
//
//  For each entry name seen in any tip:
//    - all present tips agree on sha       → pass-through
//    - present in exactly one tip           → pass-through
//    - disagreement                         → recurse via GRAFGet
//  Mode ties broken by first present tip.  Tree / blob kind carried
//  from the first present tip that marks it as dir.  Output entry
//  order is bytewise ascending by name (deterministic; note it is
//  close to but NOT identical to git's `<name>` + implicit-slash
//  canonical sort — see graf/GET.md).

typedef struct {
    u8cs name;
    u8cs mode[GET_MAX_TIPS];
    sha1 sha[GET_MAX_TIPS];
    b8   present[GET_MAX_TIPS];
    b8   any_dir;
} get_tree_rec;

static int get_name_cmp(u8cs a, u8cs b) {
    size_t la = $len(a), lb = $len(b);
    size_t ml = la < lb ? la : lb;
    int c = (ml == 0) ? 0 : memcmp(a[0], b[0], ml);
    if (c != 0) return c;
    if (la < lb) return -1;
    if (la > lb) return 1;
    return 0;
}

static ok64 get_tree_merge(u8b into, u8cs path,
                           get_tip const *tips, u32 ntips) {
    sane(into && tips && ntips > 0);

    //  Resolve each tip's tree sha at `path`.  Tips lacking the
    //  path (absent dir on a branch) drop out quietly.
    sha1 tree_shas[GET_MAX_TIPS] = {};
    b8   tip_has[GET_MAX_TIPS] = {};
    u32  tips_present = 0;
    for (u32 i = 0; i < ntips; i++) {
        ok64 o = get_tree_at(&tree_shas[i], &KEEP, tips[i].h40, path);
        if (o == OK) { tip_has[i] = YES; tips_present++; }
    }
    if (tips_present == 0) return KEEPNONE;

    Bu8 arena = {};
    call(u8bMap, arena, GET_TREE_ARENA);

    get_tree_rec *recs = calloc(GET_TREE_MAX_ENTRIES, sizeof(*recs));
    if (!recs) { u8bUnMap(arena); return GETFAIL; }
    u32 nrec = 0;
    ok64 ret = OK;

    for (u32 ti = 0; ti < ntips && ret == OK; ti++) {
        if (!tip_has[ti]) continue;

        Bu8 tbuf = {};
        if (u8bAllocate(tbuf, 1UL << 20) != OK) continue;
        u8 otype = 0;
        if (KEEPGetExact(&KEEP, &tree_shas[ti], tbuf, &otype) != OK
            || otype != DOG_OBJ_TREE) {
            u8bFree(tbuf);
            continue;
        }

        u8cs body = {u8bDataHead(tbuf), u8bIdleHead(tbuf)};
        u8cs file = {}, esha = {};
        while (GITu8sDrainTree(body, file, esha) == OK) {
            u8cs scan = {file[0], file[1]};
            if (u8csFind(scan, ' ') != OK) continue;
            u8cs mode_s = {file[0], scan[0]};
            u8cs name_s = {scan[0] + 1, file[1]};
            if ($empty(name_s) || u8csLen(esha) != 20) continue;

            get_tree_rec *r = NULL;
            for (u32 j = 0; j < nrec; j++) {
                if (get_name_cmp(recs[j].name, name_s) == 0) {
                    r = &recs[j]; break;
                }
            }
            if (!r) {
                if (nrec >= GET_TREE_MAX_ENTRIES) continue;
                r = &recs[nrec++];
                size_t nl = $len(name_s);
                if (u8bIdleLen(arena) < nl) { nrec--; continue; }
                u8p nbase = u8bIdleHead(arena);
                memcpy(nbase, name_s[0], nl);
                ((u8 **)arena)[2] += nl;
                r->name[0] = nbase;
                r->name[1] = nbase + nl;
            }
            size_t ml = $len(mode_s);
            if (u8bIdleLen(arena) < ml) continue;
            u8p mbase = u8bIdleHead(arena);
            memcpy(mbase, mode_s[0], ml);
            ((u8 **)arena)[2] += ml;
            r->mode[ti][0] = mbase;
            r->mode[ti][1] = mbase + ml;
            r->present[ti] = YES;
            memcpy(r->sha[ti].data, esha[0], 20);
            //  Git tree mode: "40000" for subtrees, "1XXXXX" for
            //  blobs/symlinks, "160000" for gitlinks.  '4' prefix ⇒
            //  dir.
            if (ml > 0 && *mbase == '4') r->any_dir = YES;
        }
        u8bFree(tbuf);
    }

    //  Sort indices by name bytewise.
    u32 *idx = calloc(nrec ? nrec : 1, sizeof(u32));
    if (!idx) { free(recs); u8bUnMap(arena); return GETFAIL; }
    for (u32 i = 0; i < nrec; i++) idx[i] = i;
    for (u32 i = 1; i < nrec; i++) {
        u32 v = idx[i];
        u32 j = i;
        while (j > 0 &&
               get_name_cmp(recs[idx[j - 1]].name, recs[v].name) > 0) {
            idx[j] = idx[j - 1];
            j--;
        }
        idx[j] = v;
    }

    for (u32 ii = 0; ii < nrec && ret == OK; ii++) {
        get_tree_rec *r = &recs[idx[ii]];
        u32 present_tips[GET_MAX_TIPS];
        u32 npres = 0;
        for (u32 ti = 0; ti < ntips; ti++)
            if (r->present[ti]) present_tips[npres++] = ti;
        if (npres == 0) continue;

        b8 agree = YES;
        for (u32 k = 1; k < npres; k++) {
            if (memcmp(r->sha[present_tips[0]].data,
                       r->sha[present_tips[k]].data, 20) != 0) {
                agree = NO; break;
            }
        }

        sha1 final_sha = r->sha[present_tips[0]];
        u8cs final_mode = {
            r->mode[present_tips[0]][0],
            r->mode[present_tips[0]][1],
        };

        if (!agree) {
            //  Conflicting child: the merged content exists only as
            //  bytes graf can reproduce on demand (`GRAFGet <child
            //  URI>`) — it has no object in any store.  Emit a
            //  zero sha to flag the entry as unresolvable rather
            //  than a fake `sha1(merged-bytes)` that no keeper can
            //  dereference.
            memset(final_sha.data, 0, sizeof(final_sha.data));
        }

        //  Emit "<mode> <name>\0<20-byte sha>" into `into`.
        ret = u8bFeed(into, final_mode);
        if (ret == OK) ret = u8bFeed1(into, ' ');
        if (ret == OK) ret = u8bFeed(into, r->name);
        if (ret == OK) ret = u8bFeed1(into, 0);
        if (ret == OK) {
            u8cs sb = {final_sha.data, final_sha.data + 20};
            ret = u8bFeed(into, sb);
        }
    }

    free(idx);
    free(recs);
    u8bUnMap(arena);
    return ret;
}

// --- Public entry ---

ok64 GRAFGet(u8b into, u8csc uri) {
    sane(into && uri);

    u8cs path = {};
    get_tip tips[GET_MAX_TIPS] = {};
    u32 ntips = 0;
    b8 is_tree = NO;
    a_dup(u8c, uri_in, uri);
    call(get_drain_uri, path, tips, &ntips, GET_MAX_TIPS,
         &is_tree, uri_in);

    if (ntips == 0) return GETNOTIPS;

    if (is_tree) {
        //  Strip the trailing '/' so the path reads as the directory
        //  name for `get_tree_at` / recursion.  Root-tree URI
        //  (`/?...` → single '/') collapses to empty path.
        if ($len(path) > 0 && path[1][-1] == '/') path[1]--;
        return get_tree_merge(into, path, tips, ntips);
    }

    //  Single-tip identity: skip the DAG walk entirely.
    if (ntips == 1) {
        return get_append_blob_at(into, tips[0].h40, path);
    }

    //  Two-tip: true 3-way merge via JOIN using the DAG LCA as base.
    //  This is the supported octopus cardinality; larger N falls
    //  through to the weave-union approximation documented in
    //  graf/GET.md.
    if (ntips == 2) {
        return get_merge_2way(into, path, tips);
    }

    return get_weave_union(into, path, tips, ntips);
}
