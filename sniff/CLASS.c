//  CLASS — see CLASS.h.

#include "CLASS.h"

#include <string.h>

#include "abc/B.h"
#include "abc/HEX.h"
#include "abc/PRO.h"
#include "abc/URI.h"
#include "dog/DOG.h"
#include "keeper/GIT.h"
#include "keeper/KEEP.h"
#include "keeper/WALK.h"

#include "AT.h"
#include "SNIFF.h"

#define CLASS_PD_BUF (1UL << 16)

#define CLASS_BU_BUF (1UL << 20)
#define CLASS_WU_BUF (1UL << 20)

// --- Resolve baseline tree sha (mirror of POST/PUT/DEL helpers) ---

static ok64 class_baseline_tree(sha1 *out, b8 *have_out) {
    sane(out && have_out);
    *have_out = NO;
    ron60 ts = 0, verb = 0;
    uri u = {};
    ok64 br = SNIFFAtBaseline(&ts, &verb, &u);
    if (br == ULOGNONE) return OK;          // fresh repo
    if (br != OK) return br;

    u8 hex40[40];
    if (SNIFFAtQueryFirstSha(&u, hex40) != OK) return OK;

    sha1 commit_sha = {};
    a_raw(csha_bin, commit_sha);
    u8cs h40 = {hex40, hex40 + 40};
    if (HEXu8sDrainSome(csha_bin, h40) != OK) return OK;

    Bu8 cbuf = {};
    call(u8bAllocate, cbuf, 1UL << 20);
    u8 ctype = 0;
    ok64 go = KEEPGetExact(&KEEP, &commit_sha, cbuf, &ctype);
    if (go != OK || ctype != DOG_OBJ_COMMIT) {
        u8bFree(cbuf); return OK;
    }
    u8cs body = {u8bDataHead(cbuf), u8bIdleHead(cbuf)};
    ok64 to = GITu8sCommitTree(body, out->data);
    u8bFree(cbuf);
    if (to != OK) return to;
    *have_out = YES;
    done;
}

// --- Staged put/delete row collector ---
//
//  Walks `.sniff` rows since the last post via `SNIFFAtScanPutDelete`,
//  emitting per-row ULOG bytes into the matching unsorted buffer.
//  Sort is the heap-merge's job; we just produce two cursors.

#define CLASS_SUB_BUF (1UL << 12)

typedef struct {
    u8bp  put_buf;
    u8bp  del_buf;
    ron60 v_put_filter;
    ron60 v_del_filter;
    ron60 v_put_emit;
    ron60 v_del_emit;
    ok64  err;
} class_pd_ctx;

static ok64 class_pd_cb(ron60 verb, u8cs path, ron60 ts, void *ctx_) {
    class_pd_ctx *c = (class_pd_ctx *)ctx_;
    //  Skip dir-prefix rows (`put lib/` etc.) — for status we accept
    //  the imprecision; expanding against bu/wu would replicate POST.
    if (!$empty(path) && *u8csLast(path) == '/') return OK;
    uri u = {};
    u.path[0] = path[0];
    u.path[1] = path[1];
    if (verb == c->v_put_filter) {
        ulogrec rec = {.ts = ts, .verb = c->v_put_emit, .uri = u};
        ok64 r = ULOGu8sFeed(u8bIdle(c->put_buf), &rec);
        if (r != OK) c->err = r;
        return r;
    }
    if (verb == c->v_del_filter) {
        ulogrec rec = {.ts = ts, .verb = c->v_del_emit, .uri = u};
        ok64 r = ULOGu8sFeed(u8bIdle(c->del_buf), &rec);
        if (r != OK) c->err = r;
        return r;
    }
    return OK;
}

//  Sort `src` (per-row ULOG bytes) into `dst` lex-by-path.  Heap-pop
//  pattern straight from POST.c's post_sort_dedup_intent.
static ok64 class_sort_pd(u8b src, u8b dst) {
    sane(src && dst);
    u8bReset(dst);
    if (u8bDataLen(src) == 0) done;
    Bu8cs slices = {};
    size_t cap = u8bDataLen(src) / 16 + 16;
    call(u8csbAllocate, slices, cap);
    u8c *base = u8bDataHead(src);
    u8c *term = base + u8bDataLen(src);
    for (u8c *p = base; p < term; ) {
        u8c *line_start = p;
        while (p < term && *p != '\n') p++;
        if (p < term) p++;
        u8cs slice = {line_start, p};
        ok64 fo = u8csbFeedP(slices, &slice);
        if (fo != OK) { u8csbFree(slices); return fo; }
    }
    u8cssHeapZ(u8csbData(slices), ULOGu8csZbyUri);
    while (u8csbDataLen(slices) > 0) {
        u8cs cur = {};
        ok64 po = HEAPu8csPopZ(&cur, slices, ULOGu8csZbyUri);
        if (po != OK) break;
        a_dup(u8c, cur_dup, cur);
        ok64 fo = u8bFeed(dst, cur_dup);
        if (fo != OK) { u8csbFree(slices); return fo; }
    }
    u8csbFree(slices);
    done;
}

// --- SNIFFMergeWalk step shim ---
//
//  Tracks an active set of submodule (`160000` gitlink) directory
//  prefixes seen earlier in the merge.  Any subsequent step whose
//  path starts with `<prefix>/` is silently dropped — gitlinks own
//  their internal state.  The merge yields paths in lex order, so a
//  submodule's own row arrives before any of its descendants.

typedef struct {
    class_cb cb;
    void    *ctx;
    ron60    v_base;
    ron60    v_wt;
    ron60    v_put;
    ron60    v_del;
    Bu8      sub_prefixes;   // newline-separated `<path>/`
    b8       sub_init;
} class_walk_ctx;

static b8 class_under_submodule(class_walk_ctx const *w, u8cs path) {
    if (!w->sub_init) return NO;
    u8cs scan = {u8bDataHead(w->sub_prefixes),
                 u8bIdleHead(w->sub_prefixes)};
    size_t pl = (size_t)$len(path);
    while (!$empty(scan)) {
        u8cp nl = scan[0];
        while (nl < scan[1] && *nl != '\n') nl++;
        size_t prl = (size_t)(nl - scan[0]);
        if (prl > 0 && prl <= pl &&
            memcmp(scan[0], path[0], prl) == 0)
            return YES;
        scan[0] = (nl < scan[1]) ? nl + 1 : scan[1];
    }
    return NO;
}

static ok64 class_remember_submodule(class_walk_ctx *w, u8cs path) {
    if (!w->sub_init) {
        ok64 ao = u8bAllocate(w->sub_prefixes, CLASS_SUB_BUF);
        if (ao != OK) return ao;
        w->sub_init = YES;
    }
    (void)u8bFeed(w->sub_prefixes, path);
    (void)u8bFeed1(w->sub_prefixes, '/');
    (void)u8bFeed1(w->sub_prefixes, '\n');
    return OK;
}

static ok64 class_merge_step(ulogreccp recs, u32 n, void *ctx_) {
    class_walk_ctx *w = (class_walk_ctx *)ctx_;

    ulogreccp base = NULL, wt = NULL, put = NULL, del = NULL;
    for (u32 i = 0; i < n; i++) {
        if      (recs[i].verb == w->v_base) base = &recs[i];
        else if (recs[i].verb == w->v_wt)   wt   = &recs[i];
        else if (recs[i].verb == w->v_put)  put  = &recs[i];
        else if (recs[i].verb == w->v_del)  del  = &recs[i];
    }

    u8cs path = {};
    ulogreccp src = base ? base : wt ? wt : put ? put : del;
    if (!src) return OK;
    path[0] = src->uri.path[0];
    path[1] = src->uri.path[1];

    //  Anything inside a previously-recorded submodule prefix → drop.
    //  Catches wt-scan rows that descended into the gitlinked dir
    //  (the embedded repo's own files have no business in our status).
    if (class_under_submodule(w, path)) return OK;

    //  Gitlink rows themselves (mode `160000` in baseline) → record
    //  the path as a prefix to filter, then drop.
    if (base != NULL) {
        u8cs mode = {base->uri.query[0], base->uri.query[1]};
        a_cstr(gitlink, "160000");
        if ($eq(mode, gitlink)) {
            (void)class_remember_submodule(w, path);
            return OK;
        }
    }

    class_step step = {};
    if (base != NULL && wt != NULL)        step.kind = CLASS_BOTH;
    else if (base != NULL)                 step.kind = CLASS_BASE_ONLY;
    else                                   step.kind = CLASS_WT_ONLY;
    step.path[0] = path[0];
    step.path[1] = path[1];
    step.base_rec = base;
    step.wt_rec   = wt;
    step.put_rec  = put;
    step.del_rec  = del;
    return w->cb(&step, w->ctx);
}

// --- Public entry ---

ok64 SNIFFClassify(class_cb cb, void *ctx) {
    sane(SNIFF.h && cb);
    a_dup(u8c, reporoot, u8bData(SNIFF.h->wt));

    a_cstr(base_name, "base");
    a_cstr(wt_name,   "wt");
    a_cstr(put_name,  "put");
    a_cstr(del_name,  "del");
    ron60 v_base = SNIFFAtVerbOf(base_name);
    ron60 v_wt   = SNIFFAtVerbOf(wt_name);
    ron60 v_put  = SNIFFAtVerbOf(put_name);
    ron60 v_del  = SNIFFAtVerbOf(del_name);

    Bu8 bu = {}, wu = {}, pu_unsorted = {}, du_unsorted = {};
    Bu8 pu = {}, du = {};
    call(u8bAllocate, bu, CLASS_BU_BUF);
    call(u8bAllocate, wu, CLASS_WU_BUF);
    call(u8bAllocate, pu_unsorted, CLASS_PD_BUF);
    call(u8bAllocate, du_unsorted, CLASS_PD_BUF);
    call(u8bAllocate, pu, CLASS_PD_BUF);
    call(u8bAllocate, du, CLASS_PD_BUF);

#define CLASS_FREE_ALL()                          \
    do { u8bFree(bu); u8bFree(wu);                \
         u8bFree(pu_unsorted); u8bFree(du_unsorted); \
         u8bFree(pu); u8bFree(du); } while (0)

    sha1 base_tree = {};
    b8 have_base = NO;
    ok64 br = class_baseline_tree(&base_tree, &have_base);
    if (br != OK) { CLASS_FREE_ALL(); return br; }
    if (have_base) {
        ok64 to = KEEPTreeULog(&KEEP, base_tree.data, 0, v_base, bu);
        if (to != OK) { CLASS_FREE_ALL(); return to; }
    }
    ok64 wr = SNIFFWtULog(reporoot, v_wt, wu);
    if (wr != OK) { CLASS_FREE_ALL(); return wr; }

    //  Pull every put/delete row since the most recent post into the
    //  unsorted intent buffers, then sort each by URI key.
    class_pd_ctx pdc = {
        .put_buf = pu_unsorted, .del_buf = du_unsorted,
        .v_put_filter = SNIFFAtVerbPut(),
        .v_del_filter = SNIFFAtVerbDelete(),
        .v_put_emit   = v_put,
        .v_del_emit   = v_del,
    };
    ron60 floor = SNIFFAtLastPostTs();
    ok64 sr = SNIFFAtScanPutDelete(floor, class_pd_cb, &pdc);
    if (sr != OK || pdc.err != OK) {
        CLASS_FREE_ALL(); return sr != OK ? sr : pdc.err;
    }
    ok64 spo = class_sort_pd(pu_unsorted, pu);
    if (spo != OK) { CLASS_FREE_ALL(); return spo; }
    ok64 sdo = class_sort_pd(du_unsorted, du);
    if (sdo != OK) { CLASS_FREE_ALL(); return sdo; }

    a_dup(u8c, view_b, u8bData(bu));
    a_dup(u8c, view_w, u8bData(wu));
    a_dup(u8c, view_p, u8bData(pu));
    a_dup(u8c, view_d, u8bData(du));
    a_pad(u8cs, ins, 4);
    u8cssFeed1(ins_idle, view_b);
    u8cssFeed1(ins_idle, view_w);
    u8cssFeed1(ins_idle, view_p);
    u8cssFeed1(ins_idle, view_d);
    a_dup(u8cs, cursors, u8csbData(ins));

    class_walk_ctx wctx = {.cb = cb, .ctx = ctx,
                           .v_base = v_base, .v_wt = v_wt,
                           .v_put = v_put,   .v_del = v_del};
    ok64 mr = SNIFFMergeWalk(cursors, class_merge_step, &wctx);
    if (wctx.sub_init) u8bFree(wctx.sub_prefixes);
    CLASS_FREE_ALL();
#undef CLASS_FREE_ALL
    return mr;
}
