//  INDEX: drive graf's streaming DAG ingest from keeper's pack store.
//
//  Two entry points:
//
//   * `GRAFIndex(k)` — full reindex.  Enumerates every COMMIT in
//     keeper's LSM runs (pack-offset sorted), pulls the body via
//     KEEPGet, feeds GRAFDagUpdate, finishes.  Used by `graf index`
//     (no URI) for forced rebuilds.
//
//   * `GRAFIndexFromTips(k, u)` — incremental walk.  Resolves the
//     URI's tip(s) and walks back over COMMIT_PARENT edges via
//     KEEPGet, stopping per-branch when the next parent is already
//     in graf's own DAG (mention ≡ known per DAG.md).  Used by
//     `graf get URI` under the new arrangement (DOG.md §10a).
//
//  Trees and blobs are not indexed — the commit→tree edge and the
//  on-disk keeper objects are sufficient to descend to any path at
//  query time.

#include "GRAF.h"
#include "DAG.h"

#include <stdlib.h>

#include "abc/FILE.h"
#include "abc/PRO.h"
#include "abc/URI.h"
#include "dog/DOG.h"
#include "dog/WHIFF.h"
#include "keeper/KEEP.h"

#define GRAF_INGEST_BUFSZ (16UL << 20)  // 16 MB per object

//  One keeper entry we want to replay.
typedef struct {
    u64 hashlet60;
    u64 val;         //  (flags, file_id, offset) — pack-local position
} graf_kent;

static int graf_kent_cmp(void const *a, void const *b) {
    graf_kent const *ka = a, *kb = b;
    //  Sort by (file_id asc, offset asc) — pack ingest order.
    u32 afid = wh64Id(ka->val), bfid = wh64Id(kb->val);
    if (afid != bfid) return afid < bfid ? -1 : 1;
    u64 aoff = wh64Off(ka->val), boff = wh64Off(kb->val);
    if (aoff != boff) return aoff < boff ? -1 : 1;
    return 0;
}

//  Collect all entries of a given obj type from keeper's index.
//  Caller frees *out with free().
static ok64 graf_collect(keeper *k, u8 want_type,
                         graf_kent **out, size_t *nout) {
    sane(k && out && nout);
    *out = NULL;
    *nout = 0;

    size_t cap = 64;
    graf_kent *buf = malloc(cap * sizeof(*buf));
    if (!buf) return NOROOM;
    size_t n = 0;

    u32 nruns = DOGPupCount(k->puppies);
    for (u32 r = 0; r < nruns; r++) {
        u8cs raw = {NULL, NULL};
        DOGPupData(raw, k->puppies, r);
        wh128cp base = (wh128cp)raw[0];
        size_t len = (size_t)((wh128cp)raw[1] - base);
        for (size_t i = 0; i < len; i++) {
            u8 t = keepKeyType(base[i].key);
            if (t != want_type) continue;
            if (n == cap) {
                cap *= 2;
                graf_kent *nb = realloc(buf, cap * sizeof(*buf));
                if (!nb) { free(buf); return NOROOM; }
                buf = nb;
            }
            buf[n].hashlet60 = keepKeyHashlet(base[i].key);
            buf[n].val = base[i].val;
            n++;
        }
    }
    *out = buf;
    *nout = n;
    done;
}

//  Feed every object of type `type`, optionally sorted by pack offset.
static ok64 graf_feed_type(keeper *k, u8 type, b8 sort_by_val, Bu8 body) {
    sane(k && body[0]);
    graf_kent *ents = NULL;
    size_t n = 0;
    call(graf_collect, k, type, &ents, &n);
    if (sort_by_val && n > 1)
        qsort(ents, n, sizeof(*ents), graf_kent_cmp);

    ok64 rc = OK;
    for (size_t i = 0; i < n; i++) {
        u8bReset(body);
        u8 ot = 0;
        ok64 o = KEEPGet(k, ents[i].hashlet60, 15, body, &ot);
        if (o != OK) continue;
        if (ot != type) continue;    //  hashlet collision — skip
        u8cs bs = {u8bDataHead(body), u8bIdleHead(body)};
        //  No pre-computed sha; GRAFDagUpdate hashes `bs` itself.
        //  Manual reindex path, not the hot get path.
        o = GRAFDagUpdate(ot, NULL, bs);
        if (o != OK) { rc = o; break; }
    }

    free(ents);
    return rc;
}

ok64 GRAFIndex(keeper *k) {
    sane(k);

    Bu8 body = {};
    call(u8bMap, body, GRAF_INGEST_BUFSZ);

    //  Only commits are needed — every record we emit is a commit edge.
    ok64 rc = OK;
    if ((rc = graf_feed_type(k, DOG_OBJ_COMMIT, YES, body)) != OK) goto out;

    rc = GRAFDagFinish();

out:
    u8bUnMap(body);
    return rc;
}

// --- Incremental tip-walk (DOG.md §10a, called from `graf get URI`) ---

#include "abc/KV.h"
#include "keeper/GIT.h"

#define GRAF_WALK_SET_CAP (1UL << 16)   // 64K hashlet slots

ok64 GRAFIndexFromTips(keeper *k, uricp u) {
    sane(k && u);

    //  Promote a 40-hex `?<sha>` query or `<sha>` path into the
    //  fragment slot so GRAFResolveTip's first branch (fragment
    //  direct-sha) handles it — its REFSResolve path doesn't
    //  recognise raw shas.
    uri probe = *u;
    u8cs hex_src = {};
    if (u8csEmpty(probe.fragment) && u8csLen(probe.query) == 40) {
        $mv(hex_src, probe.query);
    } else if (u8csEmpty(probe.fragment) &&
               u8csEmpty(probe.query) &&
               u8csLen(probe.path) == 40) {
        $mv(hex_src, probe.path);
    }
    if (!u8csEmpty(hex_src)) {
        b8 hex = YES;
        for (u8cp p = hex_src[0]; p < hex_src[1]; p++) {
            u8 ch = *p;
            b8 d = (ch >= '0' && ch <= '9');
            b8 l = (ch >= 'a' && ch <= 'f');
            b8 U_ = (ch >= 'A' && ch <= 'F');
            if (!(d || l || U_)) { hex = NO; break; }
        }
        if (hex) {
            probe.fragment[0] = hex_src[0];
            probe.fragment[1] = hex_src[1];
            probe.query[0] = probe.query[1] = NULL;
            probe.path[0]  = probe.path[1]  = NULL;
        }
    }

    //  TODO: this swallows GRAFResolveTip errors silently, which
    //  hides real failures (typo'd ref, REFS corruption, …) behind
    //  a no-op success.  The reason it's here today: BE forwards
    //  the user's URI verbatim to the parallel children before
    //  sniff has a chance to rewrite relative refs (`?..`, `?./X`)
    //  into absolute form, and a fresh-clone bootstrap can land
    //  here with no REFS yet — both legitimate "nothing to walk"
    //  cases that shouldn't abort BE's parallel reindex.
    //
    //  Right fix: have BE pre-resolve relative refs and pass an
    //  absolute URI to all parallel children (and skip the reindex
    //  entirely on a fresh empty store).  Then this can hard-fail
    //  on resolution errors again.
    sha1 tip = {};
    if (GRAFResolveTip(k, &probe, &tip) != OK) done;
    u64 tip_h = WHIFFHashlet60(&tip);
    if (tip_h == 0) done;

    //  Snapshot the existing index runs once — used as the per-commit
    //  stop test (mention ≡ known per DAG.md).  GRAFDagUpdate appends
    //  to a pending batch, so freshly-ingested commits in this same
    //  call do *not* show up here; the visited-set covers in-walk
    //  dedup instead.
    wh128css runs = {NULL, NULL};
    GRAFRuns(runs);

    Bu8 body = {};
    call(u8bMap, body, GRAF_INGEST_BUFSZ);

    //  Visited set + BFS queue — same wh128 hash-set shape DAGAncestors
    //  uses; reuse `dag_anc_put` / `DAGAncestorsHas` so this TU doesn't
    //  need its own HASHx instantiation.
    Bwh128 seen = {};
    Bwh128 queue = {};
    ok64 rc = wh128bMap(seen, GRAF_WALK_SET_CAP);
    if (rc != OK) { u8bUnMap(body); return rc; }
    rc = wh128bMap(queue, GRAF_WALK_SET_CAP);
    if (rc != OK) { wh128bUnMap(seen); u8bUnMap(body); return rc; }

    dag_anc_put(seen, tip_h);
    {
        wh128 q0 = {.key = DAGPack(0, tip_h), .val = 0};
        wh128bFeed1(queue, q0);
    }

    size_t head = 0;
    while (head < wh128bDataLen(queue)) {
        wh128cp cur = wh128bDataHead(queue) + head++;
        u64 h60 = DAGHashlet(cur->key);

        //  Already in graf's persisted runs → stop walking this
        //  branch (its parents are already known by induction).
        if (DAGLookup(runs, DAG_T_COMMIT, h60) != NULL) continue;

        u8bReset(body);
        u8 ot = 0;
        if (KEEPGet(k, h60, DAG_H60_HEXLEN, body, &ot) != OK) continue;
        if (ot != DOG_OBJ_COMMIT) continue;

        a_dup(u8c, bs, u8bData(body));
        sha1 csha = {};
        KEEPObjSha(&csha, DOG_OBJ_COMMIT, bs);
        ok64 io = GRAFDagUpdate(DOG_OBJ_COMMIT, &csha, bs);
        if (io != OK) { rc = io; break; }

        //  Parse parent edges and enqueue.
        a_dup(u8c, scan, u8bData(body));
        u8cs field = {}, value = {};
        while (GITu8sDrainCommit(scan, field, value) == OK) {
            if (u8csEmpty(field)) break;
            a_cstr(fp, "parent");
            if (!$eq(field, fp)) continue;
            if (u8csLen(value) < 40) continue;

            sha1 psha = {};
            DAGsha1FromHex(&psha, (char const *)value[0]);
            u64 ph = WHIFFHashlet60(&psha);

            if (DAGAncestorsHas(seen, ph)) continue;
            if (dag_anc_put(seen, ph) != OK) continue;

            wh128 qr = {.key = DAGPack(0, ph), .val = 0};
            if (wh128bFeed1(queue, qr) != OK) break;
        }
    }

    GRAFDagFinish();

    wh128bUnMap(queue);
    wh128bUnMap(seen);
    u8bUnMap(body);
    return rc;
}
