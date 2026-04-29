//  INDEX: drive graf's streaming DAG ingest from keeper's pack store.
//
//  `graf index` enumerates keeper's LSM runs, pulls each object body
//  via KEEPGet, and replays the DOG.md §8 streaming contract:
//      GRAFDagUpdate(COMMIT, body, empty)   (in topological order)
//      GRAFDagUpdate(TREE,   body, empty)
//      GRAFDagUpdate(BLOB,   body, empty)
//      GRAFDagFinish()
//
//  Commits are fed in *pack-offset order*, which for sniff/be-post
//  flows is identical to topological order — a commit's parents are
//  always written to keeper before the commit itself.  If that
//  invariant ever breaks (e.g. out-of-order sync ingest), gen numbers
//  on a first pass may be low; subsequent `graf index` runs converge
//  because parents then reside in the persistent LSM.

#include "GRAF.h"
#include "DAG.h"

#include <stdlib.h>

#include "abc/FILE.h"
#include "abc/PRO.h"
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
        //  No pre-computed sha here; GRAFUpdate falls back to
        //  hashing `bs` itself.  This is the manual reindex path, not
        //  the hot clone path.
        o = GRAFUpdate(ot, NULL, bs);
        if (o != OK) { rc = o; break; }
    }

    free(ents);
    return rc;
}

ok64 GRAFIndex(keeper *k) {
    sane(k);

    Bu8 body = {};
    call(u8bMap, body, GRAF_INGEST_BUFSZ);

    //  Phase order (enforced by DAG ingest state machine):
    //  commits in pack-offset order, then trees, then blobs.
    ok64 rc = OK;
    if ((rc = graf_feed_type(k, DOG_OBJ_COMMIT, YES, body)) != OK) goto out;
    if ((rc = graf_feed_type(k, DOG_OBJ_TREE,   NO,  body)) != OK) goto out;
    if ((rc = graf_feed_type(k, DOG_OBJ_BLOB,   NO,  body)) != OK) goto out;

    //  Finish walks each new commit's tree and emits PATH_VER entries.
    rc = GRAFDagFinish();

out:
    u8bUnMap(body);
    return rc;
}
