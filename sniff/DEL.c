//  DEL: append `delete <path>` rows to sniff's ULOG, or write a
//  tombstone REFS row for branch deletion.
//
#include "DEL.h"

#include <string.h>

#include "abc/BUF.h"
#include "abc/PATH.h"
#include "abc/PRO.h"
#include "keeper/REFS.h"

#include "AT.h"

ok64 DELStage(u32 nuris, uri const *uris) {
    sane(SNIFF.h && (nuris == 0 || uris != NULL));

    ron60 verb = SNIFFAtVerbDelete();
    for (u32 i = 0; i < nuris; i++) {
        u8cs raw = {};
        SNIFFAtPathBytes(&uris[i], raw);
        if (u8csEmpty(raw)) continue;

        uri urow = {};
        urow.path[0] = raw[0];
        urow.path[1] = raw[1];

        call(SNIFFAtAppend, verb, &urow);
    }
    done;
}

//  Iteration callback: any active key whose query is a strict path
//  prefix of `target` + '/' counts as a descendant.  Hitting one
//  flips `dirty` and short-circuits the walk via REFSEACH_STOP.
typedef struct {
    u8cs target;
    b8   has_descendant;
} del_descendant_ctx;

static ok64 del_descendant_cb(refcp r, void *ctx) {
    sane(r && ctx);
    del_descendant_ctx *d = (del_descendant_ctx *)ctx;

    //  Each key looks like `?<branch>` (or with a host prefix for
    //  remote-observed rows).  We only care about local rows whose
    //  query is `<target>/<sub>` (sub-branch).  Parse the URI to get
    //  its query slice; ignore non-local (host-prefixed) rows.
    uri ku = {};
    ku.data[0] = r->key[0]; ku.data[1] = r->key[1];
    ok64 lo = URILexer(&ku);
    if (lo != OK) done;
    if (!u8csEmpty(ku.host)) done;          // remote observation
    u8cs q = {ku.query[0], ku.query[1]};
    if (u8csEmpty(q)) done;                 // trunk row, ignore

    //  q must start with `<target>/` and have additional bytes.
    size_t tl = u8csLen(d->target);
    if (u8csLen(q) <= tl + 1) done;
    if (memcmp(q[0], d->target[0], tl) != 0) done;
    if (q[0][tl] != '/') done;

    d->has_descendant = YES;
    return REFSFAIL;                       // short-circuit walk
}

//  Forty ASCII '0' chars — the tombstone fragment.
#define DEL_ZERO_HEX                                               \
    "0000000000000000000000000000000000000000"

ok64 DELBranch(uri const *u) {
    sane(SNIFF.h && u);

    keeper *k = &KEEP;
    a_path(keepdir, u8bDataC(k->h->root), KEEP_DIR_S);

    //  Target branch name (URI query bytes).  Trunk has an empty
    //  query — refuse early; can't drop trunk via this path.
    u8cs target = {u->query[0], u->query[1]};
    if (u8csEmpty(target)) {
        fprintf(stderr, "sniff: delete: refusing to drop trunk\n");
        fail(SNIFFFAIL);
    }

    //  Refuse if the wt is currently on the branch being deleted —
    //  the wt would lose its branch pointer.  The manual delete-
    //  and-recreate workflow for non-ff recovery is still the
    //  user's: stash/move whatever in-flight changes you need,
    //  switch wt off the branch (`be get ?..`), drop, recreate.
    {
        ron60 bts = 0, bverb = 0;
        uri bu = {};
        if (SNIFFAtBaseline(&bts, &bverb, &bu) == OK) {
            u8cs cur = {bu.query[0], bu.query[1]};
            if (u8csLen(cur) == u8csLen(target) &&
                !u8csEmpty(cur) &&
                memcmp(cur[0], target[0], u8csLen(target)) == 0) {
                fprintf(stderr,
                        "sniff: delete: wt is on `%.*s` — switch to "
                        "another branch first (`be get ?..`)\n",
                        (int)u8csLen(target), (char *)target[0]);
                fail(SNIFFFAIL);
            }
        }
    }

    //  Refuse if any active descendant label exists.
    {
        del_descendant_ctx dctx = {.target = {target[0], target[1]},
                                   .has_descendant = NO};
        (void)REFSEach($path(keepdir), del_descendant_cb, &dctx);
        if (dctx.has_descendant) {
            fprintf(stderr,
                    "sniff: delete: `%.*s` has active descendant "
                    "branches — drop those first\n",
                    (int)u8csLen(target), (char *)target[0]);
            fail(SNIFFFAIL);
        }
    }

    //  Build refkey `?<target>` and tombstone value `0000…0`.
    a_pad(u8, keybuf, 128);
    u8bFeed1(keybuf, '?');
    u8bFeed(keybuf, target);
    a_dup(u8c, refkey, u8bData(keybuf));
    a_cstr(zeros, DEL_ZERO_HEX);

    call(REFSAppendVerb, $path(keepdir), REFSVerbPost(), refkey, zeros);
    fprintf(stderr, "sniff: deleted ?%.*s\n",
            (int)u8csLen(target), (char *)target[0]);
    done;
}
