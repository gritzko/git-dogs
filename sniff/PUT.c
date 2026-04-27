//  PUT: append `put <path>` rows to the ULOG and stamp each staged
//  file with the row's ts.  A file's mtime then points back into the
//  log — POST classifies provenance via `lstat → ron60 → row`.
//
//  Bare `be put` walks the baseline tree (tracked paths only) and
//  emits a row+stamp for each tracked file whose mtime ∉ stamp-set.
//  Untracked paths are NEVER staged by the bare form — the user
//  names them explicitly with `be put <path>`.  Empty walk →
//  SNIFFPUTNONE.
//
//  Per-uri `be put <path>` validates each path:
//    * missing on disk        → SNIFFPUTNONE (caller can't stage what
//                                isn't there)
//    * mtime ∈ get/post stamp → SNIFFPUTNONE (already baseline-clean;
//                                re-stamping under `put` would shift
//                                provenance for no semantic gain)
//    * otherwise              → append row, stamp file
//
#include "PUT.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "abc/BUF.h"
#include "abc/FILE.h"
#include "abc/HEX.h"
#include "abc/PATH.h"
#include "abc/PRO.h"
#include "keeper/GIT.h"
#include "keeper/KEEP.h"
#include "keeper/WALK.h"

#include "AT.h"

// --- Bare-walk callback (baseline-tree visitor) ---

typedef struct {
    u8cs   reporoot;
    ron60  ts;            // bumped after each emit so rows stay strictly increasing
    ron60  verb_put;
    u32    emitted;
    ok64   err;
} put_walk_ctx;

//  Per-tracked-path: lstat the wt file, skip if absent or mtime
//  matches a stamp (clean, baseline-attributed).  Otherwise append a
//  put row and stamp the file with the row's ts.
static ok64 put_visit_tracked(u8cs path, u8 kind, u8cp esha, u8cs blob,
                              void0p vctx) {
    sane(vctx);
    (void)esha;
    (void)blob;
    put_walk_ctx *c = (put_walk_ctx *)vctx;

    //  Directories don't carry content; subtree walk handles them.
    if (kind == WALK_KIND_DIR) return OK;
    //  Submodules / gitlinks: nothing to put.  POST keeps them via
    //  the gitlink-pass-through rule.
    if (kind == WALK_KIND_SUB) return WALKSKIP;

    a_path(fp);
    if (SNIFFFullpath(fp, c->reporoot, path) != OK) return OK;

    struct stat sb = {};
    if (lstat((char const *)u8bDataHead(fp), &sb) != 0) return OK;
    struct timespec mts = {.tv_sec  = sb.st_mtim.tv_sec,
                           .tv_nsec = sb.st_mtim.tv_nsec};
    ron60 mr = SNIFFAtOfTimespec(mts);
    if (SNIFFAtKnown(mr)) return OK;       // clean — skip

    uri urow = {};
    urow.path[0] = path[0];
    urow.path[1] = path[1];
    ok64 ar = SNIFFAtAppendAt(c->ts, c->verb_put, &urow);
    if (ar != OK) { c->err = ar; return ar; }

    (void)SNIFFAtStampPath(fp, c->ts);
    c->emitted++;
    c->ts++;        // strict-increase invariant for the next row
    return OK;
}

//  Resolve baseline tree-sha from sniff's at-log.  ULOGNONE on a
//  fresh (no-baseline) log; on OK the 20-byte tree sha is in
//  *tree_sha_out.
static ok64 put_baseline_tree(sha1 *tree_sha_out) {
    sane(tree_sha_out);
    ron60 ts = 0, verb = 0;
    uri u = {};
    ok64 br = SNIFFAtBaseline(&ts, &verb, &u);
    if (br == ULOGNONE) return ULOGNONE;
    if (br != OK) return br;

    u8 hex40[40];
    if (SNIFFAtQueryFirstSha(&u, hex40) != OK) return ULOGNONE;

    sha1 commit_sha = {};
    a_raw(csha_bin, commit_sha);
    u8cs h40 = {hex40, hex40 + 40};
    HEXu8sDrainSome(csha_bin, h40);

    Bu8 cbuf = {};
    call(u8bAllocate, cbuf, 1UL << 24);
    u8 ctype = 0;
    ok64 go = KEEPGetExact(&KEEP, &commit_sha, cbuf, &ctype);
    if (go != OK || ctype != DOG_OBJ_COMMIT) {
        u8bFree(cbuf);
        return ULOGNONE;
    }

    u8cs body = {u8bDataHead(cbuf), u8bIdleHead(cbuf)};
    ok64 to = GITu8sCommitTree(body, tree_sha_out->data);
    u8bFree(cbuf);
    return to;
}

// --- Public API ---

ok64 PUTStage(u32 nuris, uri const *uris) {
    sane(SNIFF.h && (nuris == 0 || uris != NULL));

    ron60 ts = 0;
    struct timespec tv = {};
    SNIFFAtNow(&ts, &tv);

    ron60 verb_put  = SNIFFAtVerbPut();
    ron60 verb_get  = SNIFFAtVerbGet();
    ron60 verb_post = SNIFFAtVerbPost();

    a_dup(u8c, reporoot, u8bData(SNIFF.h->wt));

    if (nuris == 0) {
        //  Walk the baseline tree — tracked-only; never picks up
        //  untracked siblings.  Submodules are skipped (WALKSKIP).
        sha1 tree_sha = {};
        ok64 bo = put_baseline_tree(&tree_sha);
        if (bo == ULOGNONE) {
            fprintf(stderr,
                    "sniff: put: no baseline (fresh repo); name "
                    "files explicitly\n");
            return SNIFFPUTNONE;
        }
        if (bo != OK) return bo;

        put_walk_ctx wc = {.ts = ts, .verb_put = verb_put, .err = OK};
        u8csMv(wc.reporoot, reporoot);
        ok64 wo = WALKTreeLazy(&KEEP, tree_sha.data,
                               put_visit_tracked, &wc);
        if (wc.err != OK) return wc.err;
        if (wo != OK) return wo;
        if (wc.emitted == 0) {
            fprintf(stderr, "sniff: put: no changes\n");
            return SNIFFPUTNONE;
        }
        fprintf(stderr, "sniff: staged %u put row(s)\n", wc.emitted);
        done;
    }

    u32 emitted = 0;
    for (u32 i = 0; i < nuris; i++) {
        u8cs raw = {};
        SNIFFAtPathBytes(&uris[i], raw);
        if (u8csEmpty(raw)) continue;

        a_path(fp);
        if (SNIFFFullpath(fp, reporoot, raw) != OK) {
            fprintf(stderr, "sniff: put: cannot resolve %.*s\n",
                    (int)$len(raw), (char *)raw[0]);
            return SNIFFPUTNONE;
        }

        struct stat sb = {};
        if (lstat((char const *)u8bDataHead(fp), &sb) != 0) {
            fprintf(stderr, "sniff: put: %.*s does not exist\n",
                    (int)$len(raw), (char *)raw[0]);
            return SNIFFPUTNONE;
        }

        //  Refuse PUTNONE for a file that is already baseline-clean
        //  (mtime owned by a `get` or `post` row).  PATCH and PUT
        //  stamps fall through — re-staging a patched file is OK,
        //  re-staging an existing put just refreshes the ts.
        struct timespec mts = {.tv_sec  = sb.st_mtim.tv_sec,
                               .tv_nsec = sb.st_mtim.tv_nsec};
        ron60 mr = SNIFFAtOfTimespec(mts);
        if (SNIFFAtKnown(mr)) {
            ron60 ow_verb = 0;
            uri ow_u = {};
            if (SNIFFAtRowAtTs(mr, &ow_verb, &ow_u) == OK &&
                (ow_verb == verb_get || ow_verb == verb_post)) {
                fprintf(stderr, "sniff: put: %.*s is unchanged\n",
                        (int)$len(raw), (char *)raw[0]);
                return SNIFFPUTNONE;
            }
        }

        uri urow = {};
        urow.path[0] = raw[0];
        urow.path[1] = raw[1];
        call(SNIFFAtAppendAt, ts, verb_put, &urow);
        (void)SNIFFAtStampPath(fp, ts);
        ts++;
        emitted++;
    }

    if (emitted > 0)
        fprintf(stderr, "sniff: staged %u put row(s)\n", emitted);
    done;
}
