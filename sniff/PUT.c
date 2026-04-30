//  PUT: append `put <path>` rows to the ULOG and stamp each staged
//  file with the row's ts.  A file's mtime then points back into the
//  log — POST classifies provenance via `lstat → ron60 → row`.
//
//  Bare `be put` walks the baseline tree (tracked paths only) and
//  emits a row+stamp for each tracked file whose mtime ∉ stamp-set.
//  Untracked paths are NEVER staged by the bare form — the user
//  names them explicitly with `be put <path>`.  Empty walk →
//  PUTNONE.
//
//  Per-uri `be put <path>` validates each path:
//    * missing on disk        → PUTNONE (caller can't stage what
//                                isn't there)
//    * mtime ∈ get/post stamp → PUTNONE (already baseline-clean;
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
#include "keeper/SHA1.h"

#include "AT.h"
#include "CLASS.h"

// --- Bare-walk callback (baseline-tree visitor) ---

typedef struct {
    u8cs   reporoot;
    ron60  ts;            // bumped after each emit so rows stay strictly increasing
    ron60  verb_put;
    ron60  baseline_ts;   // ts of the most recent get/post — used to
                          // re-stamp files that hash-match baseline so
                          // future mtime fast-paths skip them.
    u32    emitted;
    ok64   err;
} put_walk_ctx;

//  Per-tracked-path:
//    1. lstat — skip if absent.
//    2. mtime ∈ stamp-set → clean (fast path).
//    3. Otherwise mmap+hash and compare to the baseline blob sha:
//       * equal → file content matches baseline; re-stamp with
//         baseline_ts so the mtime fast-path picks it up next time.
//       * differs → emit a put row and stamp with put ts.
//
//  mtimes are an optimization; the SHA-1 comparison is the actual
//  dirtiness test.  Without this, a `.sniff` carried over from
//  another checkout (where every wt mtime is foreign) would put-stage
//  the entire baseline tree even though nothing actually changed.
static ok64 put_visit_tracked(u8cs path, u8 kind, u8cp esha, u8cs blob,
                              void0p vctx) {
    sane(vctx);
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

    //  Fast path: mtime equals some `get` or `post` row's ts → sniff
    //  wrote this file as part of materialising a tree, the user
    //  hasn't touched it since.  Either the row's tree at this path
    //  IS the current baseline blob (typical case) or it differs in
    //  a way invisible to bare put — staging a baseline-equal file
    //  again is a no-op POST will skip, so suppressing here is safe.
    //  put / patch / older-mod stamps don't carry the "user untouched"
    //  guarantee, so they fall through to the SHA compare.
    if (SNIFFAtKnown(mr)) {
        ron60 ow_verb = 0;
        uri ow_u = {};
        if (SNIFFAtRowAtTs(mr, &ow_verb, &ow_u) == OK) {
            ron60 vg = SNIFFAtVerbGet();
            ron60 vp = SNIFFAtVerbPost();
            if (ow_verb == vg || ow_verb == vp) return OK;
        }
    }

    //  Slow path: hash on-disk content and compare to baseline blob
    //  sha.  Symlinks resolve via readlink; regular/exec via mmap.
    sha1 disk_sha = {};
    sha1 base_sha = {};
    memcpy(base_sha.data, esha, 20);

    if (kind == WALK_KIND_LNK) {
        char tgt[1024];
        ssize_t tlen = readlink((char const *)u8bDataHead(fp),
                                tgt, sizeof(tgt));
        if (tlen <= 0) return OK;
        u8cs lv = {(u8cp)tgt, (u8cp)tgt + tlen};
        KEEPObjSha(&disk_sha, DOG_OBJ_BLOB, lv);
    } else {
        u8bp mapped = NULL;
        ok64 mo = FILEMapRO(&mapped, $path(fp));
        if (mo != OK) return OK;            // can't read → leave alone
        KEEPObjSha(&disk_sha, DOG_OBJ_BLOB, u8bDataC(mapped));
        FILEUnMap(mapped);
    }

    if (sha1eq(&disk_sha, &base_sha)) {
        //  Content matches baseline.  Re-stamp with baseline_ts so the
        //  next mtime check fast-paths this file.  No put row.
        if (c->baseline_ts != 0)
            (void)SNIFFAtStampPath(fp, c->baseline_ts);
        return OK;
    }

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

// --- Per-path classification via SNIFFClassify ----------------------

typedef struct {
    u8cs        raw;            // bytes from user URI (rel path, normalised)
    b8          seen;
    b8          stage;
    char const *skip_reason;
    ron60       mtime;          // wt mtime, captured from the merge
} put_req;

typedef struct {
    put_req *reqs;
    u32      n;
    ron60    verb_get;
    ron60    verb_post;
} put_ctx;

static ok64 put_classify_step(class_step const *step, void *ctx_) {
    put_ctx *w = (put_ctx *)ctx_;
    for (u32 j = 0; j < w->n; j++) {
        if ($len(w->reqs[j].raw) != $len(step->path)) continue;
        if (memcmp(w->reqs[j].raw[0], step->path[0],
                   (size_t)$len(step->path)) != 0) continue;
        put_req *r = &w->reqs[j];
        r->seen = YES;
        if (step->kind == CLASS_BASE_ONLY) {
            r->skip_reason = "does not exist";
            return OK;
        }
        //  WT_ONLY or BOTH — file is on disk.
        if (step->wt_rec) r->mtime = step->wt_rec->ts;
        if (step->kind == CLASS_BOTH && SNIFFAtKnown(r->mtime)) {
            ron60 ow_verb = 0;
            uri ow_u = {};
            if (SNIFFAtRowAtTs(r->mtime, &ow_verb, &ow_u) == OK &&
                (ow_verb == w->verb_get ||
                 ow_verb == w->verb_post)) {
                r->skip_reason = "is unchanged";
                return OK;
            }
        }
        r->stage = YES;
        return OK;
    }
    return OK;
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
            return PUTNONE;
        }
        if (bo != OK) return bo;

        //  Re-stamp ts: the latest get/post row's ts.  Files whose
        //  content matches the baseline get re-stamped to this so the
        //  next bare put fast-paths them via SNIFFAtKnown.
        ron60 base_ts = 0, base_verb = 0;
        uri base_u = {};
        (void)SNIFFAtBaseline(&base_ts, &base_verb, &base_u);

        put_walk_ctx wc = {.ts = ts, .verb_put = verb_put,
                           .baseline_ts = base_ts, .err = OK};
        u8csMv(wc.reporoot, reporoot);
        ok64 wo = WALKTreeLazy(&KEEP, tree_sha.data,
                               put_visit_tracked, &wc);
        if (wc.err != OK) return wc.err;
        if (wo != OK) return wo;
        if (wc.emitted == 0) {
            fprintf(stderr, "sniff: put: no changes\n");
            return PUTNONE;
        }
        fprintf(stderr, "sniff: staged %u put row(s)\n", wc.emitted);
        done;
    }

    //  Per-path loop is driven by the unified ULOG-merge classifier
    //  (`SNIFFClassify`) — same primitive POST uses for its commit-
    //  time merge.  We pre-collect the user's requested paths, then
    //  let the merge tell us, per path, whether it's in baseline
    //  and/or on disk.  No path-set in memory, no per-path lstat —
    //  the wt cursor's `ts` field carries the file's mtime already.
    //
    //  Decisions:
    //    BOTH       + mtime ∈ get/post stamp → unchanged, skip
    //    BOTH       + otherwise              → stage (real edit)
    //    WT_ONLY    (on disk, not tracked)   → stage (new file)
    //    BASE_ONLY  (tracked, removed)       → skip ("does not exist")
    //    not seen   (typo / never existed)   → skip ("does not exist")

    //  Split file-form vs dir-form (path ends in `/`) requests.
    //  Dir-form rows are emitted as-is; POST expands them at commit
    //  time against the baseline tree.  File-form rows go through
    //  SNIFFClassify to validate path-in-baseline-or-on-disk.
    put_req reqs[CLI_MAX_URIS] = {};
    u32 nreq = 0;
    u32 emitted = 0;
    u32 skipped = 0;
    for (u32 i = 0; i < nuris; i++) {
        u8cs raw = {};
        SNIFFAtPathBytes(&uris[i], raw);
        if (u8csEmpty(raw)) continue;
        if ($len(raw) >= 2 && raw[0][0] == '.' && raw[0][1] == '/')
            raw[0] += 2;

        b8 is_dir = ($len(raw) > 0 && *(raw[1] - 1) == '/');
        if (is_dir) {
            //  Dir-form: lstat-confirm the dir exists, then emit one
            //  row with the dir path.  POST walks every baseline /
            //  wt entry under the prefix at commit time.
            a_path(fp);
            if (SNIFFFullpath(fp, reporoot, raw) != OK) {
                fprintf(stderr,
                        "sniff: put: cannot resolve %.*s — skipped\n",
                        (int)$len(raw), (char *)raw[0]);
                skipped++; continue;
            }
            struct stat sb = {};
            if (lstat((char const *)u8bDataHead(fp), &sb) != 0 ||
                !S_ISDIR(sb.st_mode)) {
                fprintf(stderr,
                        "sniff: put: %.*s does not exist — skipped\n",
                        (int)$len(raw), (char *)raw[0]);
                skipped++; continue;
            }
            uri urow = {};
            urow.path[0] = raw[0];
            urow.path[1] = raw[1];
            call(SNIFFAtAppendAt, ts, verb_put, &urow);
            ts++;
            emitted++;
            continue;
        }

        if (nreq < CLI_MAX_URIS) {
            reqs[nreq].raw[0] = raw[0];
            reqs[nreq].raw[1] = raw[1];
            nreq++;
        }
    }

    if (nreq > 0) {
        put_ctx pctx = {.reqs = reqs, .n = nreq,
                        .verb_get = verb_get, .verb_post = verb_post};
        call(SNIFFClassify, put_classify_step, &pctx);

        for (u32 i = 0; i < nreq; i++) {
            put_req *r = &reqs[i];
            if (!r->stage) {
                char const *reason = r->seen ? r->skip_reason
                                             : "does not exist";
                fprintf(stderr, "sniff: put: %.*s %s — skipped\n",
                        (int)$len(r->raw), (char *)r->raw[0], reason);
                skipped++;
                continue;
            }
            a_path(fp);
            if (SNIFFFullpath(fp, reporoot, r->raw) != OK) {
                fprintf(stderr,
                        "sniff: put: cannot resolve %.*s — skipped\n",
                        (int)$len(r->raw), (char *)r->raw[0]);
                skipped++;
                continue;
            }
            uri urow = {};
            urow.path[0] = r->raw[0];
            urow.path[1] = r->raw[1];
            call(SNIFFAtAppendAt, ts, verb_put, &urow);
            (void)SNIFFAtStampPath(fp, ts);
            ts++;
            emitted++;
        }
    }

    if (emitted == 0) {
        if (skipped > 0)
            fprintf(stderr, "sniff: put: no eligible paths\n");
        return PUTNONE;
    }
    fprintf(stderr, "sniff: staged %u put row(s)\n", emitted);
    done;
}
