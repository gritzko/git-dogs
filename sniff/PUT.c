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
    //  Meta paths (.sniff / .dogs/* / .git*) leak into legacy trees
    //  but must never be re-staged.  Skip even when present on the
    //  tracked side — POST will drop them from the new tree too.
    if (SNIFFSkipMeta(path)) return OK;

    a_path(fp);
    if (SNIFFFullpath(fp, c->reporoot, path) != OK) return OK;

    struct stat sb = {};
    ok64 lo = FILELStat(&sb, $path(fp));
    if (lo == FILENOENT) return OK;    // vanished mid-walk
    if (lo != OK) return lo;             // permissions etc — propagate
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
    sha1Mv(&base_sha, (sha1 const *)esha);

    if (kind == WALK_KIND_LNK) {
        a_pad(u8, tgt, 1024);
        if (FILEReadLink(tgt, $path(fp)) != OK) return OK;
        KEEPObjSha(&disk_sha, DOG_OBJ_BLOB, u8bDataC(tgt));
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
    ok64 br = SNIFFAtCurTip(&ts, &verb, &u);
    if (br == ULOGNONE) return ULOGNONE;
    if (br != OK) return br;

    sha1hex hex = {};
    if (SNIFFAtQueryFirstSha(&u, &hex) != OK) return ULOGNONE;

    sha1 commit_sha = {};
    if (sha1FromSha1hex(&commit_sha, &hex) != OK) return ULOGNONE;

    return KEEPCommitTreeSha(&KEEP, &commit_sha, tree_sha_out);
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

// --- Dir-form expansion --------------------------------------------
//
//  `be put <dir>/` (trailing slash): expand to one per-file `put` row
//  per path.  VERBS.md §PUT contract:
//
//      tracked dir   (any baseline entry under prefix) → stage every
//                    tracked-dirty file, skip untracked siblings
//      untracked dir (no baseline entry under prefix) → stage every
//                    non-meta file under it
//
//  We previously emitted a single dir-prefix row and deferred
//  expansion to POST.  That left status (`be`) unable to surface the
//  staged files (CLASS.c skips dir-prefix rows for the per-file
//  classifier), so users saw `0 put / 0 mod` despite their explicit
//  `be put dir/`, and a fresh row-per-call broke idempotence.

typedef struct {
    u8cs   prefix;
    Bu8   *dirty;       // tracked + dirty (BOTH + mtime ∉ get/post stamp)
    Bu8   *untracked;   // WT_ONLY paths
    u32    base_seen;   // any BOTH or BASE_ONLY under prefix
    ron60  verb_get;
    ron60  verb_post;
    ok64   err;
} dir_collect_ctx;

static b8 dir_path_under(u8cs path, u8cs prefix) {
    size_t pl = (size_t)$len(prefix);
    if ((size_t)$len(path) < pl) return NO;
    return memcmp(path[0], prefix[0], pl) == 0;
}

static ok64 dir_collect_step(class_step const *step, void *vctx) {
    sane(step && vctx);
    dir_collect_ctx *c = (dir_collect_ctx *)vctx;
    if (!dir_path_under(step->path, c->prefix)) return OK;

    if (step->kind == CLASS_BOTH || step->kind == CLASS_BASE_ONLY)
        c->base_seen++;

    if (step->kind == CLASS_BOTH) {
        //  Idempotence: any stamp-set match counts as "settled" for
        //  the dir-form.  A get/post stamp means baseline-clean, a
        //  put stamp means already-staged-by-an-earlier-put.  Either
        //  way, re-staging would just shift the row's ts forward for
        //  no semantic gain — `be put dir/` twice in a row should
        //  emit zero new rows on the second call.  (The per-file
        //  form keeps the stricter get/post-only rule since users
        //  invoke it explicitly per path.)
        ron60 mr = step->wt_rec ? step->wt_rec->ts : 0;
        b8 settled = (mr != 0 && SNIFFAtKnown(mr));
        if (!settled) {
            ok64 r = u8bFeed(*c->dirty, step->path);
            if (r == OK) r = u8bFeed1(*c->dirty, '\n');
            if (r != OK) c->err = r;
        }
    } else if (step->kind == CLASS_WT_ONLY) {
        ok64 r = u8bFeed(*c->untracked, step->path);
        if (r == OK) r = u8bFeed1(*c->untracked, '\n');
        if (r != OK) c->err = r;
    }
    return OK;
}

//  Iterate newline-separated paths in `paths`, append per-file put
//  rows + stamp.  Caller advances `*ts_io` and `*emitted_io`.
static ok64 dir_emit_paths(Bu8 paths, u8cs reporoot,
                            ron60 *ts_io, u32 *emitted_io,
                            ron60 verb_put) {
    sane(ts_io && emitted_io);
    a_dup(u8c, scan, u8bData(paths));
    while (!u8csEmpty(scan)) {
        u8cp eol = scan[0];
        while (eol < scan[1] && *eol != '\n') eol++;
        u8cs path = {scan[0], eol};
        scan[0] = (eol < scan[1]) ? eol + 1 : eol;
        if ($empty(path)) continue;

        a_path(fp);
        if (SNIFFFullpath(fp, reporoot, path) != OK) continue;

        uri urow = {};
        urow.path[0] = path[0];
        urow.path[1] = path[1];
        ok64 ar = SNIFFAtAppendAt(*ts_io, verb_put, &urow);
        if (ar != OK) return ar;
        (void)SNIFFAtStampPath(fp, *ts_io);
        (*ts_io)++;
        (*emitted_io)++;
    }
    done;
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
        //  Refuse to stage sniff-meta paths (.sniff / .dogs/* / .git*)
        //  even when explicitly named — they leak into legacy trees
        //  but must not propagate forward.
        if (SNIFFSkipMeta(raw)) {
            fprintf(stderr,
                    "sniff: put: %.*s is a meta path — skipped\n",
                    (int)$len(raw), (char *)raw[0]);
            skipped++; continue;
        }

        b8 is_dir = ($len(raw) > 0 && *(raw[1] - 1) == '/');
        if (is_dir) {
            //  Dir-form: confirm the dir exists, then expand into
            //  per-file `put` rows according to the tracked/untracked
            //  rule from VERBS.md §PUT.  Empty expansion (no dirty
            //  files under a tracked dir, or empty wt subtree) is a
            //  no-op for this argument — the per-arg result mirrors
            //  the single-file `be put file.c` `is unchanged` skip.
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

            Bu8 dirty = {}, untracked = {};
            ok64 da = u8bAllocate(dirty,     1UL << 16);
            ok64 ua = u8bAllocate(untracked, 1UL << 16);
            if (da != OK || ua != OK) {
                if (dirty[0])     u8bFree(dirty);
                if (untracked[0]) u8bFree(untracked);
                fail(NOROOM);
            }
            dir_collect_ctx dctx = {
                .prefix = {raw[0], raw[1]},
                .dirty = &dirty,
                .untracked = &untracked,
                .verb_get = verb_get,
                .verb_post = verb_post,
                .err = OK,
            };
            ok64 cr = SNIFFClassify(dir_collect_step, &dctx);
            if (cr != OK) {
                u8bFree(dirty); u8bFree(untracked); return cr;
            }
            if (dctx.err != OK) {
                u8bFree(dirty); u8bFree(untracked); return dctx.err;
            }

            //  Stage everything stage-worthy under the prefix:
            //  tracked-and-dirty plus untracked files.  These two
            //  sets are disjoint by definition (untracked == not in
            //  baseline; dirty implies tracked), so there's nothing
            //  to dedupe.  `base_seen` is no longer load-bearing for
            //  this choice — both bins drain together.
            u32 before = emitted;
            ok64 er = dir_emit_paths(dirty, reporoot,
                                     &ts, &emitted, verb_put);
            if (er == OK)
                er = dir_emit_paths(untracked, reporoot,
                                    &ts, &emitted, verb_put);
            u8bFree(dirty); u8bFree(untracked);
            if (er != OK) return er;

            if (emitted == before) {
                //  Nothing dirty under a tracked dir, or empty wt
                //  subtree.  Per-arg "skipped — unchanged" message
                //  mirrors the single-file form.
                fprintf(stderr,
                        "sniff: put: %.*s is unchanged — skipped\n",
                        (int)$len(raw), (char *)raw[0]);
                skipped++;
            }
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
