//  DEL: actually unlink a file (after a dirty-safety check) and
//  append a `delete <path>` row to the ULOG.  The unlink happens
//  immediately, not at POST time — the ULOG row records that the
//  delete happened, and the next POST drops the path from the new
//  tree.
//
//  Dirty-safety: refuse DELDIRTY if `mtime ∉ stamp-set`
//  (file was user-edited since any owning row).  v1 doesn't run
//  the content-equality fallback the spec calls for on mtime drift
//  — TODO once we expose a baseline-tree path → sha lookup.
//
//  Already-absent paths are an OK no-op: append the delete row,
//  no error.  POST drops the path from the new tree as if it had
//  been there.
//
//  Branch-form delete (`?<branch>`) lives in DELBranch — a
//  separate path that writes a REFS tombstone, unrelated to the
//  worktree.
//
#include "DEL.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "abc/B.h"
#include "abc/BUF.h"
#include "abc/FILE.h"
#include "abc/HEX.h"
#include "abc/OK.h"
#include "abc/PATH.h"
#include "abc/PRO.h"
#include "keeper/GIT.h"
#include "keeper/KEEP.h"
#include "keeper/REFS.h"
#include "keeper/WALK.h"

#include "AT.h"

// --- Baseline-tree membership (for absent-path classification) ------
//
//  When a `be delete <path>` target is already absent on disk we
//  need to know whether the baseline tree had it: tracked → emit
//  the delete row so POST drops the path from the next commit;
//  untracked → silent no-op (no row, nothing to drop).  Walks the
//  baseline tree once on first use and caches the path set.

typedef struct {
    Bu8 paths;     // newline-terminated tracked paths
    b8  loaded;    // YES once we've tried to walk the baseline
    b8  ok;        // YES if walk landed (no baseline = NO, set is empty)
} del_tracked;

static ok64 del_collect_tracked(u8cs path, u8 kind, u8cp esha,
                                u8cs blob, void0p vctx) {
    (void)esha; (void)blob;
    if (kind == WALK_KIND_DIR || kind == WALK_KIND_SUB) return OK;
    if ($empty(path)) return OK;
    del_tracked *t = (del_tracked *)vctx;
    (void)u8bFeed(t->paths, path);
    (void)u8bFeed1(t->paths, '\n');
    return OK;
}

static b8 del_tracked_has(del_tracked *t, u8cs path) {
    if (!t->loaded) {
        t->loaded = YES;
        if (u8bAllocate(t->paths, 1UL << 16) != OK) return NO;
        ron60 ts = 0, verb = 0;
        uri u = {};
        if (SNIFFAtBaseline(&ts, &verb, &u) != OK) return NO;
        u8 hex40[40];
        if (SNIFFAtQueryFirstSha(&u, hex40) != OK) return NO;
        sha1 commit_sha = {};
        a_raw(csha_bin, commit_sha);
        u8cs h40 = {hex40, hex40 + 40};
        if (HEXu8sDrainSome(csha_bin, h40) != OK) return NO;
        Bu8 cbuf = {};
        if (u8bAllocate(cbuf, 1UL << 20) != OK) return NO;
        u8 ctype = 0;
        if (KEEPGetExact(&KEEP, &commit_sha, cbuf, &ctype) != OK
            || ctype != DOG_OBJ_COMMIT) {
            u8bFree(cbuf); return NO;
        }
        sha1 tree_sha = {};
        u8cs body = {u8bDataHead(cbuf), u8bIdleHead(cbuf)};
        ok64 to = GITu8sCommitTree(body, tree_sha.data);
        u8bFree(cbuf);
        if (to != OK) return NO;
        (void)WALKTreeLazy(&KEEP, tree_sha.data,
                           del_collect_tracked, t);
        t->ok = YES;
    }
    if (!t->ok) return NO;
    u8cs scan = {u8bDataHead(t->paths), u8bIdleHead(t->paths)};
    while (!$empty(scan)) {
        u8cp nl = scan[0];
        while (nl < scan[1] && *nl != '\n') nl++;
        if ((size_t)(nl - scan[0]) == (size_t)$len(path) &&
            memcmp(scan[0], path[0], (size_t)$len(path)) == 0)
            return YES;
        scan[0] = (nl < scan[1]) ? nl + 1 : scan[1];
    }
    return NO;
}

static void del_tracked_free(del_tracked *t) {
    if (t->loaded && t->ok) u8bFree(t->paths);
}

// --- Dir-form recursive delete --------------------------------------

//  Two-pass walker:
//   * pass 1 (preflight)  — refuse DELDIRTY on the first
//                           descendant whose mtime ∉ stamp-set.
//   * pass 2 (apply)      — unlink each descendant.
//  Both passes use the same callback driven by a `mode` flag.

typedef enum { DEL_DIR_PREFLIGHT, DEL_DIR_APPLY } del_dir_mode;

typedef struct {
    u8cs          reporoot;
    del_dir_mode  mode;
    u32           dirty;     // count, only filled by preflight
    u32           unlinked;  // count, only filled by apply
} del_dir_ctx;

static ok64 del_dir_cb(void *vctx, path8bp path) {
    sane(vctx && path);
    del_dir_ctx *c = (del_dir_ctx *)vctx;

    a_dup(u8c, full, u8bData(path));
    u8cs rel = {};
    if (!SNIFFRelFromFull(&rel, c->reporoot, full)) return OK;
    if (SNIFFSkipMeta(rel))                         return OK;

    if (c->mode == DEL_DIR_PREFLIGHT) {
        struct stat sb = {};
        if (lstat((char const *)full[0], &sb) != 0) return OK;
        struct timespec mts = {.tv_sec  = sb.st_mtim.tv_sec,
                               .tv_nsec = sb.st_mtim.tv_nsec};
        ron60 mr = SNIFFAtOfTimespec(mts);
        if (!SNIFFAtKnown(mr)) {
            fprintf(stderr,
                    "sniff: delete: %.*s has unstamped changes — "
                    "stage with `be put` or revert before deleting\n",
                    (int)$len(rel), (char *)rel[0]);
            c->dirty++;
            return DELDIRTY;     // short-circuit FILEScan
        }
        return OK;
    }

    //  apply
    if (unlink((char const *)full[0]) == 0) c->unlinked++;
    return OK;
}

static ok64 del_dir(u8cs reporoot, u8cs dir_rel) {
    sane($ok(reporoot) && $ok(dir_rel));

    a_path(dir_full);
    if (SNIFFFullpath(dir_full, reporoot, dir_rel) != OK) {
        fprintf(stderr, "sniff: delete: cannot resolve %.*s\n",
                (int)$len(dir_rel), (char *)dir_rel[0]);
        fail(SNIFFFAIL);
    }

    struct stat sb = {};
    if (lstat((char const *)u8bDataHead(dir_full), &sb) != 0) {
        //  Already absent — caller will append the dir row idempotently.
        done;
    }

    del_dir_ctx ctx = {.mode = DEL_DIR_PREFLIGHT};
    u8csMv(ctx.reporoot, reporoot);

    //  Preflight: any descendant with ∉ stamp-set mtime aborts.
    ok64 pf = FILEScan(dir_full,
                       (FILE_SCAN)(FILE_SCAN_FILES | FILE_SCAN_LINKS |
                                   FILE_SCAN_DEEP),
                       del_dir_cb, &ctx);
    if (ctx.dirty > 0) return DELDIRTY;
    if (pf != OK) return pf;

    //  Apply: unlink every descendant.  Empty dirs are not removed —
    //  POST won't emit them either (an empty dir has no tree entry).
    ctx.mode = DEL_DIR_APPLY;
    ok64 ar = FILEScan(dir_full,
                       (FILE_SCAN)(FILE_SCAN_FILES | FILE_SCAN_LINKS |
                                   FILE_SCAN_DEEP),
                       del_dir_cb, &ctx);
    if (ar != OK) return ar;

    fprintf(stderr, "sniff: delete: %.*s — %u file(s) unlinked\n",
            (int)$len(dir_rel), (char *)dir_rel[0], ctx.unlinked);
    done;
}

ok64 DELStage(u32 nuris, uri const *uris) {
    sane(SNIFF.h && (nuris == 0 || uris != NULL));

    if (nuris == 0) {
        fprintf(stderr,
                "sniff: delete: no paths given (use `be delete <path>` "
                "or `be delete ?<branch>`)\n");
        done;
    }

    ron60 ts = 0;
    struct timespec tv = {};
    SNIFFAtNow(&ts, &tv);

    ron60 verb = SNIFFAtVerbDelete();
    a_dup(u8c, reporoot, u8bData(SNIFF.h->wt));

    u32 unlinked = 0;
    u32 emitted = 0;
    u32 skipped = 0;
    del_tracked tracked = {};
    for (u32 i = 0; i < nuris; i++) {
        u8cs raw = {};
        SNIFFAtPathBytes(&uris[i], raw);
        if (u8csEmpty(raw)) continue;

        //  Trailing-slash dir form: atomic recursive delete.  Refuses
        //  DELDIRTY on the first dirty descendant; otherwise
        //  unlinks every file under the prefix and appends one
        //  `delete <dir>/` row.  POST drops the whole subtree from
        //  the new commit's tree.
        if (*u8csLast(raw) == '/') {
            ok64 dr = del_dir(reporoot, raw);
            if (dr != OK) return dr;
            uri urow = {};
            urow.path[0] = raw[0];
            urow.path[1] = raw[1];
            call(SNIFFAtAppendAt, ts, verb, &urow);
            ts++;
            emitted++;
            continue;
        }

        a_path(fp);
        if (SNIFFFullpath(fp, reporoot, raw) != OK) {
            fprintf(stderr, "sniff: delete: cannot resolve %.*s\n",
                    (int)$len(raw), (char *)raw[0]);
            fail(SNIFFFAIL);
        }

        struct stat sb = {};
        b8 exists = (lstat((char const *)u8bDataHead(fp), &sb) == 0);

        if (exists) {
            //  Dirty-safety: mtime must be in the ULOG stamp-set
            //  (file was last written by some sniff-tracked op).
            //  ∉ stamp-set ⇒ user-edited; refuse to clobber.
            struct timespec mts = {.tv_sec  = sb.st_mtim.tv_sec,
                                   .tv_nsec = sb.st_mtim.tv_nsec};
            ron60 mr = SNIFFAtOfTimespec(mts);
            if (!SNIFFAtKnown(mr)) {
                fprintf(stderr,
                        "sniff: delete: %.*s has unstamped changes — "
                        "stage with `be put` or revert before deleting\n",
                        (int)$len(raw), (char *)raw[0]);
                return DELDIRTY;
            }

            if (unlink((char const *)u8bDataHead(fp)) != 0) {
                fprintf(stderr, "sniff: delete: unlink %.*s failed\n",
                        (int)$len(raw), (char *)raw[0]);
                fail(SNIFFFAIL);
            }
            unlinked++;
        } else {
            //  Already absent on disk.  Only emit a row if the path
            //  was actually in the baseline tree — otherwise this is
            //  a no-op (the user named a path that never existed in
            //  the repo, e.g. a typo / a renamed-away file).
            if (!del_tracked_has(&tracked, raw)) {
                skipped++;
                continue;
            }
        }

        uri urow = {};
        urow.path[0] = raw[0];
        urow.path[1] = raw[1];
        call(SNIFFAtAppendAt, ts, verb, &urow);
        ts++;
        emitted++;
    }

    del_tracked_free(&tracked);
    if (skipped > 0)
        fprintf(stderr,
                "sniff: deleted %u file(s) (%u row(s), %u skipped)\n",
                unlinked, emitted, skipped);
    else
        fprintf(stderr,
                "sniff: deleted %u file(s) (%u row(s))\n",
                unlinked, emitted);
    done;
}

//  Iteration callback: any active key whose query is a strict path
//  prefix of `target` + '/' counts as a descendant.  Hitting one
//  sets `has_descendant` and short-circuits the walk via REFSSTOP.
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
    u8csMv(ku.data, r->key);
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
    return REFSSTOP;                       // short-circuit walk
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
        ok64 eo = REFSEach($path(keepdir), del_descendant_cb, &dctx);
        if (eo != OK) {
            fprintf(stderr,
                    "sniff: delete: REFS scan failed (%s)\n",
                    ok64str(eo));
            fail(SNIFFFAIL);
        }
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

    //  Drop the per-branch keeper shard if it was materialised by a
    //  prior `be post ?./X` (POSTSetLabel).  KEEPBranchDrop is the
    //  inverse of KEEPCreateBranch; KEEPNONE means the dir was never
    //  created (older REFS-only labels), KEEPTRUNK / KEEPDIRTY are
    //  guarded above.  Failing here would leave the REFS tombstone
    //  in place and the dir on disk — log + continue: the REFS state
    //  is the source of truth.
    {
        ok64 do_ = KEEPBranchDrop(k, target);
        if (do_ != OK && do_ != KEEPNONE && do_ != KEEPTRUNK) {
            fprintf(stderr,
                    "sniff: delete: REFS tombstoned but shard dir "
                    "drop failed (%s)\n",
                    ok64str(do_));
        }
    }

    fprintf(stderr, "sniff: deleted ?%.*s\n",
            (int)u8csLen(target), (char *)target[0]);
    done;
}
