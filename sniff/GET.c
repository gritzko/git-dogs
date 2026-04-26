//  GET: checkout a commit tree from keeper.
//
//  Responsibilities:
//    * Materialise every file in the commit's tree, creating parent
//      dirs as needed.
//    * Dirty-protect: if a file on disk has an mtime not in sniff's
//      stamp-set, leave it alone.
//    * Stamp every file we write with a shared ron60 timestamp via
//      utimensat, so a later stat() recovers that same stamp.
//    * Append one `get` ULOG row with the same timestamp.
//    * Prune: unlink any wt file that sniff wrote before but isn't
//      in the new target tree (stamp-set check protects user files).
//
#include "GET.h"

#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "abc/FILE.h"
#include "abc/HEX.h"
#include "abc/PATH.h"
#include "abc/PRO.h"
#include "dog/HOME.h"
#include "keeper/GIT.h"
#include "keeper/REFS.h"
#include "keeper/WALK.h"

#include "AT.h"

typedef struct {
    keeper        *k;
    u8cs           reporoot;
    ron60          ts;          // stamp to apply via utimensat
    struct timespec tv;         // same stamp in timespec form
    Bu8            target;      // bitmap: target[idx] = 1 iff path idx is
                                // in the new tree (set during walk, read
                                // during prune).
    u32            target_cap;
    ok64           error;
    b8             dryrun;      // pre-flight: don't write blobs; instead
                                // count overlap-with-dirty conflicts.
    u32            conflicts;   // populated in dryrun mode.
} get_ctx;

static void get_mark_target(get_ctx *g, u32 idx) {
    if (idx >= g->target_cap) return;
    u8 *base = u8bDataHead(g->target);
    base[idx] = 1;
}

static b8 get_is_target(get_ctx const *g, u32 idx) {
    if (idx >= g->target_cap) return NO;
    u8 const *base = u8bDataHead(g->target);
    return base[idx] != 0;
}

//  Write one blob to disk, create dirs as needed, chmod if exec,
//  symlink if link; then stamp it with ctx->tv.  Caller is
//  responsible for the dirty-overlap pre-flight (see get_visit's
//  dryrun branch and GETCheckout); reaching here means no dirty
//  collision was detected.
static ok64 get_write_one(get_ctx *g, u8cs path, u8 kind, u8cp esha) {
    sane(g);
    keeper *k = g->k;

    a_path(fp);
    call(SNIFFFullpath, fp, g->reporoot, path);

    Bu8 bbuf = {};
    call(u8bAllocate, bbuf, 1UL << 24);
    u8 bt = 0;
    sha1 entry_sha = {};
    memcpy(entry_sha.data, esha, 20);
    ok64 o = KEEPGetExact(k, &entry_sha, bbuf, &bt);
    if (o != OK) { u8bFree(bbuf); return o; }

    if (kind == WALK_KIND_LNK) {
        unlink((char *)u8bDataHead(fp));
        u8bFeed1(bbuf, 0);
        if (symlink((char *)u8bDataHead(bbuf), (char *)u8bDataHead(fp)) != 0) {
            u8bFree(bbuf);
            fail(SNIFFFAIL);
        }
    } else {
        int fd = -1;
        o = FILECreate(&fd, $path(fp));
        if (o != OK) { u8bFree(bbuf); return o; }
        u8cs data = {u8bDataHead(bbuf), u8bIdleHead(bbuf)};
        o = FILEFeedAll(fd, data);
        FILEClose(&fd);
        if (o != OK) { u8bFree(bbuf); return o; }
        if (kind == WALK_KIND_EXE)
            chmod((char *)u8bDataHead(fp), 0755);
    }
    u8bFree(bbuf);

    call(SNIFFAtStampPath, fp, g->ts);
    done;
}

//  In dryrun mode: lstat the target path; if it exists with an
//  unknown mtime, count it as an overlap conflict.  No writes.
static ok64 get_check_overlap_one(get_ctx *g, u8cs path) {
    sane(g);
    a_path(fp);
    call(SNIFFFullpath, fp, g->reporoot, path);
    struct stat xb = {};
    if (lstat((char *)u8bDataHead(fp), &xb) != 0) done;
    struct timespec xt = {.tv_sec = xb.st_mtim.tv_sec,
                          .tv_nsec = xb.st_mtim.tv_nsec};
    ron60 xr = SNIFFAtOfTimespec(xt);
    if (!SNIFFAtKnown(xr)) {
        if (g->conflicts < 5) {
            fprintf(stderr, "sniff: dirty overlap %.*s\n",
                    (int)$len(path), (char *)path[0]);
        }
        g->conflicts++;
    }
    done;
}

static ok64 get_visit(u8cs path, u8 kind, u8cp esha, u8cs blob,
                      void0p vctx) {
    (void)blob;  // lazy mode
    get_ctx *g = (get_ctx *)vctx;

    if (kind == WALK_KIND_SUB) return WALKSKIP;

    if (kind == WALK_KIND_DIR) {
        if (g->dryrun) return OK;       // pre-flight: skip dir creation
        if ($empty(path)) return OK;    // root; walker recurses
        a_path(dp);
        SNIFFFullpath(dp, g->reporoot, path);
        FILEMakeDirP($path(dp));
        return OK;
    }

    //  File-like entry (REG / EXE / LNK).  Mark the path as a target
    //  before writing so prune won't touch it even if write fails.
    {
        u32 idx = SNIFFIntern(path);
        get_mark_target(g, idx);
    }

    if (g->dryrun) {
        ok64 o = get_check_overlap_one(g, path);
        if (o != OK) g->error = o;
        return o;
    }

    ok64 o = get_write_one(g, path, kind, esha);
    if (o != OK) g->error = o;
    return o;
}

// --- Prune: unlink any wt file that sniff wrote before but isn't in
//     the new target tree.  The stamp-set check protects user-created
//     untracked files (they never carry a sniff stamp).

typedef struct { get_ctx *g; u32 pruned; } prune_ctx;

static ok64 get_prune_cb(void *varg, path8bp path) {
    sane(varg);
    prune_ctx *p = (prune_ctx *)varg;
    get_ctx *g = p->g;
    a_dup(u8c, full, u8bData(path));

    u8cs rel = {};
    if (!SNIFFRelFromFull(&rel, g->reporoot, full)) return OK;
    if (SNIFFSkipMeta(rel))                         return OK;

    u32 idx = SNIFFIntern(rel);
    if (get_is_target(g, idx)) return OK;

    struct stat sb = {};
    if (lstat((char const *)full[0], &sb) != 0) return OK;
    struct timespec ts = {.tv_sec = sb.st_mtim.tv_sec,
                          .tv_nsec = sb.st_mtim.tv_nsec};
    ron60 r = SNIFFAtOfTimespec(ts);
    if (!SNIFFAtKnown(r)) return OK;   // untracked user file — leave alone.

    //  unlink() wants a NUL-terminated C string; `path` is NUL-termed
    //  by FILEScanRecurse → PATHu8bTerm at each level, so the byte at
    //  full[1] is already '\0' (see abc/PATH.h).
    if (unlink((char const *)full[0]) == 0) p->pruned++;
    return OK;
}

static ok64 get_prune(get_ctx *g) {
    sane(g);
    a_path(root_path);
    u8bFeed(root_path, g->reporoot);
    call(PATHu8bTerm, root_path);
    prune_ctx pctx = {.g = g, .pruned = 0};
    call(FILEScan, root_path,
         (FILE_SCAN)(FILE_SCAN_FILES | FILE_SCAN_LINKS | FILE_SCAN_DEEP),
         get_prune_cb, &pctx);
    if (pctx.pruned > 0)
        fprintf(stderr, "sniff: pruned %u file(s)\n", pctx.pruned);
    done;
}

// --- Pre-flight: cross-branch wt-dirty scan ---
//
//  Walks every non-meta file in the wt; if any has an mtime that
//  isn't in sniff's stamp-set, the wt is considered dirty and a
//  cross-branch GET must refuse.  Same membership rule as
//  `sniff status`.

typedef struct {
    u8cs reporoot;
    b8   dirty;
    u32  count;
} get_wt_dirty_ctx;

static ok64 get_wt_dirty_cb(void *varg, path8bp path) {
    sane(varg);
    get_wt_dirty_ctx *d = (get_wt_dirty_ctx *)varg;
    a_dup(u8c, full, u8bData(path));

    u8cs rel = {};
    if (!SNIFFRelFromFull(&rel, d->reporoot, full)) return OK;
    if (SNIFFSkipMeta(rel))                          return OK;

    struct stat sb = {};
    if (lstat((char const *)full[0], &sb) != 0) return OK;
    struct timespec ts = {.tv_sec = sb.st_mtim.tv_sec,
                          .tv_nsec = sb.st_mtim.tv_nsec};
    ron60 r = SNIFFAtOfTimespec(ts);
    if (!SNIFFAtKnown(r)) {
        if (d->count < 5) {
            fprintf(stderr, "sniff: dirty %.*s\n",
                    (int)$len(rel), (char *)rel[0]);
        }
        d->count++;
        d->dirty = YES;
    }
    return OK;
}

static b8 get_wt_dirty(u8cs reporoot) {
    get_wt_dirty_ctx ctx = {.dirty = NO, .count = 0};
    ctx.reporoot[0] = reporoot[0];
    ctx.reporoot[1] = reporoot[1];
    a_path(wp);
    u8bFeed(wp, reporoot);
    if (PATHu8bTerm(wp) != OK) return NO;
    (void)FILEScan(wp,
                   (FILE_SCAN)(FILE_SCAN_FILES | FILE_SCAN_LINKS |
                               FILE_SCAN_DEEP),
                   get_wt_dirty_cb, &ctx);
    return ctx.dirty;
}

// --- Public API ---

ok64 GETCheckout(u8cs reporoot, u8cs hex, u8cs source) {
    sane($ok(hex));
    keeper *k = &KEEP;

    fprintf(stderr, "GETDBG GETCheckout hex=[%.*s] hexlen=%lld\n",
            (int)$len(hex), (char const *)hex[0], (long long)$len(hex));
    size_t hexlen = $len(hex);
    if (hexlen > 15) hexlen = 15;
    u64 hashlet = WHIFFHexHashlet60(hex);

    Bu8 buf = {};
    call(u8bAllocate, buf, 1UL << 24);
    u8 otype = 0;
    ok64 o = KEEPGet(k, hashlet, hexlen, buf, &otype);
    if (o != OK) {
        u8bFree(buf);
        fprintf(stderr, "sniff: object not found\n");
        fail(SNIFFFAIL);
    }

    //  Dereference annotated tag.
    if (otype == DOG_OBJ_TAG) {
        u8cs body = {u8bDataHead(buf), u8bIdleHead(buf)};
        u8cs field = {}, value = {};
        sha1 tag_sha = {};
        a_raw(tag_bin, tag_sha);
        b8 found = NO;
        while (GITu8sDrainCommit(body, field, value) == OK) {
            if ($empty(field)) break;
            if ($len(field) == 6 && memcmp(field[0], "object", 6) == 0 &&
                $len(value) >= 40) {
                u8cs hex40 = {value[0], $atp(value, 40)};
                HEXu8sDrainSome(tag_bin, hex40);
                found = YES;
                break;
            }
        }
        if (!found) {
            u8bFree(buf);
            fprintf(stderr, "sniff: bad tag (no object)\n");
            fail(SNIFFFAIL);
        }
        u8bReset(buf);
        o = KEEPGetExact(k, &tag_sha, buf, &otype);
        if (o != OK || otype != DOG_OBJ_COMMIT) {
            u8bFree(buf);
            fprintf(stderr, "sniff: tag target not a commit\n");
            fail(SNIFFFAIL);
        }
    }

    if (otype != DOG_OBJ_COMMIT) {
        u8bFree(buf);
        fprintf(stderr, "sniff: not a commit\n");
        fail(SNIFFFAIL);
    }

    sha1 tree_sha = {};
    u8cs commit = {u8bDataHead(buf), u8bIdleHead(buf)};
    fprintf(stderr, "GETDBG commit body (first 120 bytes): %.*s\n",
            (int)($len(commit) < 120 ? $len(commit) : 120),
            (char const *)commit[0]);
    o = GITu8sCommitTree(commit, tree_sha.data);
    fprintf(stderr, "GETDBG tree_sha=%02x%02x%02x%02x\n",
            tree_sha.data[0], tree_sha.data[1],
            tree_sha.data[2], tree_sha.data[3]);
    u8bFree(buf);
    if (o != OK) {
        fprintf(stderr, "sniff: bad commit (no tree)\n");
        fail(SNIFFFAIL);
    }

    //  --- Pre-flight gate: cross-branch wt-dirty refuse ---------
    //  Compare baseline branch (latest get/post/patch row) to the
    //  target branch.  When they differ, any unattributed mtime in
    //  the wt blocks the switch — the caller must commit, stash,
    //  or reset before `be get` will move them off the current
    //  branch.  Same-branch GETs (refresh, restore wiped wt, or
    //  switch tips on the same branch) skip this gate; the per-
    //  file overlap pre-flight further down is sufficient there.
    {
        ron60 bts = 0, bverb = 0;
        uri bu = {};
        if (SNIFFAtBaseline(&bts, &bverb, &bu) == OK) {
            u8cs t_branch = {};
            if ($ok(source) && !u8csEmpty(source) &&
                *source[0] == '?' && $len(source) != 41) {
                t_branch[0] = $atp(source, 1);
                t_branch[1] = source[1];
            }
            u8cs b_branch = {bu.query[0], bu.query[1]};
            ssize_t bl = $len(b_branch), tl = $len(t_branch);
            b8 same_branch =
                (bl == tl) &&
                (bl == 0 ||
                 memcmp(b_branch[0], t_branch[0], (size_t)bl) == 0);

            if (!same_branch && get_wt_dirty(reporoot)) {
                fprintf(stderr,
                        "sniff: cross-branch GET refused "
                        "— wt is dirty\n");
                fail(SNIFFDRTY);
            }
        }
    }
    //  --- end pre-flight gate ------------------------------------

    get_ctx ctx = {.k = k, .error = OK};
    ctx.reporoot[0] = reporoot[0];
    ctx.reporoot[1] = reporoot[1];
    SNIFFAtNow(&ctx.ts, &ctx.tv);

    //  Size the target bitmap: SNIFFCount() grows during the walk as
    //  keeper interns new tree paths, so pad generously.
    ctx.target_cap = SNIFFCount() + (1u << 20);
    call(u8bAllocate, ctx.target, ctx.target_cap);
    memset(u8bDataHead(ctx.target), 0, ctx.target_cap);

    //  Pre-flight overlap pass: walk the target tree without writing
    //  any blobs; count files that exist on disk with an unknown
    //  mtime (would clobber user edits).  Bitmap marks are kept and
    //  reused by the real walk below.
    ctx.dryrun = YES;
    o = WALKTreeLazy(k, tree_sha.data, get_visit, &ctx);
    if (o == OK && ctx.error != OK) o = ctx.error;
    if (o != OK) { u8bFree(ctx.target); return o; }
    if (ctx.conflicts > 0) {
        fprintf(stderr,
                "sniff: GET refused — %u dirty file(s) in target "
                "tree; commit, stash, or reset before checkout\n",
                ctx.conflicts);
        u8bFree(ctx.target);
        fail(SNIFFOVRL);
    }
    ctx.dryrun = NO;

    o = WALKTreeLazy(k, tree_sha.data, get_visit, &ctx);
    if (o == OK && ctx.error != OK) o = ctx.error;
    if (o != OK) { u8bFree(ctx.target); return o; }

    //  Prune: any path on disk that was sniff-stamped but isn't in the
    //  new target tree.
    (void)get_prune(&ctx);
    u8bFree(ctx.target);

    //  Compose the `get` row URI via abc/URI.  Canonical at-log form:
    //  `?<branch>#<curhash>` — query carries the be-branch path
    //  (empty for trunk), fragment carries the tip sha.  Mirrors the
    //  REFS row format so readers walk the same shape everywhere.
    uri urow = {};
    a_pad(u8, qbuf, 128);
    if ($ok(source) && !u8csEmpty(source) && *source[0] == '?' &&
        $len(source) != 41) {
        //  Named refs come in with a leading '?', e.g. `?feat`.
        //  URI query slices exclude the sentinel per RFC 3986, so
        //  drop the leading byte before copying the slice into qbuf.
        a_dup(u8c, q, source);
        u8csUsed1(q);
        u8bFeed(qbuf, q);
    }
    {
        a_dup(u8c, q, u8bData(qbuf));
        urow.query[0] = q[0];
        urow.query[1] = q[1];
    }
    {
        a_dup(u8c, h, hex);
        urow.fragment[0] = h[0];
        urow.fragment[1] = h[1];
    }

    ron60 verb = SNIFFAtVerbGet();
    call(SNIFFAtAppendAt, ctx.ts, verb, &urow);

    //  Advance the keeper-side local-branch tip with verb `post`.
    //  Key: `?heads/<branch>` when `source` carries a branch; bare `?`
    //  (trunk) only when nothing in `source` names one.  Using the
    //  literal branch is critical — REFADV walks `<store>/refs` for
    //  `?heads/<X>` keys, and a bare-`?` row leaves the per-branch
    //  local tip unadvertised, which silently short-circuits future
    //  `WIREPush` calls.  Failure here is non-fatal: the worktree is
    //  already updated, subsequent `be get` re-resolves via the
    //  peer-prefixed row.
    {
        a_path(keepdir, u8bDataC(KEEP.h->root), KEEP_DIR_S);
        a_pad(u8, key_buf, 128);
        u8bFeed1(key_buf, '?');
        if ($ok(source) && !u8csEmpty(source) && *source[0] == '?' &&
            $len(source) != 41) {
            a_dup(u8c, ref_q, source);
            u8csUsed1(ref_q);  //  drop leading '?'
            //  Strip a leading `refs/` if present so the key is the
            //  same `?heads/<X>` form REFSAppendVerb / REFADV expect.
            a_cstr(refs_pfx, "refs/");
            if ($len(ref_q) > 5 &&
                memcmp(ref_q[0], refs_pfx[0], 5) == 0)
                u8csUsed(ref_q, 5);
            u8bFeed(key_buf, ref_q);
        }
        a_dup(u8c, key_s, u8bData(key_buf));
        (void)REFSAppendVerb($path(keepdir), REFSVerbPost(), key_s, hex);
    }

    fprintf(stderr, "sniff: checkout done\n");
    done;
}
