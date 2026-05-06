//  GET: checkout a commit tree from keeper.
//
//  Pipeline:
//    1. Resolve the baseline tree from the latest get/post/patch row
//       (NULL on first checkout).
//    2. Pre-flight classifier (`get_overlap_check`) merges baseline
//       and target tree path-lists via `KEEPu8ssDrain` and produces:
//         * a no-op overlay list (paths whose content is unchanged —
//           WRITE skips them so dirty user content survives);
//         * an unlink list (clean baseline-only paths the post-WRITE
//           step drops from the wt);
//         * a refusal when any incoming change would clobber a dirty
//           wt file.
//    3. WRITE pass: WALKTreeLazy over target → materialise files,
//       creating parent dirs as needed, stamping each with a shared
//       ron60 ts via utimensat.
//    4. Drain the unlink list.
//    5. Append one `get` ULOG row with the same ts; advance the
//       keeper-side per-branch tip via REFSAppendVerb.
//
#include "GET.h"

#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "abc/FILE.h"
#include "abc/HEX.h"
#include "abc/PATH.h"
#include "abc/PRO.h"
#include "abc/RON.h"
#include "dog/HOME.h"
#include "graf/GRAF.h"
#include "keeper/GIT.h"
#include "keeper/REFS.h"
#include "keeper/WALK.h"

#include "AT.h"
#include "SNIFF.h"

typedef struct {
    keeper        *k;
    u8cs           reporoot;
    ron60          ts;          // stamp to apply via utimensat
    struct timespec tv;         // same stamp in timespec form
    ok64           error;
    //  Newline-separated, lex-sorted path lists (subsets of the target
    //  tree).  WALKTreeLazy visits the target in the same order, so we
    //  advance these cursors in lockstep with the walk.
    //
    //   noop_cursor   — target sha matches baseline; preserve whatever
    //                   bytes are on disk (including dirty user edits).
    //   merges_cursor — wt has a real local edit; the merge drain will
    //                   weave-merge wt vs tgt afterwards, so checkout
    //                   must not clobber the wt content here.
    u8cs           noop_cursor;
    u8cs           merges_cursor;
} get_ctx;

//  Write one blob to disk, create dirs as needed, chmod if exec,
//  symlink if link; then stamp it with ctx->tv.  Caller is
//  responsible for the dirty-overlap pre-flight (see get_overlap_check
//  and GETCheckout); reaching here means no dirty collision was
//  detected.
static ok64 get_write_one(get_ctx *g, u8cs path, u8 kind, u8cp esha) {
    sane(g);
    keeper *k = g->k;

    a_path(fp);
    call(SNIFFFullpath, fp, g->reporoot, path);

    Bu8 bbuf = {};
    call(u8bAllocate, bbuf, 1UL << 24);
    u8 bt = 0;
    sha1 entry_sha = {};
    sha1Mv(&entry_sha, (sha1 const *)esha);
    ok64 o = KEEPGetExact(k, &entry_sha, bbuf, &bt);
    if (o != OK) { u8bFree(bbuf); return o; }

    if (kind == WALK_KIND_LNK) {
        FILEUnLink($path(fp));
        u8bFeed1(bbuf, 0);   // NUL-terminate so $path(bbuf) is C-string-safe
        if (FILESymLink($path(bbuf), $path(fp)) != OK) {
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
            FILEChmod($path(fp), 0755);
    }
    u8bFree(bbuf);

    call(SNIFFAtStampPath, fp, g->ts);
    done;
}

static ok64 get_visit(u8cs path, u8 kind, u8cp esha, u8cs blob,
                      void0p vctx) {
    (void)blob;  // lazy mode
    get_ctx *g = (get_ctx *)vctx;

    //  Submodule (gitlink, mode 160000).  Sniff doesn't manage submodule
    //  contents — git's own submodule machinery does.  Skip the entry;
    //  no write, no mark.
    if (kind == WALK_KIND_SUB) return WALKSKIP;

    if (kind == WALK_KIND_DIR) {
        if ($empty(path)) return OK;    // root; walker recurses
        a_path(dp);
        SNIFFFullpath(dp, g->reporoot, path);
        FILEMakeDirP($path(dp));
        return OK;
    }

    //  No-op overlay: target's content at this path equals baseline's;
    //  pre-flight cleared the merged path list in lockstep with this
    //  walk's order.  Skip the write so dirty user edits aren't
    //  clobbered by a rewrite of identical bytes.  Don't stamp either —
    //  the file's mtime stays whatever the user left it as.
    //
    //  Exception: if the file was wiped from disk (lstat fails), there
    //  is nothing to preserve — fall through and recreate it.
    if (!u8csEmpty(g->noop_cursor)) {
        u8cs head = {};
        a_dup(u8c, peek, g->noop_cursor);
        if (u8csDrainLine(peek, head) == OK
            && $len(head) == $len(path)
            && memcmp(head[0], path[0], (size_t)$len(head)) == 0) {
            (void)u8csDrainLine(g->noop_cursor, head);
            a_path(probe);
            if (SNIFFFullpath(probe, g->reporoot, path) == OK) {
                struct stat sb = {};
                if (lstat((char *)u8bDataHead(probe), &sb) == 0)
                    return OK;     // present on disk — preserve it
            }
            //  File missing → fall through to get_write_one.
        }
    }

    //  Merge path: wt has a real local edit and the merge drain will
    //  weave-merge it against tgt afterwards.  Skip the write here so
    //  the wt's edits stay live for the drain to read.  No restamp
    //  either — the drain stamps after writing the merged bytes.
    if (!u8csEmpty(g->merges_cursor)) {
        u8cs head = {};
        a_dup(u8c, peek, g->merges_cursor);
        if (u8csDrainLine(peek, head) == OK
            && $len(head) == $len(path)
            && memcmp(head[0], path[0], (size_t)$len(head)) == 0) {
            (void)u8csDrainLine(g->merges_cursor, head);
            return OK;
        }
    }

    ok64 o = get_write_one(g, path, kind, esha);
    if (o != OK) g->error = o;
    return o;
}

// --- Pre-flight classifier via baseline ↔ target ULOG-row merge.
//
//  Materialise both trees as ULOG-shaped row buffers (KEEPTreeULog),
//  then heap-walk via SNIFFMergeWalk.  Per distinct path the step
//  callback sees a tie group of 1-2 records (one per side).  Decisions:
//    * both sides + identical mode/sha → no-op overlay: WRITE skips
//      so dirty user content survives.  Appended to `noop_out`.
//    * either side is mode 160000 (gitlink) → submodule, ignored.
//    * real change / add / delete  → lstat; if mtime ∉ stamp-set,
//      conflict.  For deletes (baseline-only) where the file is clean
//      and present on disk, append to `unlink_out`.
//    * baseline differs from target AND wt has an unattributed mtime:
//        - if wt content hashes to the baseline sha → clean stamp drift,
//          let checkout overwrite + restamp (no special bucket).
//        - else (real local edit) → append to `merges_out`; checkout
//          skips the path so the merge drain (`GRAFMergeWtFile`) can
//          weave-merge wt-on-disk against tgt afterwards.
//
//  `noop_out`, `unlink_out`, and `merges_out` are reset on entry; on
//  success each carries newline-separated lex-sorted paths.

typedef struct {
    u8cs   reporoot;
    u8bp   noop_out;
    u8bp   unlink_out;
    u8bp   merges_out;
    ron60  v_base;
    ron60  v_tgt;
    u32    no_base_conflicts;   // dirty wt without a baseline to merge against
} get_overlap_ctx;

//  Compare two ULOG-row kind (verb's bottom RON64 digit) and
//  uri.fragment (hex sha) by content.  YES iff both kind and sha
//  match.
static b8 get_leaf_eq(ulogreccp a, ulogreccp b) {
    if (ok64Lit(a->verb, 0) != ok64Lit(b->verb, 0)) return NO;
    if (u8csLen(a->uri.fragment) != u8csLen(b->uri.fragment)) return NO;
    return memcmp(a->uri.fragment[0], b->uri.fragment[0],
                  u8csLen(a->uri.fragment)) == 0;
}

static b8 get_is_sub(ulogreccp r) {
    return ok64Lit(r->verb, 0) == RON_s;
}

static ok64 get_overlap_step(ulogreccp recs, u32 n, void *vctx) {
    get_overlap_ctx *c = (get_overlap_ctx *)vctx;
    ulogreccp base = NULL;
    ulogreccp tgt  = NULL;
    for (u32 i = 0; i < n; i++) {
        if (ok64stem(recs[i].verb) == c->v_base) base = &recs[i];
        if (ok64stem(recs[i].verb) == c->v_tgt)  tgt  = &recs[i];
    }
    if (!base && !tgt) return OK;

    //  Path is identical in the tie group — peek from whichever side.
    u8cs path = {};
    u8csMv(path, (base ? base->uri.path : tgt->uri.path));

    b8 is_sub = (base && get_is_sub(base)) || (tgt && get_is_sub(tgt));
    if (is_sub) return OK;        //  gitlink — sniff doesn't manage

    b8 changed = !base || !tgt || !get_leaf_eq(base, tgt);

    if (!changed && tgt) {
        u8bFeed(c->noop_out, path);
        u8bFeed1(c->noop_out, '\n');
        return OK;
    }
    if (!changed) return OK;

    //  changed && !sub: lstat + stamp-set check.
    a_path(fp);
    if (SNIFFFullpath(fp, c->reporoot, path) != OK) return OK;
    struct stat sb = {};
    ok64 lo = FILELStat(&sb, $path(fp));
    if (lo == FILENOENT) return OK;    // vanished mid-walk
    if (lo != OK) return lo;             // permissions etc — propagate
    struct timespec mts = {.tv_sec  = sb.st_mtim.tv_sec,
                           .tv_nsec = sb.st_mtim.tv_nsec};
    ron60 mr = SNIFFAtOfTimespec(mts);

    //  Unattributed mtime without a baseline to compare against:
    //  refuse — there's no "clean drift" answer possible, and graf
    //  has no history to weave-merge with.  Mirrors the prior
    //  blanket dirty-overlap refusal for this corner.
    if (!SNIFFAtKnown(mr) && !base) {
        if (c->no_base_conflicts < 5)
            fprintf(stderr, "sniff: dirty overlay %.*s\n",
                    (int)$len(path), (char *)path[0]);
        c->no_base_conflicts++;
        return OK;
    }

    //  Unattributed mtime: hash wt bytes and compare to baseline.
    //  Equal → clean stamp drift, let checkout overwrite + restamp
    //  (silent fall-through) — UNLESS tgt is absent (deletion), in
    //  which case the WRITE pass never visits this path and the
    //  unlink branch below has to do the work.  Different → real
    //  local edit, schedule a weave-merge.
    if (!SNIFFAtKnown(mr) && base) {
        sha1 wt_sha = {};
        b8 hashed = NO;
        if (S_ISREG(sb.st_mode)) {
            u8bp m = NULL;
            if (FILEMapRO(&m, $path(fp)) == OK && m) {
                u8cs body = {u8bDataHead(m), u8bIdleHead(m)};
                KEEPObjSha(&wt_sha, DOG_OBJ_BLOB, body);
                FILEUnMap(m);
                hashed = YES;
            } else if (sb.st_size == 0) {
                u8cs empty = {NULL, NULL};
                KEEPObjSha(&wt_sha, DOG_OBJ_BLOB, empty);
                hashed = YES;
            }
        }

        sha1 base_sha = {};
        if (u8csLen(base->uri.fragment) == 40) {
            u8s bin_s = {base_sha.data, base_sha.data + 20};
            a_dup(u8c, hex_dup, base->uri.fragment);
            HEXu8sDrainSome(bin_s, hex_dup);
        }
        if (hashed && memcmp(wt_sha.data, base_sha.data, 20) == 0) {
            //  Clean drift.  If tgt also has the path, the WRITE pass
            //  will overwrite + restamp — silent fall-through.  If tgt
            //  is absent (deletion), fall through to the unlink branch
            //  below; otherwise the file lingers in the wt forever
            //  because nothing visits it again.
            if (tgt) return OK;
            //  base && !tgt → drop into the clean-delete arm below.
        } else {
            //  Real local edit: schedule for weave-merge.  The drain
            //  pass (`get_drain_merges`) will read wt-on-disk after
            //  the checkout pass skips this path.
            u8bFeed(c->merges_out, path);
            u8bFeed1(c->merges_out, '\n');
            return OK;
        }
    }
    if (base && !tgt) {
        //  Clean delete: schedule unlink.
        u8bFeed(c->unlink_out, path);
        u8bFeed1(c->unlink_out, '\n');
    }
    return OK;
}

//  `base_tree` may be NULL — first-checkout / no-baseline case.  Every
//  walked path then comes from the target side only; all three output
//  lists end up empty.
static ok64 get_overlap_check(keeper *k, u8cs reporoot,
                              u8cp base_tree, u8cp tgt_tree,
                              u8bp noop_out, u8bp unlink_out,
                              u8bp merges_out) {
    sane(k && tgt_tree && noop_out && unlink_out && merges_out);
    u8bReset(noop_out);
    u8bReset(unlink_out);
    u8bReset(merges_out);

    a_cstr(s_base, "base"); a_dup(u8c, db, s_base);
    a_cstr(s_tgt,  "tgt");  a_dup(u8c, dt, s_tgt);
    ron60 v_base = 0, v_tgt = 0;
    call(RONutf8sDrain, &v_base, db);
    call(RONutf8sDrain, &v_tgt,  dt);

    Bu8 bu = {}, tu = {};
    call(u8bAllocate, bu, 1UL << 20);
    call(u8bAllocate, tu, 1UL << 20);

    ok64 r = OK;
    if (base_tree) r = KEEPTreeULog(k, base_tree, 0, v_base, bu);
    if (r == OK)   r = KEEPTreeULog(k, tgt_tree,  0, v_tgt,  tu);
    if (r != OK) { u8bFree(bu); u8bFree(tu); return r; }

    a_dup(u8c, view_b, u8bData(bu));
    a_dup(u8c, view_t, u8bData(tu));
    a_pad(u8cs, ins, 2);
    u8cssFeed1(ins_idle, view_b);
    u8cssFeed1(ins_idle, view_t);
    a_dup(u8cs, cursors, u8csbData(ins));

    get_overlap_ctx ctx = {
        .noop_out   = noop_out,
        .unlink_out = unlink_out,
        .merges_out = merges_out,
        .v_base     = v_base,
        .v_tgt      = v_tgt,
        .no_base_conflicts = 0,
    };
    u8csMv(ctx.reporoot, reporoot);

    ok64 mr = SNIFFMergeWalk(cursors, get_overlap_step, &ctx);
    u8bFree(bu); u8bFree(tu);
    if (mr != OK) return mr;

    if (ctx.no_base_conflicts > 0) {
        fprintf(stderr,
                "sniff: GET refused — %u dirty file(s) overlay target "
                "paths and have no baseline to merge against; commit, "
                "stash, or reset before checkout\n",
                ctx.no_base_conflicts);
        return SNIFFOVRL;
    }
    done;
}

//  Drain a newline-separated path list and unlink each entry.  Paths
//  came from get_overlap_check's classifier, which already verified
//  presence + clean stamp; defensive lstat is omitted.  After
//  unlinking we walk back up each path's parent chain and `rmdir`
//  every directory that became empty — git's checkout collapses
//  empty dirs the same way, and rsync flags surviving ones as
//  `*deleting <dir>/`.  Reports the file count to stderr.
static ok64 get_drain_unlinks(u8cs reporoot, u8cs unlinks) {
    sane($ok(reporoot));
    u32 dropped = 0;
    a_dup(u8c, scan, unlinks);
    for (;;) {
        u8cs path = {};
        if (u8csDrainLine(scan, path) != OK) break;
        if ($empty(path)) continue;
        a_path(fp);
        if (SNIFFFullpath(fp, reporoot, path) != OK) continue;
        if (FILEUnLink($path(fp)) == OK) dropped++;
        //  Walk up: rmdir any newly-empty parent until we hit a
        //  non-empty dir, the reporoot, or rmdir fails (ENOTEMPTY).
        //  We mutate `fp` in place by truncating at the last `/`.
        u8 *base_p = u8bDataHead(fp);
        u8 *end_p  = u8bIdleHead(fp);
        a_dup(u8c, root_s, reporoot);
        size_t root_len = (size_t)$len(root_s);
        for (;;) {
            //  Trim trailing path component including its slash.
            u8 *slash = NULL;
            for (u8 *p = base_p; p < end_p; p++)
                if (*p == '/') slash = p;
            if (!slash) break;
            //  Don't try to rmdir at-or-above reporoot.
            size_t prefix_len = (size_t)(slash - base_p);
            if (prefix_len <= root_len) break;
            *slash = 0;
            ((u8 **)fp)[2] = slash;       // idle = slash
            if (rmdir((char const *)base_p) != 0) break;
            end_p = slash;
        }
    }
    if (dropped > 0)
        fprintf(stderr, "sniff: pruned %u file(s)\n", dropped);
    done;
}

//  Drain a newline-separated path list of weave-merge targets.  For
//  each path, call `GRAFMergeWtFile` (which reads the live wt file as
//  the implicit edit on `base` and merges against `tgt`'s history),
//  write the merged bytes back to the wt, and stamp the new mtime.
//  Best-effort per path: a per-path failure is logged and the rest
//  continue.
static ok64 get_drain_merges(u8cs reporoot, u8cs merges,
                             sha1 const *base, sha1 const *tgt,
                             ron60 stamp_ts) {
    sane($ok(reporoot) && base && tgt);
    if (u8csEmpty(merges)) done;

    Bu8 out = {};
    call(u8bAllocate, out, 1UL << 24);

    u32 merged = 0, failed = 0;
    a_dup(u8c, scan, merges);
    for (;;) {
        u8cs path = {};
        if (u8csDrainLine(scan, path) != OK) break;
        if ($empty(path)) continue;

        ok64 mr = GRAFMergeWtFile(path, reporoot, base, tgt, out);
        if (mr != OK) {
            fprintf(stderr,
                    "sniff: merge failed for %.*s (graf err) — "
                    "leaving wt content untouched\n",
                    (int)$len(path), (char *)path[0]);
            failed++;
            continue;
        }

        a_path(fp);
        if (SNIFFFullpath(fp, reporoot, path) != OK) {
            failed++; continue;
        }
        int fd = -1;
        if (FILECreate(&fd, $path(fp)) != OK) {
            failed++; continue;
        }
        u8cs body = {u8bDataHead(out), u8bIdleHead(out)};
        ok64 wo = FILEFeedAll(fd, body);
        FILEClose(&fd);
        if (wo != OK) { failed++; continue; }

        (void)SNIFFAtStampPath(fp, stamp_ts);
        merged++;
    }

    u8bFree(out);
    if (merged > 0)
        fprintf(stderr, "sniff: weave-merged %u file(s)\n", merged);
    if (failed > 0)
        fprintf(stderr, "sniff: merge failures: %u file(s)\n", failed);
    done;
}

// --- Pre-flight: cross-branch wt-dirty scan ---
//
//  Walks every non-meta file in the wt; if any has an mtime that
//  isn't in sniff's stamp-set, the wt is considered dirty and a
//  cross-branch GET must refuse.  Same membership rule as
//  `sniff status` (shared via SNIFFAtScanDirty).

static ok64 get_wt_dirty_cb(u8cs rel, void *ctx) {
    sane(ctx);
    u32 *count = (u32 *)ctx;
    if (*count < 5)
        fprintf(stderr, "sniff: dirty %.*s\n",
                (int)$len(rel), (char *)rel[0]);
    (*count)++;
    return OK;
}

static b8 get_wt_dirty(u8cs reporoot) {
    u32 count = 0;
    (void)SNIFFAtScanDirty(reporoot, get_wt_dirty_cb, &count);
    return count > 0;
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

    sha1 tree_sha = {}, tgt_commit_sha = {};
    u8cs commit = {u8bDataHead(buf), u8bIdleHead(buf)};
    fprintf(stderr, "GETDBG commit body (first 120 bytes): %.*s\n",
            (int)($len(commit) < 120 ? $len(commit) : 120),
            (char const *)commit[0]);
    o = GITu8sCommitTree(commit, tree_sha.data);
    fprintf(stderr, "GETDBG tree_sha=%02x%02x%02x%02x\n",
            tree_sha.data[0], tree_sha.data[1],
            tree_sha.data[2], tree_sha.data[3]);
    //  Hash the commit body for the weave-merge drain (its sha is the
    //  tgt commit hashlet graf walks from).  Must happen before
    //  u8bFree(buf) — `commit` borrows into the mapping.
    KEEPObjSha(&tgt_commit_sha, DOG_OBJ_COMMIT, commit);
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

    //  Resolve the baseline tree from the latest get/post/patch row.
    //  Used by the overlap pre-flight to distinguish "incoming change"
    //  from "no-op overlay".  Absent baseline (fresh wt) → NULL pointer
    //  passes through, every target path is treated as incoming.
    sha1 base_tree = {}, base_commit_sha = {};
    b8 has_base_tree = NO, has_base_commit = NO;
    {
        ron60 bts = 0, bverb = 0;
        uri bu = {};
        if (SNIFFAtBaseline(&bts, &bverb, &bu) == OK) {
            sha1hex hex = {};
            if (SNIFFAtQueryFirstSha(&bu, &hex) == OK) {
                //  Decode the baseline tip hex into a sha1 for the
                //  weave-merge drain (see get_drain_merges).
                if (sha1FromSha1hex(&base_commit_sha, &hex) == OK)
                    has_base_commit = YES;

                u8cs hex_s = {};
                sha1hexSlice(hex_s, &hex);
                u64 bhashlet = WHIFFHexHashlet60(hex_s);
                Bu8 cbuf = {};
                if (u8bAllocate(cbuf, 1UL << 24) == OK) {
                    u8 ctype = 0;
                    if (KEEPGet(k, bhashlet, 40, cbuf, &ctype) == OK) {
                        //  Peel annotated tag → commit (mill-tags
                        //  baselines like `?tags/v2.52.0` resolve
                        //  to a TAG object, not the commit it
                        //  points at).  Mirrors KEEPResolveTree.
                        if (ctype == DOG_OBJ_TAG) {
                            a_dup(u8c, tbody, u8bData(cbuf));
                            u8cs tf = {}, tv = {};
                            sha1 tag_target = {};
                            b8 got = NO;
                            while (GITu8sDrainCommit(tbody, tf, tv) == OK) {
                                if (u8csEmpty(tf)) break;
                                if (u8csLen(tf) == 6 &&
                                    memcmp(tf[0], "object", 6) == 0 &&
                                    u8csLen(tv) >= 40) {
                                    u8s sb = {tag_target.data,
                                              tag_target.data + 20};
                                    u8cs hx = {tv[0], tv[0] + 40};
                                    if (HEXu8sDrainSome(sb, hx) == OK)
                                        got = YES;
                                    break;
                                }
                            }
                            if (got) {
                                u64 ch = WHIFFHashlet60(&tag_target);
                                u8bReset(cbuf);
                                ctype = 0;
                                (void)KEEPGet(k, ch, 40, cbuf, &ctype);
                                //  Override base_commit_sha with the
                                //  peeled commit so weave-merge sees
                                //  the right history root.
                                memcpy(base_commit_sha.data,
                                       tag_target.data, 20);
                            }
                        }
                        if (ctype == DOG_OBJ_COMMIT) {
                            u8cs cbody = {u8bDataHead(cbuf),
                                          u8bIdleHead(cbuf)};
                            if (GITu8sCommitTree(cbody, base_tree.data) == OK)
                                has_base_tree = YES;
                        }
                    }
                    u8bFree(cbuf);
                }
            }
        }
    }

    Bu8 noop = {}, unlinks = {}, merges = {};
    call(u8bAllocate, noop,    1UL << 20);
    call(u8bAllocate, unlinks, 1UL << 20);
    call(u8bAllocate, merges,  1UL << 20);
    //  TODO: even on a fresh clone (`base_tree==NULL`) the overlap
    //  check still walks the target tree once to detect dirty wt
    //  files sitting at target-tree paths (the
    //  `no_base_conflicts` refusal — see be-get-overlay-no-baseline
    //  test).  That makes sniff GET walk the target tree TWICE on
    //  a fresh clone (once here, once in WALKTreeLazy below).  A
    //  better split would fuse the dirty-overlap detection into
    //  the WRITE pass and skip this pre-flight when there's no
    //  baseline to compare against; left as an optimisation since
    //  the safety check has to run somewhere.
    o = get_overlap_check(k, reporoot,
                          has_base_tree ? base_tree.data : NULL,
                          tree_sha.data, noop, unlinks, merges);
    if (o != OK) { u8bFree(noop); u8bFree(unlinks); u8bFree(merges); return o; }

    get_ctx ctx = {.k = k, .error = OK};
    u8csMv(ctx.reporoot, reporoot);
    SNIFFAtNow(&ctx.ts, &ctx.tv);
    ctx.noop_cursor[0]   = u8bDataHead(noop);
    ctx.noop_cursor[1]   = u8bIdleHead(noop);
    ctx.merges_cursor[0] = u8bDataHead(merges);
    ctx.merges_cursor[1] = u8bIdleHead(merges);

    o = WALKTreeLazy(k, tree_sha.data, get_visit, &ctx);
    if (o == OK && ctx.error != OK) o = ctx.error;
    if (o != OK) {
        u8bFree(noop); u8bFree(unlinks); u8bFree(merges);
        return o;
    }

    //  Drain the weave-merge list now that checkout has skipped these
    //  paths, leaving wt edits live for graf to read.  Open graf
    //  read-only — already-open is fine (idempotent).
    if (has_base_commit && u8bDataLen(merges) > 0) {
        ok64 go = GRAFOpen(SNIFF.h, NO);
        b8 own_open = (go == OK);
        if (go == OK || go == GRAFOPEN || go == GRAFOPENRO) {
            a_dup(u8c, mlist, u8bData(merges));
            (void)get_drain_merges(reporoot, mlist,
                                   &base_commit_sha, &tgt_commit_sha,
                                   ctx.ts);
            if (own_open) GRAFClose();
        }
    }

    //  Prune the baseline-only paths the classifier flagged as clean.
    {
        a_dup(u8c, ulist, u8bData(unlinks));
        (void)get_drain_unlinks(reporoot, ulist);
    }
    u8bFree(noop); u8bFree(unlinks); u8bFree(merges);

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
