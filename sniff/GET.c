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
    ok64           error;
    //  Newline-separated, lex-sorted path list (subset of the target
    //  tree) where the target sha matches the baseline sha.  WALKTreeLazy
    //  visits the target in the same order, so we advance this cursor
    //  in lockstep: a path matching the head means "no-op overlay —
    //  preserve whatever bytes are on disk" (including dirty user edits).
    u8cs           noop_cursor;
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
//
//  Returns SNIFFOVRL when conflicts > 0 (printing up to 5 paths and a
//  summary line).  `noop_out` and `unlink_out` are reset on entry; on
//  success each carries newline-separated lex-sorted paths.

typedef struct {
    u8cs   reporoot;
    u8bp   noop_out;
    u8bp   unlink_out;
    ron60  v_base;
    ron60  v_tgt;
    u32    conflicts;
} get_overlap_ctx;

//  Compare two ULOG-row uri.query (mode) and uri.fragment (hex sha)
//  by content.  YES iff both mode and sha bytes are equal.
static b8 get_leaf_eq(ulogreccp a, ulogreccp b) {
    if (u8csLen(a->uri.query) != u8csLen(b->uri.query)) return NO;
    if (u8csLen(a->uri.fragment) != u8csLen(b->uri.fragment)) return NO;
    if (memcmp(a->uri.query[0],    b->uri.query[0],
               u8csLen(a->uri.query)) != 0) return NO;
    return memcmp(a->uri.fragment[0], b->uri.fragment[0],
                  u8csLen(a->uri.fragment)) == 0;
}

static b8 get_is_sub(ulogreccp r) {
    static u8c const sub[6] = "160000";
    return u8csLen(r->uri.query) == 6 &&
           memcmp(r->uri.query[0], sub, 6) == 0;
}

static ok64 get_overlap_step(ulogreccp recs, u32 n, void *vctx) {
    get_overlap_ctx *c = (get_overlap_ctx *)vctx;
    ulogreccp base = NULL;
    ulogreccp tgt  = NULL;
    for (u32 i = 0; i < n; i++) {
        if (recs[i].verb == c->v_base) base = &recs[i];
        if (recs[i].verb == c->v_tgt)  tgt  = &recs[i];
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
    if (lstat((char *)u8bDataHead(fp), &sb) != 0) return OK;
    struct timespec mts = {.tv_sec  = sb.st_mtim.tv_sec,
                           .tv_nsec = sb.st_mtim.tv_nsec};
    ron60 mr = SNIFFAtOfTimespec(mts);
    if (!SNIFFAtKnown(mr)) {
        if (c->conflicts < 5)
            fprintf(stderr, "sniff: dirty overlap %.*s\n",
                    (int)$len(path), (char *)path[0]);
        c->conflicts++;
        return OK;
    }
    if (base && !tgt) {
        //  Clean delete: schedule unlink.
        u8bFeed(c->unlink_out, path);
        u8bFeed1(c->unlink_out, '\n');
    }
    return OK;
}

//  `base_tree` may be NULL — first-checkout / no-baseline case.  Every
//  walked path then comes from the target side only; both output lists
//  end up empty.
static ok64 get_overlap_check(keeper *k, u8cs reporoot,
                              u8cp base_tree, u8cp tgt_tree,
                              u8bp noop_out, u8bp unlink_out) {
    sane(k && tgt_tree && noop_out && unlink_out);
    u8bReset(noop_out);
    u8bReset(unlink_out);

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
        .v_base     = v_base,
        .v_tgt      = v_tgt,
        .conflicts  = 0,
    };
    u8csMv(ctx.reporoot, reporoot);

    ok64 mr = SNIFFMergeWalk(cursors, get_overlap_step, &ctx);
    u8bFree(bu); u8bFree(tu);
    if (mr != OK) return mr;

    if (ctx.conflicts > 0) {
        fprintf(stderr,
                "sniff: GET refused — %u dirty file(s) overlap with "
                "incoming changes; commit, stash, or reset before "
                "checkout\n", ctx.conflicts);
        return SNIFFOVRL;
    }
    done;
}

//  Drain a newline-separated path list and unlink each entry.  Paths
//  came from get_overlap_check's classifier, which already verified
//  presence + clean stamp; defensive lstat is omitted.  Reports the
//  count to stderr to mirror the prior `pruned %u file(s)` notice.
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
        if (unlink((char const *)u8bDataHead(fp)) == 0) dropped++;
    }
    if (dropped > 0)
        fprintf(stderr, "sniff: pruned %u file(s)\n", dropped);
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

    //  Resolve the baseline tree from the latest get/post/patch row.
    //  Used by the overlap pre-flight to distinguish "incoming change"
    //  from "no-op overlay".  Absent baseline (fresh wt) → NULL pointer
    //  passes through, every target path is treated as incoming.
    sha1 base_tree = {};
    b8 has_base_tree = NO;
    {
        ron60 bts = 0, bverb = 0;
        uri bu = {};
        if (SNIFFAtBaseline(&bts, &bverb, &bu) == OK) {
            u8 hex40[40];
            if (SNIFFAtQueryFirstSha(&bu, hex40) == OK) {
                u8cs hex_s = {hex40, hex40 + 40};
                u64 bhashlet = WHIFFHexHashlet60(hex_s);
                Bu8 cbuf = {};
                if (u8bAllocate(cbuf, 1UL << 24) == OK) {
                    u8 ctype = 0;
                    if (KEEPGet(k, bhashlet, 40, cbuf, &ctype) == OK &&
                        ctype == DOG_OBJ_COMMIT) {
                        u8cs cbody = {u8bDataHead(cbuf),
                                      u8bIdleHead(cbuf)};
                        if (GITu8sCommitTree(cbody, base_tree.data) == OK)
                            has_base_tree = YES;
                    }
                    u8bFree(cbuf);
                }
            }
        }
    }

    Bu8 noop = {}, unlinks = {};
    call(u8bAllocate, noop,    1UL << 20);
    call(u8bAllocate, unlinks, 1UL << 20);
    o = get_overlap_check(k, reporoot,
                          has_base_tree ? base_tree.data : NULL,
                          tree_sha.data, noop, unlinks);
    if (o != OK) { u8bFree(noop); u8bFree(unlinks); return o; }

    get_ctx ctx = {.k = k, .error = OK};
    u8csMv(ctx.reporoot, reporoot);
    SNIFFAtNow(&ctx.ts, &ctx.tv);
    ctx.noop_cursor[0] = u8bDataHead(noop);
    ctx.noop_cursor[1] = u8bIdleHead(noop);

    o = WALKTreeLazy(k, tree_sha.data, get_visit, &ctx);
    if (o == OK && ctx.error != OK) o = ctx.error;
    if (o != OK) { u8bFree(noop); u8bFree(unlinks); return o; }

    //  Prune the baseline-only paths the classifier flagged as clean.
    {
        a_dup(u8c, ulist, u8bData(unlinks));
        (void)get_drain_unlinks(reporoot, ulist);
    }
    u8bFree(noop); u8bFree(unlinks);

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
