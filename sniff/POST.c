//  POST: commit the current worktree state.
//
//  Inputs at commit time: the worktree on disk and the ULOG.  The most
//  recent `get` / `post` / `patch` row names a baseline tree URI
//  (single hash → keeper, multiple → graf — graf is not wired yet and
//  defaults to keeper-single-hash-only for now).  `put` / `delete`
//  rows since the last `post` are the explicit staging intent.
//
//  Per-file change-set at commit time:
//    * path matches a `put <path>` row (since last post)   → rewrite
//    * path matches a `delete <path>` row                  → drop
//    * no explicit row for the path, any put/delete exists → carry
//      over from baseline (or drop if missing from wt)
//    * no put/delete rows at all since last post           → implicit
//      all-dirty: mtime ∉ stamp-set → rewrite; missing → drop.
//
//  Pack layout: one keeper pack with `strict_order=NO`, fed in the
//  order commit → trees → blobs (forward refs permitted).
//
#include "POST.h"

#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>

#include "abc/FILE.h"
#include "abc/HEX.h"
#include "abc/PATH.h"
#include "abc/PRO.h"
#include "dog/IGNO.h"
#include "dog/QURY.h"
#include "dog/WHIFF.h"
#include "graf/GRAF.h"
#include "graf/REBASE.h"
#include "keeper/GIT.h"
#include "keeper/REFS.h"
#include "keeper/SHA1.h"
#include "keeper/WALK.h"

#include "AT.h"

//  Cap on the per-commit ULOG-shaped buffers (decisions, leaves,
//  recs).  32 MiB is enough for tens of thousands of distinct paths
//  per commit at ~100 bytes per row.  A repo that exceeds this at
//  commit time has bigger problems than the cap.
#define POST_TREE_ULOG_MAX (32UL << 20)

// --- Per-commit decision stream ---
//
//  `post_classify_step` runs the merge / decide / hash inline and
//  writes one decision ULOG row per distinct path into `ctx.decisions`.
//  Verbs in the stream:
//    keep    : carry baseline sha+mode verbatim (M/A/D printer is
//              silent on KEEP).
//    unlink  : drop from tree + unlink from disk.
//    add     : new content (freshly hashed); query optionally chains
//              `&<old_sha>` so the M/A/D printer can distinguish add
//              ("A") from rewrite ("M") and the blob feed can build
//              an OFS/REF_DELTA against the baseline blob.
//
//  Every consumer (tree-build, unlink loop, blob feed, stamp,
//  patch-parents, M/A/D print) drains `decisions`.

typedef struct {
    keeper        *k;
    u8cs           reporoot;
    Bu8            decisions;    // ULOG-shaped: <ts>\t<verb>\t<path>?<query>#<frag>
    ron60          v_keep;       // verb constants emitted into `decisions`
    ron60          v_unlink;
    ron60          v_add;
    ron60          stamp_ts;     // single per-commit stamp (post ts)
    b8             any_pd;       // any put/delete rows since last post
    b8             base_is_patch;// baseline row is a `patch`, not get/post
    b8             has_base;     // baseline row exists (any get/post/patch)
    ron60          last_post_ts;
    ok64           error;
} post_ctx;

// --- git mode helpers ---

static void post_mode_feed(Bu8 tree, u16 mode) {
    //  Git modes are printed in octal without leading zeros.  All four
    //  values we emit are 5- or 6-digit strings.
    char buf[8];
    int n = snprintf(buf, sizeof(buf), "%o", (unsigned)mode);
    u8cs m = {(u8cp)buf, (u8cp)buf + n};
    u8bFeed(tree, m);
}

// --- Forward decls ---

static ok64 post_emit_decision(post_ctx *c, ron60 verb,
                               u8cs path, u16 mode,
                               sha1 const *old_sha,
                               sha1 const *frag_sha);

// --- Hash a wt file (mmap or readlink) into a sha1 ---

//  Compute the git-blob sha for a wt file.  Symlinks (mode 120000)
//  go through `readlink`; everything else uses `FILEMapRO`.  Output
//  written into `*out`.  Errors propagate (file gone, mmap fail).
static ok64 post_hash_path(u8cs reporoot, u8cs path, u16 mode, sha1 *out) {
    sane($ok(reporoot) && out);
    a_path(fp);
    if (SNIFFFullpath(fp, reporoot, path) != OK) fail(SNIFFFAIL);

    if (mode == 0120000) {
        char target[1024];
        ssize_t tlen = readlink((char const *)u8bDataHead(fp),
                                target, sizeof(target));
        if (tlen <= 0) fail(SNIFFFAIL);
        u8cs tv = {(u8cp)target, (u8cp)target + tlen};
        KEEPObjSha(out, DOG_OBJ_BLOB, tv);
        done;
    }

    u8bp mapped = NULL;
    call(FILEMapRO, &mapped, $path(fp));
    KEEPObjSha(out, DOG_OBJ_BLOB, u8bDataC(mapped));
    FILEUnMap(mapped);
    done;
}

// --- ULOG scans ---

//  YES iff `p` lives strictly beneath `prefix` (prefix must end '/').
fun b8 post_path_under(u8cs p, u8cs prefix) {
    size_t plen = $len(prefix);
    if (plen == 0) return NO;
    if ($len(p) <= plen) return NO;
    return memcmp(p[0], prefix[0], plen) == 0;
}

//  Walk a sorted ULOG row buffer and, for every row whose URI path
//  is strictly under `prefix`, emit a fresh ULOG row to `out` with
//  the same path but `emit_verb`.  `ig` (optional) filters via IGNO.
//  Returns YES via `*any_out` if at least one row matched (caller
//  uses it to decide whether to fall back to a different source).
static ok64 post_expand_under(u8b src, ron60 emit_verb, u8cs prefix,
                              ignocp ig, u8bp out, b8 *any_out) {
    sane(src && out);
    if (any_out) *any_out = NO;
    if (u8bDataLen(src) == 0) done;

    a_dup(u8c, scan, u8bData(src));
    while (!u8csEmpty(scan)) {
        ulogrec rec = {};
        ok64 dr = ULOGu8sDrain(scan, &rec);
        if (dr == NODATA) break;
        if (dr != OK) continue;
        u8cs path = {rec.uri.path[0], rec.uri.path[1]};
        if (!post_path_under(path, prefix)) continue;
        if (ig && IGNOMatch(ig, path, NO)) continue;

        uri u = {};
        u.path[0] = path[0];
        u.path[1] = path[1];
        ulogrec out_rec = {.ts = rec.ts, .verb = emit_verb, .uri = u};
        ok64 fo = ULOGu8sFeed(u8bIdle(out), &out_rec);
        if (fo != OK) return fo;
        if (any_out) *any_out = YES;
    }
    done;
}

//  Per-walk context for `post_pd_cb`.  Holds the two unsorted ULOG
//  intent buffers plus the baseline / wt cursors needed for in-place
//  dir-prefix expansion.  3b2 fully absorbed `post_expand_dir_rows`.
typedef struct {
    post_ctx *c;
    u8bp      put_unsorted;
    u8bp      del_unsorted;
    u8bp      bu;            // baseline ULOG (KEEPTreeULog) — borrowed
    u8bp      wu;            // wt ULOG (SNIFFWtULog) — borrowed
    ignocp    ig;            // wt-root .gitignore
    ron60     v_put_filter;
    ron60     v_del_filter;
    ron60     v_put_emit;
    ron60     v_del_emit;
} pd_walk_ctx;

static ok64 post_pd_cb(ron60 verb, u8cs path, ron60 ts, void *vctx) {
    sane(vctx);
    pd_walk_ctx *w = (pd_walk_ctx *)vctx;
    post_ctx    *c = w->c;
    c->any_pd = YES;

    //  Trailing-slash paths are dir prefixes; expand against bu/wu now.
    //
    //  Rules (preserved from the legacy post_expand_dir_rows):
    //    * delete dir/: emit a delete ULOG row for every baseline path
    //      strictly under the prefix.
    //    * put dir/, baseline coverage exists: emit a put ULOG row per
    //      baseline path under the prefix (IGNO doesn't apply to
    //      tracked files).
    //    * put dir/, no baseline match: emit a put ULOG row per wt
    //      path under the prefix (subject to IGNO).
    if (!$empty(path) && *u8csLast(path) == '/') {
        if (verb == w->v_del_filter) {
            return post_expand_under(w->bu, w->v_del_emit, path,
                                     NULL, w->del_unsorted, NULL);
        }
        if (verb == w->v_put_filter) {
            b8 any_base = NO;
            ok64 br = post_expand_under(w->bu, w->v_put_emit, path,
                                        NULL, w->put_unsorted, &any_base);
            if (br != OK) return br;
            if (any_base) return OK;
            return post_expand_under(w->wu, w->v_put_emit, path,
                                     w->ig, w->put_unsorted, NULL);
        }
        return OK;
    }

    //  File-level put/delete row → emit one ULOG line into the
    //  appropriate intent buffer.  Sort+dedup happens after the walk;
    //  the merge classifier then dispatches on `verb` to set
    //  the appropriate intent buffer for the merge.
    uri u = {};
    u.path[0] = path[0];
    u.path[1] = path[1];
    if (verb == w->v_put_filter) {
        ulogrec rec = {.ts = ts, .verb = w->v_put_emit, .uri = u};
        return ULOGu8sFeed(u8bIdle(w->put_unsorted), &rec);
    }
    if (verb == w->v_del_filter) {
        ulogrec rec = {.ts = ts, .verb = w->v_del_emit, .uri = u};
        return ULOGu8sFeed(u8bIdle(w->del_unsorted), &rec);
    }
    return OK;
}

//  Sort+dedup an unsorted ULOG intent buffer into `dst` (lex-by-path).
//  Uses HEAPu8csPopZ over a per-row slice array.  `dst` is reset.
static ok64 post_sort_dedup_intent(u8b src, u8b dst) {
    sane(src && dst);
    u8bReset(dst);
    if (u8bDataLen(src) == 0) done;

    //  Heap of one-line slices into `src`.  Cap is loose — `src` has
    //  no zero-length lines so divide by 16-byte minimum row.
    Bu8cs slices = {};
    size_t cap = u8bDataLen(src) / 16 + 16;
    call(u8csbAllocate, slices, cap);

    u8c *base = u8bDataHead(src);
    u8c *term = base + u8bDataLen(src);
    for (u8c *p = base; p < term; ) {
        u8c *line_start = p;
        while (p < term && *p != '\n') p++;
        if (p < term) p++;     // include the trailing '\n'
        u8cs slice = {line_start, p};
        ok64 fo = u8csbFeedP(slices, &slice);
        if (fo != OK) { u8csbFree(slices); return fo; }
    }

    //  Heap-sort via repeated pop.
    u8cssHeapZ(u8csbData(slices), ULOGu8csZbyUri);

    u8cs prev = {};
    b8   have_prev = NO;
    while (u8csbDataLen(slices) > 0) {
        u8cs cur = {};
        ok64 po = HEAPu8csPopZ(&cur, slices, ULOGu8csZbyUri);
        if (po != OK) break;

        //  Dedup: a == b under ULOGu8csZbyUri iff !(a<b) && !(b<a).
        if (have_prev &&
            !ULOGu8csZbyUri(&prev, &cur) &&
            !ULOGu8csZbyUri(&cur, &prev)) {
            continue;
        }
        a_dup(u8c, cur_dup, cur);
        ok64 fo = u8bFeed(dst, cur_dup);
        if (fo != OK) { u8csbFree(slices); return fo; }
        u8csMv(prev, cur);
        have_prev = YES;
    }

    u8csbFree(slices);
    done;
}

// --- Baseline tree resolution ---

//  Resolve the baseline URI to a tree sha (no walk — the merge below
//  consumes the tree via KEEPTreeListLeaves).  Sets c->has_base and
//  c->base_is_patch as a side-effect.
static ok64 post_resolve_baseline(post_ctx *c, sha1 *root_out, b8 *has_out) {
    sane(c && root_out && has_out);
    *has_out = NO;

    ron60 base_ts = 0, base_verb = 0;
    uri base_u = {};
    ok64 br = SNIFFAtBaseline(&base_ts, &base_verb, &base_u);
    if (br == ULOGNONE) done;  // fresh repo
    if (br != OK) return br;
    c->has_base      = YES;
    c->base_is_patch = (base_verb == SNIFFAtVerbPatch());

    //  Baseline query carries the version info (see dog/QURY): one
    //  branch REF plus 1-to-N SHAs.  For a squash-merge POST we only
    //  need the ours tree as the baseline — patched files are
    //  mtime-dirty (PATCH does not stamp), added files aren't in ours
    //  and fall into add via the implicit-dirty rule, and
    //  deleted files were unlinked by PATCH so they vanish via the
    //  implicit-drop rule.  So take the first SHA spec as "ours".
    u8 hex40[40];
    if (SNIFFAtQueryFirstSha(&base_u, hex40) != OK) done;

    sha1 commit_sha = {};
    a_raw(csha_bin, commit_sha);
    u8cs h40 = {hex40, hex40 + 40};
    HEXu8sDrainSome(csha_bin, h40);

    Bu8 cbuf = {};
    call(u8bAllocate, cbuf, 1UL << 24);
    u8 ctype = 0;
    ok64 go = KEEPGetExact(c->k, &commit_sha, cbuf, &ctype);
    if (go != OK || ctype != DOG_OBJ_COMMIT) {
        u8bFree(cbuf);
        done;
    }

    sha1 tree_sha = {};
    u8cs body = {u8bDataHead(cbuf), u8bIdleHead(cbuf)};
    ok64 to = GITu8sCommitTree(body, tree_sha.data);
    u8bFree(cbuf);
    if (to != OK) done;

    *root_out = tree_sha;
    *has_out = YES;
    done;
}

// --- Baseline ↔ wt classifier via N-way merge ---

//  Parse an octal-ASCII mode slice ("100644", "40000", …) into a u16.
static u16 post_parse_octal_mode(u8cs s) {
    u16 m = 0;
    for (u8c const *p = s[0]; p < s[1]; p++) {
        if (*p < '0' || *p > '7') return m;
        m = (u16)(m * 8 + (*p - '0'));
    }
    return m;
}

//  Per-step classification context for `post_classify_step`.
typedef struct {
    post_ctx *c;
    ron60     v_base;
    ron60     v_wt;
    ron60     v_put;
    ron60     v_del;
} post_classify_step_ctx;

//  SNIFFMergeWalk step callback.  Inspects the tie group (one record
//  per source verb) for one path, decides the fate, hashes the wt
//  file when the fate is `add`, and emits exactly one decision row
//  into c->decisions.
//
//  Verbs in the output stream: keep / unlink / add (see post_emit_*).
static ok64 post_classify_step(ulogreccp recs, u32 n, void *vctx) {
    post_classify_step_ctx *cctx = (post_classify_step_ctx *)vctx;
    post_ctx *c = cctx->c;

    u8cs path = {recs[0].uri.path[0], recs[0].uri.path[1]};
    if ($empty(path)) return OK;

    //  Inspect sources contributing to this path.
    ulogreccp src_base = NULL, src_wt = NULL;
    b8 has_put = NO, has_del = NO;
    for (u32 i = 0; i < n; i++) {
        ulogreccp m = &recs[i];
        if      (m->verb == cctx->v_base) src_base = m;
        else if (m->verb == cctx->v_wt)   src_wt   = m;
        else if (m->verb == cctx->v_put)  has_put  = YES;
        else if (m->verb == cctx->v_del)  has_del  = YES;
    }

    //  Pull baseline mode + sha (when present).
    u16 base_mode = 0;
    sha1 base_sha = {};
    if (src_base) {
        u8cs ms = {src_base->uri.query[0], src_base->uri.query[1]};
        base_mode = post_parse_octal_mode(ms);
        u8s bin_s = {base_sha.data, base_sha.data + 20};
        a_dup(u8c, frag_dup, src_base->uri.fragment);
        HEXu8sDrainSome(bin_s, frag_dup);
    }
    //  Pull wt mode (when on disk).
    u16 wt_mode = 0;
    if (src_wt) {
        u8cs ms = {src_wt->uri.query[0], src_wt->uri.query[1]};
        wt_mode = post_parse_octal_mode(ms);
    }

    //  --- Decision ladder (mirrors the old post_decide) ---

    //  Gitlink: carry through verbatim — no on-disk file expected.
    if (base_mode == 0160000) {
        return post_emit_decision(c, c->v_keep, path, base_mode,
                                  NULL, &base_sha);
    }

    //  Explicit delete row: drop unconditionally.  Unlink iff the
    //  path was tracked or currently exists on disk.
    if (has_del) {
        if (src_base || src_wt) {
            return post_emit_decision(c, c->v_unlink, path,
                                      0, NULL, NULL);
        }
        return OK;
    }

    //  Explicit put row.
    if (has_put) {
        if (!src_wt) {
            //  Explicit put of a missing file: drop, unlink if tracked.
            if (src_base) {
                return post_emit_decision(c, c->v_unlink, path,
                                          0, NULL, NULL);
            }
            return OK;
        }
        sha1 new_sha = {};
        if (post_hash_path(c->reporoot, path, wt_mode, &new_sha) != OK)
            return OK;
        sha1 const *old = src_base ? &base_sha : NULL;
        return post_emit_decision(c, c->v_add, path, wt_mode,
                                  old, &new_sha);
    }

    //  No explicit rule.  Branches by (in baseline?) × (on disk?).

    //  Missing from wt.
    if (!src_wt) {
        //  Gitignored baseline files: keep verbatim — we don't see
        //  them on disk because SNIFFWtULog filters via SNIFFSkipMeta.
        if (src_base && SNIFFSkipMeta(path)) {
            return post_emit_decision(c, c->v_keep, path, base_mode,
                                      NULL, &base_sha);
        }
        if (c->any_pd) {
            //  Selective mode: keep baseline entries unchanged.
            if (src_base) {
                return post_emit_decision(c, c->v_keep, path, base_mode,
                                          NULL, &base_sha);
            }
            return OK;
        }
        //  Implicit mode: missing tracked file is a deletion.
        if (src_base) {
            return post_emit_decision(c, c->v_unlink, path,
                                      0, NULL, NULL);
        }
        return OK;
    }

    //  On disk, no explicit rule.  Untracked + selective = ignore.
    if (!src_base && c->any_pd) return OK;

    a_path(fp);
    if (SNIFFFullpath(fp, c->reporoot, path) != OK) return OK;
    struct stat sb = {};
    if (lstat((char const *)u8bDataHead(fp), &sb) != 0) {
        if (src_base) {
            return post_emit_decision(c, c->v_unlink, path,
                                      0, NULL, NULL);
        }
        return OK;
    }
    struct timespec ts = {.tv_sec  = sb.st_mtim.tv_sec,
                          .tv_nsec = sb.st_mtim.tv_nsec};
    ron60 mtime_r = SNIFFAtOfTimespec(ts);

    if (SNIFFAtKnown(mtime_r)) {
        //  Per-file stamp lookup: who owns this mtime?
        //    get/post → KEEP (baseline-clean)
        //    patch/put/mod → REWRITE (current bytes; patch row's
        //                    `theirs` joins parents via patch_parents)
        ron60 ow_verb = 0;
        uri ow_u = {};
        ok64 lo = SNIFFAtRowAtTs(mtime_r, &ow_verb, &ow_u);
        if (lo == OK) {
            ron60 vg = SNIFFAtVerbGet();
            ron60 vp = SNIFFAtVerbPost();
            if (ow_verb == vg || ow_verb == vp) {
                if (src_base) {
                    return post_emit_decision(c, c->v_keep, path,
                                              base_mode, NULL,
                                              &base_sha);
                }
                return OK;  // untracked clean — shouldn't happen
            }
            //  patch / put / mod stamp owns this mtime → add.
            sha1 new_sha = {};
            if (post_hash_path(c->reporoot, path, wt_mode, &new_sha) != OK)
                return OK;
            sha1 const *old = src_base ? &base_sha : NULL;
            return post_emit_decision(c, c->v_add, path, wt_mode,
                                      old, &new_sha);
        }
        //  ts known but row not found (corrupt log?) — fallback keep.
        if (src_base) {
            return post_emit_decision(c, c->v_keep, path, base_mode,
                                      NULL, &base_sha);
        }
        return OK;
    }

    //  mtime unknown.
    if (src_base) {
        //  Tracked + dirty.  In selective mode (any explicit put/delete
        //  in scope) we ignore — only files named by a put row land in
        //  the commit, plus deletes drop their targets.  Implicit mode
        //  (commit-all): hash and rewrite.
        if (c->any_pd) {
            return post_emit_decision(c, c->v_keep, path, base_mode,
                                      NULL, &base_sha);
        }
        sha1 disk_sha = {};
        if (post_hash_path(c->reporoot, path, wt_mode, &disk_sha) != OK)
            return OK;
        if (sha1eq(&disk_sha, &base_sha)) {
            //  Identical → KEEP (mtime drifted but bytes match).
            return post_emit_decision(c, c->v_keep, path, base_mode,
                                      NULL, &base_sha);
        }
        return post_emit_decision(c, c->v_add, path, wt_mode,
                                  &base_sha, &disk_sha);
    }
    if (!c->has_base) {
        //  Fresh-repo first commit: auto-stage every dirty file.
        sha1 new_sha = {};
        if (post_hash_path(c->reporoot, path, wt_mode, &new_sha) != OK)
            return OK;
        return post_emit_decision(c, c->v_add, path, wt_mode,
                                  NULL, &new_sha);
    }
    //  Untracked + dirty + has-base → ignore in implicit mode.
    return OK;
}

//  Drive `flag[idx]` / `rec[idx]` population from a 4-way ULOG-row
//  merge over (baseline tree, wt, sorted ULOG put intents, sorted ULOG
//  delete intents).  All four buffers are caller-owned — `bu` and `wu`
//  are also reused by `post_pd_cb` for dir-prefix expansion.  Each
//  input carries a distinct verb so the step callback can dispatch
//  per record.
static ok64 post_classify_via_merge(post_ctx *c,
                                    u8b bu, u8b wu,
                                    u8b put_buf, u8b del_buf,
                                    ron60 v_base, ron60 v_wt,
                                    ron60 v_put,  ron60 v_del) {
    sane(c);

    //  Heap-walk all 4 cursors; dispatch per row in `post_classify_step`.
    a_dup(u8c, view_b, u8bData(bu));
    a_dup(u8c, view_w, u8bData(wu));
    a_dup(u8c, view_p, u8bData(put_buf));
    a_dup(u8c, view_d, u8bData(del_buf));
    a_pad(u8cs, ins, 4);
    u8cssFeed1(ins_idle, view_b);
    u8cssFeed1(ins_idle, view_w);
    u8cssFeed1(ins_idle, view_p);
    u8cssFeed1(ins_idle, view_d);
    a_dup(u8cs, cursors, u8csbData(ins));

    post_classify_step_ctx cctx = {
        .c = c, .v_base = v_base, .v_wt = v_wt,
        .v_put = v_put, .v_del = v_del,
    };
    return SNIFFMergeWalk(cursors, post_classify_step, &cctx);
}

// --- Tree building (bottom-up from sorted paths) ---

//  Per-leaf row consumed by post_build_tree.  Built once from the
//  decisions buffer (filtered to keep+add) and walked by lo/hi range.
typedef struct {
    u8cs path;     // slice into ctx.decisions (mmap-stable until POST exit)
    u16  mode;
    sha1 sha;
} post_leaf;

typedef struct {
    u32    lo, hi;    // sorted-index range
    u8cs   prefix;    // directory prefix these entries live under (with trailing '/')
} tree_range;

//  Inline accessors over a Bu8 of post_leaf records.
fun post_leaf *post_leaves_head(u8b leaves) {
    return (post_leaf *)u8bDataHead(leaves);
}
fun u32 post_leaves_count(u8b leaves) {
    return (u32)(u8bDataLen(leaves) / sizeof(post_leaf));
}
fun post_leaf *post_leaves_at(u8b leaves, u32 i) {
    return post_leaves_head(leaves) + i;
}

//  Parse octal mode bytes from an `add`/`keep` decision row's
//  uri.query.  Stops at the optional `&<old_sha>` chain.
static u16 post_decision_mode(uricp u) {
    u8cs s = {u->query[0], u->query[1]};
    //  Truncate at first '&' if present.
    for (u8c const *p = s[0]; p < s[1]; p++) {
        if (*p == '&') { s[1] = p; break; }
    }
    return post_parse_octal_mode(s);
}

//  Decode the optional `&<40-hex>` old-sha chain in an add row's
//  uri.query.  Returns YES + fills *out on success; NO if absent.
static b8 post_decision_old_sha(uricp u, sha1 *out) {
    if (!u || !out) return NO;
    u8cs s = {u->query[0], u->query[1]};
    u8c const *amp = NULL;
    for (u8c const *p = s[0]; p < s[1]; p++) {
        if (*p == '&') { amp = p; break; }
    }
    if (!amp) return NO;
    u8cs hex = {amp + 1, s[1]};
    if (u8csLen(hex) != 40) return NO;
    u8s bin = {out->data, out->data + 20};
    a_dup(u8c, hex_dup, hex);
    return HEXu8sDrainSome(bin, hex_dup) == OK;
}

//  Build the leaf array from the decisions buffer (keep + add only,
//  skipping unlinks).  Decisions are emitted in lex order, so the
//  resulting array is already sorted by path.
static ok64 post_build_leaves(post_ctx *c, u8b leaves) {
    sane(c && leaves);
    u8bReset(leaves);
    a_dup(u8c, scan, u8bData(c->decisions));
    while (!u8csEmpty(scan)) {
        ulogrec rec = {};
        ok64 dr = ULOGu8sDrain(scan, &rec);
        if (dr == NODATA) break;
        if (dr != OK) continue;
        if (rec.verb != c->v_keep && rec.verb != c->v_add) continue;

        post_leaf leaf = {};
        leaf.path[0] = rec.uri.path[0];
        leaf.path[1] = rec.uri.path[1];
        leaf.mode    = post_decision_mode(&rec.uri);
        if (u8csLen(rec.uri.fragment) == 40) {
            u8s bin_s = {leaf.sha.data, leaf.sha.data + 20};
            a_dup(u8c, frag_dup, rec.uri.fragment);
            HEXu8sDrainSome(bin_s, frag_dup);
        }
        a_dup(u8c, leaf_view,
              ((u8cs){(u8c *)&leaf, (u8c *)&leaf + sizeof(leaf)}));
        ok64 fo = u8bFeed(leaves, leaf_view);
        if (fo != OK) return fo;
    }
    done;
}

//  Locate the end of the range whose sorted paths all start with
//  `prefix` (exclusive).  Caller guarantees [lo..hi) is sorted.
static u32 post_range_end(u8b leaves, u32 lo, u32 hi, u8cs prefix) {
    u32 end = lo;
    while (end < hi) {
        post_leaf *l = post_leaves_at(leaves, end);
        size_t plen = $len(prefix);
        if ($len(l->path) < plen) break;
        if (memcmp(l->path[0], prefix[0], plen) != 0) break;
        end++;
    }
    return end;
}

static ok64 post_build_tree(u8b leaves, u32 lo, u32 hi, u8cs prefix,
                            sha1 *tree_out, Bu8 tree_body_list,
                            u32 *emit_count) {
    //  Recursively build a tree for paths in [lo, hi) under `prefix`.
    //  Emits serialized tree body bytes (prefixed by u32 length) into
    //  `tree_body_list`.  The caller replays the list later to feed
    //  keeper in the pack's expected commit→trees→blobs order.
    sane(leaves && tree_out);

    Bu8 tree = {};
    call(u8bAllocate, tree, (u64)(hi - lo) * 80);

    u32 i = lo;
    while (i < hi) {
        post_leaf *l = post_leaves_at(leaves, i);
        u8cs rel = {l->path[0], l->path[1]};

        size_t plen = $len(prefix);
        if ($len(rel) <= plen) { i++; continue; }
        u8cs rest = {$atp(rel, plen), rel[1]};
        if ($empty(rest)) { i++; continue; }

        //  Find first '/' in rest to distinguish direct-child files
        //  from entries in deeper subtrees.
        u8c const *slash = NULL;
        {
            a_dup(u8c, scan, rest);
            if (u8csFind(scan, '/') == OK) slash = scan[0];
        }

        if (slash) {
            //  Sub-directory of this tree: recurse over children.
            u8cs dirname = {rest[0], slash};
            a_pad(u8, subprefix, 2048);
            u8bFeed(subprefix, prefix);
            u8bFeed(subprefix, dirname);
            u8bFeed1(subprefix, '/');
            u8cs sub = {u8bDataHead(subprefix), subprefix[2]};

            u32 sub_hi = post_range_end(leaves, i, hi, sub);

            sha1 sub_sha = {};
            ok64 so = post_build_tree(leaves, i, sub_hi, sub, &sub_sha,
                                      tree_body_list, emit_count);
            if (so != OK) { u8bFree(tree); return so; }

            if (!sha1empty(&sub_sha)) {
                post_mode_feed(tree, 040000);
                u8bFeed1(tree, ' ');
                u8bFeed(tree, dirname);
                u8bFeed1(tree, 0);
                a_rawc(sr, sub_sha);
                u8bFeed(tree, sr);
            }
            i = sub_hi;
            continue;
        }

        //  Direct-child file entry.  Leaves filtered to keep+add at
        //  build_leaves time, so every record here is tree-bound.
        sha1 entry_sha = l->sha;
        if (sha1empty(&entry_sha)) { i++; continue; }

        u16 mode = l->mode;
        if (mode == 0) mode = 0100644;

        post_mode_feed(tree, mode);
        u8bFeed1(tree, ' ');
        u8bFeed(tree, rest);
        u8bFeed1(tree, 0);
        a_rawc(er, entry_sha);
        u8bFeed(tree, er);
        i++;
    }

    if (u8bDataLen(tree) == 0) {
        memset(tree_out, 0, sizeof(*tree_out));
        u8bFree(tree);
        done;
    }

    KEEPObjSha(tree_out, DOG_OBJ_TREE, u8bDataC(tree));

    //  Record (len u32, body bytes) in tree_body_list; the feeder
    //  loop in POSTCommit parses them back out to hand to keeper.
    u32 tlen = (u32)u8bDataLen(tree);
    u8cs tl = {(u8cp)&tlen, (u8cp)&tlen + sizeof(u32)};
    u8bFeed(tree_body_list, tl);
    u8bFeed(tree_body_list, u8bDataC(tree));
    (*emit_count)++;

    u8bFree(tree);
    done;
}

// --- Empty-tree feed (handles "no files to commit" case) ---

static ok64 post_feed_empty_tree(keeper *k, keep_pack *p, sha1 *out) {
    u8cs empty = {};
    return KEEPPackFeed(k, p, DOG_OBJ_TREE, empty, 0, out);
}

// --- Resolve parent commit sha for the commit body ---

static ok64 post_parent_sha(keeper *k, u8cs parent_hex, sha1 *out) {
    sane(out && $ok(parent_hex));
    if ($len(parent_hex) != 40) fail(SNIFFFAIL);

    a_raw(bin, *out);
    HEXu8sDrainSome(bin, parent_hex);
    //  Verify the commit actually lives in keeper (sanity check).
    Bu8 tmp = {};
    call(u8bAllocate, tmp, 1UL << 20);
    u8 ctype = 0;
    ok64 go = KEEPGetExact(k, out, tmp, &ctype);
    u8bFree(tmp);
    if (go != OK || ctype != DOG_OBJ_COMMIT) fail(SNIFFFAIL);
    done;
}

// --- Baseline branch query (from ULOG) ---

//  Read the latest baseline (`get`/`post`/`patch`) row.  Fills `out`
//  with the be-branch path (row's query), and `*parent_out` with the
//  current commit's sha (row's `#fragment`).  `*had_baseline_out` is
//  YES iff a baseline row exists.
//
//  Single-parent everywhere on the write path: after the PATCH rewrite
//  the baseline query no longer chains `&<theirs>` SHAs; one ours sha
//  is the only parent the new commit gets.
static ok64 post_collect_parents(u8bp out, sha1 *parent_out, b8 *has_parent_out,
                                 b8 *had_baseline_out) {
    sane(out && parent_out && has_parent_out && had_baseline_out);
    u8bReset(out);
    *has_parent_out = NO;
    *had_baseline_out = NO;
    ron60 ts = 0, verb = 0;
    uri u = {};
    ok64 r = SNIFFAtBaseline(&ts, &verb, &u);
    if (r == ULOGNONE) done;        // fresh repo — root commit allowed
    if (r != OK) return r;
    *had_baseline_out = YES;

    //  Current commit (`ours`) lives in the row's `#fragment` (canonical
    //  form); legacy rows kept it in the query, which `SNIFFAtQueryFirstSha`
    //  handles transparently.
    {
        u8 hex40[40];
        if (SNIFFAtQueryFirstSha(&u, hex40) == OK) {
            sha1 ph = {};
            u8s bin = {ph.data, ph.data + 20};
            u8cs hx = {hex40, hex40 + 40};
            if (HEXu8sDrainSome(bin, hx) == OK && bin[0] == ph.data + 20) {
                *parent_out = ph;
                *has_parent_out = YES;
            }
        }
    }

    //  Walk the query for the branch (first QURY_REF).  Single-parent
    //  invariant: any extra SHAs in the query are legacy artefacts from
    //  pre-rewrite PATCH rows; they're ignored.
    a_dup(u8c, q, u.query);
    while (!$empty(q)) {
        qref spec = {};
        if (QURYu8sDrain(q, &spec) != OK) break;
        if (spec.type == QURY_NONE) {
            if ($empty(q)) break;
            continue;
        }
        if (spec.type == QURY_REF && u8bDataLen(out) == 0) {
            u8bFeed(out, spec.body);
            break;
        }
    }
    done;
}

//  Single-parent invariant: the multi-parent injection helpers
//  `post_patch_theirs` / `post_add_patch_parents` were removed when
//  PATCH stopped chaining `&<theirs>` onto baseline.  See VERBS.md
//  §POST: parents = [ours] only on the write path.

// --- Shared scan: produce the change-set into a post_ctx ---
//
//  Steps 2..5 of POSTCommit, lifted so a dry-run print path can run
//  the same scan without committing.  Caller pre-fills `c->reporoot`,
//  `c->k`, `c->cap`, `c->rec`, `c->flag`, `c->last_post_ts`; this
//  function drives the baseline walk + put/delete scan + wt scan +
//  dir-row expansion + per-path decide.  On return, `c->flag[idx]`
//  carries the keep/unlink/add decision per path in `c->decisions`,
//  and `*base_tree_sha` / `*have_base` reflect the baseline tree (if
//  any) so the caller can reuse them for tree-build.
static ok64 post_scan_changeset(post_ctx *c, sha1 *base_tree_sha,
                                b8 *have_base) {
    sane(c && base_tree_sha && have_base);

    //  2. Resolve baseline URI → tree sha (no walk yet).
    call(post_resolve_baseline, c, base_tree_sha, have_base);

    //  3. Build the baseline + wt ULOG row buffers up-front.  Both are
    //     reused by post_pd_cb (dir-prefix expansion) and the merge
    //     classifier; sharing avoids two scans of the same trees.
    a_cstr(s_basev, "base"); a_dup(u8c, dbv, s_basev);
    a_cstr(s_wtv,   "wt");   a_dup(u8c, dwv, s_wtv);
    a_cstr(s_putv,  "put");  a_dup(u8c, dpv, s_putv);
    a_cstr(s_delv,  "del");  a_dup(u8c, ddv, s_delv);
    ron60 v_base = 0, v_wt = 0, v_put_emit = 0, v_del_emit = 0;
    call(RONutf8sDrain, &v_base,     dbv);
    call(RONutf8sDrain, &v_wt,       dwv);
    call(RONutf8sDrain, &v_put_emit, dpv);
    call(RONutf8sDrain, &v_del_emit, ddv);

    Bu8 bu = {}, wu = {};
    Bu8 put_unsorted = {}, del_unsorted = {};
    Bu8 put_buf = {}, del_buf = {};
    call(u8bAllocate, bu,           1UL << 20);
    call(u8bAllocate, wu,           1UL << 20);
    call(u8bAllocate, put_unsorted, 1UL << 16);
    call(u8bAllocate, del_unsorted, 1UL << 16);
    call(u8bAllocate, put_buf,      1UL << 16);
    call(u8bAllocate, del_buf,      1UL << 16);

#define PD_FREE_ALL()                                  \
    do {                                                \
        u8bFree(bu); u8bFree(wu);                       \
        u8bFree(put_unsorted); u8bFree(del_unsorted);   \
        u8bFree(put_buf); u8bFree(del_buf);             \
    } while (0)

    if (*have_base) {
        ok64 br = KEEPTreeULog(c->k, base_tree_sha->data, 0, v_base, bu);
        if (br != OK) { PD_FREE_ALL(); return br; }
    }
    {
        ok64 wr = SNIFFWtULog(c->reporoot, v_wt, wu);
        if (wr != OK) { PD_FREE_ALL(); return wr; }
    }

    //  4. Put/delete scan since last post.  File-level rows go into
    //     the unsorted intent buffers; dir-prefix rows are expanded
    //     in-line against bu / wu via post_expand_under.
    pd_walk_ctx walk = {
        .c = c,
        .put_unsorted = put_unsorted,
        .del_unsorted = del_unsorted,
        .bu           = bu,
        .wu           = wu,
        .ig           = &SNIFF.ignores,
        .v_put_filter = SNIFFAtVerbPut(),
        .v_del_filter = SNIFFAtVerbDelete(),
        .v_put_emit   = v_put_emit,
        .v_del_emit   = v_del_emit,
    };
    {
        ok64 sr = SNIFFAtScanPutDelete(c->last_post_ts, post_pd_cb, &walk);
        if (sr != OK) { PD_FREE_ALL(); return sr; }
    }
    {
        ok64 ps = post_sort_dedup_intent(put_unsorted, put_buf);
        ok64 ds = ps == OK
                ? post_sort_dedup_intent(del_unsorted, del_buf)
                : OK;
        u8bFree(put_unsorted); u8bFree(del_unsorted);
        if (ps != OK) {
            u8bFree(bu); u8bFree(wu);
            u8bFree(put_buf); u8bFree(del_buf);
            return ps;
        }
        if (ds != OK) {
            u8bFree(bu); u8bFree(wu);
            u8bFree(put_buf); u8bFree(del_buf);
            return ds;
        }
    }

    //  5. Classify baseline + wt + put/del intents via 4-way merge,
    //     emitting one keep/unlink/add decision row per distinct path
    //     into ctx.decisions.
    ok64 cr = post_classify_via_merge(c, bu, wu, put_buf, del_buf,
                                      v_base, v_wt, v_put_emit, v_del_emit);
    u8bFree(bu); u8bFree(wu);
    u8bFree(put_buf); u8bFree(del_buf);
    if (cr != OK) return cr;
#undef PD_FREE_ALL

    //  classify_step inlined the per-path decide+resolve+hash and
    //  emitted one decision row per distinct path.  Downstream
    //  consumers drain c->decisions.
    done;
}

//  Initialise the post_ctx for a scan.  Allocates the path arena and
//  the dense recs buffer; both grow with `u8bFeed`.
static ok64 post_ctx_init(post_ctx *c, u8cs reporoot, keeper *k) {
    sane(c);
    *c = (post_ctx){
        .k = k,
        .last_post_ts = SNIFFAtLastPostTs(),
    };
    c->reporoot[0] = reporoot[0];
    c->reporoot[1] = reporoot[1];

    //  Decisions buffer holds the full per-commit ULOG-row stream.
    call(u8bAllocate, c->decisions, POST_TREE_ULOG_MAX);

    //  Decision verbs (cached ron60).
    a_cstr(s_keep,   "keep");   a_dup(u8c, dk, s_keep);
    a_cstr(s_unlink, "unlink"); a_dup(u8c, du, s_unlink);
    a_cstr(s_add,    "add");    a_dup(u8c, da, s_add);
    call(RONutf8sDrain, &c->v_keep,   dk);
    call(RONutf8sDrain, &c->v_unlink, du);
    call(RONutf8sDrain, &c->v_add,    da);

    //  Single per-commit stamp ts; carried in every decision row.
    struct timespec _tv = {};
    SNIFFAtNow(&c->stamp_ts, &_tv);
    done;
}

//  Emit one decision ULOG row into c->decisions.
//
//  Row shape (all variants):     <ts>\t<verb>\t<path>?<query>#<fragment>\n
//
//    keep    : query = <mode>,                 fragment = <old_sha>
//    add     : query = <mode>[&<old_sha>],     fragment = <new_sha>
//              (the optional &<old_sha> chain is present iff the path
//              had a baseline entry — distinguishing "M" from "A".)
//    unlink  : query empty, fragment empty.
static ok64 post_emit_decision(post_ctx *c, ron60 verb,
                               u8cs path, u16 mode,
                               sha1 const *old_sha, sha1 const *frag_sha) {
    sane(c && verb);

    //  Mode bytes (octal ASCII) into the query, optionally chained with
    //  &<old_sha_hex> for modified add.
    a_pad(u8, query_buf, 256);
    if (mode != 0) {
        char tmp[8];
        int n = snprintf(tmp, sizeof(tmp), "%o", (unsigned)mode);
        u8cs ms = {(u8cp)tmp, (u8cp)tmp + n};
        u8bFeed(query_buf, ms);
    }
    if (old_sha && !sha1empty(old_sha)) {
        u8bFeed1(query_buf, '&');
        a_rawc(bin, *old_sha);
        HEXu8sFeedSome(u8bIdle(query_buf), bin);
    }

    a_pad(u8, hex_buf, 40);
    if (frag_sha && !sha1empty(frag_sha)) {
        a_rawc(bin, *frag_sha);
        HEXu8sFeedSome(hex_buf_idle, bin);
    }

    uri u = {};
    u.path[0] = path[0]; u.path[1] = path[1];
    if (u8bDataLen(query_buf) > 0) {
        u.query[0] = u8bDataHead(query_buf);
        u.query[1] = u8bIdleHead(query_buf);
    }
    if (u8bDataLen(hex_buf) > 0) {
        u.fragment[0] = u8bDataHead(hex_buf);
        u.fragment[1] = u8bIdleHead(hex_buf);
    }

    ulogrec rec = {.ts = c->stamp_ts, .verb = verb, .uri = u};
    return ULOGu8sFeed(u8bIdle(c->decisions), &rec);
}

//  Iterate the decisions buffer, invoking `cb` for every row whose
//  verb is in `verb_mask` (bitmask: 1=keep, 2=unlink, 4=add).  cb sees
//  the parsed ulogrec and can pull path/mode/sha from rec->uri.
//  Verb-mask bits for `post_walk_decisions`.
#define POST_VM_KEEP   1u
#define POST_VM_UNLINK 2u
#define POST_VM_ADD    4u
#define POST_VM_ALL    (POST_VM_KEEP | POST_VM_UNLINK | POST_VM_ADD)

typedef ok64 (*post_decision_cb)(post_ctx *c, ulogreccp rec, void *ctx);
static ok64 post_walk_decisions(post_ctx *c, u32 verb_mask,
                                post_decision_cb cb, void *cbctx) {
    sane(c && cb);
    a_dup(u8c, scan, u8bData(c->decisions));
    while (!u8csEmpty(scan)) {
        ulogrec rec = {};
        ok64 dr = ULOGu8sDrain(scan, &rec);
        if (dr == NODATA) break;
        if (dr != OK) continue;
        u32 bit = 0;
        if      (rec.verb == c->v_keep)   bit = POST_VM_KEEP;
        else if (rec.verb == c->v_unlink) bit = POST_VM_UNLINK;
        else if (rec.verb == c->v_add)    bit = POST_VM_ADD;
        if (!(verb_mask & bit)) continue;
        ok64 cr = cb(c, &rec, cbctx);
        if (cr != OK) return cr;
    }
    done;
}

// --- Decision-walk callbacks for the simple per-row loops ---

//  Unlink the wt file.  Errors swallowed — best-effort.
static ok64 post_drain_unlink_cb(post_ctx *c, ulogreccp rec, void *vctx) {
    (void)vctx;
    u8cs path = {rec->uri.path[0], rec->uri.path[1]};
    a_path(fp);
    if (SNIFFFullpath(fp, c->reporoot, path) != OK) return OK;
    (void)FILEUnLink($path(fp));
    return OK;
}

//  Stamp the wt file with the post ts (only `add` rows reach here).
static ok64 post_drain_stamp_cb(post_ctx *c, ulogreccp rec, void *vctx) {
    (void)vctx;
    u8cs path = {rec->uri.path[0], rec->uri.path[1]};
    a_path(fp);
    if (SNIFFFullpath(fp, c->reporoot, path) != OK) return OK;
    (void)SNIFFAtStampPath(fp, rec->ts);
    return OK;
}

//  M/A/D printer.  ctx is FILE* (stdout for dry run, stderr for commit
//  with optional grey ANSI on/off pair).
typedef struct {
    FILE       *out;
    char const *on;
    char const *off;
    u32         changed;
} post_mad_ctx;

static ok64 post_drain_mad_cb(post_ctx *c, ulogreccp rec, void *vctx) {
    post_mad_ctx *m = (post_mad_ctx *)vctx;
    char code = 0;
    if (rec->verb == c->v_unlink)   code = 'D';
    else if (rec->verb == c->v_add) {
        sha1 old = {};
        code = post_decision_old_sha(&rec->uri, &old) ? 'M' : 'A';
    }
    if (code == 0) return OK;
    fprintf(m->out, "%s%c %.*s%s\n",
            m->on, code, (int)u8csLen(rec->uri.path),
            (char *)rec->uri.path[0], m->off);
    m->changed++;
    return OK;
}

//  Free everything post_ctx_init allocated.
static void post_ctx_free(post_ctx *c) {
    if (!c) return;
    u8bFree(c->decisions);
}

// --- Rebase emit pipeline (Stage 2 phase-2 promote) ---
//
//  When POSTCommit detects a non-ff against the same branch (REFS tip
//  diverges from cur's parent), it builds the new commit normally and
//  then replays it onto the live REFS tip via GRAFRebase.  The rebase
//  callback funnels every emitted (type, sha, body) tuple straight into
//  the active keeper pack so persistence is automatic.  The last commit
//  emit's sha becomes the new tip.
//
//  Atomicity: rebase runs after the first KEEPPackClose, in a second
//  pack opened just for the replay.  GRAFCNFL aborts mid-emit; the
//  caller closes the partial pack (orphan objects are harmless — they
//  are not referenced by REFS) and surfaces GRAFCNFL.  Cascade rebase
//  for descendants is not yet wired; see TODO(spec) at the call site.

typedef struct {
    keeper    *k;
    keep_pack *p;
    sha1       last_commit_sha;   //  most recent emitted commit
    b8         have_last_commit;
} post_rebase_ctx;

static ok64 post_rebase_emit_cb(void *vctx, u8 obj_type,
                                sha1 const *sha, u8csc body) {
    sane(vctx && sha);
    post_rebase_ctx *rc = (post_rebase_ctx *)vctx;
    sha1 fed = {};
    ok64 fo = KEEPPackFeed(rc->k, rc->p, obj_type, body, 0, &fed);
    if (fo != OK) return fo;
    //  Record the last commit sha — that's our rebased tip.
    if (obj_type == DOG_OBJ_COMMIT) {
        rc->last_commit_sha = *sha;
        rc->have_last_commit = YES;
    }
    return OK;
}

// --- Cascade rebase (Stage 2c) ---
//
//  When phase-2 rewrites a branch's stack (rebase, not ff), every
//  descendant branch that forked off the rewritten tip needs its own
//  stack replayed onto the new tip.  The cascade walker enumerates
//  direct subdirs of `<store>/<branch>/` with a `refs` file and runs
//  GRAFRebase on each, depth-first.  All emits land in the open pack
//  passed by the caller; descendants' new tips are committed via
//  REFSCompareAndAppend top-down.
//
//  Atomicity: this walker stages everything in the pack first; the
//  REFS writes happen after.  On GRAFCNFL we surface the error and
//  leave orphan objects in the pack (REFS unchanged ⇒ unreachable).
//  REFS persistence is best-effort: a CAS race mid-cascade leaves
//  earlier descendants advanced — documented as a known limitation.

//  Resolve a branch's REFS tip (`?<branch>`) to a 20-byte sha.  Returns
//  REFSNONE when no row exists, OK when a tip is present and decoded.
static ok64 post_resolve_branch_tip(sha1 *out, u8cs reporoot, u8cs branch) {
    sane(out);
    a_path(keepdir, reporoot, KEEP_DIR_S);
    a_pad(u8, keybuf, 256);
    u8bFeed1(keybuf, '?');
    if (!u8csEmpty(branch)) u8bFeed(keybuf, branch);
    a_dup(u8c, refkey, u8bData(keybuf));

    a_pad(u8, arena, 1024);
    uri resolved = {};
    ok64 ro = REFSResolve(&resolved, arena, $path(keepdir), refkey);
    if (ro != OK) return ro;
    if ($empty(resolved.query)) return REFSNONE;
    u8cs tip_hex = {resolved.query[0], resolved.query[1]};
    if (!u8csEmpty(tip_hex) && *tip_hex[0] == '?') u8csUsed(tip_hex, 1);
    if ($len(tip_hex) != 40) return REFSBAD;
    u8s bin = {out->data, out->data + 20};
    a_dup(u8c, hx, tip_hex);
    return HEXu8sDrainSome(bin, hx);
}

//  Cascade record: one descendant branch awaiting its REFS write.
typedef struct {
    u8  branch_buf[256];     // canonical absolute path
    u32 branch_len;
    sha1 old_tip;
    sha1 new_tip;
} cascade_rec;

#define CASCADE_MAX 64

typedef struct {
    keeper      *k;
    keep_pack   *p;
    u8cs         reporoot;
    cascade_rec  recs[CASCADE_MAX];
    u32          n;
    ok64         err;
    //  Optional: branch path to skip during the walk (cross-branch
    //  promote uses this so cur is not double-rebased — auto-sync
    //  handles cur directly).  NULL/empty disables the filter.
    u8cs         skip;
} cascade_ctx;

//  Stage one descendant: compute its old fork point relative to the
//  parent's old tip, run GRAFRebase onto the parent's new tip, capture
//  new tip into recs[].  Returns OK on success or a GRAFCNFL/error.
static ok64 post_cascade_one(cascade_ctx *cc, u8cs branch,
                             sha1 const *parent_old_tip,
                             sha1 const *parent_new_tip) {
    sane(cc);
    if (cc->n >= CASCADE_MAX) return SNIFFFAIL;

    sha1 child_tip = {};
    ok64 cr = post_resolve_branch_tip(&child_tip, cc->reporoot, branch);
    if (cr == REFSNONE) return OK;     //  branch has no REFS tip — skip
    if (cr != OK) return cr;

    //  Old fork point = LCA(parent_old_tip, child_tip).
    sha1 fork_old = {};
    (void)GRAFLca(&fork_old, parent_old_tip, &child_tip);

    //  If the child's tip is already an ancestor of parent_new_tip,
    //  there is nothing to replay.  Detect: LCA(child_tip,
    //  parent_new_tip) == child_tip.
    {
        sha1 lca2 = {};
        (void)GRAFLca(&lca2, &child_tip, parent_new_tip);
        if (sha1eq(&lca2, &child_tip)) {
            //  Child is already on new spine — point its REFS at the
            //  matching commit (child_tip itself).  No rebase needed.
            cascade_rec *r = &cc->recs[cc->n++];
            size_t bl = u8csLen(branch);
            if (bl > sizeof(r->branch_buf)) return SNIFFFAIL;
            memcpy(r->branch_buf, branch[0], bl);
            r->branch_len = (u32)bl;
            r->old_tip = child_tip;
            r->new_tip = child_tip;
            return OK;
        }
    }

    post_rebase_ctx rctx = {.k = cc->k, .p = cc->p};
    ok64 rb = GRAFRebase(&fork_old, parent_new_tip, &child_tip,
                         post_rebase_emit_cb, &rctx);
    if (rb != OK) return rb;

    cascade_rec *r = &cc->recs[cc->n++];
    size_t bl = u8csLen(branch);
    if (bl > sizeof(r->branch_buf)) return SNIFFFAIL;
    memcpy(r->branch_buf, branch[0], bl);
    r->branch_len = (u32)bl;
    r->old_tip = child_tip;
    r->new_tip = rctx.have_last_commit ? rctx.last_commit_sha
                                       : *parent_new_tip;
    return OK;
}

//  Recursive walker.  For each subdir of `<store>/<branch>/` that has
//  a `refs` file, stage its rebase, then recurse with the child as the
//  new parent.  `branch_old_tip` and `branch_new_tip` are the stage's
//  current parent before/after the rewrite.
static ok64 post_cascade_walk(cascade_ctx *cc, u8cs branch,
                              sha1 const *branch_old_tip,
                              sha1 const *branch_new_tip) {
    sane(cc);
    a_path(bdir, cc->reporoot, KEEP_DIR_S);
    if (!u8csEmpty(branch)) {
        ok64 ar = PATHu8bAdd(bdir, branch);
        if (ar != OK) return ar;
    }

    DIR *dp = opendir((char *)u8bDataHead(bdir));
    if (!dp) return OK;     //  no shard yet — no descendants

    //  Snapshot child names to avoid concurrent-readdir surprises.
    char names[CASCADE_MAX][128];
    u32 nfound = 0;
    struct dirent *e;
    while ((e = readdir(dp)) != NULL && nfound < CASCADE_MAX) {
        if (e->d_name[0] == '.') continue;     //  skip ., .., refs, .lock
        if (strcmp(e->d_name, "refs") == 0) continue;
        size_t nl = strlen(e->d_name);
        if (nl >= sizeof(names[0])) continue;
        //  Confirm it's a directory by stat'ing.
        a_path(child, $path(bdir));
        u8cs nm = {(u8cp)e->d_name, (u8cp)e->d_name + nl};
        if (PATHu8bAdd(child, nm) != OK) continue;
        struct stat sb = {};
        if (stat((char const *)u8bDataHead(child), &sb) != 0) continue;
        if ((sb.st_mode & S_IFMT) != S_IFDIR) continue;
        memcpy(names[nfound++], e->d_name, nl + 1);
    }
    closedir(dp);

    for (u32 i = 0; i < nfound; i++) {
        size_t nl = strlen(names[i]);
        //  Build absolute child branch path: <branch>/<name>.
        a_pad(u8, child_path, 256);
        if (!u8csEmpty(branch)) {
            u8bFeed(child_path, branch);
            u8bFeed1(child_path, '/');
        }
        u8cs nm = {(u8cp)names[i], (u8cp)names[i] + nl};
        u8bFeed(child_path, nm);
        a_dup(u8c, child_branch, u8bData(child_path));

        //  Capture the child's tip BEFORE the rebase via the global
        //  REFS lookup.  No tip → not a real branch (could be a stale
        //  shard dir or a non-branch sibling like `graf`/`spot` at
        //  trunk level); skip.
        sha1 child_old = {};
        ok64 cr = post_resolve_branch_tip(&child_old, cc->reporoot,
                                          child_branch);
        if (cr != OK) continue;     //  no row → skip

        //  Skip filter: cross-branch promote handles cur via auto-sync,
        //  so don't recurse into it from the cascade.
        if (!u8csEmpty(cc->skip) &&
            u8csLen(child_branch) == u8csLen(cc->skip) &&
            memcmp(child_branch[0], cc->skip[0],
                   u8csLen(child_branch)) == 0) {
            continue;
        }

        //  Stage rebase + record.
        ok64 ro = post_cascade_one(cc, child_branch,
                                   branch_old_tip, branch_new_tip);
        if (ro != OK) return ro;

        //  Recurse: this child's old/new tips drive the next level.
        sha1 child_new = cc->recs[cc->n - 1].new_tip;
        ok64 rr = post_cascade_walk(cc, child_branch, &child_old,
                                    &child_new);
        if (rr != OK) return rr;
    }
    return OK;
}

//  Persist staged cascade REFS writes.  Top-down (parent first ⇒ index
//  order).  CAS races during persist are surfaced but do not unwind
//  earlier successes (best-effort, documented).
static ok64 post_cascade_persist(cascade_ctx *cc) {
    sane(cc);
    a_path(keepdir, cc->reporoot, KEEP_DIR_S);
    for (u32 i = 0; i < cc->n; i++) {
        cascade_rec *r = &cc->recs[i];
        a_pad(u8, keybuf, 256);
        u8bFeed1(keybuf, '?');
        u8cs br = {r->branch_buf, r->branch_buf + r->branch_len};
        u8bFeed(keybuf, br);
        a_dup(u8c, refkey, u8bData(keybuf));

        a_pad(u8, exp_hex, 40);
        a_rawc(esha, r->old_tip);
        HEXu8sFeedSome(exp_hex_idle, esha);
        a_pad(u8, new_hex, 40);
        a_rawc(nsha, r->new_tip);
        HEXu8sFeedSome(new_hex_idle, nsha);
        a_dup(u8c, expected, u8bDataC(exp_hex));
        a_dup(u8c, val,      u8bDataC(new_hex));

        ok64 cas = REFSCompareAndAppend($path(keepdir), refkey,
                                        expected, val);
        if (cas == REFSCAS) {
            fprintf(stderr,
                    "sniff: post: cascade REFS race on `?%.*s` — "
                    "earlier descendants may have advanced\n",
                    (int)r->branch_len, (char *)r->branch_buf);
        } else if (cas != OK) {
            return cas;
        }
    }
    return OK;
}

// --- Cross-branch promote dispatcher (Stage 2d) ---
//
//  `be post ?<X>` (no -m): the URI names a different branch and the
//  user wants cur's stack moved over.  Four shapes per VERBS.md §POST:
//
//    (a) ?..             upstream   target == dirname(cur)
//    (b) ?./fix          child      target == cur + '/' + name (existing)
//    (c) ?./newleaf      missing    target under cur, no REFS row → create
//    (d) ?<absolute>     peer       any other existing branch
//
//  Operand mapping (see also docstring on POSTPromote):
//
//    (a) base_old=LCA(parent.tip, cur.tip), base_new=parent.tip,
//        child_tip=cur.tip; cur auto-syncs.
//    (b) base_old=LCA(cur.tip, fix.tip),    base_new=cur.tip,
//        child_tip=fix.tip; cur unchanged.
//    (c) KEEPCreateBranch + REFS row at cur.tip; no rebase.
//    (d) base_old=LCA(target.tip, cur.tip), base_new=target.tip,
//        child_tip=cur.tip; cur auto-syncs iff target == dirname(cur).
//
//  Cur auto-sync is mechanically a second REFSCompareAndAppend after
//  the target write succeeds.  A CAS race on cur after target advanced
//  leaves cur stale (user can `be get ?..` to resync) — best-effort
//  MWP behaviour, documented inline below.

//  YES iff `s` starts with `prefix`.
static b8 post_starts_with(u8cs s, u8cs prefix) {
    size_t pl = u8csLen(prefix);
    if (pl == 0) return YES;
    if (u8csLen(s) < pl) return NO;
    return memcmp(s[0], prefix[0], pl) == 0 ? YES : NO;
}

//  dirname of an absolute branch path: drop trailing `/segment`.
//  Empty input (= trunk) yields empty.  Output is a slice into input.
static void post_dirname(u8cs out, u8cs abs_branch) {
    out[0] = abs_branch[0];
    out[1] = abs_branch[0];
    if ($empty(abs_branch)) return;
    u8cp last_slash = NULL;
    $for(u8c, p, abs_branch) {
        if (*p == '/') last_slash = p;
    }
    if (last_slash != NULL) out[1] = last_slash;
}

//  basename of an absolute branch path: bytes after the last '/'.
//  Empty input yields empty; no '/' yields the whole input.  Output
//  is a slice into input.
static void post_basename(u8cs out, u8cs abs_branch) {
    out[0] = abs_branch[0];
    out[1] = abs_branch[1];
    if ($empty(abs_branch)) return;
    u8cp last_slash = NULL;
    $for(u8c, p, abs_branch) {
        if (*p == '/') last_slash = p;
    }
    if (last_slash != NULL) out[0] = last_slash + 1;
}

ok64 POSTPromote(u8cs reporoot, u8cs target_branch) {
    sane($ok(reporoot) && $ok(target_branch));
    keeper *k = &KEEP;

    //  --- 1. Resolve cur (baseline branch + cur tip) ---
    a_pad(u8, cur_buf, 256);
    sha1  cur_tip       = {};
    b8    has_cur_tip   = NO;
    {
        ron60 ts = 0, verb = 0;
        uri u = {};
        ok64 br = SNIFFAtBaseline(&ts, &verb, &u);
        if (br == OK) {
            //  Baseline branch is the first QURY_REF in the row's query.
            a_dup(u8c, q, u.query);
            while (!$empty(q)) {
                qref spec = {};
                if (QURYu8sDrain(q, &spec) != OK) break;
                if (spec.type == QURY_NONE) {
                    if ($empty(q)) break;
                    continue;
                }
                if (spec.type == QURY_REF) {
                    u8bFeed(cur_buf, spec.body);
                    break;
                }
            }
            //  Cur tip from row's #fragment / first SHA in query.
            u8 hex40[40];
            if (SNIFFAtQueryFirstSha(&u, hex40) == OK) {
                u8s bin = {cur_tip.data, cur_tip.data + 20};
                u8cs hx = {hex40, hex40 + 40};
                if (HEXu8sDrainSome(bin, hx) == OK)
                    has_cur_tip = YES;
            }
        }
    }
    a_dup(u8c, cur_branch, u8bData(cur_buf));

    if (!has_cur_tip) {
        fprintf(stderr,
                "sniff: post: no cur tip — cannot promote\n");
        return SNIFFFAIL;
    }

    //  --- 1b. Trailing-slash arm: `?<absolute>/` reuses cur's basename.
    //  Spec: `be post ?feat/` from cur on `?fix1` rewrites the target
    //  to `?feat/fix1`.  When cur is trunk (empty basename) or target
    //  is exactly "/", refuse: there's no name to copy.  After this,
    //  target_branch always names a leaf (no trailing slash).
    a_pad(u8, target_buf, 260);
    {
        b8 had_slash = NO;
        u8cs t_in = {target_branch[0], target_branch[1]};
        if (!$empty(t_in) && *u8csLast(t_in) == '/') {
            had_slash = YES;
            u8csShed1(t_in);   //  drop trailing '/'
        }
        if (had_slash) {
            u8cs base_in = {};
            post_basename(base_in, cur_branch);
            if ($empty(base_in)) {
                fprintf(stderr,
                        "sniff: post: trailing-slash target needs a "
                        "non-empty cur basename\n");
                return SNIFFFAIL;
            }
            //  Rebuild target as `<stripped>/<basename(cur)>`.
            if (!$empty(t_in)) {
                u8bFeed(target_buf, t_in);
                u8bFeed1(target_buf, '/');
            }
            u8bFeed(target_buf, base_in);
            //  Rebind target_branch to the rewritten path.
            target_branch[0] = u8bDataHead(target_buf);
            target_branch[1] = u8bIdleHead(target_buf);
        }
    }

    //  --- 2. Same-branch guard: caller should have routed elsewhere. ---
    if (u8csLen(target_branch) == u8csLen(cur_branch) &&
        (u8csLen(target_branch) == 0 ||
         memcmp(target_branch[0], cur_branch[0],
                u8csLen(target_branch)) == 0)) {
        //  Target == cur: not a promote.  The caller (label-only
        //  legacy path) will fall through to its own POSTSetLabel.
        return POSTNONE;
    }

    //  --- 3. Resolve target tip (may be missing → CREATE_ON_MISS). ---
    sha1 target_tip      = {};
    b8   target_exists   = NO;
    {
        ok64 tr = post_resolve_branch_tip(&target_tip, reporoot,
                                          target_branch);
        if (tr == OK) target_exists = YES;
        else if (tr != REFSNONE) {
            //  REFSBAD or other read error — surface.
            return tr;
        }
    }

    //  --- 4. Classify shape. ---
    //  is_child:  target startswith cur+'/'  (or cur empty + target nonempty)
    //  is_parent: target == dirname(cur)
    a_pad(u8, cur_with_slash, 260);
    if (!u8csEmpty(cur_branch)) {
        u8bFeed(cur_with_slash, cur_branch);
        u8bFeed1(cur_with_slash, '/');
    }
    a_dup(u8c, cur_slash, u8bData(cur_with_slash));
    b8 is_child = u8csEmpty(cur_branch)
                    ? !u8csEmpty(target_branch)
                    : post_starts_with(target_branch, cur_slash);
    u8cs cur_dir = {};
    post_dirname(cur_dir, cur_branch);
    b8 is_parent = NO;
    if (!u8csEmpty(cur_branch)) {
        size_t dl = u8csLen(cur_dir);
        size_t tl = u8csLen(target_branch);
        if (dl == tl &&
            (tl == 0 || memcmp(cur_dir[0], target_branch[0], tl) == 0)) {
            is_parent = YES;
        }
    }

    //  --- 5. CREATE_ON_MISS arm: ?./newleaf or ?<absolute>/<newleaf>. ---
    //  Spec: when the target doesn't exist, two shapes are accepted:
    //    (a) `?./X` — `is_child` (target under cur).  The new leaf
    //        sits at cur.tip; cur is unchanged.
    //    (b) `?<absolute>/<newleaf>` — `dirname(target)` is an existing
    //        branch.  Create the leaf, then replay cur's stack onto
    //        `dirname(target).tip` so the new leaf carries cur's
    //        commits on top of the absolute parent's tip.  Cur stays
    //        put.  Trailing-slash form (`?feat/`) was rewritten to
    //        `?feat/<basename(cur)>` in step 1b above and lands here.
    //
    //  Other create-on-miss shapes (`?../sib`, etc.) still fall back
    //  to the legacy POSTSetLabel via POSTNONE.
    sha1 absolute_parent_tip = {};
    b8   create_under_absolute = NO;
    if (!target_exists && !is_child) {
        //  Try arm (b): dirname(target) is a real branch.
        u8cs t_dir = {};
        post_dirname(t_dir, target_branch);
        if (!$empty(t_dir)) {
            ok64 dr = post_resolve_branch_tip(&absolute_parent_tip,
                                              reporoot, t_dir);
            if (dr == OK) create_under_absolute = YES;
            else if (dr != REFSNONE) return dr;
        }
        if (!create_under_absolute) {
            //  TODO(spec): sibling-create (`?../sib` from cur on a
            //  child).  Hand off to legacy POSTSetLabel.
            return POSTNONE;
        }
    }
    if (!target_exists) {
        //  Materialise the per-branch shard (idempotent on KEEPDUP).
        ok64 ko = KEEPCreateBranch(k->h, target_branch);
        if (ko != OK && ko != KEEPDUP && ko != KEEPTRUNK) return ko;

        //  Compute the new leaf's tip.  Default = cur_tip (arm `?./X`).
        //  For `?<absolute>/<newleaf>` (and trailing-slash rewrite), we
        //  rebase cur's stack onto absolute_parent_tip first and use
        //  the rebased tip.
        sha1 leaf_tip = cur_tip;
        if (create_under_absolute) {
            sha1 lca = {};
            (void)GRAFLca(&lca, &cur_tip, &absolute_parent_tip);
            if (sha1eq(&lca, &cur_tip)) {
                //  Cur already on absolute_parent_tip's spine — leaf
                //  lands at absolute_parent_tip.
                leaf_tip = absolute_parent_tip;
            } else if (sha1eq(&lca, &absolute_parent_tip)) {
                //  Cur is downstream of absolute parent — fast-forward
                //  case: leaf = cur_tip (no replay needed).
                leaf_tip = cur_tip;
            } else {
                //  Replay cur's stack onto absolute_parent_tip.
                keep_pack pp = {};
                call(KEEPPackOpen, k, &pp);
                pp.strict_order = NO;
                post_rebase_ctx rctx = {.k = k, .p = &pp};
                ok64 rb = GRAFRebase(&lca, &absolute_parent_tip,
                                     &cur_tip, post_rebase_emit_cb,
                                     &rctx);
                ok64 cl = KEEPPackClose(k, &pp);
                if (rb != OK) {
                    fprintf(stderr,
                            "sniff: post: leaf-create rebase aborted "
                            "(%s)\n",
                            rb == GRAFCNFL ? "merge conflict" : "error");
                    return rb;
                }
                if (cl != OK) return cl;
                leaf_tip = rctx.have_last_commit
                            ? rctx.last_commit_sha
                            : absolute_parent_tip;
            }
        }

        //  REFS row at leaf_tip with empty `expected_old`.
        a_path(keepdir, u8bDataC(k->h->root), KEEP_DIR_S);
        a_pad(u8, refkey_buf, 260);
        u8bFeed1(refkey_buf, '?');
        u8bFeed(refkey_buf, target_branch);
        a_dup(u8c, refkey, u8bData(refkey_buf));

        a_pad(u8, val_hex, 40);
        a_rawc(vsha, leaf_tip);
        HEXu8sFeedSome(val_hex_idle, vsha);
        a_dup(u8c, val, u8bDataC(val_hex));
        a_cstr(empty_s, "");
        u8cs expected = {empty_s[0], empty_s[1]};

        ok64 cr = REFSCompareAndAppend($path(keepdir), refkey,
                                       expected, val);
        if (cr == REFSCAS) {
            //  Lost the race: someone else created the branch.  Retry
            //  as a PROMOTE on the now-existing branch.
            ok64 tr = post_resolve_branch_tip(&target_tip, reporoot,
                                              target_branch);
            if (tr != OK) return cr;
            target_exists = YES;
            //  Fall through to PROMOTE arm below.
        } else if (cr != OK) {
            return cr;
        } else {
            //  Created.  Cur unchanged.  Done.
            fprintf(stderr,
                    "sniff: post: created ?%.*s at %.*s\n",
                    (int)u8csLen(target_branch),
                    (char *)target_branch[0],
                    (int)u8bDataLen(val_hex),
                    (char *)u8bDataHead(val_hex));
            return OK;
        }
    }

    //  --- 6. PROMOTE arm: target_exists is now true. ---
    //  Operand assignment per shape:
    sha1 base_old = {}, base_new = {}, child_tip = {};
    b8   advance_target_branch = YES;        //  always YES in promote
    b8   auto_sync_cur = NO;
    if (is_child) {
        //  ?./fix: replay fix's stack onto cur.tip.
        (void)GRAFLca(&base_old, &cur_tip, &target_tip);
        base_new  = cur_tip;
        child_tip = target_tip;
        auto_sync_cur = NO;
    } else {
        //  ?.. (parent) or ?<absolute> (peer/upstream): replay cur's
        //  stack onto target.tip.
        (void)GRAFLca(&base_old, &cur_tip, &target_tip);
        base_new  = target_tip;
        child_tip = cur_tip;
        auto_sync_cur = is_parent ? YES : NO;
    }

    //  Already in sync? base_old == child_tip means there are no
    //  commits to replay (child is an ancestor of base_new).
    b8 nothing_to_replay = sha1eq(&base_old, &child_tip);
    //  Also, if target already contains child_tip (ff in the other
    //  direction), nothing to do.
    if (nothing_to_replay) {
        sha1 lca2 = {};
        (void)GRAFLca(&lca2, &child_tip, &base_new);
        if (sha1eq(&lca2, &child_tip)) {
            //  child_tip is an ancestor of base_new — no advance.
            //  But if auto_sync_cur is set, we still want cur to track
            //  base_new (e.g. `?..` after parent has been advanced
            //  already with cur's commits — sync cur to parent.tip).
            if (auto_sync_cur) {
                a_path(keepdir, u8bDataC(k->h->root), KEEP_DIR_S);
                a_pad(u8, ckbuf, 260);
                u8bFeed1(ckbuf, '?');
                if (!u8csEmpty(cur_branch)) u8bFeed(ckbuf, cur_branch);
                a_dup(u8c, crefkey, u8bData(ckbuf));

                a_pad(u8, exp_hex, 40);
                a_rawc(esha, cur_tip);
                HEXu8sFeedSome(exp_hex_idle, esha);
                a_pad(u8, new_hex, 40);
                a_rawc(nsha, base_new);
                HEXu8sFeedSome(new_hex_idle, nsha);
                a_dup(u8c, expected, u8bDataC(exp_hex));
                a_dup(u8c, val,      u8bDataC(new_hex));
                ok64 cas = REFSCompareAndAppend($path(keepdir), crefkey,
                                                expected, val);
                if (cas == REFSCAS) {
                    fprintf(stderr,
                            "sniff: post: cur auto-sync raced on "
                            "?%.*s — run `be get ?..` to refresh\n",
                            (int)u8csLen(cur_branch),
                            (char *)cur_branch[0]);
                } else if (cas != OK) return cas;
            }
            fprintf(stderr,
                    "sniff: post: nothing to promote (?%.*s already "
                    "contains cur)\n",
                    (int)u8csLen(target_branch),
                    (char *)target_branch[0]);
            return OK;
        }
    }

    //  --- 7. Run GRAFRebase, capture new tip via emit_cb. ---
    keep_pack pp = {};
    call(KEEPPackOpen, k, &pp);
    pp.strict_order = NO;
    post_rebase_ctx rctx = {.k = k, .p = &pp};
    ok64 rb = GRAFRebase(&base_old, &base_new, &child_tip,
                         post_rebase_emit_cb, &rctx);
    ok64 cl = KEEPPackClose(k, &pp);
    if (rb != OK) {
        fprintf(stderr,
                "sniff: post: cross-branch rebase aborted (%s)\n",
                rb == GRAFCNFL ? "merge conflict" : "error");
        return rb;
    }
    if (cl != OK) return cl;

    sha1 target_new_tip = rctx.have_last_commit
                            ? rctx.last_commit_sha
                            : base_new;

    //  --- 8. Cascade walk on the *target* side. ---
    //  After target's stack got rewritten (if anything was replayed),
    //  every descendant of target needs its fork point bumped.  The
    //  cascade walker is generalised — it takes a starting branch and
    //  the (old, new) tip pair; we just hand it the target's view.
    cascade_ctx casc = {};
    if (rctx.have_last_commit) {
        keep_pack p3 = {};
        call(KEEPPackOpen, k, &p3);
        p3.strict_order = NO;
        casc.k = k;
        casc.p = &p3;
        a_dup(u8c, root_view, u8bDataC(k->h->root));
        casc.reporoot[0] = root_view[0];
        casc.reporoot[1] = root_view[1];
        //  Skip cur during cascade: auto-sync handles it directly.
        casc.skip[0] = cur_branch[0];
        casc.skip[1] = cur_branch[1];
        ok64 cw = post_cascade_walk(&casc, target_branch,
                                    &target_tip, &target_new_tip);
        ok64 cl3 = KEEPPackClose(k, &p3);
        if (cw != OK) {
            fprintf(stderr,
                    "sniff: post: cascade aborted (%s)\n",
                    cw == GRAFCNFL ? "merge conflict in descendant"
                                   : "error");
            return cw;
        }
        if (cl3 != OK) return cl3;
    }

    //  --- 9. Advance target's REFS row via CAS on target_tip. ---
    {
        a_path(keepdir, u8bDataC(k->h->root), KEEP_DIR_S);
        a_pad(u8, refkey_buf, 260);
        u8bFeed1(refkey_buf, '?');
        if (!u8csEmpty(target_branch)) u8bFeed(refkey_buf, target_branch);
        a_dup(u8c, refkey, u8bData(refkey_buf));

        a_pad(u8, exp_hex, 40);
        a_rawc(esha, target_tip);
        HEXu8sFeedSome(exp_hex_idle, esha);
        a_pad(u8, new_hex, 40);
        a_rawc(nsha, target_new_tip);
        HEXu8sFeedSome(new_hex_idle, nsha);
        a_dup(u8c, expected, u8bDataC(exp_hex));
        a_dup(u8c, val,      u8bDataC(new_hex));

        ok64 cas = REFSCompareAndAppend($path(keepdir), refkey,
                                        expected, val);
        if (cas == REFSCAS) {
            fprintf(stderr,
                    "sniff: post: REFS for `?%.*s` advanced "
                    "concurrently — retry\n",
                    (int)u8csLen(target_branch),
                    (char *)target_branch[0]);
            return REFSCAS;
        }
        if (cas != OK) return cas;
    }
    (void)advance_target_branch;

    //  --- 10. Persist any cascade descendants (best-effort). ---
    if (casc.n > 0) (void)post_cascade_persist(&casc);

    //  --- 11. Cur auto-sync (?.. and ?<absolute> when target IS cur's
    //  tree-parent).  Race story: if this CAS loses, target already
    //  advanced and cur is stale — user can `be get ?..` to resync.
    //  Documented MWP best-effort behaviour. ---
    if (auto_sync_cur) {
        a_path(keepdir, u8bDataC(k->h->root), KEEP_DIR_S);
        a_pad(u8, ckbuf, 260);
        u8bFeed1(ckbuf, '?');
        if (!u8csEmpty(cur_branch)) u8bFeed(ckbuf, cur_branch);
        a_dup(u8c, crefkey, u8bData(ckbuf));

        a_pad(u8, exp_hex, 40);
        a_rawc(esha, cur_tip);
        HEXu8sFeedSome(exp_hex_idle, esha);
        a_pad(u8, new_hex, 40);
        a_rawc(nsha, target_new_tip);
        HEXu8sFeedSome(new_hex_idle, nsha);
        a_dup(u8c, expected, u8bDataC(exp_hex));
        a_dup(u8c, val,      u8bDataC(new_hex));
        ok64 cas = REFSCompareAndAppend($path(keepdir), crefkey,
                                        expected, val);
        if (cas == REFSCAS) {
            fprintf(stderr,
                    "sniff: post: cur auto-sync raced on `?%.*s` — "
                    "run `be get ?..` to refresh\n",
                    (int)u8csLen(cur_branch), (char *)cur_branch[0]);
            //  Don't surface — target already advanced; cur staleness
            //  is recoverable.
        } else if (cas != OK) return cas;
    }

    //  Done.  Pretty-print the resulting tip for the user.
    {
        a_pad(u8, hex_out, 40);
        a_rawc(osha, target_new_tip);
        HEXu8sFeedSome(hex_out_idle, osha);
        fprintf(stderr,
                "sniff: post: ?%.*s -> %.*s\n",
                (int)u8csLen(target_branch),
                (char *)target_branch[0],
                (int)u8bDataLen(hex_out),
                (char *)u8bDataHead(hex_out));
    }
    return OK;
}

// --- Public API ---

ok64 POSTPrintStatus(u8cs reporoot) {
    sane($ok(reporoot));
    keeper *k = &KEEP;

    post_ctx ctx = {};
    call(post_ctx_init, &ctx, reporoot, k);

    sha1 base_tree_sha = {};
    b8   have_base = NO;
    ok64 so = post_scan_changeset(&ctx, &base_tree_sha, &have_base);
    if (so != OK) { post_ctx_free(&ctx); return so; }

    //  Walk decisions, print one line per changed path.
    post_mad_ctx mad = {.out = stdout, .on = "", .off = "", .changed = 0};
    post_walk_decisions(&ctx, POST_VM_UNLINK | POST_VM_ADD,
                        post_drain_mad_cb, &mad);
    fflush(stdout);
    fprintf(stderr, "sniff: %u change(s)\n", mad.changed);

    post_ctx_free(&ctx);
    done;
}

ok64 POSTCommit(u8cs reporoot, u8cs target_branch,
                u8cs message, u8cs author, sha1 *sha_out) {
    sane($ok(message) && $ok(author) && sha_out);
    keeper *k = &KEEP;

    //  1. Resolve baseline parent.  Single-parent invariant on the
    //     write path (see VERBS.md §POST):
    //       * no baseline row at all  → root commit (0 parents, OK).
    //       * baseline + parent sha   → normal commit.
    //       * baseline + no sha       → corrupt at-log; refuse.
    a_pad(u8, brbuf, 256);
    sha1  parent     = {};
    b8    has_parent = NO;
    b8    had_baseline = NO;
    ok64  br = post_collect_parents(brbuf, &parent, &has_parent,
                                    &had_baseline);
    if (br != OK) return br;
    if (had_baseline && !has_parent) {
        fprintf(stderr,
                "sniff: post: baseline at-log row has no parent SHA — "
                "refusing parentless commit (would orphan peer history "
                "on push)\n");
        return SNIFFFAIL;
    }

    //  Cross-branch override: when the caller passes a non-empty
    //  target_branch, the new commit lands on that branch instead
    //  of the baseline-derived one.  brbuf carries the branch path
    //  used downstream by both the REFS writer and the .sniff post
    //  row's query, so swapping it here is enough.
    if ($ok(target_branch) && !u8csEmpty(target_branch)) {
        u8bReset(brbuf);
        u8bFeed(brbuf, target_branch);
    }
    //  No baseline branch recovered AND no override → default to
    //  trunk (empty be-side query).  Locally trunk has no name; the
    //  wire layer aliases it to refs/heads/main.  brbuf left empty
    //  signals "trunk" to the ULOG/REFS writers below.

    //  --- ff-only pre-flight ----------------------------------------
    //  POST onto a branch with a recorded REFS tip is fast-forward
    //  only: the target's tip must be an ancestor of (or equal to)
    //  the wt's first parent.  Different = someone advanced the
    //  branch since our last sync, OR this is a cross-branch POST
    //  whose target is on an unrelated lineage; either way, refuse
    //  and let the user resolve manually (`be patch ?<branch>` for
    //  same-branch divergence, or `be delete ?<branch>` followed by
    //  recreate for cross-branch reset).
    //  Resolve target REFS tip up-front.  When present and != parent,
    //  the post-pack-feed REFS write below uses CAS on `expected_old =
    //  <tip>` so concurrent posters see REFSCAS.  Today this is a
    //  legacy ff-only pre-flight: we still bail with SNIFFNOFF on
    //  non-ff, the rebase-or-promote pathway is implemented in the
    //  caller (sniff post phase 2).  See VERBS.md §POST for the
    //  ff-or-rebase shape that replaces it.
    sha1 expected_tip_sha = {};
    b8   has_expected_tip = NO;
    b8   needs_rebase     = NO;   //  set when REFS tip diverges from cur's
                                  //  parent — replay the just-built commit
                                  //  onto REFS tip after the pack feed.
    if (had_baseline && has_parent) {
        a_path(keepdir, u8bDataC(k->h->root), KEEP_DIR_S);
        a_pad(u8, refkey_buf, 128);
        u8bFeed1(refkey_buf, '?');
        a_dup(u8c, branch, u8bData(brbuf));
        if (!u8csEmpty(branch)) u8bFeed(refkey_buf, branch);
        a_dup(u8c, refkey_s, u8bData(refkey_buf));

        a_pad(u8, arena, 1024);
        uri resolved = {};
        ok64 ro = REFSResolve(&resolved, arena, $path(keepdir),
                              refkey_s);
        if (ro == OK && !$empty(resolved.query)) {
            u8cs tip_hex = {resolved.query[0], resolved.query[1]};
            if (!u8csEmpty(tip_hex) && *tip_hex[0] == '?')
                u8csUsed(tip_hex, 1);
            if ($len(tip_hex) != 40) {
                fprintf(stderr,
                        "sniff: post: REFS row for `?%.*s` has malformed "
                        "tip (%zu bytes, want 40 hex)\n",
                        (int)u8csLen(branch), (char *)branch[0],
                        (size_t)$len(tip_hex));
                return SNIFFFAIL;
            }
            u8s bin = {expected_tip_sha.data, expected_tip_sha.data + 20};
            a_dup(u8c, hx, tip_hex);
            ok64 ho = HEXu8sDrainSome(bin, hx);
            if (ho != OK) {
                fprintf(stderr,
                        "sniff: post: REFS row for `?%.*s` has non-hex "
                        "tip\n",
                        (int)u8csLen(branch), (char *)branch[0]);
                return SNIFFFAIL;
            }
            has_expected_tip = YES;

            //  ff iff tip is an ancestor of (or equal to) parent.
            b8 ff_ok = NO;
            if (sha1eq(&parent, &expected_tip_sha)) {
                ff_ok = YES;
            } else {
                sha1 lca = {};
                (void)GRAFLca(&lca, &parent, &expected_tip_sha);
                if (sha1eq(&lca, &expected_tip_sha)) ff_ok = YES;
            }
            if (!ff_ok) {
                //  Same-branch divergence: defer the SNIFFNOFF bail —
                //  the new commit will be rebased onto REFS tip after
                //  the pack feed (Stage 2 phase-2 promote).
                needs_rebase = YES;
            }
        }
    }
    //  --- end ff-only pre-flight ------------------------------------

    //  Steps 2..5 — the change-set scan — share their entire body
    //  with POSTPrintStatus's dry-run path.  See post_scan_changeset.
    post_ctx ctx = {};
    call(post_ctx_init, &ctx, reporoot, k);

    sha1 base_tree_sha = {};
    b8   have_base = NO;
    ok64 so = post_scan_changeset(&ctx, &base_tree_sha, &have_base);
    if (so != OK) { post_ctx_free(&ctx); return so; }

    //  5b. Unlink files marked for delete on disk.  Done BEFORE the
    //      pack feed so a follow-up `be post` doesn't pick them up via
    //      auto-stage; mtime-attribution fix for the BEhistory
    //      "deleted-file re-added" regression.
    post_walk_decisions(&ctx, POST_VM_UNLINK, post_drain_unlink_cb, NULL);

    //  6b. Single-parent invariant on the write path.  PATCH no longer
    //      records `&<theirs>` in baseline; the new commit takes the
    //      one parent recorded in `parent` (set by post_collect_parents).

    //  7. Build trees bottom-up over the dense lex-sorted recs the
    //     classification merge populated.
    sha1 root_tree = {};
    b8 have_root = NO;
    Bu8 tree_bodies = {};
    call(u8bAllocate, tree_bodies, 1UL << 20);
    u32 tree_count = 0;

    Bu8 leaves = {};
    call(u8bAllocate, leaves, POST_TREE_ULOG_MAX);
    {
        ok64 lo = post_build_leaves(&ctx, leaves);
        if (lo != OK) {
            u8bFree(leaves); u8bFree(tree_bodies);
            post_ctx_free(&ctx);
            return lo;
        }
    }

    {
        u32 n_leaves = post_leaves_count(leaves);
        u8cs no_prefix = {};
        ok64 bo = post_build_tree(leaves, 0, n_leaves, no_prefix,
                                  &root_tree, tree_bodies, &tree_count);
        if (bo != OK) {
            u8bFree(leaves); u8bFree(tree_bodies);
            post_ctx_free(&ctx);
            return bo;
        }
        have_root = !sha1empty(&root_tree);
    }

    //  7b. Empty-commit refuse: if the new root tree matches the
    //      baseline's tree exactly, the wt has nothing to record.
    //      Refusing here keeps `.sniff` and REFS clean — VERBS.md
    //      says "empty POSTs are refused."  Skip on a fresh repo
    //      (no baseline tree to compare against).
    if (had_baseline && have_root && have_base &&
        memcmp(root_tree.data, base_tree_sha.data, 20) == 0) {
        fprintf(stderr,
                "sniff: post: no changes since base — refusing empty "
                "commit\n");
        u8bFree(leaves); u8bFree(tree_bodies);
        post_ctx_free(&ctx);
        return POSTNONE;
    }

    //  8. If the result has no files, fall back to the empty-tree sha.
    keep_pack p = {};
    {
        ok64 po = KEEPPackOpen(k, &p);
        if (po != OK) {
            u8bFree(leaves); u8bFree(tree_bodies);
            post_ctx_free(&ctx);
            return po;
        }
    }
    p.strict_order = NO;

    if (!have_root) {
        call(post_feed_empty_tree, k, &p, &root_tree);
    }

    //  9. Verify each parent commit exists locally; refuse otherwise.
    //     `parents[]` already holds the decoded sha1 bytes from the
    //     baseline row's QURY scan; `post_parent_sha` re-runs the
    //     keeper lookup as a sanity check.
    if (has_parent) {
        a_pad(u8, hx_buf, 40);
        a_rawc(psha_in, parent);
        HEXu8sFeedSome(hx_buf_idle, psha_in);
        a_dup(u8c, ph, u8bDataC(hx_buf));
        sha1 ps = {};
        if (post_parent_sha(k, ph, &ps) != OK) {
            fprintf(stderr,
                    "sniff: post: parent commit %.*s not found in keeper — "
                    "refusing\n",
                    (int)u8csLen(ph), (char const *)ph[0]);
            return SNIFFFAIL;
        }
        parent = ps;
    }

    //  10. Build commit body.  Single-parent invariant: at most one
    //      `parent <hex>\n` line.
    Bu8 com = {};
    call(u8bAllocate, com, 4096);
    a_cstr(tree_label, "tree ");
    u8bFeed(com, tree_label);
    a_pad(u8, thex, 40);
    a_rawc(tsha, root_tree);
    HEXu8sFeedSome(thex_idle, tsha);
    u8bFeed(com, u8bDataC(thex));
    u8bFeed1(com, '\n');

    if (has_parent) {
        a_cstr(par_label, "parent ");
        u8bFeed(com, par_label);
        a_pad(u8, par_hex, 40);
        a_rawc(psha, parent);
        HEXu8sFeedSome(par_hex_idle, psha);
        u8bFeed(com, u8bDataC(par_hex));
        u8bFeed1(com, '\n');
    }

    time_t now = time(NULL);
    char tsb[64];
    int tslen = snprintf(tsb, sizeof(tsb), " %lld +0000\n", (long long)now);
    u8cs ts_s = {(u8cp)tsb, (u8cp)tsb + tslen};

    a_cstr(auth_label, "author ");
    u8bFeed(com, auth_label);
    u8bFeed(com, author);
    u8bFeed(com, ts_s);

    a_cstr(comm_label, "committer ");
    u8bFeed(com, comm_label);
    u8bFeed(com, author);
    u8bFeed(com, ts_s);

    u8bFeed1(com, '\n');
    u8bFeed(com, message);
    u8bFeed1(com, '\n');

    //  11. Feed pack: commit first.
    a_dup(u8c, com_data, u8bData(com));
    ok64 fo = KEEPPackFeed(k, &p, DOG_OBJ_COMMIT, com_data, 0, sha_out);
    u8bFree(com);
    if (fo != OK) {
        KEEPPackClose(k, &p);
        u8bFree(leaves); u8bFree(tree_bodies);
        post_ctx_free(&ctx);
        return fo;
    }

    //  12. Feed all rebuilt trees.
    if (have_root) {
        u8c *walk = u8bDataHead(tree_bodies);
        u8c *end_walk = u8bIdleHead(tree_bodies);
        while (walk < end_walk) {
            u32 tlen = 0;
            memcpy(&tlen, walk, sizeof(u32));
            walk += sizeof(u32);
            u8cs tbody = {walk, walk + tlen};
            sha1 tsha_dummy = {};
            ok64 to = KEEPPackFeed(k, &p, DOG_OBJ_TREE, tbody,
                                   0, &tsha_dummy);
            walk += tlen;
            if (to != OK) {
                KEEPPackClose(k, &p);
                u8bFree(leaves); u8bFree(tree_bodies);
                post_ctx_free(&ctx);
                return to;
            }
        }
    }

    //  13. Feed all new blobs.  Drains `add` decisions; for each row
    //      reads the wt file (mmap for regular/exec, readlink for
    //      symlink) and feeds the bytes into the pack.  Delta base:
    //      when the row carries an `&<old_sha>` chain, use that sha
    //      as the OFS/REF_DELTA target so small edits ride bsdiff
    //      instead of a fresh zlib-of-everything.
    {
        a_dup(u8c, scan, u8bData(ctx.decisions));
        while (!u8csEmpty(scan)) {
            ulogrec drec = {};
            ok64 dr = ULOGu8sDrain(scan, &drec);
            if (dr == NODATA) break;
            if (dr != OK) continue;
            if (drec.verb != ctx.v_add) continue;

            u8cs path = {drec.uri.path[0], drec.uri.path[1]};
            u16  mode = post_decision_mode(&drec.uri);
            sha1 old_sha = {};
            b8   has_old = post_decision_old_sha(&drec.uri, &old_sha);

            a_path(fp);
            if (SNIFFFullpath(fp, reporoot, path) != OK) continue;

            //  Read the bytes into a scratch buffer.  Symlinks via
            //  readlink (mmap doesn't compose); regular/exec via
            //  FILEMapRO.
            Bu8 body_buf = {};
            u8bp mapped = NULL;
            u8cs body = {};
            if (mode == 0120000) {
                char target[1024];
                ssize_t tlen = readlink(
                    (char const *)u8bDataHead(fp),
                    target, sizeof(target));
                if (tlen <= 0) continue;
                ok64 ao = u8bAllocate(body_buf, (u64)tlen);
                if (ao != OK) continue;
                u8cs tv = {(u8cp)target, (u8cp)target + tlen};
                u8bFeed(body_buf, tv);
                body[0] = u8bDataHead(body_buf);
                body[1] = u8bIdleHead(body_buf);
            } else {
                ok64 mo = FILEMapRO(&mapped, $path(fp));
                if (mo != OK) continue;
                body[0] = u8bDataHead(mapped);
                body[1] = u8bIdleHead(mapped);
            }

            u64 base_hl = has_old ? WHIFFHashlet60(&old_sha) : 0;
            sha1 bsha = {};
            ok64 bo = KEEPPackFeed(k, &p, DOG_OBJ_BLOB, body,
                                   base_hl, &bsha);
            if (mapped) FILEUnMap(mapped);
            if (u8bOK(body_buf)) u8bFree(body_buf);
            if (bo != OK) {
                KEEPPackClose(k, &p);
                u8bFree(leaves); u8bFree(tree_bodies);
                post_ctx_free(&ctx);
                return bo;
            }
        }
    }

    call(KEEPPackClose, k, &p);

    //  13b. Phase-2 promote: rebase the just-built commit onto the
    //       live REFS tip when the branch diverged out from under us,
    //       then cascade-rebase every descendant branch onto the new
    //       tip.  Same-branch case only.
    //
    //       Invariant: on entry needs_rebase ⇒ has_expected_tip and
    //       has_parent (the early pre-flight only sets needs_rebase
    //       when both were observed).  GRAFRebase replays parent..sha_out
    //       onto expected_tip_sha; emitted objects feed straight into a
    //       fresh pack.  GRAFCNFL → propagate, leaving orphan objects
    //       in the pack (REFS unchanged ⇒ they are unreachable).
    //
    //       Cascade: after the same-branch rebase closes its pack, a
    //       third pack opens for the descendant walk so the just-rebased
    //       tip is visible to KEEPGetExact.  Each descendant branch is
    //       replayed via GRAFRebase, the new tips are staged in
    //       cascade_ctx.recs, and post_cascade_persist commits the
    //       REFSCompareAndAppend writes after cur's REFS update.
    //
    //       TODO(spec): cross-branch promote (target_branch != cur's
    //       baseline branch) — `?..` auto-sync, `?<absolute>` sibling/
    //       cousin promote, create-on-miss leaf, trailing-slash basename
    //       reuse.  The dispatch table from VERBS.md §POST stays
    //       deferred.  Today cross-branch non-ff still reports SNIFFNOFF
    //       via the early pre-flight on the OTHER branch's REFS row,
    //       since needs_rebase is gated by the baseline-branch lookup
    //       above.
    cascade_ctx casc = {};
    if (needs_rebase) {
        keep_pack p2 = {};
        ok64 po2 = KEEPPackOpen(k, &p2);
        if (po2 != OK) {
            u8bFree(leaves); u8bFree(tree_bodies);
            post_ctx_free(&ctx);
            return po2;
        }
        p2.strict_order = NO;
        post_rebase_ctx rctx = {.k = k, .p = &p2};
        ok64 rb = GRAFRebase(&parent, &expected_tip_sha, sha_out,
                             post_rebase_emit_cb, &rctx);
        ok64 cl2 = KEEPPackClose(k, &p2);
        if (rb != OK) {
            fprintf(stderr,
                    "sniff: post: rebase aborted (%s)\n",
                    rb == GRAFCNFL ? "merge conflict" : "error");
            u8bFree(leaves); u8bFree(tree_bodies);
            post_ctx_free(&ctx);
            return rb;
        }
        if (cl2 != OK) {
            u8bFree(leaves); u8bFree(tree_bodies);
            post_ctx_free(&ctx);
            return cl2;
        }
        if (rctx.have_last_commit) {
            *sha_out = rctx.last_commit_sha;
        } else {
            //  Trivial rebase fast-path: parent..child was empty, so
            //  the rebased tip is base_new itself.
            *sha_out = expected_tip_sha;
        }

        //  --- Cascade rebase for descendants of cur's branch ---
        //  When the same-branch rebase rewrote cur's stack, every
        //  descendant branch that forked off `expected_tip_sha` (or
        //  earlier) now has a stale fork point.  Open a third pack for
        //  the cascade so the just-rebased ?cur tip is visible to
        //  KEEPGetExact (the rebase commits live in p2, which must be
        //  closed before they are indexed).
        a_dup(u8c, branch_view, u8bData(brbuf));
        sha1 br_new = *sha_out;
        keep_pack p3 = {};
        ok64 po3 = KEEPPackOpen(k, &p3);
        if (po3 != OK) {
            u8bFree(leaves); u8bFree(tree_bodies);
            post_ctx_free(&ctx);
            return po3;
        }
        p3.strict_order = NO;
        casc.k = k;
        casc.p = &p3;
        a_dup(u8c, root_view, u8bDataC(k->h->root));
        casc.reporoot[0] = root_view[0];
        casc.reporoot[1] = root_view[1];
        ok64 cw = post_cascade_walk(&casc, branch_view,
                                    &expected_tip_sha, &br_new);
        ok64 cl3 = KEEPPackClose(k, &p3);
        if (cw != OK) {
            fprintf(stderr,
                    "sniff: post: cascade aborted (%s)\n",
                    cw == GRAFCNFL ? "merge conflict in descendant"
                                   : "error");
            u8bFree(leaves); u8bFree(tree_bodies);
            post_ctx_free(&ctx);
            return cw;
        }
        if (cl3 != OK) {
            u8bFree(leaves); u8bFree(tree_bodies);
            post_ctx_free(&ctx);
            return cl3;
        }
    }

    //  14. Advance keeper REFS for the be-branch the wt is currently
    //      on via REFSCompareAndAppend.  Atomic check-and-set on the
    //      *expected* tip (the REFS row we read at pre-flight time, or
    //      empty when no row existed yet — a fresh branch).  Concurrent
    //      posters who advanced the branch since pre-flight see REFSCAS
    //      and surface it to the caller.
    a_pad(u8, out_hex, 40);
    {
        a_rawc(osha, *sha_out);
        HEXu8sFeedSome(out_hex_idle, osha);
    }
    {
        a_path(keepdir, u8bDataC(k->h->root), KEEP_DIR_S);
        a_pad(u8, keybuf, 128);
        u8bFeed1(keybuf, '?');
        a_dup(u8c, branch, u8bData(brbuf));
        if (!u8csEmpty(branch)) u8bFeed(keybuf, branch);
        a_dup(u8c, refkey, u8bData(keybuf));

        a_dup(u8c, val, u8bDataC(out_hex));

        a_pad(u8, exp_hex, 40);
        a_cstr(empty_s, "");
        u8cs expected = {empty_s[0], empty_s[1]};
        if (has_expected_tip) {
            a_rawc(esha, expected_tip_sha);
            HEXu8sFeedSome(exp_hex_idle, esha);
            expected[0] = u8bDataHead(exp_hex);
            expected[1] = u8bIdleHead(exp_hex);
        }
        ok64 cr = REFSCompareAndAppend($path(keepdir), refkey, expected, val);
        if (cr == REFSCAS) {
            fprintf(stderr,
                    "sniff: post: REFS for `?%.*s` advanced concurrently — "
                    "retry\n",
                    (int)u8csLen(branch), (char *)branch[0]);
            //  Best-effort: don't undo the pack feed.  Caller may retry
            //  POST against the new tip.
            return REFSCAS;
        }
    }

    //  Cascade REFS persistence: write descendant branches' new tips
    //  AFTER cur's REFS update succeeded.  Best-effort on individual
    //  CAS races (logged inside post_cascade_persist).
    if (casc.n > 0) (void)post_cascade_persist(&casc);

    //  15. Append `post` ULOG row with stamp ts; futimens written
    //      files so they become clean under the new stamp.  Canonical
    //      at-log shape: `?<branch>#<curhash>` — query is the
    //      be-branch (empty for trunk), fragment is the new tip sha.
    //      Mirrors the REFS row format so readers walk the same shape.
    uri urow = {};
    {
        a_dup(u8c, branch, u8bData(brbuf));
        urow.query[0] = u8bDataHead(brbuf);
        urow.query[1] = u8bIdleHead(brbuf);
        (void)branch;
    }
    {
        a_dup(u8c, h, u8bDataC(out_hex));
        urow.fragment[0] = h[0];
        urow.fragment[1] = h[1];
    }

    //  Use the single per-commit stamp the decision rows already
    //  carry — keeps the post ULOG row, the decision rows, and the
    //  on-disk file stamps all in lockstep.
    ron60 verb = SNIFFAtVerbPost();
    ok64 ar = SNIFFAtAppendAt(ctx.stamp_ts, verb, &urow);
    (void)ar;

    //  Stamp only `add` files (drain add decisions).  KEEP files keep
    //  their previous get/post stamp — re-stamping them is redundant.
    post_walk_decisions(&ctx, POST_VM_ADD, post_drain_stamp_cb, NULL);

    //  16. Pretty-print actually-changed paths in grey (TTY only).
    {
        b8 tty = isatty(STDERR_FILENO) ? YES : NO;
        post_mad_ctx mad = {
            .out = stderr,
            .on  = tty ? "\033[90m" : "",
            .off = tty ? "\033[0m"  : "",
            .changed = 0,
        };
        post_walk_decisions(&ctx, POST_VM_UNLINK | POST_VM_ADD,
                            post_drain_mad_cb, &mad);
    }

    //  17. Clean up.
    u8bFree(leaves);
    u8bFree(tree_bodies);
    post_ctx_free(&ctx);
    fprintf(stderr, "sniff: commit %.*s\n",
            (int)u8bDataLen(out_hex), (char *)u8bDataHead(out_hex));
    done;
}

ok64 POSTSetLabel(u8cs ref_uri, u8cs sha_hex) {
    sane($ok(ref_uri) && !u8csEmpty(ref_uri) && $ok(sha_hex));
    if (u8csLen(sha_hex) != 40) fail(SNIFFFAIL);

    a_path(keepdir, u8bDataC(KEEP.h->root), KEEP_DIR_S);

    //  Canonicalise the caller-supplied ref URI (user input path:
    //  command line `be post ?<label>`).  Lex → canonicalise → feed.
    uri u = {};
    u.data[0] = ref_uri[0];
    u.data[1] = ref_uri[1];
    call(URILexer, &u);
    u.data[0] = ref_uri[0];
    u.data[1] = ref_uri[1];
    a_pad(u8, keybuf, 256);
    call(DOGCanonURIFeed, keybuf, &u);
    a_dup(u8c, key, u8bData(keybuf));

    //  Materialise the per-branch keeper shard for non-trunk labels
    //  before recording the REFS row.  KEEPCreateBranch normalises the
    //  branch (empty = trunk, mapped trunk aliases collapse to trunk
    //  too) and is idempotent on KEEPDUP — letting two POSTs against
    //  the same fresh label converge without a separate "branch
    //  exists" probe.  KEEPTRUNK is silently absorbed (trunk shard
    //  always exists by construction).
    if (!$empty(u.query)) {
        a_dup(u8c, branch, u.query);
        ok64 ko = KEEPCreateBranch(KEEP.h, branch);
        if (ko != OK && ko != KEEPDUP && ko != KEEPTRUNK) return ko;
    }

    //  Val is bare 40-hex (canonical).  `post` verb — local ref move.
    return REFSAppendVerb($path(keepdir), REFSVerbPost(), key, sha_hex);
}
