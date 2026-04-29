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

#include "abc/FILE.h"
#include "abc/HEX.h"
#include "abc/PATH.h"
#include "abc/PRO.h"
#include "dog/IGNO.h"
#include "dog/QURY.h"
#include "dog/WHIFF.h"
#include "graf/GRAF.h"
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
        //  Tracked + dirty: hash to determine real change.
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

#define POST_MAX_PARENTS 16

//  Read the latest baseline (`get`/`post`/`patch`) row.  Fills `out`
//  with the be-branch path (row's query), and `parents[]` with the
//  current commit (row's `#fragment`) plus any extra 40-hex SHAs that
//  appear in the query as `&`-chained specs (patch in-progress carries
//  its `theirs` parents that way).  `*had_baseline_out` is YES iff a
//  baseline row exists (so callers can distinguish a fresh repo from
//  a corrupt one).
//
//  Returns OK in both the "baseline exists" and "no baseline" cases —
//  callers branch on `*had_baseline_out`.  Non-OK reflects ULOG /
//  parse failures upstream.
//
//  Per the new model, this collects only `ours` (parent[0]).  Patch
//  parents (extra SHAs from prior `&<theirs>` chain entries) are added
//  later by `post_add_patch_parents`, but only for files actually
//  committed and only when their owning patch's ts stamps them — so
//  cherry-pick / selective commits get a single parent.
static ok64 post_collect_parents(u8bp out, sha1 *parents, u32 *nparents_out,
                                 u32 cap, b8 *had_baseline_out) {
    sane(out && parents && nparents_out && had_baseline_out);
    u8bReset(out);
    *nparents_out = 0;
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
        if (SNIFFAtQueryFirstSha(&u, hex40) == OK && cap > 0) {
            sha1 ph = {};
            u8s bin = {ph.data, ph.data + 20};
            u8cs hx = {hex40, hex40 + 40};
            if (HEXu8sDrainSome(bin, hx) == OK && bin[0] == ph.data + 20)
                parents[(*nparents_out)++] = ph;
        }
    }

    //  Walk the query for the branch (first QURY_REF).  Query SHAs are
    //  intentionally ignored here — they're patch-recorded `theirs`
    //  candidates, surfaced per-file in `post_add_patch_parents`.
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

//  Pull the `theirs` sha THIS patch row contributed.  PATCH appends
//  one new `&<theirs>` to the prior baseline's query each time, so
//  the most recent patch row's last query SHA is the one it added.
//  Returns OK + 40 hex bytes copied into `hex_out` on success.
static ok64 post_patch_theirs(uri const *u, u8 hex_out[40]) {
    sane(u && hex_out);
    a_dup(u8c, q, u->query);
    b8 found = NO;
    u8 last[40];
    while (!$empty(q)) {
        qref spec = {};
        if (QURYu8sDrain(q, &spec) != OK) break;
        if (spec.type == QURY_NONE) {
            if ($empty(q)) break;
            continue;
        }
        if (spec.type == QURY_SHA && $len(spec.body) == 40) {
            memcpy(last, spec.body[0], 40);
            found = YES;
        }
    }
    if (!found) fail(ULOGNONE);
    memcpy(hex_out, last, 40);
    done;
}

//  Walk every path that POST is rewriting (REWRITE, on disk).  For
//  each, look up its owning ULOG row by mtime; if the row is a `patch`
//  then its contributed `theirs` becomes a parent of the new commit
//  (de-duped against existing parents).  Implicit mode only — selective
//  commits stay single-parent ("cherry-pick") even when they touch
//  patched files.
static ok64 post_add_patch_parents(post_ctx *c, sha1 *parents,
                                   u32 *nparents, u32 cap) {
    sane(c && parents && nparents);
    ron60 v_patch = SNIFFAtVerbPatch();

    //  Drain `add` decisions — every rewrite-or-add row is a potential
    //  patch contributor.  unlink/keep rows have no patch ancestry.
    a_dup(u8c, scan, u8bData(c->decisions));
    while (!u8csEmpty(scan)) {
        ulogrec drec = {};
        ok64 dr = ULOGu8sDrain(scan, &drec);
        if (dr == NODATA) break;
        if (dr != OK) continue;
        if (drec.verb != c->v_add) continue;

        u8cs path = {drec.uri.path[0], drec.uri.path[1]};
        a_path(fp);
        if (SNIFFFullpath(fp, c->reporoot, path) != OK) continue;

        struct stat sb = {};
        if (lstat((char const *)u8bDataHead(fp), &sb) != 0) continue;
        struct timespec mts = {.tv_sec  = sb.st_mtim.tv_sec,
                               .tv_nsec = sb.st_mtim.tv_nsec};
        ron60 mr = SNIFFAtOfTimespec(mts);

        ron60 ow_verb = 0;
        uri ow_u = {};
        if (SNIFFAtRowAtTs(mr, &ow_verb, &ow_u) != OK) continue;
        if (ow_verb != v_patch) continue;

        u8 hex40[40];
        if (post_patch_theirs(&ow_u, hex40) != OK) continue;
        sha1 ph = {};
        u8s bin = {ph.data, ph.data + 20};
        u8cs hx = {hex40, hex40 + 40};
        if (HEXu8sDrainSome(bin, hx) != OK) continue;
        if (bin[0] != ph.data + 20) continue;

        //  Dedupe against the existing parent list (multiple files may
        //  share the same patch row).
        b8 dup = NO;
        for (u32 p = 0; p < *nparents; p++)
            if (sha1eq(&parents[p], &ph)) { dup = YES; break; }
        if (dup) continue;
        if (*nparents >= cap) break;
        parents[(*nparents)++] = ph;
    }
    done;
}

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

    //  1. Resolve baseline parents.  Three cases:
    //       * no baseline row at all  → root commit (0 parents, OK).
    //       * baseline + 1+ parents   → normal / merge commit.
    //       * baseline + 0 parents    → corrupt at-log; refuse.
    //     The third case used to silently produce a parentless commit,
    //     which on push replaces the peer's history with a single
    //     dangling root.  See AT.md §"Baseline rule" + the patch row's
    //     extending `<prior>&<theirs>` query for why a baseline row
    //     should always carry at least one 40-hex SHA spec.
    a_pad(u8, brbuf, 256);
    sha1  parents[POST_MAX_PARENTS] = {};
    u32   nparents = 0;
    b8    had_baseline = NO;
    ok64  br = post_collect_parents(brbuf, parents, &nparents,
                                    POST_MAX_PARENTS, &had_baseline);
    if (br != OK) return br;
    if (had_baseline && nparents == 0) {
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
    if (had_baseline && nparents > 0) {
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
            //  Decode the target's 40-hex tip into a sha1 so we can
            //  feed it to GRAFLca alongside parents[0].  A REFS row
            //  whose value isn't a clean 40-hex tip is corrupt — bail
            //  with a diagnostic rather than silently zero-decoding,
            //  which would fall through to a confusing non-ff refusal.
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
            sha1 tip_sha = {};
            u8s bin = {tip_sha.data, tip_sha.data + 20};
            a_dup(u8c, hx, tip_hex);
            ok64 ho = HEXu8sDrainSome(bin, hx);
            if (ho != OK) {
                fprintf(stderr,
                        "sniff: post: REFS row for `?%.*s` has non-hex "
                        "tip\n",
                        (int)u8csLen(branch), (char *)branch[0]);
                return SNIFFFAIL;
            }

            //  ff iff tip is an ancestor of (or equal to) parents[0].
            //  Identity short-circuit: GRAFLca treats the ancestor
            //  set as strict ancestors, so LCA(X, X) returns 0 for
            //  matching shas — handle equality up front.
            //  Otherwise: tip is an ancestor of parents[0] iff
            //  LCA(parents[0], tip) == tip.  GRAFLca zeroes `out`
            //  for unrelated histories — also non-ff.
            b8 ff_ok = NO;
            if (sha1eq(&parents[0], &tip_sha)) {
                ff_ok = YES;
            } else {
                sha1 lca = {};
                (void)GRAFLca(&lca, &parents[0], &tip_sha);
                if (sha1eq(&lca, &tip_sha)) ff_ok = YES;
            }
            if (!ff_ok) {
                a_pad(u8, p0_hex, 40);
                a_rawc(p0_sha, parents[0]);
                HEXu8sFeedSome(p0_hex_idle, p0_sha);
                fprintf(stderr,
                        "sniff: post: target `?%.*s` tip %.*s is "
                        "not an ancestor of wt's base %.*s — "
                        "non-ff\n",
                        (int)u8csLen(branch), (char *)branch[0],
                        (int)$len(tip_hex), (char *)tip_hex[0],
                        40, (char *)u8bDataHead(p0_hex));
                return SNIFFNOFF;
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

    //  6b. Per-file patch parents: in implicit (commit-all) mode, every
    //  patch row whose ts stamps a committed file contributes its
    //  `theirs` to the parent set.  Selective mode skips this — a
    //  cherry-pick is intentionally single-parent.  See VERBS.md §POST.
    if (!ctx.any_pd) {
        ok64 pp = post_add_patch_parents(&ctx, parents, &nparents,
                                         POST_MAX_PARENTS);
        if (pp != OK) { post_ctx_free(&ctx); return pp; }
    }

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
        return SNIFFNOOP;
    }

    //  8. If the result has no files, fall back to the empty-tree sha.
    keep_pack p = {};
    call(KEEPPackOpen, k, &p);
    p.strict_order = NO;

    if (!have_root) {
        call(post_feed_empty_tree, k, &p, &root_tree);
    }

    //  9. Verify each parent commit exists locally; refuse otherwise.
    //     `parents[]` already holds the decoded sha1 bytes from the
    //     baseline row's QURY scan; `post_parent_sha` re-runs the
    //     keeper lookup as a sanity check.
    for (u32 i = 0; i < nparents; i++) {
        a_pad(u8, hx_buf, 40);
        a_rawc(psha_in, parents[i]);
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
        parents[i] = ps;
    }

    //  10. Build commit body.
    Bu8 com = {};
    call(u8bAllocate, com, 4096);
    a_cstr(tree_label, "tree ");
    u8bFeed(com, tree_label);
    a_pad(u8, thex, 40);
    a_rawc(tsha, root_tree);
    HEXu8sFeedSome(thex_idle, tsha);
    u8bFeed(com, u8bDataC(thex));
    u8bFeed1(com, '\n');

    for (u32 i = 0; i < nparents; i++) {
        a_cstr(par_label, "parent ");
        u8bFeed(com, par_label);
        a_pad(u8, par_hex, 40);
        a_rawc(psha, parents[i]);
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

    //  14. Advance keeper REFS for the be-branch the wt is currently
    //      on.  `brbuf` carries the be-side branch path (literal,
    //      opaque); empty = trunk.  REFS key is `?<branch>` (or just
    //      `?` for trunk).  Value is bare 40-hex.
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

        (void)REFSAppendVerb($path(keepdir), REFSVerbPost(), refkey, val);
    }

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

    //  Val is bare 40-hex (canonical).  `post` verb — local ref move.
    return REFSAppendVerb($path(keepdir), REFSVerbPost(), key, sha_hex);
}
