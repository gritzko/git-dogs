//  WALK: tree walker on KEEP.
//
#include "WALK.h"

#include <stdio.h>
#include <string.h>

#include "abc/HEX.h"
#include "abc/PRO.h"
#include "abc/RON.h"
#include "dog/DOG.h"
#include "dog/DPATH.h"
#include "dog/ULOG.h"
#include "GIT.h"

u8 WALKu8sModeKind(u8cs mode) {
    if ($empty(mode)) return 0;
    u8 c0 = $at(mode, 0);
    if (c0 == '4') return WALK_KIND_DIR;
    if (c0 != '1' || $len(mode) < 2) return 0;
    u8 c1 = $at(mode, 1);
    if (c1 == '6') return WALK_KIND_SUB;
    if (c1 == '2') return WALK_KIND_LNK;
    if (c1 == '0') {
        // 100644 vs 100755
        return ($len(mode) >= 6 && $at(mode, 3) == '7')
             ? WALK_KIND_EXE : WALK_KIND_REG;
    }
    return 0;
}

//  Depth-first dive through one tree.  `pathbuf` carries the current
//  path (no leading/trailing '/'), shared across recursion levels.
//  Each level owns its own `tbuf` and per-entry `bbuf` (blob) so
//  nested KEEPGetExact calls don't clobber parent bytes.
static ok64 walk_tree_dive(keeper *k, sha1 const *tree_sha,
                            u8bp pathbuf, b8 eager,
                            walk_tree_fn visit, void0p ctx) {
    sane(k && tree_sha && visit);

    Bu8 tbuf = {};
    call(u8bAllocate, tbuf, 1UL << 20);
    u8 otype = 0;
    ok64 o = KEEPGetExact(k, tree_sha, tbuf, &otype);
    if (o != OK) { u8bFree(tbuf); return o; }
    if (otype != DOG_OBJ_TREE) { u8bFree(tbuf); return WALKBADFMT; }

    u8cs tree_s = {u8bDataHead(tbuf), u8bIdleHead(tbuf)};
    u8cs file = {}, esha = {};
    ok64 result = OK;

    u8 const *tsp = (u8 const *)tree_sha;
    while (GITu8sDrainTree(tree_s, file, esha, NULL) == OK) {
        // Parse "<mode> <name>".
        u8cs scan = {file[0], file[1]};
        if (u8csFind(scan, ' ') != OK) continue;
        u8cs mode_s = {file[0], scan[0]};
        u8cs name_s = {scan[0] + 1, file[1]};
        if ($empty(mode_s) || $empty(name_s)) continue;
        u8 kind = WALKu8sModeKind(mode_s);
        if (kind == 0) continue;
        if (DPATHVerify(name_s) != OK) {
            fprintf(stderr, "walk: bad path '%.*s', skip\n",
                    (int)$len(name_s), (char *)name_s[0]);
            continue;
        }

        // Push "/name" (or just "name" at root) onto pathbuf.
        size_t pre_len = u8bDataLen(pathbuf);
        if (pre_len > 0) {
            if (u8bFeed1(pathbuf, '/') != OK) { result = WALKNOROOM; break; }
        }
        if (u8bFeed(pathbuf, name_s) != OK) { result = WALKNOROOM; break; }
        u8cs path = {u8bDataHead(pathbuf), pathbuf[2]};

        // Eager blob resolve for file-like kinds.
        Bu8 bbuf = {};
        u8cs blob = {};
        b8 is_file = (kind == WALK_KIND_REG || kind == WALK_KIND_EXE ||
                      kind == WALK_KIND_LNK);
        if (eager && is_file) {
            if (u8bAllocate(bbuf, 1UL << 20) == OK) {
                sha1 entry_sha = {};
                sha1Mv(&entry_sha, (sha1cp)esha[0]);
                u8 btype = 0;
                if (KEEPGetExact(k, &entry_sha, bbuf, &btype) == OK &&
                    btype == DOG_OBJ_BLOB) {
                    blob[0] = u8bDataHead(bbuf);
                    blob[1] = u8bIdleHead(bbuf);
                }
            }
        }

        ok64 vo = visit(path, kind, esha[0], blob, ctx);
        if (bbuf[0]) u8bFree(bbuf);

        if (vo == OK && kind == WALK_KIND_DIR) {
            sha1 sub = {};
            sha1Mv(&sub, (sha1cp)esha[0]);
            vo = walk_tree_dive(k, &sub, pathbuf, eager, visit, ctx);
        }

        // Rewind pathbuf to pre-entry length.
        size_t cur_len = u8bDataLen(pathbuf);
        if (cur_len > pre_len) u8bShed(pathbuf, cur_len - pre_len);

        if (vo == WALKSKIP) continue;
        if (vo == WALKSTOP) { result = WALKSTOP; break; }
        if (vo != OK) { result = vo; break; }
    }

    u8bFree(tbuf);
    return result;
}

static ok64 walk_tree_entry(keeper *k, u8cp tree_sha, b8 eager,
                             walk_tree_fn visit, void0p ctx) {
    sane(k && tree_sha && visit);
    a_pad(u8, pathbuf, 2048);
    sha1 root = {};
    sha1Mv(&root, (sha1cp)tree_sha);

    u8cs empty_path = {}, empty_blob = {};
    ok64 vo = visit(empty_path, WALK_KIND_DIR, tree_sha, empty_blob, ctx);
    if (vo == WALKSTOP) return OK;
    if (vo == WALKSKIP) return OK;
    if (vo != OK) return vo;

    ok64 o = walk_tree_dive(k, &root, pathbuf, eager, visit, ctx);
    if (o == WALKSTOP) return OK;
    return o;
}

ok64 WALKTree(keeper *k, u8cp tree_sha, walk_tree_fn visit, void0p ctx) {
    return walk_tree_entry(k, tree_sha, YES, visit, ctx);
}

ok64 WALKTreeLazy(keeper *k, u8cp tree_sha, walk_tree_fn visit, void0p ctx) {
    return walk_tree_entry(k, tree_sha, NO, visit, ctx);
}

//  ls-files: descend an optional /subpath relative to a URI-resolved
//  tree, then walk.  See WALK.h.

//  Wrapper visitor: prepends a fixed prefix (+ '/') to every emitted
//  path so the outward-facing paths remain absolute when the walk
//  itself started at a subtree.
typedef struct {
    walk_tree_fn inner;
    void0p       inner_ctx;
    u8cs         prefix;   // e.g. "drivers/net"  (no trailing '/')
} lsf_prefix_ctx;

static ok64 lsf_prefix_visit(u8cs path, u8 kind, u8cp esha,
                              u8cs blob, void0p ctx) {
    lsf_prefix_ctx *pc = (lsf_prefix_ctx *)ctx;
    if ($empty(pc->prefix)) {
        return pc->inner(path, kind, esha, blob, pc->inner_ctx);
    }
    //  Concatenate "<prefix>" + (empty ? "" : "/" + path).
    a_pad(u8, pbuf, 4096);
    u8bFeed(pbuf, pc->prefix);
    if (!$empty(path)) {
        u8bFeed1(pbuf, '/');
        u8bFeed(pbuf, path);
    }
    a_dup(u8c, full, u8bData(pbuf));
    return pc->inner(full, kind, esha, blob, pc->inner_ctx);
}

//  Descend a '/'-separated subpath from `root_tree`.  On success,
//  *out_sha/*out_kind describe the last resolved entry; *out_prefix
//  gets a slice into `pathbuf` holding the descended prefix (stable
//  until pathbuf is reused).
static ok64 lsf_descend(keeper *k, sha1 const *root_tree, u8cs subpath,
                         u8bp pathbuf, sha1 *out_sha, u8 *out_kind) {
    sane(k && root_tree && out_sha && out_kind);

    sha1 cur_sha = *root_tree;
    u8 cur_kind = WALK_KIND_DIR;

    u8cs scan = {};
    u8csMv(scan, subpath);

    //  Iterate '/'-separated segments.
    while (!$empty(scan)) {
        //  Skip leading '/'.
        while (!$empty(scan) && *scan[0] == '/') scan[0]++;
        if ($empty(scan)) break;

        //  Slice one segment.
        u8cs seg = {scan[0], scan[0]};
        while (seg[1] < scan[1] && *seg[1] != '/') seg[1]++;
        if (seg[0] == seg[1]) break;
        scan[0] = seg[1];  // cursor past segment

        if (cur_kind != WALK_KIND_DIR) return KEEPNONE;

        //  Fetch current tree, scan entries for `seg`.
        Bu8 tbuf = {};
        call(u8bAllocate, tbuf, 1UL << 20);
        u8 otype = 0;
        ok64 o = KEEPGetExact(k, &cur_sha, tbuf, &otype);
        if (o != OK || otype != DOG_OBJ_TREE) { u8bFree(tbuf); return o ? o : KEEPNONE; }

        u8cs tree_s = {u8bDataHead(tbuf), u8bIdleHead(tbuf)};
        b8 found = NO;
        u8 next_kind = 0;
        sha1 next_sha = {};
        u8cs file = {}, esha = {};
        while (GITu8sDrainTree(tree_s, file, esha, NULL) == OK) {
            u8cs fscan = {file[0], file[1]};
            if (u8csFind(fscan, ' ') != OK) continue;
            u8cs mode_s = {file[0], fscan[0]};
            u8cs name_s = {fscan[0] + 1, file[1]};
            if (u8csLen(name_s) != u8csLen(seg)) continue;
            if (memcmp(name_s[0], seg[0], u8csLen(name_s)) != 0) continue;
            next_kind = WALKu8sModeKind(mode_s);
            (void)sha1Drain(esha, &next_sha);
            found = YES;
            break;
        }
        u8bFree(tbuf);
        if (!found || next_kind == 0) return KEEPNONE;

        //  Append to prefix pathbuf.
        if (u8bDataLen(pathbuf) > 0) u8bFeed1(pathbuf, '/');
        u8bFeed(pathbuf, seg);

        cur_sha = next_sha;
        cur_kind = next_kind;
    }

    *out_sha = cur_sha;
    *out_kind = cur_kind;
    done;
}

ok64 KEEPLsFiles(keeper *k, uricp target,
                 walk_tree_fn visit, void0p ctx) {
    sane(k && target && visit);

    //  1. Resolve URI to root tree SHA (commit→tree or tree→tree).
    sha1 root_tree = {};
    call(KEEPResolveTree, k, target, &root_tree);

    //  2. Descend /subpath (URI path, strip leading '/').
    a_pad(u8, prefix_buf, 4096);
    sha1 target_sha = root_tree;
    u8   target_kind = WALK_KIND_DIR;

    u8cs sub = {};
    //  When the URI has an authority, the `path` is the REMOTE-side
    //  repo path (e.g. `/tmp/sv-keep/src`), not a subtree inside the
    //  resolved tree — descending into it would always miss.  The
    //  in-repo subpath, when needed, belongs after a `.git/` split
    //  (see dog/DOG.md); we don't parse that here yet, so authority-
    //  bearing URIs always walk the full tree.
    if (u8csEmpty(target->authority)) {
        u8csMv(sub, target->path);
        //  "." means repo root, same as empty path.
        if (u8csLen(sub) == 1 && *sub[0] == '.') { sub[0] = sub[1]; }
    }
    call(lsf_descend, k, &root_tree, sub,
         prefix_buf, &target_sha, &target_kind);

    //  3. Dispatch: blob → one event; tree → full walk with prefix.
    a_dup(u8c, prefix_s, u8bData(prefix_buf));

    if (target_kind != WALK_KIND_DIR) {
        //  Leaf: emit a single visitor call with the accumulated path.
        u8cs blob = {};
        return visit(prefix_s, target_kind, target_sha.data, blob, ctx);
    }

    //  Tree: walk via WALKTreeLazy, wrapping the visitor to prepend
    //  `prefix_s` + '/' so paths remain absolute from the repo root.
    lsf_prefix_ctx pc = { .inner = visit, .inner_ctx = ctx, .prefix = {}};
    u8csMv(pc.prefix, prefix_s);
    return walk_tree_entry(k, target_sha.data, NO,
                            lsf_prefix_visit, &pc);
}

//  URI → single blob.  Shares the resolve + descend machinery with
//  KEEPLsFiles; differs in that it requires a file leaf and writes its
//  body into the caller's buffer.
ok64 KEEPGetByURI(keeper *k, uricp target, u8bp out) {
    sane(k && target && out);

    //  Host-bearing URI: remote materialization.  Not wired yet —
    //  keeper has KEEPSync/KEEPPush but no policy for deciding what
    //  to pull on demand.  Fail loudly until that's resolved.
    if (!$empty(target->host)) fail(KEEPFAIL);

    //  Neither ?ref nor #sha: nothing to resolve against.  Caller is
    //  expected to fall back to the filesystem.
    if ($empty(target->query) && $empty(target->fragment)) fail(KEEPFAIL);

    //  //?hash — raw blob by hash, no tree descent.  URI has empty
    //  authority and empty path; query is a hex SHA prefix.
    if ($empty(target->path) && !$empty(target->query)) {
        u8 btype = 0;
        u64 hashlet = WHIFFHexHashlet60(target->query);
        u8bReset(out);
        call(KEEPGet, k, hashlet, u8csLen(target->query), out, &btype);
        if (btype != DOG_OBJ_BLOB) fail(KEEPFAIL);
        done;
    }

    sha1 root_tree = {};
    call(KEEPResolveTree, k, target, &root_tree);

    a_pad(u8, prefix_buf, 4096);
    sha1 leaf_sha  = root_tree;
    u8   leaf_kind = WALK_KIND_DIR;

    u8cs sub = {};
    u8csMv(sub, target->path);
    if (u8csLen(sub) == 1 && *sub[0] == '.') { sub[0] = sub[1]; }
    call(lsf_descend, k, &root_tree, sub,
         prefix_buf, &leaf_sha, &leaf_kind);

    if (leaf_kind == WALK_KIND_DIR) fail(KEEPFAIL);

    u8 btype = 0;
    call(KEEPGetExact, k, &leaf_sha, out, &btype);
    if (btype != DOG_OBJ_BLOB) fail(KEEPNONE);
    done;
}

// --- KEEPTreeULog: emit leaves as ULOG rows -------------------------

typedef struct {
    u8bp  out;
    ron60 ts;
    ron60 verb;
    ok64  err;
} treeulog_ctx;

//  Map WALK_KIND_* to a single RON64 letter that appends to the
//  caller's verb stem: f=regular, x=executable, l=symlink,
//  s=submodule.  Returns 0 for kinds with no leaf row (DIR/unknown).
static u8 treeulog_kind_letter(u8 kind) {
    switch (kind) {
        case WALK_KIND_REG: return RON_f;
        case WALK_KIND_EXE: return RON_x;
        case WALK_KIND_LNK: return RON_l;
        case WALK_KIND_SUB: return RON_s;
        default:            return 0;
    }
}

static ok64 treeulog_visit(u8cs path, u8 kind, u8cp esha, u8cs blob,
                           void0p vctx) {
    (void)blob;
    treeulog_ctx *c = (treeulog_ctx *)vctx;

    //  TODO(delta-trees): emit a `dir`-kind row for WALK_KIND_DIR with
    //  the subtree SHA in the fragment so sniff/POST.c:post_build_tree
    //  can pick up the parent commit's same-path tree SHA per prefix
    //  and pass it as KEEPPackFeed's base_hashlet60 (currently 0 at
    //  POST.c:2310 — see TODO there).  Today we only emit leaf rows,
    //  which is why the on-write delta path stays unused for trees.
    if (kind == WALK_KIND_DIR) return OK;       // root + subtrees skipped
    u8 kletter = treeulog_kind_letter(kind);
    if (kletter == 0) return OK;                // unknown kind, skip

    //  Hex-encode the 20-byte leaf sha into a stack buffer used as the
    //  fragment slice.
    a_pad(u8, hex_buf, 40);
    {
        u8cs bin = {esha, esha + 20};
        a_dup(u8c, bin_dup, bin);
        HEXu8sFeedSome(u8bIdle(hex_buf), bin_dup);
    }

    uri u = {};
    u8csMv(u.path, path);
    u8csMv(u.fragment, u8bDataC(hex_buf));

    ulogrec rec = {.ts   = c->ts,
                   .verb = ok64sub(c->verb, kletter),
                   .uri  = u};
    ok64 o = ULOGu8sFeed(u8bIdle(c->out), &rec);
    if (o != OK) { c->err = o; return WALKSTOP; }

    //  Submodule entries are leaves but not recursable.
    if (kind == WALK_KIND_SUB) return WALKSKIP;
    return OK;
}

ok64 KEEPTreeULog(keeper *k, u8cp tree_sha,
                  ron60 ts, ron60 verb, u8bp out) {
    sane(k && tree_sha && out);
    u8bReset(out);
    treeulog_ctx c = {.out = out, .ts = ts, .verb = verb, .err = OK};
    ok64 o = WALKTreeLazy(k, tree_sha, treeulog_visit, &c);
    if (o != OK) return o;
    return c.err;
}

// --- KEEPTreeDiff: tree-vs-tree as a diff ULOG ----------------------
//
//  Build two side-tagged ULOGs via KEEPTreeULog, merge them through
//  ULOGMergeWalk grouped by path, and emit add/del/mod rows into the
//  caller's `out` buffer.  ULOG row layout matches POST's decision-
//  log shape so downstream consumers stay uniform.

typedef struct {
    u8bp  out;
    ron60 v_add;
    ron60 v_del;
    ron60 v_mod;
    ron60 v_a;          // side-tag for the `sha_a` cursor
    ron60 v_b;          // side-tag for the `sha_b` cursor
    ok64  err;
} treediff_ctx;

//  Append a diff row to `out`.  `verb_stem` is one of v_add / v_del /
//  v_mod; we preserve the kind letter from the source row so callers
//  can recover (mode, kind) downstream.
static ok64 treediff_emit(treediff_ctx *c, ron60 verb_stem,
                          ulogreccp src,
                          u8cs old_hex, u8cs new_hex) {
    sane(c && src);
    //  Kind letter rides in the bottom RON digit of the source verb;
    //  re-attach it to the diff verb stem.
    u8 kletter = (u8)ok64Lit(src->verb, 0);
    ron60 verb = (kletter != 0) ? ok64sub(verb_stem, kletter)
                                 : verb_stem;

    uri u = {};
    u8csMv(u.path, src->uri.path);
    if (!u8csEmpty(old_hex)) u8csMv(u.query,    old_hex);
    if (!u8csEmpty(new_hex)) u8csMv(u.fragment, new_hex);

    ulogrec rec = {.ts = 0, .verb = verb, .uri = u};
    return ULOGu8sFeed(u8bIdle(c->out), &rec);
}

static ok64 treediff_step(ulogreccp recs, u32 n, void *ctx) {
    treediff_ctx *c = (treediff_ctx *)ctx;
    sane(c && recs && n > 0);

    //  Identify A / B rows in the tie group by side-tag stem.
    ulogreccp a = NULL;
    ulogreccp b = NULL;
    for (u32 i = 0; i < n; i++) {
        ron60 stem = ok64stem(recs[i].verb);
        if      (stem == c->v_a && a == NULL) a = &recs[i];
        else if (stem == c->v_b && b == NULL) b = &recs[i];
    }

    u8cs empty = {};
    ok64 fo = OK;
    if (a == NULL && b != NULL) {
        u8cs nh = {b->uri.fragment[0], b->uri.fragment[1]};
        fo = treediff_emit(c, c->v_add, b, empty, nh);
    } else if (a != NULL && b == NULL) {
        u8cs oh = {a->uri.fragment[0], a->uri.fragment[1]};
        fo = treediff_emit(c, c->v_del, a, empty, oh);
    } else if (a != NULL && b != NULL) {
        u8cs oh = {a->uri.fragment[0], a->uri.fragment[1]};
        u8cs nh = {b->uri.fragment[0], b->uri.fragment[1]};
        //  Equal-and-same: same kind letter on both verbs AND same
        //  fragment (leaf sha) → no row.  Anything else is `mod`.
        b8 kind_eq = (ok64Lit(a->verb, 0) == ok64Lit(b->verb, 0));
        b8 sha_eq  = ($len(oh) == $len(nh)) &&
                     (u8csEmpty(oh) ||
                      memcmp(oh[0], nh[0], (size_t)$len(oh)) == 0);
        if (kind_eq && sha_eq) return OK;
        //  Use B's kind letter on the `mod` row (the new state wins).
        fo = treediff_emit(c, c->v_mod, b, oh, nh);
    }
    if (fo != OK) c->err = fo;
    return fo;
}

ok64 KEEPTreeDiff(u8cp sha_a, u8cp sha_b, u8bp out) {
    sane(out);
    u8bReset(out);

    //  RON-encode side tags + output verbs once.
    a_cstr(s_a,   "a");   a_dup(u8c, dva,   s_a);
    a_cstr(s_b,   "b");   a_dup(u8c, dvb,   s_b);
    a_cstr(s_add, "add"); a_dup(u8c, dvadd, s_add);
    a_cstr(s_del, "del"); a_dup(u8c, dvdel, s_del);
    a_cstr(s_mod, "mod"); a_dup(u8c, dvmod, s_mod);
    ron60 v_a = 0, v_b = 0, v_add = 0, v_del = 0, v_mod = 0;
    call(RONutf8sDrain, &v_a,   dva);
    call(RONutf8sDrain, &v_b,   dvb);
    call(RONutf8sDrain, &v_add, dvadd);
    call(RONutf8sDrain, &v_del, dvdel);
    call(RONutf8sDrain, &v_mod, dvmod);

    Bu8 ula = {}, ulb = {};
    call(u8bAllocate, ula, 1UL << 20);
    if (u8bAllocate(ulb, 1UL << 20) != OK) { u8bFree(ula); fail(WALKFAIL); }

    if (sha_a != NULL) {
        ok64 ar = KEEPTreeULog(&KEEP, sha_a, 0, v_a, ula);
        if (ar != OK) { u8bFree(ula); u8bFree(ulb); return ar; }
    }
    if (sha_b != NULL) {
        ok64 br = KEEPTreeULog(&KEEP, sha_b, 0, v_b, ulb);
        if (br != OK) { u8bFree(ula); u8bFree(ulb); return br; }
    }

    //  Build the cursor array — two slices over the row buffers.
    u8cs cur[2] = {};
    u8csMv(cur[0], u8bDataC(ula));
    u8csMv(cur[1], u8bDataC(ulb));
    u8css cursors = {cur, cur + 2};

    treediff_ctx ctx = {
        .out = out, .v_add = v_add, .v_del = v_del, .v_mod = v_mod,
        .v_a = v_a, .v_b = v_b, .err = OK,
    };
    ok64 mo = ULOGMergeWalk(cursors, treediff_step, &ctx);

    u8bFree(ula);
    u8bFree(ulb);
    if (mo != OK) return mo;
    return ctx.err;
}
