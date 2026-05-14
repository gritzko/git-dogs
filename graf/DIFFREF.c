//  URI-driven diff: file or whole tree, ref vs wt or ref vs ref.
//  Companion to DIFF.c (file-pair) and BLAME.c (weave).
//
#include "GRAF.h"
#include "graf/BLOB.h"
#include "graf/WEAVE.h"

#include <stdio.h>
#include <string.h>

#include "abc/FILE.h"
#include "abc/HEX.h"
#include "abc/PATH.h"
#include "abc/PRO.h"
#include "abc/RON.h"
#include "abc/URI.h"
#include "dog/DOG.h"
#include "dog/HUNK.h"
#include "dog/IGNO.h"
#include "dog/ULOG.h"
#include "keeper/KEEP.h"
#include "keeper/WALK.h"

#define DIFFREF_PATH_MAX  256
//  Cap for the ref-vs-ref tree diff (`diff:?from#to`).  The wt-vs-base
//  path streams from the visitor (no cap), but ref-vs-ref needs both
//  trees in memory to pair entries by path before diffing.
#define DIFFREF_MAX_FILES 8192

typedef struct {
    u8cs path;       //  borrowed: lives in set's arena
    sha1 sha;
} diffref_entry;

typedef struct {
    diffref_entry *v;
    u32            n;
    u32            cap;
    u32            overflow;
    Bu8            arena;     //  path bytes; owns backing
} diffref_set;

static ok64 diffref_set_push(diffref_set *s, u8cs path, u8cp esha) {
    sane(s);
    if (s->n >= s->cap) { s->overflow++; done; }
    if (u8csEmpty(path) || u8csLen(path) >= DIFFREF_PATH_MAX) {
        s->overflow++; done;
    }
    diffref_entry *e = &s->v[s->n++];
    if (u8bFeed(s->arena, path) != OK) {
        s->n--; s->overflow++; done;
    }
    u8csMv(e->path, u8bDataC(s->arena));
    (void)u8csUsedAll(u8bDataC(s->arena));
    sha1Mv(&e->sha, (sha1cp)esha);
    done;
}

//  Compose `<lead><ref>` into `ubuf`.  `#` for an all-hex ref (full or
//  short sha — KEEPResolveTree's fragment branch handles both, with
//  `WHIFFHexHashlet60` driving keeper's prefix lookup); `?` for ref
//  names (`tags/v1`, `heads/main`) which go through REFS.
static b8 ref_is_hex(u8cs ref) {
    if ($empty(ref)) return NO;
    for (u8cp p = ref[0]; p < ref[1]; p++) {
        u8 c = *p;
        b8 d = (c >= '0' && c <= '9');
        b8 lo = (c >= 'a' && c <= 'f');
        b8 up = (c >= 'A' && c <= 'F');
        if (!d && !lo && !up) return NO;
    }
    return YES;
}

static ok64 diffref_compose_ref_uri(u8bp ubuf, u8cs ref) {
    sane(ubuf);
    u8 lead = ref_is_hex(ref) ? '#' : '?';
    call(u8bFeed1, ubuf, lead);
    call(u8bFeed,  ubuf, ref);
    done;
}

static diffref_entry *diffref_set_find(diffref_set *s, u8cs path) {
    for (u32 i = 0; i < s->n; i++) {
        u8csc entry = {s->v[i].path[0], s->v[i].path[1]};
        if (u8csEq(entry, path)) return &s->v[i];
    }
    return NULL;
}

// --- Shared: load blob at ref+path via KEEPGetByURI ---------------

static ok64 diffref_load_blob(Bu8 out, keeper *k, u8cs path, u8cs ref) {
    sane(k);
    a_pad(u8, ubuf, DIFFREF_PATH_MAX + 128);
    if (!$empty(path)) call(u8bFeed, ubuf, path);
    call(diffref_compose_ref_uri, ubuf, ref);
    a_dup(u8c, udata, u8bData(ubuf));
    uri target = {};
    call(URIutf8Drain, udata, &target);
    u8bReset(out);
    call(KEEPGetByURI, k, &target, out);
    done;
}

// --- Shared: mmap wt file (ok to fail with FILEOPEN → empty) ------

static ok64 diffref_load_wt(u8bp *mapped, u8cs out_data,
                             u8cs reporoot, u8cs path) {
    sane(mapped);
    a_path(fp, reporoot, path);
    ok64 o = FILEMapRO(mapped, $path(fp));
    if (o != OK) { out_data[0] = NULL; out_data[1] = NULL; return o; }
    out_data[0] = u8bDataHead(*mapped);
    out_data[1] = u8bIdleHead(*mapped);
    done;
}

// --- 2-layer weave diff -------------------------------------------
//
//  The single primitive every diff path uses (wt-vs-base, ref-vs-ref
//  file, ref-vs-ref tree per-file).  Builds a 2-layer weave from
//  `from_data` (older) + `to_data` (newer) — `WEAVEFromBlob` ×2 +
//  `WEAVEDiff` (LCS + NEIL + canon) — then `WEAVEEmitDiff` walks the
//  resulting `inrm` stream and emits hunks with context, syntax tags,
//  and `I`/`D`/` ` hili.
//
//  Sentinel ids: `from` layer uses `WEAVE_BASE_SRC` (any value other
//  than `WEAVE_WT_SRC` works); `to` layer uses `WEAVE_WT_SRC`.  The
//  predicates are the same as for wt-vs-base — `to` is treated as
//  "the next version after `from`" regardless of whether it's the
//  worktree or another commit's blob.

#define WEAVE_BASE_SRC 1u

static b8 wt_in_from(u32 c, void *ctx) {
    (void)ctx;
    return c != WEAVE_WT_SRC;
}
static b8 wt_in_to(u32 c, void *ctx) {
    (void)ctx; (void)c;
    return YES;
}

ok64 GRAFDiff2Layer(u8cs name, u8cs ext, u8cs from_data, u8cs to_data) {
    sane($ok(name));

    //  Fast skip on byte-identical content.  Cheap u8csEq before any
    //  tokenisation; the common case in tree walks.
    if (u8csEq(from_data, to_data)) return OK;

    call(GRAFArenaInit);

    weave wA = {}, wB = {}, wnu = {};
    if (WEAVEInit(&wA)  != OK ||
        WEAVEInit(&wB)  != OK ||
        WEAVEInit(&wnu) != OK) {
        WEAVEFree(&wA); WEAVEFree(&wB); WEAVEFree(&wnu);
        GRAFArenaCleanup();
        return NOROOM;
    }
    weave *wsrc = &wA, *wdst = &wB;

    ok64 ret = WEAVEFromBlob(wsrc, from_data, ext, WEAVE_BASE_SRC);
    if (ret == OK) ret = WEAVEFromBlob(&wnu, to_data, ext, WEAVE_WT_SRC);
    if (ret == OK) ret = WEAVEDiff(wdst, wsrc, &wnu, WEAVE_WT_SRC);
    if (ret == OK) {
        wsrc = wdst;
        ret = WEAVEEmitDiff(wsrc, name,
                            wt_in_from, NULL,
                            wt_in_to,   NULL,
                            GRAFHunkEmit, NULL);
    }

    WEAVEFree(&wA);
    WEAVEFree(&wB);
    WEAVEFree(&wnu);
    GRAFArenaCleanup();
    return ret;
}

// --- wt-vs-base file: thin wrapper around GRAFDiff2Layer -----------

ok64 GRAFDiffWtFile(keeper *k, u8cs filepath, u64 base_h40, u8cs reporoot) {
    sane(k && $ok(filepath) && $ok(reporoot));

    Bu8 base_buf = {};
    call(u8bMap, base_buf, 16UL << 20);
    ok64 bo = GRAFBlobAtCommit(base_buf, k, base_h40, filepath);
    u8cs from_data = {};
    if (bo == OK) {
        a_dup(u8c, fd, u8bData(base_buf));
        u8csMv(from_data, fd);
    }

    a_path(wt_path, reporoot, filepath);
    u8bp wt_mapped = NULL;
    u8cs to_data = {};
    ok64 wto = FILEMapRO(&wt_mapped, $path(wt_path));
    if (wto == OK && wt_mapped) {
        a_dup(u8c, td, u8bData(wt_mapped));
        u8csMv(to_data, td);
    }

    u8cs ext = {};
    PATHu8sExt(ext, filepath);
    ok64 ret = GRAFDiff2Layer(filepath, ext, from_data, to_data);

    if (wt_mapped) FILEUnMap(wt_mapped);
    u8bUnMap(base_buf);
    return ret;
}

// --- Shared collect-into-set visitor (ref-vs-ref tree path) -------

typedef struct {
    diffref_set *set;
} diffref_collect_ctx;

static ok64 diffref_collect_visit(u8cs path, u8 kind, u8cp esha,
                                   u8cs blob, void0p ctx) {
    (void)blob;
    diffref_collect_ctx *c = (diffref_collect_ctx *)ctx;
    if (kind == WALK_KIND_REG || kind == WALK_KIND_EXE ||
        kind == WALK_KIND_LNK) {
        diffref_set_push(c->set, path, esha);
    }
    return OK;
}

// --- Whole tree, wt vs base ---------------------------------------
//
//  Two ULOG streams — base via `KEEPTreeULog`, wt via `ULOGu8bScanWt`
//  — heap-merged by URI key with `ULOGMergeWalk`.  Per distinct path:
//    BOTH       compare base sha (in base row's `#fragment`) against a
//               freshly-computed wt sha; equal → skip, differ → run
//               the 2-layer weave diff.
//    BASE_ONLY  file deleted in wt → 2-layer weave diff with empty wt.
//    WT_ONLY    file added in wt   → 2-layer weave diff with empty base.
//
//  Sha-skip pays for every unchanged file: one mmap + one SHA1 vs a
//  full keeper blob fetch + tokenize + diff.

//  Skip predicate for the wt scanner.  `IGNOMatch` already handles
//  unconditional `.git/.be/.be/wtlog` skipping (at any depth, including
//  nested submodule `.git/`s) AND any `.gitignore` patterns the
//  caller loaded into the `igno` struct via `IGNOLoad(reporoot)`.
static b8 diffref_wt_skip(u8cs rel, void *ctx) {
    return IGNOMatch((ignocp)ctx, rel, NO);
}

typedef struct {
    keeper *k;
    u64     base_h40;
    u8cs    reporoot;
    ron60   v_base;
    ron60   v_wt;
    Bu8     sub_prefixes;   // newline-separated `<path>/`
    b8      sub_init;
} diffref_wt_ctx;

//  Submodule descendant filter — same pattern as sniff/CLASS.c.  When
//  the merge surfaces a gitlink row (mode `160000` in the base tree),
//  we remember `<path>/` and drop every subsequent step whose path
//  starts with that prefix.  Lex order guarantees the gitlink row
//  arrives before any of its descendants, so a single forward scan of
//  remembered prefixes is sufficient.

static b8 diffref_under_submodule(diffref_wt_ctx const *c, u8cs path) {
    if (!c->sub_init) return NO;
    a_dup(u8c, scan, u8bDataC(c->sub_prefixes));
    while (!u8csEmpty(scan)) {
        u8cs prefix = {};
        u8csMv(prefix, scan);
        a_dup(u8c, find, scan);
        if (u8csFind(find, '\n') != OK) break;
        prefix[1] = find[0];
        if (!u8csEmpty(prefix) && u8csHasPrefix(path, prefix)) return YES;
        u8csUsed1(find);
        u8csMv(scan, find);
    }
    return NO;
}

static ok64 diffref_remember_submodule(diffref_wt_ctx *c, u8cs path) {
    if (!c->sub_init) {
        ok64 ao = u8bAllocate(c->sub_prefixes, 1UL << 12);
        if (ao != OK) return ao;
        c->sub_init = YES;
    }
    (void)u8bFeed(c->sub_prefixes, path);
    (void)u8bFeed1(c->sub_prefixes, '/');
    (void)u8bFeed1(c->sub_prefixes, '\n');
    return OK;
}

static ok64 diffref_wt_step(ulogreccp recs, u32 n, void *ctx_) {
    diffref_wt_ctx *c = (diffref_wt_ctx *)ctx_;
    ulogreccp base = NULL, wt = NULL;
    for (u32 i = 0; i < n; i++) {
        if      (ok64stem(recs[i].verb) == c->v_base) base = &recs[i];
        else if (ok64stem(recs[i].verb) == c->v_wt)   wt   = &recs[i];
    }
    //  Wt-only rows are untracked files (no entry in the baseline
    //  tree).  They have no `from` side to diff against, so skip
    //  them — `be diff:` is wt-vs-baseline, not wt-vs-empty.
    if (!base) return OK;

    u8cs path = {};
    u8csMv(path, base->uri.path);
    if ($empty(path) || $len(path) >= DIFFREF_PATH_MAX) return OK;

    //  Drop wt-side rows that descend into a previously-recorded
    //  submodule (the embedded repo's own files have no business in
    //  this tree's diff).
    if (diffref_under_submodule(c, path)) return OK;

    //  Submodules / gitlink trees: remember the path as a prefix to
    //  filter, then drop the row itself.
    if (base != NULL && ok64Lit(base->verb, 0) == RON_s) {
        (void)diffref_remember_submodule(c, path);
        return OK;
    }

    //  BOTH: sha-skip.  Hash wt bytes once and compare with the base
    //  entry's `#<sha>` fragment.  Equal → no diff.
    if (base != NULL && wt != NULL) {
        a_path(wt_path, c->reporoot, path);
        u8bp wt_mapped = NULL;
        if (FILEMapRO(&wt_mapped, $path(wt_path)) == OK && wt_mapped) {
            a_dup(u8c, wd, u8bDataC(wt_mapped));
            sha1 wt_sha = {};
            KEEPObjSha(&wt_sha, DOG_OBJ_BLOB, wd);
            sha1 base_sha = {};
            u8s sb = {base_sha.data, base_sha.data + 20};
            a_dup(u8c, hx, base->uri.fragment);
            b8 same = (HEXu8sDrainSome(sb, hx) == OK &&
                       sha1Eq(&wt_sha, &base_sha));
            FILEUnMap(wt_mapped);
            if (same) return OK;
        }
    }

    //  Real diff.  GRAFDiffWtFile handles the empty-base / empty-wt
    //  edge cases internally (deletion / addition both emit hunks).
    (void)GRAFDiffWtFile(c->k, path, c->base_h40, c->reporoot);
    return OK;
}

#define DIFFREF_WT_BASE_BUF (1UL << 20)
#define DIFFREF_WT_WT_BUF   (1UL << 20)

ok64 GRAFDiffWtTree(keeper *k, u64 base_h40, u8cs base_hex, u8cs reporoot) {
    sane(k && $ok(base_hex) && $ok(reporoot));

    //  Resolve base hex to its tree sha.
    a_pad(u8, ubuf, 256);
    call(diffref_compose_ref_uri, ubuf, base_hex);
    a_dup(u8c, udata, u8bData(ubuf));
    uri target = {};
    call(URIutf8Drain, udata, &target);
    sha1 base_tree = {};
    call(KEEPResolveTree, k, &target, &base_tree);

    a_cstr(s_base, "base");
    a_cstr(s_wt,   "wt");
    ron60 v_base = 0, v_wt = 0;
    {
        a_dup(u8c, sb, s_base); RONutf8sDrain(&v_base, sb);
        a_dup(u8c, sw, s_wt);   RONutf8sDrain(&v_wt,   sw);
    }

    Bu8 bu = {}, wu = {};
    ok64 mb = u8bMap(bu, DIFFREF_WT_BASE_BUF);
    ok64 mw = u8bMap(wu, DIFFREF_WT_WT_BUF);
    if (mb != OK || mw != OK) {
        if (bu[0]) u8bUnMap(bu);
        if (wu[0]) u8bUnMap(wu);
        return (mb != OK) ? mb : mw;
    }

    //  Base side: keeper tree → ULOG rows (`<ts>\t<verb>\t<path>?<mode>#<hex-sha>\n`).
    ok64 to = KEEPTreeULog(k, base_tree.data, 0, v_base, bu);
    if (to != OK) { u8bUnMap(bu); u8bUnMap(wu); return to; }

    //  Wt side: filesystem walk → ULOG rows (no sha; computed on demand).
    //  Load reporoot's `.gitignore` so build/Corpus/etc. drop out; the
    //  meta dirs (`.git/.be/.be/wtlog`) are filtered by IGNOMatch
    //  unconditionally even with no `.gitignore` present.
    igno ig = {};
    a_dup(u8c, ig_root, reporoot);
    (void)IGNOLoad(&ig, ig_root);
    ok64 wo = ULOGu8bScanWt(reporoot, v_wt,
                             diffref_wt_skip, &ig, wu);
    if (wo != OK) { IGNOFree(&ig); u8bUnMap(bu); u8bUnMap(wu); return wo; }

    //  Heap-merge by URI key, fan to the per-path step.
    a_dup(u8c, view_b, u8bData(bu));
    a_dup(u8c, view_w, u8bData(wu));
    a_pad(u8cs, ins, 2);
    u8csbFeed1(ins, view_b);
    u8csbFeed1(ins, view_w);
    a_dup(u8cs, cursors, u8csbData(ins));

    diffref_wt_ctx ctx = {.k = k, .base_h40 = base_h40,
                          .reporoot = {}, .v_base = v_base, .v_wt = v_wt};
    u8csMv(ctx.reporoot, reporoot);
    ok64 mr = ULOGMergeWalk(cursors, diffref_wt_step, &ctx);

    if (ctx.sub_init) u8bFree(ctx.sub_prefixes);
    IGNOFree(&ig);
    u8bUnMap(bu);
    u8bUnMap(wu);
    return mr;
}

// --- Whole tree, ref vs ref ---------------------------------------

//  Inner worker — every early `call()` returns through here, so the
//  outer wrapper's cleanup runs on success and on every error path.
//  Buffers/arenas are caller-owned: the wrapper allocs/maps before
//  calling, frees/unmaps after, regardless of the inner's outcome.
static ok64 graf_diff_tree_refs_inner(keeper *k, u8cs from, u8cs to,
                                      diffref_set *from_set,
                                      diffref_set *to_set,
                                      Bu8 old_buf, Bu8 new_buf) {
    sane(k && from_set && to_set);

    // --- 1. Walk `from`, collect ---
    a_pad(u8, fbuf, 256);
    call(diffref_compose_ref_uri, fbuf, from);
    a_dup(u8c, fdata, u8bData(fbuf));
    uri ftarget = {};
    call(URIutf8Drain, fdata, &ftarget);
    diffref_collect_ctx fctx = {.set = from_set};
    call(KEEPLsFiles, k, &ftarget, diffref_collect_visit, &fctx);

    // --- 2. Walk `to`, collect ---
    a_pad(u8, tbuf, 256);
    call(diffref_compose_ref_uri, tbuf, to);
    a_dup(u8c, tdata, u8bData(tbuf));
    uri ttarget = {};
    call(URIutf8Drain, tdata, &ttarget);
    diffref_collect_ctx tctx = {.set = to_set};
    call(KEEPLsFiles, k, &ttarget, diffref_collect_visit, &tctx);

    if (from_set->overflow || to_set->overflow) {
        fprintf(stderr, "graf: diff-tree: files skipped (>%u limit)\n",
                (u32)DIFFREF_MAX_FILES);
    }

    // --- 3. For each to-entry, diff against matching from-entry ---
    for (u32 i = 0; i < to_set->n; i++) {
        u8cs path = {};
        u8csMv(path, to_set->v[i].path);
        diffref_entry *f = diffref_set_find(from_set, path);

        // Same sha on both sides → unchanged, skip cheaply.
        if (f && sha1Eq(&f->sha, &to_set->v[i].sha)) continue;

        u8cs old_data = {}, new_data = {};
        if (f) {
            u8bReset(old_buf);
            u8 ot = 0;
            if (KEEPGetExact(k, &f->sha, old_buf, &ot) == OK && ot == DOG_OBJ_BLOB) {
                a_dup(u8c, old_dup, u8bData(old_buf));
                u8csMv(old_data, old_dup);
            }
        }
        u8bReset(new_buf);
        u8 nt = 0;
        if (KEEPGetExact(k, &to_set->v[i].sha, new_buf, &nt) == OK && nt == DOG_OBJ_BLOB) {
            a_dup(u8c, new_dup, u8bData(new_buf));
            u8csMv(new_data, new_dup);
        }

        u8cs ext = {};
        PATHu8sExt(ext, path);
        GRAFDiff2Layer(path, ext, old_data, new_data);
    }

    // --- 4. from-only entries (deletions): diff blob vs empty ---
    for (u32 i = 0; i < from_set->n; i++) {
        u8cs path = {};
        u8csMv(path, from_set->v[i].path);
        if (diffref_set_find(to_set, path) != NULL) continue;

        u8bReset(old_buf);
        u8 ot = 0;
        if (KEEPGetExact(k, &from_set->v[i].sha, old_buf, &ot) != OK || ot != DOG_OBJ_BLOB)
            continue;
        a_dup(u8c, old_data, u8bData(old_buf));
        u8cs new_data = {};
        u8cs ext = {};
        PATHu8sExt(ext, path);
        GRAFDiff2Layer(path, ext, old_data, new_data);
    }
    done;
}

ok64 GRAFDiffTreeRefs(keeper *k, u8cs from, u8cs to, u8cs reporoot) {
    sane(k && $ok(from) && $ok(to));
    (void)reporoot;

    //  Caller-owned storage so cleanup runs on every error path the
    //  inner returns through.  Each Bu8 stays zero until its alloc/map
    //  succeeds; the trailing free/unmap branch on each is gated on
    //  that — leaks on KEEPLsFiles ⇒ KEEPNONE etc are eliminated.
    diffref_entry from_entries[DIFFREF_MAX_FILES];
    diffref_set from_set = {.v = from_entries, .cap = DIFFREF_MAX_FILES};
    diffref_entry to_entries[DIFFREF_MAX_FILES];
    diffref_set to_set = {.v = to_entries, .cap = DIFFREF_MAX_FILES};
    Bu8 old_buf = {}, new_buf = {};

    ok64 ret = u8bAllocate(from_set.arena,
                           DIFFREF_MAX_FILES * DIFFREF_PATH_MAX);
    if (ret == OK)
        ret = u8bAllocate(to_set.arena,
                          DIFFREF_MAX_FILES * DIFFREF_PATH_MAX);
    if (ret == OK) ret = u8bMap(old_buf, 16UL << 20);
    if (ret == OK) ret = u8bMap(new_buf, 16UL << 20);
    if (ret == OK)
        ret = graf_diff_tree_refs_inner(k, from, to,
                                        &from_set, &to_set,
                                        old_buf, new_buf);

    if (new_buf[0])        u8bUnMap(new_buf);
    if (old_buf[0])        u8bUnMap(old_buf);
    if (to_set.arena[0])   u8bFree(to_set.arena);
    if (from_set.arena[0]) u8bFree(from_set.arena);
    return ret;
}
