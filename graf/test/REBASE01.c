//
//  REBASE01 — Property tests for the rebase primitives.
//
//  Tag matrix (matches the spec):
//    (a) PatchId same-body-twice           → equal ids
//    (b) PatchId different diffs           → different ids
//    (c) PatchId same diff, diff parent    → equal ids (rebase invariance)
//    (d) PatchId empty diff (= parent)     → 0
//    (e) MergeExplicit base==ours          → output = theirs
//    (f) MergeExplicit base==theirs        → output = ours
//    (g) MergeExplicit non-conflicting     → merged contains both edits
//    (h) MergeExplicit conflicting         → output has '<<<<' markers
//    (i) Rebase child_tip == base_old      → no emits, head = base_new
//    (j) Rebase single new commit          → 2 emits (tree, commit)
//    (k) Rebase patch-id collision         → second commit skipped
//    (l) Rebase conflict                   → GRAFCNFL, no emits past it
//
#include "graf/REBASE.h"

#include "graf/GRAF.h"
#include "graf/JOIN.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "abc/FILE.h"
#include "abc/HEX.h"
#include "abc/PATH.h"
#include "abc/PRO.h"
#include "abc/TEST.h"
#include "dog/DOG.h"
#include "dog/HOME.h"
#include "keeper/KEEP.h"

// --- Tiny test harness ----------------------------------------------------

static char g_tmp[256];
static home g_home;

static ok64 setup_repo(void) {
    sane(1);
    call(FILEInit);
    snprintf(g_tmp, sizeof(g_tmp), "/tmp/grafrebase-XXXXXX");
    want(mkdtemp(g_tmp) != NULL);
    a_cstr(root, g_tmp);
    memset(&g_home, 0, sizeof(g_home));
    call(HOMEOpen, &g_home, root, YES);
    call(KEEPOpen, &g_home, YES);
    done;
}

static void teardown_repo(void) {
    KEEPClose();
    HOMEClose(&g_home);
    char cmd[300];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", g_tmp);
    system(cmd);
}

//  Build a tiny single-leaf tree carrying one blob "<mode> <name>" → bsha.
static ok64 make_single_leaf_tree(keep_pack *p,
                                  char const *mode_name,
                                  char const *content,
                                  sha1 *blob_out, sha1 *tree_out) {
    sane(p && blob_out && tree_out);
    u8cs cb = {(u8cp)content, (u8cp)content + strlen(content)};
    call(KEEPPackFeed, &KEEP, p, DOG_OBJ_BLOB, cb, 0, blob_out);
    a_pad(u8, tb, 256);
    a_cstr(mn, mode_name);
    call(u8bFeed, tb, mn);
    u8bFeed1(tb, 0);
    a_rawc(ss, *blob_out);
    call(u8bFeed, tb, ss);
    a_dup(u8c, tc, u8bData(tb));
    call(KEEPPackFeed, &KEEP, p, DOG_OBJ_TREE, tc, 0, tree_out);
    done;
}

//  Build a commit body: "tree <hex>\n[parent <hex>\n]author ...\ncommitter ...\n\nmsg\n"
static void make_commit_body(u8 *const *out,
                             sha1 const *tree_sha,
                             sha1 const *parent_sha,        //  NULL for root
                             char const *author_id,
                             long ts,
                             char const *msg) {
    a_cstr(tl, "tree ");
    u8bFeed(out, tl);
    a_pad(u8, thx, 40);
    a_rawc(ts2, *tree_sha);
    HEXu8sFeedSome(thx_idle, ts2);
    u8bFeed(out, u8bDataC(thx));
    u8bFeed1(out, '\n');

    if (parent_sha != NULL) {
        a_cstr(pl, "parent ");
        u8bFeed(out, pl);
        a_pad(u8, phx, 40);
        a_rawc(ps, *parent_sha);
        HEXu8sFeedSome(phx_idle, ps);
        u8bFeed(out, u8bDataC(phx));
        u8bFeed1(out, '\n');
    }

    char hdr[256];
    int n = snprintf(hdr, sizeof(hdr),
                     "author %s %ld +0000\ncommitter %s %ld +0000\n\n%s\n",
                     author_id, ts, author_id, ts, msg);
    u8cs hs = {(u8cp)hdr, (u8cp)hdr + n};
    u8bFeed(out, hs);
}

//  Feed a synthetic commit to keeper with a given (tree, parent) pair,
//  return its sha.  Borrows `p` already opened by caller.
static ok64 feed_commit(keep_pack *p,
                        sha1 const *tree_sha, sha1 const *parent_sha,
                        char const *author_id, long ts, char const *msg,
                        sha1 *out_sha) {
    sane(p && out_sha);
    Bu8 cb = {};
    call(u8bAllocate, cb, 4096);
    make_commit_body(cb, tree_sha, parent_sha, author_id, ts, msg);
    a_dup(u8c, cd, u8bData(cb));
    call(KEEPPackFeed, &KEEP, p, DOG_OBJ_COMMIT, cd, 0, out_sha);
    u8bFree(cb);
    done;
}

//  Fetch a commit body into `out`.
static ok64 fetch_commit(sha1 const *sha, u8 *const *out) {
    sane(out);
    u8 t = 0;
    call(KEEPGetExact, &KEEP, sha, out, &t);
    if (t != DOG_OBJ_COMMIT) fail(KEEPFAIL);
    done;
}

// --- Emit-callback recorder ----------------------------------------------

#define EMIT_CAP 32
typedef struct {
    u8 type[EMIT_CAP];
    sha1 sha[EMIT_CAP];
    u32 n;
    ok64 fail_after;   //  if > 0, the (n+1)-th call returns this
} rec_emit;

static ok64 rec_cb(void *ctx, u8 type, sha1 const *sha, u8csc body) {
    (void)body;
    rec_emit *r = (rec_emit *)ctx;
    if (r->fail_after && r->n + 1 == r->fail_after) {
        return r->fail_after;
    }
    if (r->n < EMIT_CAP) {
        r->type[r->n] = type;
        r->sha[r->n] = *sha;
        r->n++;
    }
    return OK;
}

// --- Tests --------------------------------------------------------------

ok64 test_patchid(void) {
    sane(1);
    call(setup_repo);

    keep_pack p = {};
    call(KEEPPackOpen, &KEEP, &p);
    p.strict_order = NO;

    //  Two parents that share an identical tree: file `f.txt` = "old\n".
    //  Children that change `f.txt` to "new\n" against either parent
    //  should yield equal patch-ids (case (c)).
    sha1 b_old = {}, t_par_a = {}, t_par_b = {};
    call(make_single_leaf_tree, &p, "100644 f.txt", "old\n",
         &b_old, &t_par_a);
    sha1 b_old2 = {}, t_par_b_unused = {};
    call(make_single_leaf_tree, &p, "100644 f.txt", "old\n",
         &b_old2, &t_par_b);
    (void)b_old2; (void)t_par_b_unused;

    //  Two distinct parent commits referencing those (identical) trees.
    sha1 par_a = {}, par_b = {};
    call(feed_commit, &p, &t_par_a, NULL, "alice", 1000, "init A", &par_a);
    call(feed_commit, &p, &t_par_b, NULL, "bob",   2000, "init B", &par_b);

    //  Child trees: f.txt = "new\n".  Build twice to share a blob.
    sha1 b_new = {}, t_chi_a = {}, t_chi_b = {};
    call(make_single_leaf_tree, &p, "100644 f.txt", "new\n",
         &b_new, &t_chi_a);
    sha1 b_new2 = {};
    call(make_single_leaf_tree, &p, "100644 f.txt", "new\n",
         &b_new2, &t_chi_b);
    (void)b_new2;

    sha1 chi_a = {}, chi_b = {};
    call(feed_commit, &p, &t_chi_a, &par_a, "alice", 1100,
         "modify f", &chi_a);
    call(feed_commit, &p, &t_chi_b, &par_b, "bob",   2100,
         "modify f again", &chi_b);

    //  Also: a child that ADDS g.txt against par_a (different diff).
    sha1 b_g = {}, t_extra = {};
    {
        Bu8 tb = {};
        call(u8bAllocate, tb, 256);
        a_cstr(e1, "100644 f.txt");
        u8bFeed(tb, e1);
        u8bFeed1(tb, 0);
        a_rawc(o1, b_old);
        u8bFeed(tb, o1);
        a_cstr(e2, "100644 g.txt");
        u8bFeed(tb, e2);
        u8bFeed1(tb, 0);
        a_cstr(gc, "g\n");
        call(KEEPPackFeed, &KEEP, &p, DOG_OBJ_BLOB, gc, 0, &b_g);
        a_rawc(o2, b_g);
        u8bFeed(tb, o2);
        a_dup(u8c, td, u8bData(tb));
        call(KEEPPackFeed, &KEEP, &p, DOG_OBJ_TREE, td, 0, &t_extra);
        u8bFree(tb);
    }
    sha1 chi_extra = {};
    call(feed_commit, &p, &t_extra, &par_a, "alice", 1200,
         "add g", &chi_extra);

    //  A commit with no diff (tree == parent's tree).
    sha1 chi_nodiff = {};
    call(feed_commit, &p, &t_par_a, &par_a, "alice", 1300,
         "empty", &chi_nodiff);

    call(KEEPPackClose, &KEEP, &p);

    //  Fetch bodies and compute ids.
    Bu8 ba = {}, bb = {}, be = {}, bn = {};
    call(u8bAllocate, ba, 4096);
    call(u8bAllocate, bb, 4096);
    call(u8bAllocate, be, 4096);
    call(u8bAllocate, bn, 4096);
    call(fetch_commit, &chi_a,      ba);
    call(fetch_commit, &chi_b,      bb);
    call(fetch_commit, &chi_extra,  be);
    call(fetch_commit, &chi_nodiff, bn);

    a_dup(u8c, ba_d, u8bData(ba));
    a_dup(u8c, bb_d, u8bData(bb));
    a_dup(u8c, be_d, u8bData(be));
    a_dup(u8c, bn_d, u8bData(bn));

    u64 id_a    = GRAFPatchId(ba_d);
    u64 id_b    = GRAFPatchId(bb_d);
    u64 id_e    = GRAFPatchId(be_d);
    u64 id_none = GRAFPatchId(bn_d);

    //  (a) twice on the same body → same id.
    u64 id_a2 = GRAFPatchId(ba_d);
    want(id_a == id_a2);

    //  (c) rebase invariance: id_a == id_b.
    fprintf(stderr, "  id_a=%016lx id_b=%016lx id_e=%016lx id_none=%016lx\n",
            id_a, id_b, id_e, id_none);
    want(id_a == id_b);

    //  (b) different diffs → different ids.
    want(id_a != id_e);

    //  (d) empty diff → 0.
    want(id_none == 0);

    u8bFree(ba); u8bFree(bb); u8bFree(be); u8bFree(bn);

    teardown_repo();
    fprintf(stderr, "  patchid (a)PASS (b)PASS (c)PASS (d)PASS\n");
    done;
}

ok64 test_merge_explicit(void) {
    sane(1);
    call(setup_repo);

    keep_pack p = {};
    call(KEEPPackOpen, &KEEP, &p);
    p.strict_order = NO;

    //  base = "int x = 1;\nint y = 2;\n"
    sha1 sb = {};
    {
        a_cstr(c, "int x = 1;\nint y = 2;\n");
        call(KEEPPackFeed, &KEEP, &p, DOG_OBJ_BLOB, c, 0, &sb);
    }
    //  ours_e: same as base
    sha1 sb_eq = sb;
    //  theirs_t1: changes y to 20
    sha1 st1 = {};
    {
        a_cstr(c, "int x = 1;\nint y = 20;\n");
        call(KEEPPackFeed, &KEEP, &p, DOG_OBJ_BLOB, c, 0, &st1);
    }
    //  ours_o1: changes x to 10
    sha1 so1 = {};
    {
        a_cstr(c, "int x = 10;\nint y = 2;\n");
        call(KEEPPackFeed, &KEEP, &p, DOG_OBJ_BLOB, c, 0, &so1);
    }
    //  conflicting: both change x but to different values
    sha1 so_c = {}, st_c = {};
    {
        a_cstr(c, "int x = 11;\nint y = 2;\n");
        call(KEEPPackFeed, &KEEP, &p, DOG_OBJ_BLOB, c, 0, &so_c);
        a_cstr(d, "int x = 22;\nint y = 2;\n");
        call(KEEPPackFeed, &KEEP, &p, DOG_OBJ_BLOB, d, 0, &st_c);
    }

    call(KEEPPackClose, &KEEP, &p);

    //  (e) base == ours, theirs differs → output = theirs
    {
        Bu8 out = {};
        call(u8bMap, out, 1UL << 20);
        call(GRAFMergeExplicit, &sb, &sb_eq, &st1, out);
        a_dup(u8c, od, u8bData(out));
        u8cs want_s = {(u8cp)"int x = 1;\nint y = 20;\n",
                       (u8cp)"int x = 1;\nint y = 20;\n" + 23};
        if ($len(od) != $len(want_s) ||
            memcmp(od[0], want_s[0], $len(od)) != 0) {
            fprintf(stderr, "  (e) FAIL: got %.*s\n",
                    (int)$len(od), (char const *)od[0]);
            u8bUnMap(out);
            fail(TESTFAIL);
        }
        u8bUnMap(out);
    }

    //  (f) base == theirs, ours differs → output = ours
    {
        Bu8 out = {};
        call(u8bMap, out, 1UL << 20);
        call(GRAFMergeExplicit, &sb, &so1, &sb, out);
        a_dup(u8c, od, u8bData(out));
        u8cs want_s = {(u8cp)"int x = 10;\nint y = 2;\n",
                       (u8cp)"int x = 10;\nint y = 2;\n" + 23};
        if ($len(od) != $len(want_s) ||
            memcmp(od[0], want_s[0], $len(od)) != 0) {
            fprintf(stderr, "  (f) FAIL\n");
            u8bUnMap(out);
            fail(TESTFAIL);
        }
        u8bUnMap(out);
    }

    //  (g) non-conflicting divergence → merged should contain both x=10 and y=20
    {
        Bu8 out = {};
        call(u8bMap, out, 1UL << 20);
        call(GRAFMergeExplicit, &sb, &so1, &st1, out);
        a_dup(u8c, od, u8bData(out));
        u8cs s10 = {(u8cp)"x = 10", (u8cp)"x = 10" + 6};
        u8cs s20 = {(u8cp)"y = 20", (u8cp)"y = 20" + 6};
        b8 got_10 = NO, got_20 = NO;
        for (u8c *q = od[0]; q + 6 <= od[1]; q++) {
            if (memcmp(q, s10[0], 6) == 0) got_10 = YES;
            if (memcmp(q, s20[0], 6) == 0) got_20 = YES;
        }
        if (!got_10 || !got_20) {
            fprintf(stderr, "  (g) FAIL: 10=%d 20=%d\n", got_10, got_20);
            u8bUnMap(out);
            fail(TESTFAIL);
        }
        u8bUnMap(out);
    }

    //  (h) conflicting divergence → contains '<<<<' markers
    {
        Bu8 out = {};
        call(u8bMap, out, 1UL << 20);
        call(GRAFMergeExplicit, &sb, &so_c, &st_c, out);
        a_dup(u8c, od, u8bData(out));
        b8 has_marker = NO;
        for (u8c *q = od[0]; q + 4 <= od[1]; q++) {
            if (q[0] == '<' && q[1] == '<' &&
                q[2] == '<' && q[3] == '<') { has_marker = YES; break; }
        }
        if (!has_marker) {
            fprintf(stderr, "  (h) FAIL: no <<<< markers\n");
            u8bUnMap(out);
            fail(TESTFAIL);
        }
        u8bUnMap(out);
    }

    teardown_repo();
    fprintf(stderr, "  merge_explicit (e)PASS (f)PASS (g)PASS (h)PASS\n");
    done;
}

//  Build a small repo with this layout:
//
//      base_old → child1 → child2  (linear)
//      base_old → base_new          (alternate spine, 1-step ahead)
//
//  Then GRAFRebase(base_old, base_new, child2) replays both onto
//  base_new, optionally skipping child1 if its patch-id matches a
//  commit on base_new.
//
//  We keep tests deterministic by using fixed timestamps.
ok64 test_rebase(void) {
    sane(1);
    call(setup_repo);

    keep_pack p = {};
    call(KEEPPackOpen, &KEEP, &p);
    p.strict_order = NO;

    //  Initial blob+tree at base_old: f.txt = "v0\n"
    sha1 b0 = {}, t0 = {};
    call(make_single_leaf_tree, &p, "100644 f.txt", "v0\n", &b0, &t0);
    sha1 base_old = {};
    call(feed_commit, &p, &t0, NULL, "alice", 100, "v0", &base_old);

    //  base_new: tree has f.txt = "v0\n" + g.txt = "g\n"  (cherry-pickable add)
    sha1 g_blob = {}, t_bn = {};
    {
        a_cstr(gc, "g\n");
        call(KEEPPackFeed, &KEEP, &p, DOG_OBJ_BLOB, gc, 0, &g_blob);
        Bu8 tb = {};
        call(u8bAllocate, tb, 256);
        a_cstr(e1, "100644 f.txt"); u8bFeed(tb, e1);
        u8bFeed1(tb, 0); a_rawc(o1, b0); u8bFeed(tb, o1);
        a_cstr(e2, "100644 g.txt"); u8bFeed(tb, e2);
        u8bFeed1(tb, 0); a_rawc(o2, g_blob); u8bFeed(tb, o2);
        a_dup(u8c, td, u8bData(tb));
        call(KEEPPackFeed, &KEEP, &p, DOG_OBJ_TREE, td, 0, &t_bn);
        u8bFree(tb);
    }
    sha1 base_new = {};
    call(feed_commit, &p, &t_bn, &base_old, "alice", 200,
         "add g (on new spine)", &base_new);

    //  child1 on top of base_old: also adds g.txt = "g\n" — same diff!
    sha1 child1 = {};
    call(feed_commit, &p, &t_bn, &base_old, "alice", 300,
         "add g (on old spine)", &child1);

    //  child2 on top of child1: changes f.txt to "v2\n"
    sha1 b2 = {}, t_c2 = {};
    {
        a_cstr(gc, "g\n");
        sha1 g2 = {};  //  reuse same content; KEEP will dedup
        call(KEEPPackFeed, &KEEP, &p, DOG_OBJ_BLOB, gc, 0, &g2);
        a_cstr(c2, "v2\n");
        call(KEEPPackFeed, &KEEP, &p, DOG_OBJ_BLOB, c2, 0, &b2);
        Bu8 tb = {};
        call(u8bAllocate, tb, 256);
        a_cstr(e1, "100644 f.txt"); u8bFeed(tb, e1);
        u8bFeed1(tb, 0); a_rawc(o1, b2); u8bFeed(tb, o1);
        a_cstr(e2, "100644 g.txt"); u8bFeed(tb, e2);
        u8bFeed1(tb, 0); a_rawc(o2, g2); u8bFeed(tb, o2);
        a_dup(u8c, td, u8bData(tb));
        call(KEEPPackFeed, &KEEP, &p, DOG_OBJ_TREE, td, 0, &t_c2);
        u8bFree(tb);
    }
    sha1 child2 = {};
    call(feed_commit, &p, &t_c2, &child1, "alice", 400, "v2", &child2);

    call(KEEPPackClose, &KEEP, &p);

    //  (i) child_tip == base_old → no emits.
    {
        rec_emit r = {};
        ok64 o = GRAFRebase(&base_old, &base_new, &base_old, rec_cb, &r);
        want(o == OK);
        want(r.n == 0);
        fprintf(stderr, "  rebase (i)PASS\n");
    }

    //  (k) Two-commit child where the FIRST commit is patch-id-equiv
    //      to a commit on base_new — child1 should be skipped, child2
    //      replayed.  We expect at least one commit emit (child2's
    //      replay).
    {
        rec_emit r = {};
        ok64 o = GRAFRebase(&base_old, &base_new, &child2, rec_cb, &r);
        if (o != OK) {
            fprintf(stderr, "  rebase k: got 0x%lx, want OK\n",
                    (unsigned long)o);
            fail(TESTFAIL);
        }
        u32 commits = 0;
        for (u32 i = 0; i < r.n; i++) {
            if (r.type[i] == DOG_OBJ_COMMIT) commits++;
        }
        if (commits != 1) {
            fprintf(stderr, "  rebase k: %u commits emitted (want 1)\n",
                    commits);
            fail(TESTFAIL);
        }
        fprintf(stderr, "  rebase (k)PASS  (commits=%u total emits=%u)\n",
                commits, r.n);
    }

    //  (j) Single-commit child where there is no patch-id collision.
    //      Build base_alt = base_old (no extras), child_solo with a
    //      change unique to itself.  Replay onto base_alt.
    keep_pack p2 = {};
    call(KEEPPackOpen, &KEEP, &p2);
    p2.strict_order = NO;
    sha1 b_solo = {}, t_solo = {};
    call(make_single_leaf_tree, &p2, "100644 f.txt", "solo\n",
         &b_solo, &t_solo);
    sha1 child_solo = {};
    call(feed_commit, &p2, &t_solo, &base_old, "alice", 500,
         "solo edit", &child_solo);
    call(KEEPPackClose, &KEEP, &p2);
    {
        rec_emit r = {};
        ok64 o = GRAFRebase(&base_old, &base_old, &child_solo,
                            rec_cb, &r);
        if (o != OK) {
            fprintf(stderr, "  rebase j: got 0x%lx\n", (unsigned long)o);
            fail(TESTFAIL);
        }
        u32 commits = 0;
        for (u32 i = 0; i < r.n; i++) {
            if (r.type[i] == DOG_OBJ_COMMIT) commits++;
        }
        if (commits != 1) {
            fprintf(stderr, "  rebase j: commits=%u (want 1)\n", commits);
            fail(TESTFAIL);
        }
        fprintf(stderr, "  rebase (j)PASS  (commits=%u total emits=%u)\n",
                commits, r.n);
    }

    //  (l) Conflict.  Build a separate spine where:
    //      base_old has f.txt = "v0\n"
    //      base_new spine modifies f.txt → "head\n"
    //      child  spine modifies f.txt → "branch\n"
    //  Replaying child onto base_new requires merging "v0", "head",
    //  "branch" — concurrent edits, conflict.
    keep_pack p3 = {};
    call(KEEPPackOpen, &KEEP, &p3);
    p3.strict_order = NO;
    sha1 b_h = {}, t_h = {};
    call(make_single_leaf_tree, &p3, "100644 f.txt", "head\n",
         &b_h, &t_h);
    sha1 base_new_h = {};
    call(feed_commit, &p3, &t_h, &base_old, "alice", 600,
         "head edit", &base_new_h);

    sha1 b_b = {}, t_b = {};
    call(make_single_leaf_tree, &p3, "100644 f.txt", "branch\n",
         &b_b, &t_b);
    sha1 child_branch = {};
    call(feed_commit, &p3, &t_b, &base_old, "alice", 700,
         "branch edit", &child_branch);
    call(KEEPPackClose, &KEEP, &p3);
    {
        rec_emit r = {};
        ok64 o = GRAFRebase(&base_old, &base_new_h, &child_branch,
                            rec_cb, &r);
        if (o != GRAFCNFL) {
            fprintf(stderr, "  rebase l: got 0x%lx, want GRAFCNFL\n",
                    (unsigned long)o);
            fail(TESTFAIL);
        }
        //  No COMMIT emit for the conflicting commit.
        for (u32 i = 0; i < r.n; i++) {
            if (r.type[i] == DOG_OBJ_COMMIT) {
                fprintf(stderr,
                        "  rebase l: commit emit despite conflict\n");
                fail(TESTFAIL);
            }
        }
        fprintf(stderr, "  rebase (l)PASS  (emits before abort=%u)\n", r.n);
    }

    teardown_repo();
    done;
}

ok64 maintest(void) {
    sane(1);
    call(test_patchid);
    call(test_merge_explicit);
    call(test_rebase);
    done;
}

TEST(maintest)
