//
//  MERGEWT01 — Property tests for GRAFMergeWtFile.
//
//  Tag matrix:
//    (a) Non-overlapping edits (wt edits line A, tgt edits line C) →
//        merged output contains both edits, no markers.
//    (b) wt absent on disk → equivalent to "no wt edit" — merged
//        output equals tgt's blob bytes.
//    (c) wt byte-equal to base → no-op fold; merged output equals
//        tgt's blob bytes.
//
#include "graf/GRAF.h"

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
#include "dog/WHIFF.h"
#include "keeper/KEEP.h"

// --- Tiny test harness (mirrors REBASE01.c) ----------------------------

static char g_tmp[256];
static home g_home;

static ok64 setup_repo(void) {
    sane(1);
    call(FILEInit);
    snprintf(g_tmp, sizeof(g_tmp), "/tmp/grafmergewt-XXXXXX");
    want(mkdtemp(g_tmp) != NULL);
    a_cstr(root, g_tmp);
    memset(&g_home, 0, sizeof(g_home));
    call(HOMEOpenAt, &g_home, root, YES);
    call(KEEPOpen, &g_home, YES);
    done;
}

static void teardown_repo(void) {
    GRAFClose();
    KEEPClose();
    HOMEClose(&g_home);
    char cmd[300];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", g_tmp);
    system(cmd);
}

//  Build a tree carrying one blob "100644 <name>" → bsha.
static ok64 make_single_leaf_tree(keep_pack *p,
                                  char const *name,
                                  char const *content,
                                  sha1 *blob_out, sha1 *tree_out) {
    sane(p && blob_out && tree_out);
    u8cs cb = {(u8cp)content, (u8cp)content + strlen(content)};
    call(KEEPPackFeed, &KEEP, p, DOG_OBJ_BLOB, cb, 0, blob_out);
    a_pad(u8, tb, 256);
    a_cstr(prefix, "100644 ");
    call(u8bFeed, tb, prefix);
    a_cstr(nm, name);
    call(u8bFeed, tb, nm);
    u8bFeed1(tb, 0);
    a_rawc(ss, *blob_out);
    call(u8bFeed, tb, ss);
    a_dup(u8c, tc, u8bData(tb));
    call(KEEPPackFeed, &KEEP, p, DOG_OBJ_TREE, tc, 0, tree_out);
    done;
}

//  Build a commit body and feed it to keeper.
static ok64 commit_one(keep_pack *p,
                       sha1 const *tree_sha, sha1 const *parent_sha,
                       char const *msg, long ts, sha1 *out_sha) {
    sane(p && tree_sha && msg && out_sha);

    Bu8 cb = {};
    call(u8bAllocate, cb, 1024);

    a_cstr(tl, "tree ");  u8bFeed(cb, tl);
    a_pad(u8, thx, 40);
    a_rawc(ts2, *tree_sha);
    HEXu8sFeedSome(thx_idle, ts2);
    u8bFeed(cb, u8bDataC(thx));
    u8bFeed1(cb, '\n');

    if (parent_sha != NULL) {
        a_cstr(pl, "parent ");  u8bFeed(cb, pl);
        a_pad(u8, phx, 40);
        a_rawc(ps, *parent_sha);
        HEXu8sFeedSome(phx_idle, ps);
        u8bFeed(cb, u8bDataC(phx));
        u8bFeed1(cb, '\n');
    }

    char hdr[256];
    int n = snprintf(hdr, sizeof(hdr),
                     "author t <t@t> %ld +0000\n"
                     "committer t <t@t> %ld +0000\n\n%s\n",
                     ts, ts, msg);
    u8cs hs = {(u8cp)hdr, (u8cp)hdr + n};
    u8bFeed(cb, hs);

    a_dup(u8c, cd, u8bData(cb));
    call(KEEPPackFeed, &KEEP, p, DOG_OBJ_COMMIT, cd, 0, out_sha);
    u8bFree(cb);
    done;
}

//  Convenience: build tree+commit for one file with `content` parented
//  on `parent` (NULL for root).
static ok64 commit_one_file(keep_pack *p, char const *name,
                            char const *content, sha1 const *parent,
                            char const *msg, long ts, sha1 *out_commit) {
    sane(p && name && content && msg && out_commit);
    sha1 blob = {}, tree = {};
    call(make_single_leaf_tree, p, name, content, &blob, &tree);
    call(commit_one, p, &tree, parent, msg, ts, out_commit);
    done;
}

//  Write `content` into `<reporoot>/<rel>`.
static ok64 write_wt(char const *rel, char const *content) {
    sane(rel && content);
    char abs[512];
    snprintf(abs, sizeof(abs), "%s/%s", g_tmp, rel);
    int fd = open(abs, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) fail(FILEFAIL);
    size_t len = strlen(content);
    ssize_t w = write(fd, content, len);
    close(fd);
    if (w != (ssize_t)len) fail(FILEFAIL);
    done;
}

//  YES iff `out` byte-equals `want_str`.
static b8 buf_eq_cstr(u8b out, char const *want_str) {
    size_t wl = strlen(want_str);
    if (u8bDataLen(out) != wl) return NO;
    return memcmp(u8bDataHead(out), want_str, wl) == 0;
}

// --- Tests --------------------------------------------------------------

//  (a) Non-overlapping edits: wt edits line 1, tgt edits line 3.
//  Merged output contains both edits.
ok64 test_clean_merge(void) {
    sane(1);
    call(setup_repo);

    keep_pack p = {};
    call(KEEPPackOpen, &KEEP, &p);
    p.strict_order = NO;

    sha1 c_base = {}, c_tgt = {};
    call(commit_one_file, &p, "f.txt",
         "alpha\nbeta\ngamma\n", NULL,           "base", 1700000000L, &c_base);
    call(commit_one_file, &p, "f.txt",
         "alpha\nbeta\nGAMMA\n", &c_base,        "tgt",  1700000100L, &c_tgt);

    call(KEEPPackClose, &KEEP, &p);

    //  Build the DAG so build_tip_weave can walk history.
    call(GRAFOpen, &g_home, YES);
    call(GRAFIndex, &KEEP);

    //  wt = base + edit on line 1 (alpha → ALPHA).
    call(write_wt, "f.txt", "ALPHA\nbeta\ngamma\n");

    Bu8 out = {};
    call(u8bAllocate, out, 1024);

    a_cstr(path, "f.txt");
    a_dup(u8c, root, u8bData(g_home.wt));

    call(GRAFMergeWtFile, path, root, &c_base, &c_tgt, out);

    //  Expected: both edits present, base text in the middle preserved.
    want(buf_eq_cstr(out, "ALPHA\nbeta\nGAMMA\n"));

    u8bFree(out);
    teardown_repo();
    done;
}

//  (b) wt absent on disk → fold is a no-op; merged output is just the
//  tgt blob (the base side has no wt layer, history-only).
ok64 test_wt_absent(void) {
    sane(1);
    call(setup_repo);

    keep_pack p = {};
    call(KEEPPackOpen, &KEEP, &p);
    p.strict_order = NO;

    sha1 c_base = {}, c_tgt = {};
    call(commit_one_file, &p, "f.txt",
         "one\ntwo\n", NULL,            "base", 1700000000L, &c_base);
    call(commit_one_file, &p, "f.txt",
         "one\nTWO\n", &c_base,         "tgt",  1700000100L, &c_tgt);

    call(KEEPPackClose, &KEEP, &p);
    call(GRAFOpen, &g_home, YES);
    call(GRAFIndex, &KEEP);

    //  No write_wt — file is absent on disk.
    Bu8 out = {};
    call(u8bAllocate, out, 1024);

    a_cstr(path, "f.txt");
    a_dup(u8c, root, u8bData(g_home.wt));

    call(GRAFMergeWtFile, path, root, &c_base, &c_tgt, out);

    //  Without a wt edit, tgt's bytes pass through alone.
    want(buf_eq_cstr(out, "one\nTWO\n"));

    u8bFree(out);
    teardown_repo();
    done;
}

//  (c) wt byte-equal to last committed version on the base side →
//  fold is a no-op; merged output equals tgt's blob.
ok64 test_wt_clean_drift(void) {
    sane(1);
    call(setup_repo);

    keep_pack p = {};
    call(KEEPPackOpen, &KEEP, &p);
    p.strict_order = NO;

    sha1 c_base = {}, c_tgt = {};
    call(commit_one_file, &p, "f.txt",
         "x\ny\n", NULL,            "base", 1700000000L, &c_base);
    call(commit_one_file, &p, "f.txt",
         "x\nY\n", &c_base,         "tgt",  1700000100L, &c_tgt);

    call(KEEPPackClose, &KEEP, &p);
    call(GRAFOpen, &g_home, YES);
    call(GRAFIndex, &KEEP);

    //  wt content matches base — graf_fold_wt_layer in BLAME's pattern
    //  byte-dedups, but our extracted helper does not (yet).  Even so,
    //  the tokens carry WEAVE_WT_SRC stamps that don't appear in tgt's
    //  history — the merge still resolves to tgt's bytes for changed
    //  regions because tgt's `in` is also alive on the base side via
    //  the shared-spine reconciliation.
    call(write_wt, "f.txt", "x\ny\n");

    Bu8 out = {};
    call(u8bAllocate, out, 1024);

    a_cstr(path, "f.txt");
    a_dup(u8c, root, u8bData(g_home.wt));

    call(GRAFMergeWtFile, path, root, &c_base, &c_tgt, out);

    want(buf_eq_cstr(out, "x\nY\n"));

    u8bFree(out);
    teardown_repo();
    done;
}

//  (d) Same line edited by both wt and tgt → conflict markers.
//  Both sides change line 2; the merger can't pick one — output
//  carries `<<<<` / `||||` / `>>>>` framing the divergent region.
ok64 test_conflict(void) {
    sane(1);
    call(setup_repo);

    keep_pack p = {};
    call(KEEPPackOpen, &KEEP, &p);
    p.strict_order = NO;

    sha1 c_base = {}, c_tgt = {};
    call(commit_one_file, &p, "f.txt",
         "one\nbeta\nthree\n", NULL,        "base", 1700000000L, &c_base);
    call(commit_one_file, &p, "f.txt",
         "one\nBETA-tgt\nthree\n", &c_base, "tgt",  1700000100L, &c_tgt);

    call(KEEPPackClose, &KEEP, &p);
    call(GRAFOpen, &g_home, YES);
    call(GRAFIndex, &KEEP);

    //  wt edits the same line, differently from tgt.
    call(write_wt, "f.txt", "one\nBETA-wt\nthree\n");

    Bu8 out = {};
    call(u8bAllocate, out, 1024);
    a_cstr(path, "f.txt");
    a_dup(u8c, root, u8bData(g_home.wt));

    call(GRAFMergeWtFile, path, root, &c_base, &c_tgt, out);

    //  Output must carry conflict markers framing the disagreement.
    //  WEAVEMerge's NEIL/canonicalization can split a single conceptual
    //  conflict across multiple non-EQ runs (e.g., when a shared spine
    //  token sits between divergent inserts), so we only assert that
    //  markers fire and that both sides' distinguishing bytes survive
    //  somewhere in the output.
    u8s out_view = {u8bDataHead(out), u8bIdleHead(out)};
    size_t olen  = (size_t)$len(out_view);
    b8 has_open  = NO, has_mid = NO, has_close = NO;
    for (size_t i = 0; i + 4 <= olen; i++) {
        u8 const *p2 = out_view[0] + i;
        if (memcmp(p2, "<<<<", 4) == 0) has_open  = YES;
        if (memcmp(p2, "||||", 4) == 0) has_mid   = YES;
        if (memcmp(p2, ">>>>", 4) == 0) has_close = YES;
    }
    want(has_open && has_mid && has_close);

    //  Both sides' distinguishing bytes appear somewhere in the output.
    b8 has_wt = NO, has_tgt = NO;
    for (size_t i = 0; i + 3 <= olen; i++) {
        if (memcmp(out_view[0] + i, "wt",  2) == 0) has_wt  = YES;
        if (memcmp(out_view[0] + i, "tgt", 3) == 0) has_tgt = YES;
    }
    want(has_wt && has_tgt);

    u8bFree(out);
    teardown_repo();
    done;
}

ok64 maintest(void) {
    sane(1);
    call(test_clean_merge);
    call(test_wt_absent);
    call(test_wt_clean_drift);
    call(test_conflict);
    done;
}

TEST(maintest)
