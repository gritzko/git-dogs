#include "sniff/SNIFF.h"
#include "sniff/AT.h"
#include "sniff/DEL.h"
#include "sniff/GET.h"
#include "sniff/POST.h"
#include "sniff/PUT.h"

#include "graf/GRAF.h"

#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

//  Bump a file's atime/mtime forward by `bump_sec` seconds.  Lets
//  tests observe a distinct mtime without a real sleep.
static void bump_mtime(char const *abs_path, int bump_sec) {
    struct stat sb = {};
    if (stat(abs_path, &sb) != 0) return;
    struct timeval tv[2] = {
        { .tv_sec = sb.st_atim.tv_sec + bump_sec, .tv_usec = 0 },
        { .tv_sec = sb.st_mtim.tv_sec + bump_sec, .tv_usec = 0 },
    };
    utimes(abs_path, tv);
}

#include "abc/FILE.h"
#include "abc/HEX.h"
#include "abc/PATH.h"
#include "abc/PRO.h"
#include "abc/TEST.h"
#include "keeper/REFS.h"
#include "keeper/SHA1.h"
#include "keeper/WALK.h"

// --- Helpers ---

static char g_tmpdir[256];

static ok64 make_tmpdir(void) {
    sane(1);
    snprintf(g_tmpdir, sizeof(g_tmpdir), "/tmp/sniff-test-XXXXXX");
    want(mkdtemp(g_tmpdir) != NULL);
    done;
}

static void rm_tmpdir(void) {
    char cmd[300];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", g_tmpdir);
    system(cmd);
}

// --- Test: AT helpers (verb constants, baseline, last-post, scan) ---

typedef struct { u32 n; ron60 verbs[8]; u8 paths[8][32]; u8 lens[8]; } pd_capture;

static ok64 pd_collect(ron60 verb, u8cs path, ron60 ts, void *ctx) {
    (void)ts;
    pd_capture *c = (pd_capture *)ctx;
    if (c->n >= 8) return OK;
    c->verbs[c->n] = verb;
    u32 l = (u32)$len(path);
    if (l > 32) l = 32;
    memcpy(c->paths[c->n], path[0], l);
    c->lens[c->n] = (u8)l;
    c->n++;
    return OK;
}

static ok64 at_append_uri(ron60 ts, ron60 verb, char const *uri_cstr) {
    sane(1);
    a_pad(u8, urib, 512);
    a_cstr(src, uri_cstr);
    u8bFeed(urib, src);
    uri urow = {};
    a_dup(u8c, ud, u8bData(urib));
    call(URIutf8Drain, ud, &urow);
    call(SNIFFAtAppendAt, ts, verb, &urow);
    done;
}

ok64 SNIFFAtHelpers() {
    sane(1);
    call(FILEInit);
    call(make_tmpdir);

    a_cstr(root, g_tmpdir);
    home h = {};
    call(HOMEOpen, &h, root, YES);
    call(KEEPOpen, &h, YES);
    call(SNIFFOpen, &h, YES);

    //  Verb constants — stable across calls, distinct from each other.
    ron60 vr = SNIFFAtVerbRepo();
    ron60 vg = SNIFFAtVerbGet();
    ron60 vp = SNIFFAtVerbPost();
    ron60 vx = SNIFFAtVerbPatch();
    ron60 vu = SNIFFAtVerbPut();
    ron60 vd = SNIFFAtVerbDelete();
    want(vr != 0 && vg != 0 && vp != 0 && vx != 0 && vu != 0 && vd != 0);
    want(vr != vg && vr != vp && vr != vx && vr != vu && vr != vd);
    want(vg != vp && vg != vx && vg != vu && vg != vd);
    want(vp != vx && vp != vu && vp != vd);
    want(vx != vu && vx != vd);
    want(vu != vd);
    want(SNIFFAtVerbGet() == vg);   // cached

    //  SNIFFOpen writes the row-0 `repo` anchor; synthetic ULOG rows
    //  must therefore start strictly after it.
    ron60 t_repo = 0, v_repo = 0;
    {
        uri ru = {};
        call(SNIFFAtRepo, &ru);
        //  Re-fetch ts/verb via ULOGRow(0) — SNIFFAtRepo only yields
        //  the URI.
        ulogrec _r0 = {};
        call(ULOGRow, SNIFF.log_data, SNIFF.log_idx, 0, &_r0);
        t_repo = _r0.ts; v_repo = _r0.verb; ru = _r0.uri;
        want(v_repo == vr);
        //  URI path is `/…/.dogs/`.
        a_dup(u8c, rp, ru.path);
        want($len(rp) >= 7);
        a_cstr(tail, ".dogs/");
        want(memcmp(rp[1] - $len(tail), tail[0], $len(tail)) == 0);
    }
    ron60 base = t_repo + 1000;

    //  Post-repo log invariants: baseline/last-post/stamp-set all
    //  still empty except for the repo stamp itself.
    {
        ron60 ts = 0, verb = 0;
        uri u = {};
        want(SNIFFAtBaseline(&ts, &verb, &u) == ULOGNONE);
        want(SNIFFAtLastPostTs() == 0);
        want(!SNIFFAtKnown(base + 9999));
    }

    //  Timeline (offsets from the repo row):
    //    +1000 get    ?heads/main#aaaa...
    //    +1100 put    src/a.c
    //    +1200 put    src/b.c
    //    +1300 delete src/c.c
    //    +1400 post   ?heads/main#bbbb...
    //    +1500 put    src/d.c            (after last post)
    //    +1600 patch  ?heads/main#bbbb...,cccc...
    call(at_append_uri, base + 0,   vg, "?heads/main#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    call(at_append_uri, base + 100, vu, "src/a.c");
    call(at_append_uri, base + 200, vu, "src/b.c");
    call(at_append_uri, base + 300, vd, "src/c.c");
    call(at_append_uri, base + 400, vp, "?heads/main#bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    call(at_append_uri, base + 500, vu, "src/d.c");
    call(at_append_uri, base + 600, vx, "?heads/main#bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,cccccccccccccccccccccccccccccccccccccccc");

    //  Stamp-set: exact timestamps are known, neighbours aren't.
    want(SNIFFAtKnown(base + 0));
    want(SNIFFAtKnown(base + 400));
    want(SNIFFAtKnown(base + 600));
    want(!SNIFFAtKnown(base - 1));
    want(!SNIFFAtKnown(base + 550));

    //  Baseline: most recent get/post/patch is the patch at +600.
    {
        ron60 ts = 0, verb = 0;
        uri u = {};
        call(SNIFFAtBaseline, &ts, &verb, &u);
        want(ts == base + 600);
        want(verb == vx);
        a_dup(u8c, frag, u.fragment);
        want($len(frag) > 40);
        b8 has_comma = NO;
        for (u8c const *p = frag[0]; p < frag[1]; p++)
            if (*p == ',') { has_comma = YES; break; }
        want(has_comma);
    }

    //  Last post ts = base + 400.
    want(SNIFFAtLastPostTs() == base + 400);

    //  Scan put/delete since last post: only src/d.c at +500.
    {
        pd_capture cap = {};
        call(SNIFFAtScanPutDelete, base + 400, pd_collect, &cap);
        want(cap.n == 1);
        want(cap.verbs[0] == vu);
        want(cap.lens[0] == 7);
        want(memcmp(cap.paths[0], "src/d.c", 7) == 0);
    }

    //  Scan from the beginning (floor=0): all four put/delete rows, in order.
    {
        pd_capture cap = {};
        call(SNIFFAtScanPutDelete, 0, pd_collect, &cap);
        want(cap.n == 4);
        want(cap.verbs[0] == vu && cap.lens[0] == 7);
        want(memcmp(cap.paths[0], "src/a.c", 7) == 0);
        want(cap.verbs[1] == vu);
        want(memcmp(cap.paths[1], "src/b.c", 7) == 0);
        want(cap.verbs[2] == vd);
        want(memcmp(cap.paths[2], "src/c.c", 7) == 0);
        want(cap.verbs[3] == vu);
        want(memcmp(cap.paths[3], "src/d.c", 7) == 0);
    }

    //  Scan from a floor past the tail: no rows.
    {
        pd_capture cap = {};
        call(SNIFFAtScanPutDelete, base + 99999, pd_collect, &cap);
        want(cap.n == 0);
    }

    call(SNIFFClose);
    KEEPClose();
    HOMEClose(&h);
    rm_tmpdir();
    done;
}

// --- Test: checkout + commit round-trip ---

ok64 SNIFFCheckoutCommit() {
    sane(1);
    call(FILEInit);
    call(make_tmpdir);

    a_cstr(root, g_tmpdir);
    home h = {};
    call(HOMEOpen, &h, root, YES);

    // Open keeper, create a blob + tree + commit manually
    
    call(KEEPOpen, &h, YES);

    keep_pack p = {};
    call(KEEPPackOpen, &KEEP, &p);
    //  Hand-rolled objects for test — fed in non-canonical order
    //  (blob before tree).  Sniff's real POST path repacks canonically.
    p.strict_order = NO;

    // Blob: "hello\n"
    a_cstr(blob_data, "hello\n");
    sha1 blob_sha = {};
    call(KEEPPackFeed, &KEEP, &p, DOG_OBJ_BLOB, blob_data, 0, &blob_sha);

    // Tree: one entry "100644 test.txt\0<sha>"
    a_pad(u8, tree_buf, 256);
    a_cstr(tm, "100644 test.txt");
    u8bFeed(tree_buf, tm);
    u8bFeed1(tree_buf, 0);
    a_rawc(sha_s, blob_sha);
    u8bFeed(tree_buf, sha_s);
    a_dup(u8c, tree_content, u8bData(tree_buf));

    sha1 tree_sha = {};
    call(KEEPPackFeed, &KEEP, &p, DOG_OBJ_TREE, tree_content, 0, &tree_sha);

    // Commit
    a_pad(u8, cbuf, 512);
    a_cstr(c1, "tree ");
    u8bFeed(cbuf, c1);
    a_pad(u8, thex, 40);
    a_rawc(ts, tree_sha);
    HEXu8sFeedSome(thex_idle, ts);
    u8bFeed(cbuf, u8bDataC(thex));
    a_cstr(c2, "\nauthor Test <t@t> 1700000000 +0000\n"
               "committer Test <t@t> 1700000000 +0000\n\ninitial\n");
    u8bFeed(cbuf, c2);
    a_dup(u8c, commit_content, u8bData(cbuf));

    sha1 commit_sha = {};
    call(KEEPPackFeed, &KEEP, &p, DOG_OBJ_COMMIT, commit_content, 0, &commit_sha);
    call(KEEPPackClose, &KEEP, &p);

    // Hex of commit SHA for CLI
    a_pad(u8, commit_hex, 40);
    a_rawc(csha_s, commit_sha);
    HEXu8sFeedSome(commit_hex_idle, csha_s);

    // Now checkout via sniff
    sniff s = {};
    call(SNIFFOpen, &h, YES);
    u8cs hex = {u8bDataHead(commit_hex), u8bIdleHead(commit_hex)};
    u8cs no_src_ = {}; call(GETCheckout, root, hex, no_src_);

    // Verify file exists
    a_path(fp, root);
    a_cstr(fn, "/test.txt");
    call(u8bFeed, fp, fn);
    call(PATHu8bTerm, fp);
    struct stat sb = {};
    want(FILEStat(&sb, $path(fp)) == OK);

    //  New-model sniff doesn't expose a per-path hashlet cache across
    //  processes — GETCheckout just stamps the files and appends a
    //  `get` ULOG row.  Step 6 will add a full workflow-driving test;
    //  for now this scenario only verifies that:
    //    * the file materialised on disk (done above), and
    //    * a subsequent POSTCommit can still chain a commit behind the
    //      baseline captured in the ULOG's `get` row.

    // Modify file — no SNIFFRecord call anymore; POST in Step 4 will
    // detect change via mtime ∉ stamp-set.
    {
        int fd = -1;
        call(FILECreate, &fd, $path(fp));
        a_cstr(newdata, "modified\n");
        FILEFeedAll(fd, newdata);
        FILEClose(&fd);
    }
    bump_mtime((char *)u8bDataHead(fp), 2);

    // Commit (HEAD is already set to the initial commit from GETCheckout).
    //  POSTCommit's ff check uses GRAFLca, which needs GRAF open.
    call(GRAFOpen, &h, YES);
    a_cstr(msg, "second commit");
    a_cstr(author, "Test <t@t>");
    sha1 new_sha = {};
    u8cs no_target = {};
    call(POSTCommit, root, no_target, msg, author, &new_sha);

    // Verify new commit exists
    u64 new_hashlet = WHIFFHashlet60(&new_sha);
    want(KEEPHas(&KEEP, new_hashlet, 15) == OK);

    // Verify via KEEPGet
    Bu8 out = {};
    call(u8bAllocate, out, 1UL << 20);
    u8 otype = 0;
    call(KEEPGet, &KEEP, new_hashlet, 10, out, &otype);
    want(otype == DOG_OBJ_COMMIT);

    // Verify commit content mentions parent
    u8cs body = {u8bDataHead(out), u8bIdleHead(out)};
    u8cs scan = {body[0], body[1]};
    want(u8csFind(scan, 'p') == OK);  // "parent ..."

    u8bFree(out);
    call(SNIFFClose);
    GRAFClose();
    call(KEEPClose);
    HOMEClose(&h);
    rm_tmpdir();
    done;
}

// --- Helper: sha1 to hex string ---

static void sha2hex(u8bp buf, sha1 const *sha) {
    u8bReset(buf);
    a_rawc(s, *sha);
    u8s idle = {buf[2], buf[3]};
    HEXu8sFeedSome(idle, s);
    ((u8p *)buf)[2] = idle[0];  // advance DATA end
}

// --- Helper: write a file under root ---

static ok64 write_file(u8cs root, char const *rel, char const *content) {
    sane($ok(root));
    a_path(fp, root);
    a_cstr(sep, "/");
    call(u8bFeed, fp, sep);
    a_cstr(r, rel);
    call(u8bFeed, fp, r);
    call(PATHu8bTerm, fp);

    // Ensure parent dir exists
    a_path(dp, root);
    u8bFeed(dp, sep);
    u8bFeed(dp, r);
    PATHu8bTerm(dp);
    // Walk back to last /
    u8cs dpath = {u8bDataHead(dp), u8bIdleHead(dp)};
    u8cs dscan = {dpath[0], dpath[1]};
    u8cp last_slash = NULL;
    a_dup(u8c, dfind, dscan);
    while (u8csFind(dfind, '/') == OK) {
        last_slash = dfind[0];
        ++dfind[0];
    }
    if (last_slash && last_slash > dpath[0]) {
        u8 save = *last_slash;
        *(u8p)last_slash = 0;
        a_cstr(dp2, (char *)dpath[0]);
        a_path(dirp, dp2);
        FILEMakeDirP($path(dirp));
        *(u8p)last_slash = save;
    }

    int fd = -1;
    call(FILECreate, &fd, $path(fp));
    a_cstr(data, content);
    call(FILEFeedAll, fd, data);
    close(fd);
    done;
}

// --- Helper: check file exists and has expected content ---

static ok64 check_file(u8cs root, char const *rel, char const *expected) {
    sane($ok(root));
    a_path(fp, root);
    a_cstr(sep, "/");
    call(u8bFeed, fp, sep);
    a_cstr(r, rel);
    call(u8bFeed, fp, r);
    call(PATHu8bTerm, fp);

    struct stat sb = {};
    want(FILEStat(&sb, $path(fp)) == OK);

    Bu8 content = {};
    call(u8bAllocate, content, 1UL << 20);
    int fd = -1;
    call(FILEOpen, &fd, $path(fp), O_RDONLY);
    FILEdrainall(u8bIdle(content), fd);
    close(fd);

    size_t elen = strlen(expected);
    want(u8bDataLen(content) == elen);
    want(memcmp(u8bDataHead(content), expected, elen) == 0);
    u8bFree(content);
    done;
}

// --- Helper: check file does NOT exist ---

static b8 file_gone(u8cs root, char const *rel) {
    a_path(fp, root);
    a_cstr(sep, "/");
    u8bFeed(fp, sep);
    a_cstr(r, rel);
    u8bFeed(fp, r);
    PATHu8bTerm(fp);
    struct stat sb = {};
    return (FILEStat(&sb, $path(fp)) != OK);
}

// --- Helper: create initial commit with N files in keeper ---

typedef struct { char const *name; char const *data; } testfile;

static ok64 make_commit(sha1 *commit_out, keeper *k,
                        testfile const *files, u32 nfiles,
                        sha1 const *parent) {
    sane(k && commit_out);
    keep_pack p = {};
    call(KEEPPackOpen, k, &p);
    //  Hand-rolled blob→tree→commit sequence for tests — not canonical.
    p.strict_order = NO;

    // Create blobs + tree entries
    a_pad(u8, tree_buf, 4096);
    for (u32 i = 0; i < nfiles; i++) {
        a_cstr(blob, files[i].data);
        sha1 bsha = {};
        call(KEEPPackFeed, k, &p, DOG_OBJ_BLOB, blob, 0, &bsha);
        a_cstr(mode, "100644 ");
        u8bFeed(tree_buf, mode);
        a_cstr(name, files[i].name);
        u8bFeed(tree_buf, name);
        u8bFeed1(tree_buf, 0);
        a_rawc(sraw, bsha);
        u8bFeed(tree_buf, sraw);
    }

    sha1 tree_sha = {};
    a_dup(u8c, tc, u8bData(tree_buf));
    call(KEEPPackFeed, k, &p, DOG_OBJ_TREE, tc, 0, &tree_sha);

    // Commit object
    a_pad(u8, cbuf, 1024);
    a_cstr(cl1, "tree ");
    u8bFeed(cbuf, cl1);
    a_pad(u8, thex, 40);
    a_rawc(ts, tree_sha);
    HEXu8sFeedSome(thex_idle, ts);
    u8bFeed(cbuf, u8bDataC(thex));
    u8bFeed1(cbuf, '\n');

    if (parent) {
        a_cstr(pl, "parent ");
        u8bFeed(cbuf, pl);
        a_pad(u8, phex, 40);
        a_rawc(ps, *parent);
        HEXu8sFeedSome(phex_idle, ps);
        u8bFeed(cbuf, u8bDataC(phex));
        u8bFeed1(cbuf, '\n');
    }

    a_cstr(hdr, "author Test <t@t> 1700000000 +0000\n"
                "committer Test <t@t> 1700000000 +0000\n\ninitial\n");
    u8bFeed(cbuf, hdr);

    a_dup(u8c, cc, u8bData(cbuf));
    call(KEEPPackFeed, k, &p, DOG_OBJ_COMMIT, cc, 0, commit_out);
    call(KEEPPackClose, k, &p);
    done;
}

#if 0   //  Pre-migration `SNIFFRoundTrip` kept as a reference while the
        //  ULOG rewrite settles.  Covered initial commit → get → modify
        //  → put → post → delete → post → get.  Relied on the deleted
        //  wh64 cache.  When we rewrite round-trip coverage for the new
        //  API, this block goes away.
ok64 SNIFFRoundTrip_stash() {
    sane(1);
    call(FILEInit);
    call(make_tmpdir);

    a_cstr(root, g_tmpdir);
    home h = {};
    call(HOMEOpen, &h, root, YES);

    // 1. Create initial commit: a.txt, b.txt, c.txt
    
    call(KEEPOpen, &h, YES);

    testfile init_files[] = {
        {"a.txt", "alpha\n"},
        {"b.txt", "bravo\n"},
        {"c.txt", "charlie\n"},
    };
    sha1 c1_sha = {};
    call(make_commit, &c1_sha, &KEEP, init_files, 3, NULL);

    a_pad(u8, c1_hex, 40);
    sha2hex(c1_hex, &c1_sha);
    u8cs c1h = {u8bDataHead(c1_hex), u8bIdleHead(c1_hex)};

    // 2. GET: checkout initial commit
    sniff s = {};
    call(SNIFFOpen, &h, YES);
    u8cs no_src1 = {}; call(GETCheckout, root, c1h, no_src1);

    call(check_file, root, "a.txt", "alpha\n");
    call(check_file, root, "b.txt", "bravo\n");
    call(check_file, root, "c.txt", "charlie\n");
    fprintf(stderr, "  get: initial checkout OK\n");

    // Worktree's commit recorded in sniff/at.log.
    {
        a_pad(u8, at_b, 256);
        a_pad(u8, at_s, 64);
        sniff_at tail1 = {.branch = at_b, .sha = at_s};
        call(SNIFFAtRead, &tail1);
        want(u8bDataLen(tail1.sha) == 40);
        want(memcmp(u8bDataHead(tail1.sha), c1h[0], 40) == 0);
    }

    // 3. Modify a.txt, add d.txt.  Force new mtimes without a real
    // sleep: write the files first, then bump.
    call(write_file, root, "a.txt", "ALPHA MODIFIED\n");
    call(write_file, root, "d.txt", "delta new\n");
    {
        a_path(afp, root);
        a_cstr(afn, "/a.txt");
        u8bFeed(afp, afn);
        PATHu8bTerm(afp);
        bump_mtime((char *)u8bDataHead(afp), 2);

        a_path(dfp, root);
        a_cstr(dfn, "/d.txt");
        u8bFeed(dfp, dfn);
        PATHu8bTerm(dfp);
        bump_mtime((char *)u8bDataHead(dfp), 2);
    }

    // Intern d.txt and record changes
    a_cstr(dpath, "d.txt");
    u32 didx = SNIFFIntern(dpath);
    {
        a_path(afp, root);
        a_cstr(asep, "/a.txt");
        u8bFeed(afp, asep);
        PATHu8bTerm(afp);
        struct stat asb = {};
        call(FILEStat, &asb, $path(afp));
        // a.txt is idx 0 after checkout
        a_cstr(apath, "a.txt");
        u32 aidx = SNIFFIntern(apath);
        SNIFFRecord(SNIFF_CHANGED, aidx, (u64)asb.st_mtim.tv_sec);
    }
    {
        a_path(dfp, root);
        a_cstr(dsep, "/d.txt");
        u8bFeed(dfp, dsep);
        PATHu8bTerm(dfp);
        struct stat dsb = {};
        call(FILEStat, &dsb, $path(dfp));
        SNIFFRecord(SNIFF_CHANGED, didx, (u64)dsb.st_mtim.tv_sec);
    }

    // 4. POST: commit changes.  HEAD is set to c1 from GETCheckout;
    //    POSTCommit auto-stages everything dirty, then commits.
    sha1 c2_sha = {};
    a_cstr(msg2, "modify a, add d");
    a_cstr(author, "Test <t@t>");
    call(POSTCommit, root, msg2, author, &c2_sha);

    a_pad(u8, c2_hex, 40);
    sha2hex(c2_hex, &c2_sha);
    u8cs c2h = {u8bDataHead(c2_hex), u8bIdleHead(c2_hex)};
    fprintf(stderr, "  put: commit 2 OK\n");

    // Worktree's commit advanced to commit 2 (via at.log).
    {
        a_pad(u8, at_b2, 256);
        a_pad(u8, at_s2, 64);
        sniff_at tail2 = {.branch = at_b2, .sha = at_s2};
        call(SNIFFAtRead, &tail2);
        want(u8bDataLen(tail2.sha) == 40);
        want(memcmp(u8bDataHead(tail2.sha), c2h[0], 40) == 0);
    }

    // 5. Wipe sniff state + worktree, re-checkout commit 2 cleanly
    call(SNIFFClose);
    {
        char cmd[300];
        snprintf(cmd, sizeof(cmd),
                 "rm -rf %s/.dogs/sniff %s/a.txt %s/b.txt %s/c.txt %s/d.txt",
                 g_tmpdir, g_tmpdir, g_tmpdir, g_tmpdir, g_tmpdir);
        system(cmd);
    }

    call(SNIFFOpen, &h, YES);
    u8cs no_src2 = {}; call(GETCheckout, root, c2h, no_src2);

    call(check_file, root, "a.txt", "ALPHA MODIFIED\n");
    call(check_file, root, "b.txt", "bravo\n");
    call(check_file, root, "c.txt", "charlie\n");
    call(check_file, root, "d.txt", "delta new\n");
    fprintf(stderr, "  get: commit 2 checkout OK\n");

    // 6. DEL + POST: remove b.txt, create new commit
    {
        u32 npaths = SNIFFCount();
        Bu8 dsbuf = {};
        call(u8bAllocate, dsbuf, npaths);
        memset(u8bDataHead(dsbuf), 0, npaths);
        u8p dset = u8bDataHead(dsbuf);

        a_cstr(bpath, "b.txt");
        u32 bidx = SNIFFIntern(bpath);
        dset[bidx] = 1;

        //  Step 3 migrated DELStage to `(nuris, uris)`; the old
        //  idx-set shape is retired.  SNIFFRoundTrip is skipped until
        //  Step 6 rewrites it end-to-end.
        (void)dset;
        u8bFree(dsbuf);

        //  Commit the delete via POSTCommit — it owns the canonical
        //  repack of staged objects plus the commit onto main keeper.
        a_cstr(msg, "delete b");
        a_cstr(auth, "Test <t@t>");
        sha1 c3_sha = {};
        call(POSTCommit, root, msg, auth, &c3_sha);

        a_pad(u8, c3_hex, 40);
        sha2hex(c3_hex, &c3_sha);
        u8cs c3h = {u8bDataHead(c3_hex), u8bIdleHead(c3_hex)};

        // 7. GET the delete commit
        u8cs no_src3 = {}; call(GETCheckout, root, c3h, no_src3);

        call(check_file, root, "a.txt", "ALPHA MODIFIED\n");
        want(file_gone(root, "b.txt"));
        call(check_file, root, "c.txt", "charlie\n");
        call(check_file, root, "d.txt", "delta new\n");
        fprintf(stderr, "  get: commit 3 (delete b) OK\n");
    }

    call(SNIFFClose);
    call(KEEPClose);
    HOMEClose(&h);
    rm_tmpdir();
    done;
}
#endif  // SNIFFRoundTrip_stash

// --- Main ---

// --- Test: SNIFFWtListPaths ---
//
//  Build a small wt fixture, call SNIFFWtListPaths, assert the (paths,
//  meta) bytes match the expected lex-sorted layout.  Exercises the
//  meta-file filter (`.sniff*`, `.dogs/`) and the kind classification
//  (REG vs EXE vs LNK).

ok64 SNIFFWtListPathsTest() {
    sane(1);
    call(make_tmpdir);

    //  Files: a.txt (REG), b/c.txt (REG), run.sh (EXE), link (LNK→a.txt).
    //  Meta to filter: .sniff (file at root), .dogs/ (dir at root).
    char buf[400];
    snprintf(buf, sizeof(buf),
             "mkdir -p %s/b %s/.dogs && "
             "echo a > %s/a.txt && "
             "echo c > %s/b/c.txt && "
             "echo r > %s/run.sh && chmod +x %s/run.sh && "
             "ln -s a.txt %s/zlink && "
             "touch %s/.sniff && "
             "echo x > %s/.dogs/dummy",
             g_tmpdir, g_tmpdir, g_tmpdir, g_tmpdir, g_tmpdir, g_tmpdir,
             g_tmpdir, g_tmpdir, g_tmpdir);
    want(system(buf) == 0);

    a_dup(u8c, root, ((u8cs){(u8cp)g_tmpdir, (u8cp)g_tmpdir + strlen(g_tmpdir)}));

    Bu8 paths = {}, meta = {};
    call(u8bAllocate, paths, 1UL << 16);
    call(u8bAllocate, meta,  1UL << 16);
    call(SNIFFWtListPaths, root, paths, meta);

    a_cstr(want_paths, "a.txt\nb/c.txt\nrun.sh\nzlink\n");
    want(u8bDataLen(paths) == (size_t)$len(want_paths));
    want(memcmp(u8bDataHead(paths), want_paths[0],
                (size_t)$len(want_paths)) == 0);

    want(u8bDataLen(meta) == 4);
    u8 const *m = u8bDataHead(meta);
    want(m[0] == WALK_KIND_REG);   // a.txt
    want(m[1] == WALK_KIND_REG);   // b/c.txt
    want(m[2] == WALK_KIND_EXE);   // run.sh
    want(m[3] == WALK_KIND_LNK);   // zlink

    u8bFree(paths);
    u8bFree(meta);
    rm_tmpdir();
    done;
}

// --- SNIFFMergeWalk: 3-way grouping by path-key ---------------------

typedef struct {
    ron60 v_base, v_ours, v_theirs;
    u32   n;                  // step count
    u32   sizes[16];
    char  paths[16][64];
    u32   base[16], ours[16], theirs[16];
} merge_ctx;

static ok64 merge_step(ulogreccp recs, u32 n, void *vctx) {
    merge_ctx *c = (merge_ctx *)vctx;
    if (c->n >= 16) fail(FAIL);
    size_t L = u8csLen(recs[0].uri.path);
    if (L >= sizeof(c->paths[0])) L = sizeof(c->paths[0]) - 1;
    memcpy(c->paths[c->n], recs[0].uri.path[0], L);
    c->paths[c->n][L] = 0;
    c->sizes[c->n] = n;
    u32 nb = 0, no = 0, nt = 0;
    for (u32 i = 0; i < n; i++) {
        ron60 v = recs[i].verb;
        if      (v == c->v_base)   nb++;
        else if (v == c->v_ours)   no++;
        else if (v == c->v_theirs) nt++;
    }
    c->base[c->n]   = nb;
    c->ours[c->n]   = no;
    c->theirs[c->n] = nt;
    c->n++;
    return OK;
}

static ok64 SNIFFMergeWalkTest(void) {
    sane(1);

    //  Build three sorted ULOG buffers, one per "side":
    //    base : a, b, c
    //    ours : a, b
    //    theirs : b, c
    //  Expected steps: a (base, ours), b (base, ours, theirs), c (base, theirs).
    Bu8 b_base = {}, b_ours = {}, b_theirs = {};
    call(u8bAllocate, b_base,   1024);
    call(u8bAllocate, b_ours,   1024);
    call(u8bAllocate, b_theirs, 1024);

    a_cstr(s_base,   "base");   a_dup(u8c, dup_b, s_base);
    a_cstr(s_ours,   "ours");   a_dup(u8c, dup_o, s_ours);
    a_cstr(s_theirs, "theirs"); a_dup(u8c, dup_t, s_theirs);
    ron60 v_base = 0, v_ours = 0, v_theirs = 0;
    call(RONutf8sDrain, &v_base,   dup_b);
    call(RONutf8sDrain, &v_ours,   dup_o);
    call(RONutf8sDrain, &v_theirs, dup_t);

    //  Helper: feed one row with given (verb, path bytes) — empty mode/sha.
    #define EMIT(buf, vv, txt)                                          \
        do {                                                            \
            a_cstr(_p, txt);                                            \
            uri _u = {};                                                \
            _u.path[0] = _p[0]; _u.path[1] = _p[1];                     \
            ulogrec _r = {.ts = 0, .verb = (vv), .uri = _u};            \
            call(ULOGu8sFeed, u8bIdle(buf), &_r);                       \
        } while (0)

    EMIT(b_base,   v_base,   "a.txt");
    EMIT(b_base,   v_base,   "b.txt");
    EMIT(b_base,   v_base,   "c.txt");
    EMIT(b_ours,   v_ours,   "a.txt");
    EMIT(b_ours,   v_ours,   "b.txt");
    EMIT(b_theirs, v_theirs, "b.txt");
    EMIT(b_theirs, v_theirs, "c.txt");
    #undef EMIT

    a_dup(u8c, view_b, u8bData(b_base));
    a_dup(u8c, view_o, u8bData(b_ours));
    a_dup(u8c, view_t, u8bData(b_theirs));
    a_pad(u8cs, ins, 3);
    u8cssFeed1(ins_idle, view_b);
    u8cssFeed1(ins_idle, view_o);
    u8cssFeed1(ins_idle, view_t);
    a_dup(u8cs, cursors, u8csbData(ins));

    merge_ctx mctx = {.v_base = v_base, .v_ours = v_ours, .v_theirs = v_theirs};
    call(SNIFFMergeWalk, cursors, merge_step, &mctx);

    want(mctx.n == 3);
    want(strcmp(mctx.paths[0], "a.txt") == 0);
    want(mctx.sizes[0] == 2);
    want(mctx.base[0] == 1 && mctx.ours[0] == 1 && mctx.theirs[0] == 0);

    want(strcmp(mctx.paths[1], "b.txt") == 0);
    want(mctx.sizes[1] == 3);
    want(mctx.base[1] == 1 && mctx.ours[1] == 1 && mctx.theirs[1] == 1);

    want(strcmp(mctx.paths[2], "c.txt") == 0);
    want(mctx.sizes[2] == 2);
    want(mctx.base[2] == 1 && mctx.ours[2] == 0 && mctx.theirs[2] == 1);

    u8bFree(b_base);
    u8bFree(b_ours);
    u8bFree(b_theirs);
    done;
}

ok64 maintest() {
    sane(1);
    fprintf(stderr, "SNIFFAtHelpers...\n");
    call(SNIFFAtHelpers);
    fprintf(stderr, "SNIFFCheckoutCommit...\n");
    call(SNIFFCheckoutCommit);
    fprintf(stderr, "SNIFFWtListPaths...\n");
    call(SNIFFWtListPathsTest);
    fprintf(stderr, "SNIFFMergeWalk...\n");
    call(SNIFFMergeWalkTest);
    fprintf(stderr, "all passed\n");
    done;
}

TEST(maintest);
