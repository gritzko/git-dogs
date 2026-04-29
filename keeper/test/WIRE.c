//  WIRE — git upload-pack want/have negotiator + segment builder.
//
//  Cases:
//    1. Empty store, empty wants — flush-only request.
//    2. Single want, no haves — full segment from offset 12.
//    3. Single want with FF have — segment starts at end of pack
//       containing the have.
//    4. Want sha not in store — WIRENOSHA.
//    5. Capabilities parsing on the first want line.
//    6. Pkt-line round trip via a real pipe.
//    7. End-to-end with PSTR (`git index-pack`).

#include "keeper/WIRE.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "abc/FILE.h"
#include "abc/HEX.h"
#include "abc/PRO.h"
#include "abc/TEST.h"
#include "keeper/PACK.h"
#include "keeper/PKT.h"
#include "keeper/PSTR.h"
#include "keeper/REFADV.h"
#include "keeper/SHA1.h"

#define GIT_UNSET "unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR " \
                  "GIT_INDEX_FILE GIT_OBJECT_DIRECTORY && "

// --- helpers ---

static void tmp_rm(char const *path) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", path);
    int _ = system(cmd);
    (void)_;
}

//  Encode a sha1 into 40 hex chars in `out` (size 40).
static void sha_to_hex(u8 *out40, sha1 const *s) {
    u8s hs = {out40, out40 + 40};
    u8cs bs = {s->data, s->data + 20};
    HEXu8sFeedSome(hs, bs);
}

//  Build a request byte buffer holding wants, haves, done.  Each is
//  appended as a pkt-line.  No flush before "done" (vanilla git
//  upload-pack accepts both).
static ok64 build_request(u8b out,
                          sha1 const *wants, u32 nwants,
                          char const *first_caps,
                          sha1 const *haves, u32 nhaves) {
    sane(u8bOK(out));
    for (u32 i = 0; i < nwants; i++) {
        a_pad(u8, line, 256);
        a_cstr(want_pfx, "want ");
        u8bFeed(line, want_pfx);
        u8 hex[40];
        sha_to_hex(hex, &wants[i]);
        u8cs hexs = {hex, hex + 40};
        u8bFeed(line, hexs);
        if (i == 0 && first_caps && *first_caps) {
            u8bFeed1(line, ' ');
            u8cs caps = {(u8cp)first_caps,
                         (u8cp)first_caps + strlen(first_caps)};
            u8bFeed(line, caps);
        }
        u8bFeed1(line, '\n');
        a_dup(u8c, payload, u8bData(line));
        call(PKTu8sFeed, u8bIdle(out), payload);
    }
    if (nwants > 0) call(PKTu8sFeedFlush, u8bIdle(out));
    for (u32 i = 0; i < nhaves; i++) {
        a_pad(u8, line, 128);
        a_cstr(have_pfx, "have ");
        u8bFeed(line, have_pfx);
        u8 hex[40];
        sha_to_hex(hex, &haves[i]);
        u8cs hexs = {hex, hex + 40};
        u8bFeed(line, hexs);
        u8bFeed1(line, '\n');
        a_dup(u8c, payload, u8bData(line));
        call(PKTu8sFeed, u8bIdle(out), payload);
    }
    {
        a_cstr(donec, "done\n");
        call(PKTu8sFeed, u8bIdle(out), donec);
    }
    done;
}

//  Pump bytes into a pipe; return the read end.  Spawns a thread-
//  free helper: forks, writes from child, then exits.  Caller closes
//  the returned fd.
static int pipe_with_bytes(u8csc bytes) {
    int p[2] = {-1, -1};
    if (pipe(p) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(p[0]); close(p[1]); return -1; }
    if (pid == 0) {
        close(p[0]);
        u8c *cur = bytes[0];
        size_t left = (size_t)u8csLen(bytes);
        while (left > 0) {
            ssize_t n = write(p[1], cur, left);
            if (n <= 0) break;
            cur  += n;
            left -= (size_t)n;
        }
        close(p[1]);
        _exit(0);
    }
    close(p[1]);
    return p[0];
}

// ---- Test 1: empty store, no wants ----

ok64 WIREtest_empty() {
    sane(1);
    call(FILEInit);

    char tmpdir[] = "/tmp/wire-empty-XXXXXX";
    want(mkdtemp(tmpdir) != NULL);
    a_cstr(root, tmpdir);
    home h = {};
    call(HOMEOpen, &h, root, YES);
    call(KEEPOpen, &h, YES);

    refadv adv = {};
    call(REFADVOpen, &adv, &KEEP);

    //  Build a request that's just "done\n" (no wants).
    Bu8 reqbuf = {};
    call(u8bAllocate, reqbuf, 256);
    call(build_request, reqbuf, NULL, 0, NULL, NULL, 0);

    a_dup(u8c, reqbytes, u8bData(reqbuf));
    int rfd = pipe_with_bytes(reqbytes);
    want(rfd >= 0);

    wire_req req = {};
    call(WIREReadRequest, rfd, &req);
    want(req.nwants == 0);
    want(req.nhaves == 0);
    close(rfd);

    pstr_seg segs[4] = {};
    int      fds [4] = {-1,-1,-1,-1};
    u32      n = 0;
    call(WIREBuildSegments, &KEEP, &adv, &req, segs, fds, 4, &n);
    want(n == 0);
    for (int i = 0; i < 4; i++) want(fds[i] == -1);

    u8bFree(reqbuf);
    REFADVClose(&adv);
    call(KEEPClose);
    HOMEClose(&h);
    tmp_rm(tmpdir);
    done;
}

// ---- helpers: build a tiny one-pack keeper ----

//  Add a pack with a single blob; report its sha + the resulting
//  pack file_id.  KEEPPackOpen reuses the tail file when packs
//  exist, so calling this twice produces two packs in file_id=1.
static ok64 add_blob_pack(sha1 *out_sha, u32 *out_file_id,
                          char const *content) {
    sane(out_sha && out_file_id);
    keep_pack p = {};
    call(KEEPPackOpen, &KEEP, &p);
    a_cstr(blob_s, content);
    sha1 sha = {};
    call(KEEPPackFeed, &KEEP, &p, DOG_OBJ_BLOB, blob_s, 0, &sha);
    *out_sha     = sha;
    *out_file_id = p.file_id;
    call(KEEPPackClose, &KEEP, &p);
    done;
}

// ---- Test 2: single want, no haves → full segment ----

ok64 WIREtest_single_want() {
    sane(1);
    call(FILEInit);

    char tmpdir[] = "/tmp/wire-single-XXXXXX";
    want(mkdtemp(tmpdir) != NULL);
    a_cstr(root, tmpdir);
    home h = {};
    call(HOMEOpen, &h, root, YES);
    call(KEEPOpen, &h, YES);

    sha1 blob_sha = {};
    u32  fid = 0;
    call(add_blob_pack, &blob_sha, &fid, "hello wire\n");
    want(fid == 1);
    want(kv32bDataLen(KEEP.packs) == 1);

    refadv adv = {};
    call(REFADVOpen, &adv, &KEEP);

    wire_req req = {};
    req.nwants = 1;
    req.wants[0] = blob_sha;

    pstr_seg segs[4] = {};
    int      fds [4] = {-1,-1,-1,-1};
    u32      n = 0;
    call(WIREBuildSegments, &KEEP, &adv, &req, segs, fds, 4, &n);
    want(n == 1);
    want(fds[0] >= 0);
    want(segs[0].fd == fds[0]);
    want(segs[0].offset == 12);
    want(segs[0].length > 0);
    want(segs[0].count == 1);

    close(fds[0]);
    REFADVClose(&adv);
    call(KEEPClose);
    HOMEClose(&h);
    tmp_rm(tmpdir);
    done;
}

// ---- Test 3: want + matching have → tail-only segment ----

ok64 WIREtest_have_ff() {
    sane(1);
    call(FILEInit);

    char tmpdir[] = "/tmp/wire-ff-XXXXXX";
    want(mkdtemp(tmpdir) != NULL);
    a_cstr(root, tmpdir);
    home h = {};
    call(HOMEOpen, &h, root, YES);
    call(KEEPOpen, &h, YES);

    //  First pack: blob A (the "have").
    sha1 sha_a = {};
    u32  fid_a = 0;
    call(add_blob_pack, &sha_a, &fid_a, "alpha\n");
    want(fid_a == 1);

    //  Second pack: blob B (the "want") — appended to the same
    //  log file (file_id stays 1).  That mirrors keeper's append-
    //  of-packs storage: pack 2 starts where pack 1 ended.
    sha1 sha_b = {};
    u32  fid_b = 0;
    call(add_blob_pack, &sha_b, &fid_b, "bravo\n");
    want(fid_b == 1);

    refadv adv = {};
    call(REFADVOpen, &adv, &KEEP);

    wire_req req = {};
    req.nwants = 1;
    req.wants[0] = sha_b;
    req.nhaves = 1;
    req.haves[0] = sha_a;

    pstr_seg segs[4] = {};
    int      fds [4] = {-1,-1,-1,-1};
    u32      n = 0;
    call(WIREBuildSegments, &KEEP, &adv, &req, segs, fds, 4, &n);
    want(n == 1);
    want(fds[0] >= 0);
    //  Watermark must skip past the first pack — segment offset > 12.
    want(segs[0].offset > 12);
    want(segs[0].length > 0);
    want(segs[0].count == 1);   // only blob B in this segment

    close(fds[0]);
    REFADVClose(&adv);
    call(KEEPClose);
    HOMEClose(&h);
    tmp_rm(tmpdir);
    done;
}

// ---- Test 4: want sha unknown → WIRENOSHA ----

ok64 WIREtest_nosha() {
    sane(1);
    call(FILEInit);

    char tmpdir[] = "/tmp/wire-nosha-XXXXXX";
    want(mkdtemp(tmpdir) != NULL);
    a_cstr(root, tmpdir);
    home h = {};
    call(HOMEOpen, &h, root, YES);
    call(KEEPOpen, &h, YES);

    sha1 known = {};
    u32  fid   = 0;
    call(add_blob_pack, &known, &fid, "real blob\n");

    refadv adv = {};
    call(REFADVOpen, &adv, &KEEP);

    wire_req req = {};
    req.nwants = 1;
    //  All-zero sha is guaranteed not to be in the store.
    sha1 phantom = {};
    req.wants[0] = phantom;

    pstr_seg segs[4] = {};
    int      fds [4] = {-1,-1,-1,-1};
    u32      n = 0;
    ok64 rc = WIREBuildSegments(&KEEP, &adv, &req, segs, fds, 4, &n);
    want(rc == WIRENOSHA);

    REFADVClose(&adv);
    call(KEEPClose);
    HOMEClose(&h);
    tmp_rm(tmpdir);
    done;
}

// ---- Test 5: capability parsing ----

ok64 WIREtest_caps() {
    sane(1);
    call(FILEInit);

    char tmpdir[] = "/tmp/wire-caps-XXXXXX";
    want(mkdtemp(tmpdir) != NULL);
    a_cstr(root, tmpdir);
    home h = {};
    call(HOMEOpen, &h, root, YES);
    call(KEEPOpen, &h, YES);

    sha1 blob = {};
    u32  fid  = 0;
    call(add_blob_pack, &blob, &fid, "caps blob\n");

    Bu8 reqbuf = {};
    call(u8bAllocate, reqbuf, 1024);
    call(build_request, reqbuf, &blob, 1,
         "ofs-delta side-band-64k thin-pack",
         NULL, 0);

    a_dup(u8c, reqbytes, u8bData(reqbuf));
    int rfd = pipe_with_bytes(reqbytes);
    want(rfd >= 0);

    wire_req req = {};
    call(WIREReadRequest, rfd, &req);
    close(rfd);

    want(req.nwants == 1);
    want((req.caps & WIRE_CAP_OFS_DELTA)     != 0);
    want((req.caps & WIRE_CAP_SIDE_BAND_64K) != 0);
    want((req.caps & WIRE_CAP_THIN_PACK)     != 0);
    want((req.caps & WIRE_CAP_NO_PROGRESS)   == 0);

    u8bFree(reqbuf);
    call(KEEPClose);
    HOMEClose(&h);
    tmp_rm(tmpdir);
    done;
}

// ---- Test 6: pkt-line round trip ----

ok64 WIREtest_round_trip() {
    sane(1);
    call(FILEInit);

    char tmpdir[] = "/tmp/wire-round-XXXXXX";
    want(mkdtemp(tmpdir) != NULL);
    a_cstr(root, tmpdir);
    home h = {};
    call(HOMEOpen, &h, root, YES);
    call(KEEPOpen, &h, YES);

    sha1 sha_a = {};
    u32  fid_a = 0;
    call(add_blob_pack, &sha_a, &fid_a, "round trip alpha\n");
    sha1 sha_b = {};
    u32  fid_b = 0;
    call(add_blob_pack, &sha_b, &fid_b, "round trip bravo\n");

    sha1 wants[1] = { sha_b };
    sha1 haves[1] = { sha_a };
    Bu8 reqbuf = {};
    call(u8bAllocate, reqbuf, 4096);
    call(build_request, reqbuf, wants, 1, NULL, haves, 1);

    a_dup(u8c, reqbytes, u8bData(reqbuf));
    int rfd = pipe_with_bytes(reqbytes);
    want(rfd >= 0);

    wire_req req = {};
    call(WIREReadRequest, rfd, &req);
    close(rfd);

    want(req.nwants == 1);
    want(req.nhaves == 1);
    want(sha1eq(&req.wants[0], &sha_b));
    want(sha1eq(&req.haves[0], &sha_a));

    u8bFree(reqbuf);
    call(KEEPClose);
    HOMEClose(&h);
    tmp_rm(tmpdir);
    done;
}

// ---- Test 7: end-to-end via PSTR + git index-pack ----

ok64 WIREtest_end_to_end() {
    sane(1);
    call(FILEInit);

    char tmpdir[] = "/tmp/wire-e2e-XXXXXX";
    want(mkdtemp(tmpdir) != NULL);
    a_cstr(root, tmpdir);
    home h = {};
    call(HOMEOpen, &h, root, YES);
    call(KEEPOpen, &h, YES);

    sha1 blob_sha = {};
    u32  fid      = 0;
    call(add_blob_pack, &blob_sha, &fid, "end to end\n");

    refadv adv = {};
    call(REFADVOpen, &adv, &KEEP);

    wire_req req = {};
    req.nwants = 1;
    req.wants[0] = blob_sha;

    pstr_seg segs[4] = {};
    int      fds [4] = {-1,-1,-1,-1};
    u32      n = 0;
    call(WIREBuildSegments, &KEEP, &adv, &req, segs, fds, 4, &n);
    want(n == 1);

    char outpath[] = "/tmp/wire-e2e-pack-XXXXXX";
    int  out_fd = mkstemp(outpath);
    want(out_fd >= 0);
    pstr_segcs slice = {segs, segs + n};
    call(PSTRWrite, out_fd, slice);
    close(out_fd);
    for (int i = 0; i < 4; i++) if (fds[i] >= 0) close(fds[i]);

    //  Verify with git index-pack.
    char idxpath[1024];
    snprintf(idxpath, sizeof(idxpath), "%s.idx", outpath);
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
             GIT_UNSET "cd / && git index-pack -o %s %s >/dev/null 2>&1",
             idxpath, outpath);
    int rc = system(cmd);
    unlink(idxpath);
    unlink(outpath);
    want(rc == 0);

    REFADVClose(&adv);
    call(KEEPClose);
    HOMEClose(&h);
    tmp_rm(tmpdir);
    done;
}

ok64 maintest() {
    sane(1);
    fprintf(stderr, "WIREtest_empty...\n");
    call(WIREtest_empty);
    fprintf(stderr, "WIREtest_single_want...\n");
    call(WIREtest_single_want);
    fprintf(stderr, "WIREtest_have_ff...\n");
    call(WIREtest_have_ff);
    fprintf(stderr, "WIREtest_nosha...\n");
    call(WIREtest_nosha);
    fprintf(stderr, "WIREtest_caps...\n");
    call(WIREtest_caps);
    fprintf(stderr, "WIREtest_round_trip...\n");
    call(WIREtest_round_trip);
    fprintf(stderr, "WIREtest_end_to_end...\n");
    call(WIREtest_end_to_end);
    fprintf(stderr, "all passed\n");
    done;
}

TEST(maintest)
