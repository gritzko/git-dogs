//  UPLOADPACK — `keeper upload-pack` CLI verb (WIRE.md Phase 5).
//
//  Spawns the built `keeper` binary as a subprocess (the way ssh
//  invokes git-upload-pack), drives it over stdin/stdout pkt-lines,
//  and validates the responses end-to-end.
//
//  Cases:
//    1. Smoke: drive a flush-only request, drain the refs advert,
//       expect at least one ref + final flush.
//    2. End-to-end: send `want <sha>` + flush + `done`, drain NAK +
//       packfile, validate via `git index-pack --stdin`.
//
//  Real-git-client compat (clone via `file://` against our binary)
//  is deferred — exercising the wire end-to-end here pins the
//  protocol down without dragging in a git-shell shim.

#include "keeper/KEEP.h"
#include "keeper/PKT.h"
#include "keeper/REFS.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "abc/FILE.h"
#include "abc/HEX.h"
#include "abc/PRO.h"
#include "abc/TEST.h"
#include "dog/HOME.h"

// --- helpers ---

static void tmp_rm(char const *path) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", path);
    int _ = system(cmd);
    (void)_;
}

//  Locate the built keeper binary.  KEEPER_BIN env var wins, else fall
//  back to a relative path that works under ctest's WORKING_DIRECTORY
//  (which is build-debug/keeper/test).
static char const *keeper_bin(void) {
    char const *env = getenv("KEEPER_BIN");
    if (env && *env) return env;
    return "../../bin/keeper";
}

//  Build a fixture keeper repo at `tmpdir`: one trunk pack with a
//  single blob, plus a `?heads/main → ?<40hex-of-blob>` REFS entry so
//  REFADV has something to advertise.  Reports the blob's 40-hex SHA
//  via `out_hex` (must hold 41 bytes incl. NUL).
static ok64 stage_fixture(char const *tmpdir, char *out_hex_41) {
    sane(tmpdir && out_hex_41);
    a_cstr(root_s, tmpdir);
    home h = {};
    call(HOMEOpenAt, &h, root_s, YES);
    call(KEEPOpen, &h, YES);

    keep_pack p = {};
    call(KEEPPackOpen, &KEEP, &p);
    a_cstr(blob_s, "upload-pack fixture\n");
    sha1 sha = {};
    call(KEEPPackFeed, &KEEP, &p,
         KEEP_OBJ_BLOB, blob_s, 0, &sha);
    call(KEEPPackClose, &KEEP, &p);

    //  Encode sha → 40 hex chars + NUL.
    u8s hexs = {(u8 *)out_hex_41, (u8 *)out_hex_41 + 40};
    u8cs bs = {sha.data, sha.data + 20};
    HEXu8sFeedSome(hexs, bs);
    out_hex_41[40] = 0;

    //  Append a REFS entry pointing heads/main → blob sha.  The blob
    //  is not really a commit, but REFADV doesn't care — it just emits
    //  whatever (sha, refname) pairs REFS holds.  Real fetches against
    //  this fixture would refuse (git wants a commit/tag), but the
    //  pack-stitching path is exercised with raw sha lookup.
    a_path(keepdir, u8bDataC(KEEP.h->root), KEEP_DIR_S);
    a_pad(u8, kbuf, 256);
    u8bFeed1(kbuf, '?');
    a_cstr(heads, "heads/main");
    u8bFeed(kbuf, heads);
    a_dup(u8c, key, u8bData(kbuf));

    a_pad(u8, vbuf, 64);
    u8bFeed1(vbuf, '?');
    u8cs hex_cs = {(u8 *)out_hex_41, (u8 *)out_hex_41 + 40};
    u8bFeed(vbuf, hex_cs);
    a_dup(u8c, val, u8bData(vbuf));

    call(REFSAppend, $path(keepdir), key, val);

    call(KEEPClose);
    HOMEClose(&h);
    done;
}

//  Spawn `keeper upload-pack <repo>` with piped stdin/stdout.  Returns
//  child pid in *out_pid; *wfd / *rfd are the parent ends.
static ok64 spawn_upload_pack(char const *repo, pid_t *out_pid,
                              int *wfd, int *rfd) {
    sane(repo && out_pid && wfd && rfd);
    int to_child[2], from_child[2];
    if (pipe(to_child) != 0 || pipe(from_child) != 0) return FAIL;

    pid_t pid = fork();
    if (pid < 0) return FAIL;
    if (pid == 0) {
        close(to_child[1]);
        close(from_child[0]);
        dup2(to_child[0], 0);
        dup2(from_child[1], 1);
        close(to_child[0]);
        close(from_child[1]);
        execl(keeper_bin(), "keeper", "upload-pack", repo, (char *)NULL);
        _exit(127);
    }
    close(to_child[0]);
    close(from_child[1]);
    *out_pid = pid;
    *wfd = to_child[1];
    *rfd = from_child[0];
    done;
}

//  Drain the entire refs advertisement (pkt-lines until flush).
//  Reads more bytes from rfd as needed, growing `buf` up to `cap`.
//  On return, *adv_end is the count of bytes belonging to the advert
//  (everything up to and including the flush packet "0000").
static ok64 drain_advert(int rfd, u8 *buf, size_t cap, size_t *out_adv_end,
                         u32 *out_nrefs) {
    sane(rfd >= 0 && buf && out_adv_end && out_nrefs);
    *out_nrefs = 0;
    size_t have = 0;
    size_t cursor_off = 0;
    for (;;) {
        if (have >= cap) return FAIL;
        u8cs scan = {buf + cursor_off, buf + have};
        u8cs line = {};
        ok64 d = PKTu8sDrain(scan, line);
        if (d == NODATA) {
            ssize_t n = read(rfd, buf + have, cap - have);
            if (n <= 0) return FAIL;
            have += (size_t)n;
            continue;
        }
        if (d == PKTFLUSH) {
            cursor_off = (size_t)(scan[0] - buf);
            *out_adv_end = cursor_off;
            done;
        }
        if (d != OK) return d;
        cursor_off = (size_t)(scan[0] - buf);
        (*out_nrefs)++;
    }
}

// ---- Test 1: smoke ----

ok64 UPLOADPACKtest_smoke() {
    sane(1);
    call(FILEInit);

    char tmpdir[] = "/tmp/upload-pack-smoke-XXXXXX";
    want(mkdtemp(tmpdir) != NULL);

    char hex[41];
    call(stage_fixture, tmpdir, hex);

    pid_t pid = -1;
    int wfd = -1, rfd = -1;
    call(spawn_upload_pack, tmpdir, &pid, &wfd, &rfd);

    //  Drain the advertisement first (server emits it unconditionally).
    static u8 rbuf[1 << 20];
    size_t adv_end = 0;
    u32 nrefs = 0;
    call(drain_advert, rfd, rbuf, sizeof(rbuf), &adv_end, &nrefs);
    want(nrefs >= 1);

    //  Send a flush-only request — server treats this as no-want and
    //  closes the wire after emitting NAK (and an empty pack).
    {
        u8 fbuf[8];
        u8s fs = {fbuf, fbuf + sizeof(fbuf)};
        want(PKTu8sFeedFlush(fs) == OK);
        u64 wlen = (u64)(fs[0] - fbuf);
        want(write(wfd, fbuf, (size_t)wlen) == (ssize_t)wlen);
    }
    close(wfd);

    //  Drain whatever's left so the child closes cleanly.
    for (;;) {
        u8 dump[4096];
        ssize_t n = read(rfd, dump, sizeof(dump));
        if (n <= 0) break;
    }
    close(rfd);

    int status = 0;
    waitpid(pid, &status, 0);
    //  Server may exit non-zero on an empty request (no wants → nothing
    //  to ship); we only care that the advertisement made it through.

    tmp_rm(tmpdir);
    done;
}

// ---- Test 2: end-to-end fetch via git index-pack ----

ok64 UPLOADPACKtest_fetch() {
    sane(1);
    call(FILEInit);

    char tmpdir[] = "/tmp/upload-pack-fetch-XXXXXX";
    want(mkdtemp(tmpdir) != NULL);

    char hex[41];
    call(stage_fixture, tmpdir, hex);

    pid_t pid = -1;
    int wfd = -1, rfd = -1;
    call(spawn_upload_pack, tmpdir, &pid, &wfd, &rfd);

    static u8 rbuf[1 << 20];
    size_t adv_end = 0;
    u32 nrefs = 0;
    call(drain_advert, rfd, rbuf, sizeof(rbuf), &adv_end, &nrefs);
    want(nrefs >= 1);

    //  Send `want <sha>\n` + flush + `done\n`.
    {
        u8 wbuf[512];
        u8s ws = {wbuf, wbuf + sizeof(wbuf)};

        char pktpay[128];
        int plen = snprintf(pktpay, sizeof(pktpay),
                            "want %.40s\n", hex);
        u8cs payload = {(u8 *)pktpay, (u8 *)pktpay + plen};
        want(PKTu8sFeed(ws, payload) == OK);
        want(PKTu8sFeedFlush(ws) == OK);
        u8 donepay[] = "done\n";
        u8cs donecs = {donepay, donepay + 5};
        want(PKTu8sFeed(ws, donecs) == OK);

        u64 wlen = (u64)(ws[0] - wbuf);
        want(write(wfd, wbuf, (size_t)wlen) == (ssize_t)wlen);
    }
    close(wfd);

    //  Drain the rest of the response (NAK + packfile bytes).
    size_t resp_off = adv_end;
    for (;;) {
        if (resp_off >= sizeof(rbuf)) break;
        ssize_t n = read(rfd, rbuf + resp_off, sizeof(rbuf) - resp_off);
        if (n <= 0) break;
        resp_off += (size_t)n;
    }
    close(rfd);

    int status = 0;
    waitpid(pid, &status, 0);

    //  resp_off - adv_end = bytes of pack response.  Strip the leading
    //  "0008NAK\n" pkt-line, then dump the rest as a candidate pack.
    want(resp_off > adv_end + 8);
    u8cs resp = {rbuf + adv_end, rbuf + resp_off};
    u8cs naktag = {};
    ok64 d = PKTu8sDrain(resp, naktag);
    want(d == OK);
    want($len(naktag) >= 3);
    want(memcmp(naktag[0], "NAK", 3) == 0);

    //  Write the remaining pack bytes to a tmpfile, run `git index-pack`.
    char packpath[] = "/tmp/upload-pack-pack-XXXXXX";
    int pfd = mkstemp(packpath);
    want(pfd >= 0);
    size_t pack_len = (size_t)$len(resp);
    want(write(pfd, resp[0], pack_len) == (ssize_t)pack_len);
    close(pfd);

    char idxpath[1024];
    snprintf(idxpath, sizeof(idxpath), "%s.idx", packpath);
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
             "unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR "
             "GIT_INDEX_FILE GIT_OBJECT_DIRECTORY && "
             "cd / && git index-pack -o %s %s >/dev/null 2>&1",
             idxpath, packpath);
    int rc = system(cmd);
    unlink(idxpath);
    unlink(packpath);
    want(rc == 0);

    tmp_rm(tmpdir);
    done;
}

ok64 maintest() {
    sane(1);
    fprintf(stderr, "UPLOADPACKtest_smoke...\n");
    call(UPLOADPACKtest_smoke);
    fprintf(stderr, "UPLOADPACKtest_fetch...\n");
    call(UPLOADPACKtest_fetch);
    fprintf(stderr, "all passed\n");
    done;
}

TEST(maintest)
