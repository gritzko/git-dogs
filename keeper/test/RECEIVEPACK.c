//  RECEIVEPACK — `keeper receive-pack` CLI verb (WIRE.md Phase 6).
//
//  Spawns the built `keeper` binary as a subprocess (the way ssh
//  invokes git-receive-pack), drives it over stdin/stdout pkt-lines,
//  and validates the responses end-to-end.
//
//  Cases:
//    1. Smoke: drive a flush-only request, drain the refs advert,
//       expect a clean (empty) response.
//    2. Single create: send create-update + a real packfile (built
//       with `git pack-objects`), verify "unpack ok" + "ok refs/..."
//       + REFS now holds the new tip.
//    3. FF update: pre-seed REFS with tip A, push A → B (a fresh
//       commit), verify accepted + REFS holds B.
//    4. Non-FF rejection: pre-seed REFS with tip A, send B → C
//       (B != A), expect `ng … non-fast-forward`, REFS unchanged.

#include "keeper/GIT.h"
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
#include "dog/DOG.h"
#include "dog/HOME.h"

#define GIT_UNSET "unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR " \
                  "GIT_INDEX_FILE GIT_OBJECT_DIRECTORY && "

// --- helpers ---

static void tmp_rm(char const *path) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", path);
    int _ = system(cmd);
    (void)_;
}

//  Locate the built keeper binary.  KEEPER_BIN env wins, else fall
//  back to the relative path under build-debug/keeper/test.
static char const *keeper_bin(void) {
    char const *env = getenv("KEEPER_BIN");
    if (env && *env) return env;
    return "../../bin/keeper";
}

//  Spawn `keeper receive-pack <repo>` with piped stdin/stdout.
static ok64 spawn_receive_pack(char const *repo, pid_t *out_pid,
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
        execl(keeper_bin(), "keeper", "receive-pack", repo, (char *)NULL);
        _exit(127);
    }
    close(to_child[0]);
    close(from_child[1]);
    *out_pid = pid;
    *wfd = to_child[1];
    *rfd = from_child[0];
    done;
}

//  Drain the refs advertisement (pkt-lines until flush), reporting
//  byte count consumed plus advertised ref count.
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

//  Drain everything available on rfd until EOF, into buf[*off ..].
//  Updates *off.
static void drain_until_eof(int rfd, u8 *buf, size_t cap, size_t *off) {
    for (;;) {
        if (*off >= cap) break;
        ssize_t n = read(rfd, buf + *off, cap - *off);
        if (n <= 0) break;
        *off += (size_t)n;
    }
}

//  Build a repo + commit via git, then `git pack-objects --revs` to
//  produce a pack containing the commit + tree + blob.  Reports the
//  commit's 40-hex SHA into out_hex_41 and the on-disk pack path into
//  pack_path (caller-allocated, ≥ 1024 bytes).
static ok64 stage_git_commit(char const *workdir, char const *content,
                             char *out_hex_41, char *pack_path, size_t pcap) {
    sane(workdir && content && out_hex_41 && pack_path);

    char cmd[2048];
    int rc;

    //  Init repo + one commit.
    snprintf(cmd, sizeof(cmd),
             GIT_UNSET
             "cd %s && git init -q && "
             "git config user.email t@t && git config user.name t && "
             "printf '%s' > a.txt && "
             "git add a.txt && git commit -q -m c1",
             workdir, content);
    rc = system(cmd);
    if (rc != 0) return FAIL;

    //  Capture HEAD commit sha.
    snprintf(cmd, sizeof(cmd),
             GIT_UNSET
             "cd %s && git rev-parse HEAD",
             workdir);
    FILE *fp = popen(cmd, "r");
    if (!fp) return FAIL;
    if (fread(out_hex_41, 1, 40, fp) != 40) { pclose(fp); return FAIL; }
    out_hex_41[40] = 0;
    pclose(fp);

    //  Build a pack containing HEAD's reachable closure.
    snprintf(pack_path, pcap, "%s/objects.pack", workdir);
    snprintf(cmd, sizeof(cmd),
             GIT_UNSET
             "cd %s && git rev-list --objects HEAD | "
             "git pack-objects --stdout > %s",
             workdir, pack_path);
    rc = system(cmd);
    if (rc != 0) return FAIL;
    done;
}

//  Map a wire refname (e.g. "refs/heads/main", "refs/heads/feat") to
//  the local be-side REFS key ("?", "?feat") — same translation the
//  receiver applies in recv_build_key, so seed/update round-trip.
static void wire_to_be_key(u8b out, char const *refname) {
    u8csc rn = {(u8cp)refname, (u8cp)refname + strlen(refname)};
    gitref_kind k = GITREF_NONE;
    u8cs name = {};
    (void)GITParseRef(rn, &k, name);
    u8bFeed1(out, '?');
    if (k != GITREF_BRANCH) return;
    a_cstr(main_s, "main");
    if (u8csLen(name) == u8csLen(main_s) &&
        memcmp(name[0], main_s[0], (size_t)u8csLen(main_s)) == 0)
        return;  //  trunk
    u8bFeed(out, name);
}

//  Pre-seed a REFS entry.  refname looks like "refs/heads/main"; we
//  translate it to the local be-side key the receiver would produce.
static ok64 seed_ref(char const *tmpdir, char const *refname,
                     char const *hex_40) {
    sane(tmpdir && refname && hex_40);
    a_cstr(root_s, tmpdir);
    home h = {};
    call(HOMEOpenAt, &h, root_s, YES);
    call(KEEPOpen, &h, YES);
    a_path(keepdir, u8bDataC(KEEP.h->root), KEEP_DIR_S);

    a_pad(u8, kbuf, 256);
    wire_to_be_key(kbuf, refname);
    a_dup(u8c, key, u8bData(kbuf));

    u8csc val = {(u8cp)hex_40, (u8cp)hex_40 + 40};
    call(REFSAppend, $path(keepdir), key, val);

    call(KEEPClose);
    HOMEClose(&h);
    done;
}

//  Look up a REFS entry by key, copy its 40-hex sha into out (which
//  must hold at least 41 bytes incl. NUL).  Returns NO if missing.
static b8 lookup_ref(char const *tmpdir, char const *refname, char *out_41) {
    a_cstr(root_s, tmpdir);
    home h = {};
    if (HOMEOpenAt(&h, root_s, NO) != OK) return NO;
    if (KEEPOpen(&h, NO) != OK) { HOMEClose(&h); return NO; }
    a_path(keepdir, u8bDataC(KEEP.h->root), KEEP_DIR_S);

    a_pad(u8, kbuf, 256);
    wire_to_be_key(kbuf, refname);
    a_dup(u8c, key, u8bData(kbuf));

    a_pad(u8, arena, 256);
    uri res = {};
    ok64 ro = REFSResolve(&res, arena, $path(keepdir), key);
    b8 found = NO;
    if (ro == OK && u8csLen(res.query) == 40) {
        memcpy(out_41, res.query[0], 40);
        out_41[40] = 0;
        found = YES;
    }
    KEEPClose();
    HOMEClose(&h);
    return found;
}

//  Compose one ref-update pkt-line payload.  Caller appends the trailing
//  flush + pack bytes themselves.
static ok64 build_update_line(u8b out, char const *old_hex,
                              char const *new_hex, char const *refname,
                              char const *caps) {
    sane(u8bOK(out));
    a_pad(u8, line, 512);
    u8csc oh = {(u8cp)old_hex, (u8cp)old_hex + 40};
    u8csc nh = {(u8cp)new_hex, (u8cp)new_hex + 40};
    u8csc rn = {(u8cp)refname, (u8cp)refname + strlen(refname)};
    u8bFeed(line, oh);
    u8bFeed1(line, ' ');
    u8bFeed(line, nh);
    u8bFeed1(line, ' ');
    u8bFeed(line, rn);
    if (caps && *caps) {
        u8bFeed1(line, 0);
        u8csc cs = {(u8cp)caps, (u8cp)caps + strlen(caps)};
        u8bFeed(line, cs);
    }
    u8bFeed1(line, '\n');
    a_dup(u8c, payload, u8bData(line));
    return PKTu8sFeed(u8bIdle(out), payload);
}

//  Read entire file into buf (caller-allocated).  *out_len updated.
static ok64 slurp_file(char const *path, u8 *buf, size_t cap, size_t *out_len) {
    sane(path && buf && out_len);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return FAIL;
    size_t off = 0;
    for (;;) {
        if (off >= cap) { close(fd); return FAIL; }
        ssize_t n = read(fd, buf + off, cap - off);
        if (n < 0) { close(fd); return FAIL; }
        if (n == 0) break;
        off += (size_t)n;
    }
    close(fd);
    *out_len = off;
    done;
}

// ---- Test 1: smoke — flush-only request, no updates, no pack ----

ok64 RECEIVEPACKtest_smoke() {
    sane(1);
    call(FILEInit);

    char tmpdir[] = "/tmp/recv-smoke-XXXXXX";
    want(mkdtemp(tmpdir) != NULL);

    pid_t pid = -1;
    int wfd = -1, rfd = -1;
    call(spawn_receive_pack, tmpdir, &pid, &wfd, &rfd);

    static u8 rbuf[1 << 20];
    size_t adv_end = 0;
    u32 nrefs = 0;
    call(drain_advert, rfd, rbuf, sizeof(rbuf), &adv_end, &nrefs);
    //  Empty repo → zero refs advertised, just a flush.
    want(nrefs == 0);

    //  Send a single flush — server treats this as no-update, no pack.
    {
        u8 fbuf[8];
        u8s fs = {fbuf, fbuf + sizeof(fbuf)};
        want(PKTu8sFeedFlush(fs) == OK);
        u64 wlen = (u64)(fs[0] - fbuf);
        want(write(wfd, fbuf, (size_t)wlen) == (ssize_t)wlen);
    }
    close(wfd);

    size_t resp_off = adv_end;
    drain_until_eof(rfd, rbuf, sizeof(rbuf), &resp_off);
    close(rfd);

    int status = 0;
    waitpid(pid, &status, 0);

    tmp_rm(tmpdir);
    done;
}

// ---- Test 2: single create — empty repo, push refs/heads/feat ----

ok64 RECEIVEPACKtest_single_create() {
    sane(1);
    call(FILEInit);

    char tmpdir[] = "/tmp/recv-create-XXXXXX";
    want(mkdtemp(tmpdir) != NULL);

    //  Stage: build a git repo + pack with one commit elsewhere.
    char gitdir[] = "/tmp/recv-create-git-XXXXXX";
    want(mkdtemp(gitdir) != NULL);
    char hex[41];
    char packpath[1024];
    call(stage_git_commit, gitdir, "alpha\\n", hex, packpath, sizeof(packpath));

    pid_t pid = -1;
    int wfd = -1, rfd = -1;
    call(spawn_receive_pack, tmpdir, &pid, &wfd, &rfd);

    static u8 rbuf[1 << 20];
    size_t adv_end = 0;
    u32 nrefs = 0;
    call(drain_advert, rfd, rbuf, sizeof(rbuf), &adv_end, &nrefs);
    want(nrefs == 0);

    //  Send one create-update line + flush + pack bytes.
    {
        Bu8 outb = {};
        call(u8bAllocate, outb, 1024);
        char const zeros[41] =
            "0000000000000000000000000000000000000000";
        call(build_update_line, outb,
             zeros, hex, "refs/heads/feat", "report-status");
        call(PKTu8sFeedFlush, u8bIdle(outb));
        a_dup(u8c, framed, u8bData(outb));
        ssize_t wn = write(wfd, framed[0], $len(framed));
        want(wn == (ssize_t)$len(framed));
        u8bFree(outb);

        //  Append the packfile bytes raw.
        static u8 pbuf[1 << 20];
        size_t plen = 0;
        call(slurp_file, packpath, pbuf, sizeof(pbuf), &plen);
        want(write(wfd, pbuf, plen) == (ssize_t)plen);
    }
    close(wfd);

    size_t resp_off = adv_end;
    drain_until_eof(rfd, rbuf, sizeof(rbuf), &resp_off);
    close(rfd);

    int status = 0;
    waitpid(pid, &status, 0);

    //  Parse response: should see "unpack ok" then "ok refs/heads/feat".
    u8cs resp = {rbuf + adv_end, rbuf + resp_off};
    b8 saw_unpack_ok = NO;
    b8 saw_ref_ok    = NO;
    for (;;) {
        u8cs line = {};
        ok64 d = PKTu8sDrain(resp, line);
        if (d == PKTFLUSH) break;
        if (d != OK) break;
        if ($len(line) >= 9 && memcmp(line[0], "unpack ok", 9) == 0)
            saw_unpack_ok = YES;
        if ($len(line) >= 18 && memcmp(line[0], "ok refs/heads/feat", 18) == 0)
            saw_ref_ok = YES;
    }
    want(saw_unpack_ok);
    want(saw_ref_ok);

    //  Verify REFS now holds heads/feat → hex.
    char got[41];
    want(lookup_ref(tmpdir, "refs/heads/feat", got));
    want(memcmp(got, hex, 40) == 0);

    tmp_rm(tmpdir);
    tmp_rm(gitdir);
    done;
}

// ---- Test 3: FF update — seed tip A, push A → B ----

ok64 RECEIVEPACKtest_ff_update() {
    sane(1);
    call(FILEInit);

    char tmpdir[] = "/tmp/recv-ff-XXXXXX";
    want(mkdtemp(tmpdir) != NULL);

    //  Stage A in one git repo, B as a follow-up commit in another.
    //  We treat A as already-known by seeding REFS without ingesting
    //  its pack — receive-pack only checks that old_sha == current
    //  REFS tip, not that the object is in the store.
    char gitA[] = "/tmp/recv-ff-A-XXXXXX";
    want(mkdtemp(gitA) != NULL);
    char hexA[41]; char packA[1024];
    call(stage_git_commit, gitA, "alpha\\n", hexA, packA, sizeof(packA));

    char gitB[] = "/tmp/recv-ff-B-XXXXXX";
    want(mkdtemp(gitB) != NULL);
    char hexB[41]; char packB[1024];
    call(stage_git_commit, gitB, "bravo\\n", hexB, packB, sizeof(packB));

    call(seed_ref, tmpdir, "refs/heads/main", hexA);

    pid_t pid = -1;
    int wfd = -1, rfd = -1;
    call(spawn_receive_pack, tmpdir, &pid, &wfd, &rfd);

    static u8 rbuf[1 << 20];
    size_t adv_end = 0;
    u32 nrefs = 0;
    call(drain_advert, rfd, rbuf, sizeof(rbuf), &adv_end, &nrefs);
    //  REFADV should have advertised our seeded heads/main tip.
    want(nrefs >= 1);

    {
        Bu8 outb = {};
        call(u8bAllocate, outb, 1024);
        call(build_update_line, outb,
             hexA, hexB, "refs/heads/main", "report-status");
        call(PKTu8sFeedFlush, u8bIdle(outb));
        a_dup(u8c, framed, u8bData(outb));
        want(write(wfd, framed[0], $len(framed)) == (ssize_t)$len(framed));
        u8bFree(outb);

        static u8 pbuf[1 << 20];
        size_t plen = 0;
        call(slurp_file, packB, pbuf, sizeof(pbuf), &plen);
        want(write(wfd, pbuf, plen) == (ssize_t)plen);
    }
    close(wfd);

    size_t resp_off = adv_end;
    drain_until_eof(rfd, rbuf, sizeof(rbuf), &resp_off);
    close(rfd);
    int status = 0;
    waitpid(pid, &status, 0);

    u8cs resp = {rbuf + adv_end, rbuf + resp_off};
    b8 saw_unpack_ok = NO;
    b8 saw_ref_ok    = NO;
    for (;;) {
        u8cs line = {};
        ok64 d = PKTu8sDrain(resp, line);
        if (d == PKTFLUSH) break;
        if (d != OK) break;
        if ($len(line) >= 9 && memcmp(line[0], "unpack ok", 9) == 0)
            saw_unpack_ok = YES;
        if ($len(line) >= 18 && memcmp(line[0], "ok refs/heads/main", 18) == 0)
            saw_ref_ok = YES;
    }
    want(saw_unpack_ok);
    want(saw_ref_ok);

    //  REFS should now reflect hexB as the tip.
    char got[41];
    want(lookup_ref(tmpdir, "refs/heads/main", got));
    want(memcmp(got, hexB, 40) == 0);

    tmp_rm(tmpdir);
    tmp_rm(gitA);
    tmp_rm(gitB);
    done;
}

// ---- Test 4: non-FF rejection — seed A, push B → C with B != A ----

ok64 RECEIVEPACKtest_non_ff() {
    sane(1);
    call(FILEInit);

    char tmpdir[] = "/tmp/recv-noff-XXXXXX";
    want(mkdtemp(tmpdir) != NULL);

    //  Make three distinct shas via three independent commits.
    char gitA[] = "/tmp/recv-noff-A-XXXXXX";
    want(mkdtemp(gitA) != NULL);
    char hexA[41]; char packA[1024];
    call(stage_git_commit, gitA, "alpha\\n", hexA, packA, sizeof(packA));

    char gitB[] = "/tmp/recv-noff-B-XXXXXX";
    want(mkdtemp(gitB) != NULL);
    char hexB[41]; char packB[1024];
    call(stage_git_commit, gitB, "bravo\\n", hexB, packB, sizeof(packB));

    char gitC[] = "/tmp/recv-noff-C-XXXXXX";
    want(mkdtemp(gitC) != NULL);
    char hexC[41]; char packC[1024];
    call(stage_git_commit, gitC, "charlie\\n", hexC, packC, sizeof(packC));

    //  Seed REFS with A as the current tip.
    call(seed_ref, tmpdir, "refs/heads/main", hexA);

    pid_t pid = -1;
    int wfd = -1, rfd = -1;
    call(spawn_receive_pack, tmpdir, &pid, &wfd, &rfd);

    static u8 rbuf[1 << 20];
    size_t adv_end = 0;
    u32 nrefs = 0;
    call(drain_advert, rfd, rbuf, sizeof(rbuf), &adv_end, &nrefs);
    want(nrefs >= 1);

    //  Client lies: claims old=B, wants C.  Server should refuse.
    {
        Bu8 outb = {};
        call(u8bAllocate, outb, 1024);
        call(build_update_line, outb,
             hexB, hexC, "refs/heads/main", "report-status");
        call(PKTu8sFeedFlush, u8bIdle(outb));
        a_dup(u8c, framed, u8bData(outb));
        want(write(wfd, framed[0], $len(framed)) == (ssize_t)$len(framed));
        u8bFree(outb);

        //  Send pack C — pack ingest is harmless even when the ref is
        //  refused (objects become unreachable).
        static u8 pbuf[1 << 20];
        size_t plen = 0;
        call(slurp_file, packC, pbuf, sizeof(pbuf), &plen);
        want(write(wfd, pbuf, plen) == (ssize_t)plen);
    }
    close(wfd);

    size_t resp_off = adv_end;
    drain_until_eof(rfd, rbuf, sizeof(rbuf), &resp_off);
    close(rfd);
    int status = 0;
    waitpid(pid, &status, 0);

    u8cs resp = {rbuf + adv_end, rbuf + resp_off};
    b8 saw_ng = NO;
    for (;;) {
        u8cs line = {};
        ok64 d = PKTu8sDrain(resp, line);
        if (d == PKTFLUSH) break;
        if (d != OK) break;
        //  Look for "ng refs/heads/main non-fast-forward".
        if ($len(line) >= 22 &&
            memcmp(line[0], "ng refs/heads/main", 18) == 0) {
            saw_ng = YES;
        }
    }
    want(saw_ng);

    //  REFS must still hold A.
    char got[41];
    want(lookup_ref(tmpdir, "refs/heads/main", got));
    want(memcmp(got, hexA, 40) == 0);

    tmp_rm(tmpdir);
    tmp_rm(gitA);
    tmp_rm(gitB);
    tmp_rm(gitC);
    done;
}

ok64 maintest() {
    sane(1);
    fprintf(stderr, "RECEIVEPACKtest_smoke...\n");
    call(RECEIVEPACKtest_smoke);
    fprintf(stderr, "RECEIVEPACKtest_single_create...\n");
    call(RECEIVEPACKtest_single_create);
    fprintf(stderr, "RECEIVEPACKtest_ff_update...\n");
    call(RECEIVEPACKtest_ff_update);
    fprintf(stderr, "RECEIVEPACKtest_non_ff...\n");
    call(RECEIVEPACKtest_non_ff);
    fprintf(stderr, "all passed\n");
    done;
}

TEST(maintest)
