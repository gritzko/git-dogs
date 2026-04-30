//  WIRE_CLIENT — `WIREFetch` / `WIREPush` end-to-end smoke tests
//  (WIRE.md Phase 7).
//
//  Cases:
//    1. Fetch smoke: stage a repo with a real commit pack on disk,
//       point a fresh local keeper at it via `WIREFetch(file://…,
//       "heads/main")`, verify the pack ingested + REFS updated.
//    2. Push smoke: stage a local keeper holding a commit, push it
//       via `WIREPush(file://…, "heads/feat")` to a fresh receiver,
//       verify the receiver REFS holds the new tip.
//    3. Round trip: A pushes to B via WIREPush, B fetches from A
//       via WIREFetch — both repos agree on the tip.

#include "keeper/KEEP.h"
#include "keeper/PKT.h"
#include "keeper/REFADV.h"
#include "keeper/REFS.h"
#include "keeper/WIRE.h"

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

#define GIT_UNSET "unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR " \
                  "GIT_INDEX_FILE GIT_OBJECT_DIRECTORY && "

static void tmp_rm(char const *path) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", path);
    int _ = system(cmd);
    (void)_;
}

//  Build a one-commit git repo at gitdir, writing the commit's 40-hex
//  SHA into out_hex_41 and the on-disk pack path into pack_path.
static ok64 stage_git_commit(char const *gitdir, char const *content,
                             char *out_hex_41, char *pack_path,
                             size_t pcap) {
    sane(gitdir && content && out_hex_41 && pack_path);
    char cmd[2048];
    int rc;

    snprintf(cmd, sizeof(cmd),
             GIT_UNSET
             "cd %s && git init -q && "
             "git config user.email t@t && git config user.name t && "
             "printf '%s' > a.txt && "
             "git add a.txt && git commit -q -m c1",
             gitdir, content);
    rc = system(cmd);
    if (rc != 0) return FAIL;

    snprintf(cmd, sizeof(cmd),
             GIT_UNSET
             "cd %s && git rev-parse HEAD",
             gitdir);
    FILE *fp = popen(cmd, "r");
    if (!fp) return FAIL;
    if (fread(out_hex_41, 1, 40, fp) != 40) { pclose(fp); return FAIL; }
    out_hex_41[40] = 0;
    pclose(fp);

    snprintf(pack_path, pcap, "%s/objects.pack", gitdir);
    snprintf(cmd, sizeof(cmd),
             GIT_UNSET
             "cd %s && git rev-list --objects HEAD | "
             "git pack-objects --stdout > %s",
             gitdir, pack_path);
    rc = system(cmd);
    if (rc != 0) return FAIL;
    done;
}

//  Slurp a file into buf (caller-allocated).  Updates *out_len.
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

//  Ingest `pack_path` into a fresh keeper at `keeper_root`, plus seed
//  a REFS entry for the named be-branch → hex.  `branch` is be-side
//  (use `""` for the trunk shard; on the wire trunk maps to
//  `refs/heads/main`).
static ok64 stage_local_keeper(char const *keeper_root, char const *pack_path,
                               char const *branch, char const *hex_40) {
    sane(keeper_root && pack_path && branch && hex_40);

    static u8 pbuf[1 << 20];
    size_t plen = 0;
    call(slurp_file, pack_path, pbuf, sizeof(pbuf), &plen);

    a_cstr(root_s, keeper_root);
    home h = {};
    call(HOMEOpenAt, &h, root_s, YES);
    call(KEEPOpen, &h, YES);

    u8csc bytes = {pbuf, pbuf + plen};
    call(KEEPIngestFile, &KEEP, bytes);

    a_path(keepdir, u8bDataC(KEEP.h->root), KEEP_DIR_S);
    a_pad(u8, kbuf, 256);
    u8bFeed1(kbuf, '?');
    if (branch && *branch) {
        u8csc br = {(u8cp)branch, (u8cp)branch + strlen(branch)};
        u8bFeed(kbuf, br);
    }
    a_dup(u8c, key, u8bData(kbuf));

    u8csc val = {(u8cp)hex_40, (u8cp)hex_40 + 40};

    call(REFSAppend, $path(keepdir), key, val);

    call(KEEPClose);
    HOMEClose(&h);
    done;
}

//  Look up the REFS tip for be-branch `branch` (`""` = trunk) in a
//  keeper, copying 40 hex bytes into out_41.  Returns NO if missing.
static b8 lookup_local_ref(char const *keeper_root, char const *branch,
                           char *out_41) {
    a_cstr(root_s, keeper_root);
    home h = {};
    if (HOMEOpenAt(&h, root_s, NO) != OK) return NO;
    if (KEEPOpen(&h, NO) != OK) { HOMEClose(&h); return NO; }
    a_path(keepdir, u8bDataC(KEEP.h->root), KEEP_DIR_S);

    a_pad(u8, kbuf, 256);
    u8bFeed1(kbuf, '?');
    if (branch && *branch) {
        u8csc br = {(u8cp)branch, (u8cp)branch + strlen(branch)};
        u8bFeed(kbuf, br);
    }
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

//  Build a "file:///<path>" URI slice on the stack.
#define FILE_URI(name, path)                                            \
    char _##name##_buf[1024];                                           \
    snprintf(_##name##_buf, sizeof(_##name##_buf), "file://%s", path);  \
    u8csc name = {(u8cp)_##name##_buf,                                  \
                  (u8cp)_##name##_buf + strlen(_##name##_buf)}

// ---- Test 1: fetch smoke -----------------------------------------------

ok64 WIRECLIENTtest_fetch_smoke() {
    sane(1);
    call(FILEInit);

    char gitdir[]    = "/tmp/wcli-fetch-git-XXXXXX";
    want(mkdtemp(gitdir) != NULL);
    char serverdir[] = "/tmp/wcli-fetch-srv-XXXXXX";
    want(mkdtemp(serverdir) != NULL);
    char clientdir[] = "/tmp/wcli-fetch-cli-XXXXXX";
    want(mkdtemp(clientdir) != NULL);

    //  Build a real one-commit pack and ingest it into the "server"
    //  keeper, then put it under the trunk shard.  Trunk advertises
    //  on the wire as `refs/heads/main` (the only wire alias).
    char hex[41];
    char packpath[1024];
    call(stage_git_commit, gitdir, "alpha\\n", hex, packpath, sizeof(packpath));
    call(stage_local_keeper, serverdir, packpath, "", hex);

    //  Fetch from server into a fresh client keeper.  Empty want
    //  selects the trunk (peer's HEAD-mapped branch).
    {
        a_cstr(client_root_s, clientdir);
        home h = {};
        call(HOMEOpenAt, &h, client_root_s, YES);
        call(KEEPOpen, &h, YES);

        FILE_URI(uri, serverdir);
        u8csc want_cs = {NULL, NULL};
        ok64 fo = WIREFetch(&KEEP, uri, want_cs);
        want(fo == OK);

        KEEPClose();
        HOMEClose(&h);
    }

    //  Verify the client REFS now holds the same tip on its trunk.
    char got[41];
    want(lookup_local_ref(clientdir, "", got));
    want(memcmp(got, hex, 40) == 0);

    tmp_rm(gitdir);
    tmp_rm(serverdir);
    tmp_rm(clientdir);
    done;
}

// ---- Test 2: push smoke ------------------------------------------------

ok64 WIRECLIENTtest_push_smoke() {
    sane(1);
    call(FILEInit);

    char gitdir[]    = "/tmp/wcli-push-git-XXXXXX";
    want(mkdtemp(gitdir) != NULL);
    char srcdir[]    = "/tmp/wcli-push-src-XXXXXX";
    want(mkdtemp(srcdir) != NULL);
    char dstdir[]    = "/tmp/wcli-push-dst-XXXXXX";
    want(mkdtemp(dstdir) != NULL);

    //  Source keeper: a fresh commit ingested under be-branch "feat".
    char hex[41];
    char packpath[1024];
    call(stage_git_commit, gitdir, "alpha\\n", hex, packpath, sizeof(packpath));
    call(stage_local_keeper, srcdir, packpath, "feat", hex);

    //  Push from source to destination.  local_branch is be-side.
    {
        a_cstr(src_root_s, srcdir);
        home h = {};
        call(HOMEOpenAt, &h, src_root_s, YES);
        call(KEEPOpen, &h, YES);

        FILE_URI(uri, dstdir);
        a_cstr(branch_s, "feat");
        u8csc branch_cs = {branch_s[0], branch_s[1]};
        sha1 tip = {};
        u8s bin = {tip.data, tip.data + 20};
        u8cs hx = {(u8cp)hex, (u8cp)hex + 40};
        want(HEXu8sDrainSome(bin, hx) == OK);
        ok64 po = WIREPush(&KEEP, uri, branch_cs, &tip);
        want(po == OK);

        KEEPClose();
        HOMEClose(&h);
    }

    //  Destination should now have be-branch "feat" → hex.
    char got[41];
    want(lookup_local_ref(dstdir, "feat", got));
    want(memcmp(got, hex, 40) == 0);

    tmp_rm(gitdir);
    tmp_rm(srcdir);
    tmp_rm(dstdir);
    done;
}

// ---- Test 3: round trip -----------------------------------------------

ok64 WIRECLIENTtest_round_trip() {
    sane(1);
    call(FILEInit);

    char gitdir[]    = "/tmp/wcli-rt-git-XXXXXX";
    want(mkdtemp(gitdir) != NULL);
    char Adir[]      = "/tmp/wcli-rt-A-XXXXXX";
    want(mkdtemp(Adir) != NULL);
    char Bdir[]      = "/tmp/wcli-rt-B-XXXXXX";
    want(mkdtemp(Bdir) != NULL);
    char Cdir[]      = "/tmp/wcli-rt-C-XXXXXX";
    want(mkdtemp(Cdir) != NULL);

    char hex[41];
    char packpath[1024];
    call(stage_git_commit, gitdir, "round-trip\\n", hex, packpath,
         sizeof(packpath));

    //  A holds the commit on its trunk (wire-side `refs/heads/main`).
    call(stage_local_keeper, Adir, packpath, "", hex);

    //  Push A → B (trunk → wire main).
    {
        a_cstr(A_root_s, Adir);
        home h = {};
        call(HOMEOpenAt, &h, A_root_s, YES);
        call(KEEPOpen, &h, YES);

        FILE_URI(uri, Bdir);
        u8csc branch_cs = {NULL, NULL};
        sha1 tip = {};
        u8s bin = {tip.data, tip.data + 20};
        u8cs hx = {(u8cp)hex, (u8cp)hex + 40};
        want(HEXu8sDrainSome(bin, hx) == OK);
        ok64 po = WIREPush(&KEEP, uri, branch_cs, &tip);
        want(po == OK);

        KEEPClose();
        HOMEClose(&h);
    }

    //  Fetch A → C (through fresh keeper C).
    {
        a_cstr(C_root_s, Cdir);
        home h = {};
        call(HOMEOpenAt, &h, C_root_s, YES);
        call(KEEPOpen, &h, YES);

        FILE_URI(uri, Adir);
        u8csc want_cs = {NULL, NULL};
        ok64 fo = WIREFetch(&KEEP, uri, want_cs);
        want(fo == OK);

        KEEPClose();
        HOMEClose(&h);
    }

    //  Both B and C agree with A on the trunk tip.
    char gotB[41], gotC[41];
    want(lookup_local_ref(Bdir, "", gotB));
    want(memcmp(gotB, hex, 40) == 0);
    want(lookup_local_ref(Cdir, "", gotC));
    want(memcmp(gotC, hex, 40) == 0);

    tmp_rm(gitdir);
    tmp_rm(Adir);
    tmp_rm(Bdir);
    tmp_rm(Cdir);
    done;
}

ok64 maintest() {
    sane(1);
    fprintf(stderr, "WIRECLIENTtest_fetch_smoke...\n");
    call(WIRECLIENTtest_fetch_smoke);
    fprintf(stderr, "WIRECLIENTtest_push_smoke...\n");
    call(WIRECLIENTtest_push_smoke);
    fprintf(stderr, "WIRECLIENTtest_round_trip...\n");
    call(WIRECLIENTtest_round_trip);
    fprintf(stderr, "all passed\n");
    done;
}

TEST(maintest)
