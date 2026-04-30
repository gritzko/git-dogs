//  HOME: TOML config getter keyed by dotted path.
//
#include "dog/HOME.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "abc/FILE.h"
#include "abc/PRO.h"
#include "abc/TEST.h"

static void seed_config(char const *root, char const *body) {
    char dir[256];
    snprintf(dir, sizeof(dir), "%s/.dogs", root);
    mkdir(dir, 0755);
    char path[256];
    snprintf(path, sizeof(path), "%s/.dogs/config", root);
    FILE *f = fopen(path, "w");
    fputs(body, f);
    fclose(f);
}

ok64 HOMETestGet() {
    sane(1);
    call(FILEInit);

    char tmp[] = "/tmp/dog-home-XXXXXX";
    want(mkdtemp(tmp) != NULL);

    seed_config(tmp,
        "# dogs config\n"
        "[user]\n"
        "name  = \"Ada Lovelace\"\n"
        "email = \"ada@example.com\"\n"
        "[remote]\n"
        "origin = \"ssh://host/repo\"\n"
        "[a.b]\n"
        "c = \"nested\"\n");

    a_cstr(root, tmp);
    home h = {};
    call(HOMEOpenAt, &h, root, NO);

    u8 vbuf[128];

    // --- hit: [user] name ---
    {
        u8s val = {vbuf, vbuf + sizeof(vbuf)};
        u8 *val_start = val[0];
        a_cstr(u, "user");
        a_cstr(n, "name");
        a_path(needle, u, n);
        call(HOMEGetConfig, &h, val, $path(needle));
        u8cs got = {val_start, val[0]};
        a_cstr(wantn, "Ada Lovelace");
        want($eq(got, wantn));
    }

    // --- hit: [remote] origin ---
    {
        u8s val = {vbuf, vbuf + sizeof(vbuf)};
        u8 *val_start = val[0];
        a_cstr(r, "remote");
        a_cstr(o, "origin");
        a_path(needle, r, o);
        call(HOMEGetConfig, &h, val, $path(needle));
        u8cs got = {val_start, val[0]};
        a_cstr(wanto, "ssh://host/repo");
        want($eq(got, wanto));
    }

    // --- hit: nested [a.b] c ---
    {
        u8s val = {vbuf, vbuf + sizeof(vbuf)};
        u8 *val_start = val[0];
        a_cstr(a, "a");
        a_cstr(b, "b");
        a_cstr(k, "c");
        a_path(needle, a, b, k);
        call(HOMEGetConfig, &h, val, $path(needle));
        u8cs got = {val_start, val[0]};
        a_cstr(wantn, "nested");
        want($eq(got, wantn));
    }

    // --- miss: wrong key ---
    {
        u8s val = {vbuf, vbuf + sizeof(vbuf)};
        a_cstr(u, "user");
        a_cstr(n, "nope");
        a_path(needle, u, n);
        want(HOMEGetConfig(&h, val, $path(needle)) == NOCONF);
    }

    // --- miss: wrong section ---
    {
        u8s val = {vbuf, vbuf + sizeof(vbuf)};
        a_cstr(s, "nope");
        a_cstr(n, "name");
        a_path(needle, s, n);
        want(HOMEGetConfig(&h, val, $path(needle)) == NOCONF);
    }

    HOMEClose(&h);
    char rm[512];
    snprintf(rm, sizeof(rm), "rm -rf %s", tmp);
    system(rm);
    done;
}

ok64 HOMETestMissingFile() {
    sane(1);
    call(FILEInit);

    char tmp[] = "/tmp/dog-home-XXXXXX";
    want(mkdtemp(tmp) != NULL);

    a_cstr(root, tmp);
    home h = {};
    call(HOMEOpenAt, &h, root, NO);

    u8 vbuf[64];
    u8s val = {vbuf, vbuf + sizeof(vbuf)};
    a_cstr(u, "user");
    a_cstr(n, "name");
    a_path(needle, u, n);
    want(HOMEGetConfig(&h, val, $path(needle)) == NOCONF);

    HOMEClose(&h);
    char rm[512];
    snprintf(rm, sizeof(rm), "rm -rf %s", tmp);
    system(rm);
    done;
}

static b8 slice_is(u8cs s, char const *lit) {
    size_t l = strlen(lit);
    if ((size_t)$len(s) != l) return NO;
    if (l == 0) return YES;
    return memcmp(s[0], lit, l) == 0;
}

ok64 HOMETestBranches() {
    sane(1);
    call(FILEInit);

    char tmp[] = "/tmp/dog-home-XXXXXX";
    want(mkdtemp(tmp) != NULL);

    a_cstr(root, tmp);
    home h = {};
    call(HOMEOpenAt, &h, root, NO);

    // 1. No branches yet → WriteBranch returns HOMENOBR.
    {
        u8cs w = {};
        want(HOMEWriteBranch(&h, w) == HOMENOBR);
    }

    // 2. Open trunk ro first.  WriteBranch still HOMENOBR because
    //    the first open was ro (no rw requested yet).
    {
        a_cstr(trunk, "main");
        want(HOMEOpenBranch(&h, trunk, NO) == OK);
        u8cs w = {};
        want(HOMEWriteBranch(&h, w) == HOMENOBR);
    }

    // 3. A later rw open must be refused — first open was ro.
    {
        a_cstr(feat, "feature");
        want(HOMEOpenBranch(&h, feat, YES) == HOMEROBR);
    }

    // 4. Reset and try the other order: rw first.
    HOMEClose(&h);
    call(HOMEOpenAt, &h, root, NO);
    {
        a_cstr(feat, "heads/feature");
        want(HOMEOpenBranch(&h, feat, YES) == OK);
        u8cs w = {};
        want(HOMEWriteBranch(&h, w) == OK);
        want(slice_is(w, "heads/feature/"));
    }

    // 5. Dedup: reopening the same branch returns HOMEOPEN.
    {
        a_cstr(feat2, "heads/feature/");
        want(HOMEOpenBranch(&h, feat2, YES) == HOMEOPEN);
    }

    // 6. Additional ro branches stack.  Visibility includes ancestors.
    {
        a_cstr(trunk, "main");
        want(HOMEOpenBranch(&h, trunk, NO) == OK);
        a_cstr(other, "other/fix");
        want(HOMEOpenBranch(&h, other, NO) == OK);
    }

    // 7. HOMEBranchVisible — canonical-form inputs.
    {
        a_cstr(trunk_s, "");
        u8cs trunk_b = {trunk_s[0], trunk_s[1]};
        want(HOMEBranchVisible(&h, trunk_b) == YES);       // ancestor of all

        a_cstr(feat_s, "heads/feature/");
        u8cs feat_b = {feat_s[0], feat_s[1]};
        want(HOMEBranchVisible(&h, feat_b) == YES);        // exact match

        a_cstr(heads_s, "heads/");
        u8cs heads_b = {heads_s[0], heads_s[1]};
        want(HOMEBranchVisible(&h, heads_b) == YES);       // ancestor of heads/feature/

        a_cstr(stray_s, "nope/");
        u8cs stray_b = {stray_s[0], stray_s[1]};
        want(HOMEBranchVisible(&h, stray_b) == NO);
    }

    HOMEClose(&h);
    char rm[512];
    snprintf(rm, sizeof(rm), "rm -rf %s", tmp);
    system(rm);
    done;
}

ok64 maintest() {
    sane(1);
    fprintf(stderr, "HOMETestGet...\n");
    call(HOMETestGet);
    fprintf(stderr, "HOMETestMissingFile...\n");
    call(HOMETestMissingFile);
    fprintf(stderr, "HOMETestBranches...\n");
    call(HOMETestBranches);
    fprintf(stderr, "all passed\n");
    done;
}

TEST(maintest)
