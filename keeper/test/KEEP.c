#include "keeper/KEEP.h"
#include "abc/FILE.h"
#include "abc/PRO.h"
#include "abc/TEST.h"

// --- wh64 hashlet tests ---

ok64 WH64hashlet() {
    sane(1);

    // SHA: 816fb46be665c8b63647...
    u8 sha[20] = {0x81, 0x6f, 0xb4, 0x6b, 0xe6, 0x65, 0xc8, 0xb6,
                  0x36, 0x47, 0xf0, 0x09, 0x68, 0x45, 0xfe, 0xf3,
                  0x63, 0x73, 0x6b, 0x20};
    sha1 s = {};
    memcpy(s.data, sha, 20);
    u64 hashlet = WHIFFHashlet40(&s);

    // Hex output should match SHA prefix
    a_pad(u8, hex, 12);
    WHIFFHexFeed40(hex_idle, hashlet);
    want(memcmp(u8bDataHead(hex), "816fb46be6", 10) == 0);

    // FromHex round-trip
    a_cstr(h2hex, "816fb46be6");
    u64 h2 = WHIFFHexHashlet40(h2hex);
    want(h2 == hashlet);

    // Short prefix: WHIFFHexHashlet40 with 7 chars, mask compare
    a_cstr(h7hex, "816fb46");
    u64 h7 = WHIFFHexHashlet40(h7hex);
    u64 mask7 = ~((1ULL << (40 - 28)) - 1) & WHIFF_HASHLET40_MASK;
    want((hashlet & mask7) == (h7 & mask7));

    a_cstr(h7bad, "816fb47");
    u64 hbad = WHIFFHexHashlet40(h7bad);
    want((hashlet & mask7) != (hbad & mask7));

    done;
}

// --- wh64 pack/unpack tests ---

ok64 WH64pack() {
    sane(1);

    wh64 v = wh64Pack(5, 1000, 0xABCDEF0123ULL);
    want(wh64Type(v) == 5);
    want(wh64Id(v) == 1000);
    want(wh64Off(v) == 0xABCDEF0123ULL);

    wh64 vmax = wh64Pack(0xf, WHIFF_ID_MASK, WHIFF_OFF_MASK);
    want(wh64Type(vmax) == 0xf);
    want(wh64Id(vmax) == WHIFF_ID_MASK);
    want(wh64Off(vmax) == WHIFF_OFF_MASK);

    wh64 v0 = wh64Pack(0, 0, 0);
    want(wh64Type(v0) == 0);
    want(wh64Id(v0) == 0);
    want(wh64Off(v0) == 0);

    done;
}

// --- keeper open/close on empty store ---

ok64 KEEPempty() {
    sane(1);
    call(FILEInit);

    char tmpdir[] = "/tmp/keeper-test-XXXXXX";
    want(mkdtemp(tmpdir) != NULL);

    u8cs root = {(u8cp)tmpdir, (u8cp)tmpdir + strlen(tmpdir)};
    home h = {};
    call(HOMEOpen, &h, root, YES);
    
    call(KEEPOpen, &h, YES);
    want(kv32bDataLen(KEEP.packs) == 0);
    want(DOGPupCount(KEEP.puppies) == 0);

    a_cstr(_h, "abcdef");
    u64 hashlet = WHIFFHexHashlet60(_h);
    u64 val = 0;
    want(KEEPLookup(&KEEP, hashlet, 6, &val) == KEEPNONE);
    want(KEEPHas(&KEEP, hashlet, 6) == KEEPNONE);

    call(KEEPClose);
    HOMEClose(&h);

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
    system(cmd);

    done;
}

ok64 KEEPput() {
    sane(1);
    call(FILEInit);

    char tmpdir[] = "/tmp/keeper-put-XXXXXX";
    want(mkdtemp(tmpdir) != NULL);

    a_cstr(root, tmpdir);
    home h = {};
    call(HOMEOpen, &h, root, YES);
    
    call(KEEPOpen, &h, YES);
    want(kv32bDataLen(KEEP.packs) == 0);

    // Store two blobs
    a_cstr(blob1, "hello world\n");
    a_cstr(blob2, "goodbye world\n");
    u8csc objs[2] = {
        {blob1[0], blob1[1]},
        {blob2[0], blob2[1]},
    };
    wh64 wh[2] = {
        wh64Pack(DOG_OBJ_BLOB, 0, 0),
        wh64Pack(DOG_OBJ_BLOB, 0, 0),
    };

    call(KEEPPut, &KEEP, objs, wh, 2);
    want(kv32bDataLen(KEEP.packs) == 1);
    want(DOGPupCount(KEEP.puppies) == 1);

    // Both whiffs should have valid types
    want(wh64Type(wh[0]) == DOG_OBJ_BLOB);
    want(wh64Type(wh[1]) == DOG_OBJ_BLOB);

    // Compute 60-bit hashlets from known blob content
    // "hello world\n" SHA = 3b18e512dba79e4c8300dd08aeb37f8e728b8dad
    u8 sha0[20] = {0x3b,0x18,0xe5,0x12,0xdb,0xa7,0x9e,0x4c,0x83,0x00,
                   0xdd,0x08,0xae,0xb3,0x7f,0x8e,0x72,0x8b,0x8d,0xad};
    u64 h0 = WHIFFHashlet60((sha1cp)sha0);
    // "goodbye world\n" — compute via git hash-object
    a_cstr(_ce, "ce0136");
    u64 h1 = WHIFFHexHashlet60(_ce);  // just need a prefix

    // Should be retrievable by 7-char prefix (git default)
    a_cstr(_3b, "3b18e51");
    want(KEEPHas(&KEEP, WHIFFHexHashlet60(_3b), 7) == OK);

    // Get content back
    Bu8 out = {};
    call(u8bMap, out, 1UL << 20);
    u8 obj_type = 0;
    call(KEEPGet, &KEEP, h0, 15, out, &obj_type);
    want(obj_type == DOG_OBJ_BLOB);
    want(u8bDataLen(out) == u8csLen(blob1));
    want(memcmp(u8bDataHead(out), blob1[0], u8csLen(blob1)) == 0);

    u8bUnMap(out);
    call(KEEPClose);
    HOMEClose(&h);

    a_pad(u8, rmbuf, 256);
    a_cstr(rmcmd, "rm -rf ");
    u8bFeed(rmbuf, rmcmd);
    u8bFeed(rmbuf, root);
    u8bFeed1(rmbuf, 0);
    system((char *)u8bDataHead(rmbuf));

    done;
}

ok64 KEEPpackIncremental() {
    sane(1);
    call(FILEInit);

    char tmpdir[] = "/tmp/keeper-pack-XXXXXX";
    want(mkdtemp(tmpdir) != NULL);

    a_cstr(root, tmpdir);
    home h = {};
    call(HOMEOpen, &h, root, YES);
    
    call(KEEPOpen, &h, YES);

    keep_pack p = {};
    call(KEEPPackOpen, &KEEP, &p);

    //  Pre-compute the blob SHA so we can build the tree object
    //  first (intra-pack order: commit→tree→blob→tag).
    //  "hello world\n" — git SHA-1 = 3b18e512dba79e4c8300dd08aeb37f8e728b8dad.
    a_cstr(blob_content, "hello world\n");
    sha1 blob_sha = {};
    KEEPObjSha(&blob_sha, DOG_OBJ_BLOB, blob_content);

    u8 expected_blob_sha[20] = {
        0x3b,0x18,0xe5,0x12,0xdb,0xa7,0x9e,0x4c,0x83,0x00,
        0xdd,0x08,0xae,0xb3,0x7f,0x8e,0x72,0x8b,0x8d,0xad};
    want(memcmp(blob_sha.data, expected_blob_sha, 20) == 0);

    //  Build tree content: "100644 hello.txt\0" + 20-byte blob SHA.
    a_pad(u8, tree_buf, 256);
    a_cstr(tree_mode, "100644 hello.txt");
    u8bFeed(tree_buf, tree_mode);
    u8bFeed1(tree_buf, 0);  // NUL separator
    u8cs sha_slice = {blob_sha.data, blob_sha.data + 20};
    u8bFeed(tree_buf, sha_slice);

    a_dup(u8c, tree_content, u8bData(tree_buf));
    sha1 tree_sha = {};
    //  Feed tree first (type 2), then blob (type 3) — monotone order.
    call(KEEPPackFeed, &KEEP, &p, DOG_OBJ_TREE, tree_content, 0, &tree_sha);
    sha1 blob_sha2 = {};
    call(KEEPPackFeed, &KEEP, &p, DOG_OBJ_BLOB, blob_content, 0, &blob_sha2);
    want(memcmp(blob_sha.data, blob_sha2.data, 20) == 0);

    // Verify tree SHA matches git: 68aba62e560c0ebc3396e8ae9335232cd93a3f60
    u8 expected_tree_sha[20] = {
        0x68,0xab,0xa6,0x2e,0x56,0x0c,0x0e,0xbc,0x33,0x96,
        0xe8,0xae,0x93,0x35,0x23,0x2c,0xd9,0x3a,0x3f,0x60};
    want(memcmp(tree_sha.data, expected_tree_sha, 20) == 0);

    call(KEEPPackClose, &KEEP, &p);
    want(kv32bDataLen(KEEP.packs) == 1);
    want(DOGPupCount(KEEP.puppies) == 1);

    // Retrieve blob by 7-char prefix (git default)
    u64 blob_hashlet = WHIFFHashlet60(&blob_sha);
    Bu8 out = {};
    call(u8bMap, out, 1UL << 20);
    u8 obj_type = 0;
    a_cstr(_bh, "3b18e51");
    call(KEEPGet, &KEEP, WHIFFHexHashlet60(_bh), 7, out, &obj_type);
    want(obj_type == DOG_OBJ_BLOB);
    want(u8bDataLen(out) == u8csLen(blob_content));
    want(memcmp(u8bDataHead(out), blob_content[0], u8csLen(blob_content)) == 0);

    // Retrieve tree by full 15-char hashlet
    u8bReset(out);
    u64 tree_hashlet = WHIFFHashlet60(&tree_sha);
    call(KEEPGet, &KEEP, tree_hashlet, 15, out, &obj_type);
    want(obj_type == DOG_OBJ_TREE);
    want(u8bDataLen(out) == u8csLen(tree_content));
    want(memcmp(u8bDataHead(out), tree_content[0], u8csLen(tree_content)) == 0);

    u8bUnMap(out);
    call(KEEPClose);
    HOMEClose(&h);

    a_pad(u8, rmbuf, 256);
    a_cstr(rmcmd, "rm -rf ");
    u8bFeed(rmbuf, rmcmd);
    u8bFeed(rmbuf, root);
    u8bFeed1(rmbuf, 0);
    system((char *)u8bDataHead(rmbuf));

    done;
}

// --- Phase 1c: KEEPBranchDrop preconditions ---

typedef struct {
    char const *input;
    ok64        expect;
} BranchDropCase;

ok64 KEEPBranchDropTable() {
    sane(1);
    call(FILEInit);

    char tmpdir[] = "/tmp/keeper-drop-XXXXXX";
    want(mkdtemp(tmpdir) != NULL);

    a_cstr(root, tmpdir);
    home h = {};
    call(HOMEOpen, &h, root, YES);
    call(KEEPOpen, &h, YES);

    //  Trunk aliases must all refuse with KEEPTRUNK — none may be
    //  dropped because trunk carries the paths registry plus the
    //  root-level `refs` file (which also holds host aliases).
    BranchDropCase const cases[] = {
        {"",              KEEPTRUNK},
        {"main",          KEEPTRUNK},
        {"master",        KEEPTRUNK},
        {"trunk",         KEEPTRUNK},
        {"heads/main",    KEEPTRUNK},
        {"heads/master",  KEEPTRUNK},
        {"heads/trunk",   KEEPTRUNK},
        //  Step 2: drop validates against on-disk state.  None of
        //  these dirs exist in this fresh store, so the answer is
        //  KEEPNONE.
        {"feature",       KEEPNONE},
        {"heads/feature", KEEPNONE},
        {"tags/v0.0.1",   KEEPNONE},
        {"feature/fix1",  KEEPNONE},
    };
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        u8cs in = {(u8cp)cases[i].input,
                   (u8cp)cases[i].input + strlen(cases[i].input)};
        ok64 got = KEEPBranchDrop(&KEEP, in);
        if (got != cases[i].expect) {
            fprintf(stderr, "FAIL drop[%zu] '%s': got %s want %s\n",
                    i, cases[i].input,
                    ok64str(got), ok64str(cases[i].expect));
            fail(TESTFAIL);
        }
    }

    call(KEEPClose);
    HOMEClose(&h);

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
    system(cmd);
    done;
}

// --- Step 2: branch open/create/drop round-trip ---

#include <sys/stat.h>

ok64 KEEPbranchRoundTrip() {
    sane(1);
    call(FILEInit);

    char tmpdir[] = "/tmp/keeper-branch-XXXXXX";
    want(mkdtemp(tmpdir) != NULL);

    a_cstr(root, tmpdir);
    home h = {};
    call(HOMEOpen, &h, root, YES);

    //  Phase 1: open trunk first (creates the .dogs dir + lock), then
    //  use KEEPCreateBranch to materialise nested feat/ → feat/fix.
    call(KEEPOpen, &h, YES);
    call(KEEPClose);

    //  Re-open from a fresh home for create — KEEPCreateBranch is a
    //  pure mkdir over an existing parent.  Trunk is the parent of
    //  "feat"; "feat" is the parent of "feat/fix".  Order matters.
    a_cstr(feat,    "feat");
    a_cstr(featfix, "feat/fix");

    //  Parent missing → KEEPNONE.
    want(KEEPCreateBranch(&h, featfix) == KEEPNONE);

    //  Materialise "feat" first.
    want(KEEPCreateBranch(&h, feat) == OK);
    {
        a_pad(u8, p, 256);
        u8bFeed(p, root);
        a_cstr(rel, "/.dogs/feat");
        u8bFeed(p, rel);
        u8bFeed1(p, 0);
        struct stat st = {};
        want(stat((char *)u8bDataHead(p), &st) == 0);
        want((st.st_mode & S_IFMT) == S_IFDIR);
    }

    //  Re-create same branch → KEEPDUP.
    want(KEEPCreateBranch(&h, feat) == KEEPDUP);

    //  Now nested.
    want(KEEPCreateBranch(&h, featfix) == OK);

    //  Open feat/fix.  Trunk + feat + feat/fix all exist on disk.
    call(KEEPOpenBranch, &h, featfix, YES);
    //  Canonical leaf_branch carries a trailing '/'.
    a_cstr(featfix_canon, "feat/fix/");
    {
        a_dup(u8c, leaf, u8bDataC(KEEP.leaf_branch));
        want(u8csLen(leaf) == u8csLen(featfix_canon));
        want(memcmp(leaf[0], featfix_canon[0],
                    u8csLen(featfix_canon)) == 0);
    }
    want(KEEP.lock_fd >= 0);

    //  Verify leaf lock file exists.
    {
        a_pad(u8, p, 256);
        u8bFeed(p, root);
        a_cstr(rel, "/.dogs/feat/fix/.lock");
        u8bFeed(p, rel);
        u8bFeed1(p, 0);
        struct stat st = {};
        want(stat((char *)u8bDataHead(p), &st) == 0);
    }

    call(KEEPClose);

    //  Reopen on trunk so we can drop feat/fix.
    call(KEEPOpen, &h, YES);

    //  Refuses dropping while branch has children.
    want(KEEPBranchDrop(&KEEP, feat) == KEEPDIRTY);

    //  Drop the leaf.  Dir must be gone afterwards.
    call(KEEPBranchDrop, &KEEP, featfix);
    {
        a_pad(u8, p, 256);
        u8bFeed(p, root);
        a_cstr(rel, "/.dogs/feat/fix");
        u8bFeed(p, rel);
        u8bFeed1(p, 0);
        struct stat st = {};
        want(stat((char *)u8bDataHead(p), &st) != 0);
    }

    //  Now feat is empty leaf — drop succeeds.
    call(KEEPBranchDrop, &KEEP, feat);
    {
        a_pad(u8, p, 256);
        u8bFeed(p, root);
        a_cstr(rel, "/.dogs/feat");
        u8bFeed(p, rel);
        u8bFeed1(p, 0);
        struct stat st = {};
        want(stat((char *)u8bDataHead(p), &st) != 0);
    }

    call(KEEPClose);
    HOMEClose(&h);

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
    system(cmd);
    done;
}

ok64 maintest() {
    sane(1);
    fprintf(stderr, "WH64hashlet...\n");
    call(WH64hashlet);
    fprintf(stderr, "WH64pack...\n");
    call(WH64pack);
    fprintf(stderr, "KEEPempty...\n");
    call(KEEPempty);
    fprintf(stderr, "KEEPput...\n");
    call(KEEPput);
    fprintf(stderr, "KEEPpackIncremental...\n");
    call(KEEPpackIncremental);
    fprintf(stderr, "KEEPBranchDropTable...\n");
    call(KEEPBranchDropTable);
    fprintf(stderr, "KEEPbranchRoundTrip...\n");
    call(KEEPbranchRoundTrip);
    fprintf(stderr, "all passed\n");
    done;
}

TEST(maintest);
