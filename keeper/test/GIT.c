#include "keeper/GIT.h"

#include <string.h>

#include "abc/PRO.h"
#include "abc/TEST.h"

// ---- Test 1: tree parser, single entry ----

ok64 GITtest1() {
    sane(1);
    // tree entry: "100644 hello.c\0" + 20 bytes SHA1
    u8 raw[] = "100644 hello.c\0"
               "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
               "\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14";
    u8cs obj = {raw, raw + sizeof(raw) - 1};  // exclude C string NUL
    u8cs file = {};
    u8cs sha1 = {};

    u32 mode = 0;
    ok64 o = GITu8sDrainTree(obj, file, sha1, &mode);
    want(o == OK);
    want($len(file) == 14);  // "100644 hello.c"
    want(memcmp(file[0], "100644 hello.c", 14) == 0);
    want($len(sha1) == 20);
    want(*sha1[0] == 0x01);
    want(*(sha1[1] - 1) == 0x14);
    want(mode == 0100644);   // octal → 33188

    // should be exhausted
    want($empty(obj));
    o = GITu8sDrainTree(obj, file, sha1, NULL);
    want(o == NODATA);

    done;
}

// ---- Test 2: tree parser, two entries ----

ok64 GITtest2() {
    sane(1);
    u8 raw[] = "100644 a.c\0"
               "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
               "\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
               "40000 subdir\0"
               "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a"
               "\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34";
    u8cs obj = {raw, raw + sizeof(raw) - 1};
    u8cs file = {};
    u8cs sha1 = {};

    // first entry
    u32 mode = 0;
    ok64 o = GITu8sDrainTree(obj, file, sha1, &mode);
    want(o == OK);
    want($len(file) == 10);  // "100644 a.c"
    want(*sha1[0] == 0x01);
    want(mode == 0100644);

    // second entry
    o = GITu8sDrainTree(obj, file, sha1, &mode);
    want(o == OK);
    want($len(file) == 12);  // "40000 subdir"
    want(*sha1[0] == 0x21);
    want(mode == 040000);

    // exhausted
    o = GITu8sDrainTree(obj, file, sha1, NULL);
    want(o == NODATA);

    done;
}

// ---- Test 3: tree parser, truncated SHA1 ----

ok64 GITtest3() {
    sane(1);
    // only 5 bytes after NUL instead of 20
    u8 raw[] = "100644 x\0\x01\x02\x03\x04\x05";
    u8cs obj = {raw, raw + sizeof(raw) - 1};
    u8cs file = {};
    u8cs sha1 = {};

    ok64 o = GITu8sDrainTree(obj, file, sha1, NULL);
    want(o == GITBADFMT);

    done;
}

// ---- Test 4: commit parser, typical commit ----

ok64 GITtest4() {
    sane(1);
    con char commit[] =
        "tree abc123\n"
        "parent def456\n"
        "author Alice <a@b> 1234 +0000\n"
        "committer Bob <b@c> 5678 +0000\n"
        "\n"
        "Fix the frobnicator\n"
        "\n"
        "It was broken.\n";

    u8cs obj = {(u8cp)commit, (u8cp)commit + sizeof(commit) - 1};
    u8cs field = {};
    u8cs value = {};

    // tree
    ok64 o = GITu8sDrainCommit(obj, field, value);
    want(o == OK);
    want($len(field) == 4);
    want(memcmp(field[0], "tree", 4) == 0);
    want($len(value) == 6);
    want(memcmp(value[0], "abc123", 6) == 0);

    // parent
    o = GITu8sDrainCommit(obj, field, value);
    want(o == OK);
    want($len(field) == 6);
    want(memcmp(field[0], "parent", 6) == 0);
    want(memcmp(value[0], "def456", 6) == 0);

    // author
    o = GITu8sDrainCommit(obj, field, value);
    want(o == OK);
    want(memcmp(field[0], "author", 6) == 0);

    // committer
    o = GITu8sDrainCommit(obj, field, value);
    want(o == OK);
    want(memcmp(field[0], "committer", 9) == 0);

    // blank line -> body
    o = GITu8sDrainCommit(obj, field, value);
    want(o == OK);
    want($empty(field));  // empty field signals body
    want($len(value) > 0);
    want(memcmp(value[0], "Fix the frobnicator", 19) == 0);

    // exhausted
    o = GITu8sDrainCommit(obj, field, value);
    want(o == NODATA);

    done;
}

// ---- Test 5: commit parser, no body ----

ok64 GITtest5() {
    sane(1);
    con char commit[] =
        "tree aaa\n"
        "\n";

    u8cs obj = {(u8cp)commit, (u8cp)commit + sizeof(commit) - 1};
    u8cs field = {};
    u8cs value = {};

    // tree
    ok64 o = GITu8sDrainCommit(obj, field, value);
    want(o == OK);
    want(memcmp(field[0], "tree", 4) == 0);

    // blank line -> empty body
    o = GITu8sDrainCommit(obj, field, value);
    want(o == OK);
    want($empty(field));
    want($empty(value));

    // done
    o = GITu8sDrainCommit(obj, field, value);
    want(o == NODATA);

    done;
}

// ---- Test 6: commit parser, malformed (no space) ----

ok64 GITtest6() {
    sane(1);
    con char commit[] = "badline\n";
    u8cs obj = {(u8cp)commit, (u8cp)commit + sizeof(commit) - 1};
    u8cs field = {};
    u8cs value = {};

    ok64 o = GITu8sDrainCommit(obj, field, value);
    want(o == GITBADFMT);

    done;
}

// ---- Test 7: GITu8sCommitTree extracts tree SHA from commit body ----

ok64 GITtest7() {
    sane(1);
    con char commit[] =
        "tree 4b825dc642cb6eb9a060e54bf899d69f7af0d5f3\n"
        "parent aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "author A <a@b> 1 +0000\n"
        "\n"
        "msg\n";

    u8cs obj = {(u8cp)commit, (u8cp)commit + sizeof(commit) - 1};
    u8 tree_sha[20];
    ok64 o = GITu8sCommitTree(obj, tree_sha);
    want(o == OK);
    want(tree_sha[0] == 0x4b);
    want(tree_sha[1] == 0x82);
    want(tree_sha[2] == 0x5d);
    want(tree_sha[19] == 0xf3);

    done;
}

// ---- Test 8: GITu8sCommitTree on a commit without a tree line ----

ok64 GITtest8() {
    sane(1);
    con char commit[] =
        "author A <a@b> 1 +0000\n"
        "\n"
        "msg\n";
    u8cs obj = {(u8cp)commit, (u8cp)commit + sizeof(commit) - 1};
    u8 tree_sha[20] = {};
    ok64 o = GITu8sCommitTree(obj, tree_sha);
    want(o == GITBADFMT);

    done;
}

// ---- Test 9: GITParseRef table ----

typedef struct {
    char const *in;
    gitref_kind kind;
    char const *name;   // NULL => expect GITBADFMT
} parse_case;

static parse_case const PARSE_CASES[] = {
    //  Explicit prefixes
    {"HEAD",                GITREF_HEAD,   "HEAD"},
    {"refs/heads/main",     GITREF_BRANCH, "main"},
    {"heads/main",          GITREF_BRANCH, "main"},
    {"refs/heads/feat/fix", GITREF_BRANCH, "feat/fix"},
    {"heads/feat/fix",      GITREF_BRANCH, "feat/fix"},
    {"refs/tags/v1.0",      GITREF_TAG,    "v1.0"},
    {"tags/v1.0",           GITREF_TAG,    "v1.0"},
    {"refs/remotes/origin/dogs-sniff", GITREF_REMOTE, "origin/dogs-sniff"},
    {"remotes/origin/main", GITREF_REMOTE, "origin/main"},
    {"refs/notes/commits",  GITREF_OTHER,  "notes/commits"},

    //  Bare-name disambiguation
    {"main",                GITREF_BRANCH, "main"},
    {"feature",             GITREF_BRANCH, "feature"},
    {"v1.2.3",              GITREF_TAG,    "v1.2.3"},
    {"v0",                  GITREF_TAG,    "v0"},
    {"vagrant",             GITREF_BRANCH, "vagrant"},   // 'v' not v\d
    {"origin/main",         GITREF_REMOTE, "origin/main"},
    {"feature/fix",         GITREF_REMOTE, "feature/fix"},

    //  Errors
    {"",                    GITREF_NONE,   NULL},
    {"refs/",               GITREF_NONE,   NULL},
    {"refs/heads/",         GITREF_NONE,   NULL},
    {"heads/",              GITREF_NONE,   NULL},
};

ok64 GITtest9() {
    sane(1);
    size_t n = sizeof(PARSE_CASES) / sizeof(PARSE_CASES[0]);
    for (size_t i = 0; i < n; i++) {
        parse_case const *c = &PARSE_CASES[i];
        u8cs in = {(u8cp)c->in, (u8cp)c->in + strlen(c->in)};
        gitref_kind k = GITREF_NONE;
        u8cs nm = {};
        ok64 o = GITParseRef(in, &k, nm);
        if (c->name == NULL) {
            want(o == GITBADFMT);
            continue;
        }
        want(o == OK);
        want(k == c->kind);
        size_t exp_len = strlen(c->name);
        want((size_t)$len(nm) == exp_len);
        want(memcmp(nm[0], c->name, exp_len) == 0);
    }
    done;
}

// ---- Test 10: GITFeedRef table ----

typedef struct {
    gitref_kind kind;
    char const *name;
    char const *expect;   // NULL => expect GITBADFMT
} feed_case;

static feed_case const FEED_CASES[] = {
    {GITREF_HEAD,   "",                 "HEAD"},
    {GITREF_HEAD,   "anything",         "HEAD"},   //  name ignored
    {GITREF_BRANCH, "main",             "refs/heads/main"},
    {GITREF_BRANCH, "feat/fix",         "refs/heads/feat/fix"},
    {GITREF_TAG,    "v1.0",             "refs/tags/v1.0"},
    {GITREF_REMOTE, "origin/main",      "refs/remotes/origin/main"},
    {GITREF_OTHER,  "notes/commits",    "refs/notes/commits"},

    {GITREF_BRANCH, "",                 NULL},
    {GITREF_TAG,    "",                 NULL},
    {GITREF_NONE,   "x",                NULL},
};

ok64 GITtest10() {
    sane(1);
    size_t n = sizeof(FEED_CASES) / sizeof(FEED_CASES[0]);
    for (size_t i = 0; i < n; i++) {
        feed_case const *c = &FEED_CASES[i];
        u8cs nm = {(u8cp)c->name, (u8cp)c->name + strlen(c->name)};
        a_pad(u8, buf, 256);
        ok64 o = GITFeedRef(buf, c->kind, nm);
        if (c->expect == NULL) {
            want(o == GITBADFMT);
            continue;
        }
        want(o == OK);
        size_t el = strlen(c->expect);
        want(u8bDataLen(buf) == el);
        want(memcmp(u8bDataHead(buf), c->expect, el) == 0);
    }
    done;
}

// ---- Test 11: round-trip Parse → Feed → Parse ----

ok64 GITtest11() {
    sane(1);
    char const *inputs[] = {
        "HEAD",
        "refs/heads/main",
        "heads/feat/fix",
        "main",
        "v1.2.3",
        "origin/dogs-sniff",
        "refs/notes/commits",
        NULL,
    };
    for (size_t i = 0; inputs[i]; i++) {
        u8cs in = {(u8cp)inputs[i], (u8cp)inputs[i] + strlen(inputs[i])};
        gitref_kind k1 = GITREF_NONE;
        u8cs n1 = {};
        want(GITParseRef(in, &k1, n1) == OK);

        a_pad(u8, wire, 256);
        want(GITFeedRef(wire, k1, n1) == OK);

        u8cs wire_cs = {u8bDataHead(wire), u8bIdleHead(wire)};
        gitref_kind k2 = GITREF_NONE;
        u8cs n2 = {};
        want(GITParseRef(wire_cs, &k2, n2) == OK);
        want(k2 == k1);
        want($len(n2) == $len(n1));
        want(memcmp(n2[0], n1[0], (size_t)$len(n1)) == 0);
    }
    done;
}

ok64 maintest() {
    sane(1);
    call(GITtest1);
    call(GITtest2);
    call(GITtest3);
    call(GITtest4);
    call(GITtest5);
    call(GITtest6);
    call(GITtest7);
    call(GITtest8);
    call(GITtest9);
    call(GITtest10);
    call(GITtest11);
    done;
}

TEST(maintest)
