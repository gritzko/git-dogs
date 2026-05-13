#include "dog/DPATH.h"

#include <string.h>

#include "abc/PRO.h"
#include "abc/TEST.h"

typedef struct {
    const char *input;
    ok64 expect;       // OK or DPATHBAD or DPATHFAIL
    const char *body;  // expected segment (NULL if should fail)
} DPATHCase;

static const DPATHCase DPATH_CASES[] = {

    // --- Good: plain ASCII filenames ---
    {"hello",         OK, "hello"},
    {"Makefile",      OK, "Makefile"},
    {"README.md",     OK, "README.md"},
    {"a",             OK, "a"},
    {"x86_64",        OK, "x86_64"},
    {"my-file",       OK, "my-file"},
    {"v1.0.0",        OK, "v1.0.0"},
    {"file.tar.gz",   OK, "file.tar.gz"},
    {"CAPS",          OK, "CAPS"},
    {"MixedCase.TXT", OK, "MixedCase.TXT"},
    {"a b c",         OK, "a b c"},
    {"hello world",   OK, "hello world"},

    // --- Good: numbers and underscores ---
    {"0",             OK, "0"},
    {"123",           OK, "123"},
    {"__init__",      OK, "__init__"},
    {"_",             OK, "_"},

    // --- Good: dotfiles (not .git or .be) ---
    {".bashrc",       OK, ".bashrc"},
    {".config",       OK, ".config"},
    {".gitignore",    OK, ".gitignore"},
    {".github",       OK, ".github"},
    {".gitmodules",   OK, ".gitmodules"},
    {".beagle",       OK, ".beagle"},
    {".gita",         OK, ".gita"},
    {".bes",          OK, ".bes"},
    {"...",            OK, "..."},
    {"....git",       OK, "....git"},

    // --- Good: UTF-8 filenames ---
    {"\xc3\xa9",               OK, "\xc3\xa9"},          // é
    {"\xc3\xbc\x62\x65\x72",  OK, "\xc3\xbc\x62\x65\x72"}, // über
    {"\xe4\xb8\xad\xe6\x96\x87", OK, "\xe4\xb8\xad\xe6\x96\x87"}, // 中文
    {"\xf0\x9f\x90\xb6",      OK, "\xf0\x9f\x90\xb6"},  // 🐶

    // --- Bad: directory traversal ---
    {"..",            DPATHBAD, NULL},

    // --- Bad: current dir ---
    {".",             DPATHBAD, NULL},

    // --- Bad: .git (case-insensitive) ---
    {".git",          DPATHBAD, NULL},
    {".GIT",          DPATHBAD, NULL},
    {".Git",          DPATHBAD, NULL},
    {".gIt",          DPATHBAD, NULL},
    {".giT",          DPATHBAD, NULL},
    {".GiT",          DPATHBAD, NULL},

    // --- Bad: .be (case-insensitive) ---
    {".be",           DPATHBAD, NULL},
    {".BE",           DPATHBAD, NULL},
    {".Be",           DPATHBAD, NULL},
    {".bE",           DPATHBAD, NULL},

    // --- Bad: slash in name ---
    {"a/b",           DPATHBAD, NULL},
    {"/etc",          DPATHBAD, NULL},

    // --- Bad: backslash ---
    {"a\\b",          DPATHBAD, NULL},

    // --- Bad: NUL byte ---
    {"\0hidden",      DPATHFAIL, NULL},

    // --- Bad: invalid UTF-8 ---
    {"\x80",          DPATHBAD, NULL},     // bare continuation
    {"\xC0\xAF",      DPATHBAD, NULL},     // overlong /
    {"\xC1\xBF",      DPATHBAD, NULL},     // overlong
    {"\xFE",          DPATHBAD, NULL},     // invalid lead
    {"\xFF",          DPATHBAD, NULL},     // invalid lead
    {"\xED\xA0\x80",  DPATHBAD, NULL},     // surrogate half

    // --- Bad: empty ---
    {"",              DPATHFAIL, NULL},
};

#define DPATH_NCASES (sizeof(DPATH_CASES) / sizeof(DPATH_CASES[0]))

static b8 dpath_eq(u8cs s, const char *expect) {
    if (expect == NULL) return $empty(s);
    size_t elen = strlen(expect);
    if ((size_t)$len(s) != elen) return NO;
    if (elen == 0) return YES;
    return memcmp(s[0], expect, elen) == 0;
}

ok64 DPATHTestTable() {
    sane(1);
    for (size_t i = 0; i < DPATH_NCASES; i++) {
        const DPATHCase *tc = &DPATH_CASES[i];
        // Use strlen for input length, except for NUL byte test
        size_t ilen = strlen(tc->input);
        // For the NUL test case, input is "" (strlen=0) which maps to DPATHFAIL
        u8cs input = {(u8cp)tc->input, (u8cp)tc->input + ilen};

        u8cs out = {};
        ok64 o = DPATHu8sDrainSeg(input, out);

        if (o != tc->expect) {
            fprintf(stderr, "FAIL [%zu] '%.*s': got %s want %s\n",
                    i, (int)ilen, tc->input,
                    ok64str(o), ok64str(tc->expect));
            fail(TESTFAIL);
        }

        // DPATHVerify must agree
        u8csc vname = {(u8cp)tc->input, (u8cp)tc->input + ilen};
        ok64 v = DPATHVerify(vname);
        if (v != tc->expect) {
            fprintf(stderr, "FAIL Verify [%zu] '%.*s': got %s want %s\n",
                    i, (int)ilen, tc->input,
                    ok64str(v), ok64str(tc->expect));
            fail(TESTFAIL);
        }

        if (o == OK && !dpath_eq(out, tc->body)) {
            fprintf(stderr, "FAIL [%zu] '%.*s': body got '%.*s' want '%s'\n",
                    i, (int)ilen, tc->input,
                    (int)$len(out),
                    $empty(out) ? "" : (char *)out[0],
                    tc->body);
            fail(TESTFAIL);
        }
    }
    done;
}

typedef struct {
    const char *input;
    const char *canonical;  // expected normalized form
} BranchNormCase;

static const BranchNormCase BRANCH_NORM_CASES[] = {
    // trunk aliases collapse to ""
    {"",                   ""},
    {"/",                  ""},
    {"main",               ""},
    {"main/",              ""},
    {"/main",              ""},
    {"master",             ""},
    {"trunk",              ""},
    {"heads/main",         ""},
    {"heads/master",       ""},
    {"heads/trunk",        ""},
    {"heads/main/",        ""},
    // non-trunk branches gain trailing '/'
    {"feature",            "feature/"},
    {"feature/",           "feature/"},
    {"heads/feature",      "heads/feature/"},
    {"feature/fix1",       "feature/fix1/"},
    {"tags/v0.0.1",        "tags/v0.0.1/"},
    // leading slashes stripped
    {"/feature",           "feature/"},
    {"//feature//",        "feature/"},
};

#define BRANCH_NORM_N (sizeof(BRANCH_NORM_CASES)/sizeof(BRANCH_NORM_CASES[0]))

ok64 DPATHTestBranchNorm() {
    sane(1);
    for (size_t i = 0; i < BRANCH_NORM_N; i++) {
        BranchNormCase const *tc = &BRANCH_NORM_CASES[i];
        a_pad(u8, out, 256);
        u8cs in = {(u8cp)tc->input, (u8cp)tc->input + strlen(tc->input)};
        ok64 o = DPATHBranchNormFeed(out, in);
        if (o != OK) {
            fprintf(stderr, "FAIL norm[%zu] '%s': rc %s\n",
                    i, tc->input, ok64str(o));
            fail(TESTFAIL);
        }
        a_dup(u8c, got, u8bDataC(out));
        size_t elen = strlen(tc->canonical);
        if ((size_t)$len(got) != elen ||
            (elen > 0 && memcmp(got[0], tc->canonical, elen) != 0)) {
            fprintf(stderr, "FAIL norm[%zu] '%s': got '%.*s' want '%s'\n",
                    i, tc->input, (int)$len(got),
                    $empty(got) ? "" : (char *)got[0], tc->canonical);
            fail(TESTFAIL);
        }
    }
    done;
}

typedef struct {
    const char *anc;
    const char *des;
    b8          expect;
} BranchAncCase;

static const BranchAncCase BRANCH_ANC_CASES[] = {
    // trunk is ancestor of everything
    {"",              "",                 YES},
    {"",              "feature/",         YES},
    {"",              "feature/fix1/",    YES},
    // equal = ancestor
    {"feature/",      "feature/",         YES},
    // proper ancestor
    {"feature/",      "feature/fix1/",    YES},
    {"heads/",        "heads/main/",      YES},
    // siblings / unrelated
    {"feature/",      "other/",           NO},
    {"feature/",      "featureful/",      NO},   // canonical-form prevents this false match
    {"feature/fix1/", "feature/",         NO},   // descendant is not ancestor
    // non-canonical would fool a raw prefix; canonical requires trailing '/'
};

#define BRANCH_ANC_N (sizeof(BRANCH_ANC_CASES)/sizeof(BRANCH_ANC_CASES[0]))

ok64 DPATHTestBranchAncestor() {
    sane(1);
    for (size_t i = 0; i < BRANCH_ANC_N; i++) {
        BranchAncCase const *tc = &BRANCH_ANC_CASES[i];
        u8cs anc = {(u8cp)tc->anc, (u8cp)tc->anc + strlen(tc->anc)};
        u8cs des = {(u8cp)tc->des, (u8cp)tc->des + strlen(tc->des)};
        b8 got = DPATHBranchAncestor(anc, des);
        if (got != tc->expect) {
            fprintf(stderr, "FAIL ancestor[%zu] '%s' < '%s': got %d want %d\n",
                    i, tc->anc, tc->des, got, tc->expect);
            fail(TESTFAIL);
        }
    }
    done;
}

ok64 DPATHtest() {
    sane(1);
    call(DPATHTestTable);
    call(DPATHTestBranchNorm);
    call(DPATHTestBranchAncestor);
    done;
}

TEST(DPATHtest);
