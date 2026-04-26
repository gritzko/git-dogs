#include "dog/QURY.h"

#include <string.h>

#include "abc/PRO.h"
#include "abc/TEST.h"

// --- Single spec tests ---

typedef struct {
    const char *input;
    u8 type;
    const char *body;
    u8 anc_type;
    u32 ancestry;
} QREFCase;

static const QREFCase QREF_CASES[] = {

    // --- Simple ref names ---
    {"main",              QURY_REF, "main",   0, 0},
    {"master",            QURY_REF, "master", 0, 0},
    {"develop",           QURY_REF, "develop", 0, 0},
    {"HEAD",              QURY_REF, "HEAD",   0, 0},
    {"x",                 QURY_REF, "x",      0, 0},
    {"_private",          QURY_REF, "_private", 0, 0},

    // --- Version tags ---
    {"v2.8.6",            QURY_REF, "v2.8.6",  0, 0},
    {"v1.0",              QURY_REF, "v1.0",    0, 0},
    {"v0.0.1-rc1",        QURY_REF, "v0.0.1-rc1", 0, 0},
    {"release-1.2.3",     QURY_REF, "release-1.2.3", 0, 0},
    {"my.dotted.branch",  QURY_REF, "my.dotted.branch", 0, 0},
    {"a-b-c",             QURY_REF, "a-b-c",  0, 0},

    // --- Ref paths with slashes ---
    {"refs/heads/main",          QURY_REF, "refs/heads/main", 0, 0},
    {"refs/tags/v1.0",           QURY_REF, "refs/tags/v1.0", 0, 0},
    {"refs/remotes/origin/main", QURY_REF, "refs/remotes/origin/main", 0, 0},
    {"tags/gitgui-0.16.0",       QURY_REF, "tags/gitgui-0.16.0", 0, 0},
    {"feature/my-branch",        QURY_REF, "feature/my-branch", 0, 0},
    {"fix/issue-42",             QURY_REF, "fix/issue-42", 0, 0},

    // --- SHA prefixes (all hex, >= 6 chars) ---
    {"a1b2c3",            QURY_SHA, "a1b2c3",  0, 0},
    {"a1b2c3d4e5f6",      QURY_SHA, "a1b2c3d4e5f6", 0, 0},
    {"deadbeef",          QURY_SHA, "deadbeef", 0, 0},
    {"DEADBEEF",          QURY_SHA, "DEADBEEF", 0, 0},
    {"abcdef1234567890abcdef1234567890abcdef12",
        QURY_SHA, "abcdef1234567890abcdef1234567890abcdef12", 0, 0},

    // --- Short hex → REF (< 6 chars) ---
    {"abc",               QURY_REF, "abc",    0, 0},
    {"a1b2",              QURY_REF, "a1b2",   0, 0},
    {"a1b2c",             QURY_REF, "a1b2c",  0, 0},

    // --- Not SHA (has non-hex) ---
    {"abcdefg",           QURY_REF, "abcdefg", 0, 0},
    {"123xyz",            QURY_REF, "123xyz",  0, 0},

    // --- Ancestry: tilde ---
    {"HEAD~3",            QURY_REF, "HEAD",   '~', 3},
    {"main~1",            QURY_REF, "main",   '~', 1},
    {"HEAD~10",           QURY_REF, "HEAD",   '~', 10},
    {"refs/heads/main~5", QURY_REF, "refs/heads/main", '~', 5},
    {"HEAD~",             QURY_REF, "HEAD",   '~', 0},

    // --- Ancestry: caret ---
    {"HEAD^2",            QURY_REF, "HEAD",   '^', 2},
    {"main^",             QURY_REF, "main",   '^', 0},
    {"HEAD^",             QURY_REF, "HEAD",   '^', 0},
};

#define QREF_NCASES (sizeof(QREF_CASES) / sizeof(QREF_CASES[0]))

// --- Multi-ref tests (& separated) ---

typedef struct {
    const char *input;
    u32 nrefs;
    const char *bodies[4];
    u8 types[4];
    u8 anc_types[4];
    u32 ancestries[4];
} QREFMultiCase;

static const QREFMultiCase QREF_MULTI[] = {

    // --- Two refs ---
    {"main&feat", 2,
        {"main", "feat"}, {QURY_REF, QURY_REF}, {0,0}, {0,0}},

    {"HEAD~3&HEAD", 2,
        {"HEAD", "HEAD"}, {QURY_REF, QURY_REF}, {'~',0}, {3,0}},

    {"v1.0&v2.0", 2,
        {"v1.0", "v2.0"}, {QURY_REF, QURY_REF}, {0,0}, {0,0}},

    {"a1b2c3&main", 2,
        {"a1b2c3", "main"}, {QURY_SHA, QURY_REF}, {0,0}, {0,0}},

    {"refs/tags/v1&refs/tags/v2", 2,
        {"refs/tags/v1", "refs/tags/v2"}, {QURY_REF, QURY_REF}, {0,0}, {0,0}},

    {"tags/gitgui-0.15.0&tags/gitgui-0.16.0", 2,
        {"tags/gitgui-0.15.0", "tags/gitgui-0.16.0"},
        {QURY_REF, QURY_REF}, {0,0}, {0,0}},

    {"main^&feat~2", 2,
        {"main", "feat"}, {QURY_REF, QURY_REF}, {'^','~'}, {0,2}},

    // --- Three refs (merge) ---
    {"base&ours&theirs", 3,
        {"base", "ours", "theirs"},
        {QURY_REF, QURY_REF, QURY_REF}, {0,0,0}, {0,0,0}},

    {"main&feat&develop", 3,
        {"main", "feat", "develop"},
        {QURY_REF, QURY_REF, QURY_REF}, {0,0,0}, {0,0,0}},

    // --- Single (no &) ---
    {"main", 1,
        {"main"}, {QURY_REF}, {0}, {0}},

    {"HEAD~3", 1,
        {"HEAD"}, {QURY_REF}, {'~'}, {3}},
};

#define QREF_NMULTI (sizeof(QREF_MULTI) / sizeof(QREF_MULTI[0]))

// --- Relative-prefix cases (./, ../, bare ..) ---

typedef struct {
    const char *input;
    u8 type;
    const char *body;
    u8 rel;
} QREFRelCase;

static const QREFRelCase QREF_REL[] = {
    {"./fix",           QURY_REF, "fix",     QURY_REL_DOWN},
    {"./feat/sub",      QURY_REF, "feat/sub", QURY_REL_DOWN},
    {"../fix",          QURY_REF, "fix",     QURY_REL_UP},
    {"../sib/leaf",     QURY_REF, "sib/leaf", QURY_REL_UP},
    {"..",              QURY_REF, NULL,      QURY_REL_UP},
    {"main",            QURY_REF, "main",    QURY_REL_NONE},
    {"feat/fix",        QURY_REF, "feat/fix", QURY_REL_NONE},
};
#define QREF_NREL (sizeof(QREF_REL) / sizeof(QREF_REL[0]))

// --- Bad inputs ---

static const char *QURY_BAD[] = {
    "",            // empty
    "a/",          // trailing slash
    "/a",          // leading slash
    "a//b",        // double slash
    "./",          // relative prefix with no body
    "../",         // relative prefix with no body
    "...",         // three dots not a recognised form
    NULL,
};

static b8 qref_eq(u8cs s, const char *expect) {
    if (expect == NULL) return $empty(s);
    size_t elen = strlen(expect);
    if ((size_t)$len(s) != elen) return NO;
    if (elen == 0) return YES;
    return memcmp(s[0], expect, elen) == 0;
}

ok64 QURYTestSingle() {
    sane(1);
    for (size_t i = 0; i < QREF_NCASES; i++) {
        const QREFCase *tc = &QREF_CASES[i];
        u8cs input = {(u8cp)tc->input, (u8cp)tc->input + strlen(tc->input)};

        qref q = {};
        ok64 o = QURYu8sDrain(input, &q);
        if (o != OK) {
            fprintf(stderr, "FAIL [%zu] '%s': parse error %s\n",
                    i, tc->input, ok64str(o));
            fail(TESTFAIL);
        }

        if (q.type != tc->type) {
            fprintf(stderr, "FAIL [%zu] '%s': type got %d want %d\n",
                    i, tc->input, q.type, tc->type);
            fail(TESTFAIL);
        }

        if (!qref_eq(q.body, tc->body)) {
            fprintf(stderr, "FAIL [%zu] '%s': body got '%.*s' want '%s'\n",
                    i, tc->input,
                    (int)$len(q.body),
                    $empty(q.body) ? "" : (char *)q.body[0],
                    tc->body);
            fail(TESTFAIL);
        }

        if (q.anc_type != tc->anc_type) {
            fprintf(stderr, "FAIL [%zu] '%s': anc_type got '%c' want '%c'\n",
                    i, tc->input,
                    q.anc_type ? q.anc_type : '0',
                    tc->anc_type ? tc->anc_type : '0');
            fail(TESTFAIL);
        }

        if (q.ancestry != tc->ancestry) {
            fprintf(stderr, "FAIL [%zu] '%s': ancestry got %u want %u\n",
                    i, tc->input, q.ancestry, tc->ancestry);
            fail(TESTFAIL);
        }
    }
    done;
}

ok64 QURYTestMulti() {
    sane(1);
    for (size_t i = 0; i < QREF_NMULTI; i++) {
        const QREFMultiCase *tc = &QREF_MULTI[i];
        u8cs input = {(u8cp)tc->input, (u8cp)tc->input + strlen(tc->input)};

        u32 got = 0;
        while (!$empty(input)) {
            qref q = {};
            ok64 o = QURYu8sDrain(input, &q);
            if (o != OK) {
                fprintf(stderr, "FAIL multi[%zu] '%s' ref %u: parse error %s\n",
                        i, tc->input, got, ok64str(o));
                fail(TESTFAIL);
            }
            if (q.type == QURY_NONE) break;

            if (got >= tc->nrefs) {
                fprintf(stderr, "FAIL multi[%zu] '%s': too many refs (>%u)\n",
                        i, tc->input, tc->nrefs);
                fail(TESTFAIL);
            }

            if (q.type != tc->types[got]) {
                fprintf(stderr, "FAIL multi[%zu] '%s' ref %u: type got %d want %d\n",
                        i, tc->input, got, q.type, tc->types[got]);
                fail(TESTFAIL);
            }

            if (!qref_eq(q.body, tc->bodies[got])) {
                fprintf(stderr, "FAIL multi[%zu] '%s' ref %u: body got '%.*s' want '%s'\n",
                        i, tc->input, got,
                        (int)$len(q.body),
                        $empty(q.body) ? "" : (char *)q.body[0],
                        tc->bodies[got]);
                fail(TESTFAIL);
            }

            if (q.anc_type != tc->anc_types[got]) {
                fprintf(stderr, "FAIL multi[%zu] '%s' ref %u: anc_type got '%c' want '%c'\n",
                        i, tc->input, got,
                        q.anc_type ? q.anc_type : '0',
                        tc->anc_types[got] ? tc->anc_types[got] : '0');
                fail(TESTFAIL);
            }

            if (q.ancestry != tc->ancestries[got]) {
                fprintf(stderr, "FAIL multi[%zu] '%s' ref %u: ancestry got %u want %u\n",
                        i, tc->input, got, q.ancestry, tc->ancestries[got]);
                fail(TESTFAIL);
            }

            got++;
        }

        if (got != tc->nrefs) {
            fprintf(stderr, "FAIL multi[%zu] '%s': nrefs got %u want %u\n",
                    i, tc->input, got, tc->nrefs);
            fail(TESTFAIL);
        }
    }
    done;
}

ok64 QURYTestBad() {
    sane(1);
    for (int i = 0; QURY_BAD[i]; i++) {
        const char *s = QURY_BAD[i];
        u8cs input = {(u8cp)s, (u8cp)s + strlen(s)};
        qref q = {};
        ok64 o = QURYu8sDrain(input, &q);
        if (o == OK && q.type != QURY_NONE) {
            fprintf(stderr, "FAIL bad[%d] '%s': expected failure, got type %d\n",
                    i, s, q.type);
            fail(TESTFAIL);
        }
    }
    done;
}

// --- QURYBuildAbsolute resolver ---

typedef struct {
    const char *spec_input;
    const char *current;
    const char *want;
} QREFAbsCase;

static const QREFAbsCase QREF_ABS[] = {
    // Absolute ref: current is irrelevant, body passes through.
    {"main",        "trunk",     "main"},
    {"main",        "",          "main"},
    {"feat/fix",    "trunk",     "feat/fix"},

    // ./body — child of current.
    {"./fix",       "feat",      "feat/fix"},
    {"./fix",       "",          "fix"},          // trunk → root-level
    {"./sub/leaf",  "feat",      "feat/sub/leaf"},

    // ../body — sibling of current.
    {"../sib",      "feat",      "sib"},          // top-level → trunk
    {"../sib",      "feat/fix",  "feat/sib"},
    {"../sib",      "a/b/c",     "a/b/sib"},

    // .. — parent only, empty body.
    {"..",          "feat/fix",  "feat"},
    {"..",          "feat",      ""},             // top-level parent = trunk
    {"..",          "",          ""},             // trunk's parent = trunk
};
#define QREF_NABS (sizeof(QREF_ABS) / sizeof(QREF_ABS[0]))

ok64 QURYTestAbs() {
    sane(1);
    for (size_t i = 0; i < QREF_NABS; i++) {
        const QREFAbsCase *tc = &QREF_ABS[i];
        u8cs spec_in = {(u8cp)tc->spec_input,
                        (u8cp)tc->spec_input + strlen(tc->spec_input)};
        qref q = {};
        ok64 po = QURYu8sDrain(spec_in, &q);
        if (po != OK) {
            fprintf(stderr, "FAIL abs[%zu] '%s': parse error %s\n",
                    i, tc->spec_input, ok64str(po));
            fail(TESTFAIL);
        }

        u8cs cur = {(u8cp)tc->current,
                    (u8cp)tc->current + strlen(tc->current)};

        a_pad(u8, out, 256);
        ok64 ro = QURYBuildAbsolute(out, &q, cur);
        if (ro != OK) {
            fprintf(stderr, "FAIL abs[%zu] '%s' / '%s': resolve %s\n",
                    i, tc->spec_input, tc->current, ok64str(ro));
            fail(TESTFAIL);
        }

        a_dup(u8c, got, u8bData(out));
        size_t want_len = strlen(tc->want);
        if ((size_t)$len(got) != want_len ||
            (want_len > 0 && memcmp(got[0], tc->want, want_len) != 0)) {
            fprintf(stderr,
                    "FAIL abs[%zu] '%s' / '%s': got '%.*s' want '%s'\n",
                    i, tc->spec_input, tc->current,
                    (int)$len(got),
                    $empty(got) ? "" : (char *)got[0],
                    tc->want);
            fail(TESTFAIL);
        }
    }
    done;
}

ok64 QURYTestRel() {
    sane(1);
    for (size_t i = 0; i < QREF_NREL; i++) {
        const QREFRelCase *tc = &QREF_REL[i];
        u8cs input = {(u8cp)tc->input, (u8cp)tc->input + strlen(tc->input)};

        qref q = {};
        ok64 o = QURYu8sDrain(input, &q);
        if (o != OK) {
            fprintf(stderr, "FAIL rel[%zu] '%s': parse error %s\n",
                    i, tc->input, ok64str(o));
            fail(TESTFAIL);
        }
        if (q.type != tc->type) {
            fprintf(stderr, "FAIL rel[%zu] '%s': type got %d want %d\n",
                    i, tc->input, q.type, tc->type);
            fail(TESTFAIL);
        }
        if (!qref_eq(q.body, tc->body)) {
            fprintf(stderr, "FAIL rel[%zu] '%s': body got '%.*s' want '%s'\n",
                    i, tc->input,
                    (int)$len(q.body),
                    $empty(q.body) ? "" : (char *)q.body[0],
                    tc->body ? tc->body : "");
            fail(TESTFAIL);
        }
        if (q.rel != tc->rel) {
            fprintf(stderr, "FAIL rel[%zu] '%s': rel got %d want %d\n",
                    i, tc->input, q.rel, tc->rel);
            fail(TESTFAIL);
        }
    }
    done;
}

ok64 QURYtest() {
    sane(1);
    call(QURYTestSingle);
    call(QURYTestMulti);
    call(QURYTestBad);
    call(QURYTestRel);
    call(QURYTestAbs);
    done;
}

TEST(QURYtest);
