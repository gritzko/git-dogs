#include "dog/DOG.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "abc/PRO.h"
#include "abc/TEST.h"

typedef struct {
    const char *input;
    const char *scheme;
    const char *authority;
    const char *path;
    const char *query;
    const char *fragment;
} ParseCase;

static const ParseCase CASES[] = {

    // --- Normalized: bare host:path (no //) ---
    {"localhost:src/git/protocol.h",
        NULL, "localhost", "src/git/protocol.h", NULL, NULL},
    {"origin:docs/README.md",
        NULL, "origin", "docs/README.md", NULL, NULL},
    {"host:path?ref#frag",
        NULL, "host", "path", "ref", "frag"},
    {"localhost:src/git/protocol.h?v2.8.6#protocol_version",
        NULL, "localhost", "src/git/protocol.h",
        "v2.8.6", "protocol_version"},

    // --- Unchanged: proper URIs with // ---
    {"https://example.com/path",
        "https", "//example.com", "/path", NULL, NULL},
    {"file:///etc/passwd",
        "file", "//", "/etc/passwd", NULL, NULL},
    {"//localhost/src/file",
        NULL, "//localhost", "/src/file", NULL, NULL},

    // --- Unchanged: file:/path (scheme with rooted path) ---
    {"file:/etc/passwd",
        "file", NULL, "/etc/passwd", NULL, NULL},

    // --- No scheme: just path ---
    {"src/git/protocol.h",
        NULL, NULL, "src/git/protocol.h", NULL, NULL},
    {"/absolute/path",
        NULL, NULL, "/absolute/path", NULL, NULL},

    // --- Query/fragment only ---
    {"?v2.8.6",
        NULL, NULL, NULL, "v2.8.6", NULL},
    {"#symbol",
        NULL, NULL, NULL, NULL, "symbol"},

    // --- Non-numeric "port" glued back into path ---
    // RFC 3986 eats `src` as the port; we fix it up.
    {"ssh://localhost:src/dogs-sniff",
        "ssh", "//localhost", "src/dogs-sniff", NULL, NULL},
    {"ssh://host:repo",
        "ssh", "//host", "repo", NULL, NULL},
    // Numeric port left alone.
    {"ssh://host:22/repo",
        "ssh", "//host:22", "/repo", NULL, NULL},

    // --- View-projector schemes: exempt from scheme→authority promotion ---
    // `ls:`, `tree:`, `blob:`, `sha1:`, etc. stay as the scheme so
    // `ls:subdir` and `tree:src/?heads/feat` are view projections, not
    // scp-like remote paths.  See VERBS.md §"View projectors".
    {"ls:",                   "ls", NULL, NULL,        NULL,         NULL},
    {"ls:subdir",             "ls", NULL, "subdir",    NULL,         NULL},
    {"ls:./subdir",           "ls", NULL, "./subdir",  NULL,         NULL},
    {"ls:?heads/feat",        "ls", NULL, NULL,        "heads/feat", NULL},
    {"ls:subdir?heads/feat",  "ls", NULL, "subdir",    "heads/feat", NULL},
    {"tree:src/?heads/feat", "tree", NULL, "src/",     "heads/feat", NULL},
    {"blob:file.c?abc",      "blob", NULL, "file.c",   "abc",        NULL},
    {"sha1:?heads/feat",     "sha1", NULL, NULL,       "heads/feat", NULL},
};

#define NCASES (sizeof(CASES) / sizeof(CASES[0]))

static b8 s_eq(u8cs s, const char *expect) {
    if (expect == NULL) return $empty(s);
    size_t elen = strlen(expect);
    if ((size_t)$len(s) != elen) return NO;
    if (elen == 0) return YES;
    return memcmp(s[0], expect, elen) == 0;
}

static b8 check(size_t i, const char *field, u8cs got, const char *expect) {
    if (s_eq(got, expect)) return YES;
    fprintf(stderr, "FAIL [%zu] '%s': %s got '%.*s' want '%s'\n",
            i, CASES[i].input, field,
            (int)$len(got),
            $empty(got) ? "" : (char *)got[0],
            expect ? expect : "(empty)");
    return NO;
}

ok64 DOGTestDOGParseURI() {
    sane(1);
    for (size_t i = 0; i < NCASES; i++) {
        const ParseCase *tc = &CASES[i];
        u8csc text = {(u8cp)tc->input, (u8cp)tc->input + strlen(tc->input)};

        uri u = {};
        ok64 o = DOGParseURI(&u, text);
        if (o != OK) {
            fprintf(stderr, "FAIL [%zu] '%s': parse error %s\n",
                    i, tc->input, ok64str(o));
            fail(TESTFAIL);
        }

        if (!check(i, "scheme",    u.scheme,    tc->scheme))    fail(TESTFAIL);
        if (!check(i, "authority", u.authority, tc->authority)) fail(TESTFAIL);
        if (!check(i, "path",      u.path,      tc->path))      fail(TESTFAIL);
        if (!check(i, "query",     u.query,     tc->query))     fail(TESTFAIL);
        if (!check(i, "fragment",  u.fragment,  tc->fragment))  fail(TESTFAIL);
    }
    done;
}

// --- Canonical round-trip: input → DOGNormalizeArg → DOGCanonURIFeed ---
//
// `expect` is what the canonical byte stream should be.  Covers the full
// pipeline: classification (query/fragment/path), dog normalisations
// (scheme→authority, port-fixup, @host split), and canonicalisation
// (scheme-stripping for transports, `file:` preservation, `//`+path,
// `?/` → `?` trunk fold, `?` strip from fragment).
//
// The query is an opaque local branch path — no `refs/` strip, no
// `heads/main`/`master`/`trunk` aliasing.  Git refname conventions
// live behind keeper/GIT.h's GITParseRef/GITFeedRef and apply only
// at the wire boundary.
typedef struct {
    const char *input;
    const char *expect;   // DOGCanonURIFeed(norm_arg)
} CanonCase;

static const CanonCase CANON_CASES[] = {
    // Scheme preserved — ssh/https/git/file/be all pass through.
    {"ssh://localhost/src/repo?master",    "ssh://localhost/src/repo?master"},
    {"https://localhost/src/repo?master",  "https://localhost/src/repo?master"},
    {"git://localhost/src/repo?master",    "git://localhost/src/repo?master"},
    // `file:` preserved.
    {"file:///etc/passwd",                 "file:///etc/passwd"},
    // Scp-like form: `host:path`, non-numeric port glued back.
    {"ssh://localhost:src/repo?master",    "ssh://localhost/src/repo?master"},
    {"localhost:src/repo?master",          "//localhost/src/repo?master"},
    // User@host form — no `//`, promoted via the @-split rule.
    {"gritzko@pm.me/proj?main",            "//gritzko@pm.me/proj?main"},
    {"gritzko@pm.me?main",                 "//gritzko@pm.me?main"},
    // Already canonical.
    {"//localhost/src/repo?master",        "//localhost/src/repo?master"},
    // Path-only.
    {"/absolute/path",                     "/absolute/path"},
    // Bare token — RFC 3986 path-noscheme; verbs that expect a ref
    // (post, patch) demote path → query themselves.
    {"master",                             "master"},
    {"main",                               "main"},
    {"trunk",                              "trunk"},
    {"feature",                            "feature"},
    // No `refs/` strip — query is opaque.
    {"?refs/heads/main",                   "?refs/heads/main"},
    {"?heads/main",                        "?heads/main"},
    {"?refs/tags/v1.0",                    "?refs/tags/v1.0"},
    {"?tags/v2.8.6",                       "?tags/v2.8.6"},
    // Trunk: `?` and `?/` both fold to `?`.
    {"?",                                  "?"},
    {"?/",                                 "?"},
    // 40-hex SHA — bare path; verbs that expect a sha demote.
    {"0123456789abcdef0123456789abcdef01234567",
        "0123456789abcdef0123456789abcdef01234567"},
    // Whitespace — classified as fragment (commit msg).
    {"fix the typo",                       "#fix the typo"},
    // Whitespace with explicit leading `#` — `#` consumed, body kept.
    {"#fix the typo",                      "#fix the typo"},
    // Whitespace fragment with single-quoted spot body.
    {"#'u8sFeed( a, b )'",                 "#'u8sFeed( a, b )'"},
    // Bare fragment.
    {"#symbol",                            "#symbol"},
    // Bare query (version-like).
    {"?v2.8.6",                            "?v2.8.6"},
    // Numeric port preserved (real port, not a glued path).
    {"ssh://host:22/repo",                 "ssh://host:22/repo"},
    // Trunk-move row: `?#<sha>` — empty-but-present query, non-empty
    // fragment with leading `?` stripped.
    {"?#?0123456789abcdef0123456789abcdef01234567",
        "?#0123456789abcdef0123456789abcdef01234567"},
    // Remote branch observation: scheme + host + path + query +
    // fragment round-trip.
    {"ssh://peer/src/repo?heads/feat#?0123456789abcdef0123456789abcdef01234567",
        "ssh://peer/src/repo?heads/feat#0123456789abcdef0123456789abcdef01234567"},
    // Deletion row: `?branch#` — non-empty query, empty-but-present fragment.
    {"?feature/fix1#",                     "?feature/fix1#"},
    // Search projectors: scheme + body in path slot, whitespace OK.
    {"spot:u8sFeed",                       "spot:u8sFeed"},
    {"grep:u8sFeed",                       "grep:u8sFeed"},
    {"spot:'u8sFeed( a, b )'",             "spot:'u8sFeed( a, b )'"},
    // View projectors round-trip with scheme preserved.
    {"ls:subdir",                          "ls:subdir"},
    {"ls:?heads/feat",                     "ls:?heads/feat"},
    {"ls:?master",                         "ls:?master"},
    {"tree:src/?heads/feat",               "tree:src/?heads/feat"},
    {"sha1:?heads/feat",                   "sha1:?heads/feat"},
};

#define NCANON (sizeof(CANON_CASES) / sizeof(CANON_CASES[0]))

ok64 DOGTestCanonical() {
    sane(1);
    for (size_t i = 0; i < NCANON; i++) {
        const CanonCase *tc = &CANON_CASES[i];
        u8csc text = {(u8cp)tc->input, (u8cp)tc->input + strlen(tc->input)};

        uri u = {};
        ok64 o = DOGNormalizeArg(&u, text);
        if (o != OK) {
            fprintf(stderr, "FAIL [%zu] '%s': normalize error %s\n",
                    i, tc->input, ok64str(o));
            fail(TESTFAIL);
        }

        a_pad(u8, canbuf, 1024);
        call(DOGCanonURIFeed, canbuf, &u);

        a_dup(u8c, got, u8bData(canbuf));
        a_cstr(want, tc->expect);
        if (!$eq(got, want)) {
            fprintf(stderr, "FAIL [%zu] '%s':\n  got    '%.*s'\n  expect '%s'\n",
                    i, tc->input,
                    (int)$len(got), (char *)got[0], tc->expect);
            fail(TESTFAIL);
        }
    }
    done;
}

// Folding leaves through DOGChildPathHash from ROOT must match
// DOGPathHash on the joined path.
ok64 DOGTestPathHash() {
    sane(1);
    a_cstr(a, "a");
    a_cstr(b, "b");
    a_cstr(c, "c");
    u64 step = DOGChildPathHash(a, ROOT);
    step = DOGChildPathHash(b, step);
    step = DOGChildPathHash(c, step);

    a_cstr(abc, "a/b/c");
    u64 whole = DOGPathHash(abc);
    if (step != whole) {
        fprintf(stderr, "FAIL hash(a/b/c)=%llx step=%llx\n",
                (unsigned long long)whole, (unsigned long long)step);
        fail(TESTFAIL);
    }

    // Empty path (and "/") must equal ROOT.
    a_cstr(empty, "");
    if (DOGPathHash(empty) != ROOT) fail(TESTFAIL);
    a_cstr(slash, "/");
    if (DOGPathHash(slash) != ROOT) fail(TESTFAIL);

    // Repeated/leading/trailing slashes must not change the hash.
    a_cstr(messy, "/a//b/c/");
    if (DOGPathHash(messy) != whole) fail(TESTFAIL);
    done;
}

// --- DOGutf8sFeedDate: short relative date format -----------------
//
// All cases anchor on `now = 2025-04-30 12:00:00 UTC` (1746014400, a
// Wednesday) so the table reads as wall-clock minus a known reference.

typedef struct {
    i64         ts;
    char const *expect;
} DateCase;

static i64 const DOG_DATE_NOW = 1746014400;  // 2025-04-30 12:00:00 UTC (Wed)

//  All outputs padded to 7 cols, centred (lead = (7-len)/2, trail rest).
static DateCase const DATE_CASES[] = {
    //  Same day / < 12hr → "HH:MM" in UTC (anchor is 12:00 UTC).
    {DOG_DATE_NOW,            " 12:00 "},   // exact now
    {DOG_DATE_NOW - 30,       " 11:59 "},   // 30s ago
    {DOG_DATE_NOW - 120,      " 11:58 "},   // 2 min
    {DOG_DATE_NOW - 59 * 60,  " 11:01 "},   // just under 1hr
    {DOG_DATE_NOW - 3600,     " 11:00 "},   // 1 hr
    //  23hr back: not <12hr and Tue 2025-04-29 13:00 (different
    //  calendar day) → weekday + DD bucket.
    {DOG_DATE_NOW - 23*3600,  " Tue29 "},
    //  3 days back from Wed = Sun 2025-04-27.
    {DOG_DATE_NOW - 3*86400,  " Sun27 "},
    //  10 days back: < 6 months → "DDMon".  2025-04-20 → "20Apr".
    {DOG_DATE_NOW - 10*86400, " 20Apr "},
    //  ~14 months back: not <6mo and not same year → "DDMonYY".
    //  2024-02-19 12:00 UTC.
    {1708344000,              "19Feb24"},
    //  ts <= 0: "?"
    {0,                       "   ?   "},
    {-1,                      "   ?   "},
};

#define NDATE (sizeof(DATE_CASES) / sizeof(DATE_CASES[0]))

ok64 DOGTestFeedDate() {
    sane(1);
    //  DATE_CASES expectations are anchored to UTC wall-clock; pin
    //  TZ so localtime() in DOGutf8sFeedDate matches regardless of
    //  the build host's locale.
    setenv("TZ", "UTC", 1);
    tzset();
    for (size_t i = 0; i < NDATE; i++) {
        DateCase const *tc = &DATE_CASES[i];
        a_pad(u8, buf, 16);
        call(DOGutf8sFeedDate, u8bIdle(buf), tc->ts, DOG_DATE_NOW);
        a_dup(u8c, got, u8bData(buf));
        a_cstr(want, tc->expect);
        if ($len(got) != 7) {
            fprintf(stderr, "FAIL [%zu] ts=%lld: '%.*s' is %d chars; want exactly 7\n",
                    i, (long long)tc->ts,
                    (int)$len(got), (char *)got[0], (int)$len(got));
            fail(TESTFAIL);
        }
        if (!$eq(got, want)) {
            fprintf(stderr, "FAIL [%zu] ts=%lld:\n  got    '%.*s'\n  expect '%s'\n",
                    i, (long long)tc->ts,
                    (int)$len(got), (char *)got[0], tc->expect);
            fail(TESTFAIL);
        }
    }
    done;
}

ok64 DOGtest() {
    sane(1);
    call(DOGTestDOGParseURI);
    call(DOGTestCanonical);
    call(DOGTestPathHash);
    call(DOGTestFeedDate);
    done;
}

TEST(DOGtest);
