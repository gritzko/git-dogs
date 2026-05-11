//  ULOG — append-only URI event log: round-trip + lookup coverage.
//
//  Cases:
//    1. Open-empty + append three rows + Count/Head/Tail.
//    2. Persistence: close, reopen, verify all rows survive.
//    3. Random access: Row(i) recovers per-row ts + verb + URI.
//    4. Seek/Find/Has: lower_bound, exact, membership.
//    5. Monotonicity: AppendAt with stale ts returns ULOGCLOCK.
//    6. FindVerb: reverse scan picks the latest row for that verb.
//    7. Truncate: keep_n rewinds both book and idx.
//    8. Streaming Feed / Drain round-trip.
//    9. Whitespace tolerance: multi-space / multi-tab separators.

#include "dog/ULOG.h"

#include <string.h>

#include "abc/FILE.h"
#include "abc/PRO.h"
#include "abc/TEST.h"

static ok64 rm_tmp(char const *p) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", p);
    int _ = system(cmd);
    (void)_;
    return OK;
}

#define LOGPATH(name, text)                                             \
    a_pad(u8, name##_buf, FILE_PATH_MAX_LEN);                           \
    a_cstr(name##_cstr, text);                                          \
    u8bFeed(name##_buf, name##_cstr);                                   \
    u8bFeed1(name##_buf, 0);                                            \
    a_dup(u8c, name, u8bData(name##_buf))

//  Parse + keep a raw-text copy so test predicates can compare on the
//  original URI bytes independent of URILexer's consume semantics.
typedef struct { uri u; char raw[512]; } saved_uri;

static ok64 parse_uri_lit(saved_uri *s, char const *text) {
    size_t n = strlen(text);
    if (n >= sizeof(s->raw)) return TESTFAIL;
    memcpy(s->raw, text, n);
    s->raw[n] = 0;
    memset(&s->u, 0, sizeof(s->u));
    s->u.data[0] = (u8cp)s->raw;
    s->u.data[1] = (u8cp)s->raw + n;
    return URILexer(&s->u);
}

//  After URILexer, data is consumed; re-seed from the preserved raw
//  text before handing to ULOGAppend (which re-serialises components).
static uricp saved_uri_for_append(saved_uri *s) {
    size_t n = strlen(s->raw);
    s->u.data[0] = (u8cp)s->raw;
    s->u.data[1] = (u8cp)s->raw + n;
    return &s->u;
}

//  Re-serialise a parsed uri into a local buffer and compare bytes
//  against a literal.  Captures the round-trip through URIutf8Feed,
//  which is what ULOG emits.
static b8 uri_serializes_to(uricp u, char const *expect) {
    a_pad(u8, buf, 512);
    if (URIutf8Feed(u8bIdle(buf), u) != OK) return NO;
    a_dup(u8c, got, u8bData(buf));
    size_t el = strlen(expect);
    return (size_t)$len(got) == el && memcmp(got[0], expect, el) == 0;
}

static ron60 verb_of(char const *s) {
    ron60 v = 0;
    u8cs slice = {(u8cp)s, (u8cp)s + strlen(s)};
    a_dup(u8c, dup, slice);
    RONutf8sDrain(&v, dup);
    return v;
}

//  Compose a ulogrec from saved_uri + ts + verb (caller-provided).
static ulogrec rec_of(ron60 ts, ron60 verb, saved_uri *s) {
    ulogrec r = {.ts = ts, .verb = verb, .uri = *saved_uri_for_append(s)};
    return r;
}

static ok64 T_roundtrip(void) {
    sane(1);
    call(FILEInit);
    rm_tmp("/tmp/ulog-rt.log");
    LOGPATH(path, "/tmp/ulog-rt.log");

    u8bp  l_data = NULL;
    wh128bp l_idx  = NULL;
    call(ULOGOpen, &l_data, &l_idx, path);
    want(ULOGCount(l_idx) == 0);

    saved_uri s1 = {}, s2 = {}, s3 = {};
    call(parse_uri_lit, &s1, "//localhost/repo?heads/master");
    call(parse_uri_lit, &s2, "//localhost/repo?staging/abcd1234");
    call(parse_uri_lit, &s3, "?heads/main");

    ulogrec r1 = rec_of(1000, verb_of("get"),  &s1);
    ulogrec r2 = rec_of(1001, verb_of("put"),  &s2);
    ulogrec r3 = rec_of(1002, verb_of("post"), &s3);
    call(ULOGAppendAt, l_data, l_idx, &r1);
    call(ULOGAppendAt, l_data, l_idx, &r2);
    call(ULOGAppendAt, l_data, l_idx, &r3);
    want(ULOGCount(l_idx) == 3);

    ulogrec g = {};
    call(ULOGHead, l_data, l_idx, &g);
    want(g.verb == verb_of("get"));
    want(uri_serializes_to(&g.uri, "//localhost/repo?heads/master"));
    call(ULOGTail, l_data, l_idx, &g);
    want(g.verb == verb_of("post"));
    want(uri_serializes_to(&g.uri, "?heads/main"));

    call(ULOGClose, l_data, &l_idx, YES);
    done;
}

static ok64 T_persist(void) {
    sane(1);
    LOGPATH(path, "/tmp/ulog-rt.log");

    u8bp  l_data = NULL;
    wh128bp l_idx  = NULL;
    call(ULOGOpen, &l_data, &l_idx, path);
    want(ULOGCount(l_idx) == 3);

    ulogrec g = {};
    call(ULOGRow, l_data, l_idx, 1, &g);
    want(g.verb == verb_of("put"));
    want(uri_serializes_to(&g.uri, "//localhost/repo?staging/abcd1234"));

    call(ULOGClose, l_data, &l_idx, YES);
    rm_tmp("/tmp/ulog-rt.log");
    done;
}

static ok64 T_seek(void) {
    sane(1);
    rm_tmp("/tmp/ulog-sk.log");
    LOGPATH(path, "/tmp/ulog-sk.log");

    u8bp  l_data = NULL;
    wh128bp l_idx  = NULL;
    call(ULOGOpen, &l_data, &l_idx, path);

    ron60 stamps[] = {100, 200, 300, 400};
    saved_uri s = {};
    call(parse_uri_lit, &s, "//h/p");
    for (u32 i = 0; i < 4; i++) {
        ulogrec r = rec_of(stamps[i], verb_of("get"), &s);
        call(ULOGAppendAt, l_data, l_idx, &r);
    }
    want(ULOGCount(l_idx) == 4);

    u32 i = 99;
    call(ULOGSeek, l_idx, 250, &i);    want(i == 2);
    call(ULOGSeek, l_idx, 200, &i);    want(i == 1);
    call(ULOGSeek, l_idx, 500, &i);    want(i == 4);
    call(ULOGSeek, l_idx, 50,  &i);    want(i == 0);

    call(ULOGFind, l_idx, 300, &i);    want(i == 2);
    want(ULOGHas(l_idx, 100) == YES);
    want(ULOGHas(l_idx, 250) == NO);
    want(ULOGHas(l_idx, 400) == YES);
    want(ULOGFind(l_idx, 250, &i) == ULOGNONE);

    call(ULOGClose, l_data, &l_idx, YES);
    rm_tmp("/tmp/ulog-sk.log");
    done;
}

static ok64 T_clock(void) {
    sane(1);
    rm_tmp("/tmp/ulog-ck.log");
    LOGPATH(path, "/tmp/ulog-ck.log");

    u8bp  l_data = NULL;
    wh128bp l_idx  = NULL;
    call(ULOGOpen, &l_data, &l_idx, path);

    saved_uri s = {};
    call(parse_uri_lit, &s, "//h/p");
    {
        ulogrec r = rec_of(1000, verb_of("get"), &s);
        call(ULOGAppendAt, l_data, l_idx, &r);
    }
    {
        ulogrec r = rec_of(1000, verb_of("get"), &s);
        want(ULOGAppendAt(l_data, l_idx, &r) == ULOGCLOCK);
    }
    {
        ulogrec r = rec_of(999, verb_of("get"), &s);
        want(ULOGAppendAt(l_data, l_idx, &r) == ULOGCLOCK);
    }
    {
        ulogrec r = rec_of(1001, verb_of("get"), &s);
        call(ULOGAppendAt, l_data, l_idx, &r);
    }
    want(ULOGCount(l_idx) == 2);

    call(ULOGClose, l_data, &l_idx, YES);
    rm_tmp("/tmp/ulog-ck.log");
    done;
}

static ok64 T_findverb(void) {
    sane(1);
    rm_tmp("/tmp/ulog-fv.log");
    LOGPATH(path, "/tmp/ulog-fv.log");

    u8bp  l_data = NULL;
    wh128bp l_idx  = NULL;
    call(ULOGOpen, &l_data, &l_idx, path);

    saved_uri s1 = {}, s2 = {}, s3 = {}, s4 = {};
    call(parse_uri_lit, &s1, "?heads/master");
    call(parse_uri_lit, &s2, "?staging/deadbeef");
    call(parse_uri_lit, &s3, "?heads/main");
    call(parse_uri_lit, &s4, "?staging/cafef00d");

    {
        ulogrec r = rec_of(10, verb_of("get"),  &s1); call(ULOGAppendAt, l_data, l_idx, &r);
    } {
        ulogrec r = rec_of(20, verb_of("put"),  &s2); call(ULOGAppendAt, l_data, l_idx, &r);
    } {
        ulogrec r = rec_of(30, verb_of("post"), &s3); call(ULOGAppendAt, l_data, l_idx, &r);
    } {
        ulogrec r = rec_of(40, verb_of("put"),  &s4); call(ULOGAppendAt, l_data, l_idx, &r);
    }

    ulogrec g = {};
    call(ULOGFindVerb, l_data, l_idx, verb_of("put"), &g);
    want(g.ts == 40);
    want(uri_serializes_to(&g.uri, "?staging/cafef00d"));

    call(ULOGFindVerb, l_data, l_idx, verb_of("post"), &g);
    want(g.ts == 30);
    want(uri_serializes_to(&g.uri, "?heads/main"));

    want(ULOGFindVerb(l_data, l_idx, verb_of("patch"), &g) == ULOGNONE);

    call(ULOGClose, l_data, &l_idx, YES);
    rm_tmp("/tmp/ulog-fv.log");
    done;
}

static ok64 T_truncate(void) {
    sane(1);
    rm_tmp("/tmp/ulog-tr.log");
    LOGPATH(path, "/tmp/ulog-tr.log");

    u8bp  l_data = NULL;
    wh128bp l_idx  = NULL;
    call(ULOGOpen, &l_data, &l_idx, path);

    saved_uri s = {};
    call(parse_uri_lit, &s, "//h/p");
    for (u32 i = 0; i < 5; i++) {
        ulogrec r = rec_of((ron60)(100 + i), verb_of("get"), &s);
        call(ULOGAppendAt, l_data, l_idx, &r);
    }
    want(ULOGCount(l_idx) == 5);

    call(ULOGTruncate, l_data, l_idx, 3);
    want(ULOGCount(l_idx) == 3);

    ulogrec g = {};
    call(ULOGTail, l_data, l_idx, &g);
    want(g.ts == 102);

    {
        ulogrec r = rec_of(200, verb_of("get"), &s);
        call(ULOGAppendAt, l_data, l_idx, &r);
    }
    want(ULOGCount(l_idx) == 4);

    call(ULOGClose, l_data, &l_idx, YES);

    u8bp  l2_data = NULL;
    wh128bp l2_idx  = NULL;
    call(ULOGOpen, &l2_data, &l2_idx, path);
    want(ULOGCount(l2_idx) == 4);
    call(ULOGTail, l2_data, l2_idx, &g);
    want(g.ts == 200);
    call(ULOGClose, l2_data, &l2_idx, YES);
    rm_tmp("/tmp/ulog-tr.log");
    done;
}

//  Feed N rows into a scratch buffer, Drain them back; verb, ts and
//  the re-serialized URI must match.
static ok64 T_stream(void) {
    sane(1);
    a_pad(u8, buf, 1024);

    saved_uri s1 = {}, s2 = {};
    call(parse_uri_lit, &s1, "//host/path?heads/main");
    call(parse_uri_lit, &s2, "?staging/0123");

    {
        ulogrec r = rec_of(1000, verb_of("get"), &s1);
        call(ULOGu8sFeed, u8bIdle(buf), &r);
    }
    {
        ulogrec r = rec_of(1001, verb_of("put"), &s2);
        call(ULOGu8sFeed, u8bIdle(buf), &r);
    }

    a_dup(u8c, data, u8bData(buf));
    u8cs scan = {data[0], data[1]};

    ulogrec g = {};
    call(ULOGu8sDrain, scan, &g);
    want(g.ts == 1000 && g.verb == verb_of("get"));
    want(uri_serializes_to(&g.uri, "//host/path?heads/main"));

    call(ULOGu8sDrain, scan, &g);
    want(g.ts == 1001 && g.verb == verb_of("put"));
    want(uri_serializes_to(&g.uri, "?staging/0123"));

    want(u8csEmpty(scan) == YES);
    want(ULOGu8sDrain(scan, &g) == NODATA);

    //  Partial row (no '\n') → NODATA, scan unchanged.
    u8c partial[] = "1000\tget\thttp://x";
    u8cs pscan = {partial, partial + sizeof(partial) - 1};
    u8cp pstart = pscan[0];
    want(ULOGu8sDrain(pscan, &g) == NODATA);
    want(pscan[0] == pstart);
    done;
}

//  Multi-space / multi-tab separators must parse the same as a single
//  tab.  Trailing whitespace after the URI is not part of the spec
//  (URIs terminate at '\n') so we don't test that case.
static ok64 T_whitespace(void) {
    sane(1);
    //  Build a canonical single-tab row via Feed, then synthesize a
    //  sloppy variant with wide whitespace and confirm Drain parses
    //  both the same way.
    a_pad(u8, canon, 256);
    saved_uri su = {};
    call(parse_uri_lit, &su, "//host/path");
    {
        ulogrec r = rec_of(1000, verb_of("post"), &su);
        call(ULOGu8sFeed, u8bIdle(canon), &r);
    }

    u8c wide_row[] = "Fd  \t post \t\t //host/path\n";
    u8cs wide_scan = {wide_row, wide_row + sizeof(wide_row) - 1};

    ulogrec g = {};
    call(ULOGu8sDrain, wide_scan, &g);
    want(g.ts == 1000);
    want(g.verb == verb_of("post"));
    want(uri_serializes_to(&g.uri, "//host/path"));
    done;
}

// --- latest-per-key helpers & tests ----------------------------------

typedef struct {
    u32    n;
    ron60  ts[16];
    ron60  verb[16];
    char   uri[16][128];
} each_collect;

static ok64 each_cb(ulogreccp rec, void *ctx) {
    sane(rec && ctx);
    each_collect *c = (each_collect *)ctx;
    if (c->n >= 16) fail(FAIL);
    c->ts[c->n]   = rec->ts;
    c->verb[c->n] = rec->verb;
    a_pad(u8, buf, 128);
    uri u = rec->uri;
    call(URIutf8Feed, u8bIdle(buf), &u);
    size_t L = u8bDataLen(buf);
    if (L >= sizeof(c->uri[0])) L = sizeof(c->uri[0]) - 1;
    memcpy(c->uri[c->n], u8bDataHead(buf), L);
    c->uri[c->n][L] = 0;
    c->n++;
    done;
}

static ok64 T_each_latest(void) {
    sane(1);
    rm_tmp("/tmp/ulog-el.log");
    LOGPATH(path, "/tmp/ulog-el.log");

    u8bp  l_data = NULL;
    wh128bp l_idx  = NULL;
    call(ULOGOpen, &l_data, &l_idx, path);

    //  Two keys, three revisions: main@1, feat@2, main@3, main@4, feat@5.
    //  Plus one `get` row to verify verb filter (`set` only).
    saved_uri m1 = {}, f2 = {}, m3 = {}, m4 = {}, f5 = {}, g6 = {};
    call(parse_uri_lit, &m1, "?heads/main#?1111");
    call(parse_uri_lit, &f2, "?heads/feat#?aaaa");
    call(parse_uri_lit, &m3, "?heads/main#?3333");
    call(parse_uri_lit, &m4, "?heads/main#?4444");
    call(parse_uri_lit, &f5, "?heads/feat#?bbbb");
    call(parse_uri_lit, &g6, "?heads/main#?6666");

    ron60 set_v = verb_of("set"), get_v = verb_of("get");
    {
        ulogrec r = rec_of(1, set_v, &m1); call(ULOGAppendAt, l_data, l_idx, &r);
    } {
        ulogrec r = rec_of(2, set_v, &f2); call(ULOGAppendAt, l_data, l_idx, &r);
    } {
        ulogrec r = rec_of(3, set_v, &m3); call(ULOGAppendAt, l_data, l_idx, &r);
    } {
        ulogrec r = rec_of(4, set_v, &m4); call(ULOGAppendAt, l_data, l_idx, &r);
    } {
        ulogrec r = rec_of(5, set_v, &f5); call(ULOGAppendAt, l_data, l_idx, &r);
    } {
        ulogrec r = rec_of(6, get_v, &g6); call(ULOGAppendAt, l_data, l_idx, &r);
    }

    //  Filter = `set`: expect (feat@5) then (main@4) — reverse order,
    //  one row per key, get_v row skipped entirely.
    each_collect c = {};
    call(ULOGeachLatest, l_data, l_idx, set_v, each_cb, &c);
    want(c.n == 2);
    want(c.ts[0] == 5);
    want(strcmp(c.uri[0], "?heads/feat#?bbbb") == 0);
    want(c.ts[1] == 4);
    want(strcmp(c.uri[1], "?heads/main#?4444") == 0);

    //  No filter: the `get` row appears too — still its own (verb, key)
    //  so it dedups independently of set's rows.
    each_collect c_all = {};
    call(ULOGeachLatest, l_data, l_idx, 0, each_cb, &c_all);
    want(c_all.n == 3);        // get/main@6, set/feat@5, set/main@4
    want(c_all.verb[0] == get_v);
    want(c_all.ts[0] == 6);
    want(c_all.verb[1] == set_v);
    want(c_all.ts[1] == 5);
    want(c_all.verb[2] == set_v);
    want(c_all.ts[2] == 4);

    call(ULOGClose, l_data, &l_idx, YES);
    rm_tmp("/tmp/ulog-el.log");
    done;
}

static ok64 T_compact_latest(void) {
    sane(1);
    rm_tmp("/tmp/ulog-cl.log");
    LOGPATH(path, "/tmp/ulog-cl.log");

    u8bp  l_data = NULL;
    wh128bp l_idx  = NULL;
    call(ULOGOpen, &l_data, &l_idx, path);

    saved_uri s[5] = {};
    call(parse_uri_lit, &s[0], "?heads/main#?1111");
    call(parse_uri_lit, &s[1], "?heads/feat#?aaaa");
    call(parse_uri_lit, &s[2], "?heads/main#?2222");  // shadowed
    call(parse_uri_lit, &s[3], "?heads/feat#?bbbb");  // shadowed later
    call(parse_uri_lit, &s[4], "?heads/feat#?cccc");

    ron60 set_v = verb_of("set");
    for (u32 i = 0; i < 5; i++) {
        ulogrec r = rec_of(10 + i, set_v, &s[i]);
        call(ULOGAppendAt, l_data, l_idx, &r);
    }
    want(ULOGCount(l_idx) == 5);

    call(ULOGCompactLatest, &l_data, &l_idx, path, set_v);
    want(ULOGCount(l_idx) == 2);

    //  Survivors in ts order: main@12, feat@14.
    ulogrec g = {};
    call(ULOGRow, l_data, l_idx, 0, &g);
    want(g.ts == 12);
    want(uri_serializes_to(&g.uri, "?heads/main#?2222"));
    call(ULOGRow, l_data, l_idx, 1, &g);
    want(g.ts == 14);
    want(uri_serializes_to(&g.uri, "?heads/feat#?cccc"));

    call(ULOGClose, l_data, &l_idx, YES);
    rm_tmp("/tmp/ulog-cl.log");
    rm_tmp("/tmp/ulog-cl.log.tmp");
    done;
}

//  Regression: aborted RW open leaves a sparse, page-sized file with
//  no real content (FILEBookCreate ftruncate's to a page before any
//  row gets written; if the writer crashes / is killed before
//  ULOGAppendAt, the file persists in this state).  A subsequent RO
//  open via ULOGOpenRO must NOT crash on the first byte read of a
//  sparse hole — it must surface as an empty log so callers fall
//  through to the "no rows" branch (e.g., SNIFFAtTailOf returning
//  SNIFFATNONE for a fresh worktree).
static ok64 T_aborted_leftover(void) {
    sane(1);
    char const *home = getenv("HOME");
    if (!home) home = "/tmp";
    char tpath[512];
    snprintf(tpath, sizeof(tpath), "%s/tmp/ulog-al.log", home);
    {
        char mkd[512];
        snprintf(mkd, sizeof(mkd), "mkdir -p %s/tmp", home);
        int _ = system(mkd); (void)_;
    }
    rm_tmp(tpath);
    a_pad(u8, path_buf, FILE_PATH_MAX_LEN);
    {
        size_t L = strlen(tpath);
        u8cs s = {(u8cp)tpath, (u8cp)tpath + L};
        u8bFeed(path_buf, s);
        u8bFeed1(path_buf, 0);
    }
    a_dup(u8c, path, u8bData(path_buf));

    //  Mirror FILEBookCreate's body without writing any content:
    //  create the file, ftruncate it to one page, close.  This is
    //  exactly the on-disk state an aborted RW open leaves behind.
    //  Hardcoded 4096 (vs sysconf) because FILESysPage isn't in the
    //  public header and any sane page size triggers the same path.
    int fd = FILE_CLOSED;
    call(FILECreate, &fd, path);
    call(FILEResize, &fd, 4096);
    call(FILEClose, &fd);

    //  ULOGOpenRO must succeed and surface zero rows — the previous
    //  symptom was SIGBUS on *scan[0] inside ulog_rebuild_idx.
    u8bp  l_data = NULL;
    wh128bp l_idx  = NULL;
    call(ULOGOpenRO, &l_data, &l_idx, path);
    want(ULOGCount(l_idx) == 0);
    call(ULOGClose, l_data, &l_idx, NO);

    rm_tmp(tpath);
    done;
}

// --- Sidecar tests ---------------------------------------------------

//  Open writes the sidecar; reopen finds it fresh and reuses it
//  (no rebuild from log).  Verified by checking the sidecar file
//  exists on disk and the verb-hash field round-trips through it.
static ok64 T_sidecar_reuse(void) {
    sane(1);
    rm_tmp("/tmp/ulog-sc.log");
    rm_tmp("/tmp/.ulog-sc.log.idx");
    LOGPATH(path, "/tmp/ulog-sc.log");

    saved_uri s = {};
    call(parse_uri_lit, &s, "?heads/main");

    {   //  Session 1: create + append.
        u8bp    l_data = NULL;
        wh128bp l_idx  = NULL;
        call(ULOGOpen, &l_data, &l_idx, path);
        ulogrec r = rec_of(1000, verb_of("get"), &s);
        call(ULOGAppendAt, l_data, l_idx, &r);
        call(ULOGClose, l_data, &l_idx, YES);
    }

    //  Sidecar must exist on disk now.
    {
        struct stat st = {};
        want(stat("/tmp/.ulog-sc.log.idx", &st) == 0);
        //  1 row + 1 sentinel = 2 entries × 16 B.
        want((size_t)st.st_size == 2 * 16);
    }

    {   //  Session 2: reopen, verify row data + verb-hash field.
        u8bp    l_data = NULL;
        wh128bp l_idx  = NULL;
        call(ULOGOpen, &l_data, &l_idx, path);
        want(ULOGCount(l_idx) == 1);

        //  Verb prefilter byte-equal: index entry 0 has the hash of
        //  `get`; ULOGFindVerb must locate the row without scanning
        //  past it.
        ulogrec g = {};
        call(ULOGFindVerb, l_data, l_idx, verb_of("get"), &g);
        want(g.ts == 1000);

        //  A different verb's hash must NOT match — ULOGFindVerb
        //  returns ULOGNONE without dereferencing.
        want(ULOGFindVerb(l_data, l_idx, verb_of("put"), &g) == ULOGNONE);

        call(ULOGClose, l_data, &l_idx, YES);
    }

    rm_tmp("/tmp/ulog-sc.log");
    rm_tmp("/tmp/.ulog-sc.log.idx");
    done;
}

//  A stale sidecar (sentinel offset disagrees with actual log size)
//  must be rebuilt from the log on the next Open.  Simulated by
//  overwriting the sidecar with a single bogus sentinel.
static ok64 T_sidecar_stale_rebuild(void) {
    sane(1);
    rm_tmp("/tmp/ulog-st.log");
    rm_tmp("/tmp/.ulog-st.log.idx");
    LOGPATH(path, "/tmp/ulog-st.log");

    saved_uri s = {};
    call(parse_uri_lit, &s, "?heads/main");

    //  Append three rows, close (writes sidecar).
    {
        u8bp    l_data = NULL;
        wh128bp l_idx  = NULL;
        call(ULOGOpen, &l_data, &l_idx, path);
        for (u32 i = 0; i < 3; i++) {
            ulogrec r = rec_of((ron60)(100 + i), verb_of("get"), &s);
            call(ULOGAppendAt, l_data, l_idx, &r);
        }
        call(ULOGClose, l_data, &l_idx, YES);
    }

    //  Corrupt the sidecar: rewrite as a single sentinel claiming
    //  size=0.  Reopen must detect the mismatch (log file size != 0)
    //  and rebuild — surfacing all 3 rows.
    {
        int fd = open("/tmp/.ulog-st.log.idx", O_RDWR | O_TRUNC);
        if (fd < 0) fail(TESTFAIL);
        u8 sentinel[16] = {};   // ts=0, val=0 → off=0
        if (write(fd, sentinel, 16) != 16) { close(fd); fail(TESTFAIL); }
        close(fd);
    }

    {
        u8bp    l_data = NULL;
        wh128bp l_idx  = NULL;
        call(ULOGOpen, &l_data, &l_idx, path);
        want(ULOGCount(l_idx) == 3);    // rebuilt
        ulogrec g = {};
        call(ULOGTail, l_data, l_idx, &g);
        want(g.ts == 102);
        call(ULOGClose, l_data, &l_idx, YES);
    }

    rm_tmp("/tmp/ulog-st.log");
    rm_tmp("/tmp/.ulog-st.log.idx");
    done;
}

//  Sidecar fast-path: when the log is unchanged (same size AND same
//  mtime), Open must trust the on-disk sidecar verbatim — NO rebuild
//  scan.  Verified by poking a bogus verb-hash into a row entry
//  between close and reopen; the bogus byte survives iff the rebuild
//  was skipped (a rebuild would recompute the verb hash from the log).
static ok64 T_sidecar_fast_path(void) {
    sane(1);
    rm_tmp("/tmp/ulog-fp.log");
    rm_tmp("/tmp/.ulog-fp.log.idx");
    LOGPATH(path, "/tmp/ulog-fp.log");

    saved_uri s = {};
    call(parse_uri_lit, &s, "?heads/main");

    {   //  Append two rows, close.
        u8bp    l_data = NULL;
        wh128bp l_idx  = NULL;
        call(ULOGOpen, &l_data, &l_idx, path);
        for (u32 i = 0; i < 2; i++) {
            ulogrec r = rec_of((ron60)(200 + i), verb_of("get"), &s);
            call(ULOGAppendAt, l_data, l_idx, &r);
        }
        call(ULOGClose, l_data, &l_idx, YES);
    }

    //  Poke a sentinel verb-hash value into the FIRST row's val (the
    //  20-bit id field of wh64).  Real `get` hash is whatever
    //  ulogVerbHash(verb_of("get")) returns; we slam a known different
    //  20-bit pattern into the bits and check it survives.
    u32 marker_hash = 0x12345;
    {
        int fd = open("/tmp/.ulog-fp.log.idx", O_RDWR);
        if (fd < 0) fail(TESTFAIL);
        wh128 e = {};
        if (pread(fd, &e, sizeof(e), 0) != (ssize_t)sizeof(e)) {
            close(fd); fail(TESTFAIL);
        }
        //  Replace the 20-bit id field (verb hash) in val.
        u64 v = e.val;
        v &= ~(WHIFF_ID_MASK << WHIFF_ID_SHIFT);
        v |=  ((u64)marker_hash & WHIFF_ID_MASK) << WHIFF_ID_SHIFT;
        e.val = v;
        if (pwrite(fd, &e, sizeof(e), 0) != (ssize_t)sizeof(e)) {
            close(fd); fail(TESTFAIL);
        }
        close(fd);
    }

    //  Reopen: if the fast path triggers, our marker is preserved;
    //  if a rebuild ran, the real `get`-hash overwrites it.
    {
        u8bp    l_data = NULL;
        wh128bp l_idx  = NULL;
        call(ULOGOpen, &l_data, &l_idx, path);
        want(ULOGCount(l_idx) == 2);
        wh128 const *a = (wh128 const *)l_idx[0];
        want(wh64Id(a[0].val) == marker_hash);
        call(ULOGClose, l_data, &l_idx, YES);
    }

    rm_tmp("/tmp/ulog-fp.log");
    rm_tmp("/tmp/.ulog-fp.log.idx");
    done;
}

//  RO open with no sidecar present: must succeed via the anonymous
//  mmap fallback and surface every row from the log.  The idx slot
//  must NOT register as booked (FILEIsBooked == NO).
static ok64 T_sidecar_ro_fallback(void) {
    sane(1);
    rm_tmp("/tmp/ulog-rof.log");
    rm_tmp("/tmp/.ulog-rof.log.idx");
    LOGPATH(path, "/tmp/ulog-rof.log");

    saved_uri s = {};
    call(parse_uri_lit, &s, "?heads/main");

    //  RW: append 2 rows, close, then unlink the sidecar to simulate
    //  RO mount / vanished sidecar.
    {
        u8bp    l_data = NULL;
        wh128bp l_idx  = NULL;
        call(ULOGOpen, &l_data, &l_idx, path);
        ulogrec r1 = rec_of(10, verb_of("get"), &s);
        ulogrec r2 = rec_of(20, verb_of("put"), &s);
        call(ULOGAppendAt, l_data, l_idx, &r1);
        call(ULOGAppendAt, l_data, l_idx, &r2);
        call(ULOGClose, l_data, &l_idx, YES);
    }
    rm_tmp("/tmp/.ulog-rof.log.idx");

    //  RO open: sidecar absent → quiet anonymous-mmap fallback.
    {
        u8bp    l_data = NULL;
        wh128bp l_idx  = NULL;
        call(ULOGOpenRO, &l_data, &l_idx, path);
        want(ULOGCount(l_idx) == 2);
        want(FILEIsBooked((u8bp)l_idx) == NO);   // anonymous fallback

        ulogrec g = {};
        call(ULOGRow, l_data, l_idx, 0, &g);
        want(g.ts == 10);
        call(ULOGRow, l_data, l_idx, 1, &g);
        want(g.ts == 20);

        call(ULOGClose, l_data, &l_idx, NO);
    }

    rm_tmp("/tmp/ulog-rof.log");
    done;
}

//  Verb prefilter correctness: ULOGFindVerb must reject rows whose
//  20-bit verb hash doesn't match before parsing them.  Insert many
//  rows of one verb and one row of another; FindVerb on the second
//  must locate it correctly without touching the first verb's rows.
static ok64 T_verb_prefilter(void) {
    sane(1);
    rm_tmp("/tmp/ulog-vf.log");
    rm_tmp("/tmp/.ulog-vf.log.idx");
    LOGPATH(path, "/tmp/ulog-vf.log");

    u8bp    l_data = NULL;
    wh128bp l_idx  = NULL;
    call(ULOGOpen, &l_data, &l_idx, path);

    saved_uri s = {};
    call(parse_uri_lit, &s, "?heads/main");

    //  100 `get` rows then one `delete` row.
    for (u32 i = 0; i < 100; i++) {
        ulogrec r = rec_of((ron60)(i + 1), verb_of("get"), &s);
        call(ULOGAppendAt, l_data, l_idx, &r);
    }
    {
        ulogrec r = rec_of(200, verb_of("delete"), &s);
        call(ULOGAppendAt, l_data, l_idx, &r);
    }

    ulogrec g = {};
    call(ULOGFindVerb, l_data, l_idx, verb_of("delete"), &g);
    want(g.ts == 200);
    want(g.verb == verb_of("delete"));

    //  An absent verb still returns ULOGNONE.
    want(ULOGFindVerb(l_data, l_idx, verb_of("patch"), &g) == ULOGNONE);

    call(ULOGClose, l_data, &l_idx, YES);
    rm_tmp("/tmp/ulog-vf.log");
    rm_tmp("/tmp/.ulog-vf.log.idx");
    done;
}

ok64 ULOGtest(void) {
    sane(1);
    fprintf(stderr, "T_roundtrip...\n");     call(T_roundtrip);
    fprintf(stderr, "T_persist...\n");       call(T_persist);
    fprintf(stderr, "T_seek...\n");          call(T_seek);
    fprintf(stderr, "T_clock...\n");         call(T_clock);
    fprintf(stderr, "T_findverb...\n");      call(T_findverb);
    fprintf(stderr, "T_truncate...\n");      call(T_truncate);
    fprintf(stderr, "T_stream...\n");        call(T_stream);
    fprintf(stderr, "T_whitespace...\n");    call(T_whitespace);
    fprintf(stderr, "T_each_latest...\n");   call(T_each_latest);
    fprintf(stderr, "T_compact_latest...\n");call(T_compact_latest);
    fprintf(stderr, "T_aborted_leftover...\n"); call(T_aborted_leftover);
    fprintf(stderr, "T_sidecar_reuse...\n");        call(T_sidecar_reuse);
    fprintf(stderr, "T_sidecar_stale_rebuild...\n");call(T_sidecar_stale_rebuild);
    fprintf(stderr, "T_sidecar_fast_path...\n");    call(T_sidecar_fast_path);
    fprintf(stderr, "T_sidecar_ro_fallback...\n");  call(T_sidecar_ro_fallback);
    fprintf(stderr, "T_verb_prefilter...\n");       call(T_verb_prefilter);
    done;
}

TEST(ULOGtest);
