//  WIREClassify table tests.  Each case feeds one pkt-line payload
//  to the classifier under a chosen role; checks event kind, sha,
//  and slice contents.  Malformed-input cases verify rejection.

#include "keeper/WIRE.h"

#include <string.h>

#include "abc/PRO.h"
#include "abc/TEST.h"

static u8c const HEX[] = "0123456789abcdef";

//  Render 20 bytes as 40 lowercase hex chars into out.
static void sha_hex(sha1 const *s, u8 out[40]) {
    for (int i = 0; i < 20; i++) {
        out[i*2  ] = HEX[(s->data[i] >> 4) & 0xf];
        out[i*2+1] = HEX[ s->data[i]       & 0xf];
    }
}

//  20-byte sha1 with byte i = (u8)(seed + i).
static sha1 sha_seed(u8 seed) {
    sha1 s = {};
    for (int i = 0; i < 20; i++) s.data[i] = (u8)(seed + i);
    return s;
}

//  classify a (p, n) byte range — wrapper that builds the stack slice.
static ok64 classify(u8 const *p, u64 n, wire_role role, wire_evt *out) {
    u8cs sl = { (u8c *)p, (u8c *)p + n };
    return WIREClassify(sl, role, out);
}

// ---- happy paths ----

ok64 WIREtest_want() {
    sane(1);
    sha1 want = sha_seed(0x10);
    u8 hex[40]; sha_hex(&want, hex);

    //  "want " + sha + " ofs-delta thin-pack"
    u8 buf[5 + 40 + 1 + 19];
    memcpy(buf, "want ", 5);
    memcpy(buf + 5, hex, 40);
    memcpy(buf + 45, " ofs-delta thin-pack", 20);

    wire_evt ev = {};
    call(classify, buf, sizeof(buf), WIRE_UPLOAD, &ev);

    same(ev.kind, WIRE_WANT);
    want(memcmp(&ev.sha, &want, sizeof(sha1)) == 0);
    want(u8csLen(ev.caps) == 19);
    want(memcmp(ev.caps[0], "ofs-delta thin-pack", 19) == 0);
    done;
}

ok64 WIREtest_have() {
    sane(1);
    sha1 h = sha_seed(0x20);
    u8 hex[40]; sha_hex(&h, hex);
    u8 buf[5 + 40];
    memcpy(buf, "have ", 5);
    memcpy(buf + 5, hex, 40);

    wire_evt ev = {};
    call(classify, buf, sizeof(buf), WIRE_UPLOAD, &ev);

    same(ev.kind, WIRE_HAVE);
    want(memcmp(&ev.sha, &h, sizeof(sha1)) == 0);
    done;
}

ok64 WIREtest_done() {
    sane(1);
    wire_evt ev = {};
    call(classify, (u8 const*)"done", 4, WIRE_UPLOAD, &ev);
    same(ev.kind, WIRE_DONE);
    done;
}

ok64 WIREtest_shallow() {
    sane(1);
    sha1 s = sha_seed(0x30);
    u8 hex[40]; sha_hex(&s, hex);
    u8 buf[8 + 40];
    memcpy(buf, "shallow ", 8);
    memcpy(buf + 8, hex, 40);

    wire_evt ev = {};
    call(classify, buf, sizeof(buf), WIRE_UPLOAD, &ev);
    same(ev.kind, WIRE_SHALLOW);
    want(memcmp(&ev.sha, &s, sizeof(sha1)) == 0);
    done;
}

ok64 WIREtest_ref_advert() {
    sane(1);
    sha1 r = sha_seed(0x40);
    u8 hex[40]; sha_hex(&r, hex);

    //  "<sha> SP refs/heads/main\0multi_ack ofs-delta agent=keeper/1"
    char const *name = "refs/heads/main";
    char const *caps = "multi_ack ofs-delta agent=keeper/1";
    u64 nl = strlen(name), cl = strlen(caps);
    u8 buf[40 + 1 + 64 + 1 + 64];
    u64 i = 0;
    memcpy(buf + i, hex, 40); i += 40;
    buf[i++] = ' ';
    memcpy(buf + i, name, nl); i += nl;
    buf[i++] = '\0';
    memcpy(buf + i, caps, cl); i += cl;

    wire_evt ev = {};
    call(classify, buf, i, WIRE_ADVERT, &ev);

    same(ev.kind, WIRE_REF);
    want(memcmp(&ev.sha, &r, sizeof(sha1)) == 0);
    want((u64)u8csLen(ev.name) == nl &&
         memcmp(ev.name[0], name, nl) == 0);
    want((u64)u8csLen(ev.caps) == cl &&
         memcmp(ev.caps[0], caps, cl) == 0);
    done;
}

ok64 WIREtest_ref_advert_no_caps() {
    sane(1);
    sha1 r = sha_seed(0x50);
    u8 hex[40]; sha_hex(&r, hex);
    char const *name = "refs/tags/v1.2.3";
    u64 nl = strlen(name);
    u8 buf[40 + 1 + 64];
    u64 i = 0;
    memcpy(buf + i, hex, 40); i += 40;
    buf[i++] = ' ';
    memcpy(buf + i, name, nl); i += nl;

    wire_evt ev = {};
    call(classify, buf, i, WIRE_ADVERT, &ev);

    same(ev.kind, WIRE_REF);
    want((u64)u8csLen(ev.name) == nl);
    want(u8csEmpty(ev.caps));
    done;
}

ok64 WIREtest_update() {
    sane(1);
    sha1 o = sha_seed(0x60), n = sha_seed(0x70);
    u8 oh[40], nh[40];
    sha_hex(&o, oh); sha_hex(&n, nh);
    char const *name = "refs/heads/feature";
    char const *caps = "report-status";
    u64 nl = strlen(name), cl = strlen(caps);
    u8 buf[40 + 1 + 40 + 1 + 64 + 1 + 64];
    u64 i = 0;
    memcpy(buf + i, oh, 40); i += 40;
    buf[i++] = ' ';
    memcpy(buf + i, nh, 40); i += 40;
    buf[i++] = ' ';
    memcpy(buf + i, name, nl); i += nl;
    buf[i++] = '\0';
    memcpy(buf + i, caps, cl); i += cl;

    wire_evt ev = {};
    call(classify, buf, i, WIRE_RECEIVE, &ev);

    same(ev.kind, WIRE_UPDATE);
    want(memcmp(&ev.old_sha, &o, sizeof(sha1)) == 0);
    want(memcmp(&ev.sha,     &n, sizeof(sha1)) == 0);
    want((u64)u8csLen(ev.name) == nl);
    want((u64)u8csLen(ev.caps) == cl);
    done;
}

ok64 WIREtest_nak() {
    sane(1);
    wire_evt ev = {};
    call(classify, (u8 const*)"NAK", 3, WIRE_CLIENT, &ev);
    same(ev.kind, WIRE_NAK);
    done;
}

ok64 WIREtest_ack_plain() {
    sane(1);
    sha1 a = sha_seed(0x80);
    u8 hex[40]; sha_hex(&a, hex);
    u8 buf[4 + 40];
    memcpy(buf, "ACK ", 4);
    memcpy(buf + 4, hex, 40);

    wire_evt ev = {};
    call(classify, buf, sizeof(buf), WIRE_CLIENT, &ev);
    same(ev.kind, WIRE_ACK);
    want(memcmp(&ev.sha, &a, sizeof(sha1)) == 0);
    done;
}

ok64 WIREtest_ack_status() {
    sane(1);
    sha1 a = sha_seed(0x90);
    u8 hex[40]; sha_hex(&a, hex);
    u8 buf[4 + 40 + 6];
    memcpy(buf,      "ACK ",   4);
    memcpy(buf + 4,  hex,      40);
    memcpy(buf + 44, " ready", 6);

    wire_evt ev = {};
    call(classify, buf, sizeof(buf), WIRE_CLIENT, &ev);
    same(ev.kind, WIRE_ACK);
    want(memcmp(&ev.sha, &a, sizeof(sha1)) == 0);
    done;
}

// ---- malformed input ----

static ok64 expect_bad(u8 const *p, u64 n, wire_role role) {
    sane(1);
    wire_evt ev = {};
    ok64 o = classify(p, n, role, &ev);
    if (o == OK) {
        fprintf(stderr, "WIRE bad: accepted: ");
        fwrite(p, 1, n, stderr);
        fprintf(stderr, "\n");
        fail(TESTFAIL);
    }
    done;
}

ok64 WIREtest_bad() {
    sane(1);
    //  Truncated want.
    call(expect_bad, (u8 const*)"want", 4, WIRE_UPLOAD);
    //  Want with non-hex.
    call(expect_bad,
        (u8 const*)"want ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
        5+40, WIRE_UPLOAD);
    //  Want sha too short.
    call(expect_bad,
        (u8 const*)"want 0123456789abcdef",
        5+16, WIRE_UPLOAD);
    //  Have line under upload role with extra junk.
    call(expect_bad,
        (u8 const*)"have 0000000000000000000000000000000000000000XX",
        5+40+2, WIRE_UPLOAD);
    //  Wrong role: want line under receive role.
    {
        sha1 s = sha_seed(0xa0);
        u8 hex[40]; sha_hex(&s, hex);
        u8 buf[5 + 40];
        memcpy(buf, "want ", 5);
        memcpy(buf + 5, hex, 40);
        call(expect_bad, buf, sizeof(buf), WIRE_RECEIVE);
    }
    //  Update under upload role.
    {
        sha1 a = sha_seed(0xb0), b = sha_seed(0xc0);
        u8 ha[40], hb[40]; sha_hex(&a, ha); sha_hex(&b, hb);
        u8 buf[40+1+40+1+4];
        u64 i = 0;
        memcpy(buf+i, ha, 40); i += 40; buf[i++] = ' ';
        memcpy(buf+i, hb, 40); i += 40; buf[i++] = ' ';
        memcpy(buf+i, "main", 4); i += 4;
        call(expect_bad, buf, i, WIRE_UPLOAD);
    }
    //  Empty payload.
    call(expect_bad, (u8 const*)"", 0, WIRE_UPLOAD);
    //  Junk.
    call(expect_bad, (u8 const*)"hello world", 11, WIRE_UPLOAD);
    done;
}

#define RUN(t) do { \
    fprintf(stderr, "  %s ... ", #t); \
    ok64 _o = t(); \
    fprintf(stderr, "%s\n", _o == OK ? "OK" : ok64str(_o)); \
    if (_o != OK) return _o; \
} while (0)

ok64 maintest() {
    sane(1);
    RUN(WIREtest_want);
    RUN(WIREtest_have);
    RUN(WIREtest_done);
    RUN(WIREtest_shallow);
    RUN(WIREtest_ref_advert);
    RUN(WIREtest_ref_advert_no_caps);
    RUN(WIREtest_update);
    RUN(WIREtest_nak);
    RUN(WIREtest_ack_plain);
    RUN(WIREtest_ack_status);
    RUN(WIREtest_bad);
    done;
}

TEST(maintest)
