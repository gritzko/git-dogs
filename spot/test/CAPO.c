#include "spot/CAPOi.h"
#include "spot/SPOT.h"

#include <string.h>

#include "abc/FILE.h"
#include "abc/PRO.h"
#include "abc/SORT.h"
#include "abc/TEST.h"

//  BOXu64 in hash mode — must match CAPO.c so the SPOT singleton's
//  dirty descriptor (set up by box_test_open below via this TU's
//  BOXu64Open) and the CAPOEmit hot path in CAPO.c agree on what
//  dirty[1] means.  HASHu64 must be co-instantiated for Feed1's
//  HASH Put.  PRO.h is required for sane()/done.
#define X(M, name) M##u64##name
#include "abc/HASHx.h"
#define BOX_DIRTY_HASH 1
#define BOX_DIRTY_BYTES (1UL << 18)
#include "abc/BOXx.h"
#undef X

// --- Test 0: wh64Pack/Type/Id/Off roundtrip on a TRI entry ---
//   New layout: [off:40 | id:20 | type:4]
//   For TRI:  off = 18-bit packed RON64 trigram
//             id  = fn_hash20 (basename RAP truncated)
//             type= SPOT_TRI
ok64 CAPO0() {
    sane(1);
    a_cstr(tri, "abc");
    u64 off40 = CAPOTri40(tri);
    want(off40 != 0);
    testeq(off40 & ~WHIFF_OFF_MASK, (u64)0);

    u32 fn_hash = 0xdeadeULL & WHIFF_ID_MASK;
    u64 e = wh64Pack(SPOT_TRI, fn_hash, off40);
    testeq(wh64Type(e), (u8)SPOT_TRI);
    testeq(wh64Id(e),   fn_hash);
    testeq(wh64Off(e),  off40);

    // Same input -> same output
    u64 e2 = wh64Pack(SPOT_TRI, fn_hash, off40);
    testeq(e, e2);

    // Different trigram -> different off
    a_cstr(tri2, "xyz");
    want(CAPOTri40(tri2) != off40);

    done;
}

// --- Test 1: TRI entries with same off (trigram) sort by (id, type) ---
//   Same trigram, different basenames → same off, different id (fn_hash).
ok64 CAPO1() {
    sane(1);
    a_cstr(tri, "foo");
    u64 off40 = CAPOTri40(tri);
    a_cstr(p1, "main.c");
    a_cstr(p2, "other.c");
    u32 r1 = CAPOFnRap20(p1);
    u32 r2 = CAPOFnRap20(p2);

    u64 e1 = wh64Pack(SPOT_TRI, r1, off40);
    u64 e2 = wh64Pack(SPOT_TRI, r2, off40);
    testeq(wh64Off(e1),  wh64Off(e2));
    testeq(wh64Type(e1), wh64Type(e2));
    want(wh64Id(e1) != wh64Id(e2));

    done;
}

//  Helper: open a fresh BOX for the SPOT singleton over `bytes`
//  bytes of mmap'd scratch.  Tests that drive CAPOEmit through this
//  shim so the post-Phase-4 hash-set → BOX swap stays observable
//  via the same scan-by-zero pattern (BOX writes leave non-zero
//  entries in the chunk's data prefix, sentinel zeros at the tail).
static ok64 box_test_open(size_t bytes) {
    sane(1);
    call(u8bMap, SPOT.entries_mem, bytes);
    ((u64s **)SPOT.entries_box)[0] = SPOT.box_slots;
    ((u64s **)SPOT.entries_box)[1] = SPOT.box_slots;
    ((u64s **)SPOT.entries_box)[2] = SPOT.box_slots;
    ((u64s **)SPOT.entries_box)[3] = SPOT.box_slots + 16;
    u8s range = {u8bDataHead(SPOT.entries_mem),
                 u8bDataHead(SPOT.entries_mem) + bytes};
    call(BOXu64Open, SPOT.entries_box, range);
    done;
}

static void box_test_close(void) {
    if (!BNULL(SPOT.entries_mem)) u8bUnMap(SPOT.entries_mem);
}

// --- Test 2: CAPOIndexFile extracts trigrams keyed by basename hash ---
ok64 CAPO2() {
    sane(1);
    const char *src = "int foo(int x) { return x + 1; }";
    u8csc source = {(u8cp)src, (u8cp)src + strlen(src)};
    u8cs ext = $u8str(".c");
    a_cstr(name, "test.c");

    call(box_test_open, (8UL << 20));

    call(CAPOIndexFile, source, ext, name);

    u32 fn_hash = CAPOFnRap20(name);
    a_cstr(tri_foo, "foo");
    a_cstr(tri_int, "int");
    u64 off_foo = CAPOTri40(tri_foo);
    u64 off_int = CAPOTri40(tri_int);

    //  BOX writes leave non-zero entries in each chunk's data prefix
    //  with zero-filled tails — same scan-by-zero pattern as the old
    //  hash-set scratch.
    size_t nentries = 0;
    b8 found_foo = NO, found_int = NO;
    u64 *p = (u64 *)u8bDataHead(SPOT.entries_mem);
    u64 *e = (u64 *)(u8bDataHead(SPOT.entries_mem) + (8UL << 20));
    for (; p < e; p++) {
        if (*p == 0) continue;
        nentries++;
        testeq(wh64Id(*p), fn_hash);
        if (wh64Type(*p) != SPOT_TRI) continue;
        if (wh64Off(*p) == off_foo) found_foo = YES;
        if (wh64Off(*p) == off_int) found_int = YES;
    }
    want(nentries > 0);
    want(found_foo == YES);
    want(found_int == YES);

    box_test_close();
    done;
}

// --- Test 3: Sort + HIT dedup ---
ok64 CAPO3() {
    sane(1);
    a_cstr(tri, "foo");
    u64 off40 = CAPOTri40(tri);
    a_cstr(p1, "a.c");
    a_cstr(p2, "b.c");
    u64 e1 = wh64Pack(SPOT_TRI, CAPOFnRap20(p1), off40);
    u64 e2 = wh64Pack(SPOT_TRI, CAPOFnRap20(p2), off40);
    u64 e1dup = e1;

    u64 arr[] = {e2, e1, e1dup};
    u64s data = {arr, arr + 3};
    u64sSort(data);

    want(arr[0] <= arr[1]);
    want(arr[1] <= arr[2]);

    u64cs runs[1] = {{(u64cp)arr, (u64cp)arr + 3}};
    u64css iter = {runs, runs + 1};
    HITu64Start(iter);

    u64 out[3];
    u64p op = out;
    HITu64Merge(iter, &op);

    testeq((size_t)(op - out), (size_t)2);

    done;
}

// --- Test 4: TriChar filter ---
ok64 CAPO4() {
    sane(1);
    want(CAPOTriChar('a') != 0);
    want(CAPOTriChar('Z') != 0);
    want(CAPOTriChar('0') != 0);
    want(CAPOTriChar('_') != 0);

    want(CAPOTriChar(' ') == 0);
    want(CAPOTriChar('(') == 0);
    want(CAPOTriChar('{') == 0);
    want(CAPOTriChar('\n') == 0);

    done;
}

// --- Test 5: HIT seek by off-prefix yields all entries with that off ---
//   Range size is 1<<24 (the (id, type) span at the low end).
ok64 CAPO5() {
    sane(1);
    a_cstr(t1, "aaa");
    a_cstr(t2, "mmm");
    a_cstr(t3, "zzz");
    a_cstr(p1, "x.c");
    a_cstr(p2, "y.c");

    u64 entries[] = {
        wh64Pack(SPOT_TRI, CAPOFnRap20(p1), CAPOTri40(t1)),
        wh64Pack(SPOT_TRI, CAPOFnRap20(p2), CAPOTri40(t1)),
        wh64Pack(SPOT_TRI, CAPOFnRap20(p1), CAPOTri40(t2)),
        wh64Pack(SPOT_TRI, CAPOFnRap20(p2), CAPOTri40(t3)),
    };
    u64s data = {entries, entries + 4};
    u64sSort(data);

    u64cs runs[1] = {{(u64cp)entries, (u64cp)entries + 4}};
    u64css iter = {runs, runs + 1};
    HITu64Start(iter);

    u64 prefix = CAPOOffPrefix(CAPOTri40(t2));
    ok64 o = HITu64Seek(iter, &prefix);
    want(o == OK);
    want(!$empty(iter));
    testeq(wh64Off(*(*iter[0])[0]),  CAPOTri40(t2));
    testeq(wh64Type(*(*iter[0])[0]), (u8)SPOT_TRI);

    done;
}

// --- Test 6: wh64 accessors on TRI/MEN/DEF entries ---
ok64 CAPO6() {
    sane(1);
    a_cstr(name, "myFunc");
    a_cstr(path, "main.c");
    u32 fn_hash = CAPOFnRap20(path);
    u64 sym40   = CAPOSym40(name);

    u64 men = wh64Pack(SPOT_MEN, fn_hash, sym40);
    u64 def = wh64Pack(SPOT_DEF, fn_hash, sym40);
    a_cstr(tri6, "foo");
    u64 tri_e = wh64Pack(SPOT_TRI, fn_hash, CAPOTri40(tri6));

    testeq(wh64Type(men),   (u8)SPOT_MEN);
    testeq(wh64Type(def),   (u8)SPOT_DEF);
    testeq(wh64Type(tri_e), (u8)SPOT_TRI);

    // Same name -> same off for both mention and definition
    testeq(wh64Off(men), wh64Off(def));

    // fn_hash roundtrip
    testeq(wh64Id(men), fn_hash);
    testeq(wh64Id(def), fn_hash);

    a_cstr(name2, "otherFunc");
    u64 men2 = wh64Pack(SPOT_MEN, fn_hash, CAPOSym40(name2));
    want(wh64Off(men2) != wh64Off(men));

    done;
}

// --- Test 7: CAPOIndexFile emits both trigram and symbol entries ---
ok64 CAPO7() {
    sane(1);
    const char *src = "int foo(int x) { return x + 1; }";
    u8csc source = {(u8cp)src, (u8cp)src + strlen(src)};
    u8cs ext = $u8str(".c");
    a_cstr(name, "test.c");

    call(box_test_open, (8UL << 20));

    call(CAPOIndexFile, source, ext, name);

    u32 fn_hash = CAPOFnRap20(name);
    size_t nentries = 0, ntri = 0, nmen = 0, ndef = 0;
    u64 *p = (u64 *)u8bDataHead(SPOT.entries_mem);
    u64 *e = (u64 *)(u8bDataHead(SPOT.entries_mem) + (8UL << 20));
    for (; p < e; p++) {
        if (*p == 0) continue;
        nentries++;
        testeq(wh64Id(*p), fn_hash);
        u8 t = wh64Type(*p);
        if      (t == SPOT_TRI) ntri++;
        else if (t == SPOT_MEN) nmen++;
        else if (t == SPOT_DEF) ndef++;
    }
    want(nentries > 0);
    want(ntri > 0);
    want(nmen + ndef > 0);

    box_test_close();
    done;
}

// --- Test 8: same off + same id, different types sort TRI < MEN < DEF ---
ok64 CAPO8() {
    sane(1);
    u32 fn_hash = (u32)(0x12345 & WHIFF_ID_MASK);
    u64 off40   = 0xabcdef0042ULL & WHIFF_OFF_MASK;

    u64 tri_e = wh64Pack(SPOT_TRI, fn_hash, off40);
    u64 men_e = wh64Pack(SPOT_MEN, fn_hash, off40);
    u64 def_e = wh64Pack(SPOT_DEF, fn_hash, off40);

    want(tri_e < men_e);
    want(men_e < def_e);

    u64 arr[] = {def_e, tri_e, men_e};
    u64s data = {arr, arr + 3};
    u64sSort(data);
    testeq(wh64Type(arr[0]), (u8)SPOT_TRI);
    testeq(wh64Type(arr[1]), (u8)SPOT_MEN);
    testeq(wh64Type(arr[2]), (u8)SPOT_DEF);

    done;
}

// --- Test BN: same basename in two dirs collides into one fn_hash ---
ok64 CAPObasenameCollision() {
    sane(1);
    a_cstr(b1, "README.md");
    a_cstr(b2, "README.md");
    a_cstr(b3, "OTHER.md");
    testeq(CAPOFnRap20(b1), CAPOFnRap20(b2));
    want(CAPOFnRap20(b3) != CAPOFnRap20(b1));
    done;
}

// --- Test A: HunkEmit produces valid TLV that roundtrips via Drain ---

ok64 CAPOtestHunkEmit() {
    sane(1);
    char tmppath[] = "/tmp/spot_hunk_test_XXXXXX";
    int fd = mkstemp(tmppath);
    test(fd >= 0, FAILSANITY);

    spot_emit   = HUNKu8sFeed;
    spot_out_fd = fd;
    call(LESSArenaInit);

    const char *src = "void foo() {\n    int x = 1;\n    int y = 2;\n}\n";
    u8csc source = {(u8cp)src, (u8cp)src + strlen(src)};
    u8cs ext = $u8str(".c");
    Bu32 toks = {};
    call(u32bMap, toks, strlen(src) + 1);
    call(SPOTTokenize, toks, source, ext);
    u32cs htoks = {(u32cp)u32bDataHead(toks), (u32cp)u32bIdleHead(toks)};

    range32 hls[1] = {{18, 28}};
    b8 first = YES;
    a_cstr(fp, "test.c");
    call(CAPOBuildHunk, source, htoks, 0, (u32)strlen(src),
         hls, 1, ext, fp, YES, &first);

    close(fd);
    spot_out_fd = -1;
    spot_emit   = NULL;

    u8bp mapped = NULL;
    a_pad(u8, pathbuf, 256);
    u8cs ps = {(u8cp)tmppath, (u8cp)tmppath + strlen(tmppath)};
    call(u8bFeed, pathbuf, ps);
    call(PATHu8bTerm, pathbuf);
    call(FILEMapRO, &mapped, $path(pathbuf));

    a_dup(u8c, data, u8bDataC(mapped));
    want($len(data) > 20);

    hunk h = {};
    ok64 o = HUNKu8sDrain(data, &h);
    testeq(o, OK);
    want(!$empty(h.text));
    want(!$empty(h.uri));
    want($len(h.text) == strlen(src));
    want(memcmp(h.text[0], src, strlen(src)) == 0);
    want($len(h.uri) >= 6);
    want(memcmp(h.uri[0], "test.c", 6) == 0);

    FILEUnMap(mapped);
    u32bUnMap(toks);
    LESSArenaCleanup();
    unlink(tmppath);
    done;
}

// --- Test B: CAPOKnownExt recognizes standard extensions ---
ok64 CAPOtestKnownExt() {
    sane(1);
    u8cs c_ext = $u8str(".c");
    u8cs h_ext = $u8str(".h");
    u8cs py_ext = $u8str(".py");
    u8cs go_ext = $u8str(".go");
    u8cs txt_ext = $u8str(".xyz_unknown");

    want(CAPOKnownExt(c_ext) == YES);
    want(CAPOKnownExt(h_ext) == YES);
    want(CAPOKnownExt(py_ext) == YES);
    want(CAPOKnownExt(go_ext) == YES);
    want(CAPOKnownExt(txt_ext) == NO);

    u8cs empty = {};
    want(CAPOKnownExt(empty) == NO);
    done;
}

ok64 CAPOtest() {
    sane(1);
    call(CAPO0);
    call(CAPO1);
    call(CAPO2);
    call(CAPO3);
    call(CAPO4);
    call(CAPO5);
    call(CAPO6);
    call(CAPO7);
    call(CAPO8);
    call(CAPObasenameCollision);
    call(CAPOtestHunkEmit);
    call(CAPOtestKnownExt);
    done;
}

TEST(CAPOtest);
