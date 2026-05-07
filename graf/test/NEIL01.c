//
// NEIL01 — property tests for NEILCleanup + NEILShift + NEILCanon.
//
// Same property checks as graf/fuzz/NEIL.c, table driven.  Fuzz crash
// repros land in `cases[]` so the fix can't regress.
//

#include "NEIL.h"
#include "JOIN.h"

#include <stdio.h>
#include <string.h>

#include "abc/DIFF.h"
#include "abc/PRO.h"
#include "abc/TEST.h"
#include "dog/TOK.h"

// Instantiate the u64 DIFF specialization (DIFFu64s, etc).
#define X(M, name) M##u64##name
#include "abc/DIFFx.h"
#undef X

// --- Helpers (mirror the fuzz harness) ---

static b8 neil_is_ident(u8cs tok) {
    if ($len(tok) < 3) return NO;
    for (u8cp p = tok[0]; p < tok[1]; p++) {
        u8 c = *p;
        b8 d  = (c >= '0' && c <= '9');
        b8 lo = (c >= 'a' && c <= 'z');
        b8 up = (c >= 'A' && c <= 'Z');
        if (!d && !lo && !up && c != '_') return NO;
    }
    return YES;
}

static b8 hash_in(u64 h, u64 const *arr, u32 n) {
    for (u32 i = 0; i < n; i++) if (arr[i] == h) return YES;
    return NO;
}

static ok64 neil_check_basic(e32 const *edl, u32 n,
                             JOINfile const *of, JOINfile const *nf) {
    sane(1);
    u32 oi = 0, ni = 0;
    u32 prev_op = 0xff;
    for (u32 k = 0; k < n; k++) {
        u32 op  = DIFF_OP(edl[k]);
        u32 len = DIFF_LEN(edl[k]);
        if (len == 0) {
            fprintf(stderr, "NEIL01: prop1 zero-len entry at %u\n", k);
            fail(TESTFAIL);
        }
        if (k > 0 && op == prev_op) {
            fprintf(stderr, "NEIL01: prop1 adjacent same-op at %u\n", k);
            fail(TESTFAIL);
        }
        prev_op = op;
        if (op == DIFF_EQ) {
            for (u32 j = 0; j < len; j++) {
                if (oi + j >= u32bDataLen(of->toks) ||
                    ni + j >= u32bDataLen(nf->toks)) {
                    fprintf(stderr, "NEIL01: prop1 EQ overruns toks\n");
                    fail(TESTFAIL);
                }
                u8cs ov = {}, nv = {};
                tok32Val(ov, of->toks, of->data[0], (int)(oi + j));
                tok32Val(nv, nf->toks, nf->data[0], (int)(ni + j));
                if ($len(ov) != $len(nv) ||
                    memcmp(ov[0], nv[0], (size_t)$len(ov)) != 0) {
                    fprintf(stderr, "NEIL01: prop1 EQ mismatch\n");
                    fail(TESTFAIL);
                }
            }
            oi += len; ni += len;
        } else if (op == DIFF_DEL) {
            oi += len;
        } else if (op == DIFF_INS) {
            ni += len;
        } else {
            fprintf(stderr, "NEIL01: prop1 bad op %u\n", op);
            fail(TESTFAIL);
        }
    }
    if (oi != u32bDataLen(of->toks)) {
        fprintf(stderr, "NEIL01: prop2 old %u != %lu\n", oi,
                u32bDataLen(of->toks));
        fail(TESTFAIL);
    }
    if (ni != u32bDataLen(nf->toks)) {
        fprintf(stderr, "NEIL01: prop2 new %u != %lu\n", ni,
                u32bDataLen(nf->toks));
        fail(TESTFAIL);
    }
    done;
}

static ok64 neil_check_idents(e32 const *pre, u32 pre_n,
                              e32 const *post, u32 post_n,
                              JOINfile const *of) {
    sane(1);
    u64 pre_h[1024];
    u32 pn = 0;
    {
        u32 oi = 0;
        for (u32 k = 0; k < pre_n; k++) {
            u32 op  = DIFF_OP(pre[k]);
            u32 len = DIFF_LEN(pre[k]);
            if (op == DIFF_EQ) {
                for (u32 j = 0; j < len && pn < 1024; j++) {
                    u8cs v = {};
                    tok32Val(v, of->toks, of->data[0], (int)(oi + j));
                    if (!neil_is_ident(v)) continue;
                    u64 h = of->hashes[1][oi + j];
                    if (!hash_in(h, pre_h, pn)) pre_h[pn++] = h;
                }
                oi += len;
            } else if (op == DIFF_DEL) {
                oi += len;
            }
        }
    }
    if (pn == 0) done;

    u64 post_hh[1024];
    u32 ph = 0;
    {
        u32 oi = 0;
        for (u32 k = 0; k < post_n; k++) {
            u32 op  = DIFF_OP(post[k]);
            u32 len = DIFF_LEN(post[k]);
            if (op == DIFF_EQ) {
                for (u32 j = 0; j < len && ph < 1024; j++) {
                    u64 h = of->hashes[1][oi + j];
                    if (!hash_in(h, post_hh, ph)) post_hh[ph++] = h;
                }
                oi += len;
            } else if (op == DIFF_DEL) {
                oi += len;
            }
        }
    }

    for (u32 i = 0; i < pn; i++) {
        if (!hash_in(pre_h[i], post_hh, ph)) {
            fprintf(stderr, "NEIL01: prop4 ident hash %016lx dropped\n",
                    pre_h[i]);
            fail(TESTFAIL);
        }
    }
    done;
}

static ok64 neil_check_canon(e32 const *edl, u32 n) {
    sane(1);
    u32 k = 0;
    while (k < n) {
        if (DIFF_OP(edl[k]) == DIFF_EQ) { k++; continue; }
        b8 saw_ins = NO, saw_del = NO;
        while (k < n && DIFF_OP(edl[k]) != DIFF_EQ) {
            u32 op = DIFF_OP(edl[k]);
            if (op == DIFF_INS) {
                if (saw_ins || saw_del) {
                    fprintf(stderr, "NEIL01: prop5 INS after DEL/INS at %u\n",
                            k);
                    fail(TESTFAIL);
                }
                saw_ins = YES;
            } else if (op == DIFF_DEL) {
                if (saw_del) {
                    fprintf(stderr, "NEIL01: prop5 duplicate DEL at %u\n", k);
                    fail(TESTFAIL);
                }
                saw_del = YES;
            } else {
                fprintf(stderr, "NEIL01: prop5 bad op %u at %u\n", op, k);
                fail(TESTFAIL);
            }
            k++;
        }
    }
    done;
}

static ok64 neil_run_diff(e32 *out_edl, u32 cap, u32 *out_n,
                          JOINfile const *of, JOINfile const *nf) {
    sane(out_edl && out_n);
    u64 olen = u64bDataLen(of->hashes);
    u64 nlen = u64bDataLen(nf->hashes);
    u64 ws_size = DIFFWorkSize(olen, nlen);
    u64 emax = DIFFEdlMaxEntries(olen, nlen);
    if (emax == 0 || emax > cap) fail(TESTFAIL);

    Bi32 work = {};
    call(i32bAllocate, work, ws_size);

    e32g edl = {out_edl, out_edl + emax, out_edl};
    i32s ws = {i32bHead(work), i32bTerm(work)};
    u64cs oh = {of->hashes[1], of->hashes[2]};
    u64cs nh = {nf->hashes[1], nf->hashes[2]};

    ok64 r = DIFFu64s(edl, ws, oh, nh);
    *out_n = (u32)(edl[0] - edl[2]);
    i32bFree(work);
    return r;
}

// --- One case: tokenize, diff, NEIL, check all 5 properties ---

static ok64 neil_run_case(char const *name, u8csc old_data, u8csc new_data) {
    sane(1);
    fprintf(stderr, "  %s ...", name);

    u8csc c_ext = {(u8cp)"c", (u8cp)"c" + 1};

    JOINfile of = {}, nf = {};
    call(JOINTokenize, &of, old_data, c_ext);
    call(JOINTokenize, &nf, new_data, c_ext);

    u64 olen = u64bDataLen(of.hashes);
    u64 nlen = u64bDataLen(nf.hashes);
    if (olen == 0 || nlen == 0) {
        JOINFree(&of); JOINFree(&nf);
        fprintf(stderr, " skip-empty\n");
        done;
    }
    u64 emax = DIFFEdlMaxEntries(olen, nlen);

    u8 *mem[4] = {};
    call(u8bAlloc, mem, emax * sizeof(e32) * 3);
    e32 *pre_edl   = (e32 *)mem[1];
    e32 *post_edl  = pre_edl  + emax;
    e32 *shift_edl = post_edl + emax;

    u32 pre_n = 0;
    call(neil_run_diff, pre_edl, (u32)emax, &pre_n, &of, &nf);

    memcpy(post_edl, pre_edl, pre_n * sizeof(e32));
    e32g edl_g = {post_edl + pre_n, post_edl + emax, post_edl};

    u32cs old_ts = {(u32cp)of.toks[1], (u32cp)of.toks[2]};
    u32cs new_ts = {(u32cp)nf.toks[1], (u32cp)nf.toks[2]};
    call(NEILCleanup, edl_g, old_ts, new_ts, old_data, new_data);
    call(NEILShift,   edl_g, old_ts, new_ts, old_data, new_data);
    u32 post_n = (u32)(edl_g[0] - edl_g[2]);

    call(neil_check_basic,  post_edl, post_n, &of, &nf);
    call(neil_check_idents, pre_edl, pre_n, post_edl, post_n, &of);
    call(neil_check_canon,  post_edl, post_n);

    //  Property #6: shift idempotence.
    memcpy(shift_edl, post_edl, post_n * sizeof(e32));
    e32g sg = {shift_edl + post_n, shift_edl + emax, shift_edl};
    call(NEILShift, sg, old_ts, new_ts, old_data, new_data);
    u32 shift_n = (u32)(sg[0] - sg[2]);
    if (shift_n != post_n ||
        memcmp(shift_edl, post_edl, post_n * sizeof(e32)) != 0) {
        fprintf(stderr, " prop6 shift not idempotent\n");
        fail(TESTFAIL);
    }

    u8bFree(mem);
    JOINFree(&of);
    JOINFree(&nf);
    fprintf(stderr, " ok\n");
    done;
}

// --- Cases ---

typedef struct {
    char const *name;
    u8 const   *old;
    u32         old_n;
    u8 const   *new_;
    u32         new_n;
} NEILcase;

#define BLIT(s) (u8 const *)(s), (u32)(sizeof(s) - 1)
#define BRAW(...) (u8 const[]){__VA_ARGS__}, (u32)sizeof((u8 const[]){__VA_ARGS__})

// --- Fuzz crash repros (libfuzzer minimised, 4 bytes each) ---
//
//  All eight collapse to "two-entry EDL with [DEL, INS] from DIFFu64s,
//  then NEILCleanup/NEILShift early-returned without canon" — fixed by
//  always running NEILCanon on the early-return path.

static NEILcase cases[] = {
    {"identical",          BLIT("int x = 1;"),   BLIT("int x = 1;")},
    {"single_token_swap",  BLIT("a"),            BLIT("b")},
    {"insert_one_token",   BLIT("a"),            BLIT("a b")},
    {"delete_one_token",   BLIT("a b"),          BLIT("a")},

    // Fuzz repros: the two operands tokenize to a single-entry diff and
    // the post-NEIL EDL was a non-canonical [DEL, INS].
    {"crash_4a864c20",     BLIT("=="),           BRAW(0xde)},
    {"crash_867b4b63",     BLIT("=="),           BRAW(0x00)},
    {"crash_82ed2d84",     BLIT("=="),           BLIT("*")},
    {"crash_d0cf37c2",     BLIT("=="),           BRAW(0xfb)},
    {"crash_4d280dd5",     BLIT("="),            BLIT("==")},
    {"crash_1e71c906",     BLIT("D"),            BLIT("==")},
    {"crash_00276483",     BLIT("*="),           BRAW(0x00)},
    {"crash_9b0d1516",     BLIT("99"),           BRAW(0xdb)},
};

ok64 NEILtest() {
    sane(1);
    u32 n = (u32)(sizeof(cases) / sizeof(cases[0]));
    for (u32 i = 0; i < n; i++) {
        NEILcase const *c = &cases[i];
        u8csc old_d = {(u8cp)c->old,  (u8cp)c->old  + c->old_n};
        u8csc new_d = {(u8cp)c->new_, (u8cp)c->new_ + c->new_n};
        call(neil_run_case, c->name, old_d, new_d);
    }
    done;
}

TEST(NEILtest);
