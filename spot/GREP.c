#include "CAPOi.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "abc/NFA.h"
#include "abc/PRO.h"
#include "abc/SORT.h"
#include "spot/RXLITS.h"
#include "spot/SPOT.h"
#include "dog/DEF.h"

// --- Grep: substring search in source text (no tree) ---

void CAPOGrepCtx(u8csc source, u32 match_pos, u32 nctx,
                  u32 *lo, u32 *hi) {
    u32 slen = (u32)$len(source);
    if (match_pos > slen) match_pos = slen;
    u32 ls = match_pos;
    while (ls > 0 && source[0][ls - 1] != '\n') ls--;
    *lo = ls;
    for (u32 i = 0; i < nctx && *lo > 0; i++) {
        (*lo)--;
        while (*lo > 0 && source[0][*lo - 1] != '\n') (*lo)--;
    }
    u32 le = match_pos;
    while (le < slen && source[0][le] != '\n') le++;
    if (le < slen) le++;
    *hi = le;
    for (u32 i = 0; i < nctx && *hi < slen; i++) {
        while (*hi < slen && source[0][*hi] != '\n') (*hi)++;
        if (*hi < slen) (*hi)++;
    }
}

// --- Grep per-file callback ---

typedef struct {
    u8cs  substring;
    u32   ctx_lines;
} capo_grep_ctx;

static ok64 capo_grep_file_cb(void *ctx, u8csc relpath, u8csc source,
                               u8csc file_ext, u8bp mapped, path8p fpbuf) {
    sane(ctx != NULL);
    (void)fpbuf;
    capo_grep_ctx *gc = ctx;
    size_t ndl_len = (size_t)$len(gc->substring);

    if (getenv("SPOT_TRACE_QUERY")) {
        fprintf(stderr, "spot:   gcb %.*s len=%zu ndl=%zu first=%c\n",
            (int)$len(relpath), (char *)relpath[0],
            (size_t)$len(source), ndl_len,
            ndl_len > 0 ? gc->substring[0][0] : '?');
    }

    b8 tokenized = NO;
    Bu32 gtoks = {};
    u32cs gts = {};

    u32 prev_hi = 0;
    b8 found_any = NO;
    b8 first_hunk = YES;

    u8cp sp = source[0];
    u8cp se = source[1];
    if ((size_t)$len(source) < ndl_len) goto done_file;

    u8cp send = se - ndl_len;
    while (sp <= send) {
        if (memcmp(sp, gc->substring[0], ndl_len) != 0) { sp++; continue; }
        u32 match_pos = (u32)(sp - source[0]);
        u32 ctx_lo = 0, ctx_hi = 0;
        CAPOGrepCtx(source, match_pos, gc->ctx_lines, &ctx_lo, &ctx_hi);

        if (!found_any) {
            CAPOProgress((u8csc){});
            found_any = YES;
            if (!$empty(file_ext) && CAPOKnownExt(file_ext)) {
                size_t maxlen = $len(source) + 1;
                ok64 to = u32bMap(gtoks, maxlen);
                if (to == OK) {
                    to = SPOTTokenize(gtoks, source, file_ext);
                    if (to == OK) {
                        u32 *dts[2] = {u32bDataHead(gtoks),
                                       u32bIdleHead(gtoks)};
                        a_dup(u8c,dext,file_ext);
                        if (!$empty(dext) && dext[0][0] == '.')
                            dext[0]++;
                        DEFMark(dts, source, dext);
                        tokenized = YES;
                        gts[0] = (u32cp)u32bDataHead(gtoks);
                        gts[1] = (u32cp)u32bIdleHead(gtoks);
                    } else
                        u32bUnMap(gtoks);
                }
            }
        }

        range32 hls[CAPO_MAX_HLS];
        int nhl = 0;
        hls[nhl++] = (range32){match_pos, match_pos + (u32)ndl_len};
        u8cp sp2 = sp + 1;
        while (sp2 <= send && nhl < CAPO_MAX_HLS) {
            if (memcmp(sp2, gc->substring[0], ndl_len) == 0) {
                u32 mp2 = (u32)(sp2 - source[0]);
                if (mp2 >= ctx_hi) break;
                hls[nhl++] = (range32){mp2, mp2 + (u32)ndl_len};
                u32 lo2 = 0, hi2 = 0;
                CAPOGrepCtx(source, mp2, gc->ctx_lines, &lo2, &hi2);
                if (hi2 > ctx_hi) ctx_hi = hi2;
            }
            sp2++;
        }

        b8 contiguous = (ctx_lo <= prev_hi);
        if (ctx_lo < prev_hi) ctx_lo = prev_hi;
        if (ctx_lo < ctx_hi) {
            call(CAPOBuildHunk, source, gts, ctx_lo, ctx_hi,
                 hls, nhl, file_ext, relpath,
                 !contiguous, &first_hunk);
        }
        prev_hi = ctx_hi;
        sp = sp2 - 1;
        sp++;
    }

done_file:
    if (found_any) {
        if (mapped)
            LESSDefer(mapped, tokenized ? gtoks : (Bu32){});
        else if (tokenized)
            u32bUnMap(gtoks);
    } else {
        if (tokenized) u32bUnMap(gtoks);
        if (mapped) FILEUnMap(mapped);
    }
    return OK;
}

ok64 CAPOGrep(u8csc substring, u8csc ext, u8csc reporoot, u32 ctx_lines,
              u8css files, uri const *ref) {
    sane($ok(substring) && !$empty(substring) && $ok(reporoot));

    Bu64 hashbuf1 = {};
    b8 has_trigrams = NO;
    if ($len(files) == 0 && ref == NULL)
        CAPOTrigramFilter(hashbuf1, &has_trigrams, substring, reporoot);

    call(LESSArenaInit);

    capo_grep_ctx gc = {.ctx_lines = ctx_lines};
    $mv(gc.substring, substring);

    CAPOScanOpts opts = {
        .has_trigrams = has_trigrams,
        .file_fn = capo_grep_file_cb,
        .file_ctx = &gc,
    };
    if (!$empty(ext)) $mv(opts.target_ext, ext);
    if (has_trigrams) $mv(opts.tri_hashes, u64bDataC(hashbuf1));

    ok64 scan_ret = OK;
    if (ref != NULL) {
        //  Historic: walk keeper tree at the given ref.
        home *h = SPOT.h;
        ok64 ko = KEEPOpen(h, NO);
        if (ko != OK && ko != KEEPOPEN) {
            fprintf(stderr, "spot: keeper open failed: %s\n", ok64str(ko));
            if (!BNULL(hashbuf1)) u64bUnMap(hashbuf1);
            LESSArenaCleanup();
            return ko;
        }
        scan_ret = CAPOScanRef(&KEEP, ref, &opts);
        if (ko == OK) KEEPClose();
    } else if ($len(files) > 0) {
        scan_ret = CAPOScanFiles(files, &opts);
    } else {
        scan_ret = CAPOScan(reporoot, &opts);
    }
    (void)scan_ret;

    CAPOProgress((u8csc){});
    if (less_nhunks > 0)
        LESSRun(less_hunks, less_nhunks);
    LESSArenaCleanup();

    if (!BNULL(hashbuf1)) u64bUnMap(hashbuf1);
    done;
}

// --- Regex grep: extract literal runs from regex for trigram filtering ---

// Trigram-extraction context shared with the rxlits ragel scanner.
typedef struct {
    u8 buf[1024];
    u32 len;
    u32 nidxfiles;
    u64cs *runs;
    u64 *const *hashbuf1;   // u64b decays to u64 *const *
    b8 *has_trigrams;
} regexlits_ctx;

// For each 3-byte trigram in the literal run, intersect/seed the index.
static void regexlits_flush(regexlits_ctx *c) {
    if (c->len >= 3) {
        for (u32 li = 0; li + 2 < c->len; li++) {
            if (!CAPOTriChar(c->buf[li]) ||
                !CAPOTriChar(c->buf[li + 1]) ||
                !CAPOTriChar(c->buf[li + 2])) continue;
            u8 _tb[3] = {c->buf[li], c->buf[li + 1], c->buf[li + 2]};
            u8cs tri = {_tb, _tb + 3};
            u64 tri_prefix = CAPOOffPrefix(CAPOTri40(tri));
            u64cs seek_runs[CAPO_MAX_LEVELS];
            for (u32 si = 0; si < c->nidxfiles; si++) {
                seek_runs[si][0] = c->runs[si][0];
                seek_runs[si][1] = c->runs[si][1];
            }
            u64css seek_iter = {seek_runs, seek_runs + c->nidxfiles};
            HITu64Start(seek_iter);
            if (!*c->has_trigrams) {
                u64bReset(c->hashbuf1);
                CAPOCollectPaths(seek_iter, tri_prefix,
                                 u64bDataIdle(c->hashbuf1));
                *c->has_trigrams = YES;
            } else {
                u64sSort(u64bData(c->hashbuf1));
                HITu64Seek(seek_iter, &tri_prefix);
                CAPOFilterInPlace(c->hashbuf1, seek_iter, tri_prefix);
            }
        }
    }
    c->len = 0;
}

static ok64 regexlits_cb(void *ctx, u8 ch, b8 flush) {
    regexlits_ctx *c = (regexlits_ctx *)ctx;
    if (flush) { regexlits_flush(c); return OK; }
    if (c->len < sizeof(c->buf)) c->buf[c->len++] = ch;
    return OK;
}

// Walk a regex pattern, collect runs of literal characters.
// Meta chars and class escapes break a run; backslash-escaped literals stay.
// For each run >= 3 chars, extract trigrams and intersect with the index.
static void CAPORegexLiterals(u8csc pattern,
                               u64css stack, u32 nidxfiles,
                               u64cs *runs,
                               u64b hashbuf1,
                               b8 *has_trigrams) {
    (void)stack;  // resolved per-trigram via runs+nidxfiles
    regexlits_ctx ctx = {
        .nidxfiles = nidxfiles, .runs = runs,
        .hashbuf1 = hashbuf1, .has_trigrams = has_trigrams,
    };
    RXLITSu8sDrain(pattern, regexlits_cb, &ctx);
}

// --- Pcre grep per-file callback ---

typedef struct {
    nfau8cs cprog;
    u32s    nfa_ws;
    u32     ctx_lines;
} capo_pcre_ctx;

static ok64 capo_pcre_file_cb(void *ctx, u8csc relpath, u8csc source,
                                u8csc file_ext, u8bp mapped, path8p fpbuf) {
    sane(ctx != NULL);
    (void)fpbuf;
    capo_pcre_ctx *pc = ctx;

    b8 tokenized = NO;
    Bu32 gtoks = {};
    u32cs gts = {};

    u32 prev_hi = 0;
    b8 found_any = NO;
    b8 first_hunk = YES;

    u8cp lp = source[0];
    u8cp se = source[1];
    while (lp < se) {
        u8cp le = lp;
        while (le < se && *le != '\n') le++;
        u8cs ln = {lp, le};

        if (NFAu8Search(pc->cprog, ln, pc->nfa_ws)) {
            u32 match_pos = (u32)(lp - source[0]);
            u32 ctx_lo = 0, ctx_hi = 0;
            CAPOGrepCtx(source, match_pos, pc->ctx_lines, &ctx_lo, &ctx_hi);

            if (!found_any) {
                CAPOProgress((u8csc){});
                found_any = YES;
                if (!$empty(file_ext) && CAPOKnownExt(file_ext)) {
                    size_t maxlen = $len(source) + 1;
                    ok64 to = u32bMap(gtoks, maxlen);
                    if (to == OK) {
                        to = SPOTTokenize(gtoks, source, file_ext);
                        if (to == OK) {
                            u32 *dts[2] = {u32bDataHead(gtoks),
                                           u32bIdleHead(gtoks)};
                            a_dup(u8c,dext,file_ext);
                            if (!$empty(dext) && dext[0][0] == '.')
                                dext[0]++;
                            DEFMark(dts, source, dext);
                            tokenized = YES;
                            gts[0] = (u32cp)u32bDataHead(gtoks);
                            gts[1] = (u32cp)u32bIdleHead(gtoks);
                        } else
                            u32bUnMap(gtoks);
                    }
                }
            }

            // Find match span
            u32 hl_start = match_pos;
            u32 hl_end = (u32)(le - source[0]);
            for (u8cp sp = lp; sp < le; sp++) {
                for (u8cp ep = sp + 1; ep <= le; ep++) {
                    u8cs sub = {sp, ep};
                    if (NFAu8Match(pc->cprog, sub, pc->nfa_ws)) {
                        hl_start = (u32)(sp - source[0]);
                        hl_end = (u32)(ep - source[0]);
                        goto found_span;
                    }
                }
            }
            found_span:;

            range32 hls[CAPO_MAX_HLS];
            int nhl = 0;
            hls[nhl++] = (range32){hl_start, hl_end};

            u8cp lp2 = le;
            if (lp2 < se && *lp2 == '\n') lp2++;
            while (lp2 < se && nhl < CAPO_MAX_HLS) {
                u8cp le2 = lp2;
                while (le2 < se && *le2 != '\n') le2++;
                u32 mp2 = (u32)(lp2 - source[0]);
                if (mp2 >= ctx_hi) break;

                u8cs ln2 = {lp2, le2};
                if (NFAu8Search(pc->cprog, ln2, pc->nfa_ws)) {
                    u32 hs2 = mp2, he2 = (u32)(le2 - source[0]);
                    for (u8cp sp = lp2; sp < le2; sp++) {
                        for (u8cp ep = sp + 1; ep <= le2; ep++) {
                            u8cs sub = {sp, ep};
                            if (NFAu8Match(pc->cprog, sub, pc->nfa_ws)) {
                                hs2 = (u32)(sp - source[0]);
                                he2 = (u32)(ep - source[0]);
                                goto found_span2;
                            }
                        }
                    }
                    found_span2:;
                    hls[nhl++] = (range32){hs2, he2};

                    u32 lo2 = 0, hi2 = 0;
                    CAPOGrepCtx(source, mp2, pc->ctx_lines, &lo2, &hi2);
                    if (hi2 > ctx_hi) ctx_hi = hi2;
                }
                lp2 = le2;
                if (lp2 < se && *lp2 == '\n') lp2++;
            }

            b8 contiguous = (ctx_lo <= prev_hi);
            if (ctx_lo < prev_hi) ctx_lo = prev_hi;
            if (ctx_lo < ctx_hi) {
                call(CAPOBuildHunk, source, gts, ctx_lo, ctx_hi,
                     hls, nhl, file_ext, relpath,
                     !contiguous, &first_hunk);
            }
            prev_hi = ctx_hi;

            lp = source[0] + prev_hi;
            continue;
        }

        lp = le;
        if (lp < se && *lp == '\n') lp++;
    }

    if (found_any) {
        if (mapped)
            LESSDefer(mapped, tokenized ? gtoks : (Bu32){});
        else if (tokenized)
            u32bUnMap(gtoks);
    } else {
        if (tokenized) u32bUnMap(gtoks);
        if (mapped) FILEUnMap(mapped);
    }
    return OK;
}

ok64 CAPOPcreGrep(u8csc pattern, u8csc ext, u8csc reporoot, u32 ctx_lines,
                   u8css files, uri const *ref) {
    sane($ok(pattern) && !$empty(pattern) && $ok(reporoot));

    // Compile regex
    nfau8 prog_buf[512];
    u32 patch_buf[512];
    nfau8g prog = {prog_buf, prog_buf + 512, prog_buf};
    u32 *ws_patch[2] = {patch_buf, patch_buf + 512};
    a_dup(u8c,pat,pattern);
    ok64 co = NFAu8Compile(prog, pat, ws_patch);
    if (co != OK) {
        fprintf(stderr, "spot: bad regex: %s\n", ok64str(co));
        return co;
    }
    nfau8cs cprog = {prog[2], prog[0]};
    u16 nstates = NFAu8States(cprog);

    u64 wsz = NFAu8WorkSize(nstates);
    Bu32 nfa_ws_bb = {};
    call(u32bAlloc, nfa_ws_bb, wsz);
    u32s nfa_ws = {};
    $mv(nfa_ws, u32bIdle(nfa_ws_bb));

    // Trigram filtering for regex
    Bu64 hashbuf1 = {};
    b8 has_trigrams = NO;
    if ($len(files) == 0 && ref == NULL) {
        a_path(capodir);
        call(CAPOResolveDir, capodir, reporoot);
        a_dup(u8c, dirslice, u8bDataC(capodir));

        ok64 ao = u64bMap(hashbuf1, 1ULL << 27);
        if (ao == OK) {
            u64cs runs[CAPO_MAX_LEVELS] = {};
            u64css stack = {runs, runs};
            u8bp mmaps[CAPO_MAX_LEVELS] = {};
            u32 nidxfiles = 0;
            CAPOStackOpen(stack, mmaps, &nidxfiles, dirslice);
            stack[1] = stack[0] + nidxfiles;
            if (nidxfiles > 0)
                CAPORegexLiterals(pattern, stack, nidxfiles, runs,
                                   hashbuf1, &has_trigrams);
            CAPOStackClose(mmaps, nidxfiles);
            if (has_trigrams && u64bDataLen(hashbuf1) > 0)
                u64sSort(u64bData(hashbuf1));
        }
    }

    call(LESSArenaInit);

    capo_pcre_ctx pc = {.ctx_lines = ctx_lines};
    $mv(pc.cprog, cprog);
    $mv(pc.nfa_ws, nfa_ws);

    CAPOScanOpts opts = {
        .has_trigrams = has_trigrams,
        .file_fn = capo_pcre_file_cb,
        .file_ctx = &pc,
    };
    if (!$empty(ext)) $mv(opts.target_ext, ext);
    if (has_trigrams) $mv(opts.tri_hashes, u64bDataC(hashbuf1));

    if (ref != NULL) {
        home *h = SPOT.h;
        ok64 ko = KEEPOpen(h, NO);
        if (ko != OK && ko != KEEPOPEN) {
            fprintf(stderr, "spot: keeper open failed: %s\n", ok64str(ko));
            u32bFree(nfa_ws_bb);
            if (!BNULL(hashbuf1)) u64bUnMap(hashbuf1);
            LESSArenaCleanup();
            return ko;
        }
        CAPOScanRef(&KEEP, ref, &opts);
        if (ko == OK) KEEPClose();
    } else if ($len(files) > 0) {
        CAPOScanFiles(files, &opts);
    } else {
        CAPOScan(reporoot, &opts);
    }

    CAPOProgress((u8csc){});
    if (less_nhunks > 0)
        LESSRun(less_hunks, less_nhunks);
    LESSArenaCleanup();

    u32bFree(nfa_ws_bb);
    if (!BNULL(hashbuf1)) u64bUnMap(hashbuf1);
    done;
}
