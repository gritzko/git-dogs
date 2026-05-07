#include "NEIL.h"

#include "abc/PRO.h"

// Byte length of tokens [from, from+count), optionally skipping whitespace.
static u32 NEILByteSpanX(u32cs toks, u8cp base, u32 from, u32 count,
                         b8 skip_ws) {
    if (count == 0) return 0;
    u32 ntoks = (u32)$len(toks);
    if (from + count > ntoks) return 0;
    u32 total = 0;
    for (u32 i = from; i < from + count; i++) {
        if (skip_ws && NEILIsWS(toks, base, i)) continue;
        u32 lo = (i > 0) ? tok32Offset(toks[0][i - 1]) : 0;
        u32 hi = tok32Offset(toks[0][i]);
        if (hi > lo) total += hi - lo;
    }
    return total;
}

static u32 NEILByteSpan(u32cs toks, u8cp base, u32 from, u32 count) {
    return NEILByteSpanX(toks, base, from, count, YES);
}

// Merge adjacent same-op entries in place. Returns new count.
static u32 NEILMerge(e32 *buf, u32 n) {
    u32 m = 0;
    for (u32 k = 0; k < n; k++) {
        u32 op = DIFF_OP(buf[k]);
        u32 len = DIFF_LEN(buf[k]);
        if (len == 0) continue;
        if (m > 0 && DIFF_OP(buf[m - 1]) == op)
            buf[m - 1] = DIFF_ENTRY(op, DIFF_LEN(buf[m - 1]) + len);
        else
            buf[m++] = buf[k];
    }
    return m;
}

// Compare token text at index ia in (toks_a, base_a) with index ib
// in (toks_b, base_b).  Returns YES if identical.
static b8 NEILTokEq(u32cs ta, u8cp ba, u32 ia,
                     u32cs tb, u8cp bb, u32 ib) {
    u8cs va = {}, vb = {};
    tok32Val(va,ta,ba,(int)ia);
    tok32Val(vb,tb,bb,(int)ib);
    u32 la = (u32)(va[1] - va[0]);
    u32 lb = (u32)(vb[1] - vb[0]);
    if (la != lb) return NO;
    return memcmp(va[0], vb[0], la) == 0;
}

// Score the boundary between token idx-1 and token idx.
// Higher = better alignment.  Mirrors diff-match-patch scoring.
static int NEILBoundaryScore(u32cs toks, u8cp base, u32 idx, u32 ntoks) {
    if (idx == 0 || idx >= ntoks) return 6;  // edge
    u32 hi = tok32Offset(toks[0][idx - 1]);
    u32 lo = (idx > 1) ? tok32Offset(toks[0][idx - 2]) : 0;
    if (hi <= lo) return 6;
    u8 c1 = base[hi - 1];  // last byte before boundary

    u32 lo2 = hi;  // contiguous tokens
    u32 hi2 = tok32Offset(toks[0][idx]);
    if (hi2 <= lo2) return 6;
    u8 c2 = base[lo2];  // first byte at boundary

    b8 na1 = !(c1 == '_' || (c1 >= 'a' && c1 <= 'z') ||
               (c1 >= 'A' && c1 <= 'Z') || (c1 >= '0' && c1 <= '9'));
    b8 na2 = !(c2 == '_' || (c2 >= 'a' && c2 <= 'z') ||
               (c2 >= 'A' && c2 <= 'Z') || (c2 >= '0' && c2 <= '9'));
    b8 ws1 = na1 && (c1 == ' ' || c1 == '\t' || c1 == '\n' || c1 == '\r');
    b8 ws2 = na2 && (c2 == ' ' || c2 == '\t' || c2 == '\n' || c2 == '\r');
    b8 lb1 = ws1 && (c1 == '\n' || c1 == '\r');
    b8 lb2 = ws2 && (c2 == '\n' || c2 == '\r');

    if (lb1 && lb2) return 5;  // blank line
    if (lb1 || lb2) return 4;  // line break
    if (na1 && !ws1 && ws2) return 3;  // end of sentence
    if (ws1 || ws2) return 2;  // whitespace
    if (na1 || na2) return 1;  // non-alphanumeric
    return 0;
}

ok64 NEILCleanup(e32g edl, u32cs old_toks, u32cs new_toks,
                 u8csc old_src, u8csc new_src) {
    sane(edl != NULL);
    u32 nedl = (u32)(edl[0] - edl[2]);
    //  Short EDLs have no kill candidates (kill needs surrounding
    //  edits) but still need canonicalization — a 2-entry [DEL, INS]
    //  from DIFF must come back as [INS, DEL] per the in-rm invariant.
    if (nedl < 3) return NEILCanon(edl);

    // Work in a heap buffer (killed EQ expands to DEL+INS).
    u32 cap = nedl * 2 + 4;
    Bu32 bbuf = {};
    call(u32bAlloc, bbuf, cap);
    e32 *buf = bbuf[0];
    memcpy(buf, edl[2], nedl * sizeof(e32));
    u32 n = nedl;

    // Iterative semantic cleanup: kill false equalities until stable.
    // Each iteration merges edit regions, potentially exposing new kills.
    for (int iter = 0; iter < 8; iter++) {
        Bu32 obuf = {}, nbuf = {};
        ok64 ao = u32bAlloc(obuf, n);
        ok64 no = u32bAlloc(nbuf, n);
        if (ao != OK || no != OK) {
            u32bFree(obuf); u32bFree(nbuf); u32bFree(bbuf);
            fail(NEILBAD);
        }
        u32 *old_off = obuf[0];
        u32 *new_off = nbuf[0];
        {
            u32 oi = 0, ni = 0;
            for (u32 k = 0; k < n; k++) {
                old_off[k] = oi;
                new_off[k] = ni;
                u32 len = DIFF_LEN(buf[k]);
                u32 op = DIFF_OP(buf[k]);
                if (op == DIFF_EQ) { oi += len; ni += len; }
                else if (op == DIFF_DEL) { oi += len; }
                else { ni += len; }
            }
        }

        b8 changed = NO;
        u32 tcap = n * 2 + 4;
        Bu32 tbuf = {};
        ok64 to = u32bAlloc(tbuf, tcap);
        if (to != OK) {
            u32bFree(obuf); u32bFree(nbuf); u32bFree(bbuf);
            fail(NEILBAD);
        }
        e32 *tmp = tbuf[0];

        u32 w = 0;
        for (u32 k = 0; k < n; k++) {
            if (DIFF_OP(buf[k]) != DIFF_EQ) { tmp[w++] = buf[k]; continue; }
            u32 eq_len = DIFF_LEN(buf[k]);
            u32 eq_bytes = NEILByteSpan(new_toks, new_src[0],
                                        new_off[k], eq_len);

            // Accumulate edit bytes before (until prev EQ)
            u32 before_bytes = 0;
            for (u32 j = k; j > 0; ) {
                j--;
                u32 jop = DIFF_OP(buf[j]);
                if (jop == DIFF_EQ) break;
                u32 jlen = DIFF_LEN(buf[j]);
                if (jop == DIFF_DEL)
                    before_bytes += NEILByteSpan(old_toks, old_src[0],
                                                 old_off[j], jlen);
                else
                    before_bytes += NEILByteSpan(new_toks, new_src[0],
                                                 new_off[j], jlen);
            }

            // Accumulate edit bytes after (until next EQ)
            u32 after_bytes = 0;
            for (u32 j = k + 1; j < n; j++) {
                u32 jop = DIFF_OP(buf[j]);
                if (jop == DIFF_EQ) break;
                u32 jlen = DIFF_LEN(buf[j]);
                if (jop == DIFF_DEL)
                    after_bytes += NEILByteSpan(old_toks, old_src[0],
                                                 old_off[j], jlen);
                else
                    after_bytes += NEILByteSpan(new_toks, new_src[0],
                                                 new_off[j], jlen);
            }

            if (before_bytes == 0 || after_bytes == 0) {
                tmp[w++] = buf[k]; continue;
            }

            // Line-fraction kill: if the EQ is a small fragment of the
            // line(s) it spans, drop it.  Common case is incidental
            // bracket / punctuation matches inside otherwise-different
            // code: `( ) ; ,` and bare `\n`s the LCS picks up between
            // genuinely divergent text.  Keeping them as EQ glues
            // conflict markers around tiny fragments and forces ugly
            // intra-line marker runs; killing forces the surrounding
            // non-EQ run to absorb the whole line and the diff snaps
            // to line granularity.  Counts \n bytes on both sides
            // (EQ-bytes and line-span) per the user's request.
            {
                u32 eq_from   = new_off[k];
                u32 eq_blo_lf = (eq_from > 0)
                    ? tok32Offset(new_toks[0][eq_from - 1]) : 0;
                u32 eq_bhi_lf = tok32Offset(new_toks[0][eq_from + eq_len - 1]);
                a_head(u8c, pre_eq,  new_src, eq_blo_lf);
                a_rest(u8c, post_eq, new_src, eq_bhi_lf);
                u8cp line_lo_p = new_src[0];
                $rof(u8c, p, pre_eq) {
                    if (*p == '\n') { line_lo_p = p + 1; break; }
                }
                a_dup(u8c, scan, post_eq);
                (void)u8csFind(scan, '\n');     // scan[0] = '\n' or term
                u32 line_span = (u32)(scan[0] - line_lo_p);
                u32 raw_eq    = NEILByteSpanX(new_toks, new_src[0],
                                              new_off[k], eq_len, NO);
                if (line_span >= 4 && raw_eq * 4 < line_span) {
                    if (eq_len > 0) tmp[w++] = DIFF_ENTRY(DIFF_DEL, eq_len);
                    if (eq_len > 0) tmp[w++] = DIFF_ENTRY(DIFF_INS, eq_len);
                    changed = YES;
                    continue;
                }
            }

            // Whitespace-only EQs: use raw byte span for kill decision.
            if (eq_bytes == 0) {
                u32 raw = NEILByteSpanX(new_toks, new_src[0],
                                        new_off[k], eq_len, NO);
                if (raw < before_bytes + after_bytes) {
                    if (eq_len > 0) tmp[w++] = DIFF_ENTRY(DIFF_DEL, eq_len);
                    if (eq_len > 0) tmp[w++] = DIFF_ENTRY(DIFF_INS, eq_len);
                    changed = YES;
                } else {
                    tmp[w++] = buf[k];
                }
                continue;
            }

            // Never kill EQs larger than the tunable ceiling.
            if (NEIL_MAX_KILL > 0 && eq_bytes >= NEIL_MAX_KILL) {
                tmp[w++] = buf[k]; continue;
            }

            // Protect EQs that contain at least one alphanumeric token
            // of length >= 2 — IF the EQ is line-aligned on at least
            // one boundary OR the surrounding edits are small.  When
            // the EQ is mid-line on both sides AND sits between large
            // edit regions, the matched identifier is almost certainly
            // accidental (e.g. `DOG_PUP_SEQNO_W` appearing 3x in OLD
            // and 3x in NEW across a function rewrite — LCS picks one
            // pairing arbitrarily; rendering it as KEEP within
            // otherwise-DEL or -INS lines just adds visual noise).
            //
            // "Line-aligned" here means the byte just before the EQ's
            // first token is `\n` OR the byte just after the EQ's last
            // token (in `new_src`) is `\n`.  Cheap and covers the
            // single-line modification case (`int x = 5;` →
            // `int x = 7;`) where the EQ tokens straddle an `\n`.
            {
                u32 eq_from = new_off[k];
                b8 has_ident = NO;
                for (u32 j = 0; j < eq_len && !has_ident; j++) {
                    u32 ti = eq_from + j;
                    u32 lo = (ti > 0) ? tok32Offset(new_toks[0][ti - 1]) : 0;
                    u32 hi = tok32Offset(new_toks[0][ti]);
                    if (hi - lo < 2) continue;
                    b8 alnum = YES;
                    for (u32 b = lo; b < hi && alnum; b++) {
                        u8 c = new_src[0][b];
                        b8 d  = (c >= '0' && c <= '9');
                        b8 lc = (c >= 'a' && c <= 'z');
                        b8 uc = (c >= 'A' && c <= 'Z');
                        if (!d && !lc && !uc && c != '_') alnum = NO;
                    }
                    if (alnum) has_ident = YES;
                }
                if (has_ident) {
                    //  Protect when (a) the EQ touches at least one
                    //  line boundary in `new_src` (covers single-line
                    //  modifications where most tokens stay), OR (b)
                    //  the surrounding edits are small enough that the
                    //  match is plausibly intentional, not accidental.
                    //  Mid-line-on-both-sides + large surrounding edits
                    //  = LCS picked one arbitrary occurrence of a
                    //  repeated identifier across a function rewrite —
                    //  visually noisy in token-coloured renderers.
                    u32 eq_blo = (eq_from > 0)
                        ? tok32Offset(new_toks[0][eq_from - 1]) : 0;
                    u32 eq_bhi = tok32Offset(new_toks[0][eq_from + eq_len - 1]);
                    u32 nlen   = (u32)$len(new_src);
                    b8 line_aligned = NO;
                    if (eq_blo == 0 || new_src[0][eq_blo - 1] == '\n')
                        line_aligned = YES;
                    if (eq_bhi >= nlen || new_src[0][eq_bhi] == '\n')
                        line_aligned = YES;
                    //  "Big" = at least one full line worth of edit on
                    //  each side.  Single-line `int x = 5;` →
                    //  `int x = 7;` has tiny surrounds; the existing
                    //  has_ident protection is right there.
                    b8 big_both = (before_bytes >= 60 && after_bytes >= 60);
                    if (line_aligned || !big_both) {
                        tmp[w++] = buf[k]; continue;
                    }
                }
            }

            // Protect EQs that contain a line with >= 6 non-ws bytes.
            // A "line" is text between \n boundaries (or span edges).
            // This prevents the cascade where killing short EQs between
            // edits merges them into giant DEL/INS blocks.
            if (eq_bytes >= 6) {
                u32 eq_from = new_off[k];
                u32 eq_blo = (eq_from > 0)
                    ? tok32Offset(new_toks[0][eq_from - 1]) : 0;
                u32 eq_bhi = tok32Offset(new_toks[0][eq_from + eq_len - 1]);
                if (eq_bhi > eq_blo &&
                    memchr(new_src[0] + eq_blo, '\n', eq_bhi - eq_blo)) {
                    u32 nw = 0;
                    b8 has_code_line = NO;
                    for (u32 b = eq_blo; b < eq_bhi; b++) {
                        u8 c = new_src[0][b];
                        if (c == '\n') {
                            if (nw >= 6) { has_code_line = YES; break; }
                            nw = 0;
                            continue;
                        }
                        if (c != ' ' && c != '\t' && c != '\r')
                            nw++;
                    }
                    if (!has_code_line && nw >= 6) has_code_line = YES;
                    if (has_code_line) {
                        tmp[w++] = buf[k]; continue;
                    }
                }
            }

            // Kill small false EQs: two tiers.
            // Small EQs (< 16 bytes): sum condition (aggressive).
            // Larger EQs: both sides must individually exceed it.
            b8 do_kill = NO;
            if (eq_bytes < 16)
                do_kill = eq_bytes < before_bytes + after_bytes;
            else
                do_kill = eq_bytes < before_bytes &&
                          eq_bytes < after_bytes;
            if (do_kill) {
                if (eq_len > 0) tmp[w++] = DIFF_ENTRY(DIFF_DEL, eq_len);
                if (eq_len > 0) tmp[w++] = DIFF_ENTRY(DIFF_INS, eq_len);
                changed = YES;
            } else {
                tmp[w++] = buf[k];
            }
        }

        u32bFree(obuf);
        u32bFree(nbuf);

        w = NEILMerge(tmp, w);
        u32bFree(bbuf);
        memcpy(bbuf, tbuf, sizeof(Bu32));
        BNULLify(tbuf);
        buf = bbuf[0];
        n = w;

        if (!changed) break;
    }

    // Copy back into edl buffer
    u32 ecap = (u32)(edl[1] - edl[2]);
    u32 final_n = (n < ecap) ? n : ecap;
    memcpy(edl[2], buf, final_n * sizeof(e32));
    edl[0] = edl[2] + final_n;

    u32bFree(bbuf);

    //  Splice canonicalization (in-rm invariant): WEAVE.h's compose
    //  pass and the unified-diff renderers both assume each non-EQ run
    //  is exactly `[INS sum, DEL sum]` in that order.  Cleanup may have
    //  produced `DEL INS DEL INS` interleavings; collapse them now.
    return NEILCanon(edl);
}

ok64 NEILShift(e32g edl, u32cs old_toks, u32cs new_toks,
               u8csc old_src, u8csc new_src) {
    sane(edl != NULL);
    u32 nedl = (u32)(edl[0] - edl[2]);
    //  Shift needs both flanking EQs; <3 entries means no shifting can
    //  happen, but canonicalization still must run so a leftover
    //  [DEL, INS] from upstream is collapsed to [INS, DEL].
    if (nedl < 3) return NEILCanon(edl);

    u32 new_ntoks = (u32)$len(new_toks);
    u32 old_ntoks = (u32)$len(old_toks);

    // Compute old/new token offsets for each EDL entry.
    Bu32 oobuf = {}, nobuf = {};
    ok64 ao = u32bAlloc(oobuf, nedl);
    ok64 no = u32bAlloc(nobuf, nedl);
    if (ao != OK || no != OK) {
        u32bFree(oobuf); u32bFree(nobuf);
        fail(NEILBAD);
    }
    u32 *ooff = oobuf[0];
    u32 *noff = nobuf[0];
    {
        u32 oi = 0, ni = 0;
        for (u32 k = 0; k < nedl; k++) {
            ooff[k] = oi;
            noff[k] = ni;
            u32 len = DIFF_LEN(edl[2][k]);
            u32 op = DIFF_OP(edl[2][k]);
            if (op == DIFF_EQ) { oi += len; ni += len; }
            else if (op == DIFF_DEL) { oi += len; }
            else { ni += len; }
        }
    }

    // Process change regions: runs of non-EQ entries between two EQs.
    u32 k = 0;
    while (k < nedl) {
        if (DIFF_OP(edl[2][k]) != DIFF_EQ) { k++; continue; }
        u32 eq1 = k;
        u32 cs = k + 1;  // change region start
        if (cs >= nedl || DIFF_OP(edl[2][cs]) == DIFF_EQ) {
            k++; continue;
        }
        // Find end of change region
        u32 ce = cs;
        while (ce < nedl && DIFF_OP(edl[2][ce]) != DIFF_EQ) ce++;
        if (ce >= nedl) break;  // no trailing EQ
        u32 eq2 = ce;

        u32 n1 = DIFF_LEN(edl[2][eq1]);
        u32 n2 = DIFF_LEN(edl[2][eq2]);
        if (n1 + n2 == 0) { k = ce; continue; }

        // Compute total DEL/INS tokens in the change region.
        // DEL tokens are contiguous on old side, INS on new side.
        u32 dtot = 0, etot = 0;
        for (u32 i = cs; i < ce; i++) {
            if (DIFF_OP(edl[2][i]) == DIFF_DEL) dtot += DIFF_LEN(edl[2][i]);
            else etot += DIFF_LEN(edl[2][i]);
        }
        if (dtot + etot == 0) { k = ce; continue; }

        // Old/new positions at the change region boundary.
        u32 oi_cs = ooff[cs];  // old start of change region
        u32 ni_cs = noff[cs];  // new start of change region

        // 1. Max left shift: compare old/new tokens walking backward
        //    from the end of the change region.  Naturally walks through
        //    DEL/INS then into EQ1 on the respective sides.
        u32 max_left = 0;
        {
            u32 oi_end = oi_cs + dtot;
            u32 ni_end = ni_cs + etot;
            for (u32 j = 0; j < n1; j++) {
                if (!NEILTokEq(old_toks, old_src[0], oi_end - 1 - j,
                               new_toks, new_src[0], ni_end - 1 - j))
                    break;
                max_left = j + 1;
            }
        }

        // 2. Max right shift: compare old/new tokens walking forward
        //    from the start of the change region.  Naturally walks
        //    through DEL/INS then into EQ2 on the respective sides.
        u32 max_right = 0;
        for (u32 j = 0; j < n2; j++) {
            if (!NEILTokEq(old_toks, old_src[0], oi_cs + j,
                           new_toks, new_src[0], ni_cs + j))
                break;
            max_right = j + 1;
        }

        if (max_left + max_right == 0) { k = ce; continue; }

        // 3. Score all positions, pick best.
        //    Score on new side (context display) + old side if DEL present.
        int best_d = 0, best_sc = 0;
        for (int d = -(int)max_left; d <= (int)max_right; d++) {
            int sc = 0;
            if (etot > 0) {
                u32 li = (u32)((int)ni_cs + d);
                u32 ri = (u32)((int)ni_cs + (int)etot + d);
                sc += NEILBoundaryScore(new_toks, new_src[0], li, new_ntoks)
                    + NEILBoundaryScore(new_toks, new_src[0], ri, new_ntoks);
            }
            if (dtot > 0) {
                u32 li = (u32)((int)oi_cs + d);
                u32 ri = (u32)((int)oi_cs + (int)dtot + d);
                sc += NEILBoundaryScore(old_toks, old_src[0], li, old_ntoks)
                    + NEILBoundaryScore(old_toks, old_src[0], ri, old_ntoks);
            }
            if (sc >= best_sc) {  // >= prefers trailing whitespace
                best_sc = sc;
                best_d = d;
            }
        }

        if (best_d != 0) {
            edl[2][eq1] = DIFF_ENTRY(DIFF_EQ, (u32)((int)n1 + best_d));
            edl[2][eq2] = DIFF_ENTRY(DIFF_EQ, (u32)((int)n2 - best_d));
        }

        k = ce;
    }

    // Remove any 0-length entries produced by shifting.
    u32 w = 0;
    for (u32 k2 = 0; k2 < nedl; k2++) {
        if (DIFF_LEN(edl[2][k2]) == 0) continue;
        edl[2][w++] = edl[2][k2];
    }
    edl[0] = edl[2] + w;

    u32bFree(oobuf);
    u32bFree(nobuf);

    //  Splice canonicalization — same reasoning as in `NEILCleanup`.
    //  Shifting an EQ across a non-EQ run can leave a `DEL INS DEL`
    //  shape; collapse to `INS DEL`.
    return NEILCanon(edl);
}

ok64 NEILCanon(e32g edl) {
    sane(edl != NULL);
    u32 n = (u32)(edl[0] - edl[2]);
    if (n == 0) done;

    Bu32 buf = {};
    call(u32bAlloc, buf, n + 4);
    e32 *out = buf[0];
    u32 w = 0;

    u32 k = 0;
    while (k < n) {
        e32 e = edl[2][k];
        u32 op = DIFF_OP(e);
        u32 len = DIFF_LEN(e);
        if (len == 0) { k++; continue; }
        if (op == DIFF_EQ) {
            //  Coalesce adjacent EQ entries (NEIL passes don't usually
            //  produce them, but the canon is the right place to enforce
            //  it).  Keeps downstream walkers simple.
            if (w > 0 && DIFF_OP(out[w - 1]) == DIFF_EQ)
                out[w - 1] = DIFF_ENTRY(DIFF_EQ,
                                        DIFF_LEN(out[w - 1]) + len);
            else
                out[w++] = e;
            k++;
            continue;
        }
        //  Maximal non-EQ run starting at k.
        u32 sum_ins = 0, sum_del = 0;
        while (k < n) {
            e32 ek = edl[2][k];
            u32 op_k  = DIFF_OP(ek);
            u32 len_k = DIFF_LEN(ek);
            if (op_k == DIFF_EQ) break;
            if (op_k == DIFF_INS) sum_ins += len_k;
            else if (op_k == DIFF_DEL) sum_del += len_k;
            k++;
        }
        //  Emit `INS sum, DEL sum` — the in-rm invariant.  Either may
        //  be zero (one-sided edit); skip empty entries.
        if (sum_ins > 0) out[w++] = DIFF_ENTRY(DIFF_INS, sum_ins);
        if (sum_del > 0) out[w++] = DIFF_ENTRY(DIFF_DEL, sum_del);
    }

    u32 ecap = (u32)(edl[1] - edl[2]);
    u32 final_n = (w < ecap) ? w : ecap;
    memcpy(edl[2], out, final_n * sizeof(e32));
    edl[0] = edl[2] + final_n;

    u32bFree(buf);
    done;
}
