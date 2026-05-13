//  WEAVE: token-level file history as four parallel arrays.
//  See WEAVE.h for the data layout and the splice-canonicalization rule.
//
//  Each operation (FromBlob, Diff, Merge) writes a fresh dst weave from
//  the inputs; the caller manages three weave instances and reuses them.
//
#include "WEAVE.h"

#include <string.h>

#include "abc/DIFF.h"
#include "abc/PRO.h"
#include "graf/BRAM.h"
#include "graf/NEIL.h"

// u64 diff specialization for token hashlets.
#define X(M, name) M##u64##name
#include "abc/DIFFx.h"
#undef X

// --- Buffer caps ---

#define WEAVE_TEXT_MAX  (64UL << 20)   // 64 MB token-text storage
#define WEAVE_TOK_MAX   (1 << 20)      // 1M tokens per weave

// --- init / reset / free ---

ok64 WEAVEInit(weave *w) {
    sane(w);
    memset(w, 0, sizeof(*w));
    call(u8bMap,   w->text,     WEAVE_TEXT_MAX);
    call(u32bMap,  w->toks,     WEAVE_TOK_MAX);
    call(u64bMap,  w->hashlets, WEAVE_TOK_MAX);
    call(inrmbMap, w->inrm,     WEAVE_TOK_MAX);
    done;
}

void WEAVEReset(weave *w) {
    if (!w) return;
    u8bReset  (w->text);
    u32bReset (w->toks);
    u64bReset (w->hashlets);
    inrmbReset(w->inrm);
}

void WEAVEFree(weave *w) {
    if (!w) return;
    if (w->text[0])     u8bUnMap  (w->text);
    if (w->toks[0])     u32bUnMap (w->toks);
    if (w->hashlets[0]) u64bUnMap (w->hashlets);
    if (w->inrm[0])     inrmbUnMap(w->inrm);
    memset(w, 0, sizeof(*w));
}

// --- Tokenization helper for FromBlob ---

typedef struct {
    weave *w;
    u8cp   base;
} weave_blob_ctx;

static ok64 weave_blob_cb(u8 tag, u8cs tok, void *vctx) {
    sane(vctx);
    weave_blob_ctx *ctx = vctx;
    //  Split any token containing '\n' so each emitted token sits on
    //  exactly one line.  Whitespace tokens always need this (so
    //  "end-of-line + next-line indent" don't fuse and drag a clean
    //  next line into a DEL region).  Multi-line tokens of any other
    //  kind — e.g. C char/string literals or block comments that the
    //  lexer hands us as one chunk, including malformed/unterminated
    //  cases on adversarial input — also need it: `WEAVEEmitDiff`'s
    //  windowing classifies tokens by their *start* line, so a
    //  multi-line token whose start line is outside a window orphans
    //  every byte it carries on the windowed lines, producing hunk
    //  text that begins mid-line and breaks line-based rendering.
    if ($len(tok) > 1 && memchr(tok[0], '\n', (size_t)$len(tok)) != NULL) {
        u8c *p = tok[0];
        u8c *e = tok[1];
        while (p < e) {
            u8c *q = p;
            while (q < e && *q != '\n') q++;
            u8c *seg_end = (q < e) ? q + 1 : e;
            u32  end_off = (u32)(seg_end - ctx->base);
            u8cs seg     = {p, seg_end};
            call(u32bFeed1, ctx->w->toks,     tok32Pack(tag, end_off));
            call(u64bFeed1, ctx->w->hashlets, RAPHash(seg));
            p = seg_end;
        }
        done;
    }
    u32 end = (u32)(tok[1] - ctx->base);
    call(u32bFeed1, ctx->w->toks,     tok32Pack(tag, end));
    call(u64bFeed1, ctx->w->hashlets, RAPHash(tok));
    done;
}

ok64 WEAVEFromBlob(weave *w, u8cs data, u8cs ext, u32 src) {
    sane(w);
    WEAVEReset(w);
    if ($empty(data)) done;

    //  Tokenizer writes tok32 end-offsets relative to data[0].  We
    //  then copy data verbatim into w->text, so those offsets are
    //  correct in w->text coordinates as well.
    weave_blob_ctx ctx = {.w = w, .base = data[0]};
    TOKstate st = {.data = {data[0], data[1]}, .cb = weave_blob_cb, .ctx = &ctx};
    TOKLexer(&st, ext);  // best effort

    //  Fallback / tail-fill: emit synthetic 'S' tokens covering any
    //  bytes the lexer didn't tokenize (binary input or mid-input bail
    //  on malformed source — unterminated string/comment, etc.;
    //  TOKLexer returns non-OK but we ignore it, "best effort" above).
    //  Without a synthetic, those bytes still get appended to `w->text`
    //  below and the WEAVEDiff round-trip would lose them.  Split the
    //  tail at every '\n' so each emitted token starts on a single
    //  line — `WEAVEEmitDiff`'s windowing classifies tokens by their
    //  start line, and a single multi-line synthetic would orphan the
    //  bytes whose line falls in a later window.
    u32 last_end = (u32bDataLen(w->toks) == 0) ? 0
        : tok32Offset(((u32cp)w->toks[1])
                      [u32bDataLen(w->toks) - 1]);
    u32 total = (u32)$len(data);
    {
        u32 lo = last_end;
        while (lo < total) {
            u32 hi = lo;
            while (hi < total && data[0][hi] != '\n') hi++;
            if (hi < total) hi++;  // include the '\n' itself
            u8cs piece = {data[0] + lo, data[0] + hi};
            call(u32bFeed1, w->toks, tok32Pack('S', hi));
            call(u64bFeed1, w->hashlets, RAPHash(piece));
            lo = hi;
        }
    }

    //  Append data bytes to w->text.  Offsets in w->toks now match.
    call(u8bFeed, w->text, data);

    //  Stamp inrm for every token: { in = src, rm = 0 }.
    u32 n = (u32)u32bDataLen(w->toks);
    for (u32 i = 0; i < n; i++) {
        inrm e = {.in = src, .rm = 0};
        call(inrmbFeed1, w->inrm, e);
    }
    done;
}

// --- Compose helpers (write into dst) ---

//  Append token i from a source (text+toks+hashlets) into dst, with the
//  given inrm.  Token i's bytes span [lo, hi) in src_text where
//  lo = tok32Offset(src_toks[i-1]) (or 0 for i==0) and
//  hi = tok32Offset(src_toks[i]).  dst's tok32 records the new
//  cumulative end-offset within dst->text.
static ok64 weave_append(weave *dst,
                         u8cp  src_text,
                         u32cp src_toks,
                         u64cp src_hash,
                         u32   i,
                         inrm  e) {
    sane(dst);
    u32 lo = (i == 0) ? 0 : tok32Offset(src_toks[i - 1]);
    u32 hi = tok32Offset(src_toks[i]);
    u8cs ts = {src_text + lo, src_text + hi};
    u8 tag = tok32Tag(src_toks[i]);
    call(u8bFeed, dst->text, ts);
    u32 new_end = (u32)u8bDataLen(dst->text);
    call(u32bFeed1,  dst->toks,     tok32Pack(tag, new_end));
    call(u64bFeed1,  dst->hashlets, src_hash[i]);
    call(inrmbFeed1, dst->inrm,     e);
    done;
}

// --- WEAVEDiff ---

ok64 WEAVEDiff(weave *dst, weave const *src, weave const *nu, u32 src_commit) {
    sane(dst);
    if (!src || !nu) return FAILSANITY;
    WEAVEReset(dst);

    //  Direct const reads via b[1] (DATA head) and b[2] (DATA end).
    u32cp  src_toks = (u32cp)src->toks[1];
    u32cp  src_toks_e = (u32cp)src->toks[2];
    u32    src_len = (u32)(src_toks_e - src_toks);
    u8cp   src_text = (u8cp)src->text[1];
    u64cp  src_hash = (u64cp)src->hashlets[1];
    inrmcp src_irm  = (inrmcp)src->inrm[1];

    u32cp  nu_toks  = (u32cp)nu->toks[1];
    u32cp  nu_toks_e = (u32cp)nu->toks[2];
    u32    nu_len   = (u32)(nu_toks_e - nu_toks);
    u8cp   nu_text  = (u8cp)nu->text[1];
    u64cp  nu_hash  = (u64cp)nu->hashlets[1];

    //  Empty src: copy nu wholesale, restamping in=src_commit on each.
    if (src_len == 0) {
        for (u32 i = 0; i < nu_len; i++) {
            inrm e = {.in = src_commit, .rm = 0};
            call(weave_append, dst, nu_text, nu_toks, nu_hash, i, e);
        }
        done;
    }

    //  Project alive src into three parallel views — hashlets (for the
    //  LCS), text bytes, and tok32 entries (rebased offsets).  The text
    //  + toks views are needed by NEIL's predicates (`NEILIsWS` peeks
    //  bytes; the boundary-shift pass scans for line/word breaks).
    //  Without NEIL the LCS happily matches whitespace tokens between
    //  unrelated lines, producing a weave where a deleted-then-inserted
    //  pair shares its surrounding `' '` / `\n` tokens — a meaningless
    //  "context" that pollutes both the diff hunks and downstream blame.
    Bu64 alive_h     = {};
    Bu8  alive_text  = {};
    Bu32 alive_toks  = {};
    Bi32 work        = {};
    Bu32 edlbuf      = {};

    __ = u64bAlloc(alive_h, src_len + 1); if (__ != OK) goto cleanup;
    u32 src_text_len = (u32)u8bDataLen(src->text);
    if (src_text_len == 0) src_text_len = 1;
    __ = u8bMap (alive_text, src_text_len + 1); if (__ != OK) goto cleanup;
    __ = u32bAlloc(alive_toks, src_len + 1);    if (__ != OK) goto cleanup;
    {
        u32 cum = 0;
        for (u32 i = 0; i < src_len; i++) {
            if (src_irm[i].rm != 0) continue;
            __ = u64bFeed1(alive_h, src_hash[i]); if (__ != OK) goto cleanup;
            u32 lo = (i == 0) ? 0 : tok32Offset(src_toks[i - 1]);
            u32 hi = tok32Offset(src_toks[i]);
            u8cs tb = {src_text + lo, src_text + hi};
            __ = u8bFeed(alive_text, tb); if (__ != OK) goto cleanup;
            cum += (hi - lo);
            u8 tag = tok32Tag(src_toks[i]);
            __ = u32bFeed1(alive_toks, tok32Pack(tag, cum));
            if (__ != OK) goto cleanup;
        }
    }

    u64 olen = u64bDataLen(alive_h);
    u64 nlen = (u64)nu_len;

    u64 work_sz = DIFFWorkSize(olen, nlen);
    u64 edl_sz  = DIFFEdlMaxEntries(olen, nlen);
    if (work_sz > 0) { __ = i32bAllocate(work,   work_sz); if (__ != OK) goto cleanup; }
    if (edl_sz  > 0) { __ = u32bAllocate(edlbuf, edl_sz);  if (__ != OK) goto cleanup; }

    u64cs oh = {u64bDataHead(alive_h), u64bDataHead(alive_h) + olen};
    u64cs nh = {nu_hash, nu_hash + nlen};

    e32g edlg = {edlbuf[0], edlbuf[3], edlbuf[0]};
    i32s ws = {i32bHead(work), i32bTerm(work)};
    //  Patience pre-pass: line-coherent anchors before token-level
    //  Myers.  Falls back internally to plain DIFFu64s when the
    //  input has no unique line anchors.
    ok64 diff_o = BRAMu64s(edlg, ws, oh, nh);
    if (diff_o != OK) {
        //  Fallback: replace alive prefix wholesale.
        edlg[1] = edlg[0];
        if (olen > 0) { *edlg[1]++ = DIFF_ENTRY(DIFF_DEL, (u32)olen); }
        if (nlen > 0) { *edlg[1]++ = DIFF_ENTRY(DIFF_INS, (u32)nlen); }
    } else {
        //  NEIL semantic cleanup on the EDL: kill false short equalities
        //  (typically lone whitespace / punctuation tokens that LCS-
        //  matched across unrelated content) and lossless boundary shift
        //  to align edits with line/word boundaries.  Both passes
        //  in-place.  The `walk` block below re-reads `edlg[0]` so it
        //  picks up the cleaned size.
        u32cs at_view = {(u32cp)u32bDataHead(alive_toks),
                         (u32cp)u32bDataHead(alive_toks) +
                                u32bDataLen(alive_toks)};
        u32cs nt_view = {nu_toks, nu_toks_e};
        u8cs  at_text = {u8bDataHead(alive_text),
                         u8bDataHead(alive_text) + u8bDataLen(alive_text)};
        u8cs  nt_text = {nu_text, nu_text + (size_t)u8bDataLen(nu->text)};
        NEILCleanup(edlg, at_view, nt_view, at_text, nt_text);
        NEILShift  (edlg, at_view, nt_view, at_text, nt_text);
    }
    e32c *ep = edlbuf[0];
    e32c *ee = edlg[0];

    //  Walk EDL, canonicalizing each non-EQ run to INS-then-DEL on the fly.
    u32 wi = 0;  // cursor in src (full, includes dead tokens)
    u32 ni = 0;  // cursor in nu (full)

    while (ep < ee) {
        u32 op  = DIFF_OP(*ep);
        u32 len = DIFF_LEN(*ep);

        if (op == DIFF_EQ) {
            for (u32 j = 0; j < len; j++) {
                //  Carry any dead src tokens through.
                while (wi < src_len && src_irm[wi].rm != 0) {
                    __ = weave_append(dst, src_text, src_toks, src_hash,
                                      wi, src_irm[wi]);
                    if (__ != OK) goto cleanup;
                    wi++;
                }
                if (wi < src_len) {
                    __ = weave_append(dst, src_text, src_toks, src_hash,
                                      wi, src_irm[wi]);
                    if (__ != OK) goto cleanup;
                    wi++;
                }
                ni++;   // EQ advances both src-alive cursor and nu cursor
            }
            ep++;
            continue;
        }

        //  Non-EQ run: gather totals.
        u32 sum_ins = 0, sum_del = 0;
        while (ep < ee && DIFF_OP(*ep) != DIFF_EQ) {
            u32 l = DIFF_LEN(*ep);
            if (DIFF_OP(*ep) == DIFF_INS) sum_ins += l;
            else                           sum_del += l;
            ep++;
        }

        //  Prefix/suffix lift: when LCS or NEIL leaves byte-equal
        //  tokens at the boundaries of a non-EQ run (typically because
        //  NEIL killed a small EQ between two edits, or because LCS
        //  couldn't pick up the match due to budget), recover them as
        //  EQ context.  Without this, the merged weave duplicates the
        //  same byte run with both `I` and `D` tags — see test/diff/
        //  03-stock-context for the regression repro.
        //
        //  Pre-collect indices of the next `sum_del` alive src tokens
        //  so prefix and suffix walks can index by position.
        Bu32 adi_buf = {};
        u32 prefix = 0, suffix = 0;
        u32 *adi = NULL;
        u32  adi_n = 0;
        if (sum_del > 0 && sum_ins > 0) {
            __ = u32bAllocate(adi_buf, sum_del);
            if (__ != OK) goto cleanup;
            adi = adi_buf[0];
            u32 wi_p = wi;
            while (adi_n < sum_del && wi_p < src_len) {
                if (src_irm[wi_p].rm == 0) adi[adi_n++] = wi_p;
                wi_p++;
            }

            u32 lim = (sum_ins < sum_del) ? sum_ins : sum_del;

            //  Forward prefix walk.
            while (prefix < lim && prefix < adi_n) {
                u32 ni_p = ni + prefix;
                u32 wi_q = adi[prefix];
                u32 nu_lo  = (ni_p == 0) ? 0
                           : tok32Offset(nu_toks[ni_p - 1]);
                u32 nu_hi  = tok32Offset(nu_toks[ni_p]);
                u32 src_lo = (wi_q == 0) ? 0
                           : tok32Offset(src_toks[wi_q - 1]);
                u32 src_hi = tok32Offset(src_toks[wi_q]);
                if (nu_hi - nu_lo != src_hi - src_lo) break;
                if (memcmp(nu_text  + nu_lo,
                           src_text + src_lo,
                           nu_hi - nu_lo) != 0) break;
                prefix++;
            }

            //  Backward suffix walk.  Bounded so prefix + suffix never
            //  exceeds either side's available token count.
            u32 max_sf = lim - prefix;
            while (suffix < max_sf) {
                u32 ni_p = ni + sum_ins - 1 - suffix;
                u32 wi_q = adi[sum_del - 1 - suffix];
                u32 nu_lo  = (ni_p == 0) ? 0
                           : tok32Offset(nu_toks[ni_p - 1]);
                u32 nu_hi  = tok32Offset(nu_toks[ni_p]);
                u32 src_lo = (wi_q == 0) ? 0
                           : tok32Offset(src_toks[wi_q - 1]);
                u32 src_hi = tok32Offset(src_toks[wi_q]);
                if (nu_hi - nu_lo != src_hi - src_lo) break;
                if (memcmp(nu_text  + nu_lo,
                           src_text + src_lo,
                           nu_hi - nu_lo) != 0) break;
                suffix++;
            }
        }
        u32bFree(adi_buf);

        //  Prefix lift: emit `prefix` tokens as EQ-context, carrying
        //  the src token's original inrm (these bytes lived in src and
        //  survive into nu — they were never touched by this diff
        //  step, the LCS just happened not to mark them so).  Advance
        //  both wi and ni in lockstep.
        for (u32 j = 0; j < prefix; j++) {
            while (wi < src_len && src_irm[wi].rm != 0) {
                __ = weave_append(dst, src_text, src_toks, src_hash,
                                  wi, src_irm[wi]);
                if (__ != OK) goto cleanup;
                wi++;
            }
            if (wi < src_len) {
                __ = weave_append(dst, src_text, src_toks, src_hash,
                                  wi, src_irm[wi]);
                if (__ != OK) goto cleanup;
                wi++;
            }
            ni++;
        }

        //  Remaining INS: nu tokens in (ni .. ni + remain_ins).
        u32 remain_ins = sum_ins - prefix - suffix;
        for (u32 j = 0; j < remain_ins; j++) {
            inrm e = {.in = src_commit, .rm = 0};
            __ = weave_append(dst, nu_text, nu_toks, nu_hash, ni, e);
            if (__ != OK) goto cleanup;
            ni++;
        }

        //  Remaining DEL: alive src tokens, rm = src_commit.
        u32 remain_del = sum_del - prefix - suffix;
        for (u32 j = 0; j < remain_del; j++) {
            while (wi < src_len && src_irm[wi].rm != 0) {
                __ = weave_append(dst, src_text, src_toks, src_hash,
                                  wi, src_irm[wi]);
                if (__ != OK) goto cleanup;
                wi++;
            }
            if (wi < src_len) {
                inrm e = src_irm[wi];
                e.rm = src_commit;
                __ = weave_append(dst, src_text, src_toks, src_hash,
                                  wi, e);
                if (__ != OK) goto cleanup;
                wi++;
            }
        }

        //  Suffix lift: same shape as prefix.  Emits `suffix` tokens
        //  as EQ-context to close the run.
        for (u32 j = 0; j < suffix; j++) {
            while (wi < src_len && src_irm[wi].rm != 0) {
                __ = weave_append(dst, src_text, src_toks, src_hash,
                                  wi, src_irm[wi]);
                if (__ != OK) goto cleanup;
                wi++;
            }
            if (wi < src_len) {
                __ = weave_append(dst, src_text, src_toks, src_hash,
                                  wi, src_irm[wi]);
                if (__ != OK) goto cleanup;
                wi++;
            }
            ni++;
        }
    }

    //  Tail: drain any remaining src tokens (all should be dead, but
    //  copy verbatim regardless to keep the invariant that dst
    //  contains every src token plus any inserts).
    while (wi < src_len) {
        __ = weave_append(dst, src_text, src_toks, src_hash, wi, src_irm[wi]);
        if (__ != OK) goto cleanup;
        wi++;
    }

cleanup:
    u64bFree(alive_h);
    if (alive_text[0]) u8bUnMap(alive_text);
    u32bFree(alive_toks);
    i32bFree(work);
    u32bFree(edlbuf);
    return __;
}

// --- WEAVEMerge ---
//
//  3-way merge of two weaves derived from a shared ancestor history.
//  See WEAVE.h for the doc comment.  Algorithm:
//
//    1. Diff the *full* hashlet streams of a and b (dead tokens are
//       part of the spine — both sides' WEAVEDiff outputs preserve them
//       so they align by hashlet).  NEIL cleanup runs on the EDL with
//       the same text+toks views WEAVEDiff uses.
//    2. Walk the EDL.  For each EQ token, reconcile (in, rm) per the
//       table below.  For each non-EQ run, gather a-only DELs and
//       b-only INSs.  When both sides have *alive* tokens whose bytes
//       agree, dedup to one copy with `in = min`.  When they differ,
//       emit both sides' tokens in order (a then b) with their
//       original inrm — the weave records both histories.  No marker
//       bytes ever land in dst.
//
//  EQ reconciliation (per-token):
//
//    | a.rm | b.rm |  out                                            |
//    |------|------|-------------------------------------------------|
//    |  0   |  0   |  rm=0, in = min(a.in, b.in)  (deterministic)    |
//    |  X   |  X   |  rm=X, in = min(a.in, b.in)                     |
//    |  X   |  0   |  rm=X (a deleted; deleter wins)                 |
//    |  0   |  X   |  rm=X (b deleted)                               |
//    |  X   |  Y   |  rm = min(X, Y) (both deleted, dedup; arbitrary |
//    |      |      |               but deterministic)                |
//
//  In all cases hashlet/text/tag come from a (they are byte-equal by
//  hashlet).  Splice canonicalization within non-EQ runs: a's tokens
//  precede b's tokens — same shape as WEAVEDiff.

//  Total byte length of `count` consecutive tokens starting at `start`
//  in (text, toks); NULL-safe by virtue of count==0 short-circuit.
static u32 weave_byte_span(u8cp text, u32cp toks, u32 start, u32 count) {
    if (count == 0) return 0;
    u32 lo = (start == 0) ? 0 : tok32Offset(toks[start - 1]);
    u32 hi = tok32Offset(toks[start + count - 1]);
    (void)text;
    return hi - lo;
}

//  Returns YES iff the byte sequences of `acount` tokens of (a_text,
//  a_toks) starting at ai equal those of `bcount` tokens of (b_text,
//  b_toks) starting at bi.
static b8 weave_byte_equal(u8cp a_text, u32cp a_toks, u32 ai, u32 acount,
                           u8cp b_text, u32cp b_toks, u32 bi, u32 bcount) {
    u32 alen = weave_byte_span(a_text, a_toks, ai, acount);
    u32 blen = weave_byte_span(b_text, b_toks, bi, bcount);
    if (alen != blen) return NO;
    if (alen == 0) return YES;
    u32 a_lo = (ai == 0) ? 0 : tok32Offset(a_toks[ai - 1]);
    u32 b_lo = (bi == 0) ? 0 : tok32Offset(b_toks[bi - 1]);
    return memcmp(a_text + a_lo, b_text + b_lo, alen) == 0;
}

ok64 WEAVEMerge(weave *dst, weave const *a, weave const *b) {
    sane(dst);
    if (!a || !b) return FAILSANITY;
    WEAVEReset(dst);

    u32cp  a_toks   = (u32cp)a->toks[1];
    u32cp  a_toks_e = (u32cp)a->toks[2];
    u32    a_len    = (u32)(a_toks_e - a_toks);
    u8cp   a_text   = (u8cp)a->text[1];
    u64cp  a_hash   = (u64cp)a->hashlets[1];
    inrmcp a_irm    = (inrmcp)a->inrm[1];

    u32cp  b_toks   = (u32cp)b->toks[1];
    u32cp  b_toks_e = (u32cp)b->toks[2];
    u32    b_len    = (u32)(b_toks_e - b_toks);
    u8cp   b_text   = (u8cp)b->text[1];
    u64cp  b_hash   = (u64cp)b->hashlets[1];
    inrmcp b_irm    = (inrmcp)b->inrm[1];

    //  Trivial: one side empty — copy the other verbatim.
    if (a_len == 0) {
        for (u32 i = 0; i < b_len; i++) {
            __ = weave_append(dst, b_text, b_toks, b_hash, i, b_irm[i]);
            if (__ != OK) return __;
        }
        done;
    }
    if (b_len == 0) {
        for (u32 i = 0; i < a_len; i++) {
            __ = weave_append(dst, a_text, a_toks, a_hash, i, a_irm[i]);
            if (__ != OK) return __;
        }
        done;
    }

    Bi32 work   = {};
    Bu32 edlbuf = {};
    Bu64 ah_buf = {};   // synthetic hashlets keyed on (hash, in)
    Bu64 bh_buf = {};

    u64 olen = (u64)a_len;
    u64 nlen = (u64)b_len;
    u64 work_sz = DIFFWorkSize(olen, nlen);
    u64 edl_sz  = DIFFEdlMaxEntries(olen, nlen);

    if (work_sz > 0) { __ = i32bAllocate(work,   work_sz); if (__ != OK) goto cleanup; }
    if (edl_sz  > 0) { __ = u32bAllocate(edlbuf, edl_sz);  if (__ != OK) goto cleanup; }
    __ = u64bAlloc(ah_buf, olen + 1); if (__ != OK) goto cleanup;
    __ = u64bAlloc(bh_buf, nlen + 1); if (__ != OK) goto cleanup;

    //  Bias the LCS toward provenance-aware matches: encode `in` into
    //  the hashlet so tokens only LCS-match when they share BOTH the
    //  byte content AND the introducing-commit stamp.  This stops
    //  Myers from spuriously aligning a-only `int` (in=A) with the
    //  base `int` (in=0) just because the bytes match — the spine
    //  recovers cleanly when both weaves were built off a common
    //  base via WEAVEDiff (they share the base's in-stamps).
    //
    //  Mixing function: `hash * 0x9e3779b97f4a7c15 + in`.  Cheap,
    //  collision-resistant enough for diff alignment.
    for (u32 i = 0; i < a_len; i++) {
        u64 h = a_hash[i] * 0x9e3779b97f4a7c15ULL + (u64)a_irm[i].in;
        __ = u64bFeed1(ah_buf, h); if (__ != OK) goto cleanup;
    }
    for (u32 i = 0; i < b_len; i++) {
        u64 h = b_hash[i] * 0x9e3779b97f4a7c15ULL + (u64)b_irm[i].in;
        __ = u64bFeed1(bh_buf, h); if (__ != OK) goto cleanup;
    }

    u64cs ah = {u64bDataHead(ah_buf), u64bDataHead(ah_buf) + olen};
    u64cs bh = {u64bDataHead(bh_buf), u64bDataHead(bh_buf) + nlen};

    e32g edlg = {edlbuf[0], edlbuf[3], edlbuf[0]};
    i32s ws = {i32bHead(work), i32bTerm(work)};
    ok64 diff_o = DIFFu64s(edlg, ws, ah, bh);
    if (diff_o != OK) {
        //  Fallback: replace a wholesale.
        edlg[1] = edlg[0];
        if (olen > 0) { *edlg[1]++ = DIFF_ENTRY(DIFF_DEL, (u32)olen); }
        if (nlen > 0) { *edlg[1]++ = DIFF_ENTRY(DIFF_INS, (u32)nlen); }
    } else {
        //  NEIL on the full streams: kills false short EQs (lone
        //  `int` / whitespace tokens that the LCS happily matches
        //  across unrelated regions), then lossless boundary shift
        //  to align edits with line/word breaks.  Same pipeline as
        //  WEAVEDiff.
        u32cs at_view = {a_toks, a_toks_e};
        u32cs bt_view = {b_toks, b_toks_e};
        u8cs  at_text = {a_text, a_text + (size_t)u8bDataLen(a->text)};
        u8cs  bt_text = {b_text, b_text + (size_t)u8bDataLen(b->text)};
        NEILCleanup(edlg, at_view, bt_view, at_text, bt_text);
        NEILShift  (edlg, at_view, bt_view, at_text, bt_text);
    }

    e32c *ep = edlbuf[0];
    e32c *ee = edlg[0];

    u32 ai = 0;  // cursor in a
    u32 bi = 0;  // cursor in b

    while (ep < ee) {
        u32 op  = DIFF_OP(*ep);
        u32 len = DIFF_LEN(*ep);

        if (op == DIFF_EQ) {
            for (u32 j = 0; j < len; j++) {
                if (ai >= a_len || bi >= b_len) break;
                inrm ea = a_irm[ai];
                inrm eb = b_irm[bi];
                inrm out;
                //  Reconcile (in, rm) per the table in the header
                //  comment.  in = min for determinism; rm: deleter
                //  wins, both-deleted dedup to min.
                out.in = (ea.in < eb.in) ? ea.in : eb.in;
                if (ea.rm == 0 && eb.rm == 0) {
                    out.rm = 0;
                } else if (ea.rm != 0 && eb.rm == 0) {
                    out.rm = ea.rm;
                } else if (ea.rm == 0 && eb.rm != 0) {
                    out.rm = eb.rm;
                } else {
                    out.rm = (ea.rm < eb.rm) ? ea.rm : eb.rm;
                }
                __ = weave_append(dst, a_text, a_toks, a_hash, ai, out);
                if (__ != OK) goto cleanup;
                ai++;
                bi++;
            }
            ep++;
            continue;
        }

        //  Non-EQ run: gather a-only DELs and b-only INSs.
        u32 sum_del = 0, sum_ins = 0;
        while (ep < ee && DIFF_OP(*ep) != DIFF_EQ) {
            u32 l = DIFF_LEN(*ep);
            if (DIFF_OP(*ep) == DIFF_INS) sum_ins += l;
            else                           sum_del += l;
            ep++;
        }

        //  Count alive (rm == 0) tokens on each side of the run.
        u32 a_alive = 0, b_alive = 0;
        for (u32 j = 0; j < sum_del && ai + j < a_len; j++)
            if (a_irm[ai + j].rm == 0) a_alive++;
        for (u32 j = 0; j < sum_ins && bi + j < b_len; j++)
            if (b_irm[bi + j].rm == 0) b_alive++;

        //  Compute the longest common prefix of alive tokens between
        //  a-side and b-side of this non-EQ run.  Dedup only when one
        //  side is a strict alive-prefix of the other — that is the
        //  "same edit reached both sides through different attribution"
        //  shape (e.g. ours absorbed theirs's commits via foster).
        //  Partial matches inside otherwise-divergent blocks fall
        //  through to the disjoint-insert branch so the renderer can
        //  wrap them in conflict markers.
        //
        //  Regressions this rule fixes:
        //    - test/patch/15-ancestor-skip step 2: ours had {sub, mul}
        //      via foster absorption, theirs had {sub, mul, divmod}.
        //      Strict prefix (a fully in b) → dedup sub+mul, emit
        //      divmod as theirs-only INS.
        //    - test/patch/04-conflict-resolve: ours and theirs both
        //      inserted different multi-line blocks starting with
        //      "int" / "while".  Only the first ~1 token matches as
        //      prefix — far short of either side's alive count — so
        //      no dedup; both blocks emit and the renderer wraps them.
        u32 dedup_count = 0;
        u32 dedup_ja    = 0;
        u32 dedup_jb    = 0;
        if (a_alive > 0 && b_alive > 0) {
            u32 ja = 0, jb = 0;
            while (ja < sum_del && jb < sum_ins) {
                while (ja < sum_del && a_irm[ai + ja].rm != 0) ja++;
                while (jb < sum_ins && b_irm[bi + jb].rm != 0) jb++;
                if (ja >= sum_del || jb >= sum_ins) break;
                if (!weave_byte_equal(a_text, a_toks, ai + ja, 1,
                                      b_text, b_toks, bi + jb, 1)) break;
                ja++; jb++; dedup_count++;
            }
            dedup_ja = ja;
            dedup_jb = jb;
        }
        //  Strict alive-prefix containment: shorter side must match
        //  fully into the longer side's prefix.
        u32 alive_min = (a_alive < b_alive) ? a_alive : b_alive;
        b8 alive_agree = (dedup_count > 0 && dedup_count == alive_min);
        if (!alive_agree) { dedup_count = 0; dedup_ja = 0; dedup_jb = 0; }

        if (alive_agree) {
            //  Deduped prefix: emit alive pairs once with `in = min`,
            //  preserving each side's dead tokens that intersperse
            //  the prefix in their original positions (a's deads
            //  first, then b's).  Surplus alive tokens past
            //  `dedup_ja`/`dedup_jb` fall through to the disjoint-
            //  insert tail below.
            u32 ja = 0, jb = 0;
            //  a's leading dead tokens before the dedup prefix.
            while (ja < dedup_ja && a_irm[ai + ja].rm != 0) {
                __ = weave_append(dst, a_text, a_toks, a_hash,
                                  ai + ja, a_irm[ai + ja]);
                if (__ != OK) goto cleanup;
                ja++;
            }
            //  b's leading dead tokens.
            while (jb < dedup_jb && b_irm[bi + jb].rm != 0) {
                __ = weave_append(dst, b_text, b_toks, b_hash,
                                  bi + jb, b_irm[bi + jb]);
                if (__ != OK) goto cleanup;
                jb++;
            }
            //  Emit the deduped alive pairs.  Dead tokens encountered
            //  between alive pairs are passed through (a's side only —
            //  b's interspersed deads are dropped to avoid duplicate
            //  text; they were aligned in the EQ runs around this run).
            //
            //  Deduped tokens get `in = 0` (pre-timeframe spine) — the
            //  bytes reached both sides through different attribution
            //  (e.g. foster absorption), so neither side's `in` value
            //  alone reflects the truth.  WEAVEEmitMerged treats
            //  `in == 0` as member-of-every-predicate, which is what
            //  shared content needs to avoid being grouped with one
            //  side's non-spine tokens into a spurious conflict run.
            u32 acnt = 0;
            while (acnt < dedup_count && ja < dedup_ja && jb < dedup_jb) {
                while (ja < dedup_ja && a_irm[ai + ja].rm != 0) {
                    __ = weave_append(dst, a_text, a_toks, a_hash,
                                      ai + ja, a_irm[ai + ja]);
                    if (__ != OK) goto cleanup;
                    ja++;
                }
                while (jb < dedup_jb && b_irm[bi + jb].rm != 0) jb++;
                if (ja >= dedup_ja || jb >= dedup_jb) break;
                inrm out = {.in = 0, .rm = 0};
                __ = weave_append(dst, a_text, a_toks, a_hash,
                                  ai + ja, out);
                if (__ != OK) goto cleanup;
                ja++; jb++; acnt++;
            }
            //  Advance cursors past the deduped prefix.  The surplus
            //  (anything past dedup_ja on a, dedup_jb on b) gets
            //  emitted by the disjoint-insert tail.
            ai += dedup_ja;
            bi += dedup_jb;
            sum_del -= dedup_ja;
            sum_ins -= dedup_jb;
        }

        //  Disjoint inserts / pure deletes / post-dedup surplus —
        //  canonical splice order: a's tokens first, then b's, with
        //  each side's original inrm.  When no dedup ran, sum_del /
        //  sum_ins are the whole-run counts; after partial dedup they
        //  are the trailing remainder.
        for (u32 j = 0; j < sum_del && ai < a_len; j++, ai++) {
            __ = weave_append(dst, a_text, a_toks, a_hash, ai, a_irm[ai]);
            if (__ != OK) goto cleanup;
        }
        for (u32 j = 0; j < sum_ins && bi < b_len; j++, bi++) {
            __ = weave_append(dst, b_text, b_toks, b_hash, bi, b_irm[bi]);
            if (__ != OK) goto cleanup;
        }
    }

    //  Drain any tail (typically empty if the EDL was complete).
    while (ai < a_len) {
        __ = weave_append(dst, a_text, a_toks, a_hash, ai, a_irm[ai]);
        if (__ != OK) goto cleanup;
        ai++;
    }
    while (bi < b_len) {
        __ = weave_append(dst, b_text, b_toks, b_hash, bi, b_irm[bi]);
        if (__ != OK) goto cleanup;
        bi++;
    }

cleanup:
    i32bFree(work);
    u32bFree(edlbuf);
    u64bFree(ah_buf);
    u64bFree(bh_buf);
    return __;
}

// --- WEAVEReplay ---
//
//  See WEAVE.h.  Algorithm:
//
//    work = parents[0]
//    for k in 1..nparents:  work = WEAVEMerge(work, parents[k])
//    nu   = WEAVEFromBlob(result_blob, ext, merge_in)
//    dst  = WEAVEDiff(work, nu, merge_in)
//
//  WEAVEMerge combines histories without storing markers.  WEAVEDiff
//  resolves the combined-but-possibly-divergent merge against the
//  actually-shipped bytes: bytes the human added stamp `in=merge_in`
//  via the INS path; tokens the human dropped stamp `rm=merge_in`
//  via the DEL path.

ok64 WEAVEReplay(weave *dst,
                 weave const *const *parents, u32 nparents,
                 u8cs result_blob, u8cs ext,
                 u32 merge_in) {
    sane(dst);
    if (!parents || nparents == 0) return FAILSANITY;
    WEAVEReset(dst);

    weave work = {}, swap = {}, nu = {};
    __ = WEAVEInit(&work);
    if (__ != OK) return __;
    __ = WEAVEInit(&swap);
    if (__ != OK) { WEAVEFree(&work); return __; }
    __ = WEAVEInit(&nu);
    if (__ != OK) { WEAVEFree(&work); WEAVEFree(&swap); return __; }

    //  Pairwise reduce parents into `work`.  Bootstrap by merging the
    //  first parent with itself (clean copy with reconciled inrm).
    if (parents[0] == NULL) { __ = FAILSANITY; goto cleanup; }
    __ = WEAVEMerge(&work, parents[0], parents[0]);
    if (__ != OK) goto cleanup;

    for (u32 k = 1; k < nparents; k++) {
        if (parents[k] == NULL) continue;
        __ = WEAVEMerge(&swap, &work, parents[k]);
        if (__ != OK) goto cleanup;
        //  Swap the buffer headers between work and swap so the next
        //  iteration writes into a fresh (reset-on-entry) dst.  The
        //  weave struct is plain (4 buffer arrays of pointers); copy
        //  by memcpy to avoid array-assignment quirks.
        weave tmp;
        memcpy(&tmp,  &work, sizeof(weave));
        memcpy(&work, &swap, sizeof(weave));
        memcpy(&swap, &tmp,  sizeof(weave));
    }

    //  Build a one-version weave for the result blob.
    __ = WEAVEFromBlob(&nu, result_blob, ext, merge_in);
    if (__ != OK) goto cleanup;

    //  WEAVEDiff(work, nu, merge_in) reconciles into dst.
    __ = WEAVEDiff(dst, &work, &nu, merge_in);

cleanup:
    WEAVEFree(&work);
    WEAVEFree(&swap);
    WEAVEFree(&nu);
    return __;
}

// --- WEAVEEmitDiff ---
//
//  Emits one or more hunks per file, each covering a cluster of changed
//  lines flanked by `WEAVE_CTX_LINES` of context (the conventional
//  unified-diff `@@ -X,Y +A,B @@` shape minus the line-count header).
//  Per kept token (anything `alive_from || alive_to`):
//    alive_to && !alive_from → 'I' (inserted on to-side)
//    alive_from && !alive_to → 'D' (deleted on to-side)
//    alive_from && alive_to  → ' ' (context, unchanged)
//  Each tok in the hunk's `toks` carries a lexer tag (top 5 bits) and
//  a 2-bit diff side (eq/in/rm).  Tokens tile the hunk's `text` exactly.
//  See `dog/HUNK.c` for the renderer.
//  TODO: NEIL-style cleanup happens upstream in `WEAVEDiff` (ride the
//  EDL there); WEAVEEmitDiff trusts its weave's classification.

#define WEAVE_CTX_LINES 3

//  Per-token classification + line tracking, used by both passes.
//  Returns the kind of `'I'` / `'D'` / `' '`, or 0 to skip.
static u8 weave_diff_classify(inrm e,
                               WEAVEsetfn in_from, void *from_ctx,
                               WEAVEsetfn in_to,   void *to_ctx) {
    b8 af = in_from(e.in, from_ctx) &&
            (e.rm == 0 || !in_from(e.rm, from_ctx));
    b8 at = in_to  (e.in, to_ctx) &&
            (e.rm == 0 || !in_to  (e.rm, to_ctx));
    if (at && !af) return 'I';
    if (af && !at) return 'D';
    if (af && at)  return ' ';
    return 0;
}

ok64 WEAVEEmitDiff(weave const *w, u8cs name,
                   WEAVEsetfn in_from, void *from_ctx,
                   WEAVEsetfn in_to,   void *to_ctx,
                   HUNKcb cb, void *cb_ctx) {
    sane(w && cb && in_from && in_to);

    u32cp toks   = (u32cp)w->toks[1];
    u32cp toks_e = (u32cp)w->toks[2];
    u32   ntok   = (u32)(toks_e - toks);
    inrmcp irm   = (inrmcp)w->inrm[1];
    u8cp   text  = (u8cp)w->text[1];
    if (ntok == 0) done;

    //  Pass 1: walk kept tokens, count newlines (line index in the
    //  merged stream), mark every line that contains an I or D token.
    //  total_lines is one past the highest line index we'll see.
    u32 total_lines_est = 1;
    {
        u32 tlen = (u32)u8bDataLen(w->text);
        for (u32 b = 0; b < tlen; b++) if (text[b] == '\n') total_lines_est++;
    }

    Bu8 changed = {};
    call(u8bMap, changed, total_lines_est + 4);
    memset(u8bDataHead(changed), 0, total_lines_est);
    u8bFed(changed, total_lines_est);

    u8 *cmark = (u8 *)u8bDataHead(changed);
    u32 cur_line = 0;
    for (u32 i = 0; i < ntok; i++) {
        u8 tag = weave_diff_classify(irm[i], in_from, from_ctx,
                                            in_to,   to_ctx);
        if (tag == 0) continue;

        u32 lo = (i == 0) ? 0 : tok32Offset(toks[i - 1]);
        u32 hi = tok32Offset(toks[i]);
        u32 nl = 0;
        for (u32 b = lo; b < hi; b++) if (text[b] == '\n') nl++;

        if (tag == 'I' || tag == 'D') {
            //  Mark the line ABOVE too — splitting whitespace tokens
            //  at '\n' (in `weave_blob_cb`) makes line marking sharper
            //  but can leave a pure-insertion's "before context" out of
            //  the window; including the prior line restores the
            //  natural unified-diff "show the line above the insert"
            //  behaviour without overshooting context.
            if (cur_line > 0) cmark[cur_line - 1] = 1;
            for (u32 l = cur_line; l <= cur_line + nl && l < total_lines_est; l++)
                cmark[l] = 1;
        }
        cur_line += nl;
    }
    u32 total_lines = cur_line + 1;
    if (total_lines > total_lines_est) total_lines = total_lines_est;

    //  Pass 2: cluster changed lines into visible windows.  Adjacent
    //  changed regions whose context (CTX_LINES on each side) overlaps
    //  fold into one window.
    Bu32 windows = {};
    call(u32bMap, windows, (total_lines + 4) * 2);
    u32 *wbuf = (u32 *)u32bDataHead(windows);
    u32 nwin = 0;
    {
        u32 i = 0;
        while (i < total_lines) {
            if (!cmark[i]) { i++; continue; }
            u32 cluster_first = i;
            u32 cluster_last  = i;
            i++;
            //  Extend cluster while the next change is within
            //  2*CTX_LINES (i.e. its context overlaps ours).
            while (i < total_lines) {
                if (cmark[i]) { cluster_last = i; i++; continue; }
                u32 j = i;
                while (j < total_lines && !cmark[j] &&
                       j - cluster_last <= 2 * WEAVE_CTX_LINES) j++;
                if (j < total_lines && cmark[j]) {
                    cluster_last = j; i = j + 1;
                } else break;
            }
            u32 lo = (cluster_first > WEAVE_CTX_LINES)
                     ? cluster_first - WEAVE_CTX_LINES : 0;
            u32 hi = cluster_last + WEAVE_CTX_LINES;
            if (hi >= total_lines) hi = total_lines - 1;
            wbuf[nwin * 2]     = lo;
            wbuf[nwin * 2 + 1] = hi;
            nwin++;
        }
    }
    u32bFed(windows, nwin * 2);

    if (nwin == 0) {
        u8bUnMap(changed);
        u32bUnMap(windows);
        done;
    }

    //  Pass 3: emit one hunk per window.  Walk tokens once, accumulate
    //  output for the active window, flush + advance when we cross a
    //  window boundary.
    Bu8  outtext = {};
    Bu32 outtoks = {};
    call(u8bMap,  outtext, 16UL << 20);
    call(u32bMap, outtoks, 1UL << 16);

    ok64 ret = OK;
    u32 wi = 0;          // active window index
    u32 win_lo = wbuf[0];
    u32 win_hi = wbuf[1];
    cur_line = 0;
    b8 hunk_open = NO;

    #define FLUSH_HUNK() do {                                          \
        if (hunk_open) {                                               \
            hunk hk = {};                                              \
            $mv(hk.uri, name);                                         \
            hk.text[0] = u8bDataHead(outtext);                         \
            hk.text[1] = u8bDataHead(outtext) + u8bDataLen(outtext);   \
            hk.toks[0] = (tok32c *)u32bDataHead(outtoks);              \
            hk.toks[1] = (tok32c *)u32bDataHead(outtoks)               \
                       + u32bDataLen(outtoks);                         \
            ok64 _r = cb(&hk, cb_ctx);                                 \
            if (_r != OK) ret = _r;                                    \
            u8bReset(outtext);                                         \
            u32bReset(outtoks);                                        \
            hunk_open = NO;                                            \
        }                                                              \
    } while (0)

    for (u32 i = 0; i < ntok; i++) {
        u8 tag = weave_diff_classify(irm[i], in_from, from_ctx,
                                            in_to,   to_ctx);
        if (tag == 0) continue;

        u32 lo = (i == 0) ? 0 : tok32Offset(toks[i - 1]);
        u32 hi = tok32Offset(toks[i]);
        u32 nl = 0;
        for (u32 b = lo; b < hi; b++) if (text[b] == '\n') nl++;

        //  Advance past finished windows.
        while (wi < nwin && cur_line > win_hi) {
            FLUSH_HUNK();
            wi++;
            if (wi < nwin) {
                win_lo = wbuf[wi * 2];
                win_hi = wbuf[wi * 2 + 1];
            }
        }
        if (wi >= nwin) break;

        //  Token's start line determines window membership.  We treat
        //  any token whose start line is inside the window as visible.
        if (cur_line >= win_lo && cur_line <= win_hi) {
            u8cs tb = {text + lo, text + hi};
            ok64 fo = u8bFeed(outtext, tb);
            if (fo != OK) { ret = fo; goto cleanup; }
            //  Carry the lexer's syntax tag plus the diff side
            //  (eq/in/rm) through into the hunk's toks stream.
            u8 syntag = tok32Tag(toks[i]);
            u8 side = (tag == 'I') ? TOK_SIDE_IN
                    : (tag == 'D') ? TOK_SIDE_RM
                    :                TOK_SIDE_EQ;
            fo = u32bFeed1(outtoks,
                tok32PackSide(syntag, side,
                              (u32)u8bDataLen(outtext)));
            if (fo != OK) { ret = fo; goto cleanup; }
            hunk_open = YES;
        }
        cur_line += nl;
    }

    //  Final flush: any tokens past the last window are dropped; the
    //  open window (if any) emits its accumulated hunk now.
    FLUSH_HUNK();

    #undef FLUSH_HUNK

cleanup:
    u8bUnMap(outtext);
    u32bUnMap(outtoks);
    u8bUnMap(changed);
    u32bUnMap(windows);
    return ret;
}

// --- WEAVEEmitMerged ---
//
//  Conflict-aware render of a merged weave's alive bytes.  See
//  WEAVE.h for the contract.  Algorithm:
//
//    1. Walk the merged weave's alive tokens in weave order.  For
//       each, compute its membership bitmask `m` (one bit per
//       supplied predicate; `in == 0` → all-bits-set spine).
//    2. Tokens with `m == spine_mask` (member of every predicate)
//       emit verbatim — they are shared-spine context.
//    3. A maximal stretch of non-spine tokens forms a non-EQ run.
//       Detect conflict by scanning the run: two alive tokens with
//       disjoint memberships (`m1 & m2 == 0`) → conflict.
//    4. Conflict run → emit `<<<<`, per-distinct-membership cluster
//       bytes interleaved with `||||`, `>>>>`.  Non-conflict run →
//       emit alive bytes verbatim.
//
//  Implementation notes: membership is recomputed per token (cheap —
//  npreds bounded; predicates are small bitset lookups).  Distinct
//  memberships per run are recorded in a tiny stack array (cap 32);
//  in practice 2-way merges have at most 2 non-spine memberships.

#define WEAVE_EMIT_MAX_PREDS  32
#define WEAVE_EMIT_MAX_GROUPS 32

static u32 weave_emit_membership(u32 in,
                                 WEAVEsetfn const *preds,
                                 void *const *ctxs,
                                 u32 npreds, u32 spine_mask) {
    if (in == 0) return spine_mask;        // pre-timeframe → spine
    u32 m = 0;
    for (u32 p = 0; p < npreds; p++)
        if (preds[p] && preds[p](in, ctxs ? ctxs[p] : NULL))
            m |= (1u << p);
    return m;
}

static ok64 weave_emit_token(u8b out, u8cp text, u32cp toks, u32 i) {
    u32 lo = (i == 0) ? 0 : tok32Offset(toks[i - 1]);
    u32 hi = tok32Offset(toks[i]);
    u8cs tb = {text + lo, text + hi};
    return u8bFeed(out, tb);
}

//  Second-pass reframer for `WEAVEEmitMerged`.  The streaming emit
//  drops `<<<<` / `||||` / `>>>>` at token boundaries, which is
//  desirable for tiny inline edits (a single word swap inside an
//  otherwise-shared line) but produces syntactically broken halves
//  for substantial conflicts — picking one side leaves an incoherent
//  line like `value > \nLOCAL\n) {`.
//
//  Per conflict block, compare cluster bytes against the bytes of
//  the surrounding line(s):
//    * cluster_bytes * 4  <  line_bytes  → keep markers inline.
//    * otherwise → rewrite the block so every cluster is whole-line:
//      the shared prefix (last LF before `<<<<`) and shared suffix
//      (next LF after `>>>>`) are spliced into each cluster, and
//      markers sit on their own lines.
//
//  `cluster_bytes` measures content bytes only — interior `||||`
//  marker bytes are subtracted.  `line_bytes` spans the entire
//  affected line(s) so multi-line conflicts (clusters with internal
//  LFs) always trip the line-level branch.
static ok64 weave_realign_conflicts(u8b out) {
    sane(1);

    u32 n = (u32)u8bDataLen(out);
    if (n < 12) done;       // shorter than `<<<<||||>>>>`

    Bu8 src = {};
    call(u8bMap, src, (size_t)n + 16);
    call(u8bFeed, src, u8bDataC(out));
    u8bReset(out);
    u8cp sp = u8bDataHead(src);

    a_cstr(sl_open,  "<<<<");
    a_cstr(sl_mid,   "||||");
    a_cstr(sl_close, ">>>>");
    a_cstr(lf,       "\n");

    u32 i = 0;
    while (i < n) {
        b8 at_open =
            (i + 4 <= n) && (memcmp(sp + i, "<<<<", 4) == 0);
        if (!at_open) {
            (void)u8bFeed1(out, sp[i]);
            i++;
            continue;
        }

        //  Find matching `||||`* and `>>>>`.  Nested `<<<<` aborts.
        u32 mids[WEAVE_EMIT_MAX_GROUPS];
        u32 nmids = 0;
        u32 close_pos = 0;
        b8  closed = NO;
        u32 j = i + 4;
        while (j + 4 <= n) {
            if (memcmp(sp + j, "<<<<", 4) == 0) break;
            if (memcmp(sp + j, ">>>>", 4) == 0) {
                close_pos = j; closed = YES; break;
            }
            if (memcmp(sp + j, "||||", 4) == 0) {
                if (nmids < WEAVE_EMIT_MAX_GROUPS) mids[nmids++] = j;
                j += 4;
                continue;
            }
            j++;
        }
        if (!closed) {
            (void)u8bFeed1(out, sp[i]);
            i++;
            continue;
        }

        u32 conflict_end = close_pos + 4;

        //  Surrounding line: last LF before `<<<<` → first LF after
        //  `>>>>`.  Indices into `src`.
        u32 line_lo = i;
        while (line_lo > 0 && sp[line_lo - 1] != '\n') line_lo--;
        u32 line_hi = conflict_end;
        while (line_hi < n && sp[line_hi] != '\n') line_hi++;

        u32 line_bytes    = line_hi - line_lo;
        u32 cluster_bytes = close_pos - (i + 4);
        if (cluster_bytes >= 4u * nmids)
            cluster_bytes -= 4u * nmids;

        b8 line_level = (cluster_bytes * 4 >= line_bytes);

        if (!line_level) {
            //  Inline: copy the block verbatim.
            u8cs blk = {sp + i, sp + conflict_end};
            call(u8bFeed, out, blk);
            i = conflict_end;
            continue;
        }

        //  Line-level: rewind out by the shared prefix bytes already
        //  emitted (line_lo .. i), then splice prefix + cluster +
        //  suffix into each side and surround with line-anchored
        //  markers.
        u32 prefix_len = i - line_lo;
        if (prefix_len > 0) u8bShed(out, prefix_len);

        //  Marker positions: pos[0] = `<<<<`, pos[1..nmids] = `||||`,
        //  pos[nmids+1] = `>>>>`.  Cluster k = [pos[k]+4, pos[k+1]).
        u32 pos[WEAVE_EMIT_MAX_GROUPS + 2];
        u32 npos = 0;
        pos[npos++] = i;
        for (u32 m = 0; m < nmids; m++) pos[npos++] = mids[m];
        pos[npos++] = close_pos;
        u32 ngroups = npos - 1;

        u8cs prefix_s = {sp + line_lo, sp + i};
        u8cs suffix_s = {sp + conflict_end, sp + line_hi};

        call(u8bFeed, out, sl_open);
        call(u8bFeed, out, lf);
        for (u32 g = 0; g < ngroups; g++) {
            if (g > 0) {
                call(u8bFeed, out, sl_mid);
                call(u8bFeed, out, lf);
            }
            if (prefix_s[1] > prefix_s[0]) call(u8bFeed, out, prefix_s);
            u8cs c_s = {sp + pos[g] + 4, sp + pos[g + 1]};
            if (c_s[1] > c_s[0]) call(u8bFeed, out, c_s);
            if (suffix_s[1] > suffix_s[0]) call(u8bFeed, out, suffix_s);
            size_t olen = u8bDataLen(out);
            if (olen == 0 || u8bDataHead(out)[olen - 1] != '\n')
                call(u8bFeed, out, lf);
        }
        call(u8bFeed, out, sl_close);
        call(u8bFeed, out, lf);

        //  Skip the original suffix bytes (already spliced into the
        //  clusters) and the trailing LF.
        i = line_hi;
        if (i < n && sp[i] == '\n') i++;
    }

    u8bUnMap(src);
    done;
}

ok64 WEAVEEmitMerged(weave const *w,
                     WEAVEsetfn const *preds, void *const *ctxs,
                     u32 npreds, u8b out) {
    sane(w && out);
    if (npreds > WEAVE_EMIT_MAX_PREDS) return WEAVEFAIL;
    u8bReset(out);

    u32cp  toks   = (u32cp)w->toks[1];
    u32cp  toks_e = (u32cp)w->toks[2];
    u32    ntok   = (u32)(toks_e - toks);
    inrmcp irm    = (inrmcp)w->inrm[1];
    u8cp   text   = (u8cp)w->text[1];

    //  Empty weave → empty output.  npreds == 0 also short-circuits
    //  to verbatim alive-bytes emission (spine_mask = 0; every token
    //  has membership 0 = spine; nothing flagged).
    if (ntok == 0) done;

    u32 spine_mask =
        (npreds == 0) ? 0
        : (npreds == 32 ? 0xFFFFFFFFu : ((1u << npreds) - 1u));

    a_cstr(mk_open,  "<<<<");
    a_cstr(mk_mid,   "||||");
    a_cstr(mk_close, ">>>>");

    u32 i = 0;
    while (i < ntok) {
        if (irm[i].rm != 0) { i++; continue; }   // dead, skip

        u32 m = weave_emit_membership(irm[i].in, preds, ctxs,
                                      npreds, spine_mask);
        if (m == spine_mask) {
            //  Spine token — emit and continue.
            call(weave_emit_token, out, text, toks, i);
            i++;
            continue;
        }

        //  Non-spine: collect a maximal run of non-spine alive tokens.
        u32 run_lo = i;
        u32 run_hi = i;     // exclusive
        while (run_hi < ntok) {
            if (irm[run_hi].rm != 0) { run_hi++; continue; }
            u32 mm = weave_emit_membership(irm[run_hi].in, preds, ctxs,
                                           npreds, spine_mask);
            if (mm == spine_mask) break;
            run_hi++;
        }

        //  Conflict detection: two alive tokens with disjoint memberships.
        b8 conflict = NO;
        u32 groups[WEAVE_EMIT_MAX_GROUPS];
        u32 ngroups = 0;
        for (u32 j = run_lo; j < run_hi && !conflict; j++) {
            if (irm[j].rm != 0) continue;
            u32 mj = weave_emit_membership(irm[j].in, preds, ctxs,
                                           npreds, spine_mask);
            for (u32 k = 0; k < ngroups; k++) {
                if ((groups[k] & mj) == 0) { conflict = YES; break; }
            }
            if (conflict) break;
            //  Record mj if new.
            b8 dup = NO;
            for (u32 k = 0; k < ngroups; k++)
                if (groups[k] == mj) { dup = YES; break; }
            if (!dup && ngroups < WEAVE_EMIT_MAX_GROUPS)
                groups[ngroups++] = mj;
        }

        if (!conflict) {
            //  Emit alive bytes in weave order, verbatim.
            for (u32 j = run_lo; j < run_hi; j++) {
                if (irm[j].rm != 0) continue;
                call(weave_emit_token, out, text, toks, j);
            }
            i = run_hi;
            continue;
        }

        //  Conflict: cluster by distinct membership (first-appearance
        //  order) and frame with markers.  Re-collect distinct
        //  memberships; the early-out above may have skipped some.
        ngroups = 0;
        for (u32 j = run_lo; j < run_hi; j++) {
            if (irm[j].rm != 0) continue;
            u32 mj = weave_emit_membership(irm[j].in, preds, ctxs,
                                           npreds, spine_mask);
            b8 dup = NO;
            for (u32 k = 0; k < ngroups; k++)
                if (groups[k] == mj) { dup = YES; break; }
            if (!dup && ngroups < WEAVE_EMIT_MAX_GROUPS)
                groups[ngroups++] = mj;
        }

        call(u8bFeed, out, mk_open);
        for (u32 g = 0; g < ngroups; g++) {
            if (g > 0) call(u8bFeed, out, mk_mid);
            for (u32 j = run_lo; j < run_hi; j++) {
                if (irm[j].rm != 0) continue;
                u32 mj = weave_emit_membership(irm[j].in, preds, ctxs,
                                               npreds, spine_mask);
                if (mj != groups[g]) continue;
                call(weave_emit_token, out, text, toks, j);
            }
        }
        call(u8bFeed, out, mk_close);

        i = run_hi;
    }

    //  Second pass: line-align large conflict blocks.  The streaming
    //  emit above places `<<<<` / `||||` / `>>>>` at token boundaries,
    //  which is fine for tiny edits (a single word swap) but produces
    //  syntactically incoherent half-lines for larger conflicts —
    //  dropping one side wouldn't reconstruct a buildable file.
    //
    //  Rule: per conflict block, compare its cluster bytes against the
    //  bytes of the surrounding line(s).  If clusters take less than
    //  1/4 of the affected line, keep markers inline.  Otherwise
    //  rewrite the block so every cluster reads as complete line(s):
    //  the shared prefix (last LF → `<<<<`) and shared suffix (`>>>>`
    //  → next LF) are spliced into each cluster, and markers go on
    //  their own lines.
    call(weave_realign_conflicts, out);

    done;
}
