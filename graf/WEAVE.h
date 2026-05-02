#ifndef GRAF_WEAVE_H
#define GRAF_WEAVE_H

//  WEAVE: token-level history of one file as a single sequence.
//
//  Per token, four parallel arrays of equal length N:
//    text     — token bytes, indexed by tok32 cumulative end-offset.
//               Token i spans tok32Offset(toks[i-1]) .. tok32Offset(toks[i]).
//    toks     — tok32(tag, end_offset_in_text).
//    hashlets — RAPHash of the token's bytes; used for u64 token diffing.
//    inrm     — (in, rm) pair of 32-bit commit hashlets.
//                 in == 0 → token predates the timeframe (NCA bootstrap).
//                 rm == 0 → token still alive.
//
//  A weave is rebuilt fresh by every operation: WEAVEFromBlob (one-version
//  weave from raw bytes), WEAVEDiff (linear chain step), WEAVEMerge
//  (concurrent branches).  Each writes into a destination weave that
//  the caller has reset.  Three weave instances (src, nu, dst) is the
//  typical caller pattern for incremental builds along a blob chain.
//
//  Splice canonicalization (compose-time invariant):
//    Within any maximal run of non-EQ EDL ops between two EQs,
//    all INS tokens precede all DEL tokens in the output.  No
//    rm-then-in adjacency, no in-rm-in alternation.

#include "abc/INT.h"
#include "abc/RAP.h"
#include "dog/HUNK.h"
#include "dog/TOK.h"

con ok64 WEAVEFAIL = 0x2038a7ce3ca495;

//  Sentinel `src` for the worktree shadow version (uncommitted edits).
//  Real `WHIFFHashlet40` truncations land in the bottom 32 bits — full
//  0xFFFFFFFF is overwhelmingly likely to be free.  Shared between BLAME
//  (worktree blame row) and the DIFF projector (wt as next-version-after
//  -base in the wt-vs-base shape per VERBS.md `diff:`).
#define WEAVE_WT_SRC 0xFFFFFFFFu

//  Sentinel `src` for synthetic conflict-marker tokens that frame
//  divergent regions in a merged weave's alive byte stream.  Picked
//  one shy of WEAVE_WT_SRC so the same arithmetic-rare-value rationale
//  applies (bottom 32 bits of a real `WHIFFHashlet40` are unlikely
//  to be 0xFFFFFFFE).  Only ever observed at render time — never
//  stored in committed history.
#define WEAVE_CFLCT_SRC 0xFFFFFFFEu

typedef struct {
    u32 in;
    u32 rm;
} inrm;

typedef inrm const inrmc;
typedef inrm *inrmp;
typedef inrm const *inrmcp;

fun int inrmcmp(inrmcp a, inrmcp b) {
    if (a->in != b->in) return (a->in < b->in) ? -1 : 1;
    if (a->rm != b->rm) return (a->rm < b->rm) ? -1 : 1;
    return 0;
}

fun b8 inrmZ(inrmcp a, inrmcp b) {
    return a->in < b->in || (a->in == b->in && a->rm < b->rm);
}

#define X(M, name) M##inrm##name
#include "abc/Bx.h"
#undef X

typedef struct {
    Bu8    text;
    Bu32   toks;
    Bu64   hashlets;
    Binrm  inrm;
} weave;

ok64 WEAVEInit (weave *w);
void WEAVEReset(weave *w);
void WEAVEFree (weave *w);

//  Build a one-version weave from raw blob bytes.  Tokenizes `data`
//  with the lexer for `ext`, hashes each token, stamps every token
//  with inrm = {src, 0}.  Pass src=0 to mark all tokens as
//  pre-timeframe (NCA bootstrap).
ok64 WEAVEFromBlob(weave *w, u8cs data, u8cs ext, u32 src);

//  dst = src diffed against nu.  `nu` is a one-version weave produced
//  by WEAVEFromBlob; tokens that the diff classifies as INS are copied
//  from nu into dst with in=src_commit, rm=0.  dst is reset before
//  composition.  src and nu are read-only.
ok64 WEAVEDiff (weave *dst, weave const *src, weave const *nu, u32 src_commit);

//  dst = a merged with b (concurrent branches sharing an ancestor).
//  Both inputs must be weaves built incrementally from a common
//  ancestor (typically via `WEAVEFromBlob` + `WEAVEDiff`); their full
//  hashlet streams (including dead tokens) are run through `DIFFu64s`
//  + NEIL cleanup to recover the shared spine, then EQ runs reconcile
//  `inrm` per-token (deleter wins; alive-on-both keeps the lower
//  `in` for determinism), and non-EQ runs canonicalize as INS-then-DEL
//  with each side's tokens carrying their original `inrm`.  When both
//  sides have *alive* tokens at the same logical slot whose bytes
//  agree, the alive token is dedup'd (one copy with `in = min`).
//  When the alive bytes differ, both sides' tokens are emitted in
//  order with their original `inrm` — the weave records both
//  histories.  Conflict-marker bytes (`<<<<` etc.) are NEVER stored
//  in the weave; producing them is a render-time concern (a renderer
//  walking dst can detect concurrent-alive divergence by inrm and
//  emit framing bytes in its output stream).  dst is reset before
//  composition.
ok64 WEAVEMerge(weave *dst, weave const *a, weave const *b);

//  WEAVEReplay: build a weave for a known merge commit.
//
//  Given N parent weaves and the result blob the merge commit shipped,
//  produce dst = WEAVEMerge of all parents pairwise, then WEAVEDiff
//  against the result.  The merge step combines histories; the diff
//  step reconciles toward the actually-shipped bytes — INS tokens
//  (manual conflict-resolution bytes, no parent had them) get
//  `in = merge_in`, DEL tokens (dropped at the merge) get
//  `rm = merge_in`.  The output weave's alive byte sequence equals
//  `result_blob` exactly.
//
//  No conflict markers are ever stored: WEAVEMerge produces a
//  marker-free weave, and the WEAVEDiff resolves divergence into the
//  shipped bytes directly.
//
//  parents[] must be non-NULL with nparents >= 1.  N == 1 reduces to
//  WEAVEDiff(dst, parents[0], blob_weave, merge_in).
ok64 WEAVEReplay(weave *dst,
                 weave const *const *parents, u32 nparents,
                 u8cs result_blob, u8cs ext,
                 u32 merge_in);

// --- Diff emission ---
//
//  Walk a built weave and emit one hunk classifying every alive token
//  by its `inrm` membership in the `from` and `to` reachable sets.
//  Per token:
//    alive_from = in_from(in) && (rm == 0 || !in_from(rm))
//    alive_to   = in_to  (in) && (rm == 0 || !in_to  (rm))
//    alive_to && !alive_from → 'I' (inserted on the to-side)
//    alive_from && !alive_to → 'D' (deleted on the to-side)
//    alive_from && alive_to  → context
//    else                    → skipped
//  Output hunk: `text` is the concatenation of every kept token in weave
//  order; `hili` is a complete tiling of `text` with tok32(tag, end_off)
//  spans (`I`, `D`, or `' '` for context).  Suitable for HUNK rendering.
typedef b8 (*WEAVEsetfn)(u32 commit_h32, void *ctx);

ok64 WEAVEEmitDiff(weave const *w, u8cs name,
                   WEAVEsetfn in_from, void *from_ctx,
                   WEAVEsetfn in_to,   void *to_ctx,
                   HUNKcb cb, void *cb_ctx);

// --- Conflict-aware merged-weave render ---
//
//  Emit alive bytes of a merged weave (output of `WEAVEMerge`) into
//  `out`, framing divergent regions with `<<<<` / `||||` / `>>>>`
//  marker bytes when the merge inputs disagreed.
//
//  `preds[0..npreds)` carry one membership predicate per merge input
//  head — `WEAVEsetfn(commit_h32, ctx)` returns YES iff the supplied
//  32-bit commit hashlet is in that head's reachable history (the
//  natural backing is the `Bwh128` ancestor closure produced by
//  `DAGAncestors`, optionally augmented with `WEAVE_WT_SRC` for a
//  wt-as-final-layer side).  Tokens with `inrm.in == 0` (pre-timeframe
//  bootstrap) are treated as spine (member of every predicate).
//
//  Conflict criterion (per non-EQ run): the run is a conflict iff it
//  contains two alive tokens whose membership signatures are disjoint
//  (no `P_i` satisfies both).  Otherwise the run's alive bytes emit
//  verbatim in weave order.
//
//  Conflict emission: `<<<<`, then per-distinct-membership cluster
//  bytes interleaved with `||||`, then `>>>>`.  Cluster order matches
//  first-appearance order in the run.  No newline framing — JOIN
//  format compatibility.
//
//  `out` is reset on entry.  npreds <= 32.
ok64 WEAVEEmitMerged(weave const *w,
                     WEAVEsetfn const *preds, void *const *ctxs,
                     u32 npreds, u8b out);

#endif
