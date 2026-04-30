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
//  Stub for now.
ok64 WEAVEMerge(weave *dst, weave const *a, weave const *b);

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

#endif
