#ifndef GRAF_WEAVE_H
#define GRAF_WEAVE_H

//  WEAVE: interleaved token-level file history.
//
//  A weave merges all versions of a file into a single token sequence.
//  Each token carries the generation that introduced it and the
//  generation that deleted it (0 = still alive).  Token text is stored
//  in a side buffer; wtok slices point into it.
//
//  Built incrementally by diffing adjacent blob versions along the
//  PREV_BLOB chain.  Two wtok buffers are swapped each step to avoid
//  splicing.
//
//  To extract version at gen G: scan the weave, emit tokens where
//  intro_gen <= G && (del_gen == 0 || del_gen > G).

#include "abc/INT.h"
#include "abc/RAP.h"
#include "dog/TOK.h"

con ok64 WEAVEFAIL   = 0x2038a7ce3ca495;
con ok64 WEAVNOROM = 0x2038a7d761b616;

// --- wtok: one token in the weave ---

typedef struct {
    u8cs tok;        // slice into text buffer
    u32  intro_gen;  // gen of the commit that introduced this token
    u32  del_gen;    // gen of the commit that deleted it (0 = alive)
} wtok;

typedef wtok const wtokc;
typedef wtok *wtokp;
typedef wtok const *wtokcp;

fun int wtokcmp(wtokcp a, wtokcp b) {
    if (a->intro_gen < b->intro_gen) return -1;
    if (a->intro_gen > b->intro_gen) return 1;
    return 0;
}

fun b8 wtokZ(wtokcp a, wtokcp b) {
    return a->intro_gen < b->intro_gen;
}

#define X(M, name) M##wtok##name
#include "abc/Bx.h"
#undef X

// --- Weave state ---

typedef struct {
    Bu8   text;     // token text storage (append-only)
    Bwtok src;      // current weave (read side of double buffer)
    Bwtok dst;      // next weave (write side of double buffer)
} weave;

//  Initialize weave buffers.
ok64 WEAVEInit(weave *w, size_t est_tokens);

//  Add a version to the weave by diffing old_data → new_data.
//  ext: file extension for tokenizer selection.
//  gen: commit generation of new_data.
//  If the weave is empty, old_data should be empty and all tokens
//  of new_data are inserted as the initial version.
ok64 WEAVEAdd(weave *w, u8cs old_data, u8cs new_data,
              u8cs ext, u32 gen);

//  Number of tokens in the weave (alive + deleted).
fun u32 WEAVELen(weave const *w) {
    return (u32)wtokbDataLen(w->src);
}

//  Access the weave token array (read-only).
fun wtokcp WEAVETokens(weave const *w) {
    return wtokbDataHead(w->src);
}

//  Cleanup.
void WEAVEFree(weave *w);

#endif
