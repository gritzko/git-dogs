//
// JOIN - Token-level 3-way file merge primitive
//
// Tokenizes base/ours/theirs, hashes tokens with RAP,
// runs Myers diff on hash arrays, walks lockstep to merge.
//

#ifndef GRAF_JOIN_H
#define GRAF_JOIN_H

#include "abc/DIFF.h"
#include "abc/RAP.h"
#include "dog/TOK.h"

// Packed tok32 tokens: use tok32Pack/tok32Tag/tok32Offset from TOK.h

// Hash u64 marking: ms 2 bits
// For base hashes:
#define JOIN_RM_O (1ULL << 63)  // removed by ours
#define JOIN_RM_T (1ULL << 62)  // removed by theirs
// For ours/theirs hashes:
#define JOIN_IN (1ULL << 63)  // inserted (not from base)
// Mask and strip:
#define JOIN_MARK (3ULL << 62)
#define JOIN_HASH(h) ((h) & ~JOIN_MARK)

con ok64 JOINFAIL = 0x4d84973ca495;
con ok64 JOINBAD = 0x136125cb28d;

// Tokenized file ready for merge
typedef struct {
    u8cs data;        // original file content
    u32 *toks[4];     // u32b: token array (lit:5 | off:27)
    u64 *hashes[4];   // u64b: per-token RAPHash values
} JOINfile;

ok64 JOINTokenize(JOINfile *jf, u8csc data, u8csc ext);

//  DEPRECATED.  3-way merge belongs to WEAVE now — see
//  `GRAFMerge3Bytes` (raw-bytes WEAVE pipeline, `<<<<…||||…>>>>`
//  markers, 1/4-line realignment) and `GRAFMergeWtFileTunable`
//  (DAG-aware, per-side ancestor closures via build_tip_weave_tunable).
//  Retained only so `graf/test/JOIN01test` can keep characterising the
//  historic JOIN merge behaviour during the WEAVE migration.  No
//  production callers; new code MUST NOT add any.
__attribute__((deprecated("use GRAFMerge3Bytes / GRAFMergeWtFileTunable")))
ok64 JOINMerge(u8bp out, JOINfile *base, JOINfile *ours, JOINfile *theirs);

void JOINFree(JOINfile *jf);

#endif
