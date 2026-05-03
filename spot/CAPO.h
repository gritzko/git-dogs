#ifndef LIBRDX_CAPO_H
#define LIBRDX_CAPO_H

#include <stdio.h>
#include <string.h>
#include "abc/INT.h"
#include "abc/KV.h"
#include "abc/PATH.h"
#include "abc/RON.h"
#include "abc/RAP.h"
#include "dog/DOG.h"
#include "dog/SHA1.h"
#include "dog/WHIFF.h"

con ok64 CAPONOROOM = 0x30a6585d86d8616;
con ok64 CAPONODIFF = 0x30a6585d83523cf;  // no usable saved commit → full reindex
//  Singleton-open return codes, matching keeper/sniff/graf convention.
con ok64 SPOTOPEN   = 0x71961d619397;
con ok64 SPOTOPENRO = 0x71961d6193976d8;
//  SPOTOpenBranch: branch outside the Phase-3-supported set (trunk only).
con ok64 SPOTNOBR   = 0x71961d5d82db;

extern b8 CAPO_COLOR;  // stdout is a terminal with color
extern b8 CAPO_TERM;   // stderr is a terminal

// Verbose call: prints step context on failure
#define vcall(step, f, ...)                                              \
    {                                                                    \
        __ = (f(__VA_ARGS__));                                           \
        if (__ != OK) {                                                  \
            fprintf(stderr, "spot: %s: %s (%s:%d)\n",                   \
                    step, ok64str(__), __func__, __LINE__);              \
            return __;                                                   \
        }                                                                \
    }

#define CAPO_DIR ".dogs"
#define CAPO_IDX_EXT ".spot.idx"
#define CAPO_LOCK_S  ".lock.spot"
#define CAPO_SEQNO_WIDTH 10
#define CAPO_MAX_LEVELS 24
#define SPOT_LEAF_BRANCH_MAX 1024
//  Missing prefix dir along the trunk → leaf branch path.
con ok64 SPOTNOPATH = 0x71961d5d864a751;
//  In-RAM sort-and-dedup scratch.  `CAPO_FLUSH_AT` is the trigger
//  size: once data in `s->entries` reaches it, we sort + dedup in
//  place, and — if the dedup leaves ≥ 50 % unique — flush to a new
//  `.idx` run.  If < 50 % unique (highly redundant input) we keep
//  the compacted scratch and let it refill.  Keeping the trigger
//  small (1 M entries / 8 MB) bounds each sort's working set to
//  stay cache-friendly; on dedup-heavy workloads (src/git ingest
//  hits ~20 % unique) this means many small sorts instead of a few
//  enormous ones.  `CAPO_SCRATCH_LEN` is the hard cap on scratch
//  size (anonymous mmap) — generously oversized vs the trigger.
//  Hash-set scratch sized to fit L3 cache (~16 MB on most x86-64
//  cores).  Most hash-table accesses are random-strided, so a table
//  larger than L3 pays DRAM latency on every probe.  When src/git's
//  ~3 M unique postings overflow the 2 M slots, HASHNOROOM triggers
//  CAPOFlushRun and the LSM compaction handles cross-flush dedup.
//  MUST stay a power of 2 — HASHx.h folds hash → slot via bitmask.
#define CAPO_SCRATCH_LEN (1UL << 21)  // 2M u64 entries = 16MB
//  Keep CAPO_FLUSH_AT at the old 1M trigger size for source compat —
//  the hash-set path no longer consults it (HASHNOROOM is the trigger),
//  and the search path doesn't allocate it.
//  Per-session reusable token buffer cap.  16 M u32 entries = 64 MB,
//  larger than any source file we expect to ingest.  Anonymous mmap
//  pages are zero-fill on demand, so the unused tail costs nothing.
#define INGEST_TOKS_CAP  (1UL << 24)
//  Blob → (basename RAP, ext_off) map (rw): 60-bit obj_hl → packed
//  value `(fn_rap40 << 24) | ext_off24`.  Populated by SPOTUpdate(TREE)
//  for every blob entry whose basename has a known tokenizer ext;
//  consulted by SPOTUpdate(BLOB) to tag postings inline.  Absent ⇒
//  silent skip (binary, image, ext we can't tokenize).  ~16 B per
//  entry × every tokenizable blob in the ingest closure.
#define CAPO_BLOB_FN_CAP    (1u << 22)        // 4 M slots → ~64 MB
//  Per-session arena for ext strings ("c", "h", "py", …).  Offset 0
//  is reserved as a sentinel; ~50 distinct exts fit easily in 4 KB.
#define CAPO_EXT_ARENA_LEN  (1u << 12)        // 4 KB

#define CAPOTriChar(c) (RON64_REV[(u8)(c)] != 0xff)

// 60-bit object-id key for `blob_to_fn`.  Same shape as keeper's
// WHIFFHashlet60; named here to make spot's SPOTUpdate dispatch
// readable on its own.
fun u64 CAPOObjHashlet(sha1 const *sha) { return WHIFFHashlet60(sha); }

// Basename → 40-bit posting key.  Truncated `RAPHash(basename)`,
// computed at SPOTUpdate(TREE) for ingest and at search time over
// every worktree path's basename.  Two files with the same basename
// in different directories share a posting bucket — accepted as a
// filter-only signal; the worktree scan rescans anyway.
fun u64 CAPOFnRap40(u8csc basename) {
    return RAPHash(basename) & ((1ULL << 40) - 1);
}

// Index a streaming blob whose basename hash was already stamped via
// SPOTUpdate(TREE).  Tokenises and emits postings into the SPOT
// singleton's hash-set scratch (`SPOT.entries`).
ok64 CAPOIndexBlob(u8csc source, u8csc ext, u64 fn_rap);

// Index a single on-disk source file.  Hashes `basename` and
// delegates to CAPOIndexBlob.  Used by the search-time (re)tokenize
// path; ingest goes through CAPOIndexBlob directly.
ok64 CAPOIndexFile(u8csc source, u8csc ext, u8csc basename);

typedef struct spot_ spot;

// Load index stack as a typed view over SPOT.puppies (no fs scan,
// no per-call mmap; the puppy stack is owned by the singleton).
// `dir` is ignored — kept for API stability.  Each `<seqno>.spot.idx`
// along trunk → leaf appears as one run in `stack[0..nfiles)`.
ok64 CAPOStackOpen(u64css stack, u8bp *maps, u32p nfiles, u8csc dir);

// No-op: SPOT.puppies owns the mmaps now.
ok64 CAPOStackClose(u8bp *maps, u32 nfiles);

// Compact the LSM stack at the leaf branch dir, unlink merged
// sources via DOGPupThinTail and write the merged run via
// DOGPupCreate.  Mirrors KEEPCompact / dag_compact.
ok64 CAPOCompact(spot *s);

// Flush in-memory postings (s->entries) as a new puppy and run
// CAPOCompact to keep the 1/8 invariant.  Called by SPOTUpdate(BLOB)
// when scratch exceeds CAPO_FLUSH_AT, and by SPOTClose at end of run.
ok64 CAPOFlushRun(spot *s);

// Next available sequence number (max existing + 1)
ok64 CAPONextSeqno(u64p seqno, u8csc dir);

#include "abc/URI.h"

// Structural code search: needle is a code fragment, ext is file extension.
// When replace is non-empty, matched regions are replaced and files rewritten.
// When ref is non-NULL, search historic blobs at that ref via keeper
// (replace is rejected in this mode — no on-disk path to rewrite).
ok64 CAPOSpot(u8csc needle, u8csc replace, u8csc ext, u8csc reporoot,
              u8css files, uri const *ref);

// Substring grep across all AST leaves (including comments).
// ext: optional language filter (empty = all parseable files).
// ctx_lines: max context lines above/below the match (like diff -C).
// ref: optional — when set, grep historic blobs at that ref via keeper.
ok64 CAPOGrep(u8csc substring, u8csc ext, u8csc reporoot, u32 ctx_lines,
              u8css files, uri const *ref);

// Regex grep using Thompson NFA (abc/NFA.h).
// pattern: regex string (supports . * + ? | () [] \d \w \s {n,m}).
// Extracts literal substrings for trigram index filtering, then NFA-matches
// candidate files line by line. Same output format as CAPOGrep.
// ref: optional — when set, regex-grep historic blobs at that ref.
ok64 CAPOPcreGrep(u8csc pattern, u8csc ext, u8csc reporoot, u32 ctx_lines,
                   u8css files, uri const *ref);

// Compact all .spot.idx files into a single run at the leaf branch
// dir.  Uses SPOT.puppies and writes to SPOT.leaf_branch.
ok64 CAPOCompactAll(spot *s);

// Resolve spot index dir from reporoot (<reporoot>/.dogs/spot)
ok64 CAPOResolveDir(path8b out, u8csc reporoot);

// Check if extension is known to tok/ tokenizers
b8 CAPOKnownExt(u8csc ext);

// --- Index entry layout ---
//
// Every spot index entry is one u64 (`spot64`):
//   [ id:20 | type:4 | fn_rap:40 ]   (high → low)
//
// Natural u64 sort clusters by `id` first (so seek-by-trigram is a
// contiguous range), then `type`, then `fn_rap`.  `fn_rap` is the
// 40-bit truncation of `RAPHash(basename)` — basename only, no path.
//
//   type=SPOT64_TRI: id = 18-bit packed RON64 trigram (2 spare bits)
//   type=SPOT64_MEN: id = RAPHash(symbol_name) & 0xFFFFF  (S, C tags)
//   type=SPOT64_DEF: id = RAPHash(symbol_name) & 0xFFFFF  (N tag)

typedef u64 spot64;

#define SPOT64_FN_BITS    40
#define SPOT64_TYPE_BITS   4
#define SPOT64_ID_BITS    20
#define SPOT64_FN_MASK    ((1ULL << SPOT64_FN_BITS) - 1)
#define SPOT64_TYPE_MASK  ((1ULL << SPOT64_TYPE_BITS) - 1)
#define SPOT64_ID_MASK    ((1ULL << SPOT64_ID_BITS) - 1)
#define SPOT64_TYPE_SHIFT SPOT64_FN_BITS
#define SPOT64_ID_SHIFT   (SPOT64_FN_BITS + SPOT64_TYPE_BITS)

#define SPOT64_TRI 0   // text trigram
#define SPOT64_MEN 1   // symbol use   (S, C tags)
#define SPOT64_DEF 2   // symbol decl  (N tag)
//                3..15 reserved

fun spot64 spot64Pack(u8 type, u32 id20, u64 fn40) {
    return ((u64)(id20  & SPOT64_ID_MASK)   << SPOT64_ID_SHIFT) |
           ((u64)(type  & SPOT64_TYPE_MASK) << SPOT64_TYPE_SHIFT) |
            (fn40 & SPOT64_FN_MASK);
}

fun u32 spot64Id   (spot64 e) { return (u32)((e >> SPOT64_ID_SHIFT) & SPOT64_ID_MASK); }
fun u8  spot64Type (spot64 e) { return (u8)((e >> SPOT64_TYPE_SHIFT) & SPOT64_TYPE_MASK); }
fun u64 spot64FnRap(spot64 e) { return e & SPOT64_FN_MASK; }

// Pack 3 RON64 chars into the 18-bit id slot (zero-padded to 20).
fun u32 spot64TriId(u8cs tri) {
    return ((u32)RON64_REV[tri[0][0]] << 12) |
           ((u32)RON64_REV[tri[0][1]] <<  6) |
           ((u32)RON64_REV[tri[0][2]]);
}

// Truncate a symbol-name RAP to the 20-bit id slot.
fun u32 spot64SymId(u8cs name) {
    return (u32)(RAPHash(name) & SPOT64_ID_MASK);
}

// --- DOG control struct (DOG.md rule 8) ---

#include "abc/FILE.h"
#include "dog/CLI.h"
#include "dog/HOME.h"
#include "dog/HUNK.h"
#include "spot/LESS.h"

struct spot_ {
    home    *h;                     // borrowed
    int      lock_fd;               // flock on leaf dir's .lock; -1 = ro

    Bu8      arena;
    hunk     hunks[LESS_MAX_HUNKS];
    u8bp     maps[LESS_MAX_MAPS];
    Bu32     toks[LESS_MAX_MAPS];
    u32      nhunks;
    u32      nmaps;

    int          out_fd;
    spot_emit_fn emit;

    //  Puppy stack: (seqno → fd) for every `<seqno>.spot.idx` along
    //  trunk → leaf.  Mmaps live in FILE_WANT_BUFS[fd].  Mirrors
    //  keeper's `k->puppies` and graf's `g->puppies`.  Reads fan out
    //  across the whole path; writes (DOGPupCreate) and compactions
    //  (DOGPupThinTail+DOGPupCreate) only land in the leaf dir.
    Bkv32    puppies;
    Bu8      leaf_branch;           // canonical leaf-branch path
                                    // (trailing '/'; empty for trunk).

    //  Ingestion scratch (rw only): postings hash-set keyed by the
    //  posting itself.  CAPOIndexBlob inserts via HASHu64Put (skipping
    //  the 0 sentinel).  HASHNOROOM triggers CAPOFlushRun, which
    //  compacts non-zero slots, sorts them, writes the puppy and
    //  memsets the table back to zero.
    Bu64     entries;

    //  Per-session token buffer reused across every CAPOIndexBlob
    //  call (rw only).  Avoids the mmap+unmap pair we used to do per
    //  blob — for src/git ingest that's ~160k syscalls saved.
    //  Sized via INGEST_TOKS_CAP at CAPOOpen; larger blobs fall back
    //  to a one-off mmap inside CAPOIndexBlob.
    Bu32     ingest_toks;

    //  Blob → (basename RAP, ext offset).  Stamped by SPOTUpdate(TREE)
    //  for every tree entry whose basename has a known tokenizer ext;
    //  consulted by SPOTUpdate(BLOB) to tag postings inline.  Value
    //  layout: `(fn_rap40 << 24) | ext_off24`.  Absent ⇒ silent skip
    //  (binary, image, untokenizable ext).  Pack producers (git, sniff)
    //  emit trees before blobs, so the lookup hits without buffering.
    Bkv64    blob_to_fn;            // 60-bit blob_hl → packed (fn_rap, ext_off)
    Bu8      ext_arena;             // NUL-separated ext strings,
                                    // offset 0 reserved as sentinel.

    b8 color;
    b8 term;
    b8 rw;
};

typedef spot *spotp;
typedef spot const *spotcp;

//  Singleton.  Zero-initialised; populated by SPOTOpen.
extern spot SPOT;

// --- Public API (singleton, same contract as KEEP/SNIFF/GRAF) ---

//  Open spot state rooted at `home` (repo root).  Returns:
//    OK         I opened; pair with SPOTClose.
//    SPOTOPEN   already open compatible; use &SPOT, don't close.
//    SPOTOPENRO already ro and caller asked for rw.
//    (other)    real error — propagate.
ok64 SPOTOpen(home *h, b8 rw);

//  Branch-aware Open (Phase 3 surface).  Normalizes `branch` via
//  DPATHBranchNormFeed and registers it on the home singleton via
//  HOMEOpenBranch before delegating to SPOTOpen.  Phase 3 accepts
//  only the trunk (canonical form = empty); other branches return
//  SPOTNOBR.  Mirrors `KEEPOpenBranch` / `GRAFOpenBranch`.
ok64 SPOTOpenBranch(home *h, u8cs branch, b8 rw);

//  Run one CLI invocation.
ok64 SPOTExec(cli *c);

//  Feed a single git object into spot during pack ingest.  Pack
//  producers (git, sniff) emit trees before blobs, so each TREE
//  stamps its own children independently — no chain, no buffering.
//
//    COMMIT: ignored.
//    TREE:   for each (mode, name, child_sha) entry whose basename
//            has a known tokenizer ext, stamp blob_to_fn[hashlet(
//            child_sha)] = (CAPOFnRap40(name) << 24) | ext_off.
//    BLOB:   look up (fn_rap, ext_off); on hit, tokenize inline and
//            emit postings via CAPOIndexBlob.  Miss = blob with no
//            tokenizable basename in any tree we saw → silent skip.
//
//  `sha` is the caller's pre-computed git-object SHA-1.
ok64 SPOTUpdate(u8 obj_type, sha1 const *sha, u8cs blob);

void SPOTClose(void);

//  Verb + value-flag tables for CLIParse.
extern char const *const SPOT_CLI_VERBS[];
extern char const SPOT_CLI_VAL_FLAGS[];

#endif
