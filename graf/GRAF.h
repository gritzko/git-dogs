#ifndef GRAF_GRAF_H
#define GRAF_GRAF_H

#include "abc/INT.h"
#include "abc/KV.h"
#include "abc/MSET.h"
#include "dog/CLI.h"
#include "dog/DOG.h"
#include "dog/HOME.h"
#include "dog/HUNK.h"
#include "dog/SHA1.h"
#include "graf/DAG.h"
#include "graf/WEAVE.h"

#define GRAF_ARENA_SIZE (1UL << 24)   // 16MB

// Hunk → bytes serializer: HUNKu8sFeed (TLV) or HUNKu8sFeedText (plain).
typedef ok64 (*graf_emit_fn)(u8s into, hunk const *hk);

// Forward decl for transient ingest state (see graf/DAG.c).
typedef struct dag_ingest dag_ingest;

// --- graf control struct (per DOG.md rule 8) ---
//
// Mirrors keeper's branch-aware shape: per-branch dirs hold
// `<seqno>.graf.idx` files, registered as a DOGPup* puppy stack
// (`puppies`).  GRAFOpenBranch walks trunk → … → leaf calling
// DOGPupOpenAll per dir; reads fan out across the whole path; writes
// only land in the leaf dir.  The typed `wh128cs runs[]` view is
// rebuilt from the puppy stack on every Open and after each
// DOGPupCreate / DOGPupThinTail; queries (DAGLookup et al) consume it
// via `GRAFRuns()`.

typedef struct {
    home        *h;          // borrowed
    int          lock_fd;    // flock on leaf dir's .lock; -1 = ro
    Bu8          arena;      // hunk staging buffer
    int          out_fd;     // output fd (-1 = uninitialized)
    graf_emit_fn emit;       // serializer (TLV or plain text)

    //  Puppy stack: (seqno → fd) for every `<seqno>.graf.idx` along
    //  trunk → leaf.  Mmaps live in FILE_WANT_BUFS[fd].  Compaction
    //  appends a new puppy to the tail (DOGPupCreate) and drops the
    //  young suffix (DOGPupThinTail).
    Bkv32        puppies;
    Bu8          leaf_branch;  // canonical leaf-branch path (trailing
                               // '/'; empty for trunk).  Heap-backed.

    //  Typed wh128cs view over `puppies`, rebuilt by `graf_refresh_view`
    //  on every change.  Newest run sits at the highest index — query
    //  loops scan in reverse so newer LSM levels override older.
    wh128cs      runs[MSET_MAX_LEVELS];
    u32          runs_n;

    dag_ingest  *ing;        // lazily allocated on first GRAFUpdate
} graf;

//  Singleton.  Zero-initialised; populated by GRAFOpen.
extern graf GRAF;

// --- Internal helpers used by GRAFUpdate (implemented in DAG.c) ---
ok64 GRAFDagUpdate(u8 obj_type, sha1 const *sha, u8cs blob);
ok64 GRAFDagFinish(void);

// --- Error / sentinel codes ---

con ok64 GRAFFAIL    = 0x41b28f3ca495;
con ok64 GRAFOPEN    = 0x41b28f619397;
con ok64 GRAFOPENRO  = 0x41b28f6193976d8;
con ok64 GRAFNOBR    = 0x41b28f5d82db;
//  Missing prefix dir along the trunk → leaf branch path.
con ok64 GRAFNOPATH  = 0x41b28f5d864a751;
//  No `--at` anchor available — `diff:` projector forms that need a
//  baseline (any URI without an explicit `?h1..h2` range) refuse with
//  this rather than silently falling back to "wt as base".
con ok64 GRAFNOAT    = 0x41b28f5cd5d3;

// --- Public API (DOG 4-fn, singleton) ---

//  Open graf state on the trunk.  Thin wrapper over `GRAFOpenBranch`
//  with an empty branch.  Returns OK (I opened), GRAFOPEN (already
//  open compatible), GRAFOPENRO (ro/rw conflict), or a real error.
ok64 GRAFOpen(home *h, b8 rw);

//  Branch-aware Open.  Normalizes `branch` via DPATHBranchNormFeed,
//  registers it on the home singleton via HOMEOpenBranch, then walks
//  trunk → … → leaf under `<root>/.dogs/graf/`, calling
//  `DOGPupOpenAll(GRAF.puppies, dir, ".graf.idx")` per dir.  Locks
//  the leaf's `.lock` when rw.  Refreshes the typed `runs[]` view.
//  Mirrors `KEEPOpenBranch`.  Missing prefix dirs return `GRAFNOPATH`.
ok64 GRAFOpenBranch(home *h, u8cs branch, b8 rw);

//  Fill `out` with a live `wh128css` view over the open puppy stack
//  (oldest run at index 0, newest last).  Slice ends point into
//  `GRAF.runs[]`; valid until the next DOGPupCreate / DOGPupThinTail
//  / GRAFClose.
void GRAFRuns(wh128cssp out);

//  Refresh GRAF.runs[] / GRAF.runs_n from the current GRAF.puppies
//  stack.  Called by GRAFOpenBranch and after every DOGPupCreate /
//  DOGPupThinTail; exposed here so DAG.c's compactor (which lives
//  next to its writes) can keep the view in sync.
void GRAFRefreshView(void);

//  Run one CLI invocation.
ok64 GRAFExec(cli *c);

//  Feed a single object (commit/tree/blob) into graf's DAG index.
//  obj_type uses KEEP_OBJ_* constants.  `sha` is the git-object SHA-1.
//  May be NULL when the caller does not have it pre-computed (e.g.
//  the manual reindex path); graf then falls back to hashing `blob`
//  itself.  On the hot UNPKIndex → keeper_indexer_fanout path, UNPK
//  passes its already-resolved SHA, skipping a full SHA1DC pass.
ok64 GRAFUpdate(u8 obj_type, sha1 const *sha, u8cs blob);

//  Close singleton; idempotent.
ok64 GRAFClose(void);

//  Verb + value-flag tables for CLIParse.
extern char const *const GRAF_CLI_VERBS[];
extern char const GRAF_CLI_VAL_FLAGS[];

// --- Legacy globals (used by existing diff/merge code) ---

extern Bu8          graf_arena;
extern int          graf_out_fd;
extern graf_emit_fn graf_emit;

ok64 GRAFArenaInit(void);
void GRAFArenaCleanup(void);

// Serialize one hunk via graf_emit and write to graf_out_fd.
ok64 GRAFHunkEmit(hunk const *hk, void *ctx);

// User-facing diff entry.
ok64 GRAFDiff(u8cs old_path, u8cs new_path, u8cs name,
              u8cs old_mode, u8cs new_mode);

// 3-way merge entry.
ok64 GRAFMerge(u8cs base_path, u8cs ours_path, u8cs theirs_path,
               u8cs outpath);

// Drive a full streaming ingest from keeper: iterate every object in
// the keeper store (commits, trees, blobs), replay DOG.md §8 updates
// into graf's DAG, and finalize with PATH_VER emission.  Idempotent.
ok64 GRAFIndex(keeper *k);

// Token-level blame (reads blobs from keeper).
//   tip_h: 40-bit commit hashlet bounding the history (0 = no filter).
ok64 GRAFBlame(keeper *k, u8cs filepath, u64 tip_h, u8cs reporoot);

// Build the file's full token weave by replaying its blob history along
// `tip_h`'s ancestor closure (oldest-first, byte-dedup adjacent), then
// optionally folding in the on-disk worktree bytes as a final layer
// tagged `wt_src`.  Caller owns three weave instances (init'd via
// `WEAVEInit`); the one holding the final state is returned in
// `*out_final` (points into `wsrc` or `wdst`).  `cb`, when non-NULL, is
// invoked once per kept layer with its `src_id` (truncated commit
// hashlet, or `wt_src` for the wt layer) and the full 64-bit hashlet
// (0 for the wt layer).
//
//   tip_h    : 40-bit commit hashlet bounding history (0 = all).
//   wt_src   : `WEAVE_WT_SRC` to fold wt as a final layer; 0 to skip.
typedef ok64 (*GRAFweaveStepCb)(u32 src_id, u64 commit_h, void *ctx);

ok64 GRAFFileWeave(weave *wsrc, weave *wdst, weave *wnu,
                   weave **out_final,
                   keeper *k, u8cs filepath, u64 tip_h,
                   u8cs reporoot, u32 wt_src,
                   GRAFweaveStepCb cb, void *cb_ctx);

// Resolve a URI's `#hex` / `?ref` / absent-query to a 20-byte commit
// SHA-1 — the same policy `log:` uses (sniff/at.log → REFS fallback).
ok64 GRAFResolveTip(keeper *k, uricp u, sha1 *out);

// Weave diff between two commits (reads blobs from keeper).
ok64 GRAFWeaveDiff(keeper *k, u8cs filepath, u8cs reporoot,
                   u8cs from, u8cs to);

// URI-driven diff primitives.  Each emits one hunk block per changed
// file through `GRAFHunkEmit`.
//
//   GRAFDiffWtFile   — single file: weave-based diff of wt-on-disk
//                      against the baseline blob at `base_h40`
//                      (40-bit commit hashlet from sniff's `--at`
//                      anchor).  wt is folded into the file's weave
//                      as the next version after the base, so
//                      attribution is preserved.
//   GRAFDiffWtTree   — whole tree: walk the base tree, run a per-file
//                      weave diff against wt for each file.  `base_hex`
//                      is the 40-hex spelling of the same commit (used
//                      to compose the URI for `KEEPLsFiles`).  wt-only
//                      additions are not yet emitted.
//   GRAFDiffTreeRefs — whole tree: walk both refs, pair by path,
//                      orphans on either side become deletions or
//                      insertions against empty.
ok64 GRAFDiffWtFile(keeper *k, u8cs filepath, u64 base_h40, u8cs reporoot);
ok64 GRAFDiffWtTree(keeper *k, u64 base_h40, u8cs base_hex, u8cs reporoot);
ok64 GRAFDiffTreeRefs(keeper *k, u8cs from, u8cs to, u8cs reporoot);

// 2-layer weave diff: WEAVEFromBlob ×2 + WEAVEDiff (LCS+NEIL+canon) +
// WEAVEEmitDiff.  The single engine every diff path uses.  `name` is
// the hunk title (file path); `ext` selects the tokenizer; either
// blob slice may be empty (file added or deleted).  No-change pair →
// no hunks emitted.
ok64 GRAFDiff2Layer(u8cs name, u8cs ext, u8cs from_data, u8cs to_data);

// Deterministic URI-driven blob/tree merge (see graf/GET.md).
//
// URI grammar: `path?sha1&sha2&...&shaN`.  Trailing `/` on the path
// selects tree mode (future task).  Reaches keeper via &KEEP and graf
// state via &GRAF — callers must have both singletons open.
ok64 GRAFGet(u8b into, u8csc uri);

// Weave-merge a single file across two commits, treating the wt's
// on-disk bytes for `path` as an implicit edit attached to `base`.
// Builds the ancestor-closure weave per tip via `build_tip_weave`,
// folds the wt bytes as a final WEAVE_WT_SRC layer on the base side,
// runs WEAVEMerge, and writes the resulting alive-token bytes into
// `out` (reset before writing).  Reads keeper through `&KEEP`.
//
// Both `base` and `tgt` are 20-byte commit SHAs; converted internally
// via `WHIFFHashlet40` to drive graf's history walks.  Caller writes
// `out` to disk and stamps the new mtime.
//
// Returns OK on success; GRAFFAIL when neither side's history has
// any alive tokens for `path` (path absent on both); other errors
// propagated from the weave build / merge / emit steps.
//
// Note: divergent regions currently render as base-then-tgt
// concatenation — WEAVE marker emission is a follow-up.  Callers
// that need conflict signaling should diff the result against tgt.
ok64 GRAFMergeWtFile(u8cs path, u8cs reporoot,
                     sha1 const *base, sha1 const *tgt,
                     u8b out);

// Render commit history one-per-line for `be log:[path]?<ref>#<N>`.
// Branch-only URI (no path) walks the COMMIT_PARENT chain via the DAG
// index; path-bearing URI uses PATH_VER + ancestor filter.  Output
// rides graf_emit (TLV via bro on TTY, raw text otherwise).
ok64 GRAFLog(keeper *k, uricp u);

// Subway-map view of the branch tree for `be map:`.  Reads from the
// keeper + graf singletons; caller has already opened both.  Phase 1
// emits one indented row per branch within the current branch's
// ancestors+descendants window; Phase 2/3 will replace the indent
// with subway glyphs and weave in commit-timeline rows.
ok64 GRAFMap(uricp u);

// Latest common ancestor of two commits.  Intersects each tip's
// `DAGAncestors` set, picks the member with the highest `gen`, then
// recovers the full 20-byte commit sha via `KEEPGet`.  `out` left
// zeroed when the DAG is empty or the tips share no indexed
// ancestor; caller treats that as "unrelated histories" (refuse a
// merge, fall back to ours, etc).
ok64 GRAFLca(sha1 *out, sha1 const *a, sha1 const *b);

#endif
