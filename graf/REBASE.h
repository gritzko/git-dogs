#ifndef GRAF_REBASE_H
#define GRAF_REBASE_H

//  REBASE: linear-history replay primitives for the upcoming POST
//  rewrite (Stage 2).  Three orthogonal pieces:
//
//    1. GRAFPatchId        — stable u64 hash of a commit's per-file
//                            diff vs its first parent.  Same logical
//                            change → same id, regardless of parent /
//                            date / committer / actual sha.  Used to
//                            dedup "already cherry-picked" commits
//                            during replay.
//    2. GRAFMergeExplicit  — three-way blob merge with the base sha
//                            supplied directly (bypasses graf's LCA
//                            walk).  Thin wrapper over JOINMerge.
//    3. GRAFRebase         — replay loop: walk child_tip → base_old
//                            via parent chain, replay each commit
//                            onto a moving HEAD that starts at
//                            base_new.  Patch-id dedup, conflict
//                            aborts.  Object emission goes through a
//                            caller-supplied callback so persistence
//                            is the caller's call.
//
//  Linear-branch invariant on the write path: each commit has at most
//  one parent we care about; merges from imported git history are
//  hashed against their first parent only (same convention as git's
//  patch-id).
//
//  Reads only via existing keeper APIs (KEEPGet/KEEPGetExact/
//  KEEPObjSha).  No keeper mutation.  Persistence is delegated to
//  the emit callback.

#include "abc/INT.h"
#include "abc/OK.h"
#include "abc/S.h"
#include "dog/SHA1.h"

// --- Error codes ---

con ok64 GRAFCNFL = 0x41b28d6cf90c;   //  3-way merge conflict during rebase

// --- Primitive 1: patch-id ---

//  Stable u64 hash of a commit's per-file delta vs its first parent.
//  Implementation walks both trees in tandem (graf/keeper helpers),
//  emits (path, parent_blob_sha, commit_blob_sha) tuples in path-
//  ascending order, and folds them through RAPHash.  Returns 0 for
//  root commits, empty diffs, or any failure to fetch parent/commit
//  bodies — dedup callers treat 0 as "never matches".
u64 GRAFPatchId(u8csc commit_body);

// --- Primitive 2: 3-way blob merge with explicit base ---

//  Three-way blob merge with the base sha supplied directly.  Fetches
//  base/ours/theirs blobs from keeper via KEEPGetExact, tokenizes
//  each, hands them to JOINMerge.  `out` is reset before use, the
//  merged bytes are appended, and JOINMerge's conflict markers
//  surface inline.  Mirrors GRAFGet's blob-mode error handling.
ok64 GRAFMergeExplicit(sha1 const *base, sha1 const *ours,
                       sha1 const *theirs, u8 *const *out);

// --- Primitive 3: linear rebase ---

//  Object-emit callback invoked once per object produced by the
//  rebase (commits, rebuilt trees, fresh blobs from merges).  Caller
//  may persist immediately, stage in memory, or record to a transcript
//  for later commit/abort.  Return non-OK to abort the rebase: the
//  callee surfaces the error code unchanged.
typedef ok64 (*graf_rebase_emit_cb)(void *ctx,
                                    u8 obj_type,        //  DOG_OBJ_*
                                    sha1 const *sha,    //  canonical
                                    u8csc body);        //  raw bytes

//  Replay every commit between `base_old` (exclusive) and `child_tip`
//  (inclusive) onto `base_new`, oldest-first.  For each commit Cᵢ:
//    - compute its patch-id; if any ancestor of `base_new` carries
//      the same patch-id, skip (cherry-pick already upstream),
//    - else 3-way merge tree(parent(Cᵢ)) (base) vs tree(running_head)
//      (ours) vs tree(Cᵢ) (theirs); per-leaf merges go through
//      GRAFMergeExplicit, recursive tree assembly produces fresh
//      tree bodies.  Each new object is emitted via `cb`.
//    - build a fresh commit object: tree=<new_tree>,
//      parent=<running_head>, author + author-date preserved,
//      committer rewritten to "rebase <0> 0 +0000", any gpgsig
//      stripped.  Hash via KEEPObjSha → emit.  Advance running_head.
//
//  On clean completion the final tip is the last sha emitted with
//  obj_type == DOG_OBJ_COMMIT (or `base_new` itself when child_tip
//  == base_old and no commits were replayed).  Returns:
//    OK         — success, no conflicts;
//    GRAFCNFL   — three-way merge conflict, rebase aborted before the
//                 offending commit's emit chain finished.  Caller is
//                 responsible for any cleanup of objects emitted
//                 before the abort;
//    callback's error  — propagated unchanged.
ok64 GRAFRebase(sha1 const *base_old, sha1 const *base_new,
                sha1 const *child_tip,
                graf_rebase_emit_cb cb, void *ctx);

#endif
