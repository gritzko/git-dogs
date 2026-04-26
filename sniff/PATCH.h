#ifndef SNIFF_PATCH_H
#define SNIFF_PATCH_H

//  PATCH: 3-way worktree merge driven by graf.
//
//  `be patch ?<target>` resolves the current branch tip (ours),
//  the target ref / sha (theirs), and their LCA (base) via graf,
//  then walks the three trees in tandem and applies per-file
//  actions to the worktree: take-target, leave-ours, or emit the
//  3-way merged bytes produced by `GRAFGet <path>?<ours>&<theirs>`.
//
//  Every byte that ends up on disk comes through graf; sniff owns
//  only the filesystem writes, sniff-registry updates, and
//  classification against the LCA.  No commit is created — a
//  subsequent `sniff post` picks up the merged wt as staged
//  content.
//
//  See VERBS.md §PATCH for the user-facing semantics.

#include "abc/INT.h"
#include "abc/BUF.h"

//  Apply a 3-way merge from `target_query` into the current wt.
//
//  `reporoot`       absolute path of the wt root (already resolved
//                   by the caller via HOMEOpen).
//  `target_query`   branch/tag slice (e.g. "heads/feat",
//                   "tags/v1.0"), or a 40-char hex commit sha.
//                   No leading `?`.
//
//  Returns OK on clean merge (exit 0).  Returns PATCHCONFLICT when
//  at least one path ended up with `<<<<<<<`/`>>>>>>>` markers or
//  a modify/delete clash — conflict paths are logged to stderr;
//  callers map this to a non-zero CLI exit.
ok64 PATCHApply(u8cs reporoot, u8cs target_query);

//  Single-file variant: merge one path only.  Everything else in
//  the wt is left alone.
ok64 PATCHApplyFile(u8cs reporoot, u8cs filepath, u8cs target_query);

// --- Error / sentinel codes ---

con ok64 PATCHFAIL     = 0x1929d3113ca495;   // general failure
con ok64 PATCHCFLCT    = 0x64a74c44c3d531d;  // conflicts recorded in wt
con ok64 PATCHDIRTY    = 0x64a74c44d49b762;  // wt has dirty files that
                                             // would be clobbered
con ok64 PATCHURELT    = 0x64a74c45e6ce55d;  // no shared ancestor
con ok64 PATCHBUSY     = 0x1929d3112de722;   // merge already in progress —
                                             // baseline is a `patch` row;
                                             // complete with `be post` or
                                             // abort by checking out the
                                             // pre-patch commit

#endif
