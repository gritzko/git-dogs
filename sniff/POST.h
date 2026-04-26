#ifndef SNIFF_POST_H
#define SNIFF_POST_H

//  POST: commit the current base tree.
//
//  Wraps the root-dir SNIFF_TREE hashlet into a commit object with
//  parent = current HEAD and updates HEAD to the new commit.
//
//  If the base tree is unset or equals the HEAD commit's tree (i.e.
//  no prior PUT/DELETE has staged anything), POSTCommit first calls
//  PUTStage(s, k, reporoot, NULL) to auto-stage everything dirty on
//  disk.  This matches `git commit -a` ergonomics.

#include "SNIFF.h"
#include "keeper/KEEP.h"

//  Commit the wt to a branch.  `target_branch` overrides the branch
//  the commit lands on:
//    * empty (path[0] == NULL or len 0) — use the wt's recorded
//      baseline branch (same-branch POST).
//    * non-empty — cross-branch POST: the new commit goes on
//      `?<target_branch>`, the wt's recorded baseline branch is
//      left untouched in REFS, and `.sniff` is reset to
//      `(target_branch, new_tip)`.  Refused when the target
//      branch's REFS tip exists and is not an ancestor of the wt's
//      recorded base (non-ff).
ok64 POSTCommit(u8cs reporoot, u8cs target_branch,
                u8cs message, u8cs author, sha1 *sha_out);

//  Dry run: walk the same change-set the next POSTCommit would
//  build, print one line per changed path to stdout (`M/A/D path`),
//  and a `sniff: <n> change(s)` summary to stderr.  No commit, no
//  REFS, no ULOG mutation.  Wired to bare `sniff post` (no -m,
//  no `?label`) so the user can sanity-check before committing.
ok64 POSTPrintStatus(u8cs reporoot);

//  Record `ref_uri → ?<sha_hex>` in keeper/refs via REFSAppend.
//  `ref_uri` is the URI the user typed on the CLI — e.g. `?heads/main`
//  or `?tags/v0.0.1` — passed straight through (`c->uris[i].data`).
//  `sha_hex` must be exactly 40 hex chars.
ok64 POSTSetLabel(u8cs ref_uri, u8cs sha_hex);

#endif
