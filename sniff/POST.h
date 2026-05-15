#ifndef SNIFF_POST_H
#define SNIFF_POST_H

//  POST: two-phase commit-and-promote (see VERBS.md §POST).
//
//  Phase 1 — Commit-if-staged: any wt edits or PATCH-staged content
//  produces one new single-parent commit on cur (trailing words become
//  the message).  Selective vs implicit (commit-all) mode is determined
//  by presence of put/delete rows in scope.
//
//  Phase 2 — Promote: when the URI names another branch, ff-or-rebase
//  cur's stack onto that branch's tip via REFSCompareAndAppend on the
//  expected base.  Concurrent posters that move the target see REFSCAS.
//  Bare `post msg` runs only phase 1.
//
//  Single-parent invariant on the write path: every commit POST emits
//  has exactly one parent.  PATCH no longer chains `&<theirs>` onto
//  baseline; the multi-parent commit body builder has been removed
//  along with `POST_MAX_PARENTS` and `post_add_patch_parents`.

#include "SNIFF.h"
#include "keeper/KEEP.h"

//  Commit the wt to a branch.  `target_branch` overrides the branch
//  the commit lands on:
//    * empty (path[0] == NULL or len 0) — use the wt's recorded
//      baseline branch (same-branch POST).
//    * non-empty — cross-branch POST: the new commit goes on
//      `?<target_branch>`, the wt's recorded baseline branch is
//      left untouched in REFS, and `.be/wtlog` is reset to
//      `(target_branch, new_tip)`.  Refused when the target
//      branch's REFS tip exists and is not an ancestor of the wt's
//      recorded base (non-ff).
//  `inv` (may be NULL) is the parsed CLI invocation — verb, flags,
//  URIs.  POSTCommit consults the bits it needs via CLIHas / etc.;
//  currently `--force` bypasses the conflict-marker refusal
//  (POSTCFLCT) for files whose legitimate content contains `<<<<`
//  (e.g. VERBS.md describing the marker syntax).  More flags follow
//  without further signature churn.
#include "dog/CLI.h"
ok64 POSTCommit(u8cs reporoot, u8cs target_branch,
                u8cs message, u8cs author,
                cli const *inv, sha1 *sha_out);

//  Compose default message and author for a bare `be post` whose
//  ULOG carries one or more `patch` rows since the latest get/post.
//  Walks `SNIFFAtPatchChain`, fetches each absorbed commit's body via
//  keeper, and writes:
//    * msg_buf   : last entry's subject + " (+N)" when N=patches-1>0.
//    * auth_buf  : last entry's author identity ("Name <email>"); if
//                  any other entry's identity differs, " (et al)" is
//                  injected before the `<email>`.
//  Slices `*msg_out` / `*auth_out` are repointed into the freshly
//  written buffer regions and remain valid for as long as the caller
//  keeps the buffers alive.  Returns OK with `*n_out>0` when defaults
//  were composed, ULOGNONE when no patch rows are present (caller
//  falls back to the dry-run / refuse-empty arm).
ok64 POSTPatchDefaults(u8cs reporoot,
                       u8b msg_buf,  u8cs *msg_out,
                       u8b auth_buf, u8cs *auth_out,
                       u32 *n_out);

//  Dry run: walk the same change-set the next POSTCommit would
//  build, print one line per changed path to stdout (`M/A/D path`),
//  and a `sniff: <n> change(s)` summary to stderr.  No commit, no
//  REFS, no ULOG mutation.  Wired to bare `sniff post` (no -m,
//  no `?label`) so the user can sanity-check before committing.
ok64 POSTPrintStatus(u8cs reporoot);

//  Cross-branch promote (no-msg `be post ?<X>` shapes per VERBS.md
//  §POST).  `target_branch` is the absolute branch path the user
//  named (already absolutised from `?./X`/`?../X`/`?..` by the
//  caller); empty means trunk.  Decides between four shapes:
//
//    target == dirname(cur)           ?..              upstream-promote
//    target startswith cur+'/'        ?./X (existing)  promote-into-child
//    target startswith cur+'/' (gap)  ?./newleaf       create-on-miss
//    other absolute existing branch   ?<absolute>      peer-promote
//
//  Operands per shape and cur auto-sync rules: see post_promote
//  body and the table in VERBS.md.  Returns:
//    OK          — promote landed (REFS advanced).
//    POSTNONE    — nothing to do (already in sync).
//    GRAFCNFL    — three-way merge conflict mid-rebase.
//    REFSCAS     — concurrent advance of target REFS row.
//    SNIFFFAIL   — generic dispatcher / resource error.
ok64 POSTPromote(u8cs reporoot, u8cs target_branch, b8 allow_create);

//  Look up a branch's current tip via keeper REFS.  Empty `branch`
//  means trunk.  Returns OK with `*out` populated on hit, REFSNONE
//  when the branch has no entry, or REFSBAD on a malformed value
//  row.  Pure read — no side effects.
ok64 POSTResolveBranchTip(sha1 *out, u8cs reporoot, u8cs branch);

//  First-parent chain walker used by cross-shard migration on POST's
//  FF promote arm and PUT's `?br#<sha>` ref reset.  Walks from `*from`
//  backwards along the `parent` header, writing each visited commit
//  sha into `out[0..*nout)` newest-first (so `out[0] == *from`).
//
//  Termination, in priority order:
//    * `stop != NULL && cur == *stop`   → `*reached_stop = YES`
//    * KEEPGetExact miss / no parent     → `*reached_stop = NO`  (root
//                                          or unreachable from the
//                                          currently-open shard chain)
//    * `*nout == cap`                    → `*reached_stop = NO`
//
//  Caller passes `stop = NULL` to walk to the natural end (root or
//  unreachable); `*reached_stop` is then always set to NO.
//
//  Reads use the currently-active keeper singleton — callers that need
//  to walk under a specific shard must `KEEPSwitchBranch` first.
#define POST_MIG_MAX 8192
ok64 POSTFpChainTo(sha1 const *from, sha1 const *stop,
                   sha1 *out, u32 cap, u32 *nout, b8 *reached_stop);

#endif
