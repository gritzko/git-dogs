#ifndef SNIFF_AT_H
#define SNIFF_AT_H

//  AT — sniff's per-worktree state log, persisted at `<wt>/.sniff`
//  as a ULOG (see dog/ULOG.md).  Each row records a worktree-changing
//  op: checkout (`get`), stage (`put` / `delete`), commit (`post`),
//  patch (`patch`).  The row's timestamp is the ms at which the op
//  ran; sniff stamps every file it writes with that timestamp via
//  `futimens`, so file mtime ∈ log-stamp-set means "clean, attributed
//  to the matching row's URI".
//
//  URI schema for rows (new ULOG-only model):
//    repo   `file:///abs/path/.dogs/`      (wt → store anchor; row 0 only)
//    get    `//origin/path?heads/X#<sha>`  (checkout from remote)
//    get    `?heads/X#<sha>`               (local checkout by ref)
//    get    `#<sha>`                       (detached checkout)
//    post   `?heads/X#<sha>`               (local commit on branch)
//    post   `#<sha>`                       (detached commit)
//    patch  `?heads/X#<ours>,<theirs>,...` (N-hash merge URI, graf-readable)
//    put    `<path>`                       (explicit stage of one path)
//    delete `<path>`                       (explicit stage of one removal)
//    mod    `<path>`                       (daemon-observed modification;
//                                           advisory hint for POST's change-set)
//
//  Row-0 invariant: every non-empty `.sniff` ULOG has a `repo` row
//  at row 0 naming the store (the directory whose `.dogs/` subdir
//  holds the keeper pack-log).  Colocated default: the wt's own
//  `.dogs/`.  Secondary worktrees sharing a primary's store record
//  that primary's URI here.  `repo` is appendable only to an empty
//  log; any other verb is appendable only to a non-empty log.
//
//  Baseline rule: the worktree's current baseline tree URI is the URI
//  of the most recent `get`, `post`, or `patch` row.  Hash count
//  selects the tree backend — one hash → keeper (plain commit tree),
//  two or more → graf (merged tree).  `patch` appends one hash per
//  merge; `post` collapses to a single new commit sha.
//
//  Stamp-set rule: each `get`, `post`, `patch` row stamps every file
//  it touched with the row's timestamp via `futimens`.  A file is
//  "clean" iff its mtime equals one of those stamps.  `put` / `delete`
//  rows are pure intent and do not stamp anything.

#include <time.h>

#include "abc/BUF.h"
#include "abc/INT.h"
#include "abc/PATH.h"
#include "abc/RON.h"
#include "abc/URI.h"
#include "dog/ULOG.h"

//  Append one row to the current sniff log using `RONNow()`.
ok64 SNIFFAtAppend(ron60 verb, uricp u);

//  Like SNIFFAtAppend but takes an explicit timestamp.  Used by verbs
//  that need to know the stamp up-front so it can be applied to
//  fresh files via `futimens` before the row is committed.
ok64 SNIFFAtAppendAt(ron60 ts, ron60 verb, uricp u);

//  `mtime ∈ log-stamp-set?` — the attribution test.  True when some
//  row stamped a file with exactly this timestamp.  Clean files on
//  disk pass this check; user edits do not.
b8   SNIFFAtKnown(ron60 mtime);

// --- New-model helpers (used by the rewritten GET/PUT/DEL/POST/PATCH) ---

//  Encode a u8 slice holding a verb name ("get", "post", ...) into its
//  ron60 representation.  Consuming.  Caller normally caches the result.
fun ron60 SNIFFAtVerbOf(u8cs name) {
    a_dup(u8c, d, name);
    ron60 v = 0;
    RONutf8sDrain(&v, d);
    return v;
}

//  Cached verb constants.  First call initialises; subsequent calls
//  are branch-predicted loads.  Prefer these over re-encoding.
ron60 SNIFFAtVerbRepo  (void);
ron60 SNIFFAtVerbGet   (void);
ron60 SNIFFAtVerbPost  (void);
ron60 SNIFFAtVerbPatch (void);
ron60 SNIFFAtVerbPut   (void);
ron60 SNIFFAtVerbDelete(void);
ron60 SNIFFAtVerbMod   (void);

//  Read row 0 — the `repo` anchor.  On OK, `u_out` is parsed via
//  URILexer (slices point into the mmap, stable until ULOGClose);
//  its path component is the on-disk path of the store's `.dogs/`
//  directory.  ULOGNONE on an empty log.  Returns SNIFFFAIL if the
//  first row exists but its verb is not `repo`.
ok64 SNIFFAtRepo(urip u_out);

//  Baseline tree URI — the most recent row whose verb is `get`, `post`,
//  or `patch`.  On OK, `*ts_out` is the row's timestamp, `*verb_out`
//  is its verb, and `u_out` is parsed via URILexer (components point
//  into the mmap, valid until ULOGClose / ULOGTruncate — same contract
//  as ULOGRow).  ULOGNONE on an empty log or one with only put/delete
//  rows (shouldn't happen in practice — a bare log has no baseline).
ok64 SNIFFAtBaseline(ron60 *ts_out, ron60 *verb_out, urip u_out);

//  Timestamp of the latest `post` row, or 0 if none.  This is the floor
//  for "put/delete since last post" scans used by POST's change-set
//  computation.
ron60 SNIFFAtLastPostTs(void);

//  Look up the ULOG row whose ts equals `mtime` (the canonical
//  per-file classifier — `lstat → ron60 → row → verb`).  On OK,
//  `*verb_out` carries the owning verb and `u_out` is URILexer-
//  parsed (slices live in the mmap, valid until ULOGClose).
//  ULOGNONE if no row stamps exactly `mtime`.  Cheap binary search.
ok64 SNIFFAtRowAtTs(ron60 mtime, ron60 *verb_out, urip u_out);

//  Wall-clock guard: refuse if the system clock has moved backwards
//  past the latest log row.  Returns SNIFFCLOCKBAD when `RONNow() <
//  tail_ts`; OK otherwise (including on an empty log).  Cheap;
//  intended to run once at command entry.
ok64 SNIFFCheckClock(void);

//  Sample a wall-clock timestamp in both ULOG-row and filesystem form.
//  `*ts_out` is the ron60 stamp to append to the log; `*tv_out` is the
//  paired timespec to hand to futimens / utimensat so the file's mtime
//  round-trips through stat() + RONOfTime back to `*ts_out`.  Both
//  values share the same clock_gettime sample (no drift).  The emitted
//  ts is monotonic with respect to the ULOG tail: if the wall-clock
//  reading is not strictly greater than the tail's ts, the helper
//  bumps the returned ts (and the paired timespec) forward by 1 ms.
void SNIFFAtNow(ron60 *ts_out, struct timespec *tv_out);

//  Stamp a file's atime/mtime to `ts` via utimensat, so a later stat()
//  reports an mtime that ron60-encodes to exactly `ts`.  Path is the
//  already-terminated on-disk path.
ok64 SNIFFAtStampPath(path8b path, ron60 ts);

//  Convert an on-disk mtime (timespec) to the ron60 stamp used by the
//  ULOG stamp-set.  Truncates nanoseconds to milliseconds.
ron60 SNIFFAtOfTimespec(struct timespec ts);

//  CLI's DOGNormalizeArg routes bare tokens (`a.txt`) into the URI's
//  `query` slot rather than `path`, so `put`/`delete` see empty paths.
//  This helper picks the best bytes to treat as the row's path:
//  path → query → fragment → data.  Caller-owned `out` slice; after
//  the call its head/tail point into the caller's URI struct.
void SNIFFAtPathBytes(uri const *u, u8cs out);

//  Iterate every put/delete row whose timestamp is strictly greater
//  than `floor`, in chronological order (oldest first).  The callback
//  receives the row's verb (SNIFFAtVerbPut / SNIFFAtVerbDelete), its
//  URI path (the staged path — lives in the mmap), and its timestamp.
//  Stops early and propagates the first non-OK callback return.
typedef ok64 (*sniff_at_pd_cb)(ron60 verb, u8cs path, ron60 ts, void *ctx);
ok64 SNIFFAtScanPutDelete(ron60 floor, sniff_at_pd_cb cb, void *ctx);

//  Walk the wt rooted at `reporoot` and invoke `cb(rel, ctx)` for
//  every non-meta file whose mtime is NOT in the ULOG stamp-set
//  (i.e. user-edited / unattributed).  `rel` is the on-disk path
//  relative to `reporoot`; its bytes live in FILEScan's iteration
//  buffer and are valid only for the duration of the callback.
//  Used by `sniff status`, GET's cross-branch refusal, and PATCH's
//  refuse-if-dirty pre-flight — every consumer of the stamp-set
//  membership rule.  Stops early on the first non-OK from `cb`.
typedef ok64 (*sniff_at_dirty_cb)(u8cs rel, void *ctx);
ok64 SNIFFAtScanDirty(u8cs reporoot, sniff_at_dirty_cb cb, void *ctx);

//  Extract the current 40-hex commit SHA from a baseline URI.  The
//  canonical at-log row is `?<branch>#<curhash>` — fragment carries
//  the current sha, query carries the be-branch path.  For a `patch`
//  row mid-merge the query may also chain extra `&<theirs>` SHAs as
//  additional parents; this helper returns the row's "current" sha
//  (fragment first, then the first 40-hex spec in the query for
//  legacy rows).  Copies the 40 bytes into `out_hex40` on success.
//  Returns ULOGNONE when no such spec is present.
ok64 SNIFFAtQueryFirstSha(uricp u, u8 *out_hex40);

#endif
