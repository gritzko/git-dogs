#ifndef DOG_ULOG_H
#define DOG_ULOG_H

//  ULOG — append-only URI event log.
//
//  Each row is `<ron60-ms>\t<verb-ron60>\t<uri>\n`.  Both the timestamp
//  and the verb are RON-base64 encoded u64s (abc/RON.h): the verb
//  carries the CLI-shaped tag that drove the event (`get`, `put`,
//  `post`, `delete`, `patch`, `sync`, …).  Timestamps are strictly
//  monotonic across the file; a non-monotonic row (on append or while
//  scanning) is fatal (ULOGCLOCK).
//
//  Storage:
//    `u8bp  data`   pointer to the FILEBook'd buffer slot (FILE_WANT_BUFS
//                   entry).  Caller declares `u8bp data = NULL;` and
//                   passes `&data` to Open so FILEBook can fill it in.
//    `Bkv64 idx`    optional in-memory index, key = ts, val = byte
//                   offset of the row in `data`.  Naturally sorted by
//                   construction; rebuilt by one linear scan on Open.
//                   Pass NULL on Open to skip the build (streaming-
//                   only consumers); random-access functions require
//                   a non-NULL idx.
//
//  URI slices returned via `ulogrec.uri` point into the mmap and stay
//  valid until ULOGClose / ULOGTruncate.
//
//  Streaming primitives (`ULOGu8sFeed`, `ULOGu8sDrain`) are stateless —
//  use them when you have no file (encoding to a wire buffer, parsing
//  a `tail -f` stream, etc).
//
//  See dog/ULOG.md for the format and design notes.

#include <time.h>

#include "abc/BUF.h"
#include "abc/KV.h"
#include "abc/OK.h"
#include "abc/PATH.h"
#include "abc/RON.h"
#include "abc/URI.h"

con ok64 ULOGFAIL   = 0x7956103ca495;
con ok64 ULOGNONE   = 0x7956105d85ce;
con ok64 ULOGCLOCK  = 0x1e55840c558314;
con ok64 ULOGBADFMT = 0x7956102ca34f59d;

//  Default book reservation — 1 GiB virtual address space, 4 KiB
//  initial file size.  Callers can tune via ULOGOpenBooked.
#define ULOG_BOOK_DEFAULT (1UL << 30)
#define ULOG_INIT_DEFAULT 4096

// --- one parsed row -------------------------------------------------

typedef struct {
    ron60 ts;
    ron60 verb;
    uri   uri;     // URILexer-parsed; component slices point into the
                   // mmap (stable until ULOGClose / ULOGTruncate)
} ulogrec;
typedef ulogrec       *ulogrecp;
typedef ulogrec const *ulogreccp;

// --- streaming primitives (stateless) -------------------------------

//  Encode one row into `into`'s idle.  URI bytes are produced via
//  URIutf8Feed from `rec->uri`'s components.  Returns BNOROOM if idle
//  space is insufficient.  Monotonicity is the caller's responsibility.
ok64 ULOGu8sFeed(u8s into, ulogreccp rec);

//  Drain one complete row (through the trailing '\n') from `scan` into
//  `*out`.  On OK, `scan[0]` is advanced past the row and URILexer is
//  run against the row's URI slice — `out->uri` component slices point
//  into the input buffer; `out->uri.data` is the consumed input.
//  Field separator: one or more SP/TAB bytes.
//
//  Returns:
//    OK         one row parsed, scan advanced.
//    NODATA     no complete row yet (no '\n' in scan); scan unchanged.
//    ULOGBADFMT malformed row; scan advanced past the bad line's '\n'.
ok64 ULOGu8sDrain(u8cs scan, ulogrecp out);

// --- open / close ----------------------------------------------------

//  Open (create if missing) RW.  `idx` may be NULL (skip indexing).
//  Returns ULOGCLOCK if existing rows are not strictly monotonic,
//  ULOGBADFMT on malformed lines.
ok64 ULOGOpen(u8bp *data, kv64bp idx, path8s path);

//  Variant with explicit book sizing.
ok64 ULOGOpenBooked(u8bp *data, kv64bp idx, path8s path,
                    size_t book_size, size_t init_size);

//  Read-only open (PROT_READ via FILEBookRO).  Appends will fail.
//  Missing file is an error (no implicit create).  `idx` may be NULL.
ok64 ULOGOpenRO(u8bp *data, kv64bp idx, path8s path);

//  Close.  `rw=YES` trims the file (RW open page-aligned via FILEBook —
//  Close must trim back even if no append happened); `rw=NO` skips the
//  trim (RO opens never grew the file).  `idx` may be NULL.
//  After return, `data`'s slot is NULL'd by FILEUnBook.
ok64 ULOGClose(u8bp data, kv64bp idx, b8 rw);

// --- append ----------------------------------------------------------

//  Append a row using `RONNow()` clamped to `tail+1` ms.  On return,
//  `rec->ts` is overwritten with the stamp that was actually used.
//  Requires a non-NULL idx (used for monotonicity check + offset push).
ok64 ULOGAppend  (u8bp data, kv64bp idx, ulogrecp  rec);

//  Append with explicit ts (`rec->ts`).  Refuses ULOGCLOCK if
//  `rec->ts <= tail`.
ok64 ULOGAppendAt(u8bp data, kv64bp idx, ulogreccp rec);

// --- random access (require non-NULL idx) ---------------------------

//  Row count.
fun u32 ULOGCount(kv64b idx) { return (u32)kv64bDataLen(idx); }

//  Random access, 0-indexed.
ok64 ULOGRow(u8b data, kv64b idx, u32 i, ulogrecp out);

//  Lower-bound: smallest index i such that idx[i].key >= ts.
//  Writes the count if ts is past the tail.
ok64 ULOGSeek(kv64b idx, ron60 ts, u32 *i_out);

//  Exact-timestamp lookup.  ULOGNONE if no row has that stamp.
ok64 ULOGFind(kv64b idx, ron60 ts, u32 *i_out);

//  First / last row convenience (inline over ULOGRow).
fun ok64 ULOGHead(u8b data, kv64b idx, ulogrecp out) {
    if (ULOGCount(idx) == 0) return ULOGNONE;
    return ULOGRow(data, idx, 0, out);
}

fun ok64 ULOGTail(u8b data, kv64b idx, ulogrecp out) {
    u32 n = ULOGCount(idx);
    if (n == 0) return ULOGNONE;
    return ULOGRow(data, idx, n - 1, out);
}

//  Cheap `ts ∈ log` predicate (binary search).
fun b8 ULOGHas(kv64b idx, ron60 ts) {
    u32 i = 0;
    return ULOGFind(idx, ts, &i) == OK;
}

// --- reverse scans ---------------------------------------------------

//  Reverse scan with predicate; stops at the first row the predicate
//  accepts.  ULOGNONE if no row matches.  The predicate sees the full
//  record (verb + uri) so callers can filter on verb without needing
//  a second pass.
typedef b8 (*ulog_pred)(ulogreccp r, void *ctx);
ok64 ULOGFindLatest(u8b data, kv64b idx, ulog_pred pred, void *ctx,
                    ulogrecp out);

//  Latest row whose verb matches `verb`.  Reverse scan; stops at first
//  match.  ULOGNONE if no row carries that verb.
ok64 ULOGFindVerb(u8b data, kv64b idx, ron60 verb, ulogrecp out);

//  Iteration callback for `ULOGeachLatest`.  A non-OK return aborts
//  the walk and is propagated out.
typedef ok64 (*ulog_each_fn)(ulogreccp rec, void *ctx);

//  Walk in reverse chronological order, invoking `cb` at most ONCE per
//  unique (verb, URI-minus-fragment) key — always with the latest row
//  bearing that key.  `verb_filter == 0` considers every verb.
ok64 ULOGeachLatest(u8b data, kv64b idx, ron60 verb_filter,
                    ulog_each_fn cb, void *ctx);

//  Like `ULOGeachLatest` but the dedup key is the URI-minus-fragment
//  ALONE (verb is NOT folded into the hash).  At most one callback
//  per URI key, with the absolutely-latest row carrying that key
//  (regardless of which verb wrote it).  Useful for ref-resolution-
//  style walks where a delete row must mask earlier writes by any
//  other verb for the same key.  `verb_filter == 0` considers every
//  verb.
ok64 ULOGeachLatestKey(u8b data, kv64b idx, ron60 verb_filter,
                       ulog_each_fn cb, void *ctx);

// --- compact / truncate ---------------------------------------------

//  Rewrite the log keeping only the latest row per (verb,
//  URI-minus-fragment) key.  Atomic via `<path>.tmp` + rename(2).
//  On success `*data`/`idx` are reopened against the compacted file.
ok64 ULOGCompactLatest(u8bp *data, kv64bp idx, path8s path,
                       ron60 verb_filter);

//  Compaction — keep rows [0, keep_n), discard the rest.
ok64 ULOGTruncate(u8bp data, kv64bp idx, u32 keep_n);

// --- K-way heap merge over ULOG cursors -----------------------------
//
//  `ULOGMergeWalk` is the merge-and-fan-out primitive shared by every
//  consumer that diffs/classifies parallel ULOG streams (sniff status,
//  POST commit-time classify, graf tree diff, ...).  Each input is a
//  sorted ULOG-row cursor; `cb` fires once per distinct path-key with
//  every record whose URI key matches under `ULOGu8csZbyUri`.  Tied-
//  group capacity is `LSM_MAX_INPUTS`.
//
//  Callback shape: `(ulogreccp recs, u32 n, void *ctx) -> ok64`.  The
//  caller dispatches by `recs[i].verb` (which row came from which
//  source).  Records share the same path under the heap's compare —
//  use `recs[0].verb` to identify the lead row, then scan to find the
//  others.  Any non-OK return aborts the walk.

//  Stock comparators for `u8cssHeapZ`.  Each peeks the head row of
//  `*a` and `*b` (a_dup + ULOGu8sDrain on copies, no advance) and
//  returns YES iff *a sorts before *b.  Empty cursors compare as
//  +infinity (sink to heap tail).
b8 ULOGu8csZbyTs (u8cs const *a, u8cs const *b);  // chronological
b8 ULOGu8csZbyUri(u8cs const *a, u8cs const *b);  // URI path lex

//  K-way merge driver.  Caller heapifies cursors first:
//      u8cssHeapZ(cursors, ULOGu8csZbyUri);
//  Each call drains one row from the root (smallest) cursor into
//  `*out`, advances that cursor, and re-sifts.  Empty cursors are
//  swap-removed from the heap tail.  Returns ULOGNONE when every
//  cursor is empty.  Ties under `cmp` surface as consecutive equal-key
//  returns; caller dedups locally.
//  $len(cursors) capped at LSM_MAX_INPUTS (64).
ok64 ULOGu8ssDrainHeap(u8css cursors, u8csz cmp, ulogrecp out);

typedef ok64 (*ulog_step_fn)(ulogreccp recs, u32 n, void *ctx);

ok64 ULOGMergeWalk(u8css cursors, ulog_step_fn cb, void *ctx);

// --- Path utilities for wt-walking emitters -------------------------

//  Strip a `<reporoot>` prefix from the NUL-terminated absolute path
//  `full` (as delivered by `FILEScan`/`path8b`), yielding the trailing
//  relative slice into `*rel_out` (no leading slash).  Returns NO when
//  `full` is outside `reporoot` or names the wt root itself.
b8 ULOGu8sRelFromFull(u8csp rel_out, u8cs reporoot, u8cs full);

//  Convert a `struct timespec` (typically a file's mtime) into the
//  ron60 stamp used by ULOG row timestamps.  Truncates nanoseconds to
//  milliseconds.  `localtime`-aligned to round-trip with `RONNow`.
ron60 ULOGtsOfTimespec(struct timespec tsp);

// --- Generic worktree scanner emitting ULOG rows --------------------
//
//  Walk `reporoot` (recursive, sorted, files + symlinks), emit one
//  ULOG row per leaf into `out`:
//      <mtime-ron60>\t<verb>\t<rel-path>?<git-mode>\n
//  fragment is left empty (callers hash blobs on demand).  Output is
//  reset before writing.  `skip`, when non-NULL, is called per relative
//  path; returning YES drops the entry.  Use it for repo-meta filters
//  (`.dogs/`, `.sniff*`) and per-repo ignore lists; the dog layer is
//  agnostic to either.
typedef b8 (*ulog_skip_fn)(u8cs rel, void *ctx);

ok64 ULOGu8bScanWt(u8cs reporoot, ron60 verb,
                   ulog_skip_fn skip, void *skip_ctx,
                   u8bp out);

#endif
