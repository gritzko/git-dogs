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
//  On-disk: one FILEBook'd text file.  In-memory: a Bkv64 index where
//  key = timestamp and val = byte offset of the row in the text file.
//  The index is naturally sorted by construction and is rebuilt by one
//  linear scan on ULOGOpen.
//
//  URI slices returned by ULOGRow / ULOGTail / etc. point into the
//  mmap and stay valid until ULOGClose / ULOGTruncate.
//
//  See dog/ULOG.md for the format and design notes.

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

typedef struct {
    u8bp  data;   // FILEBook'd row text
    Bkv64 idx;    // key = ron60 timestamp, val = byte offset into data
    b8    dirty;  // appended-to since open
    b8    rw;     // opened RW (FILEBook page-aligned the file —
                  // Close must trim back even if no append happened)
} ulog;

typedef ulog       *ulogp;
typedef ulog const *ulogcp;

//  Open (create if missing) and rebuild the in-memory index.
//  Returns ULOGCLOCK if existing rows are not strictly monotonic,
//  ULOGBADFMT on malformed lines.
ok64 ULOGOpen(ulogp l, path8s path);

//  Read-only open: maps PROT_READ via FILEBookRO so the file is
//  never extended.  Appends fail; use for status / list / dry-run
//  consumers that scan but never mutate.  Missing file is an error
//  (no implicit create).
ok64 ULOGOpenRO(ulogp l, path8s path);

//  Variant with explicit book sizing; use when you expect the log to
//  grow past ULOG_BOOK_DEFAULT or want a smaller reservation.
ok64 ULOGOpenBooked(ulogp l, path8s path,
                    size_t book_size, size_t init_size);

//  Trim the file, unmap, free the index.  Safe on a zeroed ulog.
ok64 ULOGClose(ulogp l);

//  Append a row.  Stamp = RONNow(), or explicit.  `verb` is the
//  RON-encoded CLI verb (`get`, `put`, `post`, …).  The URI is
//  canonicalised via URIutf8Feed from `u`'s components — safe to
//  pass a parsed `uri` whose `data` slice was already consumed by
//  URILexer (see abc/URI.h).  Refuses to emit a row whose timestamp
//  is <= the current tail (ULOGCLOCK).
ok64 ULOGAppend  (ulogp l,             ron60 verb, uricp u);
ok64 ULOGAppendAt(ulogp l, ron60 ts,   ron60 verb, uricp u);

//  Row count.
u32  ULOGCount(ulogcp l);

//  Random access, 0-indexed.  Fills `*ts_out`, `*verb_out`, and
//  runs URILexer against the row's URI slice.  The resulting component
//  slices (scheme / authority / host / ... / query / fragment) point
//  into the mmap and are stable until ULOGClose / ULOGTruncate.
//  Per URILexer's consume contract, `u_out->data` ends up empty on
//  return — use URIutf8Feed if you need the canonical bytes back.
ok64 ULOGRow (ulogcp l, u32 i,
              ron60 *ts_out, ron60 *verb_out, urip u_out);

//  First / last row convenience.  ULOGNONE on an empty log.
ok64 ULOGHead(ulogcp l, ron60 *ts_out, ron60 *verb_out, urip u_out);
ok64 ULOGTail(ulogcp l, ron60 *ts_out, ron60 *verb_out, urip u_out);

//  Latest row whose verb matches `verb`.  O(hits) reverse scan; stops
//  at the first match.  Wraps the usual "what was the last `post` /
//  last `put`?" query.
ok64 ULOGFindVerb(ulogcp l, ron60 verb,
                  ron60 *ts_out, urip u_out);

//  Streaming row encoder.  Emits `<ts>\t<verb>\t<uri>\n` into `into`,
//  advancing `into[0]` past the written bytes.  URI bytes are produced
//  via URIutf8Feed from `u`'s components.  Returns BNOROOM if idle
//  space is insufficient.  Monotonicity is the caller's responsibility
//  here (no ulog state to check against).
ok64 ULOGu8sFeed(u8s into, ron60 ts, ron60 verb, uricp u);

//  Streaming row parser.  Drains one complete row (through the
//  trailing '\n') from `scan`.  On OK, `scan[0]` is advanced past the
//  row, `*ts_out` / `*verb_out` are filled, and URILexer is run
//  against the row's URI slice — `u_out`'s component slices point
//  into the input buffer (valid until the caller overwrites it);
//  `u_out->data` is the consumed input.  Field separator: one or more
//  SP/TAB bytes (URIs exclude both per RFC 3986, so the split is
//  unambiguous).
//
//  Returns:
//    OK         one row parsed, scan advanced.
//    NODATA     no complete row yet (no '\n' in scan); scan unchanged.
//    ULOGBADFMT malformed row; scan advanced past the bad line's '\n'.
//
//  Stateless — suitable for a `tail -f` / pipe ingest loop where rows
//  arrive in partial chunks.
ok64 ULOGu8sDrain(u8cs scan,
                  ron60 *ts_out, ron60 *verb_out, urip u_out);

//  Lower-bound: smallest index i such that idx[i].key >= ts.
//  Writes the count if ts is past the tail.
ok64 ULOGSeek(ulogcp l, ron60 ts, u32 *i_out);

//  Exact-timestamp lookup.  ULOGNONE if no row has that stamp.
ok64 ULOGFind(ulogcp l, ron60 ts, u32 *i_out);

//  Cheap `ts ∈ log` predicate (binary search).  Used by "is this
//  file mtime a known stamp" checks on the worktree.
b8   ULOGHas (ulogcp l, ron60 ts);

//  Reverse scan with predicate; stops at the first row the predicate
//  accepts.  The parsed `uri` handed to `pred` has its components
//  filled via URILexer and can be inspected by field.  ULOGNONE if
//  no row matches.
typedef b8 (*ulog_pred)(uricp u, void *ctx);
ok64 ULOGFindLatest(ulogcp l, ulog_pred pred, void *ctx,
                    ron60 *ts_out, urip u_out);

//  Iteration callback for `ULOGeachLatest`.  A non-OK return aborts
//  the walk and is propagated out.
typedef ok64 (*ulog_each_fn)(ron60 ts, ron60 verb, uricp u, void *ctx);

//  Walk the log in reverse chronological order, invoking `cb` at most
//  ONCE per unique (verb, URI-minus-fragment) key — always with the
//  latest row bearing that key.  `verb_filter == 0` considers every
//  verb; non-zero filters to matching rows only (others are invisible
//  to both dedup and callback).
//
//  The key is the URI bytes up to (not including) the first `#`.  A
//  row with no `#` keys on its whole URI.  Dedup compares
//  `rapidhash(key)` — collisions are astronomically unlikely at
//  realistic log sizes.
ok64 ULOGeachLatest(ulogcp l, ron60 verb_filter,
                    ulog_each_fn cb, void *ctx);

//  Rewrite the log keeping only the latest row per
//  (verb, URI-minus-fragment) key among rows whose verb matches
//  `verb_filter` (or every row if `verb_filter == 0`).  Non-matching
//  verbs — when a filter is set — are preserved verbatim.  Kept rows
//  are re-emitted in timestamp order.
//
//  Atomic via `<path>.tmp` + rename(2).  On success `l` is closed
//  and reopened against the compacted file; on failure `l` remains
//  open against the original.
ok64 ULOGCompactLatest(ulogp l, path8s path, ron60 verb_filter);

//  Compaction — keep rows [0, keep_n), discard the rest.  Rewrites the
//  book in place and truncates the index.  keep_n == ULOGCount() is a
//  no-op; keep_n > ULOGCount() is ULOGFAIL.
ok64 ULOGTruncate(ulogp l, u32 keep_n);

#endif
