//  ULOG — append-only URI event log.
//  See dog/ULOG.h for the API and dog/ULOG.md for the format.
//
#include "ULOG.h"

#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "abc/BUF.h"
#include "abc/FILE.h"
#include "abc/LSM.h"     // brings HEAPx<u8cs> primitives
#include "abc/PATH.h"
#include "abc/PRO.h"
#include "abc/RAP.h"
#include "abc/RON.h"
#include "abc/URI.h"
#include "dog/WHIFF.h"

// --- streaming primitives --------------------------------------------

ok64 ULOGu8sFeed(u8s into, ulogreccp rec) {
    sane(into && rec);
    //  Rough capacity check.  URIutf8Feed stops with its own failure
    //  if the component data doesn't fit; here we just make sure the
    //  fixed parts (ts + verb + two tabs + '\n') have room.  Assume
    //  at least 48 idle bytes available for those.
    if ((size_t)$len(into) < 48) return BNOROOM;
    call(RONutf8sFeed, into, rec->ts);
    call(u8sFeed1, into, '\t');
    call(RONutf8sFeed, into, rec->verb);
    call(u8sFeed1, into, '\t');
    uri u = rec->uri;
    call(URIutf8Feed, into, &u);
    call(u8sFeed1, into, '\n');
    done;
}

//  Advance `scan` past the next `\n` in [scan, scan[1]).  Used to
//  recover from a malformed row.
static void ulog_skip_line(u8cs scan) {
    u8cp p = scan[0];
    while (p < scan[1] && *p != '\n') p++;
    if (p < scan[1]) p++;
    scan[0] = p;
}

//  Whitespace separator: any run of SP or TAB.  RON base64 and URI
//  byte alphabets both exclude both, so the split is unambiguous.
static b8 ulog_is_ws(u8 c) { return c == ' ' || c == '\t'; }

static u8cp ulog_skip_ws(u8cp p, u8cp e) {
    while (p < e && ulog_is_ws(*p)) p++;
    return p;
}

static u8cp ulog_find_ws(u8cp p, u8cp e) {
    while (p < e && !ulog_is_ws(*p)) p++;
    return p;
}

ok64 ULOGu8sDrain(u8cs scan, ulogrecp out) {
    sane(scan && out);

    //  Need a terminating '\n' to have a complete row.
    u8cp nl = scan[0];
    while (nl < scan[1] && *nl != '\n') nl++;
    if (nl == scan[1]) return NODATA;

    u8cp p = scan[0];
    u8cp e = nl;

    //  ts = first token.
    u8cp ts_beg = p;
    u8cp ts_end = ulog_find_ws(ts_beg, e);
    if (ts_end == ts_beg || ts_end == e) {
        ulog_skip_line(scan);
        fail(ULOGBADFMT);
    }
    u8cs ts_str = {ts_beg, ts_end};
    ron60 ts = 0;
    a_dup(u8c, ts_dup, ts_str);
    if (RONutf8sDrain(&ts, ts_dup) != OK) {
        ulog_skip_line(scan);
        fail(ULOGBADFMT);
    }

    //  verb = second token.
    u8cp vb_beg = ulog_skip_ws(ts_end, e);
    u8cp vb_end = ulog_find_ws(vb_beg, e);
    if (vb_beg == e || vb_end == vb_beg || vb_end == e) {
        ulog_skip_line(scan);
        fail(ULOGBADFMT);
    }
    u8cs verb_str = {vb_beg, vb_end};
    ron60 verb = 0;
    a_dup(u8c, verb_dup, verb_str);
    if (RONutf8sDrain(&verb, verb_dup) != OK) {
        ulog_skip_line(scan);
        fail(ULOGBADFMT);
    }

    //  uri = rest of line (URIs disallow SP/TAB per RFC 3986).  Hand
    //  it to URILexer — component slices will point into `scan`'s
    //  backing bytes.
    u8cp uri_head = ulog_skip_ws(vb_end, e);
    u8cp uri_term = e;
    if (uri_head == uri_term) {
        ulog_skip_line(scan);
        fail(ULOGBADFMT);
    }
    memset(out, 0, sizeof(*out));
    out->uri.data[0] = uri_head;
    out->uri.data[1] = uri_term;
    if (URILexer(&out->uri) != OK) {
        ulog_skip_line(scan);
        fail(ULOGBADFMT);
    }

    out->ts   = ts;
    out->verb = verb;
    scan[0]   = nl + 1;
    done;
}

// --- index helpers ---------------------------------------------------

//  Read entry i from idx without bounds checking.  Caller has already
//  verified i < ULOGCount(idx).
static wh128 ulog_idx_at(wh128bp idx, u32 i) {
    wh128 const *a = (wh128 const *)idx[0];
    return a[i];
}

//  Pointer to the entry slot at index i (writable).  Used to overwrite
//  the tail sentinel in place.
static wh128 *ulog_idx_slot(wh128bp idx, u32 i) {
    return (wh128 *)idx[0] + i;
}

//  Push one wh128 into idx.  Wraps wh128bPush; callers expect the
//  underlying buffer to have idle room (booked sidecars grow on demand
//  via FILEBookEnsure; anonymous fallbacks pre-size for the rebuild).
static ok64 ulog_idx_push(wh128bp idx, wh128 e) {
    return wh128bPush(idx, &e);
}

//  Lower-bound on the wh128 index by timestamp key.  Excludes the
//  tail sentinel.
static u32 ulog_lower_bound(wh128bp idx, ron60 ts) {
    u32 n = ULOGCount(idx);
    wh128 const *a = (wh128 const *)idx[0];
    u32 lo = 0, hi = n;
    while (lo < hi) {
        u32 mid = lo + (hi - lo) / 2;
        if ((ron60)a[mid].key < ts) lo = mid + 1;
        else                        hi = mid;
    }
    return lo;
}

//  Compute the end pointer of the row whose start sits at `row_start`
//  in the log map.  Returns NULL if no '\n' is found before idle.
static u8 const *ulog_row_end(u8b data, u8 const *row_start) {
    u8 const *end = (u8 const *)data[2];   // idle head = first byte past data
    u8 const *p = row_start;
    while (p < end && *p != '\n') p++;
    return (p < end) ? p + 1 : NULL;
}

//  Scan the log mmap, fill the index (without sentinel), enforce strict
//  monotonicity.  Idle head of `data` is positioned past the last
//  complete row when this returns OK.  `idx` is reset before scanning;
//  caller pushes the sentinel after this returns.
static ok64 ulog_scan_log(u8bp data, wh128bp idx) {
    sane(data && idx);
    wh128bReset(idx);

    u8 *base = (u8 *)data[0];
    u8 *end  = (u8 *)data[3];
    u8cs scan = {base, end};
    u8 *last_nl_plus_one = base;
    ron60 prev = 0;
    while (scan[0] < scan[1]) {
        if (*scan[0] == 0) break;                             // zero-pad tail
        if (*scan[0] == '\n') {
            scan[0]++; last_nl_plus_one = (u8 *)scan[0]; continue;  // blank line
        }

        u64 off = (u64)(scan[0] - base);
        ulogrec rec = {};
        ok64 o = ULOGu8sDrain(scan, &rec);
        if (o == NODATA) break;
        if (o != OK) return o;

        if (ULOGCount(idx) > 0 && rec.ts <= prev) fail(ULOGCLOCK);
        call(ulog_idx_push, idx, ulogIdxEntry(rec.ts, rec.verb, off));
        prev = rec.ts;
        last_nl_plus_one = (u8 *)scan[0];
    }

    u8 **data_head = (u8 **)&data[1];
    u8 **idle_head = (u8 **)&data[2];
    *data_head = base;
    *idle_head = last_nl_plus_one;
    done;
}

//  Compose `<dir>/.<base>.idx` (NUL-terminated) into `out`.  `out` is
//  reset before writing.  `log_path` is a NUL-terminated path slice;
//  trailing NUL bytes (the caller's path-buffer convention) are
//  stripped before basename extraction.
static ok64 ulog_idx_path(path8b out, path8s log_path) {
    sane($ok(out) && $ok(log_path));
    u8bReset(out);

    u8cs trimmed = {log_path[0], log_path[1]};
    while (trimmed[1] > trimmed[0] && *(trimmed[1] - 1) == 0) trimmed[1]--;

    u8cs dir = {}, base = {};
    PATHu8sDir (dir,  trimmed);
    PATHu8sBase(base, trimmed);
    if ($empty(base)) fail(ULOGFAIL);

    //  Dir + '/' + '.' + base + ".idx"
    if (!$empty(dir) && !($len(dir) == 1 && *dir[0] == '.')) {
        call(u8bFeed, out, dir);
        call(u8bFeed1, out, '/');
    }
    call(u8bFeed1, out, '.');
    call(u8bFeed, out, base);
    a_cstr(suf, ".idx");
    call(u8bFeed, out, suf);
    call(PATHu8bTerm, out);
    done;
}

//  Allocate an anonymous-mmap-backed wh128b descriptor on the heap.
//  Used for RO + missing sidecar.  The caller's `*idx_out` is set to
//  point at a 4-pointer slot; ULOGCloseIdx detects this via
//  `FILEIsBooked` and frees both the slot and the mapping.
static ok64 ulog_idx_alloc_anon(wh128bp *idx_out, size_t entry_cap) {
    sane(idx_out);
    size_t bytes = entry_cap * sizeof(wh128);
    void *mem = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) fail(ULOGFAIL);
    wh128 **slot = (wh128 **)calloc(4, sizeof(wh128 *));
    if (!slot) {
        munmap(mem, bytes);
        fail(ULOGFAIL);
    }
    slot[0] = (wh128 *)mem;
    slot[1] = slot[0];                          // past = base (no past)
    slot[2] = slot[0];                          // idle = base (no data yet)
    slot[3] = slot[0] + entry_cap;              // term
    *idx_out = (wh128bp)slot;
    done;
}

//  Free an anonymous-mmap idx (counterpart of ulog_idx_alloc_anon).
static void ulog_idx_free_anon(wh128bp idx) {
    if (!idx || !idx[0]) return;
    size_t bytes = (size_t)((wh128 const *)idx[3] - (wh128 const *)idx[0])
                 * sizeof(wh128);
    munmap((void *)idx[0], bytes);
    free((void *)idx);
}

//  Fetch the log file's mtime via fstat on the booked fd.  Returns 0
//  if the buffer isn't booked or the fstat fails — both treated as
//  "force rebuild" by the freshness check.
static ron60 ulog_log_mtime(u8b data) {
    int fd = FILEBookedFD((u8bp)data);
    if (fd < 0) return 0;
    filestat fs = {};
    if (FILEFStat(&fs, &fd) != OK) return 0;
    return fs.mtime;
}

//  Validate the sidecar's tail sentinel against the log's actual size
//  AND mtime.  Returns YES iff both match — neither size-only matches
//  nor mtime-only matches qualify (rebuild on any discrepancy).
static b8 ulog_idx_is_fresh(wh128bp idx, u8b data) {
    size_t n = wh128bDataLen(idx);
    if (n == 0) return NO;
    wh128 sentinel = ulog_idx_at(idx, (u32)(n - 1));
    u64 logged_size = ulogIdxSentinelSize(sentinel);
    u64 actual_size = (u64)((u8 const *)data[2] - (u8 const *)data[0]);
    if (logged_size != actual_size) return NO;
    ron60 logged_mtime = ulogIdxSentinelMtime(sentinel);
    if (logged_mtime == 0) return NO;  // no mtime recorded yet
    ron60 actual_mtime = ulog_log_mtime(data);
    return logged_mtime == actual_mtime;
}

//  Append the tail sentinel to idx.  The sentinel records the log's
//  current byte size and mtime; on the close path (after FILETrimBook)
//  the mtime captured here is what the next Open will compare against.
//  Mid-stream pushes (after each Append) write a best-effort mtime —
//  the close-time refresh is what makes the freshness check load-bearing.
static ok64 ulog_idx_push_sentinel(wh128bp idx, u8b data) {
    u64 log_size = (u64)((u8 const *)data[2] - (u8 const *)data[0]);
    ron60 mtime = ulog_log_mtime(data);
    return ulog_idx_push(idx, ulogIdxSentinel(mtime, log_size));
}

//  Overwrite the tail sentinel in place (no push) — used on the close
//  path after FILETrimBook so the recorded mtime reflects the final
//  on-disk state.  Caller guarantees a sentinel already exists.
static void ulog_idx_refresh_sentinel(wh128bp idx, u8b data) {
    size_t n = wh128bDataLen(idx);
    if (n == 0) return;
    u64 log_size = (u64)((u8 const *)data[2] - (u8 const *)data[0]);
    ron60 mtime = ulog_log_mtime(data);
    *ulog_idx_slot(idx, (u32)(n - 1)) = ulogIdxSentinel(mtime, log_size);
}

//  Rebuild idx by linear scan of the log, then append the sentinel.
static ok64 ulog_idx_rebuild(wh128bp idx, u8bp data) {
    sane(idx && data);
    call(ulog_scan_log, data, idx);
    return ulog_idx_push_sentinel(idx, data);
}

// --- public idx API --------------------------------------------------

ok64 ULOGOpenIdx(wh128bp *idx_out, path8s log_path, u8b log_data, b8 ro) {
    sane(idx_out && $ok(log_path) && log_data);

    a_path(idx_path);
    call(ulog_idx_path, idx_path, log_path);

    //  Try the on-disk sidecar first.
    *idx_out = NULL;
    ok64 oo = ro ? FILEBookRO((u8bp *)idx_out, $path(idx_path),
                              ULOG_IDX_BOOK_DEFAULT)
                 : FILEBook  ((u8bp *)idx_out, $path(idx_path),
                              ULOG_IDX_BOOK_DEFAULT);
    if (oo != OK && !ro) {
        //  RW path with missing sidecar: create it.
        oo = FILEBookCreate((u8bp *)idx_out, $path(idx_path),
                            ULOG_IDX_BOOK_DEFAULT, ULOG_IDX_INIT_DEFAULT);
    }

    if (oo == OK) {
        //  Booked successfully.  Validate freshness; rebuild if stale.
        if (ulog_idx_is_fresh(*idx_out, log_data)) done;

        if (ro) {
            //  RO sidecar but stale — we cannot write through to disk.
            //  Drop the booked map and fall through to the anonymous
            //  mmap rebuild path (quiet fallback).
            FILEUnBook((u8bp)*idx_out);
            *idx_out = NULL;
        } else {
            //  RW: rebuild in place, sentinel reflects new tail.
            ok64 ro2 = ulog_idx_rebuild(*idx_out, (u8bp)log_data);
            if (ro2 != OK) {
                FILEUnBook((u8bp)*idx_out);
                *idx_out = NULL;
                return ro2;
            }
            done;
        }
    }

    //  Quiet anonymous-mmap fallback.  Size for one entry per ~16 B of
    //  log; cap at the booked-RW capacity so we don't outgrow it.
    u64 log_size = (u64)((u8 const *)log_data[2] - (u8 const *)log_data[0]);
    size_t cap = (size_t)(log_size / 16) + 1024;
    if (cap > (ULOG_IDX_BOOK_DEFAULT / sizeof(wh128))) {
        cap = ULOG_IDX_BOOK_DEFAULT / sizeof(wh128);
    }
    call(ulog_idx_alloc_anon, idx_out, cap);
    ok64 ro3 = ulog_idx_rebuild(*idx_out, (u8bp)log_data);
    if (ro3 != OK) {
        ulog_idx_free_anon(*idx_out);
        *idx_out = NULL;
        return ro3;
    }
    done;
}

ok64 ULOGCloseIdx(wh128bp *idx) {
    sane(idx);
    if (!*idx) done;
    if (FILEIsBooked((u8bp)*idx)) {
        //  Trim the sidecar back to its actual data length so the next
        //  Open's FILEBook sees b[2] at the real entry tail, not at
        //  page-aligned trailing zero pad.  Without this, reopen reads
        //  garbage entries from the unused tail of the page.
        FILETrimBook((u8bp)*idx);
        FILEUnBook((u8bp)*idx);
    } else {
        ulog_idx_free_anon(*idx);
    }
    *idx = NULL;
    done;
}

// --- public log + idx API --------------------------------------------

ok64 ULOGOpenBooked(u8bp *data, wh128bp *idx, path8s path,
                    size_t book_size, size_t init_size) {
    sane(data && $ok(path));

    ok64 o = FILEBook(data, path, book_size);
    if (o != OK) {
        call(FILEBookCreate, data, path, book_size, init_size);
    }

    //  Position the log's idle head past the last complete row before
    //  the idx scan/load — we need the byte size right.
    {
        wh128bp tmp = NULL;
        call(ulog_idx_alloc_anon, &tmp, 1024);
        ok64 so = ulog_scan_log(*data, tmp);
        ulog_idx_free_anon(tmp);
        if (so != OK) {
            if (*data && (*data)[0]) FILEUnBook(*data);
            return so;
        }
    }

    if (idx) {
        ok64 io = ULOGOpenIdx(idx, path, *data, NO);
        if (io != OK) {
            if (*data && (*data)[0]) FILEUnBook(*data);
            return io;
        }
    }
    done;
}

ok64 ULOGOpen(u8bp *data, wh128bp *idx, path8s path) {
    return ULOGOpenBooked(data, idx, path,
                          ULOG_BOOK_DEFAULT, ULOG_INIT_DEFAULT);
}

ok64 ULOGOpenRO(u8bp *data, wh128bp *idx, path8s path) {
    sane(data && $ok(path));

    //  RO map only — fails if file is missing (no implicit create).
    call(FILEBookRO, data, path, ULOG_BOOK_DEFAULT);

    //  Fix up data's idle head via a throw-away scan (read-only path —
    //  we won't write the sidecar from here).
    {
        wh128bp tmp = NULL;
        call(ulog_idx_alloc_anon, &tmp, 1024);
        ok64 so = ulog_scan_log(*data, tmp);
        ulog_idx_free_anon(tmp);
        if (so != OK) {
            if (*data && (*data)[0]) FILEUnBook(*data);
            return so;
        }
    }

    if (idx) {
        ok64 io = ULOGOpenIdx(idx, path, *data, YES);
        if (io != OK) {
            if (*data && (*data)[0]) FILEUnBook(*data);
            return io;
        }
    }
    done;
}

ok64 ULOGClose(u8bp data, wh128bp *idx, b8 rw) {
    sane(data);
    if (data[0]) {
        //  Any RW open page-aligned the file via FILEBook's
        //  ftruncate, so Close must trim back regardless of
        //  whether anything was actually appended.  Otherwise an
        //  early-fail RW SNIFFExec leaves trailing pad bytes
        //  visible to the next reader.  RO opens (FILEBookRO)
        //  never grew the file — skip the trim.
        if (rw) FILETrimBook(data);
        //  Refresh the sidecar sentinel's mtime/size BEFORE closing
        //  the idx so the persisted sentinel matches what fstat would
        //  see on the next Open.  RO closes have a private (or anon)
        //  idx that won't flush to disk — refresh is a no-op there.
        if (rw && idx && *idx) ulog_idx_refresh_sentinel(*idx, data);
    }
    if (idx) ULOGCloseIdx(idx);
    if (data[0]) {
        FILEUnBook(data);     // also nullifies the buffer slots
    }
    done;
}

// --- append ---------------------------------------------------------

ok64 ULOGAppendAt(u8bp data, wh128bp idx, ulogreccp rec) {
    sane(data && idx && rec);
    u32 n = ULOGCount(idx);
    if (n > 0) {
        ron60 last_ts = (ron60)ulog_idx_at(idx, n - 1).key;
        if (rec->ts <= last_ts) fail(ULOGCLOCK);
    }
    call(FILEBookEnsure, data, 2048);
    if (FILEIsBooked((u8bp)idx)) {
        call(FILEBookEnsure, (u8bp)idx, 2 * sizeof(wh128));
    }

    u64 off = (u64)u8bDataLen(data);
    call(ULOGu8sFeed, u8bIdle(data), rec);

    //  Replace the existing tail sentinel with the new row, then push
    //  a fresh sentinel.  The sentinel is always at idx[N] (busy tail).
    wh128 entry = ulogIdxEntry(rec->ts, rec->verb, off);
    if (wh128bDataLen(idx) > 0) {
        *ulog_idx_slot(idx, ULOGCount(idx)) = entry;   // overwrite sentinel
    } else {
        call(ulog_idx_push, idx, entry);
    }
    call(ulog_idx_push_sentinel, idx, data);
    done;
}

ok64 ULOGAppend(u8bp data, wh128bp idx, ulogrecp rec) {
    sane(data && idx && rec);
    //  Clamp to max(RONNow(), tail+1) so rapid same-ms appends
    //  still land instead of tripping ULOGCLOCK.
    ron60 now = RONNow();
    u32 n = ULOGCount(idx);
    if (n > 0) {
        ron60 last_ts = (ron60)ulog_idx_at(idx, n - 1).key;
        if (now <= last_ts) now = last_ts + 1;
    }
    rec->ts = now;
    return ULOGAppendAt(data, idx, rec);
}

// --- random access --------------------------------------------------

ok64 ULOGRow(u8b data, wh128bp idx, u32 i, ulogrecp out) {
    sane(data && idx && out);
    if (i >= ULOGCount(idx)) fail(ULOGNONE);
    wh128 ent = ulog_idx_at(idx, i);
    a_dup(u8c, dview, u8bDataC(data));

    u8cs scan = {dview[0] + ulogIdxOff(ent), dview[1]};
    return ULOGu8sDrain(scan, out);
}

ok64 ULOGSeek(wh128bp idx, ron60 ts, u32 *i_out) {
    sane(idx && i_out);
    *i_out = ulog_lower_bound(idx, ts);
    done;
}

ok64 ULOGFind(wh128bp idx, ron60 ts, u32 *i_out) {
    sane(idx && i_out);
    u32 i = ulog_lower_bound(idx, ts);
    u32 n = ULOGCount(idx);
    if (i >= n) fail(ULOGNONE);
    if ((ron60)ulog_idx_at(idx, i).key != ts) fail(ULOGNONE);
    *i_out = i;
    done;
}

ok64 ULOGFindLatest(u8b data, wh128bp idx, ulog_pred pred, void *ctx,
                    ulogrecp out) {
    sane(data && idx && pred && out);
    u32 n = ULOGCount(idx);
    for (u32 i = n; i > 0; ) {
        i--;
        ulogrec r = {};
        ok64 o = ULOGRow(data, idx, i, &r);
        if (o != OK) return o;
        if (pred(&r, ctx)) {
            *out = r;
            done;
        }
    }
    fail(ULOGNONE);
}

ok64 ULOGFindVerb(u8b data, wh128bp idx, ron60 verb, ulogrecp out) {
    sane(data && idx && out);
    u32 n = ULOGCount(idx);
    u32 want_h = ulogVerbHash(verb);
    for (u32 i = n; i > 0; ) {
        i--;
        wh128 ent = ulog_idx_at(idx, i);
        if (ulogIdxVerbH(ent) != want_h) continue;     // 20-bit prefilter
        ulogrec r = {};
        ok64 o = ULOGRow(data, idx, i, &r);
        if (o != OK) return o;
        if (r.verb == verb) {
            *out = r;
            done;
        }
    }
    fail(ULOGNONE);
}

// --- latest-per-key helpers ------------------------------------------

//  Compute the key slice for row `i`: the URI bytes up to (but not
//  including) the first `#`.  Walks the raw row text in the mmap —
//  O(row length) — avoiding URIutf8Feed's component reassembly.
static void ulog_row_key_bytes(u8b data, wh128bp idx, u32 i, u8csp out) {
    wh128 ent = ulog_idx_at(idx, i);
    u8cp base = (u8cp)data[0];
    u8cp row  = base + ulogIdxOff(ent);
    u8cp end  = (u8cp)data[2];  // idle head = first byte past data
    u8cp nl = row;
    while (nl < end && *nl != '\n') nl++;

    //  Skip two tab/space-separated tokens (ts, verb) to reach the URI.
    u8cp p = row;
    int tok = 0;
    while (tok < 2 && p < nl) {
        while (p < nl && *p != '\t' && *p != ' ') p++;
        while (p < nl && (*p == '\t' || *p == ' ')) p++;
        tok++;
    }
    u8cp uri_begin = p;
    //  Key ends at the first '#' or at end-of-line.
    u8cp h = uri_begin;
    while (h < nl && *h != '#') h++;

    out[0] = uri_begin;
    out[1] = h;
}

//  Linear-scan "seen" set of u64 hashes.  For N ≤ a few thousand
//  unique keys the O(N²) total is trivially fast; bigger logs would
//  want a proper hash table (HASHx).  Documented in ULOG.md.
static b8 seen_contains(Bu64 seen, u64 h) {
    u64 const *a = (u64 const *)seen[0];
    u32 n = (u32)u64bDataLen(seen);
    for (u32 j = 0; j < n; j++) if (a[j] == h) return YES;
    return NO;
}

//  Shared body for the latest-walk variants.  `dedup_per_verb=YES`
//  matches `ULOGeachLatest`'s historical behaviour ((key, verb) hash);
//  `dedup_per_verb=NO` matches `ULOGeachLatestKey`'s URI-key-only
//  hash.  Keeping one body avoids drift between the two surfaces.
static ok64 ulog_each_latest(u8b data, wh128bp idx, ron60 verb_filter,
                             b8 dedup_per_verb,
                             ulog_each_fn cb, void *ctx) {
    sane(data && idx && cb);
    u32 n = ULOGCount(idx);
    if (n == 0) done;

    Bu64 seen = {};
    call(u64bAllocate, seen, 1024);

    ok64 rc = OK;
    for (u32 i = n; i > 0; ) {
        i--;
        ulogrec r = {};
        ok64 o = ULOGRow(data, idx, i, &r);
        if (o != OK) { rc = o; break; }
        if (verb_filter && r.verb != verb_filter) continue;

        u8cs key = {};
        ulog_row_key_bytes(data, idx, i, key);
        u64 h = dedup_per_verb ? RAPHashSeed(key, (u64)r.verb)
                                : RAPHashSeed(key, 0);
        if (seen_contains(seen, h)) continue;
        u64bFeed1(seen, h);

        rc = cb(&r, ctx);
        if (rc != OK) break;
    }

    u64bFree(seen);
    return rc;
}

ok64 ULOGeachLatest(u8b data, wh128bp idx, ron60 verb_filter,
                    ulog_each_fn cb, void *ctx) {
    return ulog_each_latest(data, idx, verb_filter, YES, cb, ctx);
}

ok64 ULOGeachLatestKey(u8b data, wh128bp idx, ron60 verb_filter,
                       ulog_each_fn cb, void *ctx) {
    return ulog_each_latest(data, idx, verb_filter, NO, cb, ctx);
}

// --- ULOGCompactLatest -----------------------------------------------

//  Two-pass compaction: mark keep-bits on a reverse walk, then append
//  kept rows forward into a fresh tmp log and rename over the original.
ok64 ULOGCompactLatest(u8bp *data, wh128bp *idx, path8s path,
                       ron60 verb_filter) {
    sane(data && idx && $ok(path));

    u32 n = ULOGCount(*idx);
    if (n == 0) done;

    b8 *keep = (b8 *)calloc((size_t)n, 1);
    if (!keep) fail(ULOGFAIL);

    Bu64 seen = {};
    ok64 allo = u64bAllocate(seen, 1024);
    if (allo != OK) { free(keep); return allo; }

    //  Pass 1: reverse walk, mark rows that survive compaction.
    for (u32 i = n; i > 0; ) {
        i--;
        ulogrec r = {};
        ok64 o = ULOGRow(*data, *idx, i, &r);
        if (o != OK) { u64bFree(seen); free(keep); return o; }

        if (verb_filter && r.verb != verb_filter) {
            keep[i] = 1;
            continue;
        }
        u8cs key = {};
        ulog_row_key_bytes(*data, *idx, i, key);
        //  Dedup key includes verb: seed the hash with verb so two
        //  different verbs over the same URI-minus-fragment key hash
        //  to different slots.
        u64 h = RAPHashSeed(key, (u64)r.verb);
        if (seen_contains(seen, h)) continue;
        u64bFeed1(seen, h);
        keep[i] = 1;
    }
    u64bFree(seen);

    //  Build `<path>.tmp`.
    a_pad(u8, tmp_buf, FILE_PATH_MAX_LEN);
    u8bFeed(tmp_buf, path);
    a_cstr(tmp_suffix, ".tmp");
    if (u8bFeed(tmp_buf, tmp_suffix) != OK) { free(keep); fail(ULOGFAIL); }
    if (PATHu8bTerm(tmp_buf) != OK) { free(keep); fail(ULOGFAIL); }
    a_dup(u8c, tmp_path, u8bDataC(tmp_buf));
    (void)unlink((char const *)tmp_path[0]);

    //  Also unlink the tmp log's sidecar to avoid stale-sidecar
    //  surprise when we reopen below.
    {
        a_path(tmp_idx_path);
        ok64 ip = ulog_idx_path(tmp_idx_path, tmp_path);
        if (ip == OK) (void)unlink((char const *)$path(tmp_idx_path)[0]);
    }

    u8bp    tmp_data = NULL;
    wh128bp tmp_idx  = NULL;
    ok64 oo = ULOGOpen(&tmp_data, &tmp_idx, tmp_path);
    if (oo != OK) { free(keep); return oo; }

    //  Pass 2: forward walk, re-append kept rows into tmp.
    for (u32 i = 0; i < n; i++) {
        if (!keep[i]) continue;
        ulogrec r = {};
        ok64 o = ULOGRow(*data, *idx, i, &r);
        if (o != OK) {
            ULOGClose(tmp_data, &tmp_idx, YES);
            free(keep); return o;
        }
        ok64 ao = ULOGAppendAt(tmp_data, tmp_idx, &r);
        if (ao != OK) {
            ULOGClose(tmp_data, &tmp_idx, YES);
            free(keep); return ao;
        }
    }
    free(keep);
    ULOGClose(tmp_data, &tmp_idx, YES);

    //  Swap files: close source (drops the source sidecar), rename
    //  tmp → path (the tmp sidecar stays at .<tmp>.idx and is now
    //  stale w.r.t. the new path; unlink it and the source sidecar).
    a_path(src_idx_path);
    (void)ulog_idx_path(src_idx_path, path);
    a_path(tmp_idx_path);
    (void)ulog_idx_path(tmp_idx_path, tmp_path);

    ULOGClose(*data, idx, YES);
    (void)unlink((char const *)$path(src_idx_path)[0]);
    (void)unlink((char const *)$path(tmp_idx_path)[0]);

    ok64 ro = FILERename(tmp_path, path);
    if (ro != OK) {
        //  Best-effort recovery: try to reopen the original (still intact).
        (void)ULOGOpen(data, idx, path);
        return ro;
    }
    call(ULOGOpen, data, idx, path);
    done;
}

ok64 ULOGTruncate(u8bp data, wh128bp idx, u32 keep_n) {
    sane(data && idx);
    u32 n = ULOGCount(idx);
    if (keep_n > n) fail(ULOGFAIL);
    if (keep_n == n) done;

    u64 cut_off = 0;
    if (keep_n > 0) {
        wh128 ent = ulog_idx_at(idx, keep_n);    // first row to discard
        cut_off = ulogIdxOff(ent);
    }

    //  Shrink the wh128 index to `keep_n` entries (sentinel re-pushed
    //  after the data trim).
    wh128 **idle_idx = wh128bIdle(idx);
    wh128 *base = (wh128 *)idx[0];
    *idle_idx = base + keep_n;

    //  Drop the tail bytes of the data book.  Zero the discarded
    //  region so a reopen's rebuild halts at the first NUL; we
    //  deliberately do NOT ftruncate — keeping the backing file
    //  page-aligned is what lets subsequent MAP_SHARED writes land on
    //  strict filesystems (ext4 silently drops writes past EOF even
    //  within a page-aligned mmap).
    u8 *data_base  = (u8 *)data[0];
    u8 **data_idle = u8bIdle(data);
    u8 *old_idle   = *data_idle;
    u8 *new_idle   = data_base + cut_off;
    if (new_idle < old_idle) memset(new_idle, 0, (size_t)(old_idle - new_idle));
    *data_idle = new_idle;

    //  Re-push the tail sentinel for the new tail.
    return ulog_idx_push_sentinel(idx, data);
}

// --- K-way heap merge over ULOG cursors -----------------------------

//  Peek the head row of a cursor without advancing it.
static ok64 ulog_peek_row(u8cs scan, ulogrecp out) {
    a_dup(u8c, dup, scan);
    return ULOGu8sDrain(dup, out);
}

b8 ULOGu8csZbyTs(u8cs const *a, u8cs const *b) {
    a_dup(u8c, da, *a);
    a_dup(u8c, db, *b);
    if (u8csEmpty(da)) return NO;
    if (u8csEmpty(db)) return YES;
    ulogrec ra = {}, rb = {};
    if (ulog_peek_row(da, &ra) != OK) return NO;
    if (ulog_peek_row(db, &rb) != OK) return YES;
    return ra.ts < rb.ts;
}

b8 ULOGu8csZbyUri(u8cs const *a, u8cs const *b) {
    a_dup(u8c, da, *a);
    a_dup(u8c, db, *b);
    if (u8csEmpty(da)) return NO;
    if (u8csEmpty(db)) return YES;
    ulogrec ra = {}, rb = {};
    if (ulog_peek_row(da, &ra) != OK) return NO;
    if (ulog_peek_row(db, &rb) != OK) return YES;
    //  URI key = path component.  Falls back to query when path is
    //  empty (bare `?ref` URIs from REFS rows).
    u8cs ka = {}, kb = {};
    if (u8csEmpty(ra.uri.path)) u8csMv(ka, ra.uri.query);
    else                        u8csMv(ka, ra.uri.path);
    if (u8csEmpty(rb.uri.path)) u8csMv(kb, rb.uri.query);
    else                        u8csMv(kb, rb.uri.path);
    return u8csZ(&ka, &kb);
}

ok64 ULOGu8ssDrainHeap(u8css cursors, u8csz cmp, ulogrecp out) {
    sane(cursors && cmp && out);
    while (!$empty(cursors)) {
        u8cs *root = $head(cursors);
        if (u8csEmpty(*root)) {
            //  Swap-remove the empty root from the heap, sift, retry.
            u8csSwap(root, $last(cursors));
            --$term(cursors);
            if ($empty(cursors)) break;
            u8cssDownZ(cursors, cmp);
            continue;
        }
        ok64 d = ULOGu8sDrain(*root, out);
        //  Re-sift: the root cursor advanced, its head may have
        //  grown larger than other heap members.
        u8cssDownZ(cursors, cmp);
        return d;
    }
    return ULOGNONE;
}

// --- ULOGMergeWalk: heap-merge over parallel ULOG cursors -----------

static b8 ulog_path_eq(ulogreccp a, ulogreccp b) {
    u8cs ka = {}, kb = {};
    if (u8csEmpty(a->uri.path)) u8csMv(ka, a->uri.query);
    else                        u8csMv(ka, a->uri.path);
    if (u8csEmpty(b->uri.path)) u8csMv(kb, b->uri.query);
    else                        u8csMv(kb, b->uri.path);
    return u8csEq(ka, kb);
}

ok64 ULOGMergeWalk(u8css cursors, ulog_step_fn cb, void *ctx) {
    sane(cursors && cb);
    if ($empty(cursors)) done;

    //  Heapify in place — cursors[0] becomes the root (smallest URI key).
    u8cssHeapZ(cursors, ULOGu8csZbyUri);

    ulogrec group[LSM_MAX_INPUTS];
    u32     n = 0;

    for (;;) {
        ulogrec next = {};
        ok64 d = ULOGu8ssDrainHeap(cursors, ULOGu8csZbyUri, &next);
        if (d == ULOGNONE) break;
        if (d != OK) return d;

        if (n == 0) {
            group[0] = next;
            n = 1;
            continue;
        }
        if (ulog_path_eq(&group[0], &next)) {
            if (n < LSM_MAX_INPUTS) group[n++] = next;
            continue;
        }
        //  Mismatch: fire current group, then seed the next group with
        //  `next` as its first member.
        ok64 cr = cb(group, n, ctx);
        if (cr != OK) return cr;
        group[0] = next;
        n = 1;
    }

    //  Flush trailing group, if any.
    if (n > 0) {
        ok64 cr = cb(group, n, ctx);
        if (cr != OK) return cr;
    }
    done;
}

// --- Path utilities -------------------------------------------------

b8 ULOGu8sRelFromFull(u8csp rel_out, u8cs reporoot, u8cs full) {
    if (!rel_out) return NO;
    if ($len(full) <= $len(reporoot)) return NO;
    if (!u8csHasPrefix(full, reporoot)) return NO;
    u8cs rel = {$atp(full, $len(reporoot)), full[1]};
    //  Skip leading slash(es) between reporoot and the first segment.
    while (!$empty(rel) && *rel[0] == '/') u8csUsed1(rel);
    if ($empty(rel)) return NO;
    u8csMv(rel_out, rel);
    return YES;
}

// --- ULOGu8bScanWt: walk reporoot → ULOG rows -----------------------

typedef struct {
    u8cs         reporoot;
    u8bp         out;
    ron60        verb;
    ulog_skip_fn skip;
    void        *skip_ctx;
    ok64         err;
} ulog_wt_ctx;

//  Map a stat-derived kind/mode to the RON64 letter appended to the
//  caller's verb stem (f=regular, x=executable, l=symlink).  Mirrors
//  `wt_kind_letter` in sniff/AT.c.
static u8 ulog_wt_kind_letter(filestat const *fs) {
    if      (fs->kind == FILE_KIND_LNK) return RON_l;
    else if (fs->mode & 0100)           return RON_x;
    else                                return RON_f;
}

static ok64 ulog_wt_cb(void *varg, path8bp path) {
    sane(varg && path);
    ulog_wt_ctx *c = (ulog_wt_ctx *)varg;

    a_dup(u8c, full, u8bData(path));
    u8cs rel = {};
    if (!ULOGu8sRelFromFull(rel, c->reporoot, full)) return OK;
    if (c->skip && c->skip(rel, c->skip_ctx))         return OK;

    filestat fs = {};
    if (FILELStat(&fs, full) != OK) return OK;

    uri u = {};
    u8csMv(u.path, rel);
    //  query empty (mode encoded in verb), fragment empty (no sha yet).

    ulogrec rec = {.ts   = fs.mtime,
                   .verb = ok64sub(c->verb, ulog_wt_kind_letter(&fs)),
                   .uri  = u};
    ok64 o = ULOGu8sFeed(u8bIdle(c->out), &rec);
    if (o != OK) { c->err = o; return o; }
    return OK;
}

ok64 ULOGu8bScanWt(u8cs reporoot, ron60 verb,
                   ulog_skip_fn skip, void *skip_ctx,
                   u8bp out) {
    sane($ok(reporoot) && out);
    u8bReset(out);
    ulog_wt_ctx c = {.out = out, .verb = verb, .err = OK,
                     .skip = skip, .skip_ctx = skip_ctx};
    u8csMv(c.reporoot, reporoot);

    a_path(wp);
    u8bFeed(wp, reporoot);
    call(PATHu8bTerm, wp);

    Bu8 scratch = {};
    call(u8bAllocate, scratch, 1UL << 20);

    ok64 so = FILEScanSorted(wp,
                             (FILE_SCAN)(FILE_SCAN_FILES | FILE_SCAN_LINKS |
                                         FILE_SCAN_DEEP),
                             scratch, FILEentryZ, ulog_wt_cb, &c);
    u8bFree(scratch);
    if (c.err != OK) return c.err;
    return so;
}
