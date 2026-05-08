//  ULOG — append-only URI event log.
//  See dog/ULOG.h for the API and dog/ULOG.md for the format.
//
#include "ULOG.h"

#include <stdlib.h>
#include <string.h>
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

// --- helpers ---------------------------------------------------------

//  Scan the mmap'd text, populate the kv64 index, enforce strict
//  monotonicity.  `idx` may be NULL (skip the build).
static ok64 ulog_rebuild_idx(u8bp data, kv64bp idx) {
    sane(data);
    //  FILEBook places the whole mmap'd file content in the IDLE
    //  region (past = data = idle = map, end = map + page-aligned
    //  size).  We scan [past, end) forward, indexing each row, and
    //  then position IDLE's head past the last complete row so
    //  subsequent appends land on the right offset.  Tail zero-fill
    //  from page alignment terminates the scan at the first NUL.
    u8 *base = (u8 *)data[0];
    u8 *end  = (u8 *)data[3];
    u8cs scan = {base, end};
    u8 *last_nl_plus_one = base;
    ron60 prev = 0;
    b8 have_idx = (idx != NULL);
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

        if (have_idx && kv64bDataLen(idx) > 0 && rec.ts <= prev) fail(ULOGCLOCK);
        if (have_idx) {
            kv64 ent = {.key = rec.ts, .val = off};
            call(kv64bPush, idx, &ent);
        }
        prev = rec.ts;
        last_nl_plus_one = (u8 *)scan[0];
    }

    u8 **data_head = (u8 **)&data[1];
    u8 **idle_head = (u8 **)&data[2];
    *data_head = base;
    *idle_head = last_nl_plus_one;
    done;
}

//  Lower-bound on the kv64 index by timestamp key.
static u32 ulog_lower_bound(kv64b idx, ron60 ts) {
    kv64 const *a = (kv64 const *)idx[0];
    u32 n = (u32)kv64bDataLen(idx);
    u32 lo = 0, hi = n;
    while (lo < hi) {
        u32 mid = lo + (hi - lo) / 2;
        if (a[mid].key < ts) lo = mid + 1;
        else                 hi = mid;
    }
    return lo;
}

// --- public API ------------------------------------------------------

ok64 ULOGOpenBooked(u8bp *data, kv64bp idx, path8s path,
                    size_t book_size, size_t init_size) {
    sane(data && $ok(path));

    ok64 o = FILEBook(data, path, book_size);
    if (o != OK) {
        call(FILEBookCreate, data, path, book_size, init_size);
    }

    //  Use mmap (lazy-paged) for the index so it grows with the log.
    //  16-byte entries × 1M slots = 16 MB virtual; only touched pages
    //  are committed.  The earlier `kv64bAllocate(1024)` was a hard
    //  cap that fired SNOROOM after the 1024th `kv64bPush` — fatal
    //  for a single `be put .` over a wt with > ~1k files (e.g. a
    //  freshly-rsync'd src/git tag) and silently re-tripped on every
    //  subsequent be invocation in the same dog.
    if (idx) call(kv64bMap, idx, 1UL << 20);

    ok64 so = ulog_rebuild_idx(*data, idx);
    if (so != OK) {
        if (idx && idx[0]) kv64bUnMap(idx);
        if (*data && (*data)[0]) FILEUnBook(*data);
        return so;
    }
    done;
}

ok64 ULOGOpen(u8bp *data, kv64bp idx, path8s path) {
    return ULOGOpenBooked(data, idx, path,
                          ULOG_BOOK_DEFAULT, ULOG_INIT_DEFAULT);
}

ok64 ULOGOpenRO(u8bp *data, kv64bp idx, path8s path) {
    sane(data && $ok(path));

    //  RO map only — fails if file is missing (no implicit create).
    call(FILEBookRO, data, path, ULOG_BOOK_DEFAULT);

    if (idx) call(kv64bMap, idx, 1UL << 20);

    ok64 so = ulog_rebuild_idx(*data, idx);
    if (so != OK) {
        if (idx && idx[0]) kv64bUnMap(idx);
        if (*data && (*data)[0]) FILEUnBook(*data);
        return so;
    }
    done;
}

ok64 ULOGClose(u8bp data, kv64bp idx, b8 rw) {
    sane(data);
    if (data[0]) {
        //  Any RW open page-aligned the file via FILEBook's
        //  ftruncate, so Close must trim back regardless of
        //  whether anything was actually appended.  Otherwise an
        //  early-fail RW SNIFFExec leaves trailing pad bytes
        //  visible to the next reader.  RO opens (FILEBookRO)
        //  never grew the file — skip the trim.
        if (rw) FILETrimBook(data);
        FILEUnBook(data);     // also nullifies the buffer slots
    }
    if (idx && idx[0]) kv64bUnMap(idx);  // also nullifies
    done;
}

ok64 ULOGAppendAt(u8bp data, kv64bp idx, ulogreccp rec) {
    sane(data && idx && rec);
    size_t n = kv64bDataLen(idx);
    if (n > 0) {
        kv64 const *last = ((kv64 const *)idx[0]) + (n - 1);
        if (rec->ts <= last->key) fail(ULOGCLOCK);
    }
    call(FILEBookEnsure, data, 2048);

    u64 off = (u64)u8bDataLen(data);
    call(ULOGu8sFeed, u8bIdle(data), rec);

    kv64 ent = {.key = rec->ts, .val = off};
    call(kv64bPush, idx, &ent);
    done;
}

ok64 ULOGAppend(u8bp data, kv64bp idx, ulogrecp rec) {
    sane(data && idx && rec);
    //  Clamp to max(RONNow(), tail+1) so rapid same-ms appends
    //  still land instead of tripping ULOGCLOCK.  Mirrors the
    //  pattern keeper/REFS.c uses in refs_next_ts().
    ron60 now = RONNow();
    size_t n = kv64bDataLen(idx);
    if (n > 0) {
        kv64 const *last = ((kv64 const *)idx[0]) + (n - 1);
        if (now <= last->key) now = last->key + 1;
    }
    rec->ts = now;
    return ULOGAppendAt(data, idx, rec);
}

ok64 ULOGRow(u8b data, kv64b idx, u32 i, ulogrecp out) {
    sane(data && idx && out);
    if (i >= ULOGCount(idx)) fail(ULOGNONE);
    kv64 const *a = (kv64 const *)idx[0];
    a_dup(u8c, dview, u8bDataC(data));

    u8cs scan = {dview[0] + a[i].val, dview[1]};
    return ULOGu8sDrain(scan, out);
}

ok64 ULOGSeek(kv64b idx, ron60 ts, u32 *i_out) {
    sane(idx && i_out);
    *i_out = ulog_lower_bound(idx, ts);
    done;
}

ok64 ULOGFind(kv64b idx, ron60 ts, u32 *i_out) {
    sane(idx && i_out);
    u32 i = ulog_lower_bound(idx, ts);
    u32 n = ULOGCount(idx);
    if (i >= n) fail(ULOGNONE);
    kv64 const *a = (kv64 const *)idx[0];
    if (a[i].key != ts) fail(ULOGNONE);
    *i_out = i;
    done;
}

ok64 ULOGFindLatest(u8b data, kv64b idx, ulog_pred pred, void *ctx,
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

ok64 ULOGFindVerb(u8b data, kv64b idx, ron60 verb, ulogrecp out) {
    sane(data && idx && out);
    u32 n = ULOGCount(idx);
    for (u32 i = n; i > 0; ) {
        i--;
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
static void ulog_row_key_bytes(u8b data, kv64b idx, u32 i, u8csp out) {
    kv64 const *a = (kv64 const *)idx[0];
    u8cp base = (u8cp)data[0];
    u8cp row  = base + a[i].val;
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
static ok64 ulog_each_latest(u8b data, kv64b idx, ron60 verb_filter,
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

ok64 ULOGeachLatest(u8b data, kv64b idx, ron60 verb_filter,
                    ulog_each_fn cb, void *ctx) {
    return ulog_each_latest(data, idx, verb_filter, YES, cb, ctx);
}

ok64 ULOGeachLatestKey(u8b data, kv64b idx, ron60 verb_filter,
                       ulog_each_fn cb, void *ctx) {
    return ulog_each_latest(data, idx, verb_filter, NO, cb, ctx);
}

// --- ULOGCompactLatest -----------------------------------------------

//  Two-pass compaction: mark keep-bits on a reverse walk, then append
//  kept rows forward into a fresh tmp log and rename over the original.
ok64 ULOGCompactLatest(u8bp *data, kv64bp idx, path8s path,
                       ron60 verb_filter) {
    sane(data && idx && $ok(path));

    u32 n = ULOGCount(idx);
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
        ok64 o = ULOGRow(*data, idx, i, &r);
        if (o != OK) { u64bFree(seen); free(keep); return o; }

        if (verb_filter && r.verb != verb_filter) {
            keep[i] = 1;
            continue;
        }
        u8cs key = {};
        ulog_row_key_bytes(*data, idx, i, key);
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

    u8bp  tmp_data = NULL;
    Bkv64 tmp_idx  = {};
    ok64 oo = ULOGOpen(&tmp_data, tmp_idx, tmp_path);
    if (oo != OK) { free(keep); return oo; }

    //  Pass 2: forward walk, re-append kept rows into tmp.
    for (u32 i = 0; i < n; i++) {
        if (!keep[i]) continue;
        ulogrec r = {};
        ok64 o = ULOGRow(*data, idx, i, &r);
        if (o != OK) {
            ULOGClose(tmp_data, tmp_idx, YES);
            free(keep); return o;
        }
        ok64 ao = ULOGAppendAt(tmp_data, tmp_idx, &r);
        if (ao != OK) {
            ULOGClose(tmp_data, tmp_idx, YES);
            free(keep); return ao;
        }
    }
    free(keep);
    ULOGClose(tmp_data, tmp_idx, YES);

    //  Swap files: close source, rename tmp → path, reopen source.
    ULOGClose(*data, idx, YES);
    ok64 ro = FILERename(tmp_path, path);
    if (ro != OK) {
        //  Best-effort recovery: try to reopen the original (still intact).
        (void)ULOGOpen(data, idx, path);
        return ro;
    }
    call(ULOGOpen, data, idx, path);
    done;
}

ok64 ULOGTruncate(u8bp data, kv64bp idx, u32 keep_n) {
    sane(data && idx);
    u32 n = ULOGCount(idx);
    if (keep_n > n) fail(ULOGFAIL);
    if (keep_n == n) done;

    u64 cut_off = 0;
    if (keep_n > 0) {
        kv64 const *a = (kv64 const *)idx[0];
        cut_off = a[keep_n].val;
    }

    //  Shrink the kv64 index to `keep_n` entries.
    kv64 **idle_idx = kv64bIdle(idx);
    kv64 *base = (kv64 *)idx[0];
    *idle_idx = base + keep_n;

    //  Drop the tail bytes of the data book.  Zero the discarded
    //  region so a reopen's `ulog_rebuild_idx` halts at the first NUL;
    //  we deliberately do NOT ftruncate — keeping the backing file
    //  page-aligned is what lets subsequent MAP_SHARED writes land on
    //  strict filesystems (ext4 silently drops writes past EOF even
    //  within a page-aligned mmap).
    u8 *data_base  = (u8 *)data[0];
    u8 **data_idle = u8bIdle(data);
    u8 *old_idle   = *data_idle;
    u8 *new_idle   = data_base + cut_off;
    if (new_idle < old_idle) memset(new_idle, 0, (size_t)(old_idle - new_idle));
    *data_idle = new_idle;

    done;
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

ron60 ULOGtsOfTimespec(struct timespec tsp) {
    struct tm tm = {};
    time_t sec = tsp.tv_sec;
    //  RONNow uses localtime, so match that for round-trip.
    localtime_r(&sec, &tm);
    u32 ms = (u32)(tsp.tv_nsec / 1000000);
    if (ms > 999) ms = 999;
    ron60 r = 0;
    if (RONOfTime(&r, &tm, ms) != OK) r = 0;
    return r;
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

//  Map an `lstat`-derived kind to the RON64 letter appended to the
//  caller's verb stem (f=regular, x=executable, l=symlink).  Mirrors
//  `wt_kind_letter` in sniff/AT.c.
static u8 ulog_wt_kind_letter(struct stat const *sb) {
    if      (S_ISLNK(sb->st_mode))   return RON_l;
    else if (sb->st_mode & S_IXUSR)  return RON_x;
    else                             return RON_f;
}

static ok64 ulog_wt_cb(void *varg, path8bp path) {
    sane(varg && path);
    ulog_wt_ctx *c = (ulog_wt_ctx *)varg;

    a_dup(u8c, full, u8bData(path));
    u8cs rel = {};
    if (!ULOGu8sRelFromFull(rel, c->reporoot, full)) return OK;
    if (c->skip && c->skip(rel, c->skip_ctx))         return OK;

    struct stat sb = {};
    if (lstat((char const *)full[0], &sb) != 0) return OK;

    struct timespec mts = {.tv_sec  = sb.st_mtim.tv_sec,
                           .tv_nsec = sb.st_mtim.tv_nsec};
    ron60 ts = ULOGtsOfTimespec(mts);

    uri u = {};
    u8csMv(u.path, rel);
    //  query empty (mode encoded in verb), fragment empty (no sha yet).

    ulogrec rec = {.ts   = ts,
                   .verb = ok64sub(c->verb, ulog_wt_kind_letter(&sb)),
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
