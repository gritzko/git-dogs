//  AT — sniff's attribution log, layered over dog/ULOG.
//
#include "AT.h"
#include "SNIFF.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "abc/FILE.h"
#include "abc/PATH.h"
#include "abc/PRO.h"
#include "abc/RON.h"
#include "dog/QURY.h"
#include "dog/WHIFF.h"
#include "keeper/KEEP.h"
#include "keeper/WALK.h"   // WALK_KIND_*

// --- Standalone RO tail peek (no SNIFF singleton, no keeper) -------

ok64 SNIFFAtTailOf(u8cs wt, u8bp out) {
    sane(u8csOK(wt) && out);

    a_path(apath);
    call(SNIFFWtlogPath, apath, wt);

    //  RO open: callable concurrently with sniff's own RW handle.
    //  ULOGOpenRO maps PROT_READ and skips FILEBook's page-align
    //  ftruncate, so it can't trip the silent-EOF-truncation bug
    //  the legacy RW reader caused.
    u8bp    data = NULL;
    wh128bp idx  = NULL;
    ok64 o = ULOGOpenRO(&data, &idx, $path(apath));
    if (o != OK) fail(SNIFFNONE);

    u32 n = ULOGCount(idx);
    if (n == 0) { ULOGClose(data, &idx, NO); fail(SNIFFNONE); }

    //  Row 0 = repo anchor → root path.
    a_pad(u8, root_buf, FILE_PATH_MAX_LEN);
    {
        ulogrec r0 = {};
        if (ULOGRow(data, idx, 0, &r0) != OK ||
            r0.verb != SNIFFAtVerbRepo()) {
            ULOGClose(data, &idx, NO); fail(SNIFFNONE);
        }
        DOGRepoFromBe(r0.uri.path, root_buf);
    }

    //  Latest get/post/patch with a 40-hex sha → branch + sha.
    u8cs ref_body = {}, sha_body = {};
    b8 found = NO;
    for (u32 i = n; i > 0; ) {
        i--;
        ulogrec rec = {};
        if (ULOGRow(data, idx, i, &rec) != OK) continue;
        uri u = rec.uri;

        //  Canonical at-log shape: `?<branch>#<curhash>` — fragment
        //  carries the sha, query carries the be-branch (empty for
        //  trunk).  Legacy rows kept the sha in a query spec; fall
        //  through and walk the `&`-chain when the fragment is empty.
        u8csMv0(ref_body);
        u8csMv0(sha_body);
        if (u8csLen(u.fragment) == 40) u8csMv(sha_body, u.fragment);
        a_dup(u8c, q, u.query);
        while (!u8csEmpty(q)) {
            qref spec = {};
            if (QURYu8sDrain(q, &spec) != OK) break;
            if (spec.type == QURY_NONE) break;
            if (spec.type == QURY_REF && u8csEmpty(ref_body)) {
                u8csMv(ref_body, spec.body);
            } else if (spec.type == QURY_SHA &&
                       u8csLen(spec.body) == 40 &&
                       u8csEmpty(sha_body)) {
                u8csMv(sha_body, spec.body);
            }
        }
        if (!u8csEmpty(sha_body)) { found = YES; break; }
    }

    if (!found) { ULOGClose(data, &idx, NO); fail(SNIFFNONE); }

    //  Compose `<root>?<branch>#<sha>` into `out`.  branch may be
    //  empty (== trunk); `?` separator stays so URILexer round-trips
    //  the empty query as a present-but-empty slot.
    u8bReset(out);
    u8bFeed(out, u8bDataC(root_buf));
    u8bFeed1(out, '?');
    if (!u8csEmpty(ref_body)) u8bFeed(out, ref_body);
    u8bFeed1(out, '#');
    u8bFeed(out, sha_body);

    ULOGClose(data, &idx, NO);
    done;
}

//  Row-0 invariant guard: `repo` only at row 0, every other verb only
//  at row ≥ 1.  Returns OK if the append is allowed.
static ok64 at_check_row0(ron60 verb) {
    sane(SNIFF.h);
    ron60 vrepo = SNIFFAtVerbRepo();
    u32 n = ULOGCount(SNIFF.log_idx);
    if (n == 0 && verb != vrepo) fail(SNIFFFAIL);
    if (n > 0 && verb == vrepo)  fail(SNIFFFAIL);
    done;
}

ok64 SNIFFAtAppend(ron60 verb, uricp u) {
    sane(SNIFF.h && u);
    call(at_check_row0, verb);
    ulogrec rec = {.verb = verb, .uri = *u};
    return ULOGAppend(SNIFF.log_data, SNIFF.log_idx, &rec);
}

ok64 SNIFFAtAppendAt(ron60 ts, ron60 verb, uricp u) {
    sane(SNIFF.h && u);
    call(at_check_row0, verb);
    ulogrec rec = {.ts = ts, .verb = verb, .uri = *u};
    return ULOGAppendAt(SNIFF.log_data, SNIFF.log_idx, &rec);
}

b8 SNIFFAtKnown(ron60 mtime) {
    if (!SNIFF.h) return NO;
    return ULOGHas(SNIFF.log_idx, mtime);
}

void SNIFFAtPathBytes(uri const *u, u8cs out) {
    if (!u8csEmpty(u->path))     { out[0] = u->path[0];     out[1] = u->path[1];     return; }
    if (!u8csEmpty(u->query))    { out[0] = u->query[0];    out[1] = u->query[1];    return; }
    if (!u8csEmpty(u->fragment)) { out[0] = u->fragment[0]; out[1] = u->fragment[1]; return; }
    out[0] = u->data[0]; out[1] = u->data[1];
}

// --- Verb constants (lazy-cached) ---

static ron60 at_v_repo   = 0;
static ron60 at_v_get    = 0;
static ron60 at_v_post   = 0;
static ron60 at_v_patch  = 0;
static ron60 at_v_put    = 0;
static ron60 at_v_delete = 0;
static ron60 at_v_mod    = 0;

ron60 SNIFFAtVerbRepo(void) {
    if (at_v_repo == 0) { a_cstr(s, "repo"); at_v_repo = SNIFFAtVerbOf(s); }
    return at_v_repo;
}

ron60 SNIFFAtVerbGet(void) {
    if (at_v_get == 0) { a_cstr(s, "get"); at_v_get = SNIFFAtVerbOf(s); }
    return at_v_get;
}
ron60 SNIFFAtVerbPost(void) {
    if (at_v_post == 0) { a_cstr(s, "post"); at_v_post = SNIFFAtVerbOf(s); }
    return at_v_post;
}
ron60 SNIFFAtVerbPatch(void) {
    if (at_v_patch == 0) { a_cstr(s, "patch"); at_v_patch = SNIFFAtVerbOf(s); }
    return at_v_patch;
}
ron60 SNIFFAtVerbPut(void) {
    if (at_v_put == 0) { a_cstr(s, "put"); at_v_put = SNIFFAtVerbOf(s); }
    return at_v_put;
}
ron60 SNIFFAtVerbDelete(void) {
    if (at_v_delete == 0) { a_cstr(s, "delete"); at_v_delete = SNIFFAtVerbOf(s); }
    return at_v_delete;
}
ron60 SNIFFAtVerbMod(void) {
    if (at_v_mod == 0) { a_cstr(s, "mod"); at_v_mod = SNIFFAtVerbOf(s); }
    return at_v_mod;
}

// --- Row-0 anchor lookup ---

ok64 SNIFFAtRepo(urip u_out) {
    sane(SNIFF.h && u_out);
    if (ULOGCount(SNIFF.log_idx) == 0) return ULOGNONE;
    ulogrec rec = {};
    call(ULOGRow, SNIFF.log_data, SNIFF.log_idx, 0, &rec);
    if (rec.verb != SNIFFAtVerbRepo()) fail(SNIFFFAIL);
    *u_out = rec.uri;
    done;
}

// --- Baseline URI lookup ---

ok64 SNIFFAtBaseline(ron60 *ts_out, ron60 *verb_out, urip u_out) {
    sane(SNIFF.h && ts_out && verb_out && u_out);
    ron60 vg = SNIFFAtVerbGet();
    ron60 vp = SNIFFAtVerbPost();
    ron60 vx = SNIFFAtVerbPatch();
    u32 n = ULOGCount(SNIFF.log_idx);
    for (u32 i = n; i > 0; i--) {
        ulogrec rec = {};
        ok64 o = ULOGRow(SNIFF.log_data, SNIFF.log_idx, i - 1, &rec);
        if (o != OK) return o;
        if (rec.verb == vg || rec.verb == vp || rec.verb == vx) {
            *ts_out   = rec.ts;
            *verb_out = rec.verb;
            *u_out    = rec.uri;
            done;
        }
    }
    return ULOGNONE;
}

ok64 SNIFFAtCurTip(ron60 *ts_out, ron60 *verb_out, urip u_out) {
    sane(SNIFF.h && ts_out && verb_out && u_out);
    ron60 vg = SNIFFAtVerbGet();
    ron60 vp = SNIFFAtVerbPost();
    u32 n = ULOGCount(SNIFF.log_idx);
    for (u32 i = n; i > 0; i--) {
        ulogrec rec = {};
        ok64 o = ULOGRow(SNIFF.log_data, SNIFF.log_idx, i - 1, &rec);
        if (o != OK) return o;
        if (rec.verb == vg || rec.verb == vp) {
            *ts_out   = rec.ts;
            *verb_out = rec.verb;
            *u_out    = rec.uri;
            done;
        }
    }
    return ULOGNONE;
}

//  Pick the 40-hex sha out of a patch row's URI into `out`.  Query
//  slot wins for squash/merge/rebase-one shapes; fragment slot for
//  cherry-pick.  `out` is left empty when neither slot has 40+ hex.
static void at_patch_row_sha_hex(u8cs out, uricp u) {
    if (u->query[0] != NULL) {
        //  Located-cherry row: `?<branch>/<sha>` — split off the
        //  trailing-hashlet via DOGRefSplitPin (path-form convention,
        //  see dog/DOG.h).  Empty pin → query carries the sha alone
        //  (the pre-locator shape: `?<sha>` from SQUASH and friends).
        u8cs br_s = {}, pin_s = {};
        u8cs q = {u->query[0], u->query[1]};
        DOGRefSplitPin(q, br_s, pin_s);
        if (!u8csEmpty(pin_s) && u8csLen(pin_s) >= 40) {
            $mv(out, pin_s);
            return;
        }
        if (u8csLen(u->query) >= 40) {
            $mv(out, u->query);
            return;
        }
    }
    if (u->fragment[0] != NULL && u8csLen(u->fragment) >= 40) {
        $mv(out, u->fragment);
        return;
    }
    out[0] = NULL;
    out[1] = NULL;
}

//  Locator branch from a patch row's URI (only present for located-
//  cherry shape `?<branch>/<sha>`).  Returns the `<branch>` slice
//  (slices into `u->query`); empty slice when the row carries no
//  locator (bare cherry `#<sha>` or sha-only query).  Used by POST
//  to switch keeper before reading the picked commit body.
static void at_patch_row_locator(u8cs out, uricp u) {
    out[0] = NULL; out[1] = NULL;
    if (u->query[0] == NULL) return;
    u8cs br_s = {}, pin_s = {};
    u8cs q = {u->query[0], u->query[1]};
    DOGRefSplitPin(q, br_s, pin_s);
    if (!u8csEmpty(pin_s) && !u8csEmpty(br_s)) $mv(out, br_s);
}

//  Classify a patch row's URI into one of the four PATCH_SHAPE_*
//  values.  Mirrors PATCHShape() in sniff/PATCH.c but lives here
//  to keep AT.c self-contained.
//
//  A `?<branch>/<sha>` query (located form, see dog/DOG.h
//  §DOGRefSplitPin) reads as CHERRY-with-locator: POST treats it
//  like a single-commit pick (msg lookup, `picked:` trailer).  The
//  bare-sha query `?<sha>` (locator empty) stays SQUASH.
static u8 at_patch_row_shape(uricp u) {
    b8 has_q = (u->query[0]    != NULL);
    b8 has_f = (u->fragment[0] != NULL);
    b8 frag_empty = has_f && u8csEmpty(u->fragment);
    if (has_q && !has_f) {
        u8cs br_s = {}, pin_s = {};
        u8cs q = {u->query[0], u->query[1]};
        DOGRefSplitPin(q, br_s, pin_s);
        //  Located cherry: branch + hashlet pin.
        if (!u8csEmpty(pin_s) && !u8csEmpty(br_s)) return 2; // CHERRY
        return 1;                                            // SQUASH
    }
    if (!has_q &&  has_f && !frag_empty) return 2; // CHERRY
    if ( has_q &&  has_f && !frag_empty) return 3; // MERGE
    if ( has_q &&  has_f &&  frag_empty) return 4; // REBASE1
    return 0;  // BAD
}

ok64 SNIFFAtPatchChain(sha1b out) {
    sane(SNIFF.h && Bok(out));
    ron60 vg = SNIFFAtVerbGet();
    ron60 vp = SNIFFAtVerbPost();
    ron60 vx = SNIFFAtVerbPatch();
    u32 n = ULOGCount(SNIFF.log_idx);
    if (n == 0) return ULOGNONE;

    u32 start = 0;
    for (u32 i = n; i > 0; i--) {
        ulogrec rec = {};
        ok64 o = ULOGRow(SNIFF.log_data, SNIFF.log_idx, i - 1, &rec);
        if (o != OK) return o;
        if (rec.verb == vg || rec.verb == vp) { start = i; break; }
    }

    for (u32 i = start; i < n && sha1bHasRoom(out); i++) {
        ulogrec rec = {};
        ok64 o = ULOGRow(SNIFF.log_data, SNIFF.log_idx, i, &rec);
        if (o != OK) return o;
        if (rec.verb != vx) continue;
        u8cs sha_hex = {};
        at_patch_row_sha_hex(sha_hex, &rec.uri);
        if (u8csLen(sha_hex) < 40) continue;
        sha1 s = {};
        a_raw(sb, s);
        a_dup(u8c, hx, sha_hex);
        if (HEXu8sDrainSome(sb, hx) != OK) continue;
        sha1bFeed1(out, s);
    }
    done;
}

ok64 SNIFFAtPatchEntries(sniff_pe *entries, u32 cap, u32 *n_out) {
    sane(SNIFF.h && entries && n_out);
    *n_out = 0;
    ron60 vg = SNIFFAtVerbGet();
    ron60 vp = SNIFFAtVerbPost();
    ron60 vx = SNIFFAtVerbPatch();
    u32 n = ULOGCount(SNIFF.log_idx);
    if (n == 0) return ULOGNONE;

    u32 start = 0;
    for (u32 i = n; i > 0; i--) {
        ulogrec rec = {};
        ok64 o = ULOGRow(SNIFF.log_data, SNIFF.log_idx, i - 1, &rec);
        if (o != OK) return o;
        if (rec.verb == vg || rec.verb == vp) { start = i; break; }
    }

    for (u32 i = start; i < n && *n_out < cap; i++) {
        ulogrec rec = {};
        ok64 o = ULOGRow(SNIFF.log_data, SNIFF.log_idx, i, &rec);
        if (o != OK) return o;
        if (rec.verb != vx) continue;
        u8 sh = at_patch_row_shape(&rec.uri);
        if (sh == 0) continue;
        u8cs sha_hex = {};
        at_patch_row_sha_hex(sha_hex, &rec.uri);
        if (u8csLen(sha_hex) < 40) continue;
        sniff_pe *e = &entries[*n_out];
        e->shape = sh;
        a_raw(sb, e->sha);
        a_dup(u8c, hx, sha_hex);
        if (HEXu8sDrainSome(sb, hx) != OK) continue;
        if (sh == 3 /* MERGE */) {
            $mv(e->msg, rec.uri.fragment);
        } else {
            e->msg[0] = NULL;
            e->msg[1] = NULL;
        }
        //  Capture the locator branch (only set for located cherry).
        at_patch_row_locator(e->locator, &rec.uri);
        (*n_out)++;
    }
    done;
}

// --- Last-post timestamp ---

ron60 SNIFFAtLastPostTs(void) {
    if (!SNIFF.h) return 0;
    ron60 vp = SNIFFAtVerbPost();
    u32 n = ULOGCount(SNIFF.log_idx);
    for (u32 i = n; i > 0; ) {
        i--;
        ulogrec rec = {};
        if (ULOGRow(SNIFF.log_data, SNIFF.log_idx, i, &rec) != OK) return 0;
        if (rec.verb == vp) return rec.ts;
    }
    return 0;
}

// --- Put/delete forward scan since floor ---

// --- ron60 → timespec helper (used to restamp wt files via utimensat) ---

static struct timespec at_ts_of_ron60(ron60 r) {
    struct tm tm = {};
    u32 ms = 0;
    struct timespec ts = {};
    if (RONToTime(r, &tm, &ms) != OK) return ts;
    //  RONNow wrote via localtime; reverse via mktime (local tz).
    //  `tm_isdst = -1` tells mktime to auto-detect DST from the local
    //  calendar; without it mktime assumes tm_isdst=0, which shifts
    //  the computed time_t by one hour during DST, breaking the
    //  ron60 ↔ timespec round-trip at the SNIFFAtKnown check.
    tm.tm_isdst = -1;
    time_t sec = mktime(&tm);
    ts.tv_sec = sec;
    ts.tv_nsec = (long)ms * 1000000L;
    return ts;
}

void SNIFFAtNow(ron60 *ts_out, struct timespec *tv_out) {
    ron60 now = RONNow();
    //  Guard monotonicity against the ULOG tail.
    if (SNIFF.h) {
        ulogrec tail = {};
        if (ULOGTail(SNIFF.log_data, SNIFF.log_idx, &tail) == OK) {
            if (now <= tail.ts) now = tail.ts + 1;
        }
    }
    *ts_out = now;
    *tv_out = at_ts_of_ron60(now);
}

ok64 SNIFFAtRowAtTs(ron60 mtime, ron60 *verb_out, urip u_out) {
    sane(SNIFF.h && verb_out && u_out);
    u32 i = 0;
    ok64 fo = ULOGFind(SNIFF.log_idx, mtime, &i);
    if (fo != OK) return fo;
    ulogrec rec = {};
    call(ULOGRow, SNIFF.log_data, SNIFF.log_idx, i, &rec);
    *verb_out = rec.verb;
    *u_out    = rec.uri;
    done;
}

ok64 SNIFFCheckClock(void) {
    sane(1);
    if (!SNIFF.h) done;                       // no log yet, nothing to compare
    ulogrec tail = {};
    if (ULOGTail(SNIFF.log_data, SNIFF.log_idx, &tail) != OK) done;
    ron60 now = RONNow();
    if (now < tail.ts) {
        //  A burst of N rows in one wall-clock ms self-bumps the tail
        //  N ms ahead (SNIFFAtNow's monotonicity guard).  A single
        //  `be put .` over a several-thousand-file wt (e.g.
        //  rsync-then-stage of an upstream tag) routinely bumps the
        //  tail several seconds ahead — that's not a clock fault, just
        //  the bulk-put serializing rows in millisecond ticks.
        //  CLOCKBAD is for gross errors (NTP step, DST, suspend/resume)
        //  so allow up to 30 s of self-bump headroom before refusing.
        struct timespec tail_tv = at_ts_of_ron60(tail.ts);
        struct timespec now_tv  = at_ts_of_ron60(now);
        i64 skew_ms = ((i64)tail_tv.tv_sec - (i64)now_tv.tv_sec) * 1000
                    + ((i64)tail_tv.tv_nsec - (i64)now_tv.tv_nsec) / 1000000;
        if (skew_ms > 30000) {
            fprintf(stderr,
                    "sniff: clock skew — system clock is before the latest "
                    "wtlog row; refusing every command until clock catches "
                    "up\n");
            return CLOCKBAD;
        }
    }
    done;
}

ok64 SNIFFAtStampPath(path8b path, ron60 ts) {
    sane(path);
    struct timespec tv = at_ts_of_ron60(ts);
    struct timespec times[2] = { tv, tv };
    char const *cp = (char const *)u8bDataHead(path);
    if (utimensat(AT_FDCWD, cp, times, AT_SYMLINK_NOFOLLOW) != 0) fail(SNIFFFAIL);
    done;
}

ok64 SNIFFAtScanPutDelete(ron60 floor, sniff_at_pd_cb cb, void *ctx) {
    sane(SNIFF.h && cb);
    u32 start = 0;
    ok64 s = ULOGSeek(SNIFF.log_idx, floor, &start);
    if (s != OK && s != ULOGNONE) return s;
    u32 n = ULOGCount(SNIFF.log_idx);
    ron60 vput = SNIFFAtVerbPut();
    ron60 vdel = SNIFFAtVerbDelete();
    for (u32 i = start; i < n; i++) {
        ulogrec rec = {};
        ok64 o = ULOGRow(SNIFF.log_data, SNIFF.log_idx, i, &rec);
        if (o != OK) return o;
        if (rec.ts <= floor) continue;
        if (rec.verb != vput && rec.verb != vdel) continue;
        ok64 cr = cb(&rec, ctx);
        if (cr != OK) return cr;
    }
    done;
}

ok64 SNIFFAtQueryFirstSha(uricp u, sha1hex *out) {
    sane(u && out);

    //  Canonical at-log row: `?<branch>#<curhash>` — fragment is the
    //  current sha.  Take it directly when present.
    {
        u8cs frag = {u->fragment[0], u->fragment[1]};
        if (u8csLen(frag) == sizeof(out->data)) {
            sha1hexMv(out, (sha1hex const *)frag[0]);
            done;
        }
    }

    //  Legacy rows kept the sha in the query (`?<branch>&<sha>`) —
    //  walk the `&`-chain and pick the first 40-hex spec.  Tolerate
    //  empty leading specs (`&<sha>`) by skipping bare separators.
    a_dup(u8c, q, u->query);
    while (!$empty(q)) {
        if (*q[0] == '&') { u8csUsed1(q); continue; }
        qref spec = {};
        if (QURYu8sDrain(q, &spec) != OK) break;
        if (spec.type == QURY_NONE) break;
        if (spec.type == QURY_SHA && $len(spec.body) == sizeof(out->data)) {
            sha1hexMv(out, (sha1hex const *)spec.body[0]);
            done;
        }
    }
    fail(ULOGNONE);
}

// --- SNIFFAtScanDirty -------------------------------------------------

typedef struct {
    u8cs              reporoot;
    sniff_at_dirty_cb cb;
    void             *user_ctx;
    ok64              cb_err;
    //  Newline-separated list of `<path>/` prefixes harvested from
    //  the wt's baseline-tree gitlink (mode-160000) entries.  Files
    //  whose rel-path starts with any of these belong to a submodule
    //  whose internal state sniff doesn't manage; the dirty test is
    //  meaningless for them and they must not appear in the dirty
    //  callback.  Empty when there's no baseline or no gitlinks.
    u8cs              gitlinks;
    //  Sorted ULOG-row stream produced by `KEEPTreeULog` over the
    //  wt's baseline tree.  Each row encodes one tracked path and
    //  its blob sha.  Used for two extra classifications inside the
    //  cb:
    //    * `rel` not in baseline       → untracked; not dirty.
    //    * `rel` in baseline + bytes
    //       hash equal to base blob   → touched-unchanged; not dirty.
    //  Empty when there's no baseline.
    u8cs              base_rows;
} at_dirty_scan_ctx;

//  Scan `base_rows` (KEEPTreeULog-formatted) for a row whose
//  uri.path equals `rel`.  On match, decode the row's 40-hex
//  fragment into `*out` and return YES.  Linear; baselines run
//  from a few tens to a few thousand of entries — fine for the
//  refusal pre-flight.
static b8 at_baseline_blob_sha(u8cs base_rows, u8cs rel, sha1 *out) {
    if (u8csEmpty(base_rows) || u8csEmpty(rel)) return NO;
    a_dup(u8c, scan, base_rows);
    while (!u8csEmpty(scan)) {
        ulogrec rec = {};
        ok64 dr = ULOGu8sDrain(scan, &rec);
        if (dr == NODATA) break;
        if (dr != OK) continue;
        if (!u8csEq(rec.uri.path, rel)) continue;
        if (u8csLen(rec.uri.fragment) != 40) return NO;
        u8s bin = {out->data, out->data + 20};
        a_dup(u8c, hex, rec.uri.fragment);
        if (HEXu8sDrainSome(bin, hex) != OK) return NO;
        return YES;
    }
    return NO;
}

//  Hash the on-disk content of `full` as a git blob.  Returns OK
//  with `*out` filled, or fails (caller treats as "couldn't hash").
//  Hash the on-disk content of `full` (a path8b buffer) as a git
//  blob.  Returns OK with `*out` filled, or fails (caller treats as
//  "couldn't hash").
static ok64 at_hash_wt_blob(sha1 *out, path8bp full,
                            filestat const *fs) {
    sane(out != NULL && full != NULL && fs != NULL);
    a_dup(u8c, full_s, u8bData(full));   // path8s view for FILE APIs
    if (fs->kind == FILE_KIND_LNK) {
        a_pad(u8, tgt, 4096);
        ok64 ro = FILEReadLink(tgt, full_s);
        if (ro != OK) return ro;
        KEEPObjSha(out, DOG_OBJ_BLOB, u8bDataC(tgt));
        done;
    }
    if (fs->kind != FILE_KIND_REG) fail(SNIFFFAIL);
    if (fs->size == 0) {
        u8cs empty = {NULL, NULL};
        KEEPObjSha(out, DOG_OBJ_BLOB, empty);
        done;
    }
    u8bp m = NULL;
    ok64 mo = FILEMapRO(&m, full_s);
    if (mo != OK) return mo;
    u8cs body = {u8bDataHead(m), u8bIdleHead(m)};
    KEEPObjSha(out, DOG_OBJ_BLOB, body);
    FILEUnMap(m);
    done;
}

//  YES iff `rel` starts with any `<path>/` prefix in the gitlinks
//  slice (each entry is `<path>/\n`).
static b8 at_under_gitlink(u8cs gitlinks, u8cs rel) {
    if (u8csEmpty(gitlinks)) return NO;
    a_dup(u8c, scan, gitlinks);
    while (!u8csEmpty(scan)) {
        u8cs entry = {};
        u8csMv(entry, scan);
        a_dup(u8c, find, scan);
        if (u8csFind(find, '\n') != OK) break;
        entry[1] = find[0];
        if (u8csHasPrefix(rel, entry)) return YES;
        u8csUsed1(find);
        u8csMv(scan, find);
    }
    return NO;
}

static ok64 at_dirty_scan_cb(void *varg, path8bp path) {
    sane(varg && path);
    at_dirty_scan_ctx *c = (at_dirty_scan_ctx *)varg;

    a_dup(u8c, full, u8bData(path));
    u8cs rel = {};
    if (!SNIFFRelFromFull(rel, c->reporoot, full)) return OK;
    if (SNIFFSkipMeta(rel))                         return OK;
    if (at_under_gitlink(c->gitlinks, rel))         return OK;

    filestat fs = {};
    ok64 lo = FILELStat(&fs, full);
    if (lo == FILENOENT) return OK;    // vanished mid-walk
    if (lo != OK) return lo;             // propagate other errors

    //  Directory hook: any subdir that hosts its own `.git` (file or
    //  directory) is a separate repository — sniff doesn't manage
    //  its contents.  FILESKIP prunes the recursion so none of its
    //  files get checked.  Catches both git-submodule shapes (`.git`
    //  dir with HEAD/, or `.git` file containing `gitdir: ...`).
    //  Also catches beagle's own sub-mount shape (a regular `.be`
    //  *file* at the subdir's root — secondary-wt anchor written by
    //  GET's submodule materialiser, see MODULES.plan.md).
    if (fs.kind == FILE_KIND_DIR) {
        a_path(probe, full, ((u8cs)u8slit(".git")));
        filestat git_fs = {};
        if (FILELStat(&git_fs, $path(probe)) == OK) return FILESKIP;
        a_path(beprobe, full, ((u8cs)u8slit(".be")));
        filestat be_fs = {};
        if (FILELStat(&be_fs, $path(beprobe)) == OK &&
            be_fs.kind == FILE_KIND_REG) return FILESKIP;
        return OK;
    }

    if (SNIFFAtKnown(fs.mtime)) return OK;

    //  Mtime ∉ stamp set.  Two cases that should still be silent:
    //    1. Path is not in the baseline tree (untracked) — sniff
    //       has no opinion about it.
    //    2. Path IS in baseline AND on-disk bytes hash equal to
    //       the baseline blob sha (touched-unchanged / clean drift).
    sha1 base_sha = {};
    b8 in_base = at_baseline_blob_sha(c->base_rows, rel, &base_sha);
    if (!in_base) return OK;

    sha1 wt_sha = {};
    if (at_hash_wt_blob(&wt_sha, path, &fs) == OK &&
        sha1Eq(&wt_sha, &base_sha)) {
        return OK;
    }

    ok64 o = c->cb(rel, c->user_ctx);
    if (o != OK) c->cb_err = o;
    return o;
}

// --- Baseline pre-walk for the dirty scan ----------------------------

//  Best-effort: produce a baseline ULOG via `KEEPTreeULog` (sorted
//  rows, one per leaf path) into `rows_out`, and a newline-separated
//  list of gitlink prefixes (`<path>/\n`) into `gitlinks_out`.
//  Failures (no baseline, no commit, walk error) silently leave both
//  buffers empty — callers see empty inputs and behave as before
//  the fix.
static void at_collect_baseline(u8bp rows_out, u8bp gitlinks_out) {
    u8bReset(rows_out);
    u8bReset(gitlinks_out);
    ron60 ts = 0, verb = 0;
    uri u = {};
    if (SNIFFAtBaseline(&ts, &verb, &u) != OK) return;
    sha1hex hex = {};
    if (SNIFFAtQueryFirstSha(&u, &hex) != OK) return;
    sha1 commit_sha = {};
    if (sha1FromSha1hex(&commit_sha, &hex) != OK) return;
    sha1 tree_sha = {};
    if (KEEPCommitTreeSha(&KEEP, &commit_sha, &tree_sha) != OK) return;

    //  Verb stem irrelevant here; we read `kind` via `ok64Lit` later.
    a_cstr(stem_name, "base");
    a_dup(u8c, stem_d, stem_name);
    ron60 stem = 0;
    if (RONutf8sDrain(&stem, stem_d) != OK) return;
    if (KEEPTreeULog(&KEEP, tree_sha.data, 0, stem, rows_out) != OK)
        return;

    //  Filter rows for gitlinks (kind == 's').  Append `<path>/\n`
    //  for each into gitlinks_out.
    a_dup(u8c, scan, u8bDataC(rows_out));
    while (!u8csEmpty(scan)) {
        ulogrec rec = {};
        ok64 dr = ULOGu8sDrain(scan, &rec);
        if (dr != OK) break;
        if (ok64Lit(rec.verb, 0) != RON_s) continue;
        if (u8csEmpty(rec.uri.path)) continue;
        (void)u8bFeed (gitlinks_out, rec.uri.path);
        (void)u8bFeed1(gitlinks_out, '/');
        (void)u8bFeed1(gitlinks_out, '\n');
    }
}

ok64 SNIFFAtScanDirty(u8cs reporoot, sniff_at_dirty_cb cb, void *ctx) {
    sane($ok(reporoot) && cb != NULL);

    //  Pre-walk baseline once: produce a ULOG of leaf rows (used to
    //  classify wt entries as in-baseline / out-of-baseline plus to
    //  recover blob shas for the touched-unchanged check) and a
    //  newline-separated list of gitlink prefixes derived from the
    //  same rows.  Both can stay empty (no baseline / first checkout).
    Bu8 base_rows = {};
    Bu8 gitlinks  = {};
    call(u8bAllocate, base_rows, 1UL << 22);
    call(u8bAllocate, gitlinks,  1UL << 14);
    at_collect_baseline(base_rows, gitlinks);

    at_dirty_scan_ctx sc = {.cb = cb, .user_ctx = ctx, .cb_err = OK};
    u8csMv(sc.reporoot,  reporoot);
    u8csMv(sc.gitlinks,  u8bDataC(gitlinks));
    u8csMv(sc.base_rows, u8bDataC(base_rows));

    a_path(wp);
    u8bFeed(wp, reporoot);
    call(PATHu8bTerm, wp);
    //  FILE_SCAN_DIRS gets the cb a chance to FILESKIP whole nested
    //  repos via the `.git`-inside heuristic.
    ok64 so = FILEScan(wp,
                       (FILE_SCAN)(FILE_SCAN_FILES | FILE_SCAN_LINKS |
                                   FILE_SCAN_DIRS  | FILE_SCAN_DEEP),
                       at_dirty_scan_cb, &sc);
    u8bFree(gitlinks);
    u8bFree(base_rows);
    if (sc.cb_err != OK) return sc.cb_err;
    return so;
}

// --- SNIFFWtListPaths -------------------------------------------------

typedef struct {
    u8cs reporoot;
    u8bp paths;
    u8bp meta;
    ok64 err;
} at_list_ctx;

static ok64 at_list_cb(void *varg, path8bp path) {
    sane(varg && path);
    at_list_ctx *c = (at_list_ctx *)varg;

    a_dup(u8c, full, u8bData(path));
    u8cs rel = {};
    if (!SNIFFRelFromFull(rel, c->reporoot, full)) return OK;
    if (SNIFFSkipMeta(rel))                         return OK;

    filestat fs = {};
    ok64 lo = FILELStat(&fs, full);
    if (lo == FILENOENT) return OK;    // vanished mid-walk
    if (lo != OK) return lo;             // propagate other errors
    u8 kind;
    if      (fs.kind == FILE_KIND_LNK) kind = WALK_KIND_LNK;
    else if (fs.mode & 0100)           kind = WALK_KIND_EXE;
    else                               kind = WALK_KIND_REG;

    ok64 o = u8bFeed(c->paths, rel);
    if (o == OK) o = u8bFeed1(c->paths, '\n');
    if (o == OK) o = u8bFeed1(c->meta,  kind);
    if (o != OK) { c->err = o; return o; }
    return OK;
}

ok64 SNIFFWtListPaths(u8cs reporoot, u8bp out_paths, u8bp out_meta) {
    sane($ok(reporoot) && out_paths && out_meta);
    u8bReset(out_paths);
    u8bReset(out_meta);
    at_list_ctx c = {.paths = out_paths, .meta = out_meta, .err = OK};
    u8csMv(c.reporoot, reporoot);

    a_path(wp);
    u8bFeed(wp, reporoot);
    call(PATHu8bTerm, wp);

    //  Same sizing rationale as `SNIFFWtULog`: ignored mega-dirs
    //  (Corpus/, .git/objects/, build/) still get sorted before the
    //  per-file callback gets to skip them.
    Bu8 scratch = {};
    call(u8bMap, scratch, 1UL << 24);

    ok64 so = FILEScanSorted(wp,
                             (FILE_SCAN)(FILE_SCAN_FILES | FILE_SCAN_LINKS |
                                         FILE_SCAN_DEEP),
                             scratch, FILEentryZ, at_list_cb, &c);
    u8bUnMap(scratch);
    if (c.err != OK) return c.err;
    return so;
}

// --- SNIFFWtULog: emit wt entries as ULOG rows ----------------------

typedef struct {
    u8cs  reporoot;
    u8bp  out;
    ron60 verb;
    ok64  err;
} at_ulog_ctx;

//  Map a stat-derived kind/mode to the RON64 letter appended to the
//  caller's verb stem (f=regular, x=executable, l=symlink).  No
//  submodule case here — gitlinks live in trees, not the wt scan.
static u8 wt_kind_letter(filestat const *fs) {
    if      (fs->kind == FILE_KIND_LNK) return RON_l;
    else if (fs->mode & 0100)           return RON_x;
    else                                return RON_f;
}

static ok64 at_ulog_cb(void *varg, path8bp path) {
    sane(varg && path);
    at_ulog_ctx *c = (at_ulog_ctx *)varg;

    a_dup(u8c, full, u8bData(path));
    u8cs rel = {};
    if (!SNIFFRelFromFull(rel, c->reporoot, full)) return OK;
    if (SNIFFSkipMeta(rel))                         return OK;

    filestat fs = {};
    ok64 lo = FILELStat(&fs, full);
    if (lo == FILENOENT) return OK;    // vanished mid-walk
    if (lo != OK) return lo;             // propagate other errors

    uri u = {};
    u8csMv(u.path, rel);
    //  query empty (mode encoded in verb), fragment empty (no sha yet).

    ulogrec rec = {.ts   = fs.mtime,
                   .verb = ok64sub(c->verb, wt_kind_letter(&fs)),
                   .uri  = u};
    ok64 o = ULOGu8sFeed(u8bIdle(c->out), &rec);
    if (o != OK) { c->err = o; return o; }
    return OK;
}

ok64 SNIFFWtULog(u8cs reporoot, ron60 verb, u8bp out) {
    sane($ok(reporoot) && out);
    u8bReset(out);
    at_ulog_ctx c = {.out = out, .verb = verb, .err = OK};
    u8csMv(c.reporoot, reporoot);

    a_path(wp);
    u8bFeed(wp, reporoot);
    call(PATHu8bTerm, wp);

    //  FILEScanSorted sorts each visited dir's entries in scratch
    //  space; ignored dirs (Corpus/, .git/objects/, build/) can hold
    //  tens of thousands of entries even though no row will be
    //  emitted for them.  Use a 16 MB mmap region — VA only, paged
    //  on demand — to comfortably handle the worst real-world dir.
    Bu8 scratch = {};
    call(u8bMap, scratch, 1UL << 24);

    ok64 so = FILEScanSorted(wp,
                             (FILE_SCAN)(FILE_SCAN_FILES | FILE_SCAN_LINKS |
                                         FILE_SCAN_DEEP),
                             scratch, FILEentryZ, at_ulog_cb, &c);
    u8bUnMap(scratch);
    if (c.err != OK) return c.err;
    return so;
}
