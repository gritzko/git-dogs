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
#include "dog/QURY.h"

//  Row-0 invariant guard: `repo` only at row 0, every other verb only
//  at row ≥ 1.  Returns OK if the append is allowed.
static ok64 at_check_row0(ron60 verb) {
    sane(SNIFF.h);
    ron60 vrepo = SNIFFAtVerbRepo();
    u32 n = ULOGCount(&SNIFF.log);
    if (n == 0 && verb != vrepo) fail(SNIFFFAIL);
    if (n > 0 && verb == vrepo)  fail(SNIFFFAIL);
    done;
}

ok64 SNIFFAtAppend(ron60 verb, uricp u) {
    sane(SNIFF.h && u);
    call(at_check_row0, verb);
    return ULOGAppend(&SNIFF.log, verb, u);
}

ok64 SNIFFAtAppendAt(ron60 ts, ron60 verb, uricp u) {
    sane(SNIFF.h && u);
    call(at_check_row0, verb);
    return ULOGAppendAt(&SNIFF.log, ts, verb, u);
}

b8 SNIFFAtKnown(ron60 mtime) {
    if (!SNIFF.h) return NO;
    return ULOGHas(&SNIFF.log, mtime);
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
    if (ULOGCount(&SNIFF.log) == 0) return ULOGNONE;
    ron60 ts = 0, verb = 0;
    call(ULOGRow, &SNIFF.log, 0, &ts, &verb, u_out);
    if (verb != SNIFFAtVerbRepo()) fail(SNIFFFAIL);
    done;
}

// --- Baseline URI lookup ---

ok64 SNIFFAtBaseline(ron60 *ts_out, ron60 *verb_out, urip u_out) {
    sane(SNIFF.h && ts_out && verb_out && u_out);
    ron60 vg = SNIFFAtVerbGet();
    ron60 vp = SNIFFAtVerbPost();
    ron60 vx = SNIFFAtVerbPatch();
    u32 n = ULOGCount(&SNIFF.log);
    for (u32 i = n; i > 0; i--) {
        ron60 ts = 0, verb = 0;
        uri u = {};
        ok64 o = ULOGRow(&SNIFF.log, i - 1, &ts, &verb, &u);
        if (o != OK) return o;
        if (verb == vg || verb == vp || verb == vx) {
            *ts_out = ts;
            *verb_out = verb;
            *u_out = u;
            done;
        }
    }
    return ULOGNONE;
}

// --- Last-post timestamp ---

ron60 SNIFFAtLastPostTs(void) {
    if (!SNIFF.h) return 0;
    ron60 vp = SNIFFAtVerbPost();
    ron60 ts = 0;
    uri u = {};
    ok64 o = ULOGFindVerb(&SNIFF.log, vp, &ts, &u);
    if (o != OK) return 0;
    return ts;
}

// --- Put/delete forward scan since floor ---

// --- ron60 ↔ timespec helpers ---

ron60 SNIFFAtOfTimespec(struct timespec tsp) {
    struct tm tm = {};
    time_t sec = tsp.tv_sec;
    //  RONNow uses localtime, so match that for round-trip.
    localtime_r(&sec, &tm);
    u32 ms = (u32)(tsp.tv_nsec / 1000000);
    if (ms > 999) ms = 999;
    ron60 r = 0;
    RONOfTime(&r, &tm, ms);
    return r;
}

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
        ron60 tail_ts = 0, tail_verb = 0;
        uri tu = {};
        if (ULOGTail(&SNIFF.log, &tail_ts, &tail_verb, &tu) == OK) {
            if (now <= tail_ts) now = tail_ts + 1;
        }
    }
    *ts_out = now;
    *tv_out = at_ts_of_ron60(now);
}

ok64 SNIFFAtRowAtTs(ron60 mtime, ron60 *verb_out, urip u_out) {
    sane(SNIFF.h && verb_out && u_out);
    u32 i = 0;
    ok64 fo = ULOGFind(&SNIFF.log, mtime, &i);
    if (fo != OK) return fo;
    ron60 ts = 0, verb = 0;
    uri u = {};
    call(ULOGRow, &SNIFF.log, i, &ts, &verb, &u);
    *verb_out = verb;
    *u_out = u;
    done;
}

ok64 SNIFFCheckClock(void) {
    sane(1);
    if (!SNIFF.h) done;                       // no log yet, nothing to compare
    ron60 tail_ts = 0, tail_verb = 0;
    uri tu = {};
    if (ULOGTail(&SNIFF.log, &tail_ts, &tail_verb, &tu) != OK) done;
    ron60 now = RONNow();
    if (now < tail_ts) {
        fprintf(stderr,
                "sniff: clock skew — system clock is before the latest "
                ".sniff row; refusing every command until clock catches "
                "up\n");
        return SNIFFCLOCKBAD;
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
    ok64 s = ULOGSeek(&SNIFF.log, floor, &start);
    if (s != OK && s != ULOGNONE) return s;
    u32 n = ULOGCount(&SNIFF.log);
    ron60 vput = SNIFFAtVerbPut();
    ron60 vdel = SNIFFAtVerbDelete();
    for (u32 i = start; i < n; i++) {
        ron60 ts = 0, verb = 0;
        uri u = {};
        ok64 o = ULOGRow(&SNIFF.log, i, &ts, &verb, &u);
        if (o != OK) return o;
        if (ts <= floor) continue;
        if (verb != vput && verb != vdel) continue;
        a_dup(u8c, path, u.path);
        ok64 cr = cb(verb, path, ts, ctx);
        if (cr != OK) return cr;
    }
    done;
}

ok64 SNIFFAtQueryFirstSha(uricp u, u8 *out_hex40) {
    sane(u && out_hex40);

    //  Canonical at-log row: `?<branch>#<curhash>` — fragment is the
    //  current sha.  Take it directly when present.
    {
        u8cs frag = {u->fragment[0], u->fragment[1]};
        if (u8csLen(frag) == 40) {
            memcpy(out_hex40, frag[0], 40);
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
        if (spec.type == QURY_SHA && $len(spec.body) == 40) {
            memcpy(out_hex40, spec.body[0], 40);
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
} at_dirty_scan_ctx;

static ok64 at_dirty_scan_cb(void *varg, path8bp path) {
    sane(varg && path);
    at_dirty_scan_ctx *c = (at_dirty_scan_ctx *)varg;

    a_dup(u8c, full, u8bData(path));
    u8cs rel = {};
    if (!SNIFFRelFromFull(&rel, c->reporoot, full)) return OK;
    if (SNIFFSkipMeta(rel))                         return OK;

    struct stat sb = {};
    if (lstat((char const *)full[0], &sb) != 0) return OK;
    struct timespec ts = {.tv_sec  = sb.st_mtim.tv_sec,
                          .tv_nsec = sb.st_mtim.tv_nsec};
    if (SNIFFAtKnown(SNIFFAtOfTimespec(ts))) return OK;

    ok64 o = c->cb(rel, c->user_ctx);
    if (o != OK) c->cb_err = o;
    return o;
}

ok64 SNIFFAtScanDirty(u8cs reporoot, sniff_at_dirty_cb cb, void *ctx) {
    sane($ok(reporoot) && cb != NULL);
    at_dirty_scan_ctx sc = {.cb = cb, .user_ctx = ctx, .cb_err = OK};
    u8csMv(sc.reporoot, reporoot);
    a_path(wp);
    u8bFeed(wp, reporoot);
    call(PATHu8bTerm, wp);
    ok64 so = FILEScan(wp,
                       (FILE_SCAN)(FILE_SCAN_FILES | FILE_SCAN_LINKS |
                                   FILE_SCAN_DEEP),
                       at_dirty_scan_cb, &sc);
    if (sc.cb_err != OK) return sc.cb_err;
    return so;
}
