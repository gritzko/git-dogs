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
#include "keeper/WALK.h"   // WALK_KIND_*

// --- Standalone RO tail peek (no SNIFF singleton, no keeper) -------

//  Strip a trailing `.dogs/` (and any trailing slashes) from `in`,
//  feeding the bare root path into `out`.  Mirrors
//  `sniff_store_root_from_repo` (sniff/SNIFF.c) but operates on the
//  caller's slice without touching the SNIFF singleton.
static void at_root_from_repo_path(u8cs in, u8bp out) {
    a_dup(u8c, p, in);
    if (!$empty(p) && *u8csLast(p) == '/') u8csShed1(p);
    a_cstr(dogs, ".dogs");
    size_t dl = $len(dogs);
    if ($len(p) >= dl && memcmp($atp(p, $len(p) - dl), dogs[0], dl) == 0)
        for (size_t i = 0; i < dl; i++) u8csShed1(p);
    while ($len(p) > 1 && *u8csLast(p) == '/') u8csShed1(p);
    u8bReset(out);
    u8bFeed(out, p);
}

ok64 SNIFFAtTailOf(u8cs wt, u8bp out) {
    sane($ok(wt) && out);

    a_cstr(rel, SNIFF_FILE);
    a_path(apath, wt, rel);

    //  RO open: callable concurrently with sniff's own RW handle.
    //  ULOGOpenRO maps PROT_READ and skips FILEBook's page-align
    //  ftruncate, so it can't trip the silent-EOF-truncation bug
    //  the legacy RW reader caused.
    u8bp  data = NULL;
    Bkv64 idx  = {};
    ok64 o = ULOGOpenRO(&data, idx, $path(apath));
    if (o != OK) fail(SNIFFATNONE);

    u32 n = ULOGCount(idx);
    if (n == 0) { ULOGClose(data, idx, NO); fail(SNIFFATNONE); }

    //  Row 0 = repo anchor → root path.
    a_pad(u8, root_buf, FILE_PATH_MAX_LEN);
    {
        ulogrec r0 = {};
        if (ULOGRow(data, idx, 0, &r0) != OK ||
            r0.verb != SNIFFAtVerbRepo()) {
            ULOGClose(data, idx, NO); fail(SNIFFATNONE);
        }
        u8cs rp = {r0.uri.path[0], r0.uri.path[1]};
        at_root_from_repo_path(rp, root_buf);
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
        ref_body[0] = ref_body[1] = NULL;
        sha_body[0] = sha_body[1] = NULL;
        {
            u8cs frag = {u.fragment[0], u.fragment[1]};
            if (u8csLen(frag) == 40) {
                sha_body[0] = frag[0];
                sha_body[1] = frag[1];
            }
        }
        a_dup(u8c, q, u.query);
        while (!$empty(q)) {
            qref spec = {};
            if (QURYu8sDrain(q, &spec) != OK) break;
            if (spec.type == QURY_NONE) break;
            if (spec.type == QURY_REF && $empty(ref_body)) {
                ref_body[0] = spec.body[0];
                ref_body[1] = spec.body[1];
            } else if (spec.type == QURY_SHA &&
                       $len(spec.body) == 40 &&
                       $empty(sha_body)) {
                sha_body[0] = spec.body[0];
                sha_body[1] = spec.body[1];
            }
        }
        if (!$empty(sha_body)) { found = YES; break; }
    }

    if (!found) { ULOGClose(data, idx, NO); fail(SNIFFATNONE); }

    //  Compose `<root>?<branch>#<sha>` into `out`.  branch may be
    //  empty (== trunk); `?` separator stays so URILexer round-trips
    //  the empty query as a present-but-empty slot.
    u8bReset(out);
    a_dup(u8c, root_s, u8bData(root_buf));
    u8bFeed(out, root_s);
    u8bFeed1(out, '?');
    if (!$empty(ref_body)) u8bFeed(out, ref_body);
    u8bFeed1(out, '#');
    u8bFeed(out, sha_body);

    ULOGClose(data, idx, NO);
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
        fprintf(stderr,
                "sniff: clock skew — system clock is before the latest "
                ".sniff row; refusing every command until clock catches "
                "up\n");
        return CLOCKBAD;
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
        a_dup(u8c, path, rec.uri.path);
        ok64 cr = cb(rec.verb, path, rec.ts, ctx);
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
    if (!SNIFFRelFromFull(&rel, c->reporoot, full)) return OK;
    if (SNIFFSkipMeta(rel))                         return OK;

    struct stat sb = {};
    if (lstat((char const *)full[0], &sb) != 0) return OK;
    u8 kind;
    if      (S_ISLNK(sb.st_mode))     kind = WALK_KIND_LNK;
    else if (sb.st_mode & S_IXUSR)    kind = WALK_KIND_EXE;
    else                              kind = WALK_KIND_REG;

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

    //  FILEScanSorted needs scratch buffer for per-dir entry stacks.
    //  Sized at 1 MB — large enough for tens of thousands of entries
    //  per dir, well beyond anything reasonable.
    Bu8 scratch = {};
    call(u8bAllocate, scratch, 1UL << 20);

    ok64 so = FILEScanSorted(wp,
                             (FILE_SCAN)(FILE_SCAN_FILES | FILE_SCAN_LINKS |
                                         FILE_SCAN_DEEP),
                             scratch, FILEentryZ, at_list_cb, &c);
    u8bFree(scratch);
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

static b8 wt_mode_str(u8 kind, u8cs out) {
    static u8c const m_reg[6] = "100644";
    static u8c const m_exe[6] = "100755";
    static u8c const m_lnk[6] = "120000";
    u8c const *p = NULL;
    switch (kind) {
        case WALK_KIND_REG: p = m_reg; break;
        case WALK_KIND_EXE: p = m_exe; break;
        case WALK_KIND_LNK: p = m_lnk; break;
        default:            return NO;
    }
    out[0] = p; out[1] = p + 6;
    return YES;
}

static ok64 at_ulog_cb(void *varg, path8bp path) {
    sane(varg && path);
    at_ulog_ctx *c = (at_ulog_ctx *)varg;

    a_dup(u8c, full, u8bData(path));
    u8cs rel = {};
    if (!SNIFFRelFromFull(&rel, c->reporoot, full)) return OK;
    if (SNIFFSkipMeta(rel))                         return OK;

    struct stat sb = {};
    if (lstat((char const *)full[0], &sb) != 0) return OK;
    u8 kind;
    if      (S_ISLNK(sb.st_mode))     kind = WALK_KIND_LNK;
    else if (sb.st_mode & S_IXUSR)    kind = WALK_KIND_EXE;
    else                              kind = WALK_KIND_REG;

    u8cs mode_s = {};
    if (!wt_mode_str(kind, mode_s)) return OK;

    //  ts = file mtime as ron60 (round-trips through SNIFFAtKnown).
    //  fragment is empty: hash on demand only when classification needs it.
    struct timespec mts = {.tv_sec  = sb.st_mtim.tv_sec,
                           .tv_nsec = sb.st_mtim.tv_nsec};
    ron60 ts = SNIFFAtOfTimespec(mts);

    uri u = {};
    u.path[0]  = rel[0];     u.path[1]  = rel[1];
    u.query[0] = mode_s[0];  u.query[1] = mode_s[1];
    //  fragment left empty (no sha yet)

    ulogrec rec = {.ts = ts, .verb = c->verb, .uri = u};
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

    Bu8 scratch = {};
    call(u8bAllocate, scratch, 1UL << 20);

    ok64 so = FILEScanSorted(wp,
                             (FILE_SCAN)(FILE_SCAN_FILES | FILE_SCAN_LINKS |
                                         FILE_SCAN_DEEP),
                             scratch, FILEentryZ, at_ulog_cb, &c);
    u8bFree(scratch);
    if (c.err != OK) return c.err;
    return so;
}
