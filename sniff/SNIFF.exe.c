//  SNIFFExec — run a parsed CLI against an open sniff state.
//  Same effect as invoking `sniff ...` as a separate process.
//
#include "SNIFF.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "AT.h"
#include "CLASS.h"
#include "DEL.h"
#include "GET.h"
#include "LS.h"
#include "PATCH.h"
#include "POST.h"
#include "PUT.h"
#include "dog/CLI.h"
#include "dog/QURY.h"
#include "dog/DOG.h"
#include "dog/HOME.h"
#include "dog/IGNO.h"
#include "dog/ULOG.h"
#include "keeper/GIT.h"
#include "keeper/KEEP.h"
#include "keeper/REFS.h"
#include "keeper/WALK.h"

#include "abc/B.h"
#include "abc/FILE.h"
#include "abc/FSW.h"
#include "abc/HEX.h"
#include "abc/PATH.h"
#include "abc/PRO.h"
#include "abc/UTF8.h"

// --- Mode: Watch daemon ---

static volatile sig_atomic_t sniff_quit = 0;

static void sniff_sighandler(int sig) {
    (void)sig;
    sniff_quit = 1;
}

static ok64 sniff_write_pid(u8cs reporoot) {
    sane($ok(reporoot));
    a_cstr(pidname, "sniff.pid");
    a_path(pp, reporoot, DOG_BE_S, pidname);
    FILE *fp = fopen((char *)u8bDataHead(pp), "w");
    if (!fp) fail(SNIFFFAIL);
    fprintf(fp, "%d\n", (int)getpid());
    fclose(fp);
    done;
}

static ok64 sniff_rm_pid(u8cs reporoot) {
    sane($ok(reporoot));
    a_cstr(pidname, "sniff.pid");
    a_path(pp, reporoot, DOG_BE_S, pidname);
    FILEUnLink($path(pp));
    done;
}

typedef struct { int wfd; u32 count; } watchdir_ctx;

static ok64 sniff_watchdir_cb(void0p arg, path8p path) {
    watchdir_ctx *ctx = (watchdir_ctx *)arg;
    u8csc p = {u8bDataHead(path), u8bIdleHead(path)};
    ok64 o = FSWDir(ctx->wfd, p);
    if (o == OK) ctx->count++;
    return OK;
}

static ok64 sniff_drain_cb(u8cs path, void *ctx) {
    (void)path; (void)ctx; return OK;
}

//  The watch daemon emits one `mod <dir/>` ULOG row per directory
//  containing dirty files (mtime ∉ stamp set).  Dedup is via .be/wtlog
//  itself: a directory whose `mod <dir/>` row already exists since the
//  most recent baseline (get/post/patch) is skipped.  Coarse-grained
//  by design — POST does its own wt scan; the row is just an advisory
//  "something happened in this area" signal for external tools.

typedef struct {
    u8cs   reporoot;
    Bu8   *seen_dirs;    // newline-sep set of dir paths already mod'd
} watch_scan_ctx;

//  YES iff `dir` already appears in `*seen` (linear scan; the set is
//  bounded by the number of distinct dirs touched between two
//  get/post events — small in practice).
static b8 watch_dir_seen(Bu8 *seen, u8cs dir) {
    a_dup(u8c, scan, u8bData(*seen));
    while (!u8csEmpty(scan)) {
        u8cs line = {};
        if (u8csDrainLine(scan, line) != OK) break;
        if (u8csLen(line) == u8csLen(dir) &&
            memcmp(line[0], dir[0], u8csLen(dir)) == 0) return YES;
    }
    return NO;
}

static void watch_dir_remember(Bu8 *seen, u8cs dir) {
    u8bFeed(*seen, dir);
    u8bFeed1(*seen, '\n');
}

//  Compute the parent dir slice (with trailing '/') for `rel` into
//  `out`.  Files at the wt root use "/".
static void watch_parent_dir(u8csc rel, u8b out) {
    u8bReset(out);
    u8c const *slash_last = NULL;
    for (u8c const *p = rel[0]; p < rel[1]; p++) {
        if (*p == '/') slash_last = p;
    }
    if (slash_last) {
        u8cs parent = {rel[0], slash_last + 1};   // include trailing '/'
        u8bFeed(out, parent);
    } else {
        u8bFeed1(out, '/');                       // root marker
    }
}

//  Seed `*seen` from the .be/wtlog log: every `mod <dir/>` row whose ts
//  is past the most recent get/post/patch baseline contributes its
//  path.
static ok64 watch_seed_seen(Bu8 *seen) {
    sane(seen);
    u8bReset(*seen);
    ron60 base_ts = 0, bv = 0;
    uri bu = {};
    if (SNIFFAtBaseline(&base_ts, &bv, &bu) != OK) base_ts = 0;
    ron60 v_mod = SNIFFAtVerbMod();
    u32 n = ULOGCount(SNIFF.log_idx);
    for (u32 i = 0; i < n; i++) {
        ulogrec rec = {};
        if (ULOGRow(SNIFF.log_data, SNIFF.log_idx, i, &rec) != OK) continue;
        if (rec.ts <= base_ts) continue;
        if (rec.verb != v_mod) continue;
        u8cs path = {rec.uri.path[0], rec.uri.path[1]};
        if ($empty(path)) continue;
        if (!watch_dir_seen(seen, path)) watch_dir_remember(seen, path);
    }
    done;
}

static ok64 watch_scan_cb(void *varg, path8bp path) {
    sane(varg && path);
    watch_scan_ctx *w = (watch_scan_ctx *)varg;
    a_dup(u8c, full, u8bData(path));

    u8cs rel = {};
    if (!SNIFFRelFromFull(rel, w->reporoot, full)) return OK;
    if (SNIFFSkipMeta(rel))                         return OK;
    //  The daemon's own pidfile (`<root>/.be/sniff.pid`) is filtered
    //  by SNIFFSkipMeta above (anything under `.be/`).

    filestat fs = {};
    ok64 lo = FILELStat(&fs, full);
    if (lo == FILENOENT) return OK;    // vanished mid-walk
    if (lo != OK) return lo;             // propagate
    ron60 mtime = fs.mtime;

    //  Clean against some baseline → nothing to log.
    if (SNIFFAtKnown(mtime)) return OK;

    a_pad(u8, dirbuf, 1024);
    watch_parent_dir(rel, dirbuf);
    a_dup(u8c, dir, u8bData(dirbuf));
    if (watch_dir_seen(w->seen_dirs, dir)) return OK;

    //  Append one `mod <dir/>` row via the usual URI-struct path.
    uri urow = {};
    urow.path[0] = dir[0];
    urow.path[1] = dir[1];
    ron60 vmod = SNIFFAtVerbMod();
    if (SNIFFAtAppend(vmod, &urow) == OK) {
        watch_dir_remember(w->seen_dirs, dir);
    }
    return OK;
}

static ok64 watch_rescan(u8cs reporoot, Bu8 *seen_dirs) {
    sane($ok(reporoot) && seen_dirs);
    //  Rebuild the seen set from .be/wtlog each scan — the baseline may
    //  have advanced (get/post/patch) since the last invocation,
    //  invalidating prior `mod` rows.
    call(watch_seed_seen, seen_dirs);

    watch_scan_ctx wc = {.seen_dirs = seen_dirs};
    wc.reporoot[0] = reporoot[0];
    wc.reporoot[1] = reporoot[1];

    a_path(wp);
    u8bFeed(wp, reporoot);
    call(PATHu8bTerm, wp);
    call(FILEScan, wp,
         (FILE_SCAN)(FILE_SCAN_FILES | FILE_SCAN_LINKS | FILE_SCAN_DEEP),
         watch_scan_cb, &wc);
    done;
}

static ok64 sniff_daemon(u8cs reporoot) {
    sane(1);
    pid_t pid = fork();
    if (pid < 0) fail(SNIFFFAIL);
    if (pid > 0) {
        fprintf(stderr, "sniff: daemon pid %d\n", (int)pid);
        _exit(0);
    }
    setsid();
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        dup2(devnull, STDIN_FILENO);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        if (devnull > STDERR_FILENO) close(devnull);
    }
    call(sniff_write_pid, reporoot);
    struct sigaction sa = {.sa_handler = sniff_sighandler};
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    int wfd = -1;
    call(FSWInit, &wfd);
    { u8csc rp = {reporoot[0], reporoot[1]}; FSWDir(wfd, rp); }
    watchdir_ctx wctx = {.wfd = wfd};
    {
        a_path(wp, reporoot);
        FILEScan(wp, (FILE_SCAN)(FILE_SCAN_DIRS | FILE_SCAN_DEEP),
                 sniff_watchdir_cb, &wctx);
    }

    //  Newline-sep set of directories whose `mod <dir/>` row has
    //  already been written since the most recent baseline.  Rebuilt
    //  per scan in watch_rescan().
    Bu8 seen_dirs = {};
    call(u8bAllocate, seen_dirs, 1UL << 16);

    //  Seed scan: emit mod rows for anything already dirty when the
    //  daemon starts.
    (void)watch_rescan(reporoot, &seen_dirs);

    while (!sniff_quit) {
        ok64 o = FSWPoll(wfd, 1000);
        if (o != OK) continue;
        FSWDrain(wfd, sniff_drain_cb, NULL);
        (void)watch_rescan(reporoot, &seen_dirs);
    }

    u8bFree(seen_dirs);
    FSWClose(wfd);
    sniff_rm_pid(reporoot);
    done;
}

// --- Mode: Stop daemon ---

static ok64 sniff_stop(u8cs reporoot) {
    sane($ok(reporoot));
    a_cstr(pidname, "sniff.pid");
    a_path(pp, reporoot, DOG_BE_S, pidname);
    FILE *fp = fopen((char *)u8bDataHead(pp), "r");
    if (!fp) { fprintf(stderr, "sniff: no daemon running\n"); done; }
    int dpid = 0;
    if (fscanf(fp, "%d", &dpid) != 1 || dpid <= 0) {
        fclose(fp); fail(SNIFFFAIL);
    }
    fclose(fp);
    if (kill(dpid, SIGTERM) != 0) {
        FILEUnLink($path(pp)); fail(SNIFFFAIL);
    }
    fprintf(stderr, "sniff: stopped pid %d\n", dpid);
    FILEUnLink($path(pp));
    done;
}

// --- Mode: Status ---
//
//  Bare `sniff` — overview of the working tree via the unified
//  4-way ULOG-merge classifier (`SNIFFClassify`).  Output follows
//  the ULOG row shape — `<time>\t<status>\t<path>` — except the
//  time is rendered human-readable via DOGutf8sFeedDate (7-char
//  relative form: `12:34`, `Tue`, `01Jan`, `01Jan25`).
//
//  Eight statuses, 3-char marker + colour on a tty (groups in
//  output order — clean state first, then staged, then unstaged,
//  then untracked):
//
//    ok   default in baseline + on disk + mtime ∈ stamp-set (clean)
//    put  blue    in baseline + put row since last post (staged mod)
//    new  green   not in baseline + put row             (staged add)
//    mov  cyan    put row with fragment (move src→dst)  (staged rename)
//    mod  yellow  in baseline + mtime ∉ stamp-set, no put/del row
//    del  brown   del row since last post               (staged remove)
//    mis  red     in baseline, file gone, no del row    (rm without `be delete`)
//    unk  grey    wt only, no put row                   (untracked)
//
//  Per-row time source: put/new/mov → put_rec->ts; del → del_rec->ts;
//  ok/mod/unk → wt_rec->ts (file's mtime); mis → 0 ("?").
//  `mov` rows render as `<src> -> <dst>` — the put row's fragment
//  carries the resolved dest path (see sniff/AT.md §"Move-form put
//  rows").  The dest path's own CLASS_WT_ONLY step is suppressed by
//  looking up its wt-mtime against the same put row.
//  Submodules are filtered upstream by SNIFFClassify.

#define STATUS_ANSI_PUT "\033[34m"        // dark blue
#define STATUS_ANSI_NEW "\033[32m"        // dark green
#define STATUS_ANSI_MOV "\033[36m"        // cyan
#define STATUS_ANSI_MOD "\033[33m"        // yellow
#define STATUS_ANSI_DEL "\033[38;5;94m"   // 256-color brown
#define STATUS_ANSI_MIS "\033[31m"        // red
#define STATUS_ANSI_UNK "\033[90m"        // grey
#define STATUS_ANSI_OFF "\033[0m"

//  Display verbs encode the status bucket inside one shared ULOG-
//  formatted row stream.  Disjoint from the .be/wtlog log's own verbs;
//  these never persist — the buffer is mmap'd and freed inside one
//  status invocation.  Re-encoded each call (cheap; <10 bytes each).
typedef struct {
    ron60 v_put, v_new, v_mov, v_mod, v_del, v_mis, v_unk;
} status_verbs;

static void status_verbs_init(status_verbs *v) {
    a_cstr(s_put, "put"); v->v_put = SNIFFAtVerbOf(s_put);
    a_cstr(s_new, "new"); v->v_new = SNIFFAtVerbOf(s_new);
    a_cstr(s_mov, "mov"); v->v_mov = SNIFFAtVerbOf(s_mov);
    a_cstr(s_mod, "mod"); v->v_mod = SNIFFAtVerbOf(s_mod);
    a_cstr(s_del, "del"); v->v_del = SNIFFAtVerbOf(s_del);
    a_cstr(s_mis, "mis"); v->v_mis = SNIFFAtVerbOf(s_mis);
    a_cstr(s_unk, "unk"); v->v_unk = SNIFFAtVerbOf(s_unk);
}

typedef struct {
    //  ULOG-formatted rows: `<ts>\t<verb>\t<path>\n`.  Verb encodes
    //  the bucket so the dump pass groups by verb in render order.
    //  The `ok` bucket never lists rows — clean tracked files would
    //  flood the output — so it's a counter only.
    Bu8 rows;
    u32 ok_n, put_n, new_n, mov_n, mod_n, del_n, mis_n, unk_n;
    status_verbs v;
    i64 now;          // unix epoch seconds, for relative-date format
    u8cs reporoot;    // for resolving full paths in the wt-eq-base check
} status_buckets;

//  Hash the on-disk content at `<reporoot>/<rel>` as a git blob and
//  compare to the baseline blob sha encoded in `base_rec->uri.fragment`
//  (40-hex).  YES iff the bytes match — i.e. the file is "touched
//  unchanged" (mtime drift but content equals baseline) and should
//  count as `ok`, not `mod`.
static b8 status_wt_eq_base(u8cs reporoot, ulogreccp base_rec, u8cs rel) {
    if (!base_rec || u8csLen(base_rec->uri.fragment) != 40) return NO;
    a_path(fp);
    if (SNIFFFullpath(fp, reporoot, rel) != OK) return NO;
    filestat fs = {};
    if (FILELStat(&fs, $path(fp)) != OK) return NO;

    sha1 wt_sha = {};
    if (fs.kind == FILE_KIND_LNK) {
        a_pad(u8, tgt, 4096);
        if (FILEReadLink(tgt, $path(fp)) != OK) return NO;
        KEEPObjSha(&wt_sha, DOG_OBJ_BLOB, u8bDataC(tgt));
    } else if (fs.kind == FILE_KIND_REG) {
        if (fs.size == 0) {
            u8cs empty = {NULL, NULL};
            KEEPObjSha(&wt_sha, DOG_OBJ_BLOB, empty);
        } else {
            u8bp m = NULL;
            if (FILEMapRO(&m, $path(fp)) != OK) return NO;
            u8cs body = {u8bDataHead(m), u8bIdleHead(m)};
            KEEPObjSha(&wt_sha, DOG_OBJ_BLOB, body);
            FILEUnMap(m);
        }
    } else {
        return NO;
    }

    sha1 base_sha = {};
    u8s bin = {base_sha.data, base_sha.data + 20};
    a_dup(u8c, hex, base_rec->uri.fragment);
    if (HEXu8sDrainSome(bin, hex) != OK) return NO;
    return sha1Eq(&wt_sha, &base_sha);
}

//  Convert ron60 (packed local-time encoding via RONOfTime) to
//  unix-epoch seconds for DOGutf8sFeedDate.  0 → 0 ("?" placeholder).
static i64 status_ron60_to_secs(ron60 ts) {
    if (ts == 0) return 0;
    struct tm t = {};
    if (RONToTime(ts, &t, NULL) != OK) return 0;
    t.tm_isdst = -1;        // let mktime resolve DST
    time_t s = mktime(&t);
    return s == (time_t)-1 ? 0 : (i64)s;
}

//  Push one ULOG row carrying (ts, verb, path) into the shared
//  buffer.  Verb encodes the bucket — drained back out in render
//  order by status_dump_verb.
static void status_push(Bu8 rows, u8cs path, ron60 ts, ron60 verb,
                        u32 *count) {
    uri u = {};
    u.path[0] = path[0];
    u.path[1] = path[1];
    ulogrec rec = {.ts = ts, .verb = verb, .uri = u};
    if (ULOGu8sFeed(u8bIdle(rows), &rec) != OK) return;
    (*count)++;
}

//  Move flavour — carries both src (path) and dst (fragment) so the
//  dump pass can render `<src> -> <dst>` on one line.
static void status_push_mov(Bu8 rows, u8cs src, u8cs dst, ron60 ts,
                            ron60 verb, u32 *count) {
    uri u = {};
    u.path[0]     = src[0]; u.path[1]     = src[1];
    u.fragment[0] = dst[0]; u.fragment[1] = dst[1];
    ulogrec rec = {.ts = ts, .verb = verb, .uri = u};
    if (ULOGu8sFeed(u8bIdle(rows), &rec) != OK) return;
    (*count)++;
}

//  YES iff `mtime` stamps a put row whose URI carries a non-empty
//  fragment — i.e. the file at this path is the destination of an
//  in-flight move recorded in `.be/wtlog`.  Used to suppress the
//  dest's CLASS_WT_ONLY step (the source's step already emitted the
//  one `mov` line for the pair).
static b8 status_wt_is_mov_dst(ron60 mtime) {
    if (mtime == 0 || !SNIFFAtKnown(mtime)) return NO;
    ron60 ow_verb = 0;
    uri ow_u = {};
    if (SNIFFAtRowAtTs(mtime, &ow_verb, &ow_u) != OK) return NO;
    if (ow_verb != SNIFFAtVerbPut()) return NO;
    return !u8csEmpty(ow_u.fragment) ? YES : NO;
}

static ok64 status_step(class_step const *step, void *ctx) {
    status_buckets *b = (status_buckets *)ctx;
    u8cs path = {step->path[0], step->path[1]};

    //  Staged groups take precedence — del/put rows describe user
    //  intent regardless of subsequent wt fiddling.
    if (step->del_rec != NULL) {
        status_push(b->rows, path,
                    step->del_rec->ts, b->v.v_del, &b->del_n);
        return OK;
    }
    if (step->put_rec != NULL) {
        ron60 ts = step->put_rec->ts;
        //  Move-form put row: source side carries the dest in
        //  .fragment.  Emit one `mov` line and skip the per-side
        //  buckets — the dest's own WT_ONLY step is suppressed
        //  below via the stamp lookup.
        u8cs frag = {step->put_rec->uri.fragment[0],
                     step->put_rec->uri.fragment[1]};
        if (!u8csEmpty(frag)) {
            status_push_mov(b->rows, path, frag, ts,
                            b->v.v_mov, &b->mov_n);
            return OK;
        }
        if (step->kind == CLASS_BOTH || step->kind == CLASS_BASE_ONLY)
            status_push(b->rows, path, ts, b->v.v_put, &b->put_n);
        else
            status_push(b->rows, path, ts, b->v.v_new, &b->new_n);
        return OK;
    }
    switch (step->kind) {
        case CLASS_WT_ONLY:
            //  Suppress the destination side of a move — its `mov`
            //  line was already emitted on the source path's step.
            if (step->wt_rec != NULL &&
                status_wt_is_mov_dst(step->wt_rec->ts)) break;
            status_push(b->rows, path,
                        step->wt_rec ? step->wt_rec->ts : 0,
                        b->v.v_unk, &b->unk_n);
            break;
        case CLASS_BASE_ONLY:
            //  No useful timestamp — file is gone, baseline rows
            //  carry ts=0 by KEEPTreeULog convention.
            status_push(b->rows, path, 0, b->v.v_mis, &b->mis_n);
            break;
        case CLASS_BOTH:
            //  mtime fast-path: file last touched by a tracked op
            //  → unchanged from baseline content (counted as `ok`).
            //  Otherwise the file was edited since last get/post —
            //  unless its bytes hash equal to the baseline blob,
            //  which is the "touched-unchanged" / clean-drift case
            //  and also counts as `ok`.
            if (SNIFFAtKnown(step->wt_rec->ts)) {
                b->ok_n++;
            } else if (status_wt_eq_base(b->reporoot, step->base_rec,
                                         path)) {
                b->ok_n++;
            } else {
                status_push(b->rows, path,
                            step->wt_rec->ts, b->v.v_mod, &b->mod_n);
            }
            break;
    }
    return OK;
}

//  Drain the shared rows buffer, render rows whose verb matches
//  `verb_filter` as `<date>\t<status>\t<path>` (or `<src> -> <dst>`
//  for move rows whose URI carries a fragment).  On tty: time
//  column wears grey, status wears its own colour, path stays
//  default.  Walked once per bucket (≤7 passes) — trivial for
//  status sizes.
static void status_dump_verb(Bu8 rows, ron60 verb_filter,
                             char const *marker, char const *ansi,
                             b8 tty, i64 now) {
    a_dup(u8c, scan, u8bData(rows));
    while (!u8csEmpty(scan)) {
        ulogrec rec = {};
        ok64 dr = ULOGu8sDrain(scan, &rec);
        if (dr == NODATA) break;
        if (dr != OK) continue;                  // skip malformed (drain advances)
        if (rec.verb != verb_filter) continue;

        u8 date_buf[8];
        u8s date_into = {date_buf, date_buf + sizeof(date_buf)};
        u8cp date_start = date_into[0];
        (void)DOGutf8sFeedDate(date_into,
                               status_ron60_to_secs(rec.ts), now);

        if (tty) fputs(STATUS_ANSI_UNK, stdout);
        fwrite(date_start, 1, (size_t)(date_into[0] - date_start), stdout);
        if (tty) fputs(STATUS_ANSI_OFF, stdout);
        fputc('\t', stdout);
        if (tty) fputs(ansi, stdout);
        fputs(marker, stdout);
        if (tty) fputs(STATUS_ANSI_OFF, stdout);
        fputc('\t', stdout);
        fwrite(rec.uri.path[0], 1,
               (size_t)$len(rec.uri.path), stdout);
        if (!u8csEmpty(rec.uri.fragment)) {
            fputs(" -> ", stdout);
            fwrite(rec.uri.fragment[0], 1,
                   (size_t)$len(rec.uri.fragment), stdout);
        }
        fputc('\n', stdout);
    }
}

//  Worker: assumes b's rows buffer is already mapped.  Returns the
//  classification result; never frees.
static ok64 sniff_status_work(status_buckets *b) {
    sane(b);
    call(SNIFFClassify, status_step, b);

    //  `ok` rows are noise — every tracked file at baseline content
    //  prints there.  Surface only the count in the trailing summary.
    b8 tty = isatty(STDOUT_FILENO) ? YES : NO;
    if (b->put_n > 0)
        status_dump_verb(b->rows, b->v.v_put, "put", STATUS_ANSI_PUT, tty, b->now);
    if (b->new_n > 0)
        status_dump_verb(b->rows, b->v.v_new, "new", STATUS_ANSI_NEW, tty, b->now);
    if (b->mov_n > 0)
        status_dump_verb(b->rows, b->v.v_mov, "mov", STATUS_ANSI_MOV, tty, b->now);
    if (b->mod_n > 0)
        status_dump_verb(b->rows, b->v.v_mod, "mod", STATUS_ANSI_MOD, tty, b->now);
    if (b->del_n > 0)
        status_dump_verb(b->rows, b->v.v_del, "del", STATUS_ANSI_DEL, tty, b->now);
    if (b->mis_n > 0)
        status_dump_verb(b->rows, b->v.v_mis, "mis", STATUS_ANSI_MIS, tty, b->now);
    if (b->unk_n > 0)
        status_dump_verb(b->rows, b->v.v_unk, "unk", STATUS_ANSI_UNK, tty, b->now);
    //  Color the count + tag pair when the count is non-zero, on tty
    //  only.  `ok` is uncolored — its tag is informational, never
    //  surfaced as a row above.
    #define STATUS_PAINT(n, tag, ansi)                                  \
        do {                                                            \
            if (tty && (n) > 0)                                         \
                fprintf(stdout, ", " ansi "%u %s" STATUS_ANSI_OFF,      \
                        (n), (tag));                                    \
            else                                                        \
                fprintf(stdout, ", %u %s", (n), (tag));                 \
        } while (0)
    fprintf(stdout, "sniff: %u ok", b->ok_n);
    STATUS_PAINT(b->put_n, "put", STATUS_ANSI_PUT);
    STATUS_PAINT(b->new_n, "new", STATUS_ANSI_NEW);
    STATUS_PAINT(b->mov_n, "mov", STATUS_ANSI_MOV);
    STATUS_PAINT(b->mod_n, "mod", STATUS_ANSI_MOD);
    STATUS_PAINT(b->del_n, "del", STATUS_ANSI_DEL);
    STATUS_PAINT(b->mis_n, "mis", STATUS_ANSI_MIS);
    STATUS_PAINT(b->unk_n, "unk", STATUS_ANSI_UNK);
    fprintf(stdout, "\n");
    #undef STATUS_PAINT
    fflush(stdout);
    done;
}

//  Entry: maps the shared rows buffer, runs the worker, releases
//  regardless.  16 MB — mmap-backed so VA cost is paid lazily.
//  One buffer instead of six (~4× headroom): real-world wts
//  (~/dogs etc.) routinely produce tens of thousands of `unk` rows.
static ok64 sniff_status(u8cs reporoot) {
    sane(1);

    status_buckets b = {.now = (i64)time(NULL)};
    status_verbs_init(&b.v);
    u8csMv(b.reporoot, reporoot);
    call(u8bMap, b.rows, 1UL << 24);

    ok64 r = sniff_status_work(&b);

    u8bUnMap(b.rows);
    return r;
}

// --- Mode: Get summary (bare `be get`) ---
//
//  Bare `be get` (no URI) prints a worktree-anchored snapshot of
//  what's reachable: every local branch tip from keeper REFS, with
//  the current branch starred; then every remote-tracking ref so
//  the user can see which `//host?ref` rows are on file.

static ok64 sniff_get_branch_cb(keep_tipcp t, void *ctx) {
    u8cs *cp = (u8cs *)ctx;
    u8cs cur = {(*cp)[0], (*cp)[1]};
    char marker = ' ';
    if ($len(t->path) == $len(cur) &&
        ($len(cur) == 0 ||
         memcmp(t->path[0], cur[0], $len(cur)) == 0)) {
        marker = '*';
    }
    fprintf(stdout, "%c ?%.*s\t%.*s\n",
            marker,
            (int)$len(t->path), (char *)t->path[0],
            (int)$len(t->sha),  (char *)t->sha[0]);
    return OK;
}

static ok64 sniff_get_remote_cb(keep_remotecp r, void *ctx) {
    (void)ctx;
    fprintf(stdout, "  %.*s\t%.*s\n",
            (int)$len(r->key), (char *)r->key[0],
            (int)$len(r->sha), (char *)r->sha[0]);
    return OK;
}

static ok64 sniff_get_summary(u8cs reporoot) {
    sane($ok(reporoot));
    (void)reporoot;
    keeper *k = &KEEP;

    //  Current branch from sniff baseline (empty == trunk).
    ron60 bts = 0, bverb = 0;
    uri bu = {};
    u8cs cur = {};
    if (SNIFFAtBaseline(&bts, &bverb, &bu) == OK) {
        u8csMv(cur, bu.query);
    }

    fprintf(stdout, "branches:\n");
    ok64 to = KEEPEachTip(k, sniff_get_branch_cb, &cur);
    if (to != OK && to != REFSNONE) {
        fprintf(stderr, "sniff: get: branches: %s\n", ok64str(to));
        fail(to);
    }

    fprintf(stdout, "remotes:\n");
    ok64 ro = KEEPEachRemote(k, sniff_get_remote_cb, NULL);
    if (ro != OK && ro != REFSNONE) {
        fprintf(stderr, "sniff: get: remotes: %s\n", ok64str(ro));
        fail(ro);
    }
    done;
}

// --- Mode: Checkout ---

static ok64 sniff_checkout(u8cs reporoot, u8cs hex) {
    sane($ok(hex));
    a_pad(u8, src, 256);
    u8bFeed1(src, '?');
    u8bFeed(src, hex);
    a_dup(u8c, source, u8bData(src));
    return GETCheckout(reporoot, hex, source);
}

//  Pre-resolve a relative `?./X`, `?../X`, or `?..` URI in place.
//  No-op when the query has no relative prefix.  Reads the wt's
//  current branch from `.be/wtlog` baseline and writes the absolute
//  branch path into `qbuf`; rebuilds the URI's `data` slice as
//  `?<absolute>` in `databuf`.  Both buffers must outlive the
//  caller's use of `u`.  When `was_relative_out` is non-NULL it
//  receives YES iff the input had a relative prefix (callers use
//  this to enable create-on-miss).
static ok64 sniff_resolve_rel(uri *u, u8b qbuf, u8b databuf,
                              b8 *was_relative_out) {
    sane(u);
    if (was_relative_out) *was_relative_out = NO;
    if (u->query[0] == NULL || $empty(u->query)) done;
    a_dup(u8c, q_in, u->query);
    qref qspec = {};
    if (QURYu8sDrain(q_in, &qspec) != OK) done;
    if (qspec.type != QURY_REF || qspec.rel == QURY_REL_NONE) done;
    if (was_relative_out) *was_relative_out = YES;

    //  Current branch from sniff baseline.  Empty / missing baseline
    //  = trunk, which the resolver treats as the empty path.
    ron60 bts = 0, bverb = 0;
    uri bu = {};
    u8cs current = {};
    if (SNIFFAtBaseline(&bts, &bverb, &bu) == OK) {
        u8csMv(current, bu.query);
    }

    if (QURYBuildAbsolute(qbuf, &qspec, current) != OK) fail(SNIFFFAIL);

    u8bFeed1(databuf, '?');
    u8bFeed(databuf, u8bDataC(qbuf));
    u8csMv(u->query, u8bDataC(qbuf));
    u8csMv(u->data,  u8bDataC(databuf));
    done;
}

// Checkout from a parsed URI: resolve ?ref via keeper REFS, then checkout.
//
//  Resolution strategy (keeper WIREFetch no longer records per-origin
//  aliases — only `?heads/X → ?<sha>` and `?tags/X → ?<sha>`):
//
//    URI has ?query:
//      1. Try REFSResolve on the full URI (picks up any legacy
//         origin-qualified entries, plus the resolver's own
//         authority+query variant matcher).
//      2. Fallback: REFSResolve on a local-only `?<query>` (with a
//         leading `refs/` stripped) — lets `?refs/tags/v1` / `?v1` /
//         `?heads/main` all hit keeper's local refs file.
//      3. Last resort: treat query as a raw 40-hex SHA (covers the
//         `?<40hex>` URI that BEGetWorktree rewrites to).
//
//    URI has no ?query (fresh clone / re-clone):
//      1. If sniff at.log has a branch, resolve `?heads/<branch>`.
//      2. Else scan local REFS for a `?heads/*` entry, preferring
//         master/main/trunk; its sha is the checkout target and its
//         key becomes the at.log `source` so the branch is recorded.
static ok64 sniff_get_by_refkey(u8cs reporoot, u8csc keepdir,
                                 u8csc refkey) {
    a_pad(u8, arena, 1024);
    uri resolved = {};
    ok64 o = REFSResolve(&resolved, arena, keepdir, refkey);
    if (o != OK || $empty(resolved.query)) return KEEPNONE;
    return GETCheckout(reporoot, resolved.query, refkey);
}

// --- Path+query GET helpers -----------------------------------------
//
//  Both helpers are no-staging (no `.be/wtlog` row) overwrites of wt
//  files from another branch's tip.  Single-file form fetches one
//  blob via `KEEPGetByURI`; subtree form drains the target tree's
//  leaves via `KEEPTreeULog` and writes every leaf under the
//  requested prefix.

static ok64 sniff_get_blob_to_wt_switch(uri *u) {
    sane(u);
    u8cs br_split = {}, pin_split = {};
    DOGRefSplitPin(u->query, br_split, pin_split);
    u8cs target = {};
    if (u8csEmpty(pin_split)) u8csMv(target, u->query);
    else                       u8csMv(target, br_split);
    (void)SNIFFMaybeSwitchKeeper(target); (void)SNIFFMaybeSwitchGraf(target);
    done;
}

static ok64 sniff_get_blob_to_wt(u8cs reporoot, uri *u) {
    //  Same cross-branch consideration as the subtree overlay below:
    //  `be get file.c?feat` reads a blob from feat's tree, so feat's
    //  packs must be loaded.
    (void)sniff_get_blob_to_wt_switch(u);
    sane(u);
    keeper *k = &KEEP;
    Bu8 blob = {};
    call(u8bMap, blob, 64UL << 20);
    ok64 go = KEEPGetByURI(k, u, blob);
    if (go != OK) {
        u8bUnMap(blob);
        fprintf(stderr,
            "sniff: get: cannot resolve %.*s?%.*s\n",
            (int)$len(u->path),  (char const *)u->path[0],
            (int)$len(u->query), (char const *)u->query[0]);
        return go;
    }
    a_path(fp);
    a_dup(u8c, rr_s, reporoot);
    call(PATHu8bFeed, fp, rr_s);
    a_dup(u8c, path_s, u->path);
    call(PATHu8bPush, fp, path_s);
    int fd = -1;
    ok64 co = FILECreate(&fd, $path(fp));
    if (co != OK) {
        u8bUnMap(blob);
        fprintf(stderr, "sniff: get: cannot open %.*s for write: %s\n",
                (int)u8bDataLen(fp), (char const *)u8bDataHead(fp),
                ok64str(co));
        return co;
    }
    a_dup(u8c, body, u8bData(blob));
    ok64 wo = FILEFeedAll(fd, body);
    FILEClose(&fd);
    u8bUnMap(blob);
    if (wo != OK) {
        fprintf(stderr,
            "sniff: get: write %.*s failed: %s\n",
            (int)$len(u->path), (char const *)u->path[0],
            ok64str(wo));
        return wo;
    }
    fprintf(stderr,
        "sniff: get: %.*s overwritten from ?%.*s (no staging)\n",
        (int)$len(u->path),  (char const *)u->path[0],
        (int)$len(u->query), (char const *)u->query[0]);
    done;
}

//  Resolve `?ref` (URI's data) to the commit's tree sha-1.  Mirror of
//  graf/LOG.c's commit→tree extractor; lives here to avoid a graf
//  dependency in sniff for one helper.
static ok64 sniff_get_subtree_resolve_tree(uri *u, sha1 *tree_out) {
    sane(u && tree_out);
    keeper *k = &KEEP;
    a_path(keepdir, u8bDataC(k->h->root), KEEP_DIR_S);

    a_pad(u8, arena, 1024);
    uri resolved = {};
    a_dup(u8c, in_uri, u->data);
    ok64 ro = REFSResolve(&resolved, arena, $path(keepdir), in_uri);
    if (ro != OK || u8csLen(resolved.query) != 40) return SNIFFNONE;

    sha1 commit_sha = {};
    {
        u8s sb = {commit_sha.data, commit_sha.data + 20};
        a_dup(u8c, hx, resolved.query);
        if (HEXu8sDrainSome(sb, hx) != OK) return SNIFFFAIL;
    }
    Bu8 cbuf = {};
    call(u8bMap, cbuf, 1UL << 20);
    u8 ot = 0;
    ok64 go = KEEPGetExact(k, &commit_sha, cbuf, &ot);
    if (go != OK || ot != DOG_OBJ_COMMIT) {
        u8bUnMap(cbuf);
        return go == OK ? SNIFFFAIL : go;
    }
    a_dup(u8c, scan, u8bDataC(cbuf));
    u8cs field = {}, value = {};
    b8 got = NO;
    while (GITu8sDrainCommit(scan, field, value) == OK) {
        if (u8csEmpty(field)) break;
        a_cstr(ft, "tree");
        if ($eq(field, ft) && u8csLen(value) >= 40) {
            u8s sb = {tree_out->data, tree_out->data + 20};
            a_dup(u8c, hx2, value);
            if (HEXu8sDrainSome(sb, hx2) == OK) got = YES;
            break;
        }
    }
    u8bUnMap(cbuf);
    return got ? OK : SNIFFFAIL;
}

static ok64 sniff_get_subtree_to_wt(u8cs reporoot, uri *u) {
    sane(u);
    keeper *k = &KEEP;

    //  Cross-branch overlay: when the URI's query names a different
    //  branch (`be get src/?feat`), load feat's packs into PAST so
    //  the tree-walk + blob fetches below resolve via PastData.
    //  Path-prefix overlays don't change the wt's anchor; the
    //  switch is read-only context, no DATA shuffling for writes.
    {
        u8cs br_split = {}, pin_split = {};
        DOGRefSplitPin(u->query, br_split, pin_split);
        u8cs target = {};
        if (u8csEmpty(pin_split)) u8csMv(target, u->query);
        else                       u8csMv(target, br_split);
        (void)SNIFFMaybeSwitchKeeper(target); (void)SNIFFMaybeSwitchGraf(target);
    }

    sha1 tree_sha = {};
    ok64 tr = sniff_get_subtree_resolve_tree(u, &tree_sha);
    if (tr != OK) {
        fprintf(stderr,
            "sniff: get: cannot resolve %.*s?%.*s\n",
            (int)$len(u->path),  (char const *)u->path[0],
            (int)$len(u->query), (char const *)u->query[0]);
        return tr;
    }

    //  Drain the target tree's full leaf set.  KEEPTreeULog's verb
    //  stem is arbitrary — we only read uri.path / uri.fragment from
    //  each row.
    a_cstr(stem_s, "leaf");
    a_dup(u8c, stem_dup, stem_s);
    ron60 v_leaf = 0;
    call(RONutf8sDrain, &v_leaf, stem_dup);
    Bu8 ulog = {};
    call(u8bAllocate, ulog, 4UL << 20);
    ok64 lr = KEEPTreeULog(k, tree_sha.data, 0, v_leaf, ulog);
    if (lr != OK) { u8bFree(ulog); return lr; }

    //  Filter rows by the requested subtree prefix.  Path slice
    //  carries the trailing `/`; KEEPTreeULog emits paths with no
    //  trailing slash, so `<prefix>` matches `<prefix>/<...>` after
    //  comparing the prefix bytes including the final `/`.
    u8cs prefix = {u->path[0], u->path[1]};
    Bu8 blob = {};
    call(u8bMap, blob, 64UL << 20);
    u32 n_written = 0;
    a_dup(u8c, scan, u8bData(ulog));
    while (!u8csEmpty(scan)) {
        ulogrec rec = {};
        ok64 dr = ULOGu8sDrain(scan, &rec);
        if (dr == NODATA) break;
        if (dr != OK) continue;
        u8cs rp = {rec.uri.path[0], rec.uri.path[1]};
        if ($len(rp) <= $len(prefix)) continue;
        if (memcmp(rp[0], prefix[0], (size_t)$len(prefix)) != 0) continue;
        if (u8csLen(rec.uri.fragment) != 40) continue;

        sha1 leaf_sha = {};
        {
            u8s sb = {leaf_sha.data, leaf_sha.data + 20};
            a_dup(u8c, hx, rec.uri.fragment);
            if (HEXu8sDrainSome(sb, hx) != OK) continue;
        }
        u8bReset(blob);
        u8 ot = 0;
        if (KEEPGetExact(k, &leaf_sha, blob, &ot) != OK) continue;

        a_path(fp);
        a_dup(u8c, rr_s, reporoot);
        call(PATHu8bFeed, fp, rr_s);
        //  rp is multi-segment (e.g. "src/x.c"); use Add (segment-
        //  by-segment) — PATHu8bPush would reject the embedded '/'.
        a_dup(u8c, path_s, rp);
        call(PATHu8bAdd, fp, path_s);
        //  mkdir -p the parent dir.
        a_path(parent);
        a_dup(u8c, fp_s, u8bDataC(fp));
        call(PATHu8bFeed, parent, fp_s);
        call(PATHu8bPop, parent);
        (void)FILEMakeDirP($path(parent));

        int fd = -1;
        ok64 co = FILECreate(&fd, $path(fp));
        if (co != OK) {
            fprintf(stderr,
                "sniff: get: cannot open %.*s for write: %s\n",
                (int)u8bDataLen(fp), (char const *)u8bDataHead(fp),
                ok64str(co));
            continue;
        }
        a_dup(u8c, body, u8bData(blob));
        (void)FILEFeedAll(fd, body);
        FILEClose(&fd);
        n_written++;
    }
    u8bUnMap(blob);
    u8bFree(ulog);

    fprintf(stderr,
        "sniff: get: %u file(s) under %.*s overwritten from ?%.*s "
        "(no staging, no prune)\n",
        n_written,
        (int)$len(u->path),  (char const *)u->path[0],
        (int)$len(u->query), (char const *)u->query[0]);
    done;
}

static ok64 SNIFFGetURI(u8cs reporoot, uri *u) {
    sane(u);
    keeper *k = &KEEP;
    a_path(keepdir, u8bDataC(k->h->root), KEEP_DIR_S);

    //  Remote URI: under DOG.md §10a `be get` is the orchestrator —
    //  it already ran `keeper get URI` synchronously before forking
    //  the parallel spot/graf/sniff children.  Sniff is a worktree
    //  updater; it does not fetch from peers itself.  Standalone
    //  `sniff get ssh://...` will fail at REFSResolve below if the
    //  pack hasn't been pre-fetched — that's intentional (use `be
    //  get` for clones).

    //  Path+query, no authority — single-file or subtree overlay
    //  from another branch's tip (VERBS.md §GET).  Trailing `/` on
    //  the path picks subtree mode; no slash means single file.
    //  No `.be/wtlog` row is appended either way (no staging — the
    //  written paths land as regular user edits).  No pruning — wt
    //  files outside the target tree stay put (per project rule:
    //  GET overwrites unconditionally; we don't try to be clever
    //  about dirty wt state, but also don't sweep extras).
    if (!$empty(u->path) && !$empty(u->query) && $empty(u->authority)) {
        b8 is_subtree = (*u8csLast(u->path) == '/');
        if (!is_subtree)
            return sniff_get_blob_to_wt(reporoot, u);
        return sniff_get_subtree_to_wt(reporoot, u);
    }

    //  Path-only URI (no authority, no query) → `be get <hex>` or
    //  `be get <local-dir>` (the latter is rewritten by BEGetWorktree
    //  to a query-only URI before we get here).
    if ($empty(u->query) && $empty(u->authority) && !$empty(u->path)) {
        a_pad(u8, src, 256);
        u8bFeed1(src, '?');
        u8bFeed(src, u->path);
        a_dup(u8c, source, u8bData(src));
        return GETCheckout(reporoot, u->path, source);
    }

    //  Everything else: resolve the (canonicalised) URI against REFS
    //  and check out the resulting sha.  Treat *presence* of `?` —
    //  even with an empty query (`?` for trunk) — as an explicit ref
    //  lookup, distinct from "no query at all" (which falls through
    //  to the at-log branch resume below).
    b8 has_q = (u->query[0] != NULL);

    //  Pre-resolve relative refs (`?./X`, `?../X`, `?..`).  Storage
    //  must outlive the call (REFSResolve and GETCheckout both
    //  consume slices into u->query / u->data); _reluri rebases
    //  those into our stack-local buffer.
    a_pad(u8, abs_qbuf,    256);
    a_pad(u8, abs_databuf, 260);
    if (sniff_resolve_rel(u, abs_qbuf, abs_databuf, NULL) != OK)
        fail(SNIFFFAIL);

    if (has_q || !$empty(u->authority)) {
        a_pad(u8, arena1, 1024);
        uri resolved = {};
        ok64 o = REFSResolve(&resolved, arena1, $path(keepdir), u->data);

        //  Local lookup miss → retry with shorter query prefixes.
        //  `keeper get //host?refs/heads/X` stores under a
        //  peer-prefixed key with the wire-canonical query (e.g.
        //  `?master` after wcli_wire_to_be strips `refs/heads/`,
        //  `?tags/v1` after stripping `refs/`).  User input may be
        //  fully-qualified (`?refs/heads/X`) or already-stripped.
        //  Try `refs/`-then-`refs/heads/` peels.  When the URI has
        //  no authority of its own, also probe with `.` so peer
        //  rows participate (`sniff get ?master` finds remote
        //  tracking too).
        if ((o != OK || $empty(resolved.query)) && !$empty(u->query)) {
            char const *strips[] = {"refs/heads/", "refs/", "heads/", "", NULL};
            b8 bare = $empty(u->authority);
            for (u32 si = 0; strips[si] != NULL && (o != OK ||
                                $empty(resolved.query)); si++) {
                u8cs q = {u->query[0], u->query[1]};
                size_t plen = strlen(strips[si]);
                if (plen > 0) {
                    if ($len(q) <= plen) continue;
                    if (memcmp(q[0], strips[si], plen) != 0) continue;
                    u8csUsed(q, plen);
                }
                //  Local probe with stripped query (`?<stripped>`).
                a_pad(u8, retry_buf, 512);
                u8cs head = {u->data[0], u->query[0]};
                u8bFeed(retry_buf, head);
                u8bFeed(retry_buf, q);
                a_dup(u8c, retry_uri, u8bData(retry_buf));
                memset(&resolved, 0, sizeof(resolved));
                o = REFSResolve(&resolved, arena1,
                                $path(keepdir), retry_uri);
                if (o == OK && !$empty(resolved.query)) break;
                //  Peer-relay probe (`.?<stripped>`): bare-query
                //  inputs (no authority) — rewrite the URI as
                //  `.?<stripped>` so peer-prefixed tracking rows
                //  match.
                if (!bare) continue;
                a_pad(u8, dot_buf, 512);
                a_cstr(dot_pfx, ".?");
                u8bFeed(dot_buf, dot_pfx);
                u8bFeed(dot_buf, q);
                a_dup(u8c, dot_uri, u8bData(dot_buf));
                memset(&resolved, 0, sizeof(resolved));
                o = REFSResolve(&resolved, arena1,
                                $path(keepdir), dot_uri);
            }
        }

        //  GET never creates branches on miss — absolute and relative
        //  refs alike error out when REFS has no row.  `be post ?./X`
        //  is the spec-aligned create path (per VERBS.md).
        if (o == OK && !$empty(resolved.query)) {
            a_pad(u8, src, 256);
            u8bFeed1(src, '?');
            if (has_q) {
                if (!$empty(u->query)) u8bFeed(src, u->query);
            } else if (!$empty(resolved.fragment)) {
                //  Fresh-clone path: user gave no `?ref` (e.g.
                //  `be get ssh://sniff/src/dogs`).  Carry the matched
                //  row's refname (`heads/<branch>`) into the at-log so
                //  SNIFFAtBaseline → POSTCommit → keeper REFS chain
                //  records branch-keyed local moves.
                u8bFeed(src, resolved.fragment);
            }
            a_dup(u8c, source, u8bData(src));
            return GETCheckout(reporoot, resolved.query, source);
        }
        //  Raw hex fallback when the query is already a 40-hex sha
        //  that keeper has in its local store.
        if (!$empty(u->query)) {
            a_pad(u8, qbuf, 256);
            u8bFeed1(qbuf, '?');
            u8bFeed(qbuf, u->query);
            a_dup(u8c, qkey, u8bData(qbuf));
            return GETCheckout(reporoot, u->query, qkey);
        }
        //  Present-but-empty query (`?`, trunk): explicit fail rather
        //  than falling through to the at-log resume below — the user
        //  asked for trunk and the row isn't there.
        if (has_q) fail(SNIFFFAIL);
    }

    //  Bare `be get` (no URI args at all): resume the worktree's
    //  current branch (from `--at` forwarded by `be`, parked in
    //  `KEEP.h->cur_branch` by HOMEOpen) against the local trunk row
    //  `?#<sha>`.  Empty branch == trunk → falls through to the bare
    //  `?` lookup below.
    if (u8bDataLen(KEEP.h->cur_branch) > 0) {
        a_pad(u8, qbuf, 256);
        u8bFeed1(qbuf, '?');
        u8bFeed(qbuf, u8bDataC(KEEP.h->cur_branch));
        a_dup(u8c, qkey, u8bData(qbuf));
        ok64 o = sniff_get_by_refkey(reporoot, $path(keepdir), qkey);
        if (o == OK) return OK;
    }

    //  Last resort: a bare `?` (trunk) lookup — catches the case of
    //  a worktree with a local trunk row but no at.log branch name yet.
    a_cstr(trunk_s, "?");
    ok64 o = sniff_get_by_refkey(reporoot, $path(keepdir), trunk_s);
    if (o == OK) return OK;

    fail(SNIFFFAIL);
}

// --- Usage ---

static void sniff_usage(void) {
    fprintf(stderr,
            "Usage: sniff <command> [options] [URIs...]\n"
            "\n"
            "  sniff get <ref|sha>         checkout commit into the wt\n"
            "                              (alias: checkout)\n"
            "  sniff put <path>...         record `put` rows in the ULOG\n"
            "  sniff delete <path>...      record `delete` rows in the ULOG\n"
            "  sniff post <msg words...>   commit: walk baseline + wt,\n"
            "                              resolve change-set, feed one pack.\n"
            "                              Trailing free-form words become\n"
            "                              the commit message via the URI's\n"
            "                              #fragment.  (alias: commit)\n"
            "  sniff patch ?<ref|sha>      weave-merge the given ref/sha\n"
            "                              into the wt via graf\n"
            "  sniff status                list mtime-dirty files\n"
            "  sniff [--tlv] ls:[<URI>]    view projector (VERBS.md §View\n"
            "                              projectors); verb-less; --tlv\n"
            "                              emits HUNK TLV for `bro`\n"
            "  sniff watch                 start inotify daemon (fork;\n"
            "                              pid at <wt>/.be/sniff.pid)\n"
            "                              emits `mod <path>` rows\n"
            "  sniff stop                  stop the watch daemon\n"
            "  sniff help                  this message\n"
            "\n"
            "  Change-set rules at post time:\n"
            "    explicit put/delete since last post wins;\n"
            "    otherwise mtime ∉ ULOG stamp-set ⇒ include (implicit);\n"
            "    missing files with explicit-delete OR in implicit mode ⇒ drop.\n"
            "\n"
            "  Flags:\n"
            "    -m <msg>       commit message (legacy; prefer trailing words)\n"
            "    --author <who> author string\n");
}

// --- Verb/flag tables exported for the CLI wrapper ---

char const *const SNIFF_VERBS[] = {
    "index", "update", "status", "checkout",
    "commit", "watch", "stop", "help",
    "get", "post", "put", "delete", "patch", NULL
};

char const SNIFF_VAL_FLAGS[] =
    "-m\0--author\0--at\0";

// --- Entry: run the parsed CLI against the open state ---

ok64 SNIFFExec(cli *c) {
    sane(c);

    u8cs reporoot = {};
    if (!u8bHasData(c->repo)) fail(SNIFFFAIL);
    u8csMv(reporoot, $path(c->repo));

    a_cstr(v_help, "help");
    a_cstr(v_update, "update");
    a_cstr(v_status, "status");
    a_cstr(v_checkout, "checkout");
    a_cstr(v_commit, "commit");
    a_cstr(v_watch, "watch");
    a_cstr(v_stop, "stop");
    a_cstr(v_get, "get");
    a_cstr(v_post, "post");
    a_cstr(v_put, "put");
    a_cstr(v_delete, "delete");
    a_cstr(v_patch, "patch");

    if ($eq(c->verb, v_help) || CLIHas(c, "-h") || CLIHas(c, "--help")) {
        sniff_usage(); done;
    }

    if ($eq(c->verb, v_stop)) {
        call(sniff_stop, reporoot); done;
    }

    b8 is_checkout = $eq(c->verb, v_checkout) || $eq(c->verb, v_get);
    b8 is_post = $eq(c->verb, v_post) || $eq(c->verb, v_commit);
    b8 is_put = $eq(c->verb, v_put);
    b8 is_update = $eq(c->verb, v_update);
    b8 is_watch = $eq(c->verb, v_watch);
    //  Bare `sniff` (no verb, no URI, no `--status` flag) defaults
    //  to status — same overview an interactive user expects.  Any
    //  URI or projector still routes through their own arms below.
    b8 is_status = $eq(c->verb, v_status)
                || CLIHas(c, "--status")
                || ($empty(c->verb) && c->nuris == 0);

    //  Verb-less projector invocation (VERBS.md §"View projectors"):
    //  `sniff <proj>:<URI>` — no verb.  Scheme selects the projector;
    //  dog/DOG.c owns the scheme→dog table so we dispatch only when
    //  the URI's scheme resolves to this dog ("sniff").  Only `ls:`
    //  today; the branch is widened row-by-row in DOG_PROJECTORS.
    b8 is_projector = NO;
    uri *proj_u = NULL;
    if ($empty(c->verb) && c->nuris > 0) {
        uri *pu = &c->uris[0];
        char const *dog = DOGProjectorDog(pu->scheme);
        if (dog != NULL && strcmp(dog, "sniff") == 0) {
            is_projector = YES;
            proj_u = pu;
        }
    }
    b8 is_delete = $eq(c->verb, v_delete);
    b8 is_patch = $eq(c->verb, v_patch);

    ok64 ret = OK;

    if (is_post) {
        u8cs commit_msg = {};
        //  Per VERBS.md: free-form trailing words are folded into a
        //  URI's #fragment by CLIParse.  Prefer that over the legacy
        //  `-m <msg>` flag, which still works for backwards compat.
        for (u32 i = 0; i < c->nuris; i++) {
            if (!u8csEmpty(c->uris[i].fragment)) {
                $mv(commit_msg, c->uris[i].fragment);
                break;
            }
        }
        if (!$ok(commit_msg)) CLIFlag(commit_msg, c, "-m");
        u8cs commit_author = {};
        CLIFlag(commit_author, c, "--author");
        //  Default identity: assemble `<name> <<email>>` from the wt's
        //  `<root>/.be/config` (TOML — `[user] name = "..." email =
        //  "..."`).  Falls back to the legacy sniff sentinel only when
        //  config has neither field (test fixtures without a seeded
        //  identity).
        a_pad(u8, author_buf, 512);
        a_pad(u8, name_buf,   256);
        a_pad(u8, email_buf,  256);
        if (!$ok(commit_author)) {
            a_cstr(user_s,  "user");
            a_cstr(name_s,  "name");
            a_cstr(email_s, "email");
            a_path(name_p,  user_s, name_s);
            a_path(email_p, user_s, email_s);
            u8 *n_start = u8bIdleHead(name_buf);
            u8 *e_start = u8bIdleHead(email_buf);
            u8s ndst = {n_start, name_buf[3]};
            u8s edst = {e_start, email_buf[3]};
            (void)HOMEGetConfig(SNIFF.h, ndst, $path(name_p));
            (void)HOMEGetConfig(SNIFF.h, edst, $path(email_p));
            //  HOMEGetConfig advances ndst[0] / edst[0] past the
            //  bytes it wrote; the value lives in [start, ndst[0]).
            u8cs name  = {n_start, ndst[0]};
            u8cs email = {e_start, edst[0]};
            if ($empty(name) && $empty(email)) {
                a_cstr(def, "sniff <sniff@dogs>");
                u8bFeed(author_buf, def);
            } else {
                if (!$empty(name)) {
                    u8bFeed(author_buf, name);
                    u8bFeed1(author_buf, ' ');
                }
                u8bFeed1(author_buf, '<');
                if (!$empty(email)) u8bFeed(author_buf, email);
                u8bFeed1(author_buf, '>');
            }
            commit_author[0] = u8bDataHead(author_buf);
            commit_author[1] = u8bIdleHead(author_buf);
        }

        //  Pick the first URI with a non-empty query as a label target
        //  (e.g. `?heads/main`, `?tags/v0.0.1`).
        uri *label_uri = NULL;
        for (u32 i = 0; i < c->nuris; i++)
            if (!$empty(c->uris[i].query)) { label_uri = &c->uris[i]; break; }

        //  VERBS.md §"POST" remote arm: `be post //origin` resolves
        //  the authority against the local ref log (REFSResolve does
        //  authority-substring match — see keeper/REFS.c:391) and
        //  rebases cur onto the tracking ref's sha.  No alias
        //  registry; the most recent matching get/put row's URI is
        //  the connection target and its hash is the rebase tip.
        //  Skip this arm if a regular ?branch was supplied (label_uri
        //  != NULL) — that takes precedence.
        sha1 remote_target_tip = {};
        b8   has_remote_target = NO;
        if (label_uri == NULL && !$ok(commit_msg)) {
            for (u32 i = 0; i < c->nuris; i++) {
                uri *uu = &c->uris[i];
                if (u8csEmpty(uu->authority)) continue;
                if (!u8csEmpty(uu->query))    continue;
                a_path(keepdir, reporoot, KEEP_DIR_S);
                a_pad(u8, arena, 1024);
                uri resolved = {};
                a_dup(u8c, in_uri, uu->data);
                if (REFSResolve(&resolved, arena, $path(keepdir),
                                in_uri) != OK) {
                    fprintf(stderr,
                            "sniff: post: %.*s — no matching tracking "
                            "ref in log; run `be head ssh://...` first\n",
                            (int)u8csLen(uu->data),
                            (char *)uu->data[0]);
                    ret = SNIFFFAIL;
                    break;
                }
                u8cs sha_hex = {resolved.query[0], resolved.query[1]};
                if (!u8csEmpty(sha_hex) && *sha_hex[0] == '?')
                    u8csUsed(sha_hex, 1);
                if (u8csLen(sha_hex) != sizeof(sha1hex)) {
                    fprintf(stderr,
                            "sniff: post: tracking row for %.*s has "
                            "no sha\n",
                            (int)u8csLen(uu->data),
                            (char *)uu->data[0]);
                    ret = SNIFFFAIL;
                    break;
                }
                a_raw(bin, remote_target_tip);
                a_dup(u8c, hx, sha_hex);
                if (HEXu8sDrainSome(bin, hx) != OK) {
                    ret = SNIFFFAIL;
                    break;
                }
                has_remote_target = YES;
                break;
            }
        }
        if (ret == OK && has_remote_target) {
            ret = POSTRebaseOntoSha(reporoot, &remote_target_tip);
            //  Fall through to the standard close (no commit_msg /
            //  label_uri path runs).  Use a sentinel to skip the
            //  dry-run-status arm.
            goto post_done;
        }

        //  Resolve a relative label (`?./X`, `?../X`, `?..`) before
        //  POSTSetLabel sees it.  Buffers must outlive POSTSetLabel —
        //  hence stack-local pads scoped to this if-block.
        a_pad(u8, label_qbuf,    256);
        a_pad(u8, label_databuf, 260);
        if (label_uri != NULL) {
            if (sniff_resolve_rel(label_uri, label_qbuf, label_databuf,
                                  NULL) != OK) {
                ret = SNIFFFAIL;
            }
        }

        if (!$ok(commit_msg) && label_uri == NULL) {
            //  Bare `sniff post` (no -m, no ?label).  When patch rows
            //  are present since the latest get/post, compose default
            //  msg+author from the absorbed commits and commit; else
            //  fall back to dry-run status so the user sees what the
            //  next non-bare post would produce.
            a_pad(u8, def_msg_buf,  1024);
            a_pad(u8, def_auth_buf, 512);
            u8cs def_msg  = {};
            u8cs def_auth = {};
            u32  def_n    = 0;
            ok64 dr = POSTPatchDefaults(reporoot,
                                        def_msg_buf,  &def_msg,
                                        def_auth_buf, &def_auth,
                                        &def_n);
            if (dr == OK && def_n > 0) {
                u8cs no_target = {};
                sha1 sha = {};
                ret = POSTCommit(reporoot, no_target,
                                 def_msg, def_auth, c, &sha);
                if (ret == OK) {
                    a_pad(u8, hex, 40);
                    a_rawc(rs, sha);
                    HEXu8sFeedSome(hex_idle, rs);
                    fprintf(stderr, "sniff: commit %.*s\n",
                            (int)u8bDataLen(hex),
                            (char *)u8bDataHead(hex));
                }
            } else if (def_n > 0) {
                //  Patch rows in scope but msg can't be auto-resolved
                //  (zero or >1 usable msgs).  Refuse per VERBS.md §POST
                //  message-resolution; user must supply `#msg`.
                fprintf(stderr,
                    "sniff: post: cannot auto-resolve commit msg "
                    "from %u patch row(s); supply `#msg`\n", def_n);
                ret = POSTNOMSG;
            } else {
                ret = POSTPrintStatus(reporoot);
            }
        } else {
            //  POSTCommit does its own wt scan + change-set resolve;
            //  no pre-pass needed anymore.
            a_pad(u8, hex, 40);
            if ($ok(commit_msg)) {
                //  Cross-branch POST: when a label_uri is present,
                //  its query is the *commit target*.  POSTCommit
                //  lands the new commit on that branch (instead of
                //  the wt's baseline branch); the wt's other branch
                //  is left untouched in REFS, and `.be/wtlog` resets
                //  to (target, new_tip).  No separate POSTSetLabel
                //  pass — that was the old "label both branches at
                //  the same sha" behaviour, replaced here.
                u8cs target = {};
                if (label_uri != NULL) {
                    target[0] = label_uri->query[0];
                    target[1] = label_uri->query[1];
                }
                sha1 sha = {};
                ret = POSTCommit(reporoot, target,
                                 commit_msg, commit_author, c, &sha);
                if (ret == OK) {
                    a_rawc(rs, sha);
                    HEXu8sFeedSome(hex_idle, rs);
                }
            } else if (label_uri != NULL) {
                //  No commit_msg + label_uri: rebase cur onto
                //  `label_uri.tip` (VERBS.md §POST: "Rebase cur onto
                //  `?br.tip`.  Cur's stack replays from `?br.tip`;
                //  no new commit").  Cur is the only ref POST moves;
                //  the label_uri side is read-only.
                a_path(keepdir, reporoot, KEEP_DIR_S);
                a_pad(u8, arena, 1024);
                uri resolved = {};
                a_dup(u8c, lbl_in, label_uri->data);
                if (REFSResolve(&resolved, arena, $path(keepdir),
                                lbl_in) != OK ||
                    u8csEmpty(resolved.query)) {
                    fprintf(stderr,
                            "sniff: post: %.*s — no such ref in log\n",
                            (int)u8csLen(label_uri->data),
                            (char *)label_uri->data[0]);
                    ret = SNIFFFAIL;
                } else {
                    u8cs sha_hex = {resolved.query[0], resolved.query[1]};
                    if (!u8csEmpty(sha_hex) && *sha_hex[0] == '?')
                        u8csUsed(sha_hex, 1);
                    if (u8csLen(sha_hex) != sizeof(sha1hex)) {
                        fprintf(stderr,
                                "sniff: post: ref row for %.*s has "
                                "no sha\n",
                                (int)u8csLen(label_uri->data),
                                (char *)label_uri->data[0]);
                        ret = SNIFFFAIL;
                    } else {
                        sha1 target_tip = {};
                        a_raw(bin, target_tip);
                        a_dup(u8c, hx, sha_hex);
                        if (HEXu8sDrainSome(bin, hx) != OK) {
                            ret = SNIFFFAIL;
                        } else {
                            //  Cross-branch rebase: load target's
                            //  shard so graf/keeper see its history.
                            //  The branch comes from the user's
                            //  `?<branch>` query (stripped of any
                            //  trailing-hashlet pin per
                            //  dog/DOG.h §DOGRefSplitPin).
                            u8cs br_split = {}, pin_split = {};
                            DOGRefSplitPin(label_uri->query,
                                           br_split, pin_split);
                            u8cs t_br = {};
                            if (u8csEmpty(pin_split))
                                u8csMv(t_br, label_uri->query);
                            else
                                u8csMv(t_br, br_split);
                            (void)SNIFFMaybeSwitchKeeper(t_br);
                            (void)SNIFFMaybeSwitchGraf(t_br);
                            ret = POSTRebaseOntoSha(reporoot,
                                                    &target_tip);
                        }
                    }
                }
            }
        }
post_done:
        ;
    } else if (is_put) {
        //  Split URIs by aspect (VERBS.md §PUT):
        //    * `?branch` (query, no path) → POSTCreateBranch (create
        //      label at cur.tip; refuses with PUTDUP if exists).
        //    * `./path` / bare path       → PUTStage (stage file/dir).
        //  Mixed invocations process each in arrival order; first
        //  failure aborts.
        uri path_uris[CLI_MAX_URIS] = {};
        u32 npath = 0;
        for (u32 i = 0; i < c->nuris && ret == OK; i++) {
            uri u = c->uris[i];
            b8 has_q = !u8csEmpty(u.query);
            b8 has_path = !u8csEmpty(u.path);
            if (has_q && !has_path && u8csEmpty(u.authority)) {
                a_pad(u8, abs_qbuf,    256);
                a_pad(u8, abs_databuf, 260);
                if (sniff_resolve_rel(&u, abs_qbuf, abs_databuf,
                                      NULL) != OK) {
                    ret = SNIFFFAIL;
                    break;
                }
                a_dup(u8c, target, u.query);
                ret = POSTCreateBranch(reporoot, target);
                continue;
            }
            //  Path / bare — defer to PUTStage.
            if (npath < CLI_MAX_URIS) path_uris[npath++] = u;
        }
        if (ret == OK && (npath > 0 || c->nuris == 0)) {
            //  PUT.c prints its own staged-row count.
            ret = PUTStage(npath, path_uris);
        }
    } else if (is_delete) {
        //  Two URI shapes:
        //    * branch-form (`?branch`) — drop the label via REFS
        //      tombstone; safety-checked by DELBranch.
        //    * path-form (`<file>`)    — stage a file removal.
        //  Bare `sniff delete` (no URIs) is the legacy "sweep
        //  missing tracked files" path; route through DELStage.
        //
        //  Path-forms are batched into ONE DELStage call so the
        //  trailing summary line appears once for the whole
        //  invocation; branch-forms each go through DELBranch
        //  individually (independent ref ops).
        if (c->nuris == 0) {
            ret = DELStage(0, NULL);
        } else {
            uri path_uris[CLI_MAX_URIS];
            u32 npath = 0;
            for (u32 i = 0; i < c->nuris && ret == OK; i++) {
                uri *u = &c->uris[i];
                //  Branch-form is signalled by a literal leading `?`
                //  in the original token (u->data).  Bare tokens like
                //  `a.txt` also land in u->query via DOGNormalizeArg
                //  but their data has no `?` sigil — those are path-
                //  form deletes.
                b8 branch_form = !$empty(u->data) && u->data[0][0] == '?';
                if (branch_form) {
                    a_pad(u8, del_qbuf,    256);
                    a_pad(u8, del_databuf, 260);
                    if (sniff_resolve_rel(u, del_qbuf, del_databuf,
                                          NULL) != OK) {
                        ret = SNIFFFAIL; break;
                    }
                    b8 recursive = CLIHas(c, "-r") || CLIHas(c, "--force");
                    ret = DELBranch(u, recursive);
                } else {
                    if (npath < CLI_MAX_URIS) path_uris[npath++] = *u;
                }
            }
            if (ret == OK && npath > 0)
                ret = DELStage(npath, path_uris);
        }
    } else if (is_checkout) {
        if (c->nuris < 1) {
            if ($eq(c->verb, v_get)) {
                ret = sniff_get_summary(reporoot);
            } else {
                fprintf(stderr,
                    "sniff: checkout requires a URI or hex\n");
                ret = SNIFFFAIL;
            }
        } else {
            uri *u = &c->uris[0];
            if ($eq(c->verb, v_get)) {
                ret = SNIFFGetURI(reporoot, u);
            } else {
                u8cs hex = {};
                if (!$empty(u->path))
                    u8csMv(hex, u->path);
                else
                    u8csMv(hex, u->data);
                ret = sniff_checkout(reporoot, hex);
            }
        }
    } else if (is_patch) {
        if (c->nuris < 1) {
            fprintf(stderr,
                "sniff: patch requires a URI (query = ref or sha)\n");
            ret = SNIFFFAIL;
        } else {
            uri *u = &c->uris[0];
            //  Coalesce trailing fragment-only URIs (typical
            //  `be patch ?feat '#merge msg'` shape — argv lexer puts
            //  msg into uris[1] as a fragment-only URI).  Merge that
            //  fragment back into uris[0] so PATCHApply sees one URI
            //  with the full shape.
            for (u32 i = 1; i < c->nuris; i++) {
                uri *u2 = &c->uris[i];
                if (u2->fragment[0] != NULL && u->fragment[0] == NULL) {
                    $mv(u->fragment, u2->fragment);
                }
            }
            //  Accept `path?query` for single-file merge, bare
            //  `?query` (with optional `#hash` clamp) for whole-wt
            //  merge, or bare `#hash` for single-commit cherry-pick.
            if (!$empty(u->path) && !$empty(u->query)) {
                a_dup(u8c, path,  u->path);
                a_dup(u8c, query, u->query);
                a_dup(u8c, frag,  u->fragment);
                ret = PATCHApplyFile(reporoot, path, query, frag);
            } else if ((u->query[0] != NULL) ||
                       (u->fragment[0] != NULL)) {
                //  Pass the URI directly so the present-empty
                //  fragment marker (`?br#` rebase-one shape)
                //  survives.  PATCHApply classifies via PATCHShape
                //  and writes the appropriate row variant.
                ret = PATCHApply(reporoot, u);
            } else {
                fprintf(stderr,
                    "sniff: patch URI must have `?<ref|sha>` "
                    "or `#<sha>`\n");
                ret = SNIFFFAIL;
            }
        }
    } else if (is_watch) {
        ret = sniff_daemon(reporoot);
    } else if (is_status) {
        ret = sniff_status(reporoot);
    } else if (is_projector) {
        //  URI scheme picks the projector; `--tlv` switches the
        //  emitter from HUNKu8sFeedText to HUNKu8sFeed.
        b8 tlv = CLIHas(c, "--tlv");
        a_cstr(ls_s, "ls");
        if ($eq(proj_u->scheme, ls_s)) {
            ret = SNIFFLs(reporoot, proj_u, tlv);
        } else {
            //  Table says sniff owns this scheme but we don't have a
            //  handler wired — should not happen once DOG_PROJECTORS
            //  and this switch are kept in sync.  Fail loudly.
            fprintf(stderr, "sniff: projector '%.*s:' not implemented\n",
                    (int)$len(proj_u->scheme), (char *)proj_u->scheme[0]);
            ret = SNIFFFAIL;
        }
    } else if (is_update) {
        //  No per-path mtime cache in the new model; `update` is a no-op.
        //  Left in the verb table so existing scripts don't break.
        ret = OK;
    } else {
        // Default: index (no-op in the new model; retained for script compat).
        ret = OK;
    }

    return ret;
}
