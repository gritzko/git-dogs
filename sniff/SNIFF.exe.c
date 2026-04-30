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
#include "DEL.h"
#include "GET.h"
#include "LS.h"
#include "PATCH.h"
#include "POST.h"
#include "PUT.h"
#include "dog/AT.h"
#include "dog/CLI.h"
#include "dog/QURY.h"
#include "dog/DOG.h"
#include "dog/HOME.h"
#include "dog/IGNO.h"
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
    a_path(pp, reporoot);
    a_cstr(rel, "/" SNIFF_FILE ".pid");
    call(u8bFeed, pp, rel);
    call(PATHu8bTerm, pp);
    FILE *fp = fopen((char *)u8bDataHead(pp), "w");
    if (!fp) fail(SNIFFFAIL);
    fprintf(fp, "%d\n", (int)getpid());
    fclose(fp);
    done;
}

static ok64 sniff_rm_pid(u8cs reporoot) {
    sane($ok(reporoot));
    a_path(pp, reporoot);
    a_cstr(rel, "/" SNIFF_FILE ".pid");
    call(u8bFeed, pp, rel);
    call(PATHu8bTerm, pp);
    unlink((char *)u8bDataHead(pp));
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
//  containing dirty files (mtime ∉ stamp set).  Dedup is via .sniff
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
static void watch_parent_dir(u8cs rel, Bu8 out) {
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

//  Seed `*seen` from the .sniff log: every `mod <dir/>` row whose ts
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
    if (!SNIFFRelFromFull(&rel, w->reporoot, full)) return OK;
    if (SNIFFSkipMeta(rel))                         return OK;

    //  Skip the daemon's own pidfile — we don't log ourselves.
    {
        a_cstr(d_pid, ".sniff.pid");
        if ($len(rel) == $len(d_pid) &&
            memcmp(rel[0], d_pid[0], $len(d_pid)) == 0) return OK;
    }

    struct stat sb = {};
    if (lstat((char const *)full[0], &sb) != 0) return OK;
    struct timespec ts = {.tv_sec = sb.st_mtim.tv_sec,
                          .tv_nsec = sb.st_mtim.tv_nsec};
    ron60 mtime = SNIFFAtOfTimespec(ts);

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
    //  Rebuild the seen set from .sniff each scan — the baseline may
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
    a_path(pp, reporoot);
    a_cstr(rel, "/" SNIFF_FILE ".pid");
    call(u8bFeed, pp, rel);
    call(PATHu8bTerm, pp);
    FILE *fp = fopen((char *)u8bDataHead(pp), "r");
    if (!fp) { fprintf(stderr, "sniff: no daemon running\n"); done; }
    int dpid = 0;
    if (fscanf(fp, "%d", &dpid) != 1 || dpid <= 0) {
        fclose(fp); fail(SNIFFFAIL);
    }
    fclose(fp);
    if (kill(dpid, SIGTERM) != 0) {
        unlink((char *)u8bDataHead(pp)); fail(SNIFFFAIL);
    }
    fprintf(stderr, "sniff: stopped pid %d\n", dpid);
    unlink((char *)u8bDataHead(pp));
    done;
}

// --- Mode: Status ---
//
//  Bare `sniff` — overview of the working tree.  Walks the wt with
//  the standard IGNO + meta-skip filter (`SNIFFAtScanDirty`), then
//  classifies each hit against the baseline tree and prints one row
//  per file, status-first, path-second:
//
//    M  <path>     in baseline tree, mtime ∉ stamp-set (modified)
//    ?? <path>     not in baseline tree (untracked, not gitignored)
//
//  When stdout is a terminal each marker is colourised — yellow for
//  M, red for ?? — so the eye picks out status before path.  Submodule
//  paths (and anything under them) are skipped entirely; gitlinks are
//  handed off to the embedded repo by design.

#define STATUS_ANSI_M   "\033[33m"   // yellow  — modified
#define STATUS_ANSI_U   "\033[31m"   // red     — untracked
#define STATUS_ANSI_OFF "\033[0m"

//  Tracked-set: newline-separated paths from the baseline tree, plus
//  a parallel list of submodule directory prefixes (each ends with
//  '/').  Tiny in typical repos so a linear membership check is fine.

typedef struct {
    Bu8 paths;     // every tracked file path (no submodule contents)
    Bu8 subdirs;   // submodule dir prefixes, each '/'-terminated
    u32 count;
    u32 nsubs;
} status_tracked;

static ok64 status_collect_tracked(u8cs path, u8 kind, u8cp esha,
                                   u8cs blob, void0p vctx) {
    (void)esha; (void)blob;
    status_tracked *t = (status_tracked *)vctx;
    if ($empty(path)) return OK;
    if (kind == WALK_KIND_DIR) return OK;     //  trees handled by recursion
    if (kind == WALK_KIND_SUB) {
        //  Record the submodule's mount path so wt-scan hits under
        //  it can be filtered out.  Append a trailing '/' for prefix
        //  comparison.
        (void)u8bFeed(t->subdirs, path);
        (void)u8bFeed1(t->subdirs, '/');
        (void)u8bFeed1(t->subdirs, '\n');
        t->nsubs++;
        return OK;
    }
    (void)u8bFeed(t->paths, path);
    (void)u8bFeed1(t->paths, '\n');
    t->count++;
    return OK;
}

static b8 status_tracked_has(status_tracked const *t, u8cs path) {
    if (t->count == 0) return NO;
    u8cs scan = {u8bDataHead(t->paths), u8bIdleHead(t->paths)};
    while (!$empty(scan)) {
        u8cp nl = scan[0];
        while (nl < scan[1] && *nl != '\n') nl++;
        if ((size_t)(nl - scan[0]) == (size_t)$len(path) &&
            memcmp(scan[0], path[0], (size_t)$len(path)) == 0)
            return YES;
        scan[0] = (nl < scan[1]) ? nl + 1 : scan[1];
    }
    return NO;
}

//  YES iff `path` lies inside any recorded submodule prefix (matched
//  as `<prefix>/` against the path's leading bytes).
static b8 status_in_submodule(status_tracked const *t, u8cs path) {
    if (t->nsubs == 0) return NO;
    u8cs scan = {u8bDataHead(t->subdirs), u8bIdleHead(t->subdirs)};
    size_t pl = (size_t)$len(path);
    while (!$empty(scan)) {
        u8cp nl = scan[0];
        while (nl < scan[1] && *nl != '\n') nl++;
        size_t prl = (size_t)(nl - scan[0]);
        if (prl > 0 && prl <= pl &&
            memcmp(scan[0], path[0], prl) == 0)
            return YES;
        scan[0] = (nl < scan[1]) ? nl + 1 : scan[1];
    }
    return NO;
}

//  Resolve baseline tree-sha from sniff's at-log.  ULOGNONE on a
//  fresh log; on OK the 20-byte tree sha lands in *out.  Mirrors
//  PUT.c put_baseline_tree (kept local to avoid exposing internals).
static ok64 status_baseline_tree(sha1 *out) {
    sane(out);
    ron60 ts = 0, verb = 0;
    uri u = {};
    ok64 br = SNIFFAtBaseline(&ts, &verb, &u);
    if (br != OK) return br;
    u8 hex40[40];
    if (SNIFFAtQueryFirstSha(&u, hex40) != OK) return ULOGNONE;

    sha1 commit_sha = {};
    a_raw(csha_bin, commit_sha);
    u8cs h40 = {hex40, hex40 + 40};
    HEXu8sDrainSome(csha_bin, h40);

    Bu8 cbuf = {};
    call(u8bAllocate, cbuf, 1UL << 20);
    u8 ctype = 0;
    ok64 go = KEEPGetExact(&KEEP, &commit_sha, cbuf, &ctype);
    if (go != OK || ctype != DOG_OBJ_COMMIT) {
        u8bFree(cbuf);
        return ULOGNONE;
    }
    u8cs body = {u8bDataHead(cbuf), u8bIdleHead(cbuf)};
    ok64 to = GITu8sCommitTree(body, out->data);
    u8bFree(cbuf);
    return to;
}

typedef struct {
    status_tracked *tracked;
    Bu8 changed_buf;     //  paths only (newline-terminated), per group
    Bu8 untracked_buf;
    u32 changed_n;
    u32 untracked_n;
    u32 sub_skipped;     //  rows under a submodule (silent)
} status_split;

static ok64 status_split_cb(u8cs rel, void *ctx_) {
    status_split *s = (status_split *)ctx_;
    if (status_in_submodule(s->tracked, rel)) {
        s->sub_skipped++;
        return OK;
    }
    if (status_tracked_has(s->tracked, rel)) {
        (void)u8bFeed(s->changed_buf, rel);
        (void)u8bFeed1(s->changed_buf, '\n');
        s->changed_n++;
    } else {
        (void)u8bFeed(s->untracked_buf, rel);
        (void)u8bFeed1(s->untracked_buf, '\n');
        s->untracked_n++;
    }
    return OK;
}

//  Walk a newline-terminated path buffer, emitting one row per path
//  prefixed with `marker` (2 chars) and a trailing space.  When `tty`
//  is YES the marker is wrapped in ANSI colour escapes so status
//  pops out visually; on a pipe / non-tty stdout we stay plain.
static void status_dump_rows(Bu8 paths, char const *marker,
                             char const *ansi, b8 tty) {
    a_dup(u8c, b, u8bData(paths));
    u8cs scan = {b[0], b[1]};
    while (!$empty(scan)) {
        u8cp nl = scan[0];
        while (nl < scan[1] && *nl != '\n') nl++;
        if (tty) fputs(ansi, stdout);
        fputs(marker, stdout);
        if (tty) fputs(STATUS_ANSI_OFF, stdout);
        fputc(' ', stdout);
        fwrite(scan[0], 1, (size_t)(nl - scan[0]), stdout);
        fputc('\n', stdout);
        scan[0] = (nl < scan[1]) ? nl + 1 : scan[1];
    }
}

static ok64 sniff_status(u8cs reporoot) {
    sane(1);

    //  Build the tracked-set from the baseline tree.  Empty / no-baseline
    //  → tracked stays empty, so everything dirty surfaces as Untracked
    //  (which matches `git status` on a fresh repo).
    status_tracked tracked = {};
    call(u8bAllocate, tracked.paths,   1UL << 16);
    call(u8bAllocate, tracked.subdirs, 1UL << 12);
    sha1 tree_sha = {};
    ok64 bt = status_baseline_tree(&tree_sha);
    if (bt == OK) {
        (void)WALKTreeLazy(&KEEP, tree_sha.data,
                           status_collect_tracked, &tracked);
    }

    status_split split = {.tracked = &tracked};
    call(u8bAllocate, split.changed_buf,   1UL << 14);
    call(u8bAllocate, split.untracked_buf, 1UL << 14);

    call(SNIFFAtScanDirty, reporoot, status_split_cb, &split);

    b8 tty = isatty(STDOUT_FILENO) ? YES : NO;

    //  Modified rows first, then untracked — same order git-porcelain
    //  uses; readers scan top-down for "what's interesting".  Trailing
    //  summary on stdout (not stderr) so it stays in order with the
    //  list when piped — overview output isn't an error stream.
    if (split.changed_n > 0)
        status_dump_rows(split.changed_buf,   "M ",  STATUS_ANSI_M, tty);
    if (split.untracked_n > 0)
        status_dump_rows(split.untracked_buf, "??", STATUS_ANSI_U, tty);
    fprintf(stdout, "sniff: %u changed, %u untracked\n",
            split.changed_n, split.untracked_n);
    fflush(stdout);

    u8bFree(split.changed_buf);
    u8bFree(split.untracked_buf);
    u8bFree(tracked.paths);
    u8bFree(tracked.subdirs);
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
//  current branch from `.sniff` baseline and writes the absolute
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

static ok64 SNIFFGetURI(u8cs reporoot, uri *u) {
    sane(u);
    keeper *k = &KEEP;
    a_path(keepdir, u8bDataC(k->h->root), KEEP_DIR_S);

    //  Remote URI (`//host?ref`, `ssh://host/path?ref`, …): pull the
    //  reachable closure into the local keeper before resolving.  be
    //  no longer pre-fetches as a separate dispatch step — sniff is
    //  the verb owner and orchestrates downstream calls itself.
    if (!u8csEmpty(u->authority)) {
        call(KEEPGetRemote, u);
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
    //  current branch (from sniff's at.log) against the local trunk
    //  row `?#<sha>`.
    a_pad(u8, at_branch, 256);
    a_pad(u8, at_sha, 64);
    a_dup(u8c, at_root, reporoot);
    if (DOGAtTail(at_branch, at_sha, at_root) == OK &&
        u8bDataLen(at_branch) > 0) {
        a_pad(u8, qbuf, 256);
        u8bFeed1(qbuf, '?');
        u8bFeed(qbuf, u8bDataC(at_branch));
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
            "  sniff patch ?<ref|sha>      3-way merge the given ref/sha\n"
            "                              into the wt via graf\n"
            "  sniff status                list mtime-dirty files\n"
            "  sniff list                  list paths the registry knows\n"
            "  sniff [--tlv] ls:[<URI>]    view projector (VERBS.md §View\n"
            "                              projectors); verb-less; --tlv\n"
            "                              emits HUNK TLV for `bro`\n"
            "  sniff watch                 start inotify daemon (fork;\n"
            "                              pid at <wt>/.sniff.pid)\n"
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
    "-m\0--author\0";

// --- Entry: run the parsed CLI against the open state ---

ok64 SNIFFExec(cli *c) {
    sane(c);

    u8cs reporoot = {};
    if (!$ok(c->repo)) fail(SNIFFFAIL);
    $mv(reporoot, c->repo);

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
        //  `<root>/.dogs/config` (TOML — `[user] name = "..." email =
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
            //  Bare `sniff post` (no -m, no ?label) → dry run:
            //  list the change-set the next commit would produce
            //  without writing anything.
            ret = POSTPrintStatus(reporoot);
        } else {
            //  POSTCommit does its own wt scan + change-set resolve;
            //  no pre-pass needed anymore.
            a_pad(u8, hex, 40);
            if ($ok(commit_msg)) {
                //  Cross-branch POST: when a label_uri is present,
                //  its query is the *commit target*.  POSTCommit
                //  lands the new commit on that branch (instead of
                //  the wt's baseline branch); the wt's other branch
                //  is left untouched in REFS, and `.sniff` resets
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
                                 commit_msg, commit_author, &sha);
                if (ret == OK) {
                    a_rawc(rs, sha);
                    HEXu8sFeedSome(hex_idle, rs);
                }
            } else if (label_uri != NULL) {
                //  No commit_msg + label_uri = either:
                //    (a) cross-branch promote (`?..`, `?./fix`,
                //        `?<absolute>`, `?./newleaf`) per VERBS.md
                //        §POST — runs through POSTPromote;
                //    (b) legacy label-only op (target == cur) — point
                //        the URI's branch at the wt's current baseline
                //        sha via POSTSetLabel.
                //
                //  The dispatcher returns POSTNONE when the target IS
                //  cur, so we fall through to the legacy path then.
                u8cs target = {};
                target[0] = label_uri->query[0];
                target[1] = label_uri->query[1];
                ret = POSTPromote(reporoot, target);
                if (ret == POSTNONE) {
                    //  target == cur → legacy label-only behaviour.
                    ret = OK;
                    ron60 bts = 0, bverb = 0;
                    uri bu = {};
                    ret = SNIFFAtBaseline(&bts, &bverb, &bu);
                    u8 hex40[40];
                    if (ret == OK &&
                        SNIFFAtQueryFirstSha(&bu, hex40) == OK) {
                        u8cs h40 = {hex40, hex40 + 40};
                        u8bFeed(hex, h40);
                        a_dup(u8c, hex_in, u8bData(hex));
                        a_dup(u8c, ref_uri, label_uri->data);
                        ret = POSTSetLabel(ref_uri, hex_in);
                        if (ret == OK)
                            fprintf(stderr,
                                    "sniff: label %.*s -> %.*s\n",
                                    (int)u8csLen(ref_uri),
                                    (char *)ref_uri[0],
                                    (int)u8bDataLen(hex),
                                    (char *)u8bDataHead(hex));
                    } else {
                        ret = SNIFFFAIL;
                    }
                }
            }
        }
    } else if (is_put) {
        //  PUT.c prints its own staged-row count (it's the only path
        //  that knows how many input URIs survived dedup / validation).
        ret = PUTStage(c->nuris, c->uris);
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
                    ret = DELBranch(u);
                } else {
                    if (npath < CLI_MAX_URIS) path_uris[npath++] = *u;
                }
            }
            if (ret == OK && npath > 0)
                ret = DELStage(npath, path_uris);
        }
    } else if (is_checkout) {
        if (c->nuris < 1) {
            fprintf(stderr, "sniff: get/checkout requires a URI or hex\n");
            ret = SNIFFFAIL;
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
            //  Accept `path?query` for single-file merge OR bare
            //  `?query` for whole-wt merge.
            if (!$empty(u->path) && !$empty(u->query)) {
                a_dup(u8c, path, u->path);
                a_dup(u8c, query, u->query);
                ret = PATCHApplyFile(reporoot, path, query);
            } else if (!$empty(u->query)) {
                a_dup(u8c, query, u->query);
                ret = PATCHApply(reporoot, query);
            } else {
                fprintf(stderr,
                    "sniff: patch URI must have `?<ref|sha>`\n");
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
