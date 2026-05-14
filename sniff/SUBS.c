//  SUBS — submodule plumbing.  See SUBS.h.

#include "SUBS.h"

#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "abc/FILE.h"
#include "abc/PATH.h"
#include "abc/PRO.h"
#include "abc/RON.h"
#include "abc/URI.h"
#include "dog/HOME.h"
#include "keeper/KEEP.h"
#include "keeper/WIRE.h"

#include "AT.h"
#include "SNIFF.h"

// --- helpers ----------------------------------------------------------

//  Drop ASCII whitespace from both ends of `s` in place.  Whitespace
//  is space, tab, CR, LF.  Acts on a u8cs in-place by moving its head
//  and term.
static void subs_strip(u8cs s) {
    while (!u8csEmpty(s)) {
        u8c c = *s[0];
        if (c != ' ' && c != '\t' && c != '\r') break;
        u8csUsed1(s);
    }
    while (!u8csEmpty(s)) {
        u8c c = *(s[1] - 1);
        if (c != ' ' && c != '\t' && c != '\r') break;
        u8csShed1(s);
    }
}

//  YES iff a == b (byte-exact).
static b8 subs_eq(u8cs a, u8cs b) {
    if (u8csLen(a) != u8csLen(b)) return NO;
    if (u8csLen(a) == 0) return YES;
    return memcmp(a[0], b[0], u8csLen(a)) == 0;
}

//  Find the last byte equal to `v` in `s`.  On hit, `out[0]=p, out[1]=s.term`.
//  Returns NO on miss.
static b8 subs_rfind(u8cs s, u8c v, u8csp out) {
    u8c const *hit = NULL;
    $for(u8c, p, s) if (*p == v) hit = p;
    if (!hit) return NO;
    out[0] = hit;
    out[1] = s[1];
    return YES;
}

// --- SubBasename ------------------------------------------------------

ok64 SNIFFSubBasename(u8cs url, u8csp out) {
    if (u8csEmpty(url)) return SUBSPARSE;

    a_dup(u8c, work, url);

    //  Strip scheme `<word>://` if present.
    {
        a_dup(u8c, scan, work);
        u8c const *colon = NULL;
        $for(u8c, p, scan) if (*p == ':') { colon = p; break; }
        if (colon && colon + 2 < scan[1] &&
            colon[1] == '/' && colon[2] == '/') {
            work[0] = colon + 3;
        }
    }

    //  `git@host:path` (no scheme): cut at ':'.
    {
        a_dup(u8c, scan, work);
        u8c const *colon = NULL;
        $for(u8c, p, scan) {
            if (*p == ':') { colon = p; break; }
            if (*p == '/') break;
        }
        if (colon) work[0] = colon + 1;
    }

    //  Strip trailing '/' so the last segment is non-empty when the
    //  URL ended on a slash (e.g. `…/widgets/`).
    while (!u8csEmpty(work) && *(work[1] - 1) == '/')
        u8csShed1(work);

    //  Last '/' segment is the basename candidate.
    u8cs base = {};
    u8cs tail = {};
    if (subs_rfind(work, '/', tail)) {
        base[0] = tail[0] + 1;
        base[1] = work[1];
    } else {
        u8csMv(base, work);
    }

    //  Strip trailing ".git".  Strip even if the result becomes empty
    //  (`.git` URL); the empty check below rejects that case.
    if (u8csLen(base) >= 4) {
        u8c const *suf = base[1] - 4;
        if (suf[0] == '.' && suf[1] == 'g' && suf[2] == 'i' && suf[3] == 't')
            for (int i = 0; i < 4; i++) u8csShed1(base);
    }

    if (u8csEmpty(base)) return SUBSPARSE;
    u8csMv(out, base);
    return OK;
}

// --- SubsParse --------------------------------------------------------

typedef struct {
    u8cs path;
    u8cs url;
    b8   in_submod;   // YES while inside a `[submodule "…"]` section
} subs_state;

static ok64 subs_flush(subs_state *st, sniff_subs_cb cb, void *ctx) {
    if (!st->in_submod) return OK;
    if (u8csEmpty(st->path) || u8csEmpty(st->url)) {
        //  Section missing path or url → silently skip.
        st->in_submod = NO;
        u8csMv(st->path, ((u8cs){}));
        u8csMv(st->url,  ((u8cs){}));
        return OK;
    }
    ok64 o = cb(st->path, st->url, ctx);
    st->in_submod = NO;
    u8csMv(st->path, ((u8cs){}));
    u8csMv(st->url,  ((u8cs){}));
    return o;
}

ok64 SNIFFSubsParse(u8cs blob, sniff_subs_cb cb, void *ctx) {
    sane(cb);
    subs_state st = {};

    a_dup(u8c, scan, blob);
    for (;;) {
        u8cs line = {};
        if (u8csDrainLine(scan, line) != OK) break;

        //  Strip trailing whitespace / CR.
        subs_strip(line);
        if (u8csEmpty(line)) continue;

        //  Comments.
        if (*line[0] == '#' || *line[0] == ';') continue;

        //  Section header: `[submodule "<name>"]` or any other.  We
        //  only care whether it's a submodule section; the name is
        //  cosmetic (the `path` key is authoritative).
        if (*line[0] == '[') {
            ok64 o = subs_flush(&st, cb, ctx);
            if (o != OK) return o;

            //  Need a closing ']'.
            if (*(line[1] - 1) != ']') return SUBSPARSE;
            //  Inside brackets, strip first '[' and last ']'.
            u8cs hdr = {line[0] + 1, line[1] - 1};
            subs_strip(hdr);

            //  Match leading `submodule` keyword.
            static u8c const kw[] = "submodule";
            u8cs kws = {(u8c *)kw, (u8c *)kw + 9};
            if (u8csLen(hdr) >= 9 &&
                memcmp(hdr[0], kws[0], 9) == 0 &&
                (u8csLen(hdr) == 9 ||
                 hdr[0][9] == ' ' || hdr[0][9] == '\t' ||
                 hdr[0][9] == '"')) {
                st.in_submod = YES;
            }
            continue;
        }

        if (!st.in_submod) continue;

        //  key=value.  Split on the first '='.
        u8cs key = {}, val = {};
        u8c const *eq = NULL;
        $for(u8c, p, line) if (*p == '=') { eq = p; break; }
        if (!eq) continue;
        key[0] = line[0]; key[1] = eq;
        val[0] = eq + 1;  val[1] = line[1];
        subs_strip(key);
        subs_strip(val);
        if (u8csEmpty(key)) continue;

        static u8c const k_path[] = "path";
        static u8c const k_url[]  = "url";
        u8cs key_path = {(u8c *)k_path, (u8c *)k_path + 4};
        u8cs key_url  = {(u8c *)k_url,  (u8c *)k_url  + 3};
        if (subs_eq(key, key_path)) {
            u8csMv(st.path, val);
        } else if (subs_eq(key, key_url)) {
            u8csMv(st.url, val);
        }
    }

    return subs_flush(&st, cb, ctx);
}

// --- SubsParseFind ----------------------------------------------------

typedef struct {
    u8cs want_path;
    u8cs found_url;
    b8   hit;
} subs_find_ctx;

static ok64 subs_find_cb(u8cs path, u8cs url, void *vctx) {
    subs_find_ctx *c = (subs_find_ctx *)vctx;
    if (c->hit) return OK;
    if (subs_eq(path, c->want_path)) {
        u8csMv(c->found_url, url);
        c->hit = YES;
    }
    return OK;
}

ok64 SNIFFSubsParseFind(u8cs blob, u8cs path, u8csp url_out) {
    subs_find_ctx c = {};
    u8csMv(c.want_path, path);
    ok64 o = SNIFFSubsParse(blob, subs_find_cb, &c);
    if (o != OK) return o;
    if (!c.hit) return SUBSNOSEC;
    u8csMv(url_out, c.found_url);
    return OK;
}

// --- SubsSynth --------------------------------------------------------

ok64 SNIFFSubsSynth(u8bp out, u8cs paths, u8cs urls) {
    sane(out);
    u8bReset(out);

    a_dup(u8c, p_scan, paths);
    a_dup(u8c, u_scan, urls);

    for (;;) {
        u8cs path = {}, url = {};
        if (u8csDrainLine(p_scan, path) != OK) break;
        if (u8csDrainLine(u_scan, url)  != OK) return SUBSPARSE;
        if (u8csEmpty(path) || u8csEmpty(url)) continue;

        call(u8bFeed, out, ((u8cs){(u8c *)"[submodule \"",
                                   (u8c *)"[submodule \"" + 12}));
        call(u8bFeed, out, path);
        call(u8bFeed, out, ((u8cs){(u8c *)"\"]\n\tpath = ",
                                   (u8c *)"\"]\n\tpath = " + 11}));
        call(u8bFeed, out, path);
        call(u8bFeed, out, ((u8cs){(u8c *)"\n\turl = ",
                                   (u8c *)"\n\turl = " + 8}));
        call(u8bFeed, out, url);
        call(u8bFeed1, out, '\n');
    }

    //  Trailing line not exhausted on the urls side → mismatched arity.
    if (!u8csEmpty(u_scan)) {
        u8cs trail = {};
        if (u8csDrainLine(u_scan, trail) == OK && !u8csEmpty(trail))
            return SUBSPARSE;
    }
    done;
}

// --- SubMount: recursive `be get` driver ------------------------------

//  Write a one-row ULOG file at `<wt>/<path>/.be`:
//      <ron60-now>\trepo\tfile:<parent_root>/.be/\n
//  Mirrors `sniff_write_repo_row` (sniff/SNIFF.c) and BEGetWorktree's
//  secondary-wt seed (beagle/BE.cli.c) — same row shape, same `repo`
//  verb, same trailing slash convention so `home_walk_up` reads it
//  and dispatches to the secondary path.  Routed through URIutf8Feed
//  so the serialization matches the primary writer byte-for-byte;
//  the hand-rolled string used to emit the three-slash `file:///…`
//  form, which differs textually from the primary's `file:/…` and
//  tripped exact-match comparisons.
static ok64 subs_write_anchor(u8cs sub_be_path, u8cs parent_root) {
    sane($ok(sub_be_path) && $ok(parent_root));

    a_path(pathbuf);
    call(PATHu8bFeed, pathbuf, parent_root);
    a_cstr(be_s, ".be");
    call(PATHu8bPush, pathbuf, be_s);
    //  Directory URIs carry a trailing slash.
    call(u8bFeed1, pathbuf, '/');
    call(PATHu8bTerm, pathbuf);

    uri urow = {};
    a_cstr(scheme, "file");
    urow.scheme[0] = scheme[0];
    urow.scheme[1] = scheme[1];
    {
        a_dup(u8c, pb, u8bData(pathbuf));
        urow.path[0] = pb[0];
        urow.path[1] = pb[1];
    }

    a_pad(u8, row, 1024);
    ron60 ts = RONNow();
    call(RONutf8sFeed, u8bIdle(row), ts);
    call(u8bFeed1, row, '\t');
    ron60 vrepo = SNIFFAtVerbRepo();
    call(RONutf8sFeed, u8bIdle(row), vrepo);
    call(u8bFeed1, row, '\t');
    call(URIutf8Feed, u8bIdle(row), &urow);
    call(u8bFeed1, row, '\n');

    a_path(p);
    call(PATHu8bFeed, p, sub_be_path);

    int fd = FILE_CLOSED;
    call(FILECreate, &fd, $path(p));

    a_dup(u8c, body, u8bData(row));
    ok64 wo = FILEFeedAll(fd, body);
    FILEClose(&fd);
    return wo;
}

//  fork → chdir → execvp.  FILESpawn doesn't expose a `cwd`; sub
//  recursion needs the child to start inside `<wt>/<path>/` so its
//  `home_walk_up` finds the secondary-wt anchor we just wrote.  Single
//  call site, so inline rather than carving out a FILE.h knob.
static ok64 subs_spawn_be_get(u8cs exe_path, u8cs wt_path, u8cs arg) {
    sane($ok(exe_path) && $ok(wt_path) && $ok(arg));

    //  Compose NUL-terminated buffers for chdir + execvp.
    a_path(exe_buf);
    call(PATHu8bFeed, exe_buf, exe_path);

    a_path(wt_buf);
    call(PATHu8bFeed, wt_buf, wt_path);

    a_pad(u8, arg_buf, 1024);
    call(u8bFeed,  arg_buf, arg);
    call(u8bFeed1, arg_buf, 0);

    pid_t pid = fork();
    if (pid < 0) fail(SUBSPARSE);
    if (pid == 0) {
        if (chdir((char const *)u8bDataHead(wt_buf)) != 0) {
            fprintf(stderr, "sniff: sub chdir failed: %s\n", strerror(errno));
            _exit(127);
        }
        //  argv[0] = full path to the exe so sibling-dog lookup (if
        //  any) finds the right bin dir without relying on $PATH.
        char *argv[] = {
            (char *)u8bDataHead(exe_buf),
            (char *)"get",
            (char *)u8bDataHead(arg_buf),
            NULL,
        };
        execvp((char const *)u8bDataHead(exe_buf), argv);
        fprintf(stderr, "sniff: sub execvp failed: %s\n", strerror(errno));
        _exit(127);
    }

    int st = 0;
    for (;;) {
        pid_t r = waitpid(pid, &st, 0);
        if (r == pid) break;
        if (r < 0 && errno == EINTR) continue;
        fail(SUBSPARSE);
    }
    if (WIFEXITED(st) && WEXITSTATUS(st) == 0) done;
    fprintf(stderr, "sniff: sub checkout exited non-zero (status=%d)\n", st);
    fail(SUBSPARSE);
}

ok64 SNIFFSubMount(u8cs reporoot, u8cs parent_root,
                   u8cs path, u8cs hex_sha,
                   u8cs gitmodules, u8cs argv0) {
    sane($ok(reporoot) && $ok(parent_root) && $ok(path) &&
         $ok(hex_sha) && u8csLen(hex_sha) == 40);

    //  1. URL lookup.
    u8cs url = {};
    call(SNIFFSubsParseFind, gitmodules, path, url);

    //  2. Basename.
    u8cs basename = {};
    call(SNIFFSubBasename, url, basename);

    //  3. Sub-store dir under parent's `.be/`.  Spec keying is
    //  `<parent>/.be/<basename>/`; we mkdir it as a placeholder so the
    //  smoke test sees it.  Actual objects land in the parent's keeper
    //  trunk via the recursive `be get` (the shared-keeper model).
    a_path(store_dir);
    call(PATHu8bFeed, store_dir, parent_root);
    a_cstr(be_dir, ".be");
    call(PATHu8bPush, store_dir, be_dir);
    call(PATHu8bPush, store_dir, basename);
    call(FILEMakeDirP, $path(store_dir));

    //  4. Sub mount + secondary-wt anchor.
    a_path(mount);
    call(PATHu8bFeed, mount, reporoot);
    call(PATHu8bAdd,  mount, path);          //  multi-segment safe
    call(FILEMakeDirP, $path(mount));

    a_path(anchor);
    a_dup(u8c, mount_s, u8bDataC(mount));
    call(PATHu8bFeed, anchor, mount_s);
    a_cstr(be_s, ".be");
    call(PATHu8bPush, anchor, be_s);
    a_dup(u8c, anchor_s, u8bDataC(anchor));
    call(subs_write_anchor, anchor_s, parent_root);

    //  5. Pre-fetch the sub's pack into the parent's (shared) keeper.
    //  WIREFetchAll grabs every advertised heads/tags ref; the child
    //  sniff process then does a pure detached checkout against the
    //  already-resident commit (no second wire round-trip).  Sharing
    //  the parent keeper is the smoke-path simplification of
    //  MODULES.plan.md §"Storage layout" — proper per-sub branch dirs
    //  remain a follow-up.
    //
    //  On failure, roll the anchor and (empty) shard dir back so a
    //  later retry sees a clean slate — a stranded `<mount>/.be` file
    //  would otherwise make SNIFFSubIsMount lie and bare `be` think
    //  the sub is mounted with no content.
    {
        a_dup(u8c, url_const, url);
        ok64 fo = WIREFetchAll(&KEEP, url_const);
        if (fo != OK) {
            fprintf(stderr,
                    "sniff: submodule fetch failed for %.*s\n",
                    (int)$len(url), (char *)url[0]);
            (void)FILEUnLink($path(anchor));
            (void)FILERmDir($path(store_dir), false);
            return fo;
        }
    }

    //  6. Spawn `sniff get <hex>` with cwd = sub-mount.  The child
    //  opens the parent's keeper RO (via the row-0 anchor we wrote)
    //  and checks out the gitlink-pinned commit into the mount.  We
    //  shell out rather than recurse in-process because SNIFF is a
    //  singleton — a nested checkout would clobber the parent's
    //  open handle.  Use /proc/self/exe directly: this binary IS
    //  sniff, so its path is the answer (HOMEResolveSibling needs an
    //  argv0 with a slash, which the orchestrator-spawned form lacks).
    a_path(sniff_exe);
    {
        char self[FILE_PATH_MAX_LEN];
        ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
        if (n > 0) {
            self[n] = 0;
            a_cstr(self_s, self);
            call(PATHu8bFeed, sniff_exe, self_s);
        } else {
            a_cstr(sniff_name, "sniff");
            HOMEResolveSibling(NULL, sniff_exe, sniff_name, argv0);
        }
    }

    a_pad(u8, arg_buf, 64);
    call(u8bFeed, arg_buf, hex_sha);
    a_dup(u8c, arg_s, u8bData(arg_buf));
    a_dup(u8c, exe_s, u8bDataC(sniff_exe));

    //  Release the parent's keeper write-lock for the duration of the
    //  child checkout — the child opens its own keeper handle on the
    //  same `.be/` (shared via the row-0 anchor) and blocks on
    //  LOCK_EX otherwise.  Restore on the way out.
    b8 had_lock = (KEEP.lock_fd >= 0);
    if (had_lock) (void)FILEUnlock(&KEEP.lock_fd);
    ok64 sr = subs_spawn_be_get(exe_s, mount_s, arg_s);
    if (had_lock) (void)FILELock(&KEEP.lock_fd, YES);
    if (sr != OK) {
        (void)FILEUnLink($path(anchor));
        (void)FILERmDir($path(store_dir), false);
    }
    return sr;
}

// --- IsMount / ReadTip: read-only probes -------------------------------

b8 SNIFFSubIsMount(u8cs wt_root, u8cs subpath) {
    if (!$ok(wt_root) || !$ok(subpath) || u8csEmpty(subpath)) return NO;
    a_path(p);
    if (PATHu8bFeed(p, wt_root) != OK) return NO;
    if (PATHu8bAdd (p, subpath) != OK) return NO;
    a_cstr(be_s, ".be");
    if (PATHu8bPush(p, be_s) != OK) return NO;
    filestat fs = {};
    if (FILELStat(&fs, $path(p)) != OK) return NO;
    return fs.kind == FILE_KIND_REG;
}

ok64 SNIFFSubReadTip(u8cs wt_root, u8cs subpath, u8s out) {
    sane($ok(wt_root) && $ok(subpath) && !u8csEmpty(subpath));
    if ($len(out) < 40) return SUBSPARSE;

    //  Compose `<wt_root>/<subpath>` — `SNIFFAtTailOf` opens
    //  `<that>/.be` if it's a file (secondary-wt anchor) or
    //  `<that>/.be/wtlog` if it's a dir.  Either way it returns a
    //  composed `<root>?<branch>#<sha>` view; we want the fragment.
    a_path(sub_root);
    call(PATHu8bFeed, sub_root, wt_root);
    call(PATHu8bAdd,  sub_root, subpath);

    a_pad(u8, tail_buf, FILE_PATH_MAX_LEN + 128);
    a_dup(u8c, sub_root_s, u8bDataC(sub_root));
    ok64 to = SNIFFAtTailOf(sub_root_s, tail_buf);
    if (to == SNIFFNONE) return SUBSNOSEC;
    if (to != OK) return to;

    uri u = {};
    a_dup(u8c, tail_s, u8bData(tail_buf));
    u8csMv(u.data, tail_s);
    call(URILexer, &u);
    if (u8csLen(u.fragment) != 40) return SUBSNOSEC;
    u8sCopy(out, u.fragment);
    return OK;
}
