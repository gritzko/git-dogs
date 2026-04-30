#include "abc/URI.h"
#include "dog/CLI.h"
#include "dog/FRAG.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "abc/FILE.h"
#include "abc/PATH.h"
#include "abc/PRO.h"
#include "dog/DOG.h"
#include "dog/HOME.h"
#include "keeper/REFS.h"
#include "sniff/AT.h"

// Distinct codes so the MAIN-wrapper's `Error: <code>` line tells you
// what kind of failure stopped the pipeline — a dog exited non-zero
// (BEDOGEXIT) or died from a signal (BEDOGSIG). Generic BEFAIL is
// reserved for be's own internal slips. RON60 caps names at ~10 chars
// (60-bit base64 encoding) — verify with `abc/ok64 NAME`.
con ok64 BEFAIL    = 0x2ce3ca495;
con ok64 BEDOGEXIT = 0xb38d6103a149d;
con ok64 BEDOGSIG  = 0x2ce35841c490;

// --- Verb table ---

static char const *const BE_VERB_NAMES[] = {
    "get", "post", "put", "delete",
    "diff", "patch", "merge", "sync",
    "status",
    NULL
};

static void BEUsage(void) {
    fprintf(stderr,
        "Usage: be [verb] [--flags] [URI...]\n"
        "\n"
        "Verbs:\n"
        "  get [uri]            checkout / fetch / view / search\n"
        "  put [files]          stage files into a new base tree\n"
        "  delete [files]       stage removals into a new base tree\n"
        "  post -m <msg>        commit base tree; push if remote\n"
        "  patch [uri]          search & replace, reindex\n"
        "  diff [uri]           token-level diff\n"
        "  merge [uri]          3-way merge\n"
        "  sync [uri]           fetch + merge (or push)\n"
        "  status               show repo status\n"
        "\n"
        "URI format: [//remote] [path] [?ref] [#search]\n"
        "\n"
        "Bare `be` = ensure indexes are current, show status.\n"
    );
}

// --- Run a sibling tool ---

// Run a sibling tool.  `tool` is the dog name (also argv[0] in argv);
// resolved against this process's own argv[0] via HOMEResolveSibling.
static ok64 BERun(u8csc tool, u8css argv, b8 bg) {
    sane($ok(tool) && !$empty(tool));
    a_path(path);
    a$rg(a0, 0);
    HOMEResolveSibling(NULL, path, tool, a0);
    pid_t pid = 0;
    call(FILESpawn, $path(path), argv, NULL, NULL, &pid);
    if (bg) done;
    int rc = 0;
    ok64 r = FILEReap(pid, &rc);
    if (r == FILESIGNAL) {
        char const *sname = strsignal(rc);
        fprintf(stderr, "be: " U8SFMT " killed by signal %d (%s)\n",
                u8sFmt(tool), rc, sname ? sname : "?");
        return BEDOGSIG;
    }
    if (r != OK) return r;
    if (rc != 0) return BEDOGEXIT;
    done;
}

// --- Run two tools as a producer → pager pipeline ---
//
//  Used to route view-projector output (e.g. `sniff ls --tlv`) into
//  `bro` for paging and coloring.  Spawns both children, pumps bytes
//  from producer's stdout into pager's stdin in the parent, then
//  reaps both.  Returns the worse of the two exit codes.
static ok64 BERunPipe(u8csc prod, u8css prod_argv,
                      u8csc pager, u8css pager_argv) {
    sane($ok(prod) && $ok(pager));
    int to_pager_w = -1;
    pid_t pager_pid = 0;
    call(FILESpawn, pager, pager_argv, &to_pager_w, NULL, &pager_pid);

    int from_prod_r = -1;
    pid_t prod_pid = 0;
    ok64 so = FILESpawn(prod, prod_argv, NULL, &from_prod_r, &prod_pid);
    if (so != OK) {
        //  Bro started but we can't produce.  Close its stdin so it
        //  exits on EOF and we can reap cleanly.
        close(to_pager_w);
        int rc = 0; (void)FILEReap(pager_pid, &rc);
        return so;
    }

    //  Parent pump: drain producer → feed pager.  Shallow, no framing;
    //  HUNK TLV is self-framing so any chunk boundary is fine.
    u8 buf[8192];
    for (;;) {
        ssize_t n = read(from_prod_r, buf, sizeof buf);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(to_pager_w, buf + off, (size_t)(n - off));
            if (w < 0) {
                if (errno == EINTR) continue;
                goto drain_done;
            }
            off += w;
        }
    }
drain_done:
    close(from_prod_r);
    close(to_pager_w);

    int prod_rc = 0;
    int pager_rc = 0;
    (void)FILEReap(prod_pid, &prod_rc);
    (void)FILEReap(pager_pid, &pager_rc);
    if (prod_rc != 0) return BEDOGEXIT;
    if (pager_rc != 0) return BEDOGEXIT;
    done;
}

// --- Read .dogs/DOGS list ---

static u32 BEReadDogs(char out[][64], u32 maxn) {
    home h = {};
    uri at = {};
    if (HOMEOpen(&h, &at, NO) != OK) return 0;
    a_path(p);
    a_dup(u8c, root_s, u8bDataC(h.root));
    if (PATHu8bFeed(p, root_s) != OK) { HOMEClose(&h); return 0; }
    a_cstr(rel, ".dogs/DOGS");
    if (PATHu8bAdd(p, rel) != OK) { HOMEClose(&h); return 0; }

    u8bp mapped = NULL;
    if (FILEMapRO(&mapped, $path(p)) != OK) { HOMEClose(&h); return 0; }
    a_dup(u8c, data, u8bDataC(mapped));

    u32 count = 0;
    while (!$empty(data) && count < maxn) {
        u8cp nl = data[0];
        while (nl < data[1] && *nl != '\n') nl++;
        size_t len = (size_t)(nl - data[0]);
        if (len > 0 && data[0][0] != '#') {
            if (len >= 64) len = 63;
            memcpy(out[count], data[0], len);
            out[count][len] = 0;
            count++;
        }
        data[0] = (nl < data[1]) ? nl + 1 : data[1];
    }

    FILEUnMap(mapped);
    HOMEClose(&h);
    return count;
}

// --- Verb dispatch: forward URI to dogs in order ---
//
// Each dog parses the URI and handles its part:
//   get:    keeper (fetch) → sniff (checkout)
//   put:    sniff (stage tree)
//             [local only — no HEAD move, no ref push]
//   delete: sniff (stage removal)
//             [local only — same as put]
//   post:   sniff (commit, HEAD move) → keeper (push ref)
//
// spot and graf are NOT invoked as standalone steps here.  They
// receive objects exclusively through keeper's streaming DOGUpdate
// callbacks during fetch/push, so a separate reindex pass is redundant
// (and raced against keeper's own writes).

typedef struct {
    u8cs dog;
    u8cs verb;
    b8 bg;             // run in background (don't wait)
} dog_step;

//  Process-wide buffer for the `--at <root>?<branch>#<sha>` URI text
//  forwarded to every sub-dog argv.  Populated once at the top of
//  `becli` from `<cwd>/.sniff` via `SNIFFAtTailOf`; empty when no
//  `.sniff` is present (fresh dir / pre-clone bootstrap), in which
//  case sub-dogs fall back to their own cwd-walk.
static u8 be_at_buf_storage[FILE_PATH_MAX_LEN + 128];
static Bu8 be_at_buf = {
    be_at_buf_storage, be_at_buf_storage,
    be_at_buf_storage,
    be_at_buf_storage + sizeof(be_at_buf_storage)
};
static u8c const be_at_flag_lit[] = "--at";
static u8cs const be_at_flag = {
    be_at_flag_lit, be_at_flag_lit + sizeof(be_at_flag_lit) - 1
};

static ok64 BEDispatch(cli *c, dog_step const *steps, u32 nsteps,
                        b8 seq) {
    sane(c && steps);
    b8 have_at = u8bDataLen(be_at_buf) > 0;
    for (u32 i = 0; i < nsteps; i++) {
        // argv: dog verb [--at <uri>] [flags...] [URIs...]
        // cli.flags and cli.uris[].data already are u8cs slices.
        a_pad(u8cs, args, 4 + CLI_MAX_FLAGS * 2 + CLI_MAX_URIS);
        // Local copies: const dog_step's u8cs fields are deeply const and
        // can't be passed by value to the mutable-pointer Feed1 param.
        a_dup(u8c, dog, steps[i].dog);
        a_dup(u8c, verb, steps[i].verb);
        u8csbFeed1(args, dog);
        u8csbFeed1(args, verb);
        if (have_at) {
            a_dup(u8c, at_flag, be_at_flag);
            a_dup(u8c, at_val,  u8bData(be_at_buf));
            u8csbFeed1(args, at_flag);
            u8csbFeed1(args, at_val);
        }
        // Flags come as {flag, val} pairs; val is the empty-string
        // sentinel for booleans.  Forward the flag name always; only
        // forward its value if it's genuinely non-empty, otherwise the
        // callee's CLIParse would pick it up as a spurious URI.
        for (u32 j = 0; j + 1 < c->nflags; j += 2) {
            u8csbFeed1(args, c->flags[j]);
            if (!u8csEmpty(c->flags[j + 1]))
                u8csbFeed1(args, c->flags[j + 1]);
        }
        for (u32 j = 0; j < c->nuris; j++)
            u8csbFeed1(args, c->uris[j].data);
        a_dup(u8cs, argv, u8csbData(args));
        call(BERun, steps[i].dog, argv, seq ? NO : steps[i].bg);
    }
    done;
}

//  `be get <local-dir>` creates a worktree in cwd that shares
//  keeper/graf/spot with the primary repo via symlinks; sniff is
//  real (per-worktree).  Returns OK after setup whether or not any
//  action was taken; only dies on a real error (mkdir/symlink fail).
// Static storage for the rewritten URI after a worktree is wired up:
// "?<40-hex-sha>" points every downstream dog at the primary's HEAD.
static u8 wt_uri_text[42];  // '?' + 40 hex + NUL

static ok64 BEGetWorktree(uri *u) {
    sane(1);
    if (u == NULL || !u8csEmpty(u->authority)) done;
    if (u8csEmpty(u->path)) done;

    // Primary candidate has to be an existing dir containing .dogs/.
    a_cstr(dotdogs, ".dogs");
    a_dup(u8c, prim_s, u->path);
    a_path(prim_dogs, prim_s, dotdogs);
    if (FILEisdir($path(prim_dogs)) != OK) done;

    // Skip if cwd already has a .dogs (dir or symlink).
    a_path(cwd);
    call(FILEGetCwd, cwd);
    a_path(cwd_dogs);
    a_dup(u8c, cwd_s, u8bDataC(cwd));
    call(PATHu8bFeed, cwd_dogs, cwd_s);
    call(PATHu8bPush, cwd_dogs, dotdogs);
    {
        struct stat sb;
        if (lstat((char const *)*$path(cwd_dogs), &sb) == 0) done;
    }

    // Worktree layout:
    //   * `<wt>/.dogs` is a symlink to the primary's `.dogs/` — the
    //     wt and primary share the entire store (keeper, graf, spot,
    //     per-branch indexes, REFS, paths registry, ALIAS, lock).
    //   * `<wt>/.sniff` is a plain file (the ULOG) — each wt tracks
    //     its own checkout independently.  Created lazily by
    //     SNIFFOpen on first rw access; BE doesn't need to touch it.
    ok64 lo = FILESymLink($path(prim_dogs), $path(cwd_dogs));
    if (lo != OK && lo != FILEEXIST) return lo;

    fprintf(stderr, "be: worktree from %.*s\n",
            (int)$len(u->path), (char *)u->path[0]);

    // Resolve the primary's current commit via its `.sniff` log.
    // Rewrite this URI to "?<sha>" so downstream sniff checks out
    // that commit in the worktree.
    a_pad(u8, prim_at, FILE_PATH_MAX_LEN + 128);
    a_dup(u8c, prim_root, prim_s);
    if (SNIFFAtTailOf(prim_root, prim_at) != OK) done;
    uri prim_uri = {};
    u8csMv(prim_uri.data, u8bDataC(prim_at));
    URILexer(&prim_uri);
    if (u8csLen(prim_uri.fragment) != 40) done;
    wt_uri_text[0] = '?';
    memcpy(wt_uri_text + 1, prim_uri.fragment[0], 40);
    wt_uri_text[41] = 0;

    u->data[0]      = wt_uri_text;
    u->data[1]      = wt_uri_text + 41;
    u->scheme[0]    = u->scheme[1]    = NULL;
    u->authority[0] = u->authority[1] = NULL;
    u->host[0]      = u->host[1]      = NULL;
    u->port[0]      = u->port[1]      = NULL;
    u->user[0]      = u->user[1]      = NULL;
    u->path[0]      = u->path[1]      = NULL;
    u->query[0]     = wt_uri_text + 1;
    u->query[1]     = wt_uri_text + 41;
    u->fragment[0]  = u->fragment[1]  = NULL;
    done;
}

//  View-projector routing (VERBS.md §"View projectors").
//
//  Invocation: `be <scheme>:<URI>` — no verb.  `be` is a scheme
//  router; the dog that owns the scheme receives the URI verbatim
//  (scheme and all) and dispatches internally.  The scheme→dog map
//  lives in dog/DOG.c (`DOG_PROJECTORS`) — adding a projector = one
//  row there + the producing dog's internal branch.
//
//  Output: always via `dog/HUNK` — TLV to a bro pipe on TTY, plain
//  ASCII via `HUNKu8sFeedText` otherwise.  No dog needs its own
//  color / pager / renderer code.
static ok64 BEProjector(cli *c, uri *u) {
    sane(c && u);

    char const *dog_cstr = DOGProjectorDog(u->scheme);
    if (dog_cstr == NULL) {
        fprintf(stderr, "be: unknown projector '%.*s:'\n",
                (int)$len(u->scheme), (char *)u->scheme[0]);
        fail(BEFAIL);
    }
    a_cstr(dog_s, dog_cstr);

    b8 tty = isatty(STDOUT_FILENO) ? YES : NO;

    a_path(dogpath);
    a$rg(a0, 0);
    HOMEResolveSibling(NULL, dogpath, dog_s, a0);

    //  Verbless: dog argv is `<dog> [--at <uri>] [--tlv] <URI>`.  The
    //  dog sees the URI with its projector scheme intact and dispatches
    //  on u->scheme inside its own CLI.  `--at` carries the wt's tip
    //  so the projector (graf map / log "you are here", etc.) doesn't
    //  need to poke at `.sniff` itself.
    a_cstr(tlv_flag, "--tlv");
    b8 have_at = u8bDataLen(be_at_buf) > 0;
    a_pad(u8cs, dargs, 5);
    u8csbFeed1(dargs, dog_s);
    if (have_at) {
        a_dup(u8c, at_flag, be_at_flag);
        a_dup(u8c, at_val,  u8bData(be_at_buf));
        u8csbFeed1(dargs, at_flag);
        u8csbFeed1(dargs, at_val);
    }
    if (tty) u8csbFeed1(dargs, tlv_flag);
    u8csbFeed1(dargs, u->data);
    a_dup(u8cs, dargv, u8csbData(dargs));

    if (!tty) return BERun(dog_s, dargv, NO);

    //  TTY: pipe through bro.  Bro drains HUNK TLV from stdin (see
    //  bro/BRO.c §BROPipeRun) and opens /dev/tty for keystrokes.
    a_path(bropath);
    a_cstr(bro_name, "bro");
    HOMEResolveSibling(NULL, bropath, bro_name, a0);
    a_pad(u8cs, bargs, 1);
    u8csbFeed1(bargs, bro_name);
    a_dup(u8cs, bargv, u8csbData(bargs));
    return BERunPipe($path(dogpath), dargv, $path(bropath), bargv);
}

//  `be get` is a flat forward to sniff.  Sniff is the verb owner and
//  calls KEEPGetRemote internally on a remote URI before checkout.
//  be only does URI normalisation and the fresh-clone .dogs/ bootstrap
//  (a pre-routing step both keeper and sniff need a cwd-rooted store
//  to land in).
static ok64 BEGet(cli *c, b8 seq) {
    sane(c);
    static dog_step const steps[] = {
        {u8slit("sniff"), u8slit("get"), NO},
    };
    uri *u = (c->nuris > 0) ? &c->uris[0] : NULL;
    b8  remote = (u != NULL && !$empty(u->authority));

    //  Local file: URI → wire this cwd as a worktree of a sibling repo.
    call(BEGetWorktree, u);

    //  Fresh-clone bootstrap: a remote URI with no .dogs/ anywhere up
    //  to / needs an empty .dogs/ in cwd so the downstream dog can
    //  place its subdir.  Local URIs already have a HOME.
    if (remote) {
        home probe_h = {};
        uri at = {};
        ok64 ho = HOMEOpen(&probe_h, &at, NO);
        HOMEClose(&probe_h);
        if (ho != OK) {
            a_path(here);
            if (FILEGetCwd(here) == OK) {
                a_cstr(dotdogs, ".dogs");
                call(PATHu8bPush, here, dotdogs);
                call(FILEMakeDirP, $path(here));
            }
        }
    }
    return BEDispatch(c, steps, 1, seq);
}

//  `be put` stages a new base tree locally — no commit object and no
//  ref push.  spot/graf pick up the new blobs from sniff/keeper's
//  DOGUpdate callbacks; no standalone reindex step is dispatched.
static ok64 BEPut(cli *c, b8 seq) {
    sane(c);
    static dog_step const steps[] = {
        {u8slit("sniff"),  u8slit("put"), NO},
    };
    return BEDispatch(c, steps, 1, seq);
}

//  `be delete` is the mirror of `be put`: stage tree without a file.
static ok64 BEDelete(cli *c, b8 seq) {
    sane(c);
    static dog_step const steps[] = {
        {u8slit("sniff"),  u8slit("delete"), NO},
    };
    return BEDispatch(c, steps, 1, seq);
}

//  `be diff <uri>` — delegate to graf.  For local URIs (no authority)
//  graf reads objects straight from keeper's store; for a remote URI
//  we `keeper get` first to materialize the reachable closure, same
//  as `be patch`.
static ok64 BEDiff(cli *c, b8 seq) {
    sane(c);
    static dog_step const steps[] = {
        {u8slit("keeper"), u8slit("get"),  NO},
        {u8slit("graf"),   u8slit("diff"), NO},
    };
    u32 nsteps = sizeof(steps) / sizeof(steps[0]);
    uri *u = (c->nuris > 0) ? &c->uris[0] : NULL;
    u32 start = (u != NULL && !$empty(u->authority)) ? 0 : 1;
    return BEDispatch(c, steps + start, nsteps - start, seq);
}

//  `be patch <uri>` — 3-way merge `uri`'s target ref/sha into the
//  worktree.  If the URI has an authority we first `keeper get` to
//  fetch the target's reachable closure, then hand off to
//  `sniff patch`.  See VERBS.md §PATCH.
static ok64 BEPatch(cli *c, b8 seq) {
    sane(c);
    static dog_step const steps[] = {
        {u8slit("keeper"), u8slit("get"),   NO},
        {u8slit("sniff"),  u8slit("patch"), NO},
    };
    u32 nsteps = sizeof(steps) / sizeof(steps[0]);
    uri *u = (c->nuris > 0) ? &c->uris[0] : NULL;
    u32 start = (u != NULL && !$empty(u->authority)) ? 0 : 1;
    return BEDispatch(c, steps + start, nsteps - start, seq);
}

//  `be post`:
//    <free-form tail> → fragment carries the commit message; sniff
//                       commits locally.  (Legacy `-m <msg>` flag still
//                       works as a fallback.)
//    ?<branch>        → promote: phase 1 commits cur, phase 2 ff-or-
//                       rebases the named branch.
//    //<host>?<ref>   → keeper pushes the current commit to that remote.
//    bare             → sniff prints the dry-run change-set; no commit.
//
//  Path-form URIs (`be post abc/foo`, `be post .`, `be post x.txt`)
//  are spec-illegal: POST takes only branch URIs.  Refuse early with a
//  hint to use `be put` first.
//
//  Detection: the token is path-form when its raw bytes (u->data) carry
//  no `?` sigil AND either contain a `/` or `.` OR have an explicit
//  uri.path slice (URILexer-classified path).  This catches both
//  `be post abc/foo` (uri.path) and `be post x.txt` (DOGNormalizeArg
//  classified as ref_safe-bare-token, query-only no path).  Pure-letter
//  branch tokens (`?feat`, `feat`) and remote URIs (`//host?ref`) skip
//  the check.
static b8 be_post_is_path_form(uri *u) {
    if (!$empty(u->authority)) return NO;
    if (!$empty(u->path)) return YES;
    //  Bare token classified as query-only: refuse if it looks like a
    //  filesystem path (contains `.` or `/` and is not preceded by `?`
    //  in the raw bytes).
    u8cs raw = {u->data[0], u->data[1]};
    if ($empty(raw)) return NO;
    if (raw[0][0] == '?') return NO;
    $for(u8c, p, raw) {
        if (*p == '/' || *p == '.') return YES;
    }
    return NO;
}

static ok64 BEPost(cli *c, b8 seq) {
    sane(c);
    for (u32 i = 0; i < c->nuris; i++) {
        uri *u = &c->uris[i];
        //  URIs with a non-empty fragment but empty path/query/authority
        //  are pure commit-message tails synthesised by CLIParse — skip.
        if ($empty(u->path) && $empty(u->query) && $empty(u->authority) &&
            !$empty(u->fragment)) continue;
        if (be_post_is_path_form(u)) {
            fprintf(stderr,
                "be: post: path-form URI `%.*s` not allowed — use "
                "`be put %.*s` first, then `be post <msg>`\n",
                (int)u8csLen(u->data), (char *)u->data[0],
                (int)u8csLen(u->data), (char *)u->data[0]);
            fail(BEFAIL);
        }
    }
    b8 has_remote = NO;
    for (u32 i = 0; i < c->nuris; i++) {
        if (!u8csEmpty(c->uris[i].authority)) { has_remote = YES; break; }
    }
    //  Commit-message presence: any URI with a non-empty fragment (the
    //  new convention) or a legacy `-m` flag.
    b8 has_msg = NO;
    for (u32 i = 0; i < c->nuris; i++) {
        if (!u8csEmpty(c->uris[i].fragment)) { has_msg = YES; break; }
    }
    if (!has_msg) {
        a_cstr(mf, "-m");
        for (u32 fi = 0; fi + 1 < c->nflags; fi += 2) {
            if ($eq(c->flags[fi], mf)) { has_msg = YES; break; }
        }
    }
    dog_step steps[2];
    u32 nsteps = 0;
    //  Sniff runs whenever we have something to commit, a label URI
    //  (`?ref`), or nothing — bare invocation prints the would-be
    //  change-set and exits.
    if (has_msg || c->nuris > 0 || !has_remote) {
        steps[nsteps++] = (dog_step){u8slit("sniff"),  u8slit("post"), NO};
    }
    if (has_remote) {
        steps[nsteps++] = (dog_step){u8slit("keeper"), u8slit("post"), NO};
    }
    return BEDispatch(c, steps, nsteps, seq);
}

// --- Bare `be`: --update all dogs, then --status each ---

//  Bare `be` — overview of the working tree.  Forwards to bare
//  `sniff`, which lists Changed: and Untracked: against the baseline
//  tree (untracked-but-gitignored filtered).  spot / graf / keeper
//  dogs aren't surfaced here — they're index/storage layers without
//  user-relevant state to print.  Adding their summaries back is a
//  one-liner per dog if it ever matters.
static ok64 BEDefault(void) {
    sane(1);
    a_cstr(sniff_s, "sniff");
    a_pad(u8cs, args, 1);
    u8csbFeed1(args, sniff_s);
    a_dup(u8cs, argv, u8csbData(args));
    return BERun(sniff_s, argv, NO);
}

// --- Main ---

ok64 becli() {
    sane(1);
    call(FILEInit);

    //  -m / --author take a following value (legacy commit-message
    //  flag — the new convention is to fold trailing words into the
    //  URI fragment, but `-m` remains accepted).
    cli c = {};
    call(CLIParse, &c, BE_VERB_NAMES, "-m\0--author\0");

    if (CLIHas(&c, "-h") || CLIHas(&c, "--help")) {
        BEUsage();
        done;
    }

    //  Read the wt's tip URI (`<root>?<branch>#<sha>`) once, here at
    //  the top of the call chain, and stash it for `BEDispatch` to
    //  forward to every sub-dog as `--at <uri>`.  Sub-dogs that need
    //  to know the worktree's current branch / commit (sniff bare
    //  `get` resume, keeper `get //origin` default branch, graf `log`
    //  / `map` "you are here") read it back via `CLIAtURI` from
    //  their own cli.flags — no more sub-dog poking at `.sniff`.
    //  `c.repo` is the cwd-walked wt root resolved by `CLIParse`.
    //  Absent / empty `.sniff` (fresh dir, pre-clone bootstrap) →
    //  buffer stays empty and no `--at` flag is forwarded.
    if ($ok(c.repo) && !u8csEmpty(c.repo)) {
        u8bReset(be_at_buf);
        (void)SNIFFAtTailOf(c.repo, be_at_buf);
    }

    // No args → default
    if ($empty(c.verb) && c.nuris == 0 && c.nflags == 0) {
        call(BEDefault);
        done;
    }

    // Classify verb
    a_cstr(v_get,    "get");    a_cstr(v_put,    "put");
    a_cstr(v_post,   "post");   a_cstr(v_delete, "delete");
    a_cstr(v_diff,   "diff");   a_cstr(v_patch,  "patch");
    a_cstr(v_merge,  "merge");  a_cstr(v_sync,   "sync");
    a_cstr(v_status, "status");

    u8cs verb = {};
    $mv(verb, c.verb);

    // Get first URI if available
    uri *u = (c.nuris > 0) ? &c.uris[0] : NULL;
    frag fr = {};
    if (u != NULL && !$empty(u->fragment))
        FRAGu8sDrain(u->fragment, &fr);

    b8 seq = CLIHas(&c, "--seq");

    //  Projector URIs are pure views (VERBS.md Invariant 7).  Route
    //  them through BEProjector regardless of verb — `be get diff:f?r`
    //  must land in graf's diff machinery, not in BEGet's keeper+sniff
    //  checkout pipeline.  GET is the canonical projector verb per
    //  VERBS.md, but the table only specifies the read-only intent;
    //  any verb on a projector URI is treated as GET-equivalent here.
    if (u != NULL && DOGIsProjector(u->scheme)) {
        call(BEProjector, &c, u);
        done;
    }

    // No verb → view/search mode.  Projector schemes (ls:, tree:, …)
    // are verb-less by design per VERBS.md §"View projectors"; route
    // them first so `be ls:?` doesn't get mistaken for a bare URI view.
    if ($empty(verb)) {
        u8cs spot = u8slit("spot");
        u8cs bro  = u8slit("bro");
        if (u != NULL && DOGIsProjector(u->scheme)) {
            call(BEProjector, &c, u);
        } else if (u != NULL && (fr.type == FRAG_SPOT ||
                                 fr.type == FRAG_PCRE ||
                                 fr.type == FRAG_IDENT)) {
            // Search → spot.  u->data borrows from argv (NUL-terminated).
            a_pad(u8cs, args, 2);
            u8csbFeed1(args, spot);
            u8csbFeed1(args, u->data);
            a_dup(u8cs, argv, u8csbData(args));
            call(BERun, spot, argv, NO);
        } else if (u != NULL && !$empty(u->path)) {
            // View → bro
            a_pad(u8cs, args, 2);
            u8csbFeed1(args, bro);
            u8csbFeed1(args, u->data);
            a_dup(u8cs, argv, u8csbData(args));
            call(BERun, bro, argv, NO);
        } else {
            call(BEDefault);
        }
    } else if ($eq(verb, v_get)) {
        call(BEGet, &c, seq);
    } else if ($eq(verb, v_post)) {
        call(BEPost, &c, seq);
    } else if ($eq(verb, v_put)) {
        call(BEPut, &c, seq);
    } else if ($eq(verb, v_delete)) {
        call(BEDelete, &c, seq);
    } else if ($eq(verb, v_status)) {
        call(BEDefault);
    } else if ($eq(verb, v_diff)) {
        call(BEDiff, &c, seq);
    } else if ($eq(verb, v_patch)) {
        call(BEPatch, &c, seq);
    } else {
        fprintf(stderr, "be: verb '" U8SFMT "' not yet implemented\n",
                u8sFmt(verb));
    }

    done;
}

MAIN(becli);
