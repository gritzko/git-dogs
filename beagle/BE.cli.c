#include "abc/URI.h"
#include "dog/CLI.h"

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
#include "dog/QURY.h"
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
    "head", "get", "post", "put", "delete", "patch",
    //  Legacy / read-only sub-verbs surfaced as projectors elsewhere
    //  but still parsed here for argv compat:
    "diff", "merge", "sync", "status",
    NULL
};

static void BEUsage(void) {
    fprintf(stderr,
        "Usage: be [verb] [--flags] [URI...]\n"
        "\n"
        "Verbs (VERBS.md):\n"
        "  head [uri]           peek/dry-run; fetch refs from remote;\n"
        "                       show ahead/behind cur vs the target\n"
        "  get  [uri]           switch wt+cur (mkdir/cd model)\n"
        "  post [#msg|?br|//r]  commit on cur; rebase upstream;\n"
        "                       no commits land on non-cur branches\n"
        "  put  [files|?br|//r] stage files / mint label / FF-push\n"
        "  delete [files|?br]   unlink files / drop branch\n"
        "  patch [uri]          weave-merge another branch into wt\n"
        "\n"
        "URI format: [scheme:][//host][path][?ref][#frag]\n"
        "  //host  = cached remote-tracking refs only (no network)\n"
        "  ssh:    = open a wire (clone, fetch, push)\n"
        "\n"
        "Bare `be` = status (current branch, ahead/behind, dirty).\n"
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

//  Spawn a sibling tool without waiting; caller reaps later via
//  BEReap.  Used by `be get` to run spot/graf/sniff in parallel
//  after keeper completes (DOG.md §10a).
static ok64 BESpawn(u8csc tool, u8css argv, pid_t *out_pid) {
    sane($ok(tool) && !$empty(tool) && out_pid);
    a_path(path);
    a$rg(a0, 0);
    HOMEResolveSibling(NULL, path, tool, a0);
    return FILESpawn($path(path), argv, NULL, NULL, out_pid);
}

//  Wait on a previously-spawned child and translate its exit into
//  the BEDOG* code surface that `BERun` uses.
static ok64 BEReap(pid_t pid, u8csc tool) {
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
    return OK;
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
//   get:    keeper (fetch + own index) → spot+graf+sniff in parallel
//             (each pulls from keeper's read APIs and updates its own
//              state — see DOG.md §10a "Indexing").
//   put:    sniff (stage tree)            [local only]
//   delete: sniff (stage removal)         [local only]
//   post:   sniff (commit, HEAD move) → keeper (push ref)
//
// Other verbs (post/put/delete/patch/diff) keep their historical
// shape for now; the get-style fork-keeper-then-parallel pattern is
// expected to generalise but is committed only for `get`.

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

//  Build a `<dog> <verb> [--at <uri>] [flags...] [URIs...]` argv
//  slice into `args`.  Caller-owned: `args` must be a u8cs Bbuf with
//  space for `4 + CLI_MAX_FLAGS * 2 + CLI_MAX_URIS` slots.
static void be_build_argv(u8csb args, u8cs dog, u8cs verb, cli *c) {
    a_dup(u8c, ldog,  dog);
    a_dup(u8c, lverb, verb);
    u8csbFeed1(args, ldog);
    u8csbFeed1(args, lverb);
    if (u8bDataLen(be_at_buf) > 0) {
        a_dup(u8c, at_flag, be_at_flag);
        a_dup(u8c, at_val,  u8bData(be_at_buf));
        u8csbFeed1(args, at_flag);
        u8csbFeed1(args, at_val);
    }
    //  Flags come as {flag, val} pairs; val is the empty-string
    //  sentinel for booleans.  Forward the flag name always; only
    //  forward its value if it's genuinely non-empty, otherwise the
    //  callee's CLIParse would pick it up as a spurious URI.
    for (u32 j = 0; j + 1 < c->nflags; j += 2) {
        u8csbFeed1(args, c->flags[j]);
        if (!u8csEmpty(c->flags[j + 1]))
            u8csbFeed1(args, c->flags[j + 1]);
    }
    for (u32 j = 0; j < c->nuris; j++)
        u8csbFeed1(args, c->uris[j].data);
}

static ok64 BEDispatch(cli *c, dog_step const *steps, u32 nsteps,
                        b8 seq) {
    sane(c && steps);
    for (u32 i = 0; i < nsteps; i++) {
        a_pad(u8cs, args, 4 + CLI_MAX_FLAGS * 2 + CLI_MAX_URIS);
        be_build_argv(args, steps[i].dog, steps[i].verb, c);
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

static b8 be_promote_to_ref(uri *u);

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

//  `be get URI` (DOG.md §10a):
//
//    1. keeper get URI  — synchronous.  Fetches/clones (remote URI),
//       writes the pack to .dogs/keeper, builds keeper's own index.
//    2. spot get URI, graf get URI, sniff get URI — in parallel.
//       Each dog opens keeper read-only, walks the URI's tip(s), and
//       updates its own state (spot/graf indexes; sniff worktree).
//
//  `--seq` (debugging) collapses step 2 to sequential keeper-order
//  execution — same dispatch shape as the other verbs.
//
//  Pre-flight: URI normalisation (worktree wiring + fresh-clone
//  .dogs/ bootstrap so the downstream dogs have a place to land).
static ok64 BEGet(cli *c, b8 seq) {
    sane(c);
    //  GET is ref-expecting: promote bare `be get other/branch` to
    //  query=other/branch just like POST and PATCH.  Path views
    //  (`be VERBS.md`) are the verbless form, not GET.
    for (u32 i = 0; i < c->nuris; i++) be_promote_to_ref(&c->uris[i]);

    uri *u = (c->nuris > 0) ? &c->uris[0] : NULL;
    b8  remote = (u != NULL && !$empty(u->authority));

    //  Local file: URI → wire this cwd as a worktree of a sibling repo.
    call(BEGetWorktree, u);

    //  Single-file overwrite: `be get file.c?feat` (VERBS.md §GET).
    //  Path+query (no authority) is a one-file checkout — bypass the
    //  spot/graf parallel index pipeline and route only to sniff,
    //  which fetches the blob via keeper and overwrites the wt file
    //  without touching `.sniff` (no `get`/`put` row appended).
    if (u != NULL && !$empty(u->path) && !$empty(u->query) &&
        $empty(u->authority)) {
        a_pad(u8cs, args, 4 + CLI_MAX_FLAGS * 2 + CLI_MAX_URIS);
        a_cstr(get_s,   "get");
        a_cstr(sniff_s, "sniff");
        a_dup(u8c, sniff_d, sniff_s);
        a_dup(u8c, get_d,   get_s);
        be_build_argv(args, sniff_d, get_d, c);
        a_dup(u8cs, argv, u8csbData(args));
        call(BERun, sniff_d, argv, NO);
        (void)seq;
        done;
    }

    //  Fresh-clone bootstrap: a remote URI with no .dogs/ anywhere up
    //  to / needs an empty .dogs/ in cwd so the downstream dog can
    //  place its subdir.
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

    //  Step 1: keeper get URI — synchronous.  Only meaningful when
    //  the URI carries a remote authority (fetch/clone path); for a
    //  local-only checkout (`?ref`, `?<sha>`, bare `?`) keeper has
    //  nothing to do — its index is already current — so skip it.
    a_cstr(get_s,    "get");
    a_cstr(keeper_s, "keeper");
    if (remote) {
        a_pad(u8cs, args, 4 + CLI_MAX_FLAGS * 2 + CLI_MAX_URIS);
        a_dup(u8c, keeper_d, keeper_s);
        a_dup(u8c, get_d,    get_s);
        be_build_argv(args, keeper_d, get_d, c);
        a_dup(u8cs, argv, u8csbData(args));
        call(BERun, keeper_d, argv, NO);
    }

    //  Step 2: spot, graf, sniff in parallel.
    static u8c const spot_lit[]  = "spot";
    static u8c const graf_lit[]  = "graf";
    static u8c const sniff_lit[] = "sniff";
    u8cs const dogs[3] = {
        {spot_lit,  spot_lit  + 4},
        {graf_lit,  graf_lit  + 4},
        {sniff_lit, sniff_lit + 5},
    };

    if (seq) {
        for (int i = 0; i < 3; i++) {
            a_pad(u8cs, args, 4 + CLI_MAX_FLAGS * 2 + CLI_MAX_URIS);
            a_dup(u8c, dog_d, dogs[i]);
            a_dup(u8c, get_d, get_s);
            be_build_argv(args, dog_d, get_d, c);
            a_dup(u8cs, argv, u8csbData(args));
            call(BERun, dog_d, argv, NO);
        }
        done;
    }

    pid_t pids[3] = {0};
    ok64  spawn_err[3] = {OK, OK, OK};
    for (int i = 0; i < 3; i++) {
        a_pad(u8cs, args, 4 + CLI_MAX_FLAGS * 2 + CLI_MAX_URIS);
        a_dup(u8c, dog_d, dogs[i]);
        a_dup(u8c, get_d, get_s);
        be_build_argv(args, dog_d, get_d, c);
        a_dup(u8cs, argv, u8csbData(args));
        spawn_err[i] = BESpawn(dog_d, argv, &pids[i]);
        if (spawn_err[i] != OK) {
            fprintf(stderr, "be: spawn " U8SFMT ": %s\n",
                    u8sFmt(dog_d), ok64str(spawn_err[i]));
        }
    }
    ok64 worst = OK;
    for (int i = 0; i < 3; i++) {
        if (spawn_err[i] != OK) { worst = spawn_err[i]; continue; }
        a_dup(u8c, dog_d, dogs[i]);
        ok64 r = BEReap(pids[i], dog_d);
        if (r != OK) worst = r;
    }
    return worst;
}

//  `be head <uri>` — peek/dry-run.  Per VERBS.md §"HEAD":
//    - `?br` (local)              — ahead/behind cur vs ?br
//    - `//host` (cached)          — diff cur vs cached origin tracking
//    - `ssh://host` (transport)   — fetch refs+pack, update .dogs/refs,
//                                    print diff cur vs origin
//    - `#frag`                    — commit-msg search; diff cur vs match
//
//  Implementation: thin orchestrator (DOG.md §10a "be is a thin
//  router; sub-dogs do the work"):
//    transport-scheme remote → keeper get URI (fetches; updates the
//                              local remote-tracking cache)
//    cached-or-local target  → no fetch step; sniff/graf print the
//                              diff against the named ref
//
//  HEAD never modifies a branch's history or the wt; the only side
//  effect on a transport-scheme URI is the cache refresh in
//  `.dogs/refs` and the pack data added to keeper.
//
//  Skeleton: today HEAD piggy-backs on `keeper get` for the fetch
//  half (which prints the fetched ref's sha to stderr — enough to
//  satisfy the canonical "rebase trunk on top of remote main" test's
//  cache-refresh assertion).  The diff-summary half is TODO once
//  the underlying graf/sniff "ahead/behind cur vs ref" entry point
//  lands.  See VERBS.todo.md §"HEAD".
static ok64 BEHead(cli *c, b8 seq) {
    sane(c);
    uri *u = (c->nuris > 0) ? &c->uris[0] : NULL;
    b8 transport = (u != NULL && !$empty(u->scheme));
    b8 cached    = (u != NULL && !transport && !$empty(u->authority));

    //  Transport scheme: forward to keeper get to fetch refs + pack.
    //  `?*` wildcard query (`be head ssh://origin?*`) routes to keeper
    //  get just like a single-ref form — keeper detects the literal
    //  `*` and runs the bulk-fetch (advertise + multi-want) path.
    if (transport || cached) {
        a_pad(u8cs, args, 4 + CLI_MAX_FLAGS * 2 + CLI_MAX_URIS);
        a_cstr(get_s,    "get");
        a_cstr(keeper_s, "keeper");
        a_dup(u8c, keeper_d, keeper_s);
        a_dup(u8c, get_d,    get_s);
        be_build_argv(args, keeper_d, get_d, c);
        a_dup(u8cs, argv, u8csbData(args));
        call(BERun, keeper_d, argv, NO);
        (void)seq;
        done;
    }

    //  Local: hand off to `graf head`.  graf dispatches internally:
    //    fragment-only URI → commit-message substring search;
    //    `?br` / no URI    → ahead/behind cur vs target + tree diff.
    //  Bare `be` (no verb) is the spec's "current branch + ahead/
    //  behind + dirty list" combo and adds `sniff status` upstream;
    //  `be head` itself stays read-only and refuses to mix in wt
    //  status (per VERBS.md §HEAD: "never modifies a branch's
    //  history or the wt").
    {
        a_pad(u8cs, args, 4 + CLI_MAX_FLAGS * 2 + CLI_MAX_URIS);
        a_cstr(head_s, "head");
        a_cstr(graf_s, "graf");
        a_dup(u8c, graf_d, graf_s);
        a_dup(u8c, head_d, head_s);
        be_build_argv(args, graf_d, head_d, c);
        a_dup(u8cs, argv, u8csbData(args));
        call(BERun, graf_d, argv, NO);
    }
    (void)seq;
    done;
}

//  Fork spot + graf in parallel against the worktree's current tip
//  (via `--at`).  Used by verbs that move a ref locally — post,
//  patch — so the user-facing indexes stay current without a manual
//  `be get` step.  `be_at_buf` is refreshed from `.sniff` first
//  (the calling verb may have just moved the tip).
static ok64 be_reindex(cli *c) {
    sane(c);
    //  Re-derive the wt root: a post that just bootstrapped a fresh
    //  `.dogs/` (`be post` in an empty dir) leaves `c->repo` empty
    //  because CLIParse's cwd-walk happened before the post created
    //  the store.  Walk again here so SNIFFAtTailOf can read `.sniff`.
    u8cs repo = {};
    if ($ok(c->repo) && !u8csEmpty(c->repo)) {
        $mv(repo, c->repo);
    } else {
        home rh = {};
        uri none = {};
        if (HOMEOpen(&rh, &none, NO) == OK) {
            //  HOMEOpen owns its `rh` storage; copy the slice into the
            //  cli's `_repo` buffer (still alive on the parent stack)
            //  and re-export via c->repo.
            size_t rlen = u8bDataLen(rh.root);
            if (rlen >= sizeof(c->_repo)) rlen = sizeof(c->_repo) - 1;
            memcpy(c->_repo, u8bDataHead(rh.root), rlen);
            c->_repo[rlen] = 0;
            c->repo[0] = (u8cp)c->_repo;
            c->repo[1] = (u8cp)c->_repo + rlen;
            $mv(repo, c->repo);
        }
        HOMEClose(&rh);
    }
    if (!u8csEmpty(repo)) {
        u8bReset(be_at_buf);
        (void)SNIFFAtTailOf(repo, be_at_buf);
    }
    static u8c const spot_lit[] = "spot";
    static u8c const graf_lit[] = "graf";
    u8cs const dogs[2] = {
        {spot_lit, spot_lit + 4},
        {graf_lit, graf_lit + 4},
    };
    a_cstr(get_s, "get");

    pid_t pids[2] = {0};
    ok64  spawn_err[2] = {OK, OK};
    for (int i = 0; i < 2; i++) {
        a_pad(u8cs, args, 4);
        a_dup(u8c, dog_d, dogs[i]);
        a_dup(u8c, get_d, get_s);
        u8csbFeed1(args, dog_d);
        u8csbFeed1(args, get_d);
        if (u8bDataLen(be_at_buf) > 0) {
            a_dup(u8c, at_flag, be_at_flag);
            a_dup(u8c, at_val,  u8bData(be_at_buf));
            u8csbFeed1(args, at_flag);
            u8csbFeed1(args, at_val);
        }
        a_dup(u8cs, argv, u8csbData(args));
        spawn_err[i] = BESpawn(dog_d, argv, &pids[i]);
    }
    ok64 worst = OK;
    for (int i = 0; i < 2; i++) {
        if (spawn_err[i] != OK) { worst = spawn_err[i]; continue; }
        a_dup(u8c, dog_d, dogs[i]);
        ok64 r = BEReap(pids[i], dog_d);
        if (r != OK) worst = r;
    }
    return worst;
}

//  `be put` is the ref-writer (VERBS.md §"PUT").  Per the URI's
//  `//remote` slot it also doubles as the FF-push verb — the wire
//  side maps to keeper's old `post` (push) entry point.  Local
//  shapes (label move, file staging, sha reset) stay in sniff put.
static ok64 BEPut(cli *c, b8 seq) {
    sane(c);
    b8 has_remote = NO;
    for (u32 i = 0; i < c->nuris; i++) {
        if (!u8csEmpty(c->uris[i].authority)) { has_remote = YES; break; }
    }
    if (has_remote) {
        //  FF-push: `be put //origin` (cached) and `be put ssh://host`
        //  (transport) both open the wire — VERBS.md §"Schemes —
        //  cached vs transport" carves out PUT-to-remote as the one
        //  cached-form write-through.
        static dog_step const push_steps[] = {
            {u8slit("keeper"), u8slit("post"), NO},
        };
        return BEDispatch(c, push_steps, 1, seq);
    }
    static dog_step const local_steps[] = {
        {u8slit("sniff"),  u8slit("put"), NO},
    };
    return BEDispatch(c, local_steps, 1, seq);
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

//  Ref-expecting verbs (post, patch) may read path/fragment as the query
//  when it fits QURY's
//  ref grammar — `be post feat` (path) and `be post '#feat'` (fragment)
//  both yield query=feat.  Promotion only happens when query is empty
//  (caller hasn't explicitly set a ref).  Returns YES if anything moved.
static b8 be_promote_to_ref(uri *u) {
    //  Legacy: a URILexer-produced path that matches QURY ref grammar
    //  (e.g. `be get feat/sub` → path="feat/sub") gets routed to the
    //  query slot.  Bareword promotion is now handled centrally by
    //  DOGPromoteBareword in becli() per VERBS.md §"Bareword
    //  defaults"; the fragment→query branch was removed so POST's
    //  fragment-default (`be post fix` ⇒ msg="fix") survives.
    if (!$empty(u->query)) return NO;
    qref qr = {};
    if (!$empty(u->path)) {
        u8cs s = {u->path[0], u->path[1]};
        if (QURYu8sDrain(s, &qr) == OK &&
            (qr.type == QURY_REF || qr.type == QURY_SHA)) {
            u8csMv(u->query, s);
            u->path[0] = u->path[1] = NULL;
            return YES;
        }
    }
    return NO;
}

//  `be patch <uri>` — 3-way merge `uri`'s target ref/sha into the
//  worktree.  If the URI has an authority we first `keeper get` to
//  fetch the target's reachable closure, then hand off to
//  `sniff patch`.  See VERBS.md §PATCH.
static ok64 BEPatch(cli *c, b8 seq) {
    sane(c);
    //  PATCH is ref-expecting (absorbs another branch's stack): promote
    //  bare `be patch feat` to query=feat just like POST.
    for (u32 i = 0; i < c->nuris; i++) be_promote_to_ref(&c->uris[i]);
    static dog_step const steps[] = {
        {u8slit("keeper"), u8slit("get"),   NO},
        {u8slit("sniff"),  u8slit("patch"), NO},
    };
    u32 nsteps = sizeof(steps) / sizeof(steps[0]);
    uri *u = (c->nuris > 0) ? &c->uris[0] : NULL;
    u32 start = (u != NULL && !$empty(u->authority)) ? 0 : 1;
    call(BEDispatch, c, steps + start, nsteps - start, seq);
    //  Patch may move the wt's HEAD via 3-way merge; refresh spot+graf.
    (void)be_reindex(c);
    done;
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
        //  POST is ref-expecting: bare `be post feat` should target ref
        //  feat, not be rejected as path-form.  Promote first.
        be_promote_to_ref(u);
        //  Pure-fragment URIs (commit-message via `#msg` or whitespace
        //  arg) — skip the path-form check, they're message-only.
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
    b8 has_remote    = NO;
    b8 has_transport = NO;
    for (u32 i = 0; i < c->nuris; i++) {
        if (!u8csEmpty(c->uris[i].authority)) has_remote = YES;
        if (!u8csEmpty(c->uris[i].scheme))    has_transport = YES;
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
    //  Per VERBS.md §"POST" + §"Schemes — cached vs transport":
    //    `be post //origin`     — rebase cur onto cached origin tip.
    //    `be post ssh://origin` — fetch refs+pack first, then rebase.
    //    `be post //origin?br`  — same but scoped to remote's ?br.
    //    `be post ?br`          — rebase cur onto local ?br.
    //    `be post '#msg'`       — commit on cur.
    //  Push lives under `be put //origin` (VERBS.md §"PUT"), not POST.
    //  POST never produces a commit on a non-cur branch.
    dog_step steps[4];
    u32 nsteps = 0;
    //  Step 1 (transport-scheme remote only): keeper get URI to fetch
    //  refs+pack, refreshing `.dogs/refs` for the rebase that follows.
    if (has_transport && has_remote) {
        steps[nsteps++] = (dog_step){u8slit("keeper"), u8slit("get"), NO};
    }
    //  Step 2 (any remote): graf get URI to walk the (possibly newly
    //  fetched) commit DAG into graf's index — sniff's POSTRebaseOntoSha
    //  calls GRAFLca, which fails (returns 0) if either tip's ancestor
    //  set isn't indexed.  No-op when the URI's commits are already in
    //  graf's index.
    if (has_remote) {
        steps[nsteps++] = (dog_step){u8slit("graf"),   u8slit("get"), NO};
    }
    //  Step 3: sniff post — handles the commit / ff / rebase per the
    //  URI shape it sees.  When `//remote` is present sniff resolves
    //  it to the cached tracking ref and rebases cur on top.
    b8 ran_sniff = NO;
    if (has_msg || c->nuris > 0 || !has_remote) {
        steps[nsteps++] = (dog_step){u8slit("sniff"),  u8slit("post"), NO};
        ran_sniff = YES;
    }
    call(BEDispatch, c, steps, nsteps, seq);

    //  Local reindex: a successful sniff post moved the wt's HEAD;
    //  refresh spot/graf so subsequent log/diff/search see the new
    //  tip without a manual `be get`.  Skip the bare-dry-run case
    //  (no commit, no message, no URI) — sniff just printed the
    //  would-be change-set and `.sniff` baseline is unchanged.
    b8 dry_run = !has_msg && c->nuris == 0;
    if (ran_sniff && !dry_run) (void)be_reindex(c);
    done;
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

    //  Per-verb bareword default (VERBS.md §"Bareword defaults"):
    //  promote a bareword sitting in u->path into the verb's natural
    //  slot.  POST → fragment (commit msg); GET / HEAD / PATCH →
    //  query (branch); PUT / DELETE / verbless → path (no-op).  When
    //  a promotion fires we also rewrite u->data with a leading `?`
    //  or `#` so be_build_argv forwards a URI shape that sub-dogs
    //  re-parse the same way (no second round of bareword promotion
    //  at the sub-dog layer).  Bareword bytes get packed into one
    //  scratch buffer that lives for becli's full frame (covers the
    //  later BEDispatch → be_build_argv hand-off).
    a_pad(u8, bareword_scratch, CLI_MAX_URIS * 65);
    {
        u8 def = 'p';
        if (!$empty(c.verb)) {
            a_cstr(_v_post,  "post");
            a_cstr(_v_get,   "get");
            a_cstr(_v_head,  "head");
            a_cstr(_v_patch, "patch");
            a_cstr(_v_diff,  "diff");
            if      ($eq(c.verb, _v_post))  def = 'f';
            else if ($eq(c.verb, _v_get))   def = 'q';
            else if ($eq(c.verb, _v_head))  def = 'q';
            else if ($eq(c.verb, _v_patch)) def = 'q';
            else if ($eq(c.verb, _v_diff))  def = 'q';
        }
        if (def != 'p') {
            for (u32 i = 0; i < c.nuris; i++) {
                uri *u = &c.uris[i];
                u8cs orig_path = {u->path[0], u->path[1]};
                ok64 pr = DOGPromoteBareword(u, def);
                if (pr != OK) continue;
                if (u->path[0] != NULL) continue;        // not promoted
                if (u8csEmpty(orig_path)) continue;
                u8c *before = *u8bIdle(bareword_scratch);
                if (u8bFeed1(bareword_scratch,
                             (def == 'q') ? '?' : '#') != OK) continue;
                if (u8bFeed(bareword_scratch, orig_path) != OK) continue;
                u8c *after = *u8bIdle(bareword_scratch);
                u->data[0] = before;
                u->data[1] = after;
            }
        }
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
    a_cstr(v_head,   "head");
    a_cstr(v_get,    "get");    a_cstr(v_put,    "put");
    a_cstr(v_post,   "post");   a_cstr(v_delete, "delete");
    a_cstr(v_diff,   "diff");   a_cstr(v_patch,  "patch");
    a_cstr(v_merge,  "merge");  a_cstr(v_sync,   "sync");
    a_cstr(v_status, "status");

    u8cs verb = {};
    $mv(verb, c.verb);

    // Get first URI if available
    uri *u = (c.nuris > 0) ? &c.uris[0] : NULL;

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

    // No verb → view/file mode.  Projector schemes (spot:, grep:, regex:,
    // ls:, tree:, …) were already routed through BEProjector above; here
    // a bare path-shaped URI displays the file via bro.  Search has no
    // implicit `#frag` form anymore — use `be spot:body`, `be grep:body`,
    // `be regex:body` (VERBS.md §"View projectors").
    if ($empty(verb)) {
        u8cs bro  = u8slit("bro");
        if (u != NULL && !$empty(u->path)) {
            a_pad(u8cs, args, 2);
            u8csbFeed1(args, bro);
            u8csbFeed1(args, u->data);
            a_dup(u8cs, argv, u8csbData(args));
            call(BERun, bro, argv, NO);
        } else {
            call(BEDefault);
        }
    } else if ($eq(verb, v_head)) {
        call(BEHead, &c, seq);
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
