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
#include "abc/RON.h"
#include "dog/DOG.h"
#include "dog/HOME.h"
#include "dog/QURY.h"
#include "keeper/REFS.h"
#include "sniff/AT.h"
#include "sniff/SUBS.h"

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
static ok64 be_ensure_repo(void);
static ok64 be_sub_shard_setup(cli *c, uri *u);

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
static ok64 BERunPipe(path8sc prod, u8css prod_argv,
                      path8sc pager, u8css pager_argv) {
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
//  `becli` from `<cwd>/.be/wtlog` via `SNIFFAtTailOf`; empty when no
//  `.be/wtlog` is present (fresh dir / pre-clone bootstrap), in which
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
static void be_build_argv(u8csb args, u8csc dog, u8csc verb, cli *c) {
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
//  Static storage for the rewritten URI after a worktree is wired up:
//  "?<6..40-hex-hashlet>" points every downstream dog at the primary's
//  HEAD.  Re-filled on each BEGetWorktree call.
static u8  wt_uri_storage[64];
static Bu8 wt_uri_buf = {
    wt_uri_storage, wt_uri_storage,
    wt_uri_storage,
    wt_uri_storage + sizeof(wt_uri_storage)
};

static b8 be_promote_to_ref(uri *u);

static ok64 BEGetWorktree(uri *u) {
    sane(1);
    if (u == NULL || !u8csEmpty(u->authority)) done;
    if (u8csEmpty(u->path)) done;

    // Primary candidate has to be an existing dir containing .be/.
    a_dup(u8c, prim_s, u->path);
    a_path(prim_be, prim_s, DOG_BE_S);
    if (FILEisdir($path(prim_be)) != OK) done;

    // Skip if cwd already has a .be (dir, symlink, or wtlog file).
    a_path(cwd);
    call(FILEGetCwd, cwd);
    a_path(cwd_be);
    a_dup(u8c, cwd_s, u8bDataC(cwd));
    call(PATHu8bFeed, cwd_be, cwd_s);
    call(PATHu8bPush, cwd_be, DOG_BE_S);
    {
        filestat fs = {};
        if (FILELStat(&fs, $path(cwd_be)) == OK) done;
    }

    // Worktree layout: secondary wt has `<wt>/.be` as a REGULAR FILE
    // (= its own wtlog).  Row 0's `repo` URI names the primary's
    // `.be/`, so keeper/graf/spot reach the shared store via that
    // anchor.  We seed the file with a single `repo` row pointing at
    // the primary, then sniff's row-0 read on the next open redirects
    // h->root automatically.
    {
        int fd = FILE_CLOSED;
        ok64 co = FILECreate(&fd, $path(cwd_be));
        if (co != OK) return co;

        a_path(repo_uri);
        a_cstr(file_pref, "file://");
        call(u8bFeed, repo_uri, file_pref);
        call(u8bFeed, repo_uri, prim_s);
        call(u8bFeed1, repo_uri, '/');
        call(u8bFeed, repo_uri, DOG_BE_S);
        call(u8bFeed1, repo_uri, '/');

        //  Compose the row body: `<ts>\trepo\t<uri>\n`.  ts =
        //  RONNow(); verb = `repo`; uri = file:///<prim>/.be/.
        a_pad(u8, row, 1024);
        ron60 ts = RONNow();
        call(RONutf8sFeed, u8bIdle(row), ts);
        call(u8bFeed1, row, '\t');
        a_cstr(repo_verb, "repo");
        call(u8bFeed, row, repo_verb);
        call(u8bFeed1, row, '\t');
        call(u8bFeed, row, u8bDataC(repo_uri));
        call(u8bFeed1, row, '\n');

        a_dup(u8c, rowbytes, u8bData(row));
        (void)FILEFeedAll(fd, rowbytes);
        FILEClose(&fd);
    }

    fprintf(stderr, "be: worktree from %.*s\n",
            (int)$len(u->path), (char *)u->path[0]);

    // Resolve the primary's current commit via its wtlog.
    // Rewrite this URI to "?<sha>" so downstream sniff checks out
    // that commit in the worktree.
    a_pad(u8, prim_at, FILE_PATH_MAX_LEN + 128);
    a_dup(u8c, prim_root, prim_s);
    if (SNIFFAtTailOf(prim_root, prim_at) != OK) done;
    uri prim_uri = {};
    u8csMv(prim_uri.data, u8bDataC(prim_at));
    URILexer(&prim_uri);
    //  Hashlet: 6..40 hex chars (full sha1 = 40, prefix abbreviations
    //  shorter).  Anything outside that range is not a valid pin.
    size_t flen = u8csLen(prim_uri.fragment);
    if (flen < 6 || flen > 40) done;

    //  Compose "?<hashlet>" into the static buffer; expose data and
    //  query slices into it (other URI components stay empty).
    u8bReset(wt_uri_buf);
    call(u8bFeed1, wt_uri_buf, '?');
    call(u8bFeed,  wt_uri_buf, prim_uri.fragment);

    zerop(u);
    u8csMv(u->data,  u8bDataC(wt_uri_buf));
    u8csMv(u->query, u->data);
    u8csUsed1(u->query);  //  drop leading '?'
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

    //  `--color` (alias `--ansi`) forces the bro pager pipeline even
    //  when stdout is not a terminal — useful for capturing the
    //  ANSI-coloured renderer output (vs. the plain unified-diff text
    //  that graf emits when piped).  Bro reads BRO_COLOR=1 from the
    //  environment and uses BROPlain to one-shot dump ANSI when its
    //  own stdout is non-TTY.
    b8 force_color = CLIHas(c, "--color") || CLIHas(c, "--ansi");
    if (force_color) setenv("BRO_COLOR", "1", 1);
    b8 tty = (isatty(STDOUT_FILENO) || force_color) ? YES : NO;

    a_path(dogpath);
    a$rg(a0, 0);
    HOMEResolveSibling(NULL, dogpath, dog_s, a0);

    //  Verbless: dog argv is `<dog> [--at <uri>] [--tlv] <URI>`.  The
    //  dog sees the URI with its projector scheme intact and dispatches
    //  on u->scheme inside its own CLI.  `--at` carries the wt's tip
    //  so the projector (graf map / log "you are here", etc.) doesn't
    //  need to poke at `.be/wtlog` itself.
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
//       writes the pack to .be, builds keeper's own index.
//    2. spot get URI, graf get URI, sniff get URI — in parallel.
//       Each dog opens keeper read-only, walks the URI's tip(s), and
//       updates its own state (spot/graf indexes; sniff worktree).
//
//  `--seq` (debugging) collapses step 2 to sequential keeper-order
//  execution — same dispatch shape as the other verbs.
//
//  Pre-flight: URI normalisation (worktree wiring + fresh-clone
//  .be/ bootstrap so the downstream dogs have a place to land).
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
    //  without touching `.be/wtlog` (no `get`/`put` row appended).
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

    //  Auto-bootstrap: GET is a writer (advances cur, stamps files,
    //  appends a `get` row), so it needs `.be/` markers like PUT/POST.
    //  Covers both the fresh-clone (remote) and the local
    //  `be get ?branch` on an empty dir cases.
    call(be_ensure_repo);

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
//    - `ssh://host` (transport)   — fetch refs+pack, update .be/refs,
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
//  `.be/refs` and the pack data added to keeper.
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

    //  Transport scheme: forward to keeper get (fetches refs + pack),
    //  then spot get + graf get in parallel so the freshly-pulled
    //  commits + trees + blobs get indexed for downstream walks
    //  (`be log:`, `be patch`, `be spot ...`).  Per VERBS.md §HEAD,
    //  HEAD with a transport scheme updates `.be/refs` and pulls a
    //  pack; without the indexing chain, `be log:` on the fetched
    //  history would walk only as far as graf's DAG already knew.
    //
    //  `?*` wildcard query (`be head ssh://origin?*`) routes to keeper
    //  get just like a single-ref form — keeper detects the literal
    //  `*` and runs the bulk-fetch (advertise + multi-want) path.
    if (transport || cached) {
        a_cstr(get_s,    "get");

        //  Step 1: keeper get URI — synchronous.
        {
            a_pad(u8cs, args, 4 + CLI_MAX_FLAGS * 2 + CLI_MAX_URIS);
            a_cstr(keeper_s, "keeper");
            a_dup(u8c, keeper_d, keeper_s);
            a_dup(u8c, get_d,    get_s);
            be_build_argv(args, keeper_d, get_d, c);
            a_dup(u8cs, argv, u8csbData(args));
            call(BERun, keeper_d, argv, NO);
        }

        //  Step 2: graf + spot get URI in parallel.  HEAD is read-
        //  only so sniff is NOT included (no wt change, no get row).
        //  Mirrors BEGet's parallel pattern minus sniff.
        static u8c const graf_lit[] = "graf";
        static u8c const spot_lit[] = "spot";
        u8cs const dogs[2] = {
            {graf_lit, graf_lit + 4},
            {spot_lit, spot_lit + 4},
        };

        if (seq) {
            for (int i = 0; i < 2; i++) {
                a_pad(u8cs, args, 4 + CLI_MAX_FLAGS * 2 + CLI_MAX_URIS);
                a_dup(u8c, dog_d, dogs[i]);
                a_dup(u8c, get_d2, get_s);
                be_build_argv(args, dog_d, get_d2, c);
                a_dup(u8cs, argv, u8csbData(args));
                call(BERun, dog_d, argv, NO);
            }
            done;
        }

        pid_t pids[2] = {0};
        ok64  spawn_err[2] = {OK, OK};
        for (int i = 0; i < 2; i++) {
            a_pad(u8cs, args, 4 + CLI_MAX_FLAGS * 2 + CLI_MAX_URIS);
            a_dup(u8c, dog_d, dogs[i]);
            a_dup(u8c, get_d2, get_s);
            be_build_argv(args, dog_d, get_d2, c);
            a_dup(u8cs, argv, u8csbData(args));
            spawn_err[i] = BESpawn(dog_d, argv, &pids[i]);
            if (spawn_err[i] != OK) {
                fprintf(stderr, "be: spawn " U8SFMT ": %s\n",
                        u8sFmt(dog_d), ok64str(spawn_err[i]));
            }
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
//  `be get` step.  `be_at_buf` is refreshed from `.be/wtlog` first
//  (the calling verb may have just moved the tip).
static ok64 be_reindex(cli *c) {
    sane(c);
    //  Re-derive the wt root: a post that just bootstrapped a fresh
    //  `.be/` (`be post` in an empty dir) leaves `c->repo` empty
    //  because CLIParse's cwd-walk happened before the post created
    //  the store.  Walk again here so SNIFFAtTailOf can read `.be/wtlog`.
    u8cs repo = {};
    if (u8bHasData(c->repo)) {
        u8csMv(repo, $path(c->repo));
    } else {
        home rh = {};
        uri none = {};
        if (HOMEOpen(&rh, &none, NO) == OK) {
            //  HOMEOpen owns its `rh` storage; feed it into the cli's
            //  path8b (NUL-terminated by construction) for re-export.
            (void)PATHu8bFeed(c->repo, u8bDataC(rh.root));
            if (u8bHasData(c->repo)) u8csMv(repo, $path(c->repo));
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

//  Repo bootstrap: when no `.be/` is reachable from cwd, lay down
//  the empty markers `<cwd>/.be/refs` and `<cwd>/.be/wtlog` so the
//  HOME walk-up succeeds for downstream dogs.  No-op when an existing
//  repo is already in scope.  Both ULOGs grow append-only so an empty
//  file is the well-defined "no rows yet" state.
static ok64 be_ensure_repo(void) {
    sane(1);
    {
        home probe = {};
        uri none = {};
        ok64 ho = HOMEOpen(&probe, &none, NO);
        HOMEClose(&probe);
        if (ho == OK) done;
    }
    a_path(here);
    call(FILEGetCwd, here);
    a_dup(u8c, here_s, u8bDataC(here));
    a_path(be_dir);
    call(PATHu8bFeed, be_dir, here_s);
    call(PATHu8bPush, be_dir, DOG_BE_S);
    call(FILEMakeDirP, $path(be_dir));
    {
        a_path(refs_path);
        a_dup(u8c, be_s, u8bDataC(be_dir));
        call(PATHu8bFeed, refs_path, be_s);
        call(PATHu8bPush, refs_path, DOG_REFS_S);
        int fd = -1;
        call(FILECreate, &fd, $path(refs_path));
        call(FILEClose, &fd);
    }
    {
        a_path(wtlog_path);
        a_dup(u8c, be_s, u8bDataC(be_dir));
        call(PATHu8bFeed, wtlog_path, be_s);
        call(PATHu8bPush, wtlog_path, DOG_WTLOG_S);
        int fd = -1;
        call(FILECreate, &fd, $path(wtlog_path));
        call(FILEClose, &fd);
    }
    done;
}

//  Subdir-of-existing-repo + remote clone = treat cwd as a submodule
//  worktree of a fresh shard under the ancestor's `.be/`.
//
//  Layout (matches "/.be/ is the trunk shard; non-trunk shards mention
//  the path .../.be/<shard>"):
//
//      <parent_root>/.be/                          parent's trunk shard
//      <parent_root>/.be/<basename>/.be/           sub's own store
//          ├── refs                                (empty markers)
//          └── wtlog
//      <cwd>/.be                                   regular FILE anchor
//          └── <ts>\trepo\tfile:<parent>/.be/<basename>/.be/\n
//
//  Walk-up from any path inside cwd then resolves to the sub's store
//  (via the anchor file's row-0), so keeper / sniff / graf / spot all
//  open the shard cleanly without colliding with the parent's keeper.
//
//  After setup we rewrite c->repo to cwd so the be_at_buf fill below
//  reads the freshly-minted (empty) shard wtlog, not the parent's.
static ok64 be_sub_shard_setup(cli *c, uri *u) {
    sane(c && u);

    //  Only fires when CLIParse walked up to an ancestor (c->repo
    //  non-empty) and cwd is a strict subdir of it.  Pure remote
    //  clones only — `?ref` / `#sha` / projector forms are handled
    //  by the normal in-repo path.
    if (!u8bHasData(c->repo)) done;
    if (u8csEmpty(u->authority)) done;

    a_path(cwd);
    call(FILEGetCwd, cwd);
    a_dup(u8c, cwd_s,  u8bDataC(cwd));
    a_dup(u8c, repo_s, u8bDataC(c->repo));
    if (u8csEq(cwd_s, repo_s)) done;             // not a subdir
    if (u8csLen(cwd_s) <= u8csLen(repo_s)) done;
    if (!u8csHasPrefix(cwd_s, repo_s)) done;
    //  Boundary check: cwd must continue into repo with a '/' so a
    //  cousin named `<repo>x/…` doesn't masquerade as a subdir.
    if (cwd_s[0][u8csLen(repo_s)] != '/') done;

    //  Refuse to clobber an existing `<cwd>/.be` — either anchor file
    //  or store dir.  A stale one means the user already mounted here
    //  and a fresh shard would orphan the previous state.
    a_path(cwd_be);
    call(PATHu8bFeed, cwd_be, cwd_s);
    call(PATHu8bPush, cwd_be, DOG_BE_S);
    {
        filestat fs = {};
        if (FILELStat(&fs, $path(cwd_be)) == OK) done;
    }

    //  Derive shard name from the URL basename — same rule the
    //  .gitmodules-driven sub-mount uses (sniff/SUBS.c).
    a_dup(u8c, url_d, u->data);
    u8cs basename = {};
    call(SNIFFSubBasename, url_d, basename);

    //  mkdir <parent>/.be/<basename>/.be/
    a_path(shard_be);
    call(PATHu8bFeed, shard_be, repo_s);
    call(PATHu8bPush, shard_be, DOG_BE_S);
    a_dup(u8c, base_s, basename);
    call(PATHu8bPush, shard_be, base_s);
    a_path(shard_root);
    a_dup(u8c, sr_pre, u8bDataC(shard_be));
    call(PATHu8bFeed, shard_root, sr_pre);
    call(PATHu8bPush, shard_be, DOG_BE_S);
    call(FILEMakeDirP, $path(shard_be));

    //  Seed empty refs + wtlog so HOME walk-up finds a well-formed
    //  store on first open.
    {
        a_path(p);
        a_dup(u8c, s, u8bDataC(shard_be));
        call(PATHu8bFeed, p, s);
        call(PATHu8bPush, p, DOG_REFS_S);
        int fd = -1;
        call(FILECreate, &fd, $path(p));
        call(FILEClose, &fd);
    }
    {
        a_path(p);
        a_dup(u8c, s, u8bDataC(shard_be));
        call(PATHu8bFeed, p, s);
        call(PATHu8bPush, p, DOG_WTLOG_S);
        int fd = -1;
        call(FILECreate, &fd, $path(p));
        call(FILEClose, &fd);
    }

    //  Compose row-0 URI: `file:<shard_root>/.be/`.  Routed through
    //  URIutf8Feed so the bytes match `sniff_write_repo_row`'s output
    //  shape (single slash after `file:`, trailing slash on path).
    a_path(uri_path);
    a_dup(u8c, sr_s, u8bDataC(shard_be));
    call(PATHu8bFeed, uri_path, sr_s);
    call(u8bFeed1, uri_path, '/');
    call(PATHu8bTerm, uri_path);

    uri urow = {};
    a_cstr(scheme_s, "file");
    urow.scheme[0] = scheme_s[0];
    urow.scheme[1] = scheme_s[1];
    {
        a_dup(u8c, p, u8bData(uri_path));
        urow.path[0] = p[0];
        urow.path[1] = p[1];
    }

    a_pad(u8, row, 1024);
    ron60 ts = RONNow();
    call(RONutf8sFeed, u8bIdle(row), ts);
    call(u8bFeed1, row, '\t');
    a_cstr(repo_verb, "repo");
    call(u8bFeed, row, repo_verb);
    call(u8bFeed1, row, '\t');
    call(URIutf8Feed, u8bIdle(row), &urow);
    call(u8bFeed1, row, '\n');

    int fd = -1;
    call(FILECreate, &fd, $path(cwd_be));
    a_dup(u8c, body, u8bData(row));
    call(FILEFeedAll, fd, body);
    FILEClose(&fd);

    //  Re-anchor c->repo at cwd so the be_at_buf fill (and any later
    //  c->repo readers) see the sub, not the parent.
    u8bReset(c->repo);
    call(PATHu8bFeed, c->repo, cwd_s);

    fprintf(stderr, "be: subdir clone — shard at %.*s/.be/%.*s\n",
            (int)$len(repo_s),   (char *)repo_s[0],
            (int)$len(basename), (char *)basename[0]);
    done;
}

//  `be put` is the ref-writer (VERBS.md §"PUT").  Per the URI's
//  `//remote` slot it also doubles as the FF-push verb — the wire
//  side maps to keeper's old `post` (push) entry point.  Local
//  shapes (label move, file staging, sha reset) stay in sniff put.
//
//  PUT also doubles as the repo-init verb: when nothing is reachable
//  from cwd it lays down the canonical `.be/refs` + `.be/wtlog`
//  markers so the dispatched sniff-put has a HOME to walk into.
static ok64 BEPut(cli *c, b8 seq) {
    sane(c);
    b8 has_remote = NO;
    for (u32 i = 0; i < c->nuris; i++) {
        if (!u8csEmpty(c->uris[i].authority)) { has_remote = YES; break; }
    }
    if (!has_remote) call(be_ensure_repo);
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
//  `be delete <uri>` per VERBS.md §DELETE.  Local URIs (paths or
//  `?branch`) are sniff's job — DELStage / DELBranch.  Remote URIs
//  (`//host` cached or transport-scheme) open the wire / drop the
//  alias; both arms live in `keeper delete`.  Mixing local + remote
//  URIs in one invocation is rejected by the all-or-nothing branch
//  taken on the first authority-bearing URI — the verbs are too
//  different to interleave coherently.
static ok64 BEDelete(cli *c, b8 seq) {
    sane(c);
    b8 has_remote = NO;
    for (u32 i = 0; i < c->nuris; i++) {
        if (!u8csEmpty(c->uris[i].authority)) { has_remote = YES; break; }
    }
    //  Local-only DELETE on a fresh dir is an edge case but the test
    //  surface expects auto-bootstrap parity with PUT/POST.
    if (!has_remote) call(be_ensure_repo);
    if (has_remote) {
        static dog_step const remote_steps[] = {
            {u8slit("keeper"), u8slit("delete"), NO},
        };
        return BEDispatch(c, remote_steps, 1, seq);
    }
    static dog_step const local_steps[] = {
        {u8slit("sniff"),  u8slit("delete"), NO},
    };
    return BEDispatch(c, local_steps, 1, seq);
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
//  worktree.  Steps:
//    1. (transport-scheme remote only) keeper get URI to fetch
//       refs+pack, refreshing `.be/refs` and seeding keeper with
//       the target commit's reachable closure.
//    2. (any remote) graf get URI to walk the (possibly newly
//       fetched) commits into graf's DAG index — sniff's PATCH
//       calls GRAFLca / GRAFResolveTip, which fail if the target's
//       ancestor set isn't indexed.  No-op when the URI's commits
//       are already in graf's index.  Mirrors the equivalent step
//       in BEPost.  Without this, a remote `be patch ssh://host?<sha>`
//       reports GRAFFAIL even though the pack data sits in keeper.
//    3. sniff patch — performs the 3-way merge into the wt.
//  See VERBS.md §PATCH.
static ok64 BEPatch(cli *c, b8 seq) {
    sane(c);
    //  PATCH is ref-expecting (absorbs another branch's stack): promote
    //  bare `be patch feat` to query=feat just like POST.
    for (u32 i = 0; i < c->nuris; i++) be_promote_to_ref(&c->uris[i]);
    //  Auto-bootstrap parity with PUT/POST — local PATCH on a fresh
    //  dir needs the same `.be/` markers downstream.
    b8 has_remote = NO, has_transport = NO;
    for (u32 i = 0; i < c->nuris; i++) {
        if (!u8csEmpty(c->uris[i].authority)) has_remote = YES;
        if (!u8csEmpty(c->uris[i].scheme))    has_transport = YES;
    }
    if (!has_remote) call(be_ensure_repo);

    dog_step steps[3];
    u32 nsteps = 0;
    if (has_transport && has_remote) {
        steps[nsteps++] = (dog_step){u8slit("keeper"), u8slit("get"), NO};
    }
    if (has_remote) {
        steps[nsteps++] = (dog_step){u8slit("graf"),   u8slit("get"), NO};
    }
    steps[nsteps++] = (dog_step){u8slit("sniff"),  u8slit("patch"), NO};
    call(BEDispatch, c, steps, nsteps, seq);
    //  Patch may move the wt's HEAD via 3-way merge; refresh spot+graf.
    (void)be_reindex(c);
    done;
}

//  `be post` — commit and/or fast-forward (never rebase; see VERBS.md
//  §POST).  Rebase is `be patch ?br#` + `be post`, looped.
//    <free-form tail> → fragment carries the commit message; sniff
//                       commits on cur.  (Legacy `-m <msg>` flag still
//                       works as a fallback.)
//    ?<branch>        → FF-advance ?branch to cur's (post-commit) tip;
//                       refused (POSTNOFF) if cur isn't a descendant.
//    //<host>[?<ref>] → keeper FF-pushes cur's tip to the remote's
//                       counterpart; refused if not a fast-forward.
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
    //  Auto-bootstrap: `be post 'msg'` on a fresh dir is the
    //  canonical "init + first commit" path (see workflow.sh §1).
    //  Mirrors BEPut's call to be_ensure_repo; only meaningful when
    //  there's no remote authority (push targets always have a repo).
    b8 has_remote_pre = NO;
    for (u32 i = 0; i < c->nuris; i++) {
        if (!u8csEmpty(c->uris[i].authority)) {
            has_remote_pre = YES; break;
        }
    }
    if (!has_remote_pre) call(be_ensure_repo);
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
    //  Per VERBS.md §POST:
    //    `be post '#msg'`           — commit on cur.
    //    `be post ?br`              — commit on cur, then FF-advance ?br
    //                                 to cur.tip (POSTPromote inside sniff).
    //    `be post //origin '#msg'`  — commit on cur, then FF-push cur's
    //    `be post ssh://origin '#msg'` new tip to origin's counterpart.
    //  POST never rewrites cur (rebase is `be patch ?br#` + `be post`).
    //  Pure pushes (no commit) belong to PUT (`be put //origin`).  POST
    //  with `//remote` but no commit content refuses via POSTNONE.
    dog_step steps[2];
    u32 nsteps = 0;
    //  Step 1: sniff post — commit-on-cur + optional ?branch promote.
    //  Skip only the bare-status case (no msg, no URIs): there's
    //  nothing to commit and sniff would just dry-run.
    b8 ran_sniff = NO;
    if (has_msg || c->nuris > 0 || !has_remote) {
        steps[nsteps++] = (dog_step){u8slit("sniff"),  u8slit("post"), NO};
        ran_sniff = YES;
    }
    //  Step 2: keeper post — FF-push cur's new tip to remote.  Picks
    //  up the post-commit `--at <root>?<branch>#<sha>` injected by `be`
    //  between dispatch steps so the wire side knows what tip to send.
    //  No transport scheme on `//remote`: keeper_post resolves the
    //  authority via REFSResolve (alias table) and opens the wire.
    if (has_remote) {
        steps[nsteps++] = (dog_step){u8slit("keeper"), u8slit("post"), NO};
    }
    call(BEDispatch, c, steps, nsteps, seq);

    //  Local reindex: a successful sniff post moved the wt's HEAD;
    //  refresh spot/graf so subsequent log/diff/search see the new
    //  tip without a manual `be get`.  Skip the bare-dry-run case
    //  (no commit, no message, no URI) — sniff just printed the
    //  would-be change-set and `.be/wtlog` baseline is unchanged.
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

static ok64 becli_inner(cli *c) {
    sane(c);
    call(FILEInit);

    //  -m / --author take a following value (legacy commit-message
    //  flag — the new convention is to fold trailing words into the
    //  URI fragment, but `-m` remains accepted).
    call(CLIParse, c, BE_VERB_NAMES, "-m\0--author\0");

    if (CLIHas(c, "-h") || CLIHas(c, "--help")) {
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
        if (!$empty(c->verb)) {
            a_cstr(_v_post,  "post");
            a_cstr(_v_get,   "get");
            a_cstr(_v_head,  "head");
            a_cstr(_v_patch, "patch");
            a_cstr(_v_diff,  "diff");
            if      ($eq(c->verb, _v_post))  def = 'f';
            else if ($eq(c->verb, _v_get))   def = 'q';
            else if ($eq(c->verb, _v_head))  def = 'q';
            else if ($eq(c->verb, _v_patch)) def = 'q';
            else if ($eq(c->verb, _v_diff))  def = 'q';
        }
        if (def != 'p') {
            for (u32 i = 0; i < c->nuris; i++) {
                uri *u = &c->uris[i];
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

    //  Subdir-of-existing-repo + remote `be get`: drop a fresh shard
    //  under the ancestor's `.be/` and anchor cwd there before the
    //  --at flag is composed.  Without this the sub-dogs would walk
    //  up to the parent and pollute its keeper.
    {
        a_cstr(v_get_s, "get");
        if (!u8csEmpty(c->verb) && u8csEq(c->verb, v_get_s) &&
            c->nuris > 0)
            (void)be_sub_shard_setup(c, &c->uris[0]);
    }

    //  Read the wt's tip URI (`<root>?<branch>#<sha>`) once, here at
    //  the top of the call chain, and stash it for `BEDispatch` to
    //  forward to every sub-dog as `--at <uri>`.  Sub-dogs that need
    //  to know the worktree's current branch / commit (sniff bare
    //  `get` resume, keeper `get //origin` default branch, graf `log`
    //  / `map` "you are here") read it back via `CLIAtURI` from
    //  their own cli.flags — no more sub-dog poking at `.be/wtlog`.
    //  `c.repo` is the cwd-walked wt root resolved by `CLIParse`.
    //  Absent / empty `.be/wtlog` (fresh dir, pre-clone bootstrap) →
    //  buffer stays empty and no `--at` flag is forwarded.
    if (u8bHasData(c->repo)) {
        u8bReset(be_at_buf);
        (void)SNIFFAtTailOf($path(c->repo), be_at_buf);
    }

    // No args → default
    if ($empty(c->verb) && c->nuris == 0 && c->nflags == 0) {
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
    $mv(verb, c->verb);

    // Get first URI if available
    uri *u = (c->nuris > 0) ? &c->uris[0] : NULL;

    b8 seq = CLIHas(c, "--seq");

    //  Projector URIs are pure views (VERBS.md Invariant 7).  Route
    //  them through BEProjector regardless of verb — `be get diff:f?r`
    //  must land in graf's diff machinery, not in BEGet's keeper+sniff
    //  checkout pipeline.  GET is the canonical projector verb per
    //  VERBS.md, but the table only specifies the read-only intent;
    //  any verb on a projector URI is treated as GET-equivalent here.
    if (u != NULL && DOGIsProjector(u->scheme)) {
        call(BEProjector, c, u);
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
        call(BEHead, c, seq);
    } else if ($eq(verb, v_get)) {
        call(BEGet, c, seq);
    } else if ($eq(verb, v_post)) {
        call(BEPost, c, seq);
    } else if ($eq(verb, v_put)) {
        call(BEPut, c, seq);
    } else if ($eq(verb, v_delete)) {
        call(BEDelete, c, seq);
    } else if ($eq(verb, v_status)) {
        call(BEDefault);
    } else if ($eq(verb, v_diff)) {
        call(BEDiff, c, seq);
    } else if ($eq(verb, v_patch)) {
        call(BEPatch, c, seq);
    } else {
        fprintf(stderr, "be: verb '" U8SFMT "' not yet implemented\n",
                u8sFmt(verb));
    }

    done;
}

ok64 becli() {
    sane(1);
    cli c = {};
    call(PATHu8bAlloc, c.repo);
    try(becli_inner, &c);
    PATHu8bFree(c.repo);
    done;
}

MAIN(becli);
