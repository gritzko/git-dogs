//  sniff CLI — thin wrapper: parse, open, exec, close.
//
//  Sniff has no shard index of its own (DOG.md §"Indexing"); it
//  reads worktree state and the `.sniff` ULOG, and writes commits
//  through keeper.  Reindexing of graf/spot is no longer driven
//  from here — under the new arrangement (DOG.md §10a) `be` spawns
//  spot/graf alongside keeper, and each dog refreshes its own
//  index from keeper's read APIs.
//
#include "SNIFF.h"

#include <unistd.h>

#include "abc/FILE.h"
#include "abc/PRO.h"
#include "abc/URI.h"
#include "dog/CLI.h"
#include "dog/DOG.h"
#include "graf/GRAF.h"
#include "keeper/KEEP.h"
#include "AT.h"

static ok64 sniffcli_inner(cli *c) {
    sane(c);
    call(FILEInit);
    call(CLIParse, c, SNIFF_VERBS, SNIFF_VAL_FLAGS);

    char cwd[1024];
    u8cs reporoot = {};
    if (u8bHasData(c->repo)) {
        u8csMv(reporoot, $path(c->repo));
    } else {
        if (!getcwd(cwd, sizeof(cwd))) fail(SNIFFFAIL);
        a_cstr(cwds, cwd);
        (void)PATHu8bFeed(c->repo, cwds);
        u8csMv(reporoot, $path(c->repo));
    }

    // Help and stop don't need an open state.
    a_cstr(v_help, "help");
    a_cstr(v_stop, "stop");
    b8 need_state = !u8csEq(c->verb, v_help) && !u8csEq(c->verb, v_stop)
                 && !CLIHas(c, "-h") && !CLIHas(c, "--help");

    if (!need_state) return SNIFFExec(c);

    // rw for anything that mutates the ULOG at `<wt>/.sniff` or the
    // store.  View projectors (verbless `sniff <proj>:<URI>`) are
    // always RO per VERBS.md §"View projectors are pure".  Bare
    // `sniff post` (no -m, no `?label`) is a dry-run change-set
    // print — also RO; otherwise FILEBook's page-align grows .sniff
    // and ULOGClose can't trim under a non-dirty handle.
    a_cstr(v_status, "status");
    a_cstr(v_list,   "list");
    a_cstr(v_post,   "post");
    a_cstr(v_commit, "commit");
    a_cstr(v_mflag,  "-m");
    b8 is_projector = u8csEmpty(c->verb) && c->nuris > 0 &&
                      DOGIsProjector(c->uris[0].scheme);
    //  `be post` always opens the home rw — even bare `be post`, which
    //  used to be a pure dry-run, can now compose a commit when patch
    //  rows are present (see VERBS.md §POST and POSTPatchDefaults).
    //  The patch chain isn't observable until the ULOG is mmapped, so
    //  we can't pick rw vs ro at CLI-open time.  The rare bare status
    //  preview pays an unnecessary write lock — acceptable.
    b8 is_post_dryrun = NO;
    b8 ro = u8csEq(c->verb, v_status) || u8csEq(c->verb, v_list) || is_projector
         || is_post_dryrun;
    b8 rw = !ro;

    //  Prefer the explicit `--at <root>?<branch>#<sha>` flag forwarded
    //  by `be`; falls back to the legacy reporoot path (cwd-walk via
    //  HOMEOpen when reporoot is empty).
    home h = {};
    uri at = {};
    CLIAtURI(&at, c);
    if (u8csEmpty(at.path) && u8csOK(reporoot) && !u8csEmpty(reporoot))
        u8csMv(at.path, reporoot);
    call(HOMEOpen, &h, &at, rw);
    call(SNIFFOpen, &h, rw);   // opens keeper singleton too

    //  POST (ff check) and PATCH (3-way merge LCA) call into graf for
    //  ancestor queries.  Open graf only for those two verbs — `sniff
    //  get` doesn't move HEAD, doesn't read the DAG, and grabbing
    //  graf's leaf `.lock` here serialises against the parallel graf
    //  child BE forks for `be get`, producing 20-minute wall-time
    //  hangs on big-repo clones (CPU stays idle on flock wait).  rw
    //  open mirrors the inline-reindex below — keeps the lock held
    //  for the whole post/patch including the index update.
    a_cstr(v_get,      "get");
    a_cstr(v_patch,    "patch");
    a_cstr(v_put,      "put");
    a_cstr(v_delete,   "delete");
    a_cstr(v_checkout, "checkout");
    //  graf needs to be open whenever sniff may consult the DAG
    //  (POST ff-check, PATCH 3-way LCA, PUT branch creation
    //  rebase, DELETE branch ancestor checks).  Do NOT open it
    //  for `get`/`checkout` — those don't read graf, and `be get`
    //  forks a parallel graf-rw child whose lock would race with
    //  the sniff-rw lock if we opened it here (long flock waits
    //  on big-repo clones).
    b8 needs_graf = !u8csEq(c->verb, v_get) && !u8csEq(c->verb, v_checkout)
                 && (rw || u8csEq(c->verb, v_post) || u8csEq(c->verb, v_commit)
                        || u8csEq(c->verb, v_patch));
    ok64 go = needs_graf ? GRAFOpen(&h, rw) : NONE;

    ok64 ret = SNIFFExec(c);

    //  Post-exec reindex for rw verbs that landed a commit.  Walk the
    //  new tip into graf's DAG so subsequent `sniff patch` LCAs see
    //  it without a manual `graf index` step.  BE matches this with
    //  be_reindex when invoked through `be post` / `be patch`.
    if (rw && needs_graf && ret == OK && (go == OK || go == GRAFOPEN)) {
        a_pad(u8, tail_buf, FILE_PATH_MAX_LEN + 128);
        if (SNIFFAtTailOf(reporoot, tail_buf) == OK) {
            uri tip = {};
            u8csMv(tip.data, u8bDataC(tail_buf));
            URILexer(&tip);
            (void)GRAFIndexFromTips(&KEEP, &tip);
        }
    }

    if (go == OK) GRAFClose();
    SNIFFClose();
    HOMEClose(&h);
    return ret;
}

ok64 sniffcli() {
    sane(1);
    cli c = {};
    call(PATHu8bAlloc, c.repo);
    try(sniffcli_inner, &c);
    PATHu8bFree(c.repo);
    done;
}

MAIN(sniffcli);
