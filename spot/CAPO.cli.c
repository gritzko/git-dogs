//  spot CLI — thin wrapper: parse, open, exec, close.
//
#include "CAPO.h"
#include "SPOT_VERSION.h"

#include <stdio.h>

#include "abc/FILE.h"
#include "abc/PRO.h"
#include "dog/CLI.h"
#include "dog/HOME.h"

static ok64 capocli_inner(cli *c) {
    sane(c);
    call(FILEInit);
    call(CLIParse, c, SPOT_CLI_VERBS, SPOT_CLI_VAL_FLAGS);

    if (CLIHas(c, "-v") || CLIHas(c, "--version")) {
        fprintf(stderr, "spot %s %s\n", SPOT_GIT_TAG, SPOT_COMMIT_HASH);
        done;
    }

    //  `spot get URI` walks tip(s) and updates the trigram index, so
    //  it must open the repo writeable.  Search verbs stay read-only.
    a_cstr(v_get, "get");
    b8 need_rw = $eq(c->verb, v_get);

    //  Prefer `--at` from be (`<root>?<branch>#<sha>`); fall back to
    //  the cwd-walked `c->repo`.  HOMEOpen parks the URI's branch and
    //  fragment in `h->cur_branch` / `h->cur_sha` so SPOTIndexFromTips
    //  has a baseline tip when the user URI is bare (`?`, no args).
    home h = {};
    uri at = {};
    CLIAtURI(&at, c);
    if (u8csEmpty(at.path) && u8bHasData(c->repo))
        u8csMv(at.path, $path(c->repo));
    //  Direct call so we can run HOMEClose on failure: HOMEOpen may
    //  have allocated buffers before HOMEFindDogs returned NOHOME.
    {
        ok64 ho = HOMEOpen(&h, &at, need_rw);
        if (ho != OK) { HOMEClose(&h); return ho; }
    }

    call(SPOTOpen, &h, need_rw);
    ok64 ret = SPOTExec(c);
    SPOTClose();
    HOMEClose(&h);
    return ret;
}

ok64 capocli() {
    sane(1);
    cli c = {};
    call(PATHu8bAlloc, c.repo);
    try(capocli_inner, &c);
    PATHu8bFree(c.repo);
    done;
}

MAIN(capocli);
