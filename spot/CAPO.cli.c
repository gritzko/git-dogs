//  spot CLI — thin wrapper: parse, open, exec, close.
//
#include "CAPO.h"
#include "SPOT_VERSION.h"

#include <stdio.h>

#include "abc/FILE.h"
#include "abc/PRO.h"
#include "dog/CLI.h"

ok64 capocli() {
    sane(1);
    call(FILEInit);

    cli c = {};
    call(CLIParse, &c, SPOT_CLI_VERBS, SPOT_CLI_VAL_FLAGS);

    if (CLIHas(&c, "-v") || CLIHas(&c, "--version")) {
        fprintf(stderr, "spot %s %s\n", SPOT_GIT_TAG, SPOT_COMMIT_HASH);
        done;
    }

    //  `spot get` ingests freshly-fetched packs into the trigram index,
    //  so it must open the repo writeable.  Search verbs stay read-only.
    a_cstr(v_get, "get");
    b8 need_rw = $eq(c.verb, v_get);

    home h = {};
    call(HOMEOpenAt, &h, c.repo, need_rw);

    call(SPOTOpen, &h, need_rw);
    ok64 ret = SPOTExec(&c);
    SPOTClose();
    HOMEClose(&h);
    return ret;
}

MAIN(capocli);
