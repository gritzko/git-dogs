//  graf CLI — thin wrapper: parse, open, exec, close.
//
#include "GRAF.h"

#include "abc/FILE.h"
#include "abc/PRO.h"
#include "dog/CLI.h"

ok64 grafcli() {
    sane(1);
    call(FILEInit);

    cli c = {};
    call(CLIParse, &c, GRAF_CLI_VERBS, GRAF_CLI_VAL_FLAGS);

    // Most graf verbs read .dogs/graf/; index writes. Use rw=YES to
    // keep parity with the previous behavior (always mkdir -p).
    //
    // Prefer `--at` from be; fall back to cwd-walk via c.repo.
    home h = {};
    uri at = {};
    CLIAtURI(&at, &c);
    if (u8csEmpty(at.path) && $ok(c.repo) && !u8csEmpty(c.repo))
        u8csMv(at.path, c.repo);
    //  Direct call so we can run HOMEClose on failure: HOMEOpen may
    //  have allocated buffers (root/wt/cur_branch/cur_sha/branches_data)
    //  before the HOMEFindDogs walk-up returned NOHOME.
    {
        ok64 ho = HOMEOpen(&h, &at, YES);
        if (ho != OK) { HOMEClose(&h); return ho; }
    }

    call(GRAFOpen, &h, YES);
    ok64 ret = GRAFExec(&c);
    GRAFClose();
    HOMEClose(&h);
    return ret;
}

MAIN(grafcli);
