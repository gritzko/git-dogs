//  git-dl: thin CLI wrapper around WIREFetch (WIRE.md Phase 7).
//
//  Usage: git-dl <remote-uri> <out-keeper-dir> [<refname>]
//
//    <remote-uri>     file:///path | //host/path | keeper://local/path
//    <out-keeper-dir> directory to open / create as the destination
//                     keeper repo (a fresh one is initialised on first
//                     run via HOMEOpen + KEEPOpen rw).
//    <refname>        optional: heads/<X>, tags/<X>, or refs/<X>;
//                     defaults to "heads/main".
//
//  All real work — transport spawn, advert drain, want/have/done
//  negotiation, pack ingest, REFS update — lives in keeper/WIRECLI.c
//  under WIREFetch.  This binary stays around as a focused debugging
//  entry point that doesn't drag in the full `keeper` CLI verb table.

#include "WIRE.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "abc/FILE.h"
#include "abc/PRO.h"
#include "abc/S.h"
#include "dog/HOME.h"
#include "keeper/KEEP.h"

con ok64 GITDLFAIL = 0x1049d3553ca495;

ok64 gitdl() {
    sane(1);
    call(FILEInit);

    if ($arglen < 3) {
        fprintf(stderr,
            "Usage: git-dl <remote-uri> <out-keeper-dir> [<refname>]\n"
            "  remote-uri  file:///P | //host/P | keeper://local/P\n"
            "  out-dir     destination keeper repo (created if absent)\n"
            "  refname     heads/<X> | tags/<X> | refs/<X>  (default: heads/main)\n");
        fail(GITDLFAIL);
    }
    a$rg(remote_arg, 1);
    a$rg(out_arg,    2);

    //  Optional ref selector (3rd positional).
    u8cs ref_cs = {};
    if ($arglen >= 4) {
        a$rg(ref_arg, 3);
        u8csMv(ref_cs, ref_arg);
    }

    //  Build / open the destination keeper rooted at out_arg.  HOMEOpen
    //  with rw=YES creates the dir on first use.
    {
        char outbuf[1024];
        snprintf(outbuf, sizeof(outbuf), "%.*s",
                 (int)u8csLen(out_arg), (char *)out_arg[0]);
        mkdir(outbuf, 0755);
    }

    home h = {};
    call(HOMEOpenAt, &h, out_arg, YES);
    call(KEEPOpen, &h, YES);

    ok64 fo = WIREFetch(&KEEP, remote_arg, ref_cs);

    KEEPClose();
    HOMEClose(&h);

    if (fo != OK) {
        fprintf(stderr, "git-dl: fetch failed: 0x%llx\n",
                (unsigned long long)fo);
        return fo;
    }
    fprintf(stderr, "git-dl: ok\n");
    done;
}

MAIN(gitdl)
