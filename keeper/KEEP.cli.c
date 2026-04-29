//  keeper CLI — thin wrapper: parse, open, exec, close.
//
//  Also hosts the indexer fan-out: when keeper is invoked as the
//  standalone `keeper` binary, every object UNPKIndex resolves is
//  forwarded to graf and spot through their DOGUpdate contracts.
//  The fan-out lives here (not in keeplib) so keeplib stays free of
//  graflib/spotlib dependencies.
//
#include "KEEP.h"
#include "RECV.h"
#include "REFADV.h"
#include "UNPK.h"
#include "WIRE.h"

#include <string.h>
#include <unistd.h>

#include "abc/FILE.h"
#include "abc/PRO.h"
#include "dog/CLI.h"
#include "dog/DOG.h"
#include "dog/SHA1.h"
#include "graf/GRAF.h"
#include "spot/CAPO.h"

//  UNPKIndex emit → GRAFUpdate + SPOTUpdate.  Called once per resolved
//  object inside KEEPIngestFile.  `content` is valid only for the
//  callback's lifetime; both indexers copy what they need.  A ro graf
//  or spot silently drops updates (they guard internally).
static void keeper_indexer_fanout(void *ctx, u8 type,
                                   sha1 const *sha, u8cs content) {
    (void)ctx;
    GRAFUpdate(type, sha, content);
    SPOTUpdate(type, sha, content);
}


//  Drop-in for `git-upload-pack <repo-path>`: read pkt-lines on stdin,
//  emit refs advertisement + pack response on stdout.  Stateless across
//  requests (one process per ssh invocation, like vanilla git).
//
//  Repo path comes from argv (parsed into c->uris[0].data) — it is
//  *not* derived from cwd, so this verb works under any ssh ForceCommand
//  config.  Path is opened read-only since serving never mutates state.
static ok64 keeper_upload_pack(cli *c) {
    sane(c);
    if (c->nuris < 1) {
        return KEEPFAIL;
    }
    u8cs path = {c->uris[0].data[0], c->uris[0].data[1]};
    if (u8csEmpty(path)) return KEEPFAIL;

    home h = {};
    call(HOMEOpen, &h, path, NO);
    call(KEEPOpen, &h, NO);

    refadv adv = {};
    call(REFADVOpen, &adv, &KEEP);
    call(REFADVEmit, STDOUT_FILENO, &adv);
    ok64 wo = WIREServeUpload(STDIN_FILENO, STDOUT_FILENO, &KEEP, &adv);
    REFADVClose(&adv);
    KEEPClose();
    HOMEClose(&h);
    return wo;
}

//  Drop-in for `git-receive-pack <repo-path>`: read pkt-lines + pack on
//  stdin, emit refs advertisement + unpack/per-ref status on stdout.
//  Stateless across requests (one process per ssh invocation).  Repo
//  path comes from argv (parsed into c->uris[0].data); rw mode is
//  required because push writes packs + REFS.
static ok64 keeper_receive_pack(cli *c) {
    sane(c);
    if (c->nuris < 1) {
        return KEEPFAIL;
    }
    u8cs path = {c->uris[0].data[0], c->uris[0].data[1]};
    if (u8csEmpty(path)) return KEEPFAIL;

    home h = {};
    call(HOMEOpen, &h, path, YES);
    call(KEEPOpen, &h, YES);

    //  Indexer fan-out so received objects also reach graf/spot.
    //  Mirrors the rw branch in keepercli().
    ok64 go = GRAFOpen(&h, YES);
    ok64 so = SPOTOpen(&h, YES);
    keep_indexer_emit = keeper_indexer_fanout;
    keep_indexer_ctx  = NULL;

    refadv adv = {};
    call(REFADVOpen, &adv, &KEEP);
    call(REFADVEmit, STDOUT_FILENO, &adv);
    ok64 ro = RECVServe(STDIN_FILENO, STDOUT_FILENO, &KEEP, &adv);
    REFADVClose(&adv);

    keep_indexer_emit = NULL;
    keep_indexer_ctx  = NULL;
    if (so == OK) SPOTClose();
    if (go == OK) GRAFClose();

    KEEPClose();
    HOMEClose(&h);
    return ro;
}

ok64 keepercli() {
    sane(1);
    call(FILEInit);

    cli c = {};
    call(CLIParse, &c, KEEP_CLI_VERBS, KEEP_CLI_VAL_FLAGS);

    //  upload-pack short-circuits the standard cwd-derived HOME/KEEP
    //  open: it opens the repo named in argv (the ssh contract), runs
    //  the wire negotiator on stdin/stdout, and exits.  Falls through
    //  to the generic dispatch on argless invocation.
    a_cstr(v_upload_pack, "upload-pack");
    if ($eq(c.verb, v_upload_pack)) {
        return keeper_upload_pack(&c);
    }
    a_cstr(v_receive_pack, "receive-pack");
    if ($eq(c.verb, v_receive_pack)) {
        return keeper_receive_pack(&c);
    }

    a_cstr(v_status, "status");
    a_cstr(v_refs,   "refs");
    a_cstr(v_verify, "verify");
    b8 ro = $eq(c.verb, v_status) || $eq(c.verb, v_refs)
         || $eq(c.verb, v_verify);
    //  Verb-less projector dispatch (`keeper tree:?...`, `commit:`,
    //  `blob:`) is also read-only — no pack ingest, no ref writes.
    if (!ro && $empty(c.verb) && c.nuris > 0) {
        char const *dog = DOGProjectorDog(c.uris[0].scheme);
        if (dog != NULL && strcmp(dog, "keeper") == 0) ro = YES;
    }
    b8 rw = !ro;

    home h = {};
    call(HOMEOpen, &h, c.repo, rw);

    call(KEEPOpen, &h, rw);

    //  Indexer fan-out: only for rw verbs (fetch/push).  ro verbs
    //  don't ingest packs so there's nothing to forward.
    ok64 go = NONE;
    ok64 so = NONE;
    if (rw) {
        go = GRAFOpen(&h, YES);
        so = SPOTOpen(&h, YES);
        keep_indexer_emit = keeper_indexer_fanout;
        keep_indexer_ctx  = NULL;
    }

    ok64 ret = KEEPExec(&KEEP, &c);

    if (rw) {
        keep_indexer_emit = NULL;
        keep_indexer_ctx  = NULL;
        if (so == OK) SPOTClose();
        if (go == OK) GRAFClose();
    }

    KEEPClose();
    HOMEClose(&h);
    return ret;
}

MAIN(keepercli);
