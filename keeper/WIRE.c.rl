//  WIRE.c.rl — git pkt-line text-payload classifier (DRAFT).
//
//  Scope: pure function.  Caller has already extracted one complete
//  pkt-line payload (e.g. via PKTu8sDrain) and decided which role's
//  grammar applies.  This machine classifies the payload into a
//  wire_evt or returns WIREBADREQ.
//
//  No streaming, no buffering, no zlib, no framing.  Slices in the
//  emitted event point into the caller's payload — caller copies
//  what it wants to keep.
//
//  Build: ragel -C WIRE.c.rl -o WIRE.rl.c -L

#include "WIRE.h"

#include "abc/HEX.h"
#include "abc/PRO.h"

#include <string.h>

%%{
    machine wire_line;
    alphtype unsigned char;

    # ---- captures ----

    action sha_zero {
        ctx.sha_pos = 0;
        memset(&ctx.sha, 0, sizeof(ctx.sha));
    }
    action sha_acc {
        //  Bounded write — sha_done rejects everything ≠ 40 chars.
        if (ctx.sha_pos < 40) {
            u8 v = BASE16rev[fc];
            ctx.sha.data[ctx.sha_pos >> 1] |=
                (ctx.sha_pos & 1) ? v : (v << 4);
        }
        ctx.sha_pos++;
    }
    action sha_done { if (ctx.sha_pos != 40) ctx.bad = 1; }
    action sha_save_old { ctx.sha_old = ctx.sha; }

    action nm_start { ctx.name[0] = (u8c *)fpc; }
    action nm_end   { ctx.name[1] = (u8c *)fpc; }

    action caps_start { ctx.caps[0] = (u8c *)fpc; }
    action caps_end   { ctx.caps[1] = (u8c *)fpc; }

    # ---- emitters ----

    action ev_want {
        out->kind = WIRE_WANT;
        out->sha  = ctx.sha;
        $mv(out->caps, ctx.caps);
    }
    action ev_have    { out->kind = WIRE_HAVE;    out->sha = ctx.sha; }
    action ev_done    { out->kind = WIRE_DONE; }
    action ev_nak     { out->kind = WIRE_NAK; }
    action ev_ack     { out->kind = WIRE_ACK;     out->sha = ctx.sha; }
    action ev_shallow { out->kind = WIRE_SHALLOW; out->sha = ctx.sha; }
    action ev_ref {
        out->kind = WIRE_REF;
        out->sha  = ctx.sha;
        $mv(out->name, ctx.name);
        $mv(out->caps, ctx.caps);
    }
    action ev_update {
        out->kind    = WIRE_UPDATE;
        out->old_sha = ctx.sha_old;
        out->sha     = ctx.sha;       // new_sha
        $mv(out->name, ctx.name);
        $mv(out->caps, ctx.caps);
    }

    # ---- terminals ----

    sha   = [a-f0-9]+ >sha_zero $sha_acc %sha_done;
    sp    = ' ';
    nul   = 0;
    name  = ( (any - nul) - sp - '\n' )+ >nm_start %nm_end;
    caps  = ( any - '\n' )* >caps_start %caps_end;

    # ---- line shapes ----

    want_l    = "want " sha (sp caps)?                  %ev_want;
    have_l    = "have " sha                             %ev_have;
    done_l    = "done"                                  %ev_done;
    shallow_l = "shallow " sha                          %ev_shallow;

    nak_l     = "NAK"                                   %ev_nak;
    ack_l     = "ACK " sha
                 (sp (alpha+))?                         %ev_ack;

    ref_l     = sha sp name
                 (nul caps)?                            %ev_ref;

    update_l  = sha %sha_save_old sp sha sp name
                 (nul caps)?                            %ev_update;

    # ---- entry points (one per role) ----

    upload   := want_l | have_l | done_l | shallow_l;
    receive  := update_l;
    advert   := ref_l;
    client   := ref_l | ack_l | nak_l;
}%%

%% write data;

ok64 WIREClassify(u8csc payload, wire_role role, wire_evt *out) {
    sane(out);

    *out = (wire_evt){0};
    struct {
        sha1   sha;
        sha1   sha_old;
        u32    sha_pos;
        b8     bad;          // any sha != 40 chars; rejected post-exec
        u8c   *name[2];
        u8c   *caps[2];
    } ctx = {0};

    u8c const *p   = payload[0];
    u8c const *pe  = payload[1];
    u8c const *eof = pe;
    int cs = 0;

    %% write init;

    switch (role) {
    case WIRE_UPLOAD:  cs = wire_line_en_upload;  break;
    case WIRE_RECEIVE: cs = wire_line_en_receive; break;
    case WIRE_CLIENT:  cs = wire_line_en_client;  break;
    case WIRE_ADVERT:  cs = wire_line_en_advert;  break;
    default: return WIREBADREQ;
    }

    %% write exec;

    if (cs < wire_line_first_final || ctx.bad) {
        *out = (wire_evt){0};
        return WIREBADREQ;
    }
    done;
}
