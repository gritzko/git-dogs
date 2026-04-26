//  RECV: git receive-pack server (push direction).
//
//  See RECV.h for the contract and WIRE.md Phase 6 for the surrounding
//  plan.

#include "RECV.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "abc/FILE.h"
#include "abc/HEX.h"
#include "abc/PRO.h"
#include "dog/DOG.h"
#include "keeper/GIT.h"
#include "keeper/PKT.h"
#include "keeper/REFS.h"

// --- capability tokens (recognised on the first ref-update line) ---

static u8c const RECV_CAP_REPORT_STATUS_S[] = "report-status";
static u8c const RECV_CAP_SIDE_BAND_64K_S[] = "side-band-64k";
static u8c const RECV_CAP_OFS_DELTA_S[]     = "ofs-delta";
static u8c const RECV_CAP_QUIET_S[]         = "quiet";
static u8c const RECV_CAP_AGENT_PFX[]       = "agent=";

// --- small helpers ---

//  Decode a 40-hex slice into `out`.  Returns NO on shape/format error.
static b8 recv_decode_sha(sha1 *out, u8csc hex) {
    if (u8csLen(hex) != 40) return NO;
    a_dup(u8c, hex_dup, hex);
    u8s bin = {out->data, out->data + 20};
    if (HEXu8sDrainSome(bin, hex_dup) != OK) return NO;
    if (bin[0] != out->data + 20) return NO;
    return YES;
}

//  Hex-encode a sha1 into out40 (must hold 40 bytes).
static void recv_sha_to_hex(u8 *out40, sha1 const *s) {
    u8s hs = {out40, out40 + 40};
    u8cs bs = {s->data, s->data + 20};
    HEXu8sFeedSome(hs, bs);
}

//  Token equality.
static b8 recv_token_eq(u8csc s, u8c const *tok, size_t tlen) {
    if ((size_t)u8csLen(s) != tlen) return NO;
    return memcmp(s[0], tok, tlen) == 0;
}

static b8 recv_starts_with(u8csc s, u8c const *pfx, size_t plen) {
    if ((size_t)u8csLen(s) < plen) return NO;
    return memcmp(s[0], pfx, plen) == 0;
}

//  Parse a space-separated capability list off the tail of the first
//  ref-update line.  Sets bits in *caps; unknown tokens are dropped.
static void recv_parse_caps(u32 *caps, u8csc tail) {
    u8cs scan = {tail[0], tail[1]};
    while (!u8csEmpty(scan)) {
        while (!u8csEmpty(scan) && (scan[0][0] == ' ' || scan[0][0] == '\t'))
            scan[0]++;
        if (u8csEmpty(scan)) break;
        u8c *tok_start = scan[0];
        while (!u8csEmpty(scan) &&
               scan[0][0] != ' ' && scan[0][0] != '\t' && scan[0][0] != '\n')
            scan[0]++;
        u8csc tok = {tok_start, scan[0]};
        if (u8csLen(tok) == 0) continue;
        if (recv_token_eq(tok, RECV_CAP_REPORT_STATUS_S,
                          sizeof(RECV_CAP_REPORT_STATUS_S) - 1)) {
            *caps |= RECV_CAP_REPORT_STATUS;
        } else if (recv_token_eq(tok, RECV_CAP_SIDE_BAND_64K_S,
                                 sizeof(RECV_CAP_SIDE_BAND_64K_S) - 1)) {
            *caps |= RECV_CAP_SIDE_BAND_64K;
        } else if (recv_token_eq(tok, RECV_CAP_OFS_DELTA_S,
                                 sizeof(RECV_CAP_OFS_DELTA_S) - 1)) {
            *caps |= RECV_CAP_OFS_DELTA;
        } else if (recv_token_eq(tok, RECV_CAP_QUIET_S,
                                 sizeof(RECV_CAP_QUIET_S) - 1)) {
            *caps |= RECV_CAP_QUIET;
        } else if (recv_starts_with(tok, RECV_CAP_AGENT_PFX,
                                    sizeof(RECV_CAP_AGENT_PFX) - 1)) {
            *caps |= RECV_CAP_AGENT;
        }
        if (!u8csEmpty(scan) && scan[0][0] == '\n') scan[0]++;
    }
}

//  Drain one pkt-line from buf, refilling via FILEDrain on NODATA.
//  Returns OK / PKTFLUSH / PKTDELIM / RECVFAIL on EOF/read error.
//  On refill, leftover bytes already in buf are preserved by feeding
//  past the current write head; `adv[1]` is reset to point at the new
//  buffer tail after each drain.
static ok64 recv_read_pkt(int in_fd, u8b buf, u8cs adv, u8csp line) {
    for (;;) {
        ok64 o = PKTu8sDrain(adv, line);
        if (o != NODATA) return o;
        if (!u8bHasRoom(buf)) return RECVFAIL;
        u8s fill;
        u8sFork(u8bIdle(buf), fill);
        ok64 fr = FILEDrain(in_fd, fill);
        if (fr == FILEEND) return RECVFAIL;
        if (fr != OK) return RECVFAIL;
        u8sJoin(u8bIdle(buf), fill);
        adv[1] = u8csTerm(u8bDataC(buf));
    }
}

// --- request reader ---

ok64 RECVReadRequest(int in_fd, recv_reqp req) {
    sane(in_fd >= 0 && req);

    memset(req, 0, sizeof(*req));
    req->upds = calloc(RECV_MAX_UPDATES, sizeof(recv_update));
    if (!req->upds) fail(RECVFAIL);
    ok64 ao = u8bAllocate(req->arena, RECV_ARENA_BYTES);
    if (ao != OK) {
        free(req->upds);
        req->upds = NULL;
        return ao;
    }

    Bu8 buf = {};
    ok64 bo = u8bAllocate(buf, RECV_REQ_BUF);
    if (bo != OK) {
        RECVCloseRequest(req);
        return bo;
    }

    u8cs adv = {u8bDataHead(buf), u8bDataHead(buf)};
    ok64 rc = OK;

    for (;;) {
        u8cs line = {};
        ok64 d = recv_read_pkt(in_fd, buf, adv, line);
        if (d == PKTFLUSH) break;
        if (d == PKTDELIM) continue;
        if (d != OK) { rc = d; break; }

        //  Trim trailing '\n' if present.
        if (u8csLen(line) > 0 && line[1][-1] == '\n') line[1]--;

        //  Layout: "<old-40hex> SP <new-40hex> SP <refname>[NUL <caps>]"
        if (u8csLen(line) < 40 + 1 + 40 + 1 + 1) {
            rc = RECVBADREQ;
            break;
        }
        u8c const *p = line[0];
        u8c const *e = line[1];

        u8csc old_hex = {p, p + 40};
        if (p[40] != ' ') { rc = RECVBADREQ; break; }
        u8csc new_hex = {p + 41, p + 81};
        if (p + 81 >= e || p[81] != ' ') { rc = RECVBADREQ; break; }
        u8c const *name_start = p + 82;
        u8c const *name_end   = name_start;
        while (name_end < e && *name_end != 0) name_end++;
        if (name_end == name_start) { rc = RECVBADREQ; break; }
        u8csc refname = {name_start, name_end};

        if (req->count >= RECV_MAX_UPDATES) {
            rc = RECVBADREQ;
            break;
        }
        recv_update *u = &req->upds[req->count];
        if (!recv_decode_sha(&u->old_sha, old_hex) ||
            !recv_decode_sha(&u->new_sha, new_hex)) {
            rc = RECVBADREQ;
            break;
        }

        //  Copy refname into the request arena so the slice outlives `buf`.
        if (u8bIdleLen(req->arena) < (size_t)u8csLen(refname)) {
            rc = RECVFAIL;
            break;
        }
        u8 *name_dst = u8bIdleHead(req->arena);
        u8bFeed(req->arena, refname);
        u->refname[0] = name_dst;
        u->refname[1] = u8bIdleHead(req->arena);

        //  Capabilities ride after a NUL on the first line only.
        if (req->count == 0 && name_end < e && *name_end == 0) {
            u8csc tail = {name_end + 1, e};
            recv_parse_caps(&req->caps, tail);
        }

        req->count++;
    }

    //  Preserve any bytes past `adv[0]` — they are the first bytes of
    //  the packfile the client streamed right after the flush.  The
    //  pipe reader may have pulled them in while filling buf for
    //  pkt-line parsing; without this stash they would be lost when
    //  buf is freed, and KEEPIngestFile would see a truncated pack.
    if (rc == OK) {
        u8cs leftover = {adv[0], u8bIdleHead(buf)};
        if (!u8csEmpty(leftover)) {
            ok64 to = u8bAllocate(req->tail, u8csLen(leftover));
            if (to == OK) u8bFeed(req->tail, leftover);
        }
    }
    u8bFree(buf);
    if (rc != OK) RECVCloseRequest(req);
    return rc;
}

void RECVCloseRequest(recv_reqp req) {
    if (!req) return;
    if (req->tail[0] != NULL) {
        u8bFree(req->tail);
    }
    if (req->upds) {
        free(req->upds);
        req->upds = NULL;
    }
    if (req->arena[0] != NULL) {
        u8bFree(req->arena);
    }
    req->count = 0;
    req->caps  = 0;
}

// --- pack ingest ---

#define RECV_PACK_BUF (1u << 20)   // 1 MiB chunked drain

ok64 RECVIngestPack(keeper *k, int in_fd, u8csc tail) {
    sane(k && in_fd >= 0);

    Bu8 buf = {};
    call(u8bMap, buf, 1ULL << 30);  // up to 1 GiB packfile

    //  Consume any pre-buffered pack bytes first (see RECVReadRequest).
    if (!u8csEmpty(tail)) {
        if (u8bIdleLen(buf) < (size_t)u8csLen(tail)) {
            u8bUnMap(buf);
            return RECVFAIL;
        }
        u8bFeed(buf, tail);
    }

    for (;;) {
        if (!u8bHasRoom(buf)) {
            //  Pack larger than our cap — bail rather than truncate.
            u8bUnMap(buf);
            return RECVFAIL;
        }
        u8s fill;
        u8sFork(u8bIdle(buf), fill);
        //  Cap one read so we don't try to map huge contiguous chunks.
        size_t want = $len(fill);
        if (want > RECV_PACK_BUF) {
            fill[1] = fill[0] + RECV_PACK_BUF;
        }
        ok64 fr = FILEDrain(in_fd, fill);
        if (fr == FILEEND) break;
        if (fr != OK) {
            u8bUnMap(buf);
            return RECVFAIL;
        }
        u8sJoin(u8bIdle(buf), fill);
    }

    u64 nbytes = u8bDataLen(buf);
    if (nbytes == 0) {
        //  Empty pack stream — delete-only updates etc.  Nothing to do.
        u8bUnMap(buf);
        done;
    }
    if (nbytes < 12) {
        u8bUnMap(buf);
        return RECVFAIL;
    }

    a_dup(u8c, bytes, u8bData(buf));
    ok64 io = KEEPIngestFile(k, bytes);
    u8bUnMap(buf);
    if (io != OK) return RECVFAIL;
    done;
}

// --- updates application ---

//  Build the local REFS key for a wire-side refname.  Maps:
//    refs/heads/main → `?`           (trunk; the only wire alias)
//    refs/heads/<X>  → `?<X>`        (literal local branch path)
//  Tags / remotes / OTHER kinds are not first-class locally yet —
//  reject with RECVBADREF.
static ok64 recv_build_key(u8b out, u8csc refname) {
    sane(u8bOK(out));
    gitref_kind k = GITREF_NONE;
    u8cs name = {};
    if (GITParseRef(refname, &k, name) != OK) return RECVBADREF;
    if (k != GITREF_BRANCH) return RECVBADREF;
    u8bFeed1(out, '?');
    a_cstr(main_s, "main");
    if (u8csLen(name) == u8csLen(main_s) &&
        memcmp(name[0], main_s[0], (size_t)u8csLen(main_s)) == 0)
        done;  //  trunk: bare `?`
    u8bFeed(out, name);
    done;
}

//  Compose the to-URI value: bare 40-hex (canonical fragment form).
static ok64 recv_build_val(u8b out, sha1 const *sha) {
    sane(u8bOK(out));
    u8 hex[40];
    recv_sha_to_hex(hex, sha);
    u8csc hexs = {hex, hex + 40};
    u8bFeed(out, hexs);
    done;
}

//  Look up the current local tip for `refname` via the REFADV map.
//  Sets *have_tip = YES if found, NO otherwise.
static void recv_lookup_tip(refadvcp adv, u8csc refname,
                            sha1 *out_tip, b8 *have_tip) {
    *have_tip = NO;
    if (!adv) return;
    for (u32 i = 0; i < adv->count; i++) {
        u8cs r = {adv->ents[i].refname[0], adv->ents[i].refname[1]};
        if (u8csLen(r) != u8csLen(refname)) continue;
        if (memcmp(r[0], refname[0], (size_t)u8csLen(refname)) != 0) continue;
        *out_tip   = adv->ents[i].tip;
        *have_tip  = YES;
        return;
    }
}

ok64 RECVApplyUpdates(keeper *k, refadvcp adv, recv_reqcp req,
                      recv_resultp out_results, u32 cap, u32p out_n) {
    sane(k && req && out_results && out_n);
    *out_n = 0;
    if (req->count > cap) return RECVFAIL;

    a_path(keepdir, u8bDataC(k->h->root), KEEP_DIR_S);

    for (u32 i = 0; i < req->count; i++) {
        recv_update const *u = &req->upds[i];
        recv_result *r = &out_results[i];
        r->refname[0] = u->refname[0];
        r->refname[1] = u->refname[1];
        r->result = OK;

        b8 is_create = sha1empty(&u->old_sha);
        b8 is_delete = sha1empty(&u->new_sha);

        //  FF check: unless creating or deleting, old_sha must equal
        //  the current tip.  Deletes are unconditional — git's
        //  receive-pack accepts them as long as the client knew the
        //  current tip (handshake rule), which the wire layer
        //  enforces upstream.
        if (!is_create && !is_delete) {
            sha1 cur = {};
            b8 have_tip = NO;
            recv_lookup_tip(adv, u->refname, &cur, &have_tip);
            if (!have_tip || !sha1eq(&cur, &u->old_sha)) {
                r->result = RECVNOTFF;
                continue;
            }
        }

        //  Build REFS key + val for this update.  For deletes,
        //  recv_build_val writes the all-zeros sha — exactly the
        //  tombstone shape REFS recognises.
        a_pad(u8, kbuf, 512);
        ok64 ko = recv_build_key(kbuf, u->refname);
        if (ko != OK) { r->result = ko; continue; }
        a_pad(u8, vbuf, 64);
        ok64 vo = recv_build_val(vbuf, &u->new_sha);
        if (vo != OK) { r->result = RECVFAIL; continue; }

        a_dup(u8c, key, u8bData(kbuf));
        a_dup(u8c, val, u8bData(vbuf));
        ok64 ao = REFSAppend($path(keepdir), key, val);
        if (ao != OK) { r->result = RECVFAIL; continue; }
    }

    *out_n = req->count;
    done;
}

// --- response emit ---

ok64 RECVEmitResponse(int out_fd, ok64 unpack_status,
                      recv_resultcp results, u32 n) {
    sane(out_fd >= 0);

    u64 cap = 64;
    cap += 4 + 32;   // unpack line slack
    for (u32 i = 0; i < n; i++) {
        cap += 4 + 4 + (u64)u8csLen(results[i].refname) + 64;
    }

    Bu8 frame = {};
    call(u8bAllocate, frame, cap);

    //  unpack line.
    {
        a_pad(u8, line, 256);
        a_cstr(unpack_pfx, "unpack ");
        u8bFeed(line, unpack_pfx);
        if (unpack_status == OK) {
            a_cstr(ok_s, "ok");
            u8bFeed(line, ok_s);
        } else {
            a_cstr(err_s, "error");
            u8bFeed(line, err_s);
        }
        u8bFeed1(line, '\n');
        a_dup(u8c, payload, u8bData(line));
        ok64 po = PKTu8sFeed(u8bIdle(frame), payload);
        if (po != OK) { u8bFree(frame); return po; }
    }

    //  Per-update lines.
    for (u32 i = 0; i < n; i++) {
        a_pad(u8, line, 512);
        if (results[i].result == OK && unpack_status == OK) {
            a_cstr(ok_pfx, "ok ");
            u8bFeed(line, ok_pfx);
            u8bFeed(line, results[i].refname);
            u8bFeed1(line, '\n');
        } else {
            a_cstr(ng_pfx, "ng ");
            u8bFeed(line, ng_pfx);
            u8bFeed(line, results[i].refname);
            u8bFeed1(line, ' ');
            char const *reason = "failed";
            if (unpack_status != OK) {
                reason = "unpacker failed";
            } else if (results[i].result == RECVNOTFF) {
                reason = "non-fast-forward";
            } else if (results[i].result == RECVBADREF) {
                reason = "bad ref";
            }
            u8csc rs = {(u8cp)reason, (u8cp)reason + strlen(reason)};
            u8bFeed(line, rs);
            u8bFeed1(line, '\n');
        }
        a_dup(u8c, payload, u8bData(line));
        ok64 po = PKTu8sFeed(u8bIdle(frame), payload);
        if (po != OK) { u8bFree(frame); return po; }
    }

    ok64 fo = PKTu8sFeedFlush(u8bIdle(frame));
    if (fo != OK) { u8bFree(frame); return fo; }

    a_dup(u8c, fdata, u8bData(frame));
    ok64 wo = FILEFeedAll(out_fd, fdata);
    u8bFree(frame);
    return wo;
}

// --- top-level orchestration ---

ok64 RECVServe(int in_fd, int out_fd, keeper *k, refadvcp adv) {
    sane(in_fd >= 0 && out_fd >= 0 && k);

    recv_req req = {};
    ok64 rro = RECVReadRequest(in_fd, &req);
    if (rro != OK) {
        //  No request → no response; surface error to caller.
        return rro;
    }

    //  Drain the packfile (may be empty for delete-only requests, which
    //  we currently refuse — but git still sends a 32-byte empty pack
    //  for those, so consume it regardless).
    ok64 unpack_status = OK;
    if (req.count > 0) {
        u8csc rtail = {u8bDataHead(req.tail), u8bIdleHead(req.tail)};
        ok64 io = RECVIngestPack(k, in_fd, rtail);
        if (io != OK) unpack_status = io;
    }

    //  Apply updates regardless of pack status — RECVEmitResponse will
    //  override per-ref status with "unpacker failed" when the unpack
    //  itself failed.  Even on unpack failure, we still want to walk
    //  updates so each ref gets its `ng` line on the wire.
    recv_result results[RECV_MAX_UPDATES] = {};
    u32 nres = 0;
    if (req.count > 0) {
        ok64 ao = RECVApplyUpdates(k, adv, &req, results,
                                   RECV_MAX_UPDATES, &nres);
        if (ao != OK && unpack_status == OK) unpack_status = ao;
    }

    ok64 eo = RECVEmitResponse(out_fd, unpack_status, results, nres);
    RECVCloseRequest(&req);
    return eo;
}
