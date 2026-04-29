//  WIRE: git upload-pack want/have negotiator + segment list builder.
//
//  See WIRE.h for the contract and WIRE.md Phase 4 for the surrounding
//  plan.

#include "WIRE.h"

#include <fcntl.h>
#include <unistd.h>

#include "abc/FILE.h"
#include "abc/HEX.h"
#include "abc/PATH.h"
#include "abc/PRO.h"
#include "keeper/PKT.h"

// --- request reader ---

#define WIRE_READ_BUF (1u << 16)   // 64 KiB pkt buffer

//  Capability tokens recognised on the first want line.
static u8c const WIRE_CAP_OFS_DELTA_S[]     = "ofs-delta";
static u8c const WIRE_CAP_SIDE_BAND_64K_S[] = "side-band-64k";
static u8c const WIRE_CAP_MULTI_ACK_DET_S[] = "multi_ack_detailed";
static u8c const WIRE_CAP_THIN_PACK_S[]     = "thin-pack";
static u8c const WIRE_CAP_NO_PROGRESS_S[]   = "no-progress";

//  Parse a 40-hex SHA into `out`.  Returns NO on shape/format error.
static b8 wire_decode_sha(sha1 *out, u8csc hex) {
    if (u8csLen(hex) != 40) return NO;
    a_dup(u8c, hex_dup, hex);
    u8s bin = {out->data, out->data + 20};
    if (HEXu8sDrainSome(bin, hex_dup) != OK) return NO;
    if (bin[0] != out->data + 20) return NO;
    return YES;
}

//  Slice [head, term) literal-prefix match.
static b8 wire_starts_with(u8csc s, u8c const *pfx, size_t plen) {
    if ((size_t)u8csLen(s) < plen) return NO;
    return memcmp(s[0], pfx, plen) == 0;
}

//  Token equality: |s| == plen && bytes equal.
static b8 wire_token_eq(u8csc s, u8c const *tok, size_t tlen) {
    if ((size_t)u8csLen(s) != tlen) return NO;
    return memcmp(s[0], tok, tlen) == 0;
}

//  Parse a space-separated capability list off the tail of the first
//  want line, OR from a pkt-line that consists of only capability
//  tokens (rarely used, kept for tolerance).  Sets bits in *caps.
static void wire_parse_caps(u32 *caps, u8csc tail) {
    u8cs scan = {tail[0], tail[1]};
    while (!u8csEmpty(scan)) {
        //  skip leading SP
        while (!u8csEmpty(scan) && scan[0][0] == ' ') scan[0]++;
        if (u8csEmpty(scan)) break;
        u8c *tok_start = scan[0];
        while (!u8csEmpty(scan) && scan[0][0] != ' ' && scan[0][0] != '\n')
            scan[0]++;
        u8csc tok = {tok_start, scan[0]};
        if (u8csLen(tok) == 0) continue;
        //  Strip "agent=..." silently.
        if (wire_token_eq(tok, WIRE_CAP_OFS_DELTA_S,
                          sizeof(WIRE_CAP_OFS_DELTA_S) - 1)) {
            *caps |= WIRE_CAP_OFS_DELTA;
        } else if (wire_token_eq(tok, WIRE_CAP_SIDE_BAND_64K_S,
                                 sizeof(WIRE_CAP_SIDE_BAND_64K_S) - 1)) {
            *caps |= WIRE_CAP_SIDE_BAND_64K;
        } else if (wire_token_eq(tok, WIRE_CAP_MULTI_ACK_DET_S,
                                 sizeof(WIRE_CAP_MULTI_ACK_DET_S) - 1)) {
            *caps |= WIRE_CAP_MULTI_ACK_DET;
        } else if (wire_token_eq(tok, WIRE_CAP_THIN_PACK_S,
                                 sizeof(WIRE_CAP_THIN_PACK_S) - 1)) {
            *caps |= WIRE_CAP_THIN_PACK;
        } else if (wire_token_eq(tok, WIRE_CAP_NO_PROGRESS_S,
                                 sizeof(WIRE_CAP_NO_PROGRESS_S) - 1)) {
            *caps |= WIRE_CAP_NO_PROGRESS;
        }
        if (!u8csEmpty(scan) && scan[0][0] == '\n') scan[0]++;
    }
}

//  Drain one pkt-line from buf, refilling via FILEDrain on NODATA.
//  Returns OK / PKTFLUSH / PKTDELIM / WIREFAIL on EOF/read error.
static ok64 wire_read_pkt(int in_fd, u8b buf, u8cs adv, u8csp line) {
    for (;;) {
        ok64 o = PKTu8sDrain(adv, line);
        if (o != NODATA) return o;
        if (!u8bHasRoom(buf)) return WIREFAIL;
        u8s fill;
        u8sFork(u8bIdle(buf), fill);
        ok64 fr = FILEDrain(in_fd, fill);
        if (fr == FILEEND) return WIREFAIL;
        if (fr != OK) return WIREFAIL;
        u8sJoin(u8bIdle(buf), fill);
        adv[1] = u8csTerm(u8bDataC(buf));
    }
}

ok64 WIREReadRequest(int in_fd, wire_reqp req) {
    sane(in_fd >= 0 && req);

    memset(req, 0, sizeof(*req));

    Bu8 buf = {};
    call(u8bAllocate, buf, WIRE_READ_BUF);

    u8cs adv = {u8bDataHead(buf), u8bDataHead(buf)};
    b8  saw_want = NO;
    b8  saw_done = NO;
    ok64 rc = OK;

    while (!saw_done) {
        u8cs line = {};
        ok64 d = wire_read_pkt(in_fd, buf, adv, line);
        if (d == PKTFLUSH) {
            //  Flush before "done" — common end-of-haves marker.
            //  Loop continues; client should send "done" shortly.
            //  If we already saw zero wants, treat flush as terminator.
            if (!saw_want) { rc = OK; break; }
            continue;
        }
        if (d == PKTDELIM) continue;
        if (d != OK) { rc = d; break; }

        //  Trim trailing '\n' if present.
        if (u8csLen(line) > 0 && line[1][-1] == '\n') line[1]--;

        if (wire_starts_with(line, (u8c *)"want ", 5)) {
            if (req->nwants >= WIRE_MAX_WANTS) { rc = WIREBADREQ; break; }
            //  Layout: "want <40-hex>[ SP <caps>]".
            u8cs rest = {line[0] + 5, line[1]};
            if (u8csLen(rest) < 40) { rc = WIREBADREQ; break; }
            u8csc hex = {rest[0], rest[0] + 40};
            sha1 sha = {};
            if (!wire_decode_sha(&sha, hex)) { rc = WIREBADREQ; break; }
            req->wants[req->nwants++] = sha;
            //  Capabilities ride on the first want line only.
            if (!saw_want && u8csLen(rest) > 40) {
                u8csc tail = {rest[0] + 40, rest[1]};
                wire_parse_caps(&req->caps, tail);
            }
            saw_want = YES;
        } else if (wire_starts_with(line, (u8c *)"have ", 5)) {
            if (req->nhaves >= WIRE_MAX_HAVES) {
                //  Drop excess silently — over-ship is the failure mode.
                continue;
            }
            u8cs rest = {line[0] + 5, line[1]};
            if (u8csLen(rest) < 40) { rc = WIREBADREQ; break; }
            u8csc hex = {rest[0], rest[0] + 40};
            sha1 sha = {};
            if (!wire_decode_sha(&sha, hex)) { rc = WIREBADREQ; break; }
            req->haves[req->nhaves++] = sha;
        } else if (wire_starts_with(line, (u8c *)"done", 4)) {
            saw_done = YES;
            break;
        } else {
            //  Unknown line type — be tolerant, ignore.
            continue;
        }
    }

    u8bFree(buf);
    return rc;
}

// --- segment builder ---

//  Compose <root>/.dogs/NNNNN.keeper into `out` (reset first).
//  Mirrors KEEP.c's static keep_pack_path; replicated here because
//  that helper isn't exposed.  `kdir` is the dir prefix (trunk or a
//  branch subdir) the caller already resolved.
static ok64 wire_pack_path(path8b out, u8csc kdir, u32 file_id) {
    sane(u8bOK(out) && !u8csEmpty(kdir));
    a_pad(u8, fname, KEEP_SEQNO_W + sizeof(KEEP_PACK_EXT));
    call(RONu8sFeedPad, u8bIdle(fname), (ok64)file_id, KEEP_SEQNO_W);
    ((u8 **)fname)[2] += KEEP_SEQNO_W;
    a_cstr(ext, KEEP_PACK_EXT);
    u8bFeed(fname, ext);
    call(PATHu8bDup, out, kdir);
    call(PATHu8bPush, out, u8bDataC(fname));
    done;
}

//  Find the PACK bookmark covering log_off in file_id by scanning
//  every LSM run for the trunk shard.  Sets *bm_offset, *bm_count,
//  *bm_byte_len.  Returns KEEPNONE if no covering bookmark exists.
static ok64 wire_find_pack(keeper *k, u32 file_id, u64 log_off,
                           u64 *bm_offset, u32 *bm_count, u32 *bm_byte_len) {
    sane(k && bm_offset && bm_count && bm_byte_len);
    u64  best_off = 0;
    u32  best_count = 0;
    u32  best_len  = 0;
    b8   any = NO;
    for (u32 r = 0, _nr_ = DOGPupCount(k->puppies); r < _nr_; r++) { u8cs _raw_ = {NULL,NULL}; DOGPupData(_raw_, k->puppies, r);
        wh128cp base = (wh128cp)_raw_[0];
        wh128cp term = (wh128cp)_raw_[1];
        for (wh128cp e = base; e < term; e++) {
            if (wh64Type(e->key) != KEEP_TYPE_PACK) continue;
            if (wh64Id(e->key)   != file_id)        continue;
            u64 bo = wh64Off(e->key);
            if (bo > log_off) continue;
            if (any && bo <= best_off) continue;
            best_off   = bo;
            best_count = keepPackBmCount(e->val);
            best_len   = keepPackBmLen(e->val);
            any = YES;
        }
    }
    if (!any) return KEEPNONE;
    *bm_offset   = best_off;
    *bm_count    = best_count;
    *bm_byte_len = best_len;
    done;
}

//  Find the *last* PACK bookmark in file_id (the dir tail).
//  Returns KEEPNONE if file_id has no bookmarks.
static ok64 wire_tail_pack(keeper *k, u32 file_id,
                           u64 *bm_offset, u32 *bm_count, u32 *bm_byte_len) {
    sane(k && bm_offset && bm_count && bm_byte_len);
    u64  best_off  = 0;
    u32  best_count = 0;
    u32  best_len  = 0;
    b8   any = NO;
    for (u32 r = 0, _nr_ = DOGPupCount(k->puppies); r < _nr_; r++) { u8cs _raw_ = {NULL,NULL}; DOGPupData(_raw_, k->puppies, r);
        wh128cp base = (wh128cp)_raw_[0];
        wh128cp term = (wh128cp)_raw_[1];
        for (wh128cp e = base; e < term; e++) {
            if (wh64Type(e->key) != KEEP_TYPE_PACK) continue;
            if (wh64Id(e->key)   != file_id)        continue;
            u64 bo = wh64Off(e->key);
            if (any && bo <= best_off) continue;
            best_off   = bo;
            best_count = keepPackBmCount(e->val);
            best_len   = keepPackBmLen(e->val);
            any = YES;
        }
    }
    if (!any) return KEEPNONE;
    *bm_offset   = best_off;
    *bm_count    = best_count;
    *bm_byte_len = best_len;
    done;
}

//  Sum obj_count of every PACK bookmark in file_id whose
//  offset is in [from, to).
static u32 wire_count_in_range(keeper *k, u32 file_id, u64 from, u64 to) {
    u64 total = 0;
    for (u32 r = 0, _nr_ = DOGPupCount(k->puppies); r < _nr_; r++) { u8cs _raw_ = {NULL,NULL}; DOGPupData(_raw_, k->puppies, r);
        wh128cp base = (wh128cp)_raw_[0];
        wh128cp term = (wh128cp)_raw_[1];
        for (wh128cp e = base; e < term; e++) {
            if (wh64Type(e->key) != KEEP_TYPE_PACK) continue;
            if (wh64Id(e->key)   != file_id)        continue;
            u64 bo = wh64Off(e->key);
            if (bo < from || bo >= to) continue;
            total += keepPackBmCount(e->val);
        }
    }
    if (total > 0xffffffffu) return 0xffffffffu;
    return (u32)total;
}

//  Resolve a sha to (file_id, log_off) by scanning every LSM run for
//  the first object-type entry whose hashlet matches.  Trust the
//  60-bit hashlet (collision rate ~2^-60); callers that need stricter
//  guarantees can re-verify by inflating via KEEPGetExact.
static ok64 wire_locate_sha(keeper *k, sha1 const *sha,
                            u32 *out_file_id, u64 *out_off) {
    sane(k && sha && out_file_id && out_off);
    u64 hashlet60 = WHIFFHashlet60(sha);
    u64 key_lo = keepKeyPack(KEEP_OBJ_COMMIT, hashlet60);
    u64 key_hi = keepKeyPack(KEEP_OBJ_TAG, hashlet60);

    for (u32 r = 0, _nr_ = DOGPupCount(k->puppies); r < _nr_; r++) { u8cs _raw_ = {NULL,NULL}; DOGPupData(_raw_, k->puppies, r);
        wh128cp base = (wh128cp)_raw_[0];
        size_t  len  = (size_t)((wh128cp)_raw_[1] - base);
        if (len == 0) continue;
        size_t lo = 0, hi = len;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            if (base[mid].key < key_lo) lo = mid + 1;
            else hi = mid;
        }
        if (lo < len && base[lo].key >= key_lo && base[lo].key <= key_hi) {
            *out_file_id = wh64Id(base[lo].val);
            *out_off     = wh64Off(base[lo].val);
            done;
        }
    }
    return KEEPNONE;
}

ok64 WIREBuildSegments(keeper *k, refadvcp adv, wire_reqcp req,
                       pstr_seg *out_segs, int *fd_pool,
                       u32 cap, u32 *out_n) {
    sane(k && req && out_segs && fd_pool && out_n);
    (void)adv;  // tip→dir lookup wired in once multi-branch fan-out lands.

    *out_n = 0;
    if (cap == 0) return WIREFAIL;

    if (req->nwants == 0) {
        //  Empty request — caller still sends a 32-byte empty pack
        //  (PSTRWrite with zero segments).
        return OK;
    }

    //  Phase 1c: dir chain is always [trunk shard 0].  One want →
    //  one segment.  Multi-want is a follow-up.
    sha1 const *want = &req->wants[0];

    u32 want_fid = 0;
    u64 want_off = 0;
    ok64 wo = wire_locate_sha(k, want, &want_fid, &want_off);
    if (wo != OK) return WIRENOSHA;

    u64 want_pack_off = 0;
    u32 want_pack_count = 0;
    u32 want_pack_len   = 0;
    call(wire_find_pack, k, want_fid, want_off,
         &want_pack_off, &want_pack_count, &want_pack_len);
    u64 end_offset = want_pack_off + want_pack_len;

    //  Walk haves; per dir take the max start of a covering pack.
    //  Phase 1c: only the trunk shard, so a single watermark.
    u64 watermark = 12;          // start-of-first-pack default
    u32 watermark_fid = want_fid;
    b8  have_anchor = NO;

    for (u32 i = 0; i < req->nhaves; i++) {
        u32 hfid = 0;
        u64 hoff = 0;
        ok64 hr = wire_locate_sha(k, &req->haves[i], &hfid, &hoff);
        if (hr != OK) continue;             // unknown have, skip
        if (hfid != want_fid) continue;     // different log file (multi-shard tba)
        u64 hpoff = 0;
        u32 hpcount = 0;
        u32 hplen   = 0;
        ok64 fp = wire_find_pack(k, hfid, hoff, &hpoff, &hpcount, &hplen);
        if (fp != OK) continue;
        u64 cand = hpoff + hplen;
        if (!have_anchor || cand > watermark) {
            watermark = cand;
            have_anchor = YES;
        }
    }
    if (!have_anchor) {
        //  Default: ship the whole trunk log up to (and including)
        //  the want's pack — start from the very first object.
        watermark = 12;
    }

    //  Compute object count for the segment by summing PACK bookmarks
    //  in [watermark .. end_offset).
    u32 seg_count = wire_count_in_range(k, watermark_fid,
                                        watermark, end_offset);

    //  Open the trunk pack log file.
    a_path(kdir, u8bDataC(k->h->root), KEEP_DIR_S);
    a_pad(u8, packpath, FILE_PATH_MAX_LEN);
    call(wire_pack_path, packpath, $path(kdir), want_fid);

    int fd = -1;
    call(FILEOpen, &fd, $path(packpath), O_RDONLY);
    fd_pool[0] = fd;

    if (end_offset <= watermark) {
        //  Client is already at or past the want's pack tail.
        out_segs[0].fd     = fd;
        out_segs[0].offset = watermark;
        out_segs[0].length = 0;
        out_segs[0].count  = 0;
        *out_n = 1;
        done;
    }

    out_segs[0].fd     = fd;
    out_segs[0].offset = watermark;
    out_segs[0].length = end_offset - watermark;
    out_segs[0].count  = seg_count;
    *out_n = 1;
    done;
}

// --- one-shot serve ---

ok64 WIREServeUpload(int in_fd, int out_fd, keeper *k, refadvcp adv) {
    sane(in_fd >= 0 && out_fd >= 0 && k);

    wire_req req = {};
    call(WIREReadRequest, in_fd, &req);

    //  Send NAK pkt-line ahead of the pack stream (canonical reply
    //  when we don't ACK any haves in this MVP).  The vanilla git
    //  client expects this framing per protocol v0.
    {
        a_pad(u8, frame, 16);
        a_cstr(nak, "NAK\n");
        call(PKTu8sFeed, u8bIdle(frame), nak);
        a_dup(u8c, fdata, u8bData(frame));
        call(FILEFeedAll, out_fd, fdata);
    }

    pstr_seg segs[WIRE_MAX_WANTS];
    int      fds [WIRE_MAX_WANTS];
    for (u32 i = 0; i < WIRE_MAX_WANTS; i++) fds[i] = -1;
    u32 nseg = 0;

    ok64 bo = WIREBuildSegments(k, adv, &req, segs, fds, WIRE_MAX_WANTS, &nseg);
    if (bo != OK) {
        for (u32 i = 0; i < WIRE_MAX_WANTS; i++)
            if (fds[i] >= 0) close(fds[i]);
        return bo;
    }

    pstr_segcs segslice = {segs, segs + nseg};
    ok64 wo = PSTRWrite(out_fd, segslice);

    for (u32 i = 0; i < WIRE_MAX_WANTS; i++)
        if (fds[i] >= 0) close(fds[i]);

    return wo;
}
