#ifndef KEEPER_RECV_H
#define KEEPER_RECV_H

//  RECV: git receive-pack server (push direction).
//
//  Symmetric to keeper/WIRE.c (upload-pack).  Reads pkt-line ref-update
//  commands from a fd, drains the raw packfile that follows the request
//  flush, hands it to KEEPIngestFile (which UNPK-indexes and links it
//  into the trunk shard), then verifies fast-forward + appends each
//  accepted update to REFS.  Per-update results plus the unpack status
//  are emitted back over pkt-line.
//
//  Wire shape (git protocol v0/v1):
//
//    S → C : refs advertisement                                (REFADV)
//    C → S : <old-sha> <new-sha> <refname>\0<caps>\n           (one line/upd)
//            … more updates …
//            flush
//    C → S : raw packfile bytes                                (or empty)
//    S → C : "unpack ok\n" | "unpack <err>\n"                  pkt-line
//    S → C : "ok <refname>\n" | "ng <refname> <reason>\n"      one per upd
//    S → C : flush
//
//  Phase 6 MVP refuses ref deletion (new_sha all-zeros) with RECVBADREF
//  rather than implementing a delete path through REFS.  All-zeros
//  old_sha (ref creation) is supported.  Only `refs/heads/...` updates
//  are accepted in this pass; tag/symref pushes are TODOs.

#include "abc/INT.h"
#include "abc/OK.h"
#include "abc/S.h"
#include "abc/B.h"
#include "dog/SHA1.h"
#include "keeper/KEEP.h"
#include "keeper/REFADV.h"

con ok64 RECVFAIL    = 0x6ce31f3ca495;
con ok64 RECVNOTFF   = 0x1b38c7d761d3cf;
con ok64 RECVBADREF  = 0x6ce31f2ca35b38f;
con ok64 RECVBADREQ  = 0x6ce31f2ca35b39a;

#define RECV_MAX_UPDATES  64
#define RECV_REQ_BUF      (1u << 16)
#define RECV_ARENA_BYTES  (RECV_MAX_UPDATES * 256u)

//  Capability bits parsed off the first ref-update line.
//  Mirror WIRE_CAP_* but kept independent so RECV doesn't need WIRE.h.
#define RECV_CAP_REPORT_STATUS   (1u << 0)
#define RECV_CAP_SIDE_BAND_64K   (1u << 1)
#define RECV_CAP_OFS_DELTA       (1u << 2)
#define RECV_CAP_QUIET           (1u << 3)
#define RECV_CAP_AGENT           (1u << 4)

typedef struct {
    sha1  old_sha;
    sha1  new_sha;
    u8cs  refname;       // arena-owned slice, e.g. "refs/heads/foo"
} recv_update;

typedef recv_update       *recv_updatep;
typedef recv_update const *recv_updatecp;

typedef struct {
    recv_update *upds;       // borrowed pointer into upds_b
    u8b          upds_b;     // RECV_MAX_UPDATES-slot backing buffer
    u32          count;      // populated entry count
    u8b          arena;      // backing for refname slices
    u32          caps;       // negotiated capabilities (RECV_CAP_*)
    //  Any bytes that followed the flush but landed in the request
    //  read-buffer are preserved here — they are the first bytes of
    //  the pack and must be fed to RECVIngestPack before draining fd.
    u8b          tail;
} recv_req;

typedef recv_req       *recv_reqp;
typedef recv_req const *recv_reqcp;

//  Per-update result reported back to the client.
typedef struct {
    u8cs  refname;       // points into req->arena
    ok64  result;        // OK or RECVNOTFF / RECVBADREF / etc.
} recv_result;

typedef recv_result       *recv_resultp;
typedef recv_result const *recv_resultcp;

//  Parse pkt-line ref-update commands from in_fd until flush.
//  Subsequent packfile bytes are NOT consumed here — caller drains
//  them via RECVIngestPack.  `req` is reset on entry; on success
//  caller must release it via RECVCloseRequest.
ok64 RECVReadRequest(int in_fd, recv_reqp req);

//  Free arena + updates array.  Safe on a zeroed `req`.
void RECVCloseRequest(recv_reqp req);

//  Drain raw packfile bytes from in_fd and hand them to
//  KEEPIngestFile.  Reads until EOF (no trailer-aware framing —
//  receive-pack closes its write side after the pack).  `tail` is any
//  pre-buffered pack bytes that the pkt-line reader over-read past the
//  request's flush; they are prepended to whatever is drained from fd.
//  An empty stream (e.g. delete-only updates, no objects) is allowed
//  and returns OK with no on-disk state changed.
ok64 RECVIngestPack(keeper *k, int in_fd, u8csc tail);

//  Fast-forward check + REFS update for each parsed update.
//
//  For each:
//    * Resolve current local tip via the REFADV map.
//    * Refuse with RECVNOTFF unless old_sha matches the current tip
//      (or old_sha is all-zeros for ref creation).
//    * Refuse with RECVBADREF for ref deletion (new_sha all-zeros).
//    * On accept, append to REFS via REFSAppend.
//
//  Per-update outcomes are written to out_results[0 .. *out_n).
//  The whole call returns OK even when individual updates are
//  rejected — each ng is reflected in its `result` field.  Hard
//  RECVFAIL is returned only for I/O / encoding failures.
ok64 RECVApplyUpdates(keeper *k, refadvcp adv, recv_reqcp req,
                      recv_resultp out_results, u32 cap, u32p out_n);

//  Emit the receive-pack response over pkt-line:
//    "unpack ok\n" | "unpack <reason>\n"   (single line)
//    "ok <refname>\n" | "ng <refname> <reason>\n" per result
//    flush
ok64 RECVEmitResponse(int out_fd, ok64 unpack_status,
                      recv_resultcp results, u32 n);

//  Top-level orchestration matching WIREServeUpload's contract.
//  Reads request, ingests pack, applies updates, emits response.
//  Refs advertisement is emitted by the caller before this is called.
ok64 RECVServe(int in_fd, int out_fd, keeper *k, refadvcp adv);

#endif
