#ifndef KEEPER_WIRE_H
#define KEEPER_WIRE_H

//  WIRE: git upload-pack want/have negotiator + segment list builder.
//
//  Reads a client request (wants/haves/caps) over pkt-line, resolves
//  each want sha to a (dir, end-of-pack) pair via REFADV's tip→dir
//  map (with LSM fallback), resolves each have sha to a per-dir pack
//  start offset (the watermark), and emits the ordered list of
//  byte-segments ready to feed into PSTRWrite.
//
//  Algorithm (see keeper/WIRE.md, Approach A "linear prefix"):
//
//    1. For each want sha:
//         REFADVTipDirs lookup → list of dirs holding it as a tip.
//         Pick the topmost dir (shortest dir slice; lex tiebreak).
//         If no tip match, LSM lookup → containing pack → dir.
//         Record (dir, end_offset = end of pack containing want).
//       (MVP handles the first want; multi-want is a follow-up.)
//    2. Walk the dir chain root → … → target dir.
//    3. For each have sha:
//         LSM lookup → (file_id, log_off) → containing pack →
//         dir → start offset of the pack containing the have.
//         Per dir in the chain, take max(have starts) as the
//         watermark.  Dirs with no matching have stay at offset 12
//         (start of first object in pack log file).
//    4. For each dir in the chain (root → … → target):
//         end = (dir == target) ? want's pack-end : tail-of-dir.
//         Append a pstr_seg { fd, start = watermark,
//                             length = end - start,
//                             count  = sum of pack obj_counts in
//                                      [watermark .. end) }.
//
//  Phase 1c reality: keeper has only the trunk shard (nshards=1), so
//  the dir chain is always [trunk].  Code is shaped so multi-shard
//  fan-out is a drop-in once Phase 2 of the keeper roadmap lights up
//  sibling shards.
//
//  WIREServeUpload glues the three pieces:
//    request --[in_fd]--> wire_req
//    wire_req + keeper + refadv --> pstr_segs
//    pstr_segs --[PSTRWrite]--> packfile bytes on out_fd
//  No side-band-64k framing in this MVP — git clients accept raw pack
//  bytes when the side-band cap was not advertised by them.

#include "abc/INT.h"
#include "abc/OK.h"
#include "abc/S.h"
#include "abc/B.h"
#include "dog/SHA1.h"
#include "keeper/KEEP.h"
#include "keeper/REFADV.h"
#include "keeper/PSTR.h"

con ok64 WIREFAIL    = 0x8126ce3ca495;
con ok64 WIREBADREQ  = 0x8126ce2ca35b39a;
con ok64 WIRENOWANT  = 0x8126ce5d880a5dd;
con ok64 WIRENOSHA   = 0x2049b39761c44a;

#define WIRE_MAX_WANTS  64
#define WIRE_MAX_HAVES  256

//  Capability bits parsed off the first want line.
#define WIRE_CAP_OFS_DELTA       (1u << 0)
#define WIRE_CAP_SIDE_BAND_64K   (1u << 1)
#define WIRE_CAP_MULTI_ACK_DET   (1u << 2)
#define WIRE_CAP_THIN_PACK       (1u << 3)
#define WIRE_CAP_NO_PROGRESS     (1u << 4)

//  Parsed client request after pkt-line drain.  Wants and haves are
//  20-byte SHA-1s converted from the 40-hex-on-the-wire form.
typedef struct {
    sha1  wants[WIRE_MAX_WANTS];
    u32   nwants;
    sha1  haves[WIRE_MAX_HAVES];
    u32   nhaves;
    u32   caps;
} wire_req;

typedef wire_req       *wire_reqp;
typedef wire_req const *wire_reqcp;

//  Read pkt-lines from in_fd until "done" or flush-without-want.
//  Parses each line as want/have/done and populates `req`.  Returns
//  OK on success, WIREBADREQ on malformed lines.  Capability list is
//  parsed off the first want line only.  `req` is reset on entry.
ok64 WIREReadRequest(int in_fd, wire_reqp req);

//  Build the segment list for one upload-pack response.
//
//  Inputs:
//    k       — open keeper (Phase 1c: trunk shard only).
//    adv     — refs advertisement (built via REFADVOpen).
//    req     — parsed wire_req.
//    fd_pool — caller-allocated array of length cap.  WIRE opens
//              one fd per dir in the chain and writes them here so
//              the caller can close them after PSTRWrite consumes
//              the segments.  Each pool entry parallels out_segs[i].
//
//  Outputs:
//    out_segs[0..*out_n) — pstr_segs in root → target order.
//    *out_n              — populated segment count.
//
//  Returns OK / WIRENOSHA (a want sha is not in our store) /
//  WIREFAIL (open or index error) / WIRENOWANT (req.nwants == 0
//  with no haves; out_n=0, no fds opened — empty pack on the wire).
ok64 WIREBuildSegments(keeper *k, refadvcp adv, wire_reqcp req,
                       pstr_seg *out_segs, int *fd_pool,
                       u32 cap, u32 *out_n);

//  Convenience: do the whole upload-pack response in one call.
//  Reads request from in_fd, builds segments, writes packfile to
//  out_fd.  side-band-64k framing is wrapped in a follow-up; this
//  MVP writes raw pack bytes (git clients accept raw if no
//  side-band cap was advertised).
//
//  Sends "NAK\n" pkt-line ahead of the pack stream (canonical reply
//  when no haves were ACK'd in this MVP).
ok64 WIREServeUpload(int in_fd, int out_fd, keeper *k, refadvcp adv);

// --- client side (Phase 7) ---------------------------------------------

con ok64 WIRECLFL  = 0x8126ce3153d5;
con ok64 WIRECLNRF = 0x2049b38c5576cf;

//  Spawn a git-protocol peer (ssh or local exec) and run a fetch
//  conversation: drain refs advertisement, send wants/haves, read pack.
//  Ingest the pack into `k` (via KEEPIngestFile) and append a REFS
//  entry pointing `?heads/<name>` (or `?tags/<name>`) → `?<sha>`.
//
//  `remote_uri` forms:
//    //host/path        → ssh host "keeper upload-pack path"  (preferred)
//    //host/path.git    → ssh host "git-upload-pack path.git" (real git)
//    file:///path       → exec "keeper upload-pack path" locally
//    keeper://local/p   → exec "keeper upload-pack p" locally
//
//  `want_ref` selects the advertised ref the caller wants.  Forms:
//    "heads/<name>"     match against "refs/heads/<name>"
//    "tags/<name>"      match against "refs/tags/<name>"
//    "refs/<...>"       match the full refname
//    ""                 use the peer's first-line / HEAD ref
//
//  Returns OK on success, WIRECLNRF if the peer doesn't advertise
//  the requested ref, WIRECLFL on transport / ingest errors.
ok64 WIREFetch(keeper *k, u8csc remote_uri, u8csc want_ref);

//  Spawn a git-protocol peer (ssh or local exec) and run a push
//  conversation: drain peer's refs advertisement, locate peer's tip
//  for the chosen branch, send a single ref-update + a packfile that
//  carries everything reachable from our local tip but not from the
//  peer's tip (MVP: ships the full reachable set, server filters).
//  Reads back unpack/per-ref status; OK iff peer accepted the update.
//
//  `local_branch` is the local refname to push, e.g. "heads/main" or
//  "main".  The same name is offered to the peer (`refs/heads/<X>`).
//
//  Returns OK on success, WIRECLNRF if the local branch has no
//  REFS entry, WIRECLFL on transport / pack-build / refusal.
ok64 WIREPush(keeper *k, u8csc remote_uri, u8csc local_branch);

#endif
