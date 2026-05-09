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
//  Step 2 reality: WIRE still scans only the trunk dir's pack file
//  (file_id 1).  Multi-branch fan-out — picking up the segment in
//  the leaf branch dir, walking trunk → leaf to find the right pack
//  file — is a follow-up.  The keeper-level k->puppies registry now
//  flattens every dir along the open branch path, so the index-side
//  scans here are already branch-aware.
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

//  Bulk fetch: drive a single upload-pack session that sends one
//  `want <sha>` per peer-advertised heads/tags ref.  The peer streams
//  back one packfile carrying the union of all wants' reachable
//  closures; KEEPIngestStream lands every object in our log.  Each
//  matched ref is recorded under the peer URI so subsequent cached
//  reads (`be ... //origin?<X>`) hit `.dogs/refs`.  Capped at 64
//  refs per session — past that, trailing entries are skipped.
//
//  Returns OK on success (zero refs is OK — peer advertised none),
//  WIRECLFL on transport / ingest errors.
ok64 WIREFetchAll(keeper *k, u8csc remote_uri);

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
//  `local_tip` is the authoritative sha to push.  Callers in the
//  worktree path (sniff at-log driven) read it from `.sniff` and
//  pass it down — keeper-side REFS may lag if the wt advanced via
//  a sniff path that didn't reach REFS-append, so the wt's at_sha
//  is the source of truth, not REFADV.
//
//  Returns OK on success, WIRECLNRF if local_tip is zero,
//  WIRECLFL on transport / pack-build / refusal.
ok64 WIREPush(keeper *k, u8csc remote_uri, u8csc local_branch,
              sha1 const *local_tip);

//  Spawn a git-protocol peer and run a delete-only push: drain the
//  advertisement, look up the peer's tip for `local_branch`, send
//  `<peer_old> 000…0 refs/heads/<X>` + flush (no pack body — git's
//  receive-pack accepts a delete-only command without a packfile),
//  and drain the report-status response.
//
//  `local_branch` is be-side (empty selects trunk → wire alias
//  `refs/heads/main`).  Returns OK on accept, WIRECLNRF if the peer
//  did not advertise the ref (nothing to delete), WIRECLFL on
//  transport failure or peer refusal.
ok64 WIREPushDelete(keeper *k, u8csc remote_uri, u8csc local_branch);

// --- pkt-line text payload classifier -----------------------------------
//
//  Pure function.  Caller has already extracted one complete pkt-line
//  payload (e.g. via PKTu8sDrain) and chosen a role.  Slices in *out
//  point into `payload`; copy what you want to outlive it.
//
//    OK           — out populated.
//    WIREBADREQ   — payload is malformed for this role.

typedef enum {
    WIRE_WANT,
    WIRE_HAVE,
    WIRE_DONE,
    WIRE_SHALLOW,
    WIRE_ACK,
    WIRE_NAK,
    WIRE_REF,             // <sha> SP <name>[\0 caps]
    WIRE_UPDATE,          // <old> SP <new> SP <name>[\0 caps]
} wire_evt_kind;

typedef enum {
    WIRE_UPLOAD,          // client → server (fetch): want/have/done/shallow
    WIRE_RECEIVE,         // client → server (push):  <old> <new> <name>
    WIRE_ADVERT,          // server → client:         ref advert lines
    WIRE_CLIENT,          // server → client during nego: ack/nak/ref
} wire_role;

typedef struct {
    wire_evt_kind kind;
    sha1          sha, old_sha;
    u8cs          caps;
    u8cs          name;
} wire_evt;

ok64 WIREClassify(u8csc payload, wire_role role, wire_evt *out);

#endif
