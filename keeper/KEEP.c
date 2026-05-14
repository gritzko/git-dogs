//  KEEP: local git object store.
//
//  Stores git packfiles under .be/ (trunk-flat) indexed by u64→w64
//  in LSM sorted runs of wh128 entries.
//
#include "KEEP.h"
#include "REFS.h"

#include "DELT.h"
#include "PACK.h"
#include "SHA1.h"
#include "ZINF.h"

#include <dirent.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "abc/BUF.h"
#include "abc/FILE.h"
#include "abc/HEX.h"
#include "abc/PATH.h"
#include "abc/PRO.h"
#include "abc/POL.h"
#include "abc/RON.h"
#include "dog/DOG.h"
#include "dog/DPATH.h"
#include "dog/HOME.h"
#include "UNPK.h"

// wh128 templates for LSM index runs and waiter buffers
#define X(M, name) M##wh128##name
#include "abc/QSORTx.h"
#include "abc/HITx.h"
#undef X

// kv64 templates used by the upload-pack negotiation below:
//   HEAP: priority queue over (log_offset_inverted, sha_table_index)
//   HASH: visited-sha set, keyed by SHA hashlet60
#define X(M, name) M##kv64##name
#include "abc/HEAPx.h"
#include "abc/HASHx.h"
#undef X

#define KEEP_BUFSZ (1ULL << 30)  // 1 GB working buffer (mmap'd, pages on demand)

u8c *const KEEP_DIR_S[2] = {
    (u8c *)KEEP_DIR,
    (u8c *)KEEP_DIR + sizeof(KEEP_DIR) - 1,
};

// --- Helpers ---

// Build <h->root>/.be/ into `out`.  The worktree root has
// already been resolved by HOMEOpen.
static ok64 keep_resolve_dir(path8b out, home *h) {
    sane(out && h);
    a_dup(u8c, root_s, u8bDataC(h->root));
    call(PATHu8bFeed, out, root_s);
    a_cstr(rel, "/" KEEP_DIR);
    call(u8bFeed, out, rel);
    call(PATHu8bTerm, out);
    done;
}

// Build <h->root>/.be[/<branch>] into `out` (NUL-terminated path).
// Empty branch → trunk dir.  `branch` may be in DPATHBranchNormFeed
// canonical form (trailing '/'); PATHu8bAdd splits on '/' and pushes
// each segment, so trailing slash is harmless.
static ok64 keep_branch_dir(path8b out, home *h, u8cs branch) {
    sane(out && h);
    a_path(kdir, u8bDataC(h->root), KEEP_DIR_S);
    call(PATHu8bDup, out, $path(kdir));
    if (!u8csEmpty(branch)) {
        call(PATHu8bAdd, out, branch);
    }
    done;
}

// Scan one branch dir for both .keeper and .keeper.idx files,
// extending the keeper-level registries.  Lockless-reader invariant:
// pack scan first, then idx, so any idx entry references a pack
// already in our maps.
static ok64 keep_scan_branch_dir(keeper *k, u8csc keepdir) {
    sane(k);
    a_cstr(pack_ext, KEEP_PACK_EXT);
    call(DOGPupOpenAll, k->packs, keepdir, pack_ext);
    a_cstr(idx_ext, KEEP_IDX_EXT);
    call(DOGPupOpenAll, k->puppies, keepdir, idx_ext);
    done;
}

//  Filename → seqno.  Returns 0 on parse failure or non-keeper file.
//  Accepts `<10-RON64>.keeper` and `<10-RON64>.keeper.idx`.
static u32 keep_filename_seqno(u8cs name) {
    static char const KEXT[]  = ".keeper";
    static char const IEXT[]  = ".keeper.idx";
    static const size_t SEQ_W = 10;
    size_t n = u8csLen(name);
    if (n != SEQ_W + sizeof(KEXT) - 1 &&
        n != SEQ_W + sizeof(IEXT) - 1) return 0;
    char const *tail = (char const *)name[0] + SEQ_W;
    if (memcmp(tail, KEXT, sizeof(KEXT) - 1) == 0 &&
        n == SEQ_W + sizeof(KEXT) - 1) {
        /* OK */
    } else if (memcmp(tail, IEXT, sizeof(IEXT) - 1) == 0 &&
               n == SEQ_W + sizeof(IEXT) - 1) {
        /* OK */
    } else {
        return 0;
    }
    u8cs seq_s = {name[0], name[0] + SEQ_W};
    ok64 v = 0;
    if (RONutf8sDrain(&v, seq_s) != OK) return 0;
    return (u32)v;
}

//  Path-callback: track max seqno across every `.keeper` / `.keeper.idx`
//  filename under `<root>/.be/` (recursive).  Ctx is a `u32 *max`.
static ok64 keep_max_seqno_cb(void0p arg, path8p path) {
    u32 *max = (u32 *)arg;
    u8cs base = {};
    PATHu8sBase(base, u8bDataC(path));
    u32 sq = keep_filename_seqno(base);
    if (sq > *max) *max = sq;
    return OK;
}

//  Recursively scan `<root>/.be/` for every `.keeper` / `.keeper.idx`
//  file and return the global max seqno (default 0 when none found).
//  Used by `keep_recompute_next_seqno` to keep fresh seqnos unique
//  across sibling branches that are NOT loaded into the registry
//  (only trunk → leaf is loaded; siblings stay on disk).  Cheap:
//  one recursive dir-listing pass at open time, no file mmaps.
static u32 keep_global_max_seqno(home *h) {
    u32 max = 0;
    a_path(bedir, u8bDataC(h->root), KEEP_DIR_S);
    (void)FILEDeepScanFiles(bedir, keep_max_seqno_cb, &max);
    return max;
}

// Update k->next_seqno = max(any seqno on disk under `.be/`) + 1.
// Default 1 when no pack/idx files exist anywhere.  Scans the whole
// `.be/` tree on disk — not just loaded PAST+DATA — so sibling
// branches' seqnos (never loaded into the registry) still don't
// collide with a freshly-created leaf pack.
static void keep_recompute_next_seqno(keeper *k) {
    u32 max = keep_global_max_seqno(k->h);
    //  Defensive: in case PAST/DATA contains a seqno that's no longer
    //  on disk (registry races, edge cases), take the larger.
    kv32s packs_all = {};
    kv32PastDataS(k->packs, packs_all);
    for (kv32 const *p = packs_all[0]; p < packs_all[1]; p++)
        if (p->key > max) max = p->key;
    kv32s pups_all = {};
    kv32PastDataS(k->puppies, pups_all);
    for (kv32 const *p = pups_all[0]; p < pups_all[1]; p++)
        if (p->key > max) max = p->key;
    k->next_seqno = max + 1;
}

// Largest seqno currently in the packs registry, or 0 if empty.  Used
// to pick the file_id of the tail pack to append to — distinct from
// next_seqno, which spans both packs and puppies.  When puppies has
// advanced past packs (e.g. an incremental idx run was added without
// a fresh pack), next_seqno - 1 no longer points at the tail pack.
static u32 keep_packs_max_seqno(keeper const *k) {
    u32 max = 0;
    kv32 const *db = (kv32 const *)kv32bDataHead(k->packs);
    kv32 const *de = (kv32 const *)kv32bIdleHead(k->packs);
    for (kv32 const *p = db; p < de; p++)
        if (p->key > max) max = p->key;
    return max;
}

//  Linear-scan the keeper-level pack registry for the (seqno=file_id)
//  entry; return the mmap'd buffer via FILE_WANT_BUFS[fd], or NULL
//  when not present or the slot has been released.  Scans both PAST
//  (parent / read-only pack registrations from trunk → … → ancestor)
//  and DATA (the active leaf branch) — cross-branch object resolution
//  needs visibility into every loaded pack.
static u8bp keep_pack_buf(keeper const *k, u32 file_id) {
    if (file_id == 0) return NULL;
    kv32s all = {};
    kv32PastDataS(k->packs, all);
    for (kv32 const *p = all[0]; p < all[1]; p++) {
        if (p->key != file_id) continue;
        u8bp slot = FILE_WANT_BUFS[p->val];
        if (!slot || !slot[0]) return NULL;
        return slot;
    }
    return NULL;
}

//  Add-or-replace the (seqno → fd) entry for `ro` in the keeper-level
//  registry.  `ro` must be a booked u8bp (i.e. it points into
//  FILE_WANT_BUFS so FILEBookedFD can recover the fd).  Returns
//  KEEPNOROOM when the registry is full.
static ok64 keep_pack_install(keeper *k, u32 seqno, u8bp ro) {
    sane(k && ro);
    int fd = FILEBookedFD(ro);
    if (fd < 0) return KEEPFAIL;
    kv32 *db = (kv32 *)kv32bDataHead(k->packs);
    kv32 *de = (kv32 *)kv32bIdleHead(k->packs);
    for (kv32 *p = db; p < de; p++) {
        if (p->key == seqno) { p->val = (u32)fd; return OK; }
    }
    kv32 kv = {.key = seqno, .val = (u32)fd};
    return kv32bPush(k->packs, &kv);
}

//  Drop the (seqno) entry from the registry.  Caller is responsible
//  for unmapping the slot (via FILEUnMap) before or after as needed.
static void keep_pack_drop(keeper *k, u32 seqno) {
    if (seqno == 0) return;
    kv32 *db = (kv32 *)kv32bDataHead(k->packs);
    kv32 *de = (kv32 *)kv32bIdleHead(k->packs);
    for (kv32 *p = db; p < de; p++) {
        if (p->key != seqno) continue;
        //  Compact: shift tail down by one, retract data end.
        for (kv32 *q = p; q + 1 < de; q++) *q = *(q + 1);
        ((kv32 **)k->packs)[2] = de - 1;
        return;
    }
}

//  Drop the (seqno) entry from the keeper-level puppies registry.
//  Mirrors keep_pack_drop; caller is responsible for unmapping the
//  slot first when needed.
static void keep_idx_drop(keeper *k, u32 seqno) {
    if (seqno == 0) return;
    kv32 *db = (kv32 *)kv32bDataHead(k->puppies);
    kv32 *de = (kv32 *)kv32bIdleHead(k->puppies);
    for (kv32 *p = db; p < de; p++) {
        if (p->key != seqno) continue;
        for (kv32 *q = p; q + 1 < de; q++) *q = *(q + 1);
        ((kv32 **)k->puppies)[2] = de - 1;
        return;
    }
}

//  Read the i-th index run as a wh128 slice (zero-copy view into
//  FILE_WANT_BUFS via the puppy's fd).  DATA only — the leaf branch's
//  runs.  Used by `KEEPCompact` (which by spec only ever merges /
//  thins leaf-owned runs; see KEEP.h §"Branch-aware object store").
fun void keep_run_at(wh128csp out, keeper const *k, u32 i) {
    u8cs raw = {NULL, NULL};
    DOGPupData(raw, k->puppies, i);
    out[0] = (wh128cp)raw[0];
    out[1] = (wh128cp)raw[1];
}

//  Like `keep_run_at` but indexes into PastData — every loaded idx
//  run including the inherited parent-dir runs.  Used by every
//  cross-branch read path (KEEPLookup, KEEPGetExact).  Returns an
//  empty slice when `i` is out-of-range or the slot was released.
fun void keep_run_at_all(wh128csp out, keeper const *k, u32 i) {
    out[0] = NULL; out[1] = NULL;
    kv32s pups_all = {};
    kv32PastDataS(k->puppies, pups_all);
    size_t n = (size_t)(pups_all[1] - pups_all[0]);
    if (i >= n) return;
    u32 fd = pups_all[0][i].val;
    u8bp slot = FILE_WANT_BUFS[fd];
    if (!slot || !slot[0]) return;
    out[0] = (wh128cp)slot[0];
    out[1] = (wh128cp)slot[2];
}

fun u32 keep_run_count_all(keeper const *k) {
    return (u32)kv32bPastDataLen(k->puppies);
}

//  Create a fresh idx run in the leaf dir using a globally-unique
//  seqno (`k->next_seqno`), then advance `next_seqno` on success.
//  Centralises the "DOGPupCreate, but globally unique" pattern that
//  every keeper-side idx publisher needs after the PAST/DATA
//  partition (DOGPupCreate's default max(DATA)+1 only spans the leaf).
static ok64 keep_pup_create_next(keeper *k, path8s dir, u8cs ext,
                                 u8cs data) {
    sane(k && $ok(dir));
    u32 seqno = k->next_seqno;
    call(DOGPupCreateAt, k->puppies, dir, ext, data, seqno);
    if (seqno >= k->next_seqno) k->next_seqno = seqno + 1;
    done;
}

// --- Singleton ---

keeper KEEP = {};

//  `KEEP.h` being non-NULL indicates that KEEPOpen has populated the
//  singleton and KEEPClose hasn't yet released it.
static b8 keep_is_open(void) { return KEEP.h != NULL; }

//  Detect the ro/rw state of the currently-held flock.  If we Open'd
//  with rw=YES we took LOCK_EX; rw=NO took LOCK_SH.  We save the bit
//  so subsequent Open calls can detect mode mismatches.
static b8 keep_is_rw = NO;

// --- Open: mmap pack files + load index runs ---

//  YES iff `path` (NUL-terminated u8b) is an existing directory.
static b8 keep_dir_exists(path8s path) {
    filestat fs = {};
    if (FILEStat(&fs, path) != OK) return NO;
    return fs.kind == FILE_KIND_DIR;
}

//  Walk one branch path component at a time, calling `dir_cb` for
//  each prefix dir (trunk first).  `dir_cb` receives a freshly-built
//  path8 slice (NUL-terminated) for each prefix dir along trunk → leaf
//  plus an `is_leaf` flag — YES on the last call (trunk's call when
//  `leaf` is empty, otherwise the deepest segment's call).  Callbacks
//  use the flag to flip a PAST/DATA boundary on the active branch
//  registries before scanning the owned leaf dir.
//  Stops on first non-OK from `dir_cb`.
typedef ok64 (*keep_dir_cb)(keeper *k, u8cs dir, b8 is_leaf, void0p ctx);

static ok64 keep_walk_branch(keeper *k, u8cs leaf, keep_dir_cb cb, void0p ctx) {
    sane(k && cb);
    a_path(kdir, u8bDataC(k->h->root), KEEP_DIR_S);
    //  Trunk first.  Empty `leaf` means trunk IS the leaf.
    b8 trunk_is_leaf = u8csEmpty(leaf);
    {
        a_path(d);
        call(PATHu8bDup, d, $path(kdir));
        call(cb, k, $path(d), trunk_is_leaf, ctx);
    }
    if (trunk_is_leaf) done;

    //  Identify where the last segment begins; we need the cb to know
    //  it's looking at the leaf BEFORE the scan runs (so it can flip
    //  its PAST/DATA boundary first).  We scan once to find the last
    //  '/'+1 offset, then the main loop checks against it.
    u8cp last_seg_start = leaf[0];
    for (u8cp p = leaf[0]; p < leaf[1]; p++)
        if (*p == '/' && p + 1 < leaf[1]) last_seg_start = p + 1;

    //  Each '/'-separated leaf component, accumulating.
    a_path(d);
    call(PATHu8bDup, d, $path(kdir));
    u8cp p = leaf[0];
    u8cp seg_start = p;
    while (p <= leaf[1]) {
        b8 at_end = (p == leaf[1]);
        if (at_end || *p == '/') {
            if (p > seg_start) {
                u8cs seg = {seg_start, p};
                call(PATHu8bPush, d, seg);
                b8 is_leaf = (seg_start == last_seg_start);
                call(cb, k, $path(d), is_leaf, ctx);
            }
            seg_start = p + 1;
        }
        p++;
    }
    done;
}

static ok64 keep_open_dir_cb(keeper *k, u8cs dir, b8 is_leaf, void0p ctx) {
    (void)ctx;
    //  Branch shard dirs are materialised lazily: a branch may be
    //  created (REFS row written) before any commit shards land in
    //  its own dir.  Treat a missing ancestor/leaf dir as "no shards
    //  inherited from here" — REFS at the sniff layer is the source
    //  of truth on branch existence.  Writes (KEEPPackOpen) mkdir
    //  the leaf on demand.
    b8 exists = keep_dir_exists(dir);
    //  About to scan the leaf dir: freeze the parents' DATA (everything
    //  accumulated so far for trunk + intermediate ancestor dirs) into
    //  PAST on both `packs` and `puppies`.  Writes target the leaf
    //  (`KEEPPackOpen` picks `file_id` from `next_seqno`; KEEPCompact
    //  iterates DATA-only via `kv32bDataLen(k->puppies)`).  Reads use
    //  `kv32PastDataS` so cross-branch resolution stays whole.
    //  Trunk-only branches skip the flip — DATA = trunk entries,
    //  PAST stays empty.  See KEEP.h §"Branch-aware object store" and
    //  abc/Bx.h §PastDataS.
    if (is_leaf) {
        if (kv32bDataLen(k->packs) > 0)
            ((kv32 **)k->packs)[1] = (kv32 *)k->packs[2];
        if (kv32bDataLen(k->puppies) > 0)
            ((kv32 **)k->puppies)[1] = (kv32 *)k->puppies[2];
    }
    if (!exists) return OK;
    return keep_scan_branch_dir(k, dir);
}

ok64 KEEPOpenBranch(home *h, u8cs branch, b8 rw) {
    sane(h != NULL && $ok(branch));

    // Normalize.  Empty canonical form = trunk.
    a_pad(u8, nb, KEEP_LEAF_BRANCH_MAX);
    call(DPATHBranchNormFeed, nb, branch);
    a_dup(u8c, norm, u8bDataC(nb));

    //  Already open?  Compatible if the existing mode is at least as
    //  strong as the request.  The only true conflict is an rw request
    //  against a ro-open keeper — invalidates live pointers if we
    //  reopened, so caller must reshuffle their scope.
    if (keep_is_open()) {
        if (rw && !keep_is_rw) return KEEPOPENRO;
        return KEEPOPEN;
    }

    // Register on the process-wide home singleton.  Idempotent — a
    // compatible re-open is silently absorbed.  HOMEROBR (rw on
    // anything but the first slot) and HOMEMAX (capacity exhausted)
    // mean the home can't track this branch as the writeable one,
    // but the keeper itself is fine to proceed (it has its own lock
    // on the leaf dir).  This pattern shows up when the test/CLI
    // opens trunk, closes, then opens a feature branch in the same
    // process — the home keeps the trunk slot, but the keeper now
    // legitimately writes to a different leaf.
    {
        ok64 o = HOMEOpenBranch(h, branch, rw);
        if (o != OK && o != HOMEOPEN && o != HOMEROBR && o != HOMEMAX)
            return o;
    }

    keeper *k = &KEEP;
    zerop(k);
    k->h = h;
    k->lock_fd = -1;
    call(kv32bAllocate, k->puppies, FILE_MAX_OPEN);
    call(kv32bAllocate, k->packs,   KEEP_MAX_FILES);
    k->next_seqno = 1;
    keep_is_rw = rw;

    //  Stash the canonical leaf-branch bytes in keeper-owned storage.
    //  path8b is heap-backed (matches home->root style); freed in
    //  KEEPClose.  Empty `norm` (trunk) leaves DATA empty but the
    //  buffer is still NUL-terminated by PATHu8bTerm so $path() works.
    if (u8csLen(norm) >= KEEP_LEAF_BRANCH_MAX) return KEEPFAIL;
    call(u8bAllocate, k->leaf_branch, KEEP_LEAF_BRANCH_MAX);
    call(PATHu8bTerm, k->leaf_branch);
    if (!u8csEmpty(norm)) call(PATHu8bFeed, k->leaf_branch, norm);

    //  Trunk dir always exists after this — sniff/init creates it.
    a_path(trunkdir, u8bDataC(h->root), KEEP_DIR_S);
    call(FILEMakeDirP, $path(trunkdir));

    //  Walk trunk → … → leaf, registering every pack + idx file along
    //  the way.  Missing prefix dirs short-circuit with KEEPNONE.
    {
        a_dup(u8c, leaf, u8bDataC(k->leaf_branch));
        ok64 wo = keep_walk_branch(k, leaf, keep_open_dir_cb, NULL);
        if (wo != OK) {
            //  Tear down partially-allocated state to keep the singleton clean.
            if (!BNULL(k->packs))       DOGPupClose(k->packs);
            if (!BNULL(k->puppies))     DOGPupClose(k->puppies);
            if (!BNULL(k->leaf_branch)) u8bFree(k->leaf_branch);
            zerop(k);
            keep_is_rw = NO;
            return wo;
        }
    }

    keep_recompute_next_seqno(k);

    //  Worktree sharing: take an exclusive lock on the LEAF dir (writes
    //  only land in the deepest dir).  For trunk leaf this is
    //  `.be/.lock`.  Readers open lockless — the idx-before-packs
    //  scan order plus idx-via-rename publication keep readers
    //  consistent without blocking on slow writers.
    if (rw) {
        a_path(leafdir);
        a_dup(u8c, leaf, u8bDataC(k->leaf_branch));
        call(keep_branch_dir, leafdir, h, leaf);
        //  Lazy materialisation: branches "created" via REFS may not
        //  have a shard dir on disk yet.  mkdir -p before lock open.
        call(FILEMakeDirP, $path(leafdir));
        a_pad(u8, lockpath, FILE_PATH_MAX_LEN);
        u8bFeed(lockpath, $path(leafdir));
        a_cstr(lockrel, "/.lock");
        u8bFeed(lockpath, lockrel);
        PATHu8bTerm(lockpath);
        call(FILECreate, &k->lock_fd, $path(lockpath));
        call(FILELock,   &k->lock_fd, rw);
    }

    // Pre-allocate working buffers for KEEPGet (mmap, reset per call)
    call(u8bMap, k->buf1, KEEP_BUFSZ);
    call(u8bMap, k->buf2, KEEP_BUFSZ);
    call(u8bMap, k->buf3, KEEP_BUFSZ);
    call(u8bMap, k->buf4, KEEP_BUFSZ);

    done;
}

ok64 KEEPOpen(home *h, b8 rw) {
    //  Empty-but-valid slice: both ends point at the same byte so
    //  $ok(branch) holds in KEEPOpenBranch's sanity check.
    static u8c const _zero = 0;
    u8cs trunk = {(u8cp)&_zero, (u8cp)&_zero};
    return KEEPOpenBranch(h, trunk, rw);
}

// --- KEEPSwitchBranch ------------------------------------------------
//
// Re-target keeper from current leaf to `new_branch`.  See KEEP.h.
// Pseudocode:
//   1. Normalize new_branch.
//   2. Compute LCA-prefix length of (old_leaf, new_branch).
//   3. Flip DATA→PAST on both `packs` and `puppies` (the old leaf's
//      entries become part of the read-only context).
//   4. For each '/'-separated segment of new_branch past the LCA,
//      keep_scan_branch_dir into the new leaf dir.  On the LAST
//      segment, this is the new DATA fill (no further flip needed —
//      DATA is already empty after step 3).
//   5. Recompute next_seqno across PastData ∪ PastData.
//   6. In rw mode, swap the flock: release the old leaf's `.lock`,
//      take an exclusive lock on the new leaf's `.lock`.
//   7. Update k->leaf_branch.

//  Longest shared '/'-bounded prefix of `a` and `b`, in bytes.
//  Returns the offset at which they first differ at a segment
//  boundary; the slice [0, n) of either name covers ancestors
//  already loaded as PAST.  Empty bytes for the trunk-only case.
//  Examples:
//    ("feat",  "other")         → 0   (no shared segment)
//    ("feat",  "feat/sub")      → 5   ("feat" is an ancestor of
//                                       feat/sub; trailing '/' aware)
//    ("feat/sub1", "feat/sub2") → 5   ("feat/" is shared)
//    ("feat/sub", "feat/sub")   → 8   (identical)
static size_t keep_branch_lca_prefix(u8cs a, u8cs b) {
    size_t na = u8csLen(a), nb = u8csLen(b);
    size_t n = na < nb ? na : nb;
    size_t matched = 0;        // count of bytes that matched bytewise
    size_t last_slash = 0;     // boundary at start = trunk-only LCA
    for (; matched < n; matched++) {
        if (a[0][matched] != b[0][matched]) break;
        if (a[0][matched] == '/') last_slash = matched + 1;
    }
    //  Whole-string match: the shorter is an exact ancestor of the
    //  longer iff matched == min(na, nb) AND either na == nb OR the
    //  next byte in the longer is '/'.
    if (matched == n) {
        if (na == nb) return na;
        u8cp longer_head = (na > nb) ? a[0] : b[0];
        if (longer_head[n] == '/') return n;
    }
    return last_slash;
}

ok64 KEEPSwitchBranch(home *h, u8cs new_branch) {
    sane(h != NULL && $ok(new_branch));
    keeper *k = &KEEP;
    if (!keep_is_open()) return KEEPFAIL;

    //  Normalize.
    a_pad(u8, nb, KEEP_LEAF_BRANCH_MAX);
    call(DPATHBranchNormFeed, nb, new_branch);
    a_dup(u8c, norm, u8bDataC(nb));

    //  No-op when already on the requested branch.
    a_dup(u8c, cur, u8bDataC(k->leaf_branch));
    if (u8csLen(cur) == u8csLen(norm) &&
        (u8csLen(norm) == 0 ||
         memcmp(cur[0], norm[0], u8csLen(norm)) == 0))
        done;

    //  LCA: bytes of `norm` already covered by k->packs PAST (and
    //  by the old leaf's DATA, which we're about to PAST).
    size_t lca = keep_branch_lca_prefix(cur, norm);

    //  1. Collapse old leaf's DATA into PAST on both registries.
    if (kv32bDataLen(k->packs) > 0)
        ((kv32 **)k->packs)[1] = (kv32 *)k->packs[2];
    if (kv32bDataLen(k->puppies) > 0)
        ((kv32 **)k->puppies)[1] = (kv32 *)k->puppies[2];

    //  2. Walk the new tail.  PATHu8bDup the trunk-keepdir, push
    //  every full-prefix path of `norm`, but only INVOKE scan for
    //  segments past the LCA.
    a_path(d, u8bDataC(h->root), KEEP_DIR_S);
    if (u8csLen(norm) > 0) {
        u8cp p = norm[0];
        u8cp seg_start = p;
        size_t off = 0;
        while (p <= norm[1]) {
            b8 at_end = (p == norm[1]);
            if (at_end || *p == '/') {
                if (p > seg_start) {
                    u8cs seg = {seg_start, p};
                    call(PATHu8bPush, d, seg);
                    //  Only scan if we've crossed the LCA boundary.
                    if (off >= lca) {
                        if (!keep_dir_exists($path(d))) return KEEPNONE;
                        call(keep_scan_branch_dir, k, $path(d));
                    }
                }
                seg_start = p + 1;
                off = (size_t)(p - norm[0]) + 1;
            }
            p++;
        }
    }

    //  3. next_seqno: span PastData ∪ PastData on both registries.
    keep_recompute_next_seqno(k);

    //  4. Swap the flock if we held one.  The old lock lives at the
    //  cur leaf dir; the new lock at the new leaf dir.  Trunk →
    //  leaf swaps `<root>/.be/.lock` for `<root>/.be/<leaf>/.lock`.
    if (k->lock_fd >= 0) {
        a_path(leafdir);
        call(keep_branch_dir, leafdir, h, norm);
        a_pad(u8, lockpath, FILE_PATH_MAX_LEN);
        u8bFeed(lockpath, $path(leafdir));
        a_cstr(lockrel, "/.lock");
        u8bFeed(lockpath, lockrel);
        PATHu8bTerm(lockpath);
        int newfd = -1;
        ok64 co = FILECreate(&newfd, $path(lockpath));
        if (co != OK) return co;
        ok64 lo = FILELock(&newfd, YES);
        if (lo != OK) { FILEClose(&newfd); return lo; }
        FILEClose(&k->lock_fd);
        k->lock_fd = newfd;
    }

    //  5. Update leaf_branch.
    u8bReset(k->leaf_branch);
    call(PATHu8bTerm, k->leaf_branch);
    if (!u8csEmpty(norm)) call(PATHu8bFeed, k->leaf_branch, norm);
    done;
}

ok64 KEEPCreateBranch(home *h, u8cs branch) {
    sane(h != NULL && $ok(branch));

    a_pad(u8, nb, KEEP_LEAF_BRANCH_MAX);
    call(DPATHBranchNormFeed, nb, branch);
    a_dup(u8c, norm, u8bDataC(nb));

    //  Trunk is always present.
    if (u8csEmpty(norm)) return KEEPTRUNK;

    //  Find the parent by trimming off the last '/'-separated component.
    //  Canonical form ends with '/', so first strip it, then look for
    //  the last internal '/'.  No internal '/' → parent is trunk.
    u8cs body = {norm[0], norm[1]};
    if (!u8csEmpty(body) && *(body[1] - 1) == '/') body[1]--;
    u8cp slash = NULL;
    for (u8cp p = body[0]; p < body[1]; p++) if (*p == '/') slash = p;
    u8cs parent = {body[0], slash ? slash : body[0]};

    //  Validate parent exists.
    a_path(pdir);
    call(keep_branch_dir, pdir, h, parent);
    if (!keep_dir_exists($path(pdir))) return KEEPNONE;

    //  Refuse if leaf already exists.
    a_path(leafdir);
    call(keep_branch_dir, leafdir, h, norm);
    if (keep_dir_exists($path(leafdir))) return KEEPDUP;

    //  mkdir leaf.  FILEMakeDirP is forgiving (idempotent), but we've
    //  already verified the leaf doesn't exist, so this materialises
    //  exactly the new dir.
    call(FILEMakeDirP, $path(leafdir));
    done;
}

// --- Update: feed a single git object into the store ---
//
// Convenience single-object path over KEEPPackOpen/Feed/Close.
// Opens a fresh pack log, writes one object, closes. For bulk
// ingestion prefer KEEPPackOpen/KEEPPackFeed/KEEPPackClose.
ok64 KEEPUpdate(keeper *k, u8 obj_type, u8cs blob) {
    sane(k && $ok(blob));
    keep_pack p = {};
    call(KEEPPackOpen, k, &p);
    u8csc content = {blob[0], blob[1]};
    sha1 sha = {};
    ok64 o = KEEPPackFeed(k, &p, obj_type, content, 0, &sha);
    KEEPPackClose(k, &p);
    return o;
}

// --- Close ---

static ok64 keep_idx_path(path8b out, u8csc kdir, u32 seqno);

// --- Compaction: merge youngest LSM runs into one (1/8 size-tiered) ---
//
// Mirrors spot's CAPOCompact / graf's dag_compact via the shared
// puppy API.  Builds a typed `wh128cs[]` view from the puppy stack,
// runs HITwh128Compact, then `DOGPupThinTail(m)` + `DOGPupCreate`
// to commit the merged run + drop the m sources.  No-op when the
// stack already satisfies the 1/8 invariant.
ok64 KEEPCompact(keeper *k) {
    sane(k);
    if (!keep_is_rw) done;
    u32 n = DOGPupCount(k->puppies);
    if (n < 2) done;

    //  Build typed view from puppy data slices.
    wh128cs runs[KEEP_MAX_LEVELS] = {};
    for (u32 i = 0; i < n && i < KEEP_MAX_LEVELS; i++)
        keep_run_at(runs[i], k, i);
    wh128css stack = {runs, runs + n};
    if (HITwh128IsCompact(stack)) done;

    size_t total = 0;
    for (u32 i = 0; i < n; i++)
        total += (size_t)(runs[i][1] - runs[i][0]);

    Bwh128 cbuf = {};
    call(wh128bAllocate, cbuf, total);
    wh128 *base = cbuf[0];
    wh128s into = {cbuf[0], cbuf[3]};
    size_t before_len = $len(stack);
    call(HITwh128Compact, stack, into);
    size_t m = before_len - $len(stack) + 1;
    if (m < 2) { wh128bFree(cbuf); done; }

    //  Compaction lands in the leaf branch dir (writes only land at
    //  the leaf).  The merged run subsumes the youngest m sources;
    //  any of those originally created in trunk are still dropped via
    //  DOGPupThinTail because the tail of the puppies stack is by
    //  seqno (== filename) — newer files always sit at the tail.
    a_path(leafdir);
    {
        a_dup(u8c, leaf, u8bDataC(k->leaf_branch));
        call(keep_branch_dir, leafdir, k->h, leaf);
    }
    a_cstr(ext, KEEP_IDX_EXT);
    u8cs merged = {(u8cp)base, (u8cp)(into[0])};
    //  Order: thin first (drops the m sources), then create (writes
    //  the new run with seqno = max(remaining)+1).
    call(DOGPupThinTail, k->puppies, $path(leafdir), ext, (u32)m);
    call(keep_pup_create_next, k, $path(leafdir), ext, merged);

    wh128bFree(cbuf);
    done;
}

ok64 KEEPClose(void) {
    sane(1);
    if (!keep_is_open()) return OK;
    keeper *k = &KEEP;
    if (keep_is_rw) (void)KEEPCompact(k);
    if (!BNULL(k->packs))       DOGPupClose(k->packs);
    if (!BNULL(k->puppies))     DOGPupClose(k->puppies);
    if (!BNULL(k->leaf_branch)) u8bFree(k->leaf_branch);
    if (k->buf1[0]) u8bUnMap(k->buf1);
    if (k->buf2[0]) u8bUnMap(k->buf2);
    if (k->buf3[0]) u8bUnMap(k->buf3);
    if (k->buf4[0]) u8bUnMap(k->buf4);
    if (k->lock_fd >= 0) FILEClose(&k->lock_fd);
    zerop(k);
    keep_is_rw = NO;
    done;
}

// --- Drop-a-dir: KEEPBranchDrop ---

typedef struct {
    keeper *k;
    u8cs    ext;
    void  (*drop_fn)(keeper *, u32);
} keep_drop_ctx;

static ok64 keep_branch_drop_cb(void0p arg, path8p path) {
    keep_drop_ctx *c = (keep_drop_ctx *)arg;
    u8cs base = {};
    PATHu8sBase(base, u8bDataC(path));
    if (u8csLen(base) != DOG_PUP_SEQNO_W + u8csLen(c->ext)) return OK;
    a_dup(u8c, ext_tail, base);
    u8csUsed(ext_tail, DOG_PUP_SEQNO_W);
    if (!u8csEq(ext_tail, c->ext)) return OK;

    u8cs seqno_slice = {base[0], base[0] + DOG_PUP_SEQNO_W};
    ok64 v = 0;
    if (RONutf8sDrain(&v, seqno_slice) != OK) return OK;
    u32 sq = (u32)v;

    Bkv32 *reg = (c->drop_fn == keep_pack_drop) ? &c->k->packs
                                                : &c->k->puppies;
    kv32 *db = (kv32 *)kv32bDataHead(*reg);
    kv32 *de = (kv32 *)kv32bIdleHead(*reg);
    for (kv32 *p = db; p < de; p++) {
        if (p->key != sq) continue;
        u8bp slot = FILE_WANT_BUFS[p->val];
        if (slot && slot[0]) FILEUnMap(slot);
        break;
    }
    c->drop_fn(c->k, sq);
    FILEUnLink(u8bDataC(path));
    return OK;
}

//  ls one branch dir for files matching `ext`; for each match, parse
//  its seqno, evict the entry from `reg` (closing any FILE_WANT_BUFS
//  slot), and unlink the file.  Returns OK even when the dir is empty.
static ok64 keep_branch_drop_files(keeper *k, u8cs branchdir, u8cs ext,
                                   void (*drop_fn)(keeper *, u32)) {
    sane(k);
    a_path(dpat, branchdir);
    keep_drop_ctx c = {.k = k, .ext = {ext[0], ext[1]}, .drop_fn = drop_fn};
    (void)FILEScanFiles(dpat, keep_branch_drop_cb, &c);
    done;
}

static ok64 keep_subdir_seen_cb(void0p arg, path8p path) {
    (void)path;
    *(b8 *)arg = YES;
    return KEEPNONE;  //  any non-OK aborts the scan
}

//  YES iff `branchdir` has any subdirectory (other than . / ..).
static b8 keep_branch_has_subdir(u8cs branchdir) {
    a_path(dpat, branchdir);
    b8 found = NO;
    (void)FILEScan(dpat, FILE_SCAN_DIRS, keep_subdir_seen_cb, &found);
    return found;
}

ok64 KEEPBranchDrop(keeper *k, u8cs branch) {
    sane(k && $ok(branch));

    a_pad(u8, nb, KEEP_LEAF_BRANCH_MAX);
    call(DPATHBranchNormFeed, nb, branch);
    a_dup(u8c, norm, u8bDataC(nb));

    //  Trunk is never droppable — store root plus paths registry plus
    //  the root-level `refs` (which carries host aliases) live there.
    if (u8csEmpty(norm)) return KEEPTRUNK;

    //  Branch must exist on disk.
    a_path(bdir);
    call(keep_branch_dir, bdir, k->h, norm);
    if (!keep_dir_exists($path(bdir))) return KEEPNONE;

    //  Refuse if `branch` IS the active leaf — caller must close+reopen
    //  on a different branch first.
    {
        a_dup(u8c, leaf, u8bDataC(k->leaf_branch));
        if (u8csEq(norm, leaf)) return KEEPDIRTY;
    }

    //  Refuse if branch has subdirs (descendants).
    if (keep_branch_has_subdir($path(bdir))) return KEEPDIRTY;

    //  Evict + unlink all .keeper.idx and .keeper files.  Idx first
    //  (preserves "idx references valid pack" invariant for any
    //  concurrent reader).
    {
        a_cstr(idx_ext, KEEP_IDX_EXT);
        u8cs ext = {idx_ext[0], idx_ext[1]};
        call(keep_branch_drop_files, k, $path(bdir), ext, keep_idx_drop);
    }
    {
        a_cstr(pack_ext, KEEP_PACK_EXT);
        u8cs ext = {pack_ext[0], pack_ext[1]};
        call(keep_branch_drop_files, k, $path(bdir), ext, keep_pack_drop);
    }

    //  Best-effort: unlink any sidecar shard files keeper doesn't
    //  own — graf's `.graf.idx` runs and lock, spot's lock.  These
    //  show up when a verb switched graf into this branch via
    //  `GRAFSwitchBranch` for a cross-branch read but the higher-
    //  level branch-delete only knows about keeper files.  Iterate
    //  the dir once and unlink anything matching the known suffixes.
    {
        a_path(scratch);
        call(PATHu8bDup, scratch, $path(bdir));
        size_t base_len = u8bDataLen(scratch);
        char const *names[] = {
            ".lock", ".lock.graf", ".lock.spot",
        };
        for (size_t i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
            ((u8 **)scratch)[2] = u8bDataHead(scratch) + base_len;
            a_cstr(rel_dummy, "x");  (void)rel_dummy;
            u8cs nm = {(u8c *)names[i],
                       (u8c *)names[i] + strlen(names[i])};
            if (PATHu8bPush(scratch, nm) == OK)
                FILEUnLink($path(scratch));
        }
        //  Also unlink any `.graf.idx` files matching `<seqno>.graf.idx`.
        ((u8 **)scratch)[2] = u8bDataHead(scratch) + base_len;
        call(PATHu8bTerm, scratch);
        fileit it = {};
        a_path(dpat);
        a_dup(u8c, bd, u8bDataC(bdir));
        call(PATHu8bFeed, dpat, bd);
        if (FILEIterOpen(&it, dpat) == OK) {
            scan(FILENext, &it) {
                if (it.type != DT_REG) continue;
                u8cs base = {};
                PATHu8sBase(base, u8bDataC(it.path));
                size_t n = u8csLen(base);
                static char const SUF[] = ".graf.idx";
                size_t s = sizeof(SUF) - 1;
                if (n <= s) continue;
                if (memcmp(base[0] + n - s, SUF, s) != 0) continue;
                FILEUnLink(u8bDataC(it.path));
            }
            seen(END);
            FILEIterClose(&it);
        }
    }
    call(FILERmDir, $path(bdir), false);
    done;
}

// --- Lookup: hashlet → wh64 val ---
// hexlen: number of significant hex chars in the hashlet (6-10).
// With 60-bit hashlets, max is 15 hex chars.

ok64 KEEPLookup(keeper *k, u64 hashlet60, size_t hexlen, u64p val) {
    sane(k && val);

    // Build range for prefix matching.
    // key = hashlet60[60] | type[4].
    // key_lo: hashlet prefix with low bits zeroed, type=0.
    // key_hi: hashlet prefix with low bits all-ones, type=0xf.
    if (hexlen > 15) hexlen = 15;
    u64 nbits = hexlen * 4;
    u64 shift = 60 - nbits;
    u64 hmask = shift < 60 ? (WHIFF_HASHLET60_MASK >> shift) << shift : WHIFF_HASHLET60_MASK;
    u64 hpre = hashlet60 & hmask;

    //  Object lookup: restrict the type range to 1..4.  KEEP_TYPE_PACK
    //  (0xF) bookmarks share the index but must never be returned as
    //  objects.  See keeper/LOG.md.
    u64 key_lo = keepKeyPack(KEEP_OBJ_COMMIT, hpre);
    u64 key_hi = keepKeyPack(KEEP_OBJ_TAG,
                             hpre | (~hmask & WHIFF_HASHLET60_MASK));

    u32 nruns = keep_run_count_all(k);
    for (u32 r = 0; r < nruns; r++) {
        wh128cs run = {NULL, NULL};
        keep_run_at_all(run, k, r);
        wh128cp base = run[0];
        size_t len = (size_t)(run[1] - run[0]);
        if (len == 0) continue;
        size_t lo = 0, hi = len;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            if (base[mid].key < key_lo) lo = mid + 1;
            else hi = mid;
        }
        if (lo < len && base[lo].key >= key_lo && base[lo].key <= key_hi) {
            *val = base[lo].val;
            done;
        }
    }
    return KEEPNONE;
}

// --- Has ---

ok64 KEEPHas(keeper *k, u64 hashlet60, size_t hexlen) {
    u64 val = 0;
    return KEEPLookup(k, hashlet60, hexlen, &val);
}

// --- Resolve: inflate object at pack val (file_id + offset) ---

static ok64 KEEPGetPacked(keeper *k, u64 val, u8bp out, u8p out_type) {
    u32 file_id = wh64Id(val);
    u64 offset  = wh64Off(val);

    u8bp pack_map = keep_pack_buf(k, file_id);
    if (!pack_map) return KEEPNONE;
    u8cp pack = u8bDataHead(pack_map);
    u64 packlen = (u64)(u8bIdleHead(pack_map) - pack);

    if (offset >= packlen) return KEEPFAIL;

    // Chase delta chain, resolve to base object
    u64 chain[256];
    int depth = 0;
    u64 cur = offset;
    u8 obj_type = 0;

    // Use pre-allocated working buffers, reset each call
    u8bReset(k->buf1);
    u8bReset(k->buf2);
    u8p buf1 = u8bHead(k->buf1);
    u8p buf2 = u8bHead(k->buf2);

    u64 outsz = 0;
    u8p result = NULL;
    ok64 rc = OK;

    for (;;) {
        pack_obj obj = {};
        u8cs from = {pack + cur, pack + packlen};
        rc = PACKDrainObjHdr(from, &obj);
        if (rc != OK) goto cleanup;

        if (obj.type >= 1 && obj.type <= 4) {
            // Base object: inflate directly
            obj_type = obj.type;
            if (obj.size > KEEP_BUFSZ) { rc = KEEPNOROOM; goto cleanup; }
            u8s into = {buf1, buf1 + KEEP_BUFSZ};
            rc = PACKInflate(from, into, obj.size);
            if (rc != OK) goto cleanup;
            result = buf1;
            outsz = obj.size;
            break;
        }

        if (depth >= 256) { rc = KEEPFAIL; goto cleanup; }
        chain[depth++] = cur;

        if (obj.type == PACK_OBJ_OFS_DELTA) {
            cur = cur - obj.ofs_delta;
        } else if (obj.type == PACK_OBJ_REF_DELTA) {
            // Look up base by SHA-1 prefix
            u64 base_hashlet = WHIFFHashlet60((sha1cp)obj.ref_delta[0]);
            u64 base_val = 0;
            rc = KEEPLookup(k, base_hashlet, 10, &base_val);
            if (rc != OK) goto cleanup;
            // Base might be in a different pack file
            u32 bfile = wh64Id(base_val);
            if (bfile != file_id) {
                // Cross-file: get base recursively, apply delta chain.
                // Caveats:
                //   * The recursive KEEPGet call uses buf1/buf2 as
                //     scratch, clobbering ours.  Reset buf1 before
                //     copying from buf3 so we don't carry residue.
                //   * `out` may alias k->buf3 (when a deeper recursive
                //     KEEPGetPacked got `out=k->buf3` from its caller).
                //     The post-loop `u8bFeed(out, content)` would then
                //     append onto our just-loaded base.  Reset buf3
                //     after the copy so the final feed lands in an
                //     empty buffer regardless of aliasing.
                u8bReset(k->buf3);
                u8 btype = 0;
                rc = KEEPGet(k, base_hashlet, 15, k->buf3, &btype);
                if (rc != OK) goto cleanup;
                obj_type = btype;
                u8bReset(k->buf1);
                (void)u8bFeed(k->buf1, u8bData(k->buf3));
                u8bReset(k->buf3);
                buf1 = u8bHead(k->buf1);
                outsz = u8bDataLen(k->buf1);
                result = buf1;
                break;  // apply delta chain from here
            }
            cur = wh64Off(base_val);
        } else {
            rc = KEEPFAIL;
            goto cleanup;
        }
    }

    // Apply delta chain bottom-up
    u8p src = buf1;
    u8p dst = buf2;

    for (int i = depth - 1; i >= 0; i--) {
        pack_obj dobj = {};
        u8cs from = {pack + chain[i], pack + packlen};
        rc = PACKDrainObjHdr(from, &dobj);
        if (rc != OK) goto cleanup;

        u8p dinst = dst + KEEP_BUFSZ / 2;
        if (dobj.size > KEEP_BUFSZ / 2) { rc = KEEPNOROOM; goto cleanup; }
        u8s dinto = {dinst, dinst + KEEP_BUFSZ / 2};
        rc = PACKInflate(from, dinto, dobj.size);
        if (rc != OK) goto cleanup;

        u8cs delta = {dinst, dinst + dobj.size};
        u8cs base = {src, src + outsz};
        u8g apply_out = {dst, dst, dst + KEEP_BUFSZ / 2};
        rc = DELTApply(delta, base, apply_out);
        if (rc != OK) goto cleanup;
        outsz = u8gLeftLen(apply_out);

        u8p tmp = src; src = dst; dst = tmp;
    }

    result = src;
    if (out_type) *out_type = obj_type;

    // Copy result into caller's output buffer.  `out` may alias one
    // of our scratch buffers (k->buf1/buf2/buf3) — callers pass these
    // in to avoid an extra allocation.  In the cross-file REF_DELTA
    // arm above we stage the base into k->buf1 (the u8bFeed at line
    // 1042); when out == k->buf1 the final `result` lives at
    // k->buf1[0..outsz) but out's idle slot starts past the staged
    // base bytes, so u8bFeed's memcpy aliases.  Reset out first so
    // idle resumes at buf[0], then memmove handles the now-degenerate
    // src==dst overlap (or any other aliased combination).
    u8bReset(out);
    if (u8bIdleLen(out) < outsz) {
        rc = BNOROOM; goto cleanup;
    }
    memmove(u8bIdleHead(out), result, outsz);
    u8bFed(out, outsz);

cleanup:
    return rc;
}

// --- Get: inflate object from pack by hashlet ---

ok64 KEEPGet(keeper *k, u64 hashlet, size_t hexlen, u8bp out, u8p out_type) {
    sane(k && out);

    u64 val = 0;
    ok64 lo = KEEPLookup(k, hashlet, hexlen, &val);
    if (lo != OK) return lo;

    return KEEPGetPacked(k, val, out, out_type);
}

// --- GetSha: inflate object, verify full SHA-1 ---

// KEEPObjSha defined below with KEEPPackFeed; declared in KEEP.h.

ok64 KEEPGetExact(keeper *k, sha1 const *sha, u8bp out, u8p out_type) {
    sane(k && sha && out);

    u64 hashlet60 = WHIFFHashlet60(sha);
    //  Object lookup: skip KEEP_TYPE_PACK bookmarks (see LOG.md).
    u64 key_lo = keepKeyPack(KEEP_OBJ_COMMIT, hashlet60);
    u64 key_hi = keepKeyPack(KEEP_OBJ_TAG, hashlet60);

    u32 nruns = keep_run_count_all(k);
    for (u32 r = 0; r < nruns; r++) {
        wh128cs run = {NULL, NULL};
        keep_run_at_all(run, k, r);
        wh128cp base = run[0];
        size_t len = (size_t)(run[1] - run[0]);
        if (len == 0) continue;

        // Binary search for first entry >= key_lo
        size_t lo = 0, hi = len;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            if (base[mid].key < key_lo) lo = mid + 1;
            else hi = mid;
        }

        // Scan all entries with matching hashlet
        for (size_t i = lo; i < len && base[i].key <= key_hi; i++) {
            u8bReset(out);
            u8 otype = 0;
            ok64 rc = KEEPGetPacked(k, base[i].val, out, &otype);
            if (rc != OK) continue;

            // Verify full SHA-1
            sha1 actual = {};
            u8cs content = {u8bDataHead(out), u8bIdleHead(out)};
            KEEPObjSha(&actual, otype, content);
            if (sha1Eq(&actual, sha)) {
                if (out_type) *out_type = otype;
                done;
            }
        }
    }
    return KEEPNONE;
}

// --- Verify: get object, check SHA-1, recurse into tree/commit ---

#include "GIT.h"

// Simple visited-set: linear scan (good enough for <10K objects)
#define VERIFY_MAX_VISITED 16384
static u64 verify_visited[VERIFY_MAX_VISITED];
static u32 verify_nvisited = 0;

static b8 verify_seen(u64 hashlet) {
    for (u32 i = 0; i < verify_nvisited; i++)
        if (verify_visited[i] == hashlet) return YES;
    return NO;
}

static void verify_mark(u64 hashlet) {
    if (verify_nvisited < VERIFY_MAX_VISITED)
        verify_visited[verify_nvisited++] = hashlet;
}

static ok64 keep_verify_sha(keeper *k, sha1 expected_sha,
                             u32 *checked, u32 *failed) {
    u64 hashlet = WHIFFHashlet60(&expected_sha);
    if (verify_seen(hashlet)) return OK;  // already verified
    verify_mark(hashlet);

    #define VERIFY_BUFSZ (1ULL << 24)  // 16 MB
    u8p objmem = malloc(VERIFY_BUFSZ);
    if (!objmem) return KEEPNOROOM;
    Bu8 obj = {};
    obj[0] = obj[1] = obj[2] = objmem;
    obj[3] = objmem + VERIFY_BUFSZ;
    u8 obj_type = 0;

    ok64 rc = KEEPGet(k, hashlet, 15, obj, &obj_type);
    if (rc != OK) {
        a_pad(u8, hex, 16);
        WHIFFHexFeed60(hex_idle, hashlet);
        u8bFeed1(hex, 0);
        fprintf(stderr, "  MISS: %s\n", (char *)u8bDataHead(hex));
        (*failed)++;
        free(objmem);
        return rc;
    }

    // Recompute SHA-1
    a_dup(u8c, content, u8bDataC(obj));

    u8cs type_name = {};
    if (GITTypeName(type_name, obj_type) != OK) {
        fprintf(stderr, "  BAD TYPE: %u\n", obj_type);
        (*failed)++;
        u8bUnMap(obj);
        return KEEPFAIL;
    }

    Bu8 tmp = {};
    if (u8bAlloc(tmp, 64 + u8csLen(content)) != OK) {
        u8bUnMap(obj);
        return KEEPNOROOM;
    }
    u8bFeed(tmp, type_name);
    u8bPrintf(tmp, " %lu", (unsigned long)u8csLen(content));
    u8bFeed1(tmp, 0);
    u8bFeed(tmp, content);

    sha1 actual_sha = {};
    SHA1Sum(&actual_sha, u8bDataC(tmp));
    u8bFree(tmp);

    if (sha1cmp(&actual_sha, &expected_sha) != 0) {
        a_pad(u8, hex_exp, 16);
        WHIFFHexFeed60(hex_exp_idle, WHIFFHashlet60(&expected_sha));
        u8bFeed1(hex_exp, 0);
        a_pad(u8, hex_got, 16);
        WHIFFHexFeed60(hex_got_idle, WHIFFHashlet60(&actual_sha));
        u8bFeed1(hex_got, 0);
        fprintf(stderr, "  HASH MISMATCH: expected %s got %s\n",
                (char *)u8bDataHead(hex_exp), (char *)u8bDataHead(hex_got));
        (*failed)++;
        u8bUnMap(obj);
        return KEEPFAIL;
    }

    (*checked)++;

    // Recurse based on type
    if (obj_type == DOG_OBJ_COMMIT) {
        // Parse tree SHA from commit
        a_dup(u8c, body, content);
        u8cs field = {}, value = {};
        while (GITu8sDrainCommit(body, field, value) == OK) {
            if ($empty(field)) break;
            if (u8csEq(field, GIT_FIELD_TREE) && u8csLen(value) >= 40) {
                sha1 tree_sha = {};
                u8s sb = {tree_sha.data, tree_sha.data + 20};
                u8cs hx = {value[0], value[0] + 40};
                ok64 ho = HEXu8sDrainSome(sb, hx);
                if (ho != OK) break;
                ok64 o = keep_verify_sha(k, tree_sha, checked, failed);
                if (o != OK) {
                    a_pad(u8, hex, 16);
                    WHIFFHexFeed60(hex_idle, WHIFFHashlet60(&tree_sha));
                    u8bFeed1(hex, 0);
                    fprintf(stderr, "  tree %s verify failed\n",
                            (char *)u8bDataHead(hex));
                }
                break;
            }
        }
    } else if (obj_type == DOG_OBJ_TREE) {
        // Parse tree entries: each is "mode name\0<20-byte sha>"
        a_dup(u8c, body, content);
        while (!u8csEmpty(body)) {
            u8cs entry_field = {}, entry_sha = {};
            ok64 o = GITu8sDrainTree(body, entry_field, entry_sha, NULL);
            if (o != OK) break;
            if (u8csLen(entry_sha) != 20) continue;
            // Skip gitlinks (submodule refs) — mode 160000, commit in another repo
            a_cstr(gitlink_pfx, "160000");
            if (u8csHasPrefix(entry_field, gitlink_pfx) &&
                u8csLen(entry_field) > 6) continue;
            {
                u8cs vscan = {entry_field[0], entry_field[1]};
                if (u8csFind(vscan, ' ') == OK) {
                    u8cs vname = {vscan[0] + 1, entry_field[1]};
                    if (DPATHVerify(vname) != OK) {
                        fprintf(stderr, "  bad path '%.*s', skip\n",
                                (int)$len(vname), (char *)vname[0]);
                        continue;
                    }
                }
            }
            sha1 child_sha = {};
            sha1FromBin(&child_sha, entry_sha);
            o = keep_verify_sha(k, child_sha, checked, failed);
            if (o != OK) {
                a_pad(u8, hex, 16);
                WHIFFHexFeed60(hex_idle, WHIFFHashlet60(&child_sha));
                u8bFeed1(hex, 0);
                fprintf(stderr, "  child %s verify failed\n",
                        (char *)u8bDataHead(hex));
            }
        }
    } else if (obj_type == DOG_OBJ_TAG) {
        // Parse "object <sha>" from tag body, recurse
        a_dup(u8c, body, content);
        u8cs field = {}, value = {};
        while (GITu8sDrainCommit(body, field, value) == OK) {
            if (u8csEmpty(field)) break;
            if (u8csEq(field, GIT_FIELD_OBJECT) && u8csLen(value) >= 40) {
                sha1 target_sha = {};
                u8s sb = {target_sha.data, target_sha.data + 20};
                u8cs hx = {value[0], value[0] + 40};
                ok64 ho = HEXu8sDrainSome(sb, hx);
                if (ho != OK) break;
                keep_verify_sha(k, target_sha, checked, failed);
                break;
            }
        }
    }
    // blobs: hash check is sufficient

    free(objmem);
    return OK;
}

ok64 KEEPVerify(keeper *k, u8cs hex_sha) {
    sane(k && $ok(hex_sha));
    verify_nvisited = 0;
    if ($len(hex_sha) < 40) {
        fprintf(stderr, "keeper: verify requires full 40-char SHA\n");
        return KEEPFAIL;
    }

    sha1 sha = {};
    u8s sb = {sha.data, sha.data + 20};
    u8cs hx = {hex_sha[0], hex_sha[0] + 40};
    call(HEXu8sDrainSome, sb, hx);

    u32 checked = 0, failed = 0;
    ok64 rc = keep_verify_sha(k, sha, &checked, &failed);

    fprintf(stderr, "keeper: verified %u objects, %u failed\n", checked, failed);
    return (failed == 0 && rc == OK) ? OK : KEEPFAIL;
}

// --- Scan ---

ok64 KEEPScan(keeper *k, u64 from_val, keep_cb cb, void *ctx) {
    sane(k && cb);

    u32 file_id = wh64Id(from_val);
    u64 offset  = wh64Off(from_val);

    u8bp pack_map = keep_pack_buf(k, file_id);
    if (!pack_map) return KEEPNONE;
    u8cp pack = u8bDataHead(pack_map);
    u64 packlen = (u64)(u8bIdleHead(pack_map) - pack);

    // Skip PACK header if at start
    if (offset == 0 && packlen >= 12) {
        u8cs head = {pack, pack + 4};
        if (u8csEq(head, GIT_PACK_MAGIC)) offset = 12;
    }

    u8p buf = (u8p)malloc(KEEP_BUFSZ);
    if (!buf) return KEEPNOROOM;

    while (offset < packlen) {
        pack_obj obj = {};
        u8cs from = {pack + offset, pack + packlen};
        ok64 o = PACKDrainObjHdr(from, &obj);
        if (o != OK) break;

        if (obj.type >= 1 && obj.type <= 4 && obj.size <= KEEP_BUFSZ) {
            u8s into = {buf, buf + KEEP_BUFSZ};
            if (PACKInflate(from, into, obj.size) == OK) {
                u8csc content = {buf, buf + obj.size};
                sha1 sha = {};
                KEEPObjSha(&sha, obj.type, content);
                u64 hashlet = WHIFFHashlet60(&sha);
                u8cs cview = {buf, buf + obj.size};
                o = cb(obj.type, cview, hashlet, ctx);
                if (o != OK) break;
            } else {
                //  Inflate failed — advancing by `obj.size` would land
                //  in mid-stream.  Bail; the caller's index is the
                //  authoritative pack layout.
                break;
            }
        } else {
            //  Object we don't materialise (OFS/REF delta, or size
            //  beyond scratch buffer).  Without inflating we can't
            //  know its deflated footprint; stop the scan.
            break;
        }

        //  PACKInflate advances `from[0]` past the consumed deflated
        //  bytes; that's where the next object starts.
        offset = (u64)(from[0] - pack);
    }

    free(buf);
    done;
}

// --- Pack writer: incremental API ---

//  Feed `val` into `out` as exactly `width` lowercase hex digits,
//  zero-padded on the left.  Same-width padding keeps byte-sorted
//  filenames numerically ordered.
//  Render `val` as a `width`-char zero-padded RON64 string into `out`.
//  Matches DOG_PUP_SEQNO_W convention so puppy filenames sort by seqno.
static ok64 keep_hex_pad(u8b out, u32 val, u32 width) {
    sane(u8bOK(out));
    test(width <= 10, KEEPFAIL);  // 60-bit RON64 caps at 10 chars
    call(RONu8sFeedPad, u8bIdle(out), (ok64)val, (u8)width);
    ((u8 **)out)[2] += width;
    done;
}

//  Write the "NNNNN<ext>" leaf filename (5-hex-char file_id plus
//  extension) into `out`.  `ext` is the dotted extension slice
//  (`KEEP_PACK_EXT` / `KEEP_IDX_EXT`, each including the leading dot).
//  KEEP_SEQNO_W = 5 matches the wh64 val's 20-bit file_id field.
static ok64 keep_leaf_name(path8b out, u32 seqno, u8csc ext) {
    sane(u8bOK(out));
    call(keep_hex_pad, out, seqno, KEEP_SEQNO_W);
    call(u8bFeed, out, ext);
    done;
}

//  Compose "<kdir>/NNNNN.keeper" into `out` (reset first).
//  `kdir` is the `.be` prefix (absolute or relative, no trailing
//  slash).  `PATHu8bDup` preserves any leading '/' that a
//  segment-wise `PATHu8bAdd` would eat as an empty prefix segment.
static ok64 keep_pack_path(path8b out, u8csc kdir, u32 file_id) {
    sane(u8bOK(out) && !$empty(kdir));
    a_pad(u8, fname, KEEP_SEQNO_W + sizeof(KEEP_PACK_EXT));
    a_cstr(ext, KEEP_PACK_EXT);
    call(keep_leaf_name, fname, file_id, ext);
    call(PATHu8bDup, out, kdir);
    call(PATHu8bPush, out, u8bDataC(fname));
    done;
}

//  Compose "<kdir>/NNNNN.idx" into `out` (reset first).
static ok64 keep_idx_path(path8b out, u8csc kdir, u32 seqno) {
    sane(u8bOK(out) && !$empty(kdir));
    a_pad(u8, fname, KEEP_SEQNO_W + sizeof(KEEP_IDX_EXT));
    a_cstr(ext, KEEP_IDX_EXT);
    call(keep_leaf_name, fname, seqno, ext);
    call(PATHu8bDup, out, kdir);
    call(PATHu8bPush, out, u8bDataC(fname));
    done;
}

// Compute git object SHA-1: SHA1("type size\0" + content)
void KEEPObjSha(sha1 *out, u8 type, u8csc content) {
    a_pad(u8, hdr, 64);
    u8cs tname = {};
    GITTypeName(tname, type);
    u8bFeed(hdr, tname);
    u8bPrintf(hdr, " %llu", (unsigned long long)u8csLen(content));
    u8bFeed1(hdr, 0);

    SHA1state ctx;
    SHA1Open(&ctx);
    SHA1Feed(&ctx, u8bDataC(hdr));
    SHA1Feed(&ctx, content);
    SHA1Close(&ctx, out);
}

// Encode pack object varint header into buffer
static void keep_feed_obj_hdr(u8bp buf, u8 type, u64 size) {
    u8 first = (u8)((type << 4) | (size & 0x0f));
    size >>= 4;
    if (size > 0) first |= 0x80;
    u8bFeed1(buf, first);
    while (size > 0) {
        u8 c = (u8)(size & 0x7f);
        size >>= 7;
        if (size > 0) c |= 0x80;
        u8bFeed1(buf, c);
    }
}

//  OFS_DELTA negative-offset varint.  Matches PACKDrainOfs's decoding:
//    ofs = c & 0x7f;                    (first byte, MSB bits)
//    while (cont): ofs = ((ofs+1)<<7) | (c & 0x7f);
static void pack_feed_ofs(u8bp buf, u64 val) {
    u8 tmp[16];
    int pos = 0;
    tmp[pos] = (u8)(val & 0x7f);
    while ((val >>= 7) != 0) {
        val--;
        tmp[++pos] = (u8)(0x80 | (val & 0x7f));
    }
    for (int i = pos; i >= 0; i--) u8bFeed1(buf, tmp[i]);
}

ok64 KEEPPackOpen(keeper *k, keep_pack *p) {
    sane(k && p);
    zerop(p);
    p->strict_order = YES;

    //  Append-to-log: reuse the tail log file if it exists, else
    //  create a fresh one.  Log files hold many concatenated packs
    //  (stripped: one PACK header at offset 0, no trailers, no
    //  per-pack headers).  See keeper/LOG.md.
    b8 appending = (kv32bDataLen(k->packs) > 0);
    p->file_id = appending ? keep_packs_max_seqno(k) : k->next_seqno;

    call(wh128bAllocate, p->entries, KEEP_PACK_MAX_OBJS);
    call(u8bMap, p->delta_base,  KEEP_BUFSZ);
    call(u8bMap, p->delta_instr, KEEP_BUFSZ);

    // Pack lands in the active leaf-branch dir (writes only land at
    // the leaf; trunk leaf collapses to <root>/.be/).
    a_path(kdir);
    call(keep_branch_dir, kdir, k->h, u8bDataC(k->leaf_branch));

    a_pad(u8, packpath, FILE_PATH_MAX_LEN);
    call(keep_pack_path, packpath, $path(kdir), p->file_id);

    if (appending) {
        //  Existing tail file is mapped read-only via the keeper-level
        //  packs registry; replace that mapping with a FILEBook
        //  (writable mmap with extendable file) so concurrent reads
        //  of already-written objects still work while this pack is
        //  being appended.
        u8bp tail = keep_pack_buf(k, p->file_id);
        if (tail) {
            FILEUnMap(tail);
            keep_pack_drop(k, p->file_id);
        }
        call(FILEBook, &p->log, $path(packpath), 16ULL << 30);
        //  FILEBook ftruncates the file to the page-aligned map size
        //  (so writes into the mmap's tail-of-page persist on disk-
        //  backed FSs) and sets b[2] at the real content end, so
        //  u8bDataLen below reports the pre-extension length.
        p->pack_offset = u8bDataLen(p->log);
        //  Expose the RW view to readers for the duration of the
        //  pack build — any lookups into this file_id resolve via
        //  the FILEBook'd buffer, not a stale RO mapping.
        call(keep_pack_install, k, p->file_id, p->log);
    } else {
        //  Fresh log file: reserve 1GB VA, start at 4KB.  Write the
        //  one-and-only file-level PACK header (count=0, patched on
        //  each KEEPPackClose).  PACKu8sFeedHdr already advances the
        //  DATA/IDLE boundary by 12 via its three u8sFeed calls, so
        //  no further u8bFed is needed — an earlier `u8bFed(12)`
        //  here double-advanced and left a 12-byte zero gap between
        //  the header and the first object, which later broke
        //  UNPKIndex on sync ingest.
        call(FILEBookCreate, &p->log, $path(packpath),
             1ULL << 30, 4096);
        call(PACKu8sFeedHdr, u8bIdle(p->log), 0);
        p->pack_offset = 12;
    }

    done;
}

//  Scan the in-progress pack's entries for a hashlet hit that points
//  at a RAW object (types 1..4).  Opportunistic OFS_DELTA candidate —
//  avoids the 20-byte REF header for same-pack bases.  Skips entries
//  whose on-disk record is itself a delta: we don't resolve in-pack
//  chains here; caller falls through to the REF path (KEEPGet) where
//  the LSM resolver handles chains.
static b8 keep_find_raw_in_pack(keep_pack *p, u64 base_hashlet60,
                                u64 *offset_out, u8 *type_out) {
    a_dup(wh128, es, wh128bData(p->entries));
    for (wh128cp e = es[0]; e < es[1]; e++) {
        if (keepKeyHashlet(e->key) != base_hashlet60) continue;
        if (wh64Id(e->val) != p->file_id) continue;
        u64 off = wh64Off(e->val);
        if (off < p->pack_offset) continue;

        u8cs from = {u8bDataHead(p->log) + off,
                     u8bDataHead(p->log) + u8bDataLen(p->log)};
        pack_obj bo = {};
        if (PACKDrainObjHdr(from, &bo) != OK) continue;
        if (bo.type < 1 || bo.type > 4) continue;
        *offset_out = off;
        *type_out   = bo.type;
        return YES;
    }
    return NO;
}

ok64 KEEPPackFeed(keeper *k, keep_pack *p,
                  u8 type, u8csc content,
                  u64 base_hashlet60,
                  sha1 *sha_out) {
    sane(k && p && p->log && type >= 1 && type <= 4);

    //  Intra-pack order invariant: commit → tree → blob → tag.  Only
    //  enforced for canonical (main-log) packs.  Staging packs toggle
    //  `strict_order=NO` and feed objects in DFS order; their contents
    //  are repacked canonically on `be post`.
    if (p->strict_order) test(type >= p->last_type, ORDERBAD);
    p->last_type = type;

    KEEPObjSha(sha_out, type, content);

    u64 obj_offset    = u8bDataLen(p->log);
    b8  emitted_delta = NO;

    if (base_hashlet60 != 0) {
        //  Resolve the base into p->delta_base.  Prefer an OFS
        //  candidate in this pack (raw only); fall through to KEEPGet
        //  which walks k->puppies and resolves delta chains internally.
        b8  in_pack = NO;
        u64 in_pack_off = 0;
        u8  base_type = 0;
        u8bReset(p->delta_base);

        if (keep_find_raw_in_pack(p, base_hashlet60, &in_pack_off,
                                  &base_type)) {
            u8cs from = {u8bDataHead(p->log) + in_pack_off,
                         u8bDataHead(p->log) + u8bDataLen(p->log)};
            pack_obj bo = {};
            if (PACKDrainObjHdr(from, &bo) == OK &&
                bo.size <= (u64)u8bIdleLen(p->delta_base)) {
                u8s into = {u8bIdleHead(p->delta_base),
                            u8bTerm(p->delta_base)};
                if (PACKInflate(from, into, bo.size) == OK) {
                    u8bFed(p->delta_base, bo.size);
                    in_pack = YES;
                }
            }
        }

        if (!in_pack) {
            //  Committed-run lookup: KEEPGet chases any internal
            //  OFS/REF chain and hands us the fully-resolved body.
            //  DAG invariant: REF_DELTA bases must live in this leaf
            //  branch or one of its ancestor dirs along the open
            //  branch path.  Since KEEPOpenBranch only ever loads
            //  packs from trunk → … → leaf, every hit in `k->packs`
            //  is by construction visible to a delta encoded into
            //  the leaf — no extra check needed.
            if (KEEPGet(k, base_hashlet60, 15, p->delta_base,
                        &base_type) != OK) {
                u8bReset(p->delta_base);
            }
        }

        if (u8bDataLen(p->delta_base) > 0) {
            //  Hash the resolved base — REF_DELTA needs the 20-byte
            //  SHA; also serves as a collision guard (hashlet60 uses
            //  only 15 hex chars of the SHA prefix).
            sha1 base_sha = {};
            u8csc bc = {u8bDataHead(p->delta_base),
                        u8bIdleHead(p->delta_base)};
            KEEPObjSha(&base_sha, base_type, bc);

            if (WHIFFHashlet60(&base_sha) == base_hashlet60) {
                u8bReset(p->delta_instr);
                ok64 deo = DELTEncode(bc, content, p->delta_instr);
                if (deo == OK &&
                    u8bDataLen(p->delta_instr) < u8csLen(content)) {
                    u64 delta_len = u8bDataLen(p->delta_instr);
                    u8  dtype = in_pack ? PACK_OBJ_OFS_DELTA
                                        : PACK_OBJ_REF_DELTA;
                    call(FILEBookEnsure, p->log,
                         64 + delta_len + 256);

                    a_pad(u8, ohdr, 16);
                    keep_feed_obj_hdr(ohdr, dtype, delta_len);
                    a_dup(u8c, ohb, u8bData(ohdr));
                    u8bFeed(p->log, ohb);

                    if (in_pack) {
                        u64 neg = obj_offset - in_pack_off;
                        a_pad(u8, ofs, 16);
                        pack_feed_ofs(ofs, neg);
                        a_dup(u8c, ofsb, u8bData(ofs));
                        u8bFeed(p->log, ofsb);
                    } else {
                        u8cs sha_sl = {};
                        sha1slice(sha_sl, &base_sha);
                        u8bFeed(p->log, sha_sl);
                    }

                    a_dup(u8c, zsrc, u8bDataC(p->delta_instr));
                    call(ZINFDeflate, u8bIdle(p->log), zsrc);
                    emitted_delta = YES;
                }
            }
        }
    }

    if (!emitted_delta) {
        //  Raw-object path (same as pre-delta).
        call(FILEBookEnsure, p->log, 16);
        a_pad(u8, ohdr, 16);
        keep_feed_obj_hdr(ohdr, type, u8csLen(content));
        a_dup(u8c, oh, u8bData(ohdr));
        u8bFeed(p->log, oh);

        u64 clen = u8csLen(content);
        call(FILEBookEnsure, p->log, clen + 256);
        a_dup(u8c, zsrc, content);
        call(ZINFDeflate, u8bIdle(p->log), zsrc);
    }

    //  Index entry records the resolved object type, not the pack type
    //  (delta vs raw is an on-wire concern; lookups are type-aware).
    u64 hashlet = WHIFFHashlet60(sha_out);
    wh128 entry = {
        .key = keepKeyPack(type, hashlet),
        .val = wh64Pack(KEEP_VAL_FLAGS, p->file_id, obj_offset),
    };
    wh128bPush(p->entries, &entry);

    p->nobjs++;

    done;
}

ok64 KEEPPackClose(keeper *k, keep_pack *p) {
    sane(k && p && p->log);

    //  Update file-level PACK header count: add THIS pack's nobjs
    //  to whatever was already there.  No per-pack headers, no
    //  per-pack trailers.  See keeper/LOG.md.
    u8p hdr = u8bDataHead(p->log);
    u32 old_count = ((u32)hdr[8] << 24) | ((u32)hdr[9] << 16) |
                    ((u32)hdr[10] << 8) | (u32)hdr[11];
    u32 new_count = old_count + p->nobjs;
    hdr[8]  = (u8)(new_count >> 24);
    hdr[9]  = (u8)(new_count >> 16);
    hdr[10] = (u8)(new_count >> 8);
    hdr[11] = (u8)(new_count);

    //  Capture this pack's byte length before unmapping; the pack
    //  bookmark val carries (obj_count, byte_len) for O(1) wire
    //  reconstruction (see keeper/WIRE.md Phase 0).
    u64 file_len = u8bDataLen(p->log);
    u64 pack_byte_len = file_len - p->pack_offset;

    //  Persist the log, unmap the RW view, re-map RO for readers.
    call(FILETrimBook, p->log);
    a_path(kdir);
    call(keep_branch_dir, kdir, k->h, u8bDataC(k->leaf_branch));
    a_pad(u8, packpath, FILE_PATH_MAX_LEN);
    call(keep_pack_path, packpath, $path(kdir), p->file_id);

    FILEUnBook(p->log);
    p->log = NULL;

    u8bp ro = NULL;
    call(FILEMapRO, &ro, $path(packpath));
    b8 fresh = (p->file_id >= k->next_seqno);
    test(kv32bDataLen(k->packs) < KEEP_MAX_FILES, KEEPNOROOM);
    call(keep_pack_install, k, p->file_id, ro);
    if (fresh) k->next_seqno = p->file_id + 1;

    //  Pack bookmark, per keeper/LOG.md layout:
    //    key = wh64Pack(KEEP_TYPE_PACK, file_id, offset) — sorts by
    //          (file_id, offset) so enumeration is a forward scan.
    //    val = obj_count32 | byte_len32 (see keepPackBmVal).
    {
        wh128 bm = {
            .key = wh64Pack(KEEP_TYPE_PACK, p->file_id, p->pack_offset),
            .val = keepPackBmVal(p->nobjs, (u32)pack_byte_len),
        };
        wh128bPush(p->entries, &bm);
    }

    // Sort index entries, publish as a fresh puppy.  Idx files use
    // their own LSM seqno space (the new run sits at the top of the
    // ladder regardless of which pack file_id it indexes) — a single
    // pack file_id may have many sidecar idx runs published over its
    // lifetime as more objects are appended.  Pull the next seqno
    // from the global counter so it doesn't collide with an inherited
    // parent's puppies entry.
    a_dup(wh128, sorted, wh128bData(p->entries));
    wh128sSort(sorted);
    a_cstr(ext, KEEP_IDX_EXT);
    u8cs raw = {(u8cp)sorted[0], (u8cp)sorted[1]};
    call(keep_pup_create_next, k, $path(kdir), ext, raw);
    //  Maintain the 1/8 LSM ladder right after every puppy create, so
    //  the runs[KEEP_MAX_LEVELS] view cap is never reached and reads
    //  always see the full stack.
    call(KEEPCompact, k);

    wh128bFree(p->entries);
    if (p->delta_base[0])  u8bUnMap(p->delta_base);
    if (p->delta_instr[0]) u8bUnMap(p->delta_instr);
    done;
}

// --- KEEPPut: convenience wrapper ---

ok64 KEEPPut(keeper *k, u8csc *objects, wh64 *whiffs, u32 nobjs) {
    sane(k && objects && whiffs && nobjs > 0);

    keep_pack p = {};
    call(KEEPPackOpen, k, &p);

    for (u32 i = 0; i < nobjs; i++) {
        u8 type = wh64Type(whiffs[i]);
        sha1 sha = {};
        ok64 o = KEEPPackFeed(k, &p, type, objects[i], 0, &sha);
        if (o != OK) {
            if (p.log) FILEUnBook(p.log);
            wh128bFree(p.entries);
            if (p.delta_base[0])  u8bUnMap(p.delta_base);
            if (p.delta_instr[0]) u8bUnMap(p.delta_instr);
            return o;
        }
        u64 hashlet = WHIFFHashlet60(&sha);
        whiffs[i] = wh64Pack(type, p.file_id, hashlet);
    }

    call(KEEPPackClose, k, &p);
    done;
}

// --- Tree-SHA resolution ---

// Resolve a URI (target.fragment = hex, target.query = refname) to a
// root tree SHA-1.  Handles annotated-tag dereference.
ok64 KEEPResolveTree(keeper *k, uricp target, sha1 *tree_sha) {
    sane(k);

    sha1 commit_sha = {};

    // Try fragment (#hash) or query (?ref)
    if (!u8csEmpty(target->fragment)) {
        // Fragment = hex SHA prefix
        u64 hashlet = WHIFFHexHashlet60(target->fragment);
        u8 type = 0;
        u8bReset(k->buf1);
        call(KEEPGet, k, hashlet, u8csLen(target->fragment), k->buf1, &type);
        if (type == DOG_OBJ_TREE) {
            // Already a tree — compute its SHA
            a_dup(u8c, content, u8bData(k->buf1));
            KEEPObjSha(tree_sha, DOG_OBJ_TREE, content);
            done;
        }
        if (type != DOG_OBJ_COMMIT) fail(KEEPFAIL);
        // Parse tree SHA from commit
        a_dup(u8c, body, u8bDataC(k->buf1));
        u8cs field = {}, value = {};
        while (GITu8sDrainCommit(body, field, value) == OK) {
            if (u8csEmpty(field)) break;
            if (u8csEq(field, GIT_FIELD_TREE) && u8csLen(value) >= 40) {
                u8s sb = {tree_sha->data, tree_sha->data + 20};
                u8cs hx = {value[0], value[0] + 40};
                call(HEXu8sDrainSome, sb, hx);
                done;
            }
        }
        fail(KEEPFAIL);
    }

    if (!u8csEmpty(target->query)) {
        // Resolve ?ref via REFS.  REFSResolve handles full URIs
        // (`//auth/path?ref`), alias chains, and the `refs/` / `heads/` /
        // `tags/` normalisation users expect.  If the target URI has no
        // authority, we fall back to a bare `?<query>` match (legacy).
        a_path(keepdir, u8bDataC(k->h->root), KEEP_DIR_S);
        b8 found = NO;

        //  Always try REFSResolve first — it handles full URIs
        //  (`//auth/path?ref`), alias chains, the `refs/`/`heads/`/
        //  `tags/` variants, AND the `.?ref` / `?ref` local-dot
        //  shorthand.  The old gate on `target->authority` missed the
        //  local-dot case (`.?master` parses as path="."
        //  authority="").  REFSResolve now recognises that shape.
        if (!u8csEmpty(target->data)) {
            a_pad(u8, arena_buf, 512);
            uri resolved = {};
            a_dup(u8c, in_uri, target->data);
            ok64 ro = REFSResolve(&resolved, arena_buf, $path(keepdir), in_uri);
            if (ro == OK && u8csLen(resolved.query) >= 40) {
                u8s sb = {commit_sha.data, commit_sha.data + 20};
                u8cs hx = {resolved.query[0], resolved.query[0] + 40};
                if (HEXu8sDrainSome(sb, hx) == OK) found = YES;
            }
            //  When the URI has a query but no authority, probe with
            //  `.` so peer-observed tracking rows (`<peer>?<query>`)
            //  match, and additionally try `refs/`/`heads/` prefix
            //  peels — the wire-side canonicaliser stores `master`
            //  after stripping `refs/heads/` but the user may type
            //  `heads/master`.
            if (!found && !u8csEmpty(target->query) &&
                u8csEmpty(target->authority)) {
                char const *strips[] = {"", "heads/", "refs/heads/",
                                        "refs/", NULL};
                for (u32 si = 0; strips[si] != NULL && !found; si++) {
                    a_dup(u8c, q, target->query);
                    a_cstr(strip_s, strips[si]);
                    if (!u8csEmpty(strip_s)) {
                        if (u8csLen(q) <= u8csLen(strip_s)) continue;
                        if (!u8csHasPrefix(q, strip_s)) continue;
                        u8csUsed(q, u8csLen(strip_s));
                    }
                    a_pad(u8, dot_buf, 512);
                    a_cstr(dot_pfx, ".?");
                    u8bFeed(dot_buf, dot_pfx);
                    u8bFeed(dot_buf, q);
                    a_dup(u8c, dot_uri, u8bData(dot_buf));
                    memset(&resolved, 0, sizeof(resolved));
                    if (REFSResolve(&resolved, arena_buf,
                                    $path(keepdir), dot_uri) == OK &&
                        u8csLen(resolved.query) >= 40) {
                        u8s sb = {commit_sha.data, commit_sha.data + 20};
                        u8cs hx = {resolved.query[0],
                                   resolved.query[0] + 40};
                        if (HEXu8sDrainSome(sb, hx) == OK) found = YES;
                    }
                }
            }
        }

        if (!found) {
            a_pad(u8, qbuf, 256);
            u8bFeed1(qbuf, '?');
            u8bFeed(qbuf, target->query);
            a_dup(u8c, qkey, u8bData(qbuf));

            Bu8 rarena = {};
            call(u8bMap, rarena, (size_t)REFS_MAX_REFS * 320);
            ref rarr[REFS_MAX_REFS];
            u32 rn = 0;
            REFSLoad(rarr, &rn, REFS_MAX_REFS, rarena, $path(keepdir));

            for (u32 i = 0; i < rn; i++) {
                if (REFMatch(&rarr[i], qkey)) {
                    a_dup(u8c, val, rarr[i].val);
                    if (!u8csEmpty(val) && *val[0] == '?')
                        u8csUsed(val, 1);
                    if (u8csLen(val) >= 40) {
                        u8s sb = {commit_sha.data, commit_sha.data + 20};
                        u8cs hx = {val[0], val[0] + 40};
                        if (HEXu8sDrainSome(sb, hx) == OK) found = YES;
                    }
                    break;
                }
            }
            u8bUnMap(rarena);
        }
        if (!found) fail(KEEPNONE);

        // Get commit, extract tree SHA
        u64 hashlet = WHIFFHashlet60(&commit_sha);
        u8 type = 0;
        u8bReset(k->buf1);
        call(KEEPGet, k, hashlet, 15, k->buf1, &type);
        if (type != DOG_OBJ_COMMIT && type != DOG_OBJ_TAG) fail(KEEPFAIL);

        // If tag, get the commit it points to
        if (type == DOG_OBJ_TAG) {
            a_dup(u8c, tbody, u8bDataC(k->buf1));
            u8cs tf = {}, tv = {};
            while (GITu8sDrainCommit(tbody, tf, tv) == OK) {
                if (u8csEmpty(tf)) break;
                if (u8csEq(tf, GIT_FIELD_OBJECT) && u8csLen(tv) >= 40) {
                    u8s sb2 = {commit_sha.data, commit_sha.data + 20};
                    u8cs hx2 = {tv[0], tv[0] + 40};
                    call(HEXu8sDrainSome, sb2, hx2);
                    break;
                }
            }
            hashlet = WHIFFHashlet60(&commit_sha);
            u8bReset(k->buf1);
            call(KEEPGet, k, hashlet, 15, k->buf1, &type);
        }

        a_dup(u8c, body, u8bDataC(k->buf1));
        u8cs field = {}, value = {};
        while (GITu8sDrainCommit(body, field, value) == OK) {
            if (u8csEmpty(field)) break;
            if (u8csEq(field, GIT_FIELD_TREE) && u8csLen(value) >= 40) {
                u8s sb = {tree_sha->data, tree_sha->data + 20};
                u8cs hx = {value[0], value[0] + 40};
                call(HEXu8sDrainSome, sb, hx);
                done;
            }
        }
        fail(KEEPFAIL);
    }

    fail(KEEPFAIL);  // no ref or hash in URI
}

ok64 KEEPCommitTreeSha(keeper *k, sha1 const *commit, sha1 *tree_out) {
    sane(k && commit && tree_out);
    u8bReset(k->buf1);
    u8 ctype = 0;
    call(KEEPGetExact, k, commit, k->buf1, &ctype);
    if (ctype != DOG_OBJ_COMMIT) fail(KEEPFAIL);
    a_dup(u8c, body, u8bData(k->buf1));
    return GITu8sCommitTree(body, tree_out->data);
}

// --- Import: read git .idx v2 file alongside .pack, build wh128 index ---
//
// Git pack index v2 format:
//   magic (ff744f63), version (2), 256 fanout entries (u32 BE),
//   N×20 SHA-1, N×u32 CRC, N×u32 offset (BE), [8-byte offsets for >2GB]
//   pack SHA-1, index SHA-1

ok64 KEEPImport(keeper *k, u8cs pack_path) {
    sane(k && $ok(pack_path));

    // NUL-terminate pack_path for FILEMapRO
    a_path(pack_pp, pack_path);

    // Derive .idx path from .pack path (replace extension)
    a_pad(u8, idx_path_buf, 1024);
    call(u8bFeed, idx_path_buf, pack_path);
    a_cstr(pack_ext, ".pack");
    if (u8csHasSuffix(u8bDataC(idx_path_buf), pack_ext)) {
        u8bShed(idx_path_buf, u8csLen(pack_ext));
    } else {
        fprintf(stderr, "keeper: expected .pack file\n");
        fail(KEEPFAIL);
    }
    a_cstr(idx_ext, ".idx");
    call(u8bFeed, idx_path_buf, idx_ext);
    call(PATHu8bTerm, idx_path_buf);

    // Map both files
    u8bp pack_map = NULL, idx_map = NULL;
    call(FILEMapRO, &pack_map, $path(pack_pp));
    ok64 io = FILEMapRO(&idx_map, $path(idx_path_buf));
    if (io != OK) { FILEUnMap(pack_map); return io; }

    u8cp idx = u8bDataHead(idx_map);
    u64 idx_len = (u64)(u8bIdleHead(idx_map) - idx);

    // Verify idx v2 header
    if (idx_len < 8 + 256*4 || idx[0] != 0xff || idx[1] != 0x74 ||
        idx[2] != 0x4f || idx[3] != 0x63) {
        fprintf(stderr, "keeper: not a git pack index v2\n");
        FILEUnMap(pack_map); FILEUnMap(idx_map);
        fail(KEEPFAIL);
    }

    // Read total object count from fanout[255]
    u8cp fanout = idx + 8;
    u32 nobjects = (fanout[255*4] << 24) | (fanout[255*4+1] << 16) |
                   (fanout[255*4+2] << 8) | fanout[255*4+3];

    // Pointers to the four tables (v2 layout).  The big-offset table
    // is variable-length: one 8-byte entry per object whose 4-byte
    // "small" offset has the high bit set.  We don't know M up front,
    // so at each use we range-check against idx_len.
    u8cp sha_table = idx + 8 + 256 * 4;                // N × 20 bytes
    u8cp crc_table = sha_table + (u64)nobjects * 20;   // N × 4 bytes
    u8cp off_table = crc_table + (u64)nobjects * 4;    // N × 4 bytes
    u8cp big_table = off_table + (u64)nobjects * 4;    // M × 8 bytes
    u8cp idx_end   = idx + idx_len;

    if ((u64)(big_table - idx) > idx_len) {
        fprintf(stderr, "keeper: index file too small\n");
        FILEUnMap(pack_map); FILEUnMap(idx_map);
        fail(KEEPFAIL);
    }

    fprintf(stderr, "keeper: importing %u objects\n", nobjects);

    // Determine file_id (1-based, matching filename NNNN.packs)
    u32 file_id = k->next_seqno;
    a_path(kdir);
    call(keep_branch_dir, kdir, k->h, u8bDataC(k->leaf_branch));
    {
        a_pad(u8, dst, 1024);
        call(keep_pack_path, dst, $path(kdir), file_id);

        int fd = -1;
        call(FILECreate, &fd, $path(dst));
        a_dup(u8c, data, u8bData(pack_map));
        call(FILEFeedAll, fd, data);
        close(fd);
    }

    // Build wh128 entries from the idx tables
    wh128 *entries = (wh128 *)malloc((u64)nobjects * sizeof(wh128));
    if (!entries) { FILEUnMap(pack_map); FILEUnMap(idx_map); failc(KEEPNOROOM); }

    for (u32 i = 0; i < nobjects; i++) {
        sha1cp sha = (sha1cp)(sha_table + (u64)i * 20);
        u64 hashlet = WHIFFHashlet60(sha);

        // 4-byte offset (BE); high bit set means "this is an index
        // into the 8-byte big-offset table" (v2 layout for >2GB packs).
        u8cp offp = off_table + (u64)i * 4;
        u64 off = ((u64)offp[0] << 24) | ((u64)offp[1] << 16) |
                  ((u64)offp[2] << 8) | offp[3];

        if (off & 0x80000000ULL) {
            u64 big_idx = off & 0x7FFFFFFFULL;
            u8cp bp = big_table + big_idx * 8;
            if (bp + 8 > idx_end) {
                fprintf(stderr, "keeper: idx large-offset OOB "
                        "(obj %u, big_idx=%llu)\n",
                        i, (unsigned long long)big_idx);
                free(entries);
                FILEUnMap(pack_map); FILEUnMap(idx_map);
                fail(KEEPFAIL);
            }
            off = ((u64)bp[0] << 56) | ((u64)bp[1] << 48) |
                  ((u64)bp[2] << 40) | ((u64)bp[3] << 32) |
                  ((u64)bp[4] << 24) | ((u64)bp[5] << 16) |
                  ((u64)bp[6] <<  8) |  (u64)bp[7];
        }

        // git idx v2 doesn't carry type; use 0 (lookup spans all types)
        entries[i].key = keepKeyPack(0, hashlet);
        entries[i].val = wh64Pack(KEEP_VAL_FLAGS, file_id, off);
    }

    // Sort and dedup (wh128 dedup: same key+val only)
    wh128s sorted = {entries, entries + nobjects};
    wh128sSort(sorted);
    wh128sDedup(sorted);
    u32 nentries = (u32)(sorted[1] - sorted[0]);

    // Write .idx file to idx/
    {
        a_pad(u8, idxpath, 1024);
        call(keep_idx_path, idxpath, $path(kdir), file_id);

        int fd = -1;
        call(FILECreate, &fd, $path(idxpath));
        u8cs data = {(u8cp)entries, (u8cp)(entries + nentries)};
        call(FILEFeedAll, fd, data);
        close(fd);
    }

    free(entries);
    FILEUnMap(pack_map);
    FILEUnMap(idx_map);

    fprintf(stderr, "keeper: indexed %u objects\n", nentries);
    done;
}

// --- Ingest: append received pack-stream bytes to the tail log ---
//
// A receive-pack or upload-pack ingest carries a whole git pack
// (PACK header + object records + SHA-1 trailer).  Keeper's log is
// append-of-packs (see keeper/LOG.md): the tail NNNNN.keeper file
// holds many concatenated packs, and new ones land at the tail.
// We strip the 12-byte header and 20-byte trailer from the incoming
// bytes, append the raw object stream to the current tail log,
// patch the log's file-level PACK header count, UNPK-index just
// the newly-appended slice, and emit one pack bookmark pointing at
// the append offset.  An empty pack (count == 0) produces zero
// file changes.

ok64 KEEPIngestFile(keeper *k, u8csc bytes) {
    sane(k && $ok(bytes));
    u64 file_len = u8csLen(bytes);
    if (file_len < 12) fail(KEEPFAIL);

    //  Strip git's 20-byte SHA-1 trailer if present.
    if (file_len >= 32) {
        sha1 check = {};
        u8csc body = {bytes[0], bytes[0] + (file_len - 20)};
        SHA1Sum(&check, body);
        if (memcmp(check.data, bytes[0] + (file_len - 20), 20) == 0)
            file_len -= 20;
    }

    //  Parse PACK header → object count.
    pack_hdr ph = {};
    {
        u8cs hscan = {bytes[0], bytes[0] + file_len};
        call(PACKDrainHdr, hscan, &ph);
    }

    //  No-op ingest: zero-object pack = zero file changes.
    if (ph.count == 0) done;

    //  Object-stream slice (header stripped; trailer already dropped).
    u64 stream_len = file_len - 12;
    u8csc stream = {bytes[0] + 12, bytes[0] + file_len};

    a_path(kdir);
    call(keep_branch_dir, kdir, k->h, u8bDataC(k->leaf_branch));
    call(FILEMakeDirP, $path(kdir));

    //  Append to existing tail log, or create the very first one.
    b8  appending = (kv32bDataLen(k->packs) > 0);
    u32 file_id = appending ? keep_packs_max_seqno(k) : k->next_seqno;
    a_pad(u8, packpath, FILE_PATH_MAX_LEN);
    call(keep_pack_path, packpath, $path(kdir), file_id);

    u8bp log = NULL;
    u64  pack_offset = 0;
    if (appending) {
        //  Swap the existing RO mapping for an RW FILEBook view for
        //  the duration of the append.
        u8bp tail = keep_pack_buf(k, file_id);
        if (tail) {
            FILEUnMap(tail);
            keep_pack_drop(k, file_id);
        }
        call(FILEBook, &log, $path(packpath), 16ULL << 30);
        pack_offset = u8bDataLen(log);
    } else {
        test(kv32bDataLen(k->packs) < KEEP_MAX_FILES, KEEPNOROOM);
        //  16 GiB cap matches the append path above; keeps fresh
        //  clones of multi-GB repos (linux.git ~6 GB, ~3.4 GB after
        //  side-band demux) from BNOROOM'ing inside u8bFeed.  The
        //  file is `posix_fallocate`d sparsely — physical bytes
        //  follow `u8bFeed`, so the unused tail costs nothing.
        call(FILEBookCreate, &log, $path(packpath), 16ULL << 30, 4096);
        //  Lay down the one-and-only file-level PACK header with
        //  count=0; patched below after the append.
        call(PACKu8sFeedHdr, u8bIdle(log), 0);
        pack_offset = 12;
    }
    call(keep_pack_install, k, file_id, log);

    //  Append the object stream to the tail.
    call(FILEBookEnsure, log, stream_len);
    u8bFeed(log, stream);

    //  Patch the file-level count: old_count + ph.count.  Matches
    //  KEEPPackClose's convention.
    {
        u8p hdr = u8bDataHead(log);
        u32 old_count = ((u32)hdr[8] << 24) | ((u32)hdr[9] << 16) |
                        ((u32)hdr[10] << 8) | (u32)hdr[11];
        u32 new_count = old_count + ph.count;
        hdr[8]  = (u8)(new_count >> 24);
        hdr[9]  = (u8)(new_count >> 16);
        hdr[10] = (u8)(new_count >> 8);
        hdr[11] = (u8)(new_count);
    }

    u64 log_len = u8bDataLen(log);
    u64 pack_byte_len = log_len - pack_offset;

    //  Persist + flip back to an RO mapping for readers.
    call(FILETrimBook, log);
    FILEUnBook(log);
    log = NULL;

    //  Drop the RW (FILEBook) entry before installing the RO mapping
    //  so the registry never holds two slots for the same seqno.
    keep_pack_drop(k, file_id);
    u8bp ro = NULL;
    call(FILEMapRO, &ro, $path(packpath));
    call(keep_pack_install, k, file_id, ro);
    if (!appending) k->next_seqno = file_id + 1;

    //  Index just the newly-appended slice of the log.  UNPK needs
    //  the pack slice positioned at its final log location so
    //  emitted offsets are log-absolute.
    Bwh128 entries = {};
    call(wh128bAllocate, entries, (u64)ph.count + 16);
    u8cs log_view = {u8bDataHead(ro), u8bDataHead(ro) + log_len};
    unpk_in uin = {
        .pack = {log_view[0], log_view[1]},
        .scan_start = pack_offset,
        .scan_end = log_len,
        .count = ph.count,
        .file_id = file_id,
    };
    unpk_stats ust = {};
    call(UNPKIndex, k, &uin, entries, &ust);

    //  Pack bookmark: key points at the append offset, val carries
    //  (obj_count, byte_len) for O(1) wire reconstruction.
    {
        wh128 bm = {
            .key = wh64Pack(KEEP_TYPE_PACK, file_id, pack_offset),
            .val = keepPackBmVal(ph.count, (u32)pack_byte_len),
        };
        call(wh128bPush, entries, &bm);
    }

    //  Sort + dedup, publish as a fresh puppy.
    a_dup(wh128, sorted, wh128bData(entries));
    wh128sSort(sorted);
    wh128sDedup(sorted);
    u64 nent = wh128sLen(sorted);

    a_cstr(ext, KEEP_IDX_EXT);
    u8cs raw = {(u8cp)sorted[0], (u8cp)(sorted[0] + nent)};
    ok64 cr = keep_pup_create_next(k, $path(kdir), ext, raw);
    wh128bFree(entries);
    if (cr != OK) return cr;
    //  Compact-per-flush keeps the puppy ladder under the 1/8 invariant.
    call(KEEPCompact, k);

    done;
}

// --- Stream-ingest a side-band-64k upload-pack response ---
//
// Reads the entire upload-pack response off `rfd` directly into the
// keeper's tail log: pkt-line headers parsed inline, side-band frames
// dispatched in real time (band-1 → log via u8bFeed, band-2 → stderr
// live, band-3 → fatal).  No intermediate response/pack buffer.
//
// The first 12 band-1 bytes (git's per-pack PACK header) are stashed
// for the count parse but not written to the log — the log layout
// follows KEEPIngestFile's: a single file-level PACK header at offset
// 0, then concatenated raw object streams.  After EOF, the trailing
// 20-byte SHA-1 trailer is shed via u8bShed and the file-level PACK
// header count is patched.  UNPK indexes the appended slice.

static u32 keep_hex4(u8 const *h) {
    u32 v = 0;
    for (int i = 0; i < 4; i++) {
        u8 c = h[i];
        u32 d;
        if (c >= '0' && c <= '9')      d = (u32)(c - '0');
        else if (c >= 'a' && c <= 'f') d = (u32)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') d = (u32)(c - 'A' + 10);
        else return 0xFFFFFFFFu;
        v = (v << 4) | d;
    }
    return v;
}

static ssize_t keep_read_full(int fd, void *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, (char *)buf + got, n - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return (ssize_t)got;
        got += (size_t)r;
    }
    return (ssize_t)got;
}

ok64 KEEPIngestStream(keeper *k, int rfd) {
    sane(k && rfd >= 0);

    a_path(kdir);
    call(keep_branch_dir, kdir, k->h, u8bDataC(k->leaf_branch));
    call(FILEMakeDirP, $path(kdir));

    b8  appending = (kv32bDataLen(k->packs) > 0);
    u32 file_id = appending ? keep_packs_max_seqno(k) : k->next_seqno;
    a_pad(u8, packpath, FILE_PATH_MAX_LEN);
    call(keep_pack_path, packpath, $path(kdir), file_id);

    u8bp log = NULL;
    u64  pack_offset = 0;
    if (appending) {
        u8bp tail = keep_pack_buf(k, file_id);
        if (tail) {
            FILEUnMap(tail);
            keep_pack_drop(k, file_id);
        }
        call(FILEBook, &log, $path(packpath), 16ULL << 30);
        pack_offset = u8bDataLen(log);
    } else {
        test(kv32bDataLen(k->packs) < KEEP_MAX_FILES, KEEPNOROOM);
        call(FILEBookCreate, &log, $path(packpath), 16ULL << 30, 4096);
        call(PACKu8sFeedHdr, u8bIdle(log), 0);
        pack_offset = 12;
    }
    call(keep_pack_install, k, file_id, log);

    //  Stream-demux: pkt-line headers parsed inline; side-band-64k
    //  caps body at 65519 bytes (round up for slack).
    static u8 body[65540];
    u8 git_hdr[12];
    u32 git_hdr_got = 0;
    b8 raw_mode = NO;       // server inlined PACK, no sideband
    b8 saw_pack = NO;       // any band-1 / raw bytes seen?

    //  Forward `n` band-1 bytes from `src` into the log, stripping
    //  the leading 12 (git PACK header) into `git_hdr`.
    #define KEEP_INGEST_FORWARD(src, nbytes)                            \
        do {                                                            \
            u8 const *_p = (src);                                       \
            u32       _n = (nbytes);                                    \
            if (_n) saw_pack = YES;                                     \
            if (git_hdr_got < 12 && _n) {                               \
                u32 _take = 12 - git_hdr_got;                           \
                if (_take > _n) _take = _n;                             \
                memcpy(git_hdr + git_hdr_got, _p, _take);               \
                git_hdr_got += _take;                                   \
                _p += _take;                                            \
                _n -= _take;                                            \
            }                                                           \
            if (_n) {                                                   \
                ok64 _e = FILEBookEnsure(log, _n);                      \
                if (_e != OK) return _e;                                \
                u8cs _slice = {_p, _p + _n};                            \
                u8bFeed(log, _slice);                                   \
            }                                                           \
        } while (0)

    for (;;) {
        if (raw_mode) {
            //  No-sideband fallback: drain the rest of rfd through
            //  body[] and forward into the log (with strip filter).
            ssize_t got = read(rfd, body, sizeof(body));
            if (got == 0) break;
            if (got < 0) {
                if (errno == EINTR) continue;
                fail(KEEPFAIL);
            }
            KEEP_INGEST_FORWARD(body, (u32)got);
            continue;
        }

        u8 hdr[4];
        ssize_t n = keep_read_full(rfd, hdr, 4);
        if (n == 0) break;
        if (n != 4) fail(KEEPFAIL);
        u32 plen = keep_hex4(hdr);
        if (plen == 0xFFFFFFFFu) {
            //  Header isn't valid hex — server (e.g. keeper's own
            //  upload-pack) advertised side-band-64k support but is
            //  actually streaming raw pack bytes after the NAK.  The
            //  4 bytes we just consumed are the start of "PACK".
            KEEP_INGEST_FORWARD(hdr, 4);
            raw_mode = YES;
            continue;
        }
        if (plen == 0) break;            // flush-pkt
        if (plen <= 4) continue;         // delim / response-end
        u32 blen = plen - 4;
        if (blen > sizeof(body)) fail(KEEPFAIL);
        n = keep_read_full(rfd, body, blen);
        if ((u32)n != blen) fail(KEEPFAIL);
        if (blen == 0) continue;

        //  Bare NAK/ACK status — absorb.
        if (blen >= 3 &&
            (memcmp(body, "NAK", 3) == 0 ||
             memcmp(body, "ACK", 3) == 0)) continue;

        //  Server-without-sideband fallback: pkt body starts with
        //  "PACK" — the body itself is the start of the raw pack;
        //  remainder of rfd is raw too.
        if (blen >= 4 && memcmp(body, "PACK", 4) == 0) {
            KEEP_INGEST_FORWARD(body, blen);
            raw_mode = YES;
            continue;
        }

        u8 band = body[0];
        u32 dlen = blen - 1;
        u8 *data = body + 1;
        switch (band) {
        case 0x01:
            KEEP_INGEST_FORWARD(data, dlen);
            break;
        case 0x02: {                       // progress (live stderr)
            ssize_t w;
            do {
                w = write(STDERR_FILENO, data, dlen);
            } while (w < 0 && errno == EINTR);
            break;
        }
        case 0x03:                         // fatal
            (void)write(STDERR_FILENO, data, dlen);
            fail(KEEPFAIL);
        default:
            //  Unknown band — skip.
            break;
        }
    }
    #undef KEEP_INGEST_FORWARD

    //  No bytes received (clean disconnect with no pack) — leave the
    //  log as-is and return OK.  Bookmark write would be ill-formed.
    if (!saw_pack) {
        FILETrimBook(log);
        FILEUnBook(log);
        keep_pack_drop(k, file_id);
        u8bp ro = NULL;
        call(FILEMapRO, &ro, $path(packpath));
        call(keep_pack_install, k, file_id, ro);
        if (!appending) k->next_seqno = file_id + 1;
        done;
    }

    //  Got fewer bytes than a valid pack tail (12 hdr stashed + 0
    //  bytes appended + 20 trailer wouldn't reach here — trailer
    //  appended to log is at least 20 bytes).
    if (git_hdr_got < 12 || u8bDataLen(log) < pack_offset + 20)
        fail(KEEPFAIL);

    //  Drop the 20-byte SHA-1 trailer from the log tail.
    u8bShed(log, 20);

    //  Parse the stashed git PACK header for the object count.
    pack_hdr ph = {};
    {
        u8cs hscan = {git_hdr, git_hdr + 12};
        call(PACKDrainHdr, hscan, &ph);
    }

    //  Empty pack: zero objects, no log mutation needed beyond what
    //  we've already done (which was nothing for the data region).
    if (ph.count == 0) {
        FILETrimBook(log);
        FILEUnBook(log);
        keep_pack_drop(k, file_id);
        u8bp ro = NULL;
        call(FILEMapRO, &ro, $path(packpath));
        call(keep_pack_install, k, file_id, ro);
        if (!appending) k->next_seqno = file_id + 1;
        done;
    }

    //  Patch the file-level PACK header count: old + ph.count.
    {
        u8p hdr = u8bDataHead(log);
        u32 old_count = ((u32)hdr[8] << 24) | ((u32)hdr[9] << 16) |
                        ((u32)hdr[10] << 8) | (u32)hdr[11];
        u32 new_count = old_count + ph.count;
        hdr[8]  = (u8)(new_count >> 24);
        hdr[9]  = (u8)(new_count >> 16);
        hdr[10] = (u8)(new_count >> 8);
        hdr[11] = (u8)(new_count);
    }

    u64 log_len = u8bDataLen(log);
    u64 pack_byte_len = log_len - pack_offset;

    call(FILETrimBook, log);
    FILEUnBook(log);
    log = NULL;

    keep_pack_drop(k, file_id);
    u8bp ro = NULL;
    call(FILEMapRO, &ro, $path(packpath));
    call(keep_pack_install, k, file_id, ro);
    if (!appending) k->next_seqno = file_id + 1;

    //  Index the newly-appended slice.
    Bwh128 entries = {};
    call(wh128bAllocate, entries, (u64)ph.count + 16);
    u8cs log_view = {u8bDataHead(ro), u8bDataHead(ro) + log_len};
    unpk_in uin = {
        .pack = {log_view[0], log_view[1]},
        .scan_start = pack_offset,
        .scan_end = log_len,
        .count = ph.count,
        .file_id = file_id,
    };
    unpk_stats ust = {};
    call(UNPKIndex, k, &uin, entries, &ust);

    {
        wh128 bm = {
            .key = wh64Pack(KEEP_TYPE_PACK, file_id, pack_offset),
            .val = keepPackBmVal(ph.count, (u32)pack_byte_len),
        };
        call(wh128bPush, entries, &bm);
    }

    a_dup(wh128, sorted, wh128bData(entries));
    wh128sSort(sorted);
    wh128sDedup(sorted);
    u64 nent = wh128sLen(sorted);

    a_cstr(ext, KEEP_IDX_EXT);
    u8cs raw = {(u8cp)sorted[0], (u8cp)(sorted[0] + nent)};
    ok64 cr = keep_pup_create_next(k, $path(kdir), ext, raw);
    wh128bFree(entries);
    if (cr != OK) return cr;
    call(KEEPCompact, k);

    done;
}

// --- Sync: clone or update from remote via git-upload-pack ---

#include "PKT.h"
#include "ZINF.h"
#include <sys/wait.h>

// Compute git object SHA-1: hash("<type> <size>\0<content>")
// Incremental: feeds header and content separately (no copy needed).
static void keep_git_sha1(sha1 *out, u8 type, u8csc content) {
    a_pad(u8, hdr, 64);
    u8cs tname = {};
    GITTypeName(tname, type);
    u8bFeed(hdr, tname);
    u8bPrintf(hdr, " %llu", (unsigned long long)u8csLen(content));
    u8bFeed1(hdr, 0);

    SHA1state ctx;
    SHA1Open(&ctx);
    SHA1Feed(&ctx, u8bDataC(hdr));
    SHA1Feed(&ctx, content);
    SHA1Close(&ctx, out);
}

// DFS tree node for pack indexing (used by KEEPSync)
typedef struct { u64 offset; u32 child; u32 sibling; } pack_node;

// ----------------------------------------------------------------
//  Upload-pack negotiation helpers.  Plain (no multi_ack) mode: the
//  walker streams `have <sha>` pkt-lines into a scratch buffer which
//  gets drained to wfd periodically.  No ACK handshake mid-walk —
//  server buffers everything and computes the pack cutoff once the
//  caller follows up with `done`.
// ----------------------------------------------------------------

typedef struct {
    u8s *ws;        // pkt-line scratch slice (head/term)
    u8  *wbuf;      // base of scratch (for write-and-rewind)
    int  wfd;
    int  total;     // haves sent total
    ok64 io_err;
} keep_neg_ctx;

//  Drain the pkt-line scratch buffer to wfd, then rewind it.
static ok64 keep_sync_drain_buf(keep_neg_ctx *w) {
    u64 wlen = w->ws[0][0] - w->wbuf;
    u64 written = 0;
    while (written < wlen) {
        u64 chunk = wlen - written;
        if (chunk > 32768) chunk = 32768;
        ssize_t n = write(w->wfd, w->wbuf + written, chunk);
        if (n <= 0) return KEEPFAIL;
        written += (u64)n;
    }
    w->ws[0][0] = w->wbuf;
    return OK;
}

//  Walker callback: append `have <sha>\n` to the scratch buffer.
//  When the scratch is close to full, drain to wfd (no flush packet,
//  no ACK read — server just buffers the haves and processes them on
//  `done`).  Return non-OK to stop the walk.
static ok64 keep_sync_have_cb(void *cb_ctx, sha1hex const *sha) {
    keep_neg_ctx *w = (keep_neg_ctx *)cb_ctx;
    if (w->io_err != OK) return FAILSANITY;

    char pay[64];
    int plen = snprintf(pay, sizeof(pay), "have %.40s\n", sha->data);
    u8cs payload = {(u8cp)pay, (u8cp)pay + plen};
    if (PKTu8sFeed(*w->ws, payload) != OK) {
        //  Scratch full: drain what we have and retry.
        if (keep_sync_drain_buf(w) != OK) {
            w->io_err = KEEPFAIL;
            return FAILSANITY;
        }
        if (PKTu8sFeed(*w->ws, payload) != OK) {
            w->io_err = KEEPFAIL;
            return FAILSANITY;
        }
    }
    w->total++;
    return OK;
}

// Drain one pkt-line from the ref advertisement, refilling buf via
// FILEDrain on NODATA. adv is a const view tracking the parser cursor:
// PKTu8sDrain advances adv[0]; this helper extends adv[1] to match the
// new DATA term after each refill. Used for both the HEAD line and
// every subsequent ref so the same retry policy applies uniformly.
//
// Returns OK with `line` populated, PKTFLUSH/PKTDELIM, or KEEPFAIL on
// EOF/read error/buffer exhaustion.
static ok64 keep_sync_drain_pkt(int rfd, u8b buf, u8cs adv, u8csp line) {
    for (;;) {
        ok64 o = PKTu8sDrain(adv, line);
        if (o != NODATA) return o;
        if (!u8bHasRoom(buf)) {
            fprintf(stderr, "keeper: adv buffer full at %zu bytes\n",
                    u8bDataLen(buf));
            return KEEPNOROOM;
        }
        $u8 fill;
        u8sFork(u8bIdle(buf), fill);
        ok64 fr = FILEDrain(rfd, fill);
        if (fr == FILEEND) {
            // Silent on 0-byte EOF — git-upload-pack's own fatal: ...
            // line on stderr already told the user what went wrong
            // (bad path, permission denied, etc). Only flag mid-stream
            // EOF where the lost flush packet is the actual surprise.
            if (u8bDataLen(buf) > 0)
                fprintf(stderr, "keeper: adv read EOF after %zu bytes "
                                "(no flush packet)\n",
                        u8bDataLen(buf));
            return KEEPFAIL;
        }
        if (fr != OK) {
            fprintf(stderr, "keeper: adv read: %s\n", ok64str(fr));
            return KEEPFAIL;
        }
        u8sJoin(u8bIdle(buf), fill);
        adv[1] = u8csTerm(u8bDataC(buf));
    }
}

//  Extract the parent SHAs from a commit object body.  Reads through
//  headers via GITu8sDrainCommit (hand-rolled scanner — no Ragel), stops
//  at the blank line that separates headers from message.  Writes up
//  to `cap` parent sha1s into `out`, returns count in `*n`.
static ok64 keep_commit_parents(u8cs body, sha1 *out, u32 *n, u32 cap) {
    sane(out && n);
    a_dup(u8c, scan, body);
    u8cs field = {}, value = {};
    *n = 0;
    while (GITu8sDrainCommit(scan, field, value) == OK) {
        if (u8csEmpty(field)) break;  // blank line → commit message follows
        if (!u8csEq(field, GIT_FIELD_PARENT)) continue;
        if (u8csLen(value) < 40) continue;
        if (*n >= cap) break;
        u8s obin = {out[*n].data, out[*n].data + 20};
        u8cs hex40 = {value[0], value[0] + 40};
        if (HEXu8sDrainSome(obin, hex40) != OK) continue;
        (*n)++;
    }
    done;
}

//  Extract the pointed-to object SHA from a tag body.  Tag bodies
//  start with `object <hex>\n`.  Same header parser.
static ok64 keep_tag_target(u8cs body, sha1 *out) {
    sane(out);
    a_dup(u8c, scan, body);
    u8cs field = {}, value = {};
    while (GITu8sDrainCommit(scan, field, value) == OK) {
        if (u8csEmpty(field)) break;
        if (!u8csEq(field, GIT_FIELD_OBJECT)) continue;
        if (u8csLen(value) < 40) return GITBADFMT;
        u8s obin = {out->data, out->data + 20};
        u8cs hex40 = {value[0], value[0] + 40};
        return HEXu8sDrainSome(obin, hex40);
    }
    return GITBADFMT;
}

//  Priority-queue negotiation: BFS from seed SHAs, walking parent
//  edges, sending each visited commit as a `have <sha>`.  Heap is
//  ordered by keeper log offset (newest-ingested first) so recent
//  commits flood the wire first — that's exactly the ordering git's
//  own fetch-pack uses, and it lets the server converge to a common
//  ancestor in one or two rounds for the typical incremental fetch.
//
//  Dedup is on pop (we may push a commit once per parent edge that
//  reaches it).  Seed is the caller's static auto-have list.
//
//  Termination: heap empty (all reachable commits/tags enumerated).
//  Final `done\n` sent by the caller.
//  Look up a commit's log offset via keeper's LSM (via its 60-bit
//  hashlet), stash the sha in shatab, push (~offset, idx) onto the
//  heap.  Key = ~offset makes the default min-on-key heap yield
//  newest-ingested first.  Caller owns shatab/heap.
static ok64 keep_sync_push_sha(keeper *k, sha1 const *sha,
                                sha1 *shatab, u32 *nshatab,
                                u32 cap, Bkv64 heap_b) {
    u64 hashlet60 = WHIFFHashlet60(sha);
    u64 val = 0;
    if (KEEPLookup(k, hashlet60, 15, &val) != OK) return NONE;
    if (*nshatab >= cap) return NONE;
    shatab[*nshatab] = *sha;
    kv64 e = {.key = ~wh64Off(val), .val = (u64)*nshatab};
    (*nshatab)++;
    return HEAPkv64Push1(heap_b, e);
}

static ok64 keep_sync_parent_walk(keeper *k,
                                    char const *const *haves,
                                    keep_neg_ctx *w) {
    sane(k && w);

    //  Scratch alloc.  256k slots covers ~100k commits at 50% load.
    #define NEG_CAP      (1U << 18)
    #define NEG_MAX_SHAS (1U << 18)
    Bkv64 heap_b    = {};
    Bkv64 visited_b = {};
    sha1 *shatab    = NULL;
    u32   nshatab   = 0;
    Bu8   body_b    = {};
    ok64  ret       = OK;

    if (kv64bAllocate(heap_b,    NEG_CAP) != OK) { ret = KEEPNOROOM; goto out; }
    if (kv64bAllocate(visited_b, NEG_CAP) != OK) { ret = KEEPNOROOM; goto out; }
    shatab = calloc(NEG_MAX_SHAS, sizeof(sha1));
    if (!shatab)                               { ret = KEEPNOROOM; goto out; }
    if (u8bAllocate(body_b, 1U << 20) != OK)   { ret = KEEPNOROOM; goto out; }

    kv64s visited = {kv64bHead(visited_b), kv64bTerm(visited_b)};

    //  Seed from auto-have list (server-advertised ref SHAs we have).
    if (haves) {
        for (int hi = 0; haves[hi]; hi++) {
            sha1 seed = {};
            u8s sb = {seed.data, seed.data + 20};
            u8cs hex40 = {(u8cp)haves[hi], (u8cp)haves[hi] + 40};
            if (HEXu8sDrainSome(sb, hex40) != OK) continue;
            (void)keep_sync_push_sha(k, &seed, shatab, &nshatab,
                                     NEG_MAX_SHAS, heap_b);
        }
    }

    //  BFS loop.
    sha1 parents[16];
    while (!Bempty(heap_b)) {
        if (w->io_err != OK) break;

        kv64 top = {};
        if (HEAPkv64Pop(&top, heap_b) != OK) break;
        u32 idx = (u32)top.val;
        if (idx >= nshatab) continue;
        sha1 cur = shatab[idx];

        //  Dedup on pop (visited set keyed by hashlet60).
        u64 hashlet60 = WHIFFHashlet60(&cur);
        kv64 vprobe = {.key = hashlet60, .val = 0};
        if (HASHkv64Get(&vprobe, visited) == OK) continue;
        kv64 ventry = {.key = hashlet60, .val = 1};
        HASHkv64Put(visited, &ventry);

        //  Emit have.
        sha1hex sh = {};
        sha1hexFromSha1(&sh, &cur);
        if (keep_sync_have_cb(w, &sh) != OK) break;

        //  Walk the object: commit → push parents, tag → push pointed-
        //  to object (which recursively resolves to a commit on the
        //  next iteration).  Anything else: nothing to chase.
        u8bReset(body_b);
        u8 type = 0;
        if (KEEPGetExact(k, &cur, body_b, &type) != OK) continue;
        u8cs body_s = {u8bDataHead(body_b), u8bIdleHead(body_b)};
        if (type == DOG_OBJ_COMMIT) {
            u32 np = 0;
            if (keep_commit_parents(body_s, parents, &np, 16) != OK)
                continue;
            for (u32 i = 0; i < np; i++)
                (void)keep_sync_push_sha(k, &parents[i], shatab, &nshatab,
                                         NEG_MAX_SHAS, heap_b);
        } else if (type == DOG_OBJ_TAG) {
            sha1 target = {};
            if (keep_tag_target(body_s, &target) != OK) continue;
            (void)keep_sync_push_sha(k, &target, shatab, &nshatab,
                                     NEG_MAX_SHAS, heap_b);
        }
    }

    //  Final drain of any batched haves still in the scratch.
    if (w->io_err == OK && (u64)(w->ws[0][0] - w->wbuf) > 0) {
        if (keep_sync_drain_buf(w) != OK) w->io_err = KEEPFAIL;
    }

    if (w->io_err != OK) ret = w->io_err;

out:
    if (body_b[0])    u8bFree(body_b);
    if (shatab)       free(shatab);
    if (visited_b[0]) kv64bFree(visited_b);
    if (heap_b[0])    kv64bFree(heap_b);
    return ret;
}

// Drain REF_DELTA waiters: binary search + scan in sorted wh128 slice.
// Links matching waiters as children of parent_idx in the DFS tree.
static void keep_drain_waiters(wh128cs waiters,
                               pack_node *nodes, b8 *resolved,
                               u64 sha_key, u32 parent_idx) {
    wh128cp wbuf = waiters[0];
    size_t wlen = (size_t)(waiters[1] - waiters[0]);
    // Binary search for first entry with matching key
    size_t lo = 0, hi = wlen;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (wbuf[mid].key < sha_key) lo = mid + 1;
        else hi = mid;
    }
    // Scan all entries with matching key
    for (size_t j = lo; j < wlen && wbuf[j].key == sha_key; j++) {
        u32 w = (u32)wbuf[j].val;
        if (resolved[w]) continue;
        nodes[w].sibling = nodes[parent_idx].child;
        nodes[parent_idx].child = w;
    }
}

ok64 KEEPSync(keeper *k, u8cs remote, u8cs origin_uri,
              char const *const *wants, char const *const *haves) {
    sane(k);

    if ($empty(remote)) {
        fprintf(stderr, "keeper: sync requires a remote\n");
        return KEEPFAIL;
    }

    // Parse remote: "host /path" or just "/path" for local
    // Build command: ssh host git-upload-pack 'path'
    // or local: git-upload-pack 'path'
    a_pad(u8, cmdbuf, 2 * FILE_PATH_MAX_LEN);
    a_dup(u8c, rscan, remote);
    if (u8csFind(rscan, ' ') == OK) {
        u8cs host = {remote[0], rscan[0]};
        u8cs rpath = {rscan[0] + 1, remote[1]};
        a_cstr(ssh_pre, "ssh ");
        a_cstr(gup, " git-upload-pack '");
        a_cstr(sq, "'");
        call(u8bFeed, cmdbuf, ssh_pre);
        call(u8bFeed, cmdbuf, host);
        call(u8bFeed, cmdbuf, gup);
        call(u8bFeed, cmdbuf, rpath);
        call(u8bFeed, cmdbuf, sq);
    } else {
        a_cstr(gup, "git-upload-pack '");
        a_cstr(sq, "'");
        call(u8bFeed, cmdbuf, gup);
        call(u8bFeed, cmdbuf, remote);
        call(u8bFeed, cmdbuf, sq);
    }
    call(u8bFeed1, cmdbuf, 0);  // NUL terminate for popen
    char *cmd = (char *)u8bDataHead(cmdbuf);

    fprintf(stderr, "keeper: connecting: %s\n", cmd);

    // Fork + pipe
    int to_child[2], from_child[2];
    if (pipe(to_child) != 0 || pipe(from_child) != 0) return KEEPFAIL;

    pid_t pid = fork();
    if (pid < 0) return KEEPFAIL;

    if (pid == 0) {
        close(to_child[1]);
        close(from_child[0]);
        dup2(to_child[0], 0);
        dup2(from_child[1], 1);
        close(to_child[0]);
        close(from_child[1]);
        execl("/bin/sh", "sh", "-c", cmd, NULL);
        _exit(127);
    }

    close(to_child[0]);
    close(from_child[1]);
    int wfd = to_child[1];
    int rfd = from_child[0];

    // Declare refs early so sync_fail's free() is safe even if we jump
    // there before the allocation below — e.g. when ssh-auth fails and
    // the advertisement EOFs at 0 bytes. (Pre-existing bug: refs was
    // declared after the goto site; sync_fail's free(refs) read
    // indeterminate memory and SEGV'd on every early-fail path.)
    typedef struct { sha1hex sha; sha1hex peeled; char name[256]; } push_ref;
    push_ref *refs = NULL;

    // Read ref advertisement
    #define PUSH_BUFSZ KEEP_BUFSZ  // same as KEEPGet buffers (1 GB mmap)
    // mmap large buffers (virtual space only, pages on demand)
    Bu8 rbuf_b = {}, objbuf_b = {};
    u8bMap(rbuf_b, PUSH_BUFSZ);
    u8bMap(objbuf_b, PUSH_BUFSZ);
    u8p rbuf = u8bHead(rbuf_b);
    u8p buf1 = u8bHead(k->buf1);  // reuse keeper's pre-allocated buffers
    u8p buf2 = u8bHead(k->buf2);
    u8p objbuf = u8bHead(objbuf_b);
    if (!rbuf || !buf1 || !buf2 || !objbuf) {
        if (rbuf_b[0]) u8bUnMap(rbuf_b);
        if (objbuf_b[0]) u8bUnMap(objbuf_b);
        close(wfd); close(rfd);
        kill(pid, SIGTERM); waitpid(pid, NULL, 0);
        return KEEPNOROOM;
    }

    // Parse ref advertisement — collect all refs.
    // Use a single drain helper for HEAD and all subsequent lines so the
    // NODATA-retry/refill policy is identical (was: bug — first read had
    // no retry path, fragile if HEAD pkt-line spanned a pipe boundary).
    // adv tracks the parser cursor; head/term both start at the buffer's
    // empty DATA region and grow as keep_sync_drain_pkt refills.
    u8cp adv_start = u8bDataHead(rbuf_b);
    u8cs adv = {adv_start, adv_start};
    u8cs line = {};

    ok64 po = keep_sync_drain_pkt(rfd, rbuf_b, adv, line);
    if (po != OK || $len(line) < 40) goto sync_fail;

    // First line = HEAD sha
    sha1hex head_hex;
    {
        u8cs hex40 = {line[0], line[0] + 40};
        sha1hexFromHex(&head_hex, hex40);
    }

    // Drain remaining refs until flush.
    u32 ref_cap = 4096;
    refs = malloc(ref_cap * sizeof(push_ref));
    if (!refs) { u8bUnMap(rbuf_b); u8bUnMap(objbuf_b);
                 close(wfd); close(rfd);
                 kill(pid, SIGTERM); waitpid(pid, NULL, 0);
                 return KEEPNOROOM; }
    u32 nrefs = 0;
    refs[0].sha = head_hex;
    refs[0].peeled = head_hex;
    snprintf(refs[0].name, 256, "HEAD");
    nrefs++;

    for (;;) {
        ok64 o = keep_sync_drain_pkt(rfd, rbuf_b, adv, line);
        if (o == PKTFLUSH) break;
        if (o != OK) break;
        if ($len(line) >= 42) {
            // Extract ref name: after SHA + space, until NUL/space/newline
            u8cp namestart = line[0] + 41;
            u8cp nameend = namestart;
            while (nameend < line[1] && *nameend != 0 &&
                   *nameend != ' ' && *nameend != '\n')
                nameend++;
            size_t namelen = (size_t)(nameend - namestart);
            if (namelen == 0 || namelen >= 256) continue;

            // Peeled tag (^{}): update peeled SHA for matching ref.
            if (namelen > 3 && nameend[-1] == '}' && nameend[-2] == '{' && nameend[-3] == '^') {
                size_t base_namelen = namelen - 3;
                u8cs base_name = {namestart, namestart + base_namelen};
                u8cs hex40     = {line[0],   line[0]   + 40};
                for (u32 pi = 0; pi < nrefs; pi++) {
                    a_cstr(rname, refs[pi].name);
                    if (u8csEq(rname, base_name)) {
                        sha1hexFromHex(&refs[pi].peeled, hex40);
                        break;
                    }
                }
                continue;
            }

            // Grow if needed
            if (nrefs >= ref_cap) {
                ref_cap *= 2;
                push_ref *grown = realloc(refs, ref_cap * sizeof(push_ref));
                if (!grown) break;
                refs = grown;
            }

            u8cs hex40 = {line[0], line[0] + 40};
            sha1hexFromHex(&refs[nrefs].sha,    hex40);
            sha1hexFromHex(&refs[nrefs].peeled, hex40);
            memcpy(refs[nrefs].name, namestart, namelen);
            refs[nrefs].name[namelen] = 0;
            nrefs++;
        }
    }

    fprintf(stderr, "keeper: %u ref(s), HEAD=%.12s\n", nrefs, head_hex.data);

    // ----------------------------------------------------------------
    //  upload-pack negotiation (git multi-round, multi_ack_detailed).
    //
    //    wants + flush
    //    loop:
    //      haves pulled newest-first off a priority queue (key = log
    //      offset from keeper's LSM index, so commits we ingested last
    //      pop first).  Dedup on pop via a visited set.  When popped,
    //      send as `have <sha>\n`; on batch-fill, flush + read ACK
    //      lines.  Also load the commit body, parse `parent <hex>`
    //      headers and push each parent onto the queue.
    //      Stops on: heap empty, `ACK <sha> ready`, or MAX_IN_VAIN
    //      consecutive unACKed haves.
    //    done
    //
    //  Seed set: the static auto-have list (`haves[]`) — server-
    //  advertised ref SHAs whose object we already have locally.
    //  That's where the graph walk starts; the parent-chain expansion
    //  covers cases where our tips are ahead of the server's (so the
    //  server needs to see an older common ancestor) or vice versa.
    //  Pack-receive code below is unchanged.
    // ----------------------------------------------------------------
    int nhave_sent = 0;

    {
        #define NEGBUF (1 << 20)  // 1MB for want/have pkt-lines
        u8 *wbuf = malloc(NEGBUF);
        if (!wbuf) goto sync_fail;
        u8s ws = {wbuf, wbuf + NEGBUF};
        b8 first_want = YES;
        //  No multi_ack_detailed: with it, the server sends back ACK
        //  round-trips interleaved with our haves, which means we'd
        //  have to read/handshake mid-walk to avoid pipe-buffer dead-
        //  lock when the walk pushes tens of thousands of haves.
        //  Sticking to the plain protocol: client sends all haves +
        //  done, server computes cutoff once, sends pack.  No ACKs
        //  mid-flight, no handshake state machine.
        char const *first_caps = "no-progress";

        if (wants) {
            for (int wi = 0; wants[wi]; wi++) {
                sha1hex const *sha = NULL;
                size_t wlen = strlen(wants[wi]);
                sha1hex const *tail = NULL;
                for (u32 j = 0; j < nrefs; j++) {
                    if (wlen == 40 && memcmp(refs[j].sha.data, wants[wi], 40) == 0) {
                        sha = &refs[j].sha; break;
                    }
                    if (strcmp(refs[j].name, wants[wi]) == 0) {
                        sha = &refs[j].sha; break;
                    }
                    size_t nlen = strlen(refs[j].name);
                    if (nlen <= wlen + 1) continue;
                    if (refs[j].name[nlen - wlen - 1] != '/') continue;
                    if (memcmp(refs[j].name + nlen - wlen, wants[wi], wlen) != 0)
                        continue;
                    b8 is_head = (nlen > 11 &&
                                  memcmp(refs[j].name, "refs/heads/", 11) == 0);
                    b8 is_tag  = (nlen > 10 &&
                                  memcmp(refs[j].name, "refs/tags/", 10) == 0);
                    if (is_head || is_tag) { sha = &refs[j].sha; break; }
                    if (!tail) tail = &refs[j].sha;
                }
                if (!sha && tail) sha = tail;
                if (!sha) {
                    fprintf(stderr, "keeper: want %s not advertised, skipping\n",
                            wants[wi]);
                    continue;
                }
                char pay[256];
                int plen;
                if (first_want) {
                    plen = snprintf(pay, sizeof(pay),
                        "want %.40s %s\n", sha->data, first_caps);
                    first_want = NO;
                } else {
                    plen = snprintf(pay, sizeof(pay),
                        "want %.40s\n", sha->data);
                }
                u8cs payload = {(u8cp)pay, (u8cp)pay + plen};
                PKTu8sFeed(ws, payload);
            }
        } else {
            for (u32 i = 0; i < nrefs; i++) {
                char pay[256];
                int plen;
                if (first_want) {
                    plen = snprintf(pay, sizeof(pay),
                        "want %.40s %s\n", refs[i].sha.data, first_caps);
                    first_want = NO;
                } else {
                    plen = snprintf(pay, sizeof(pay),
                        "want %.40s\n", refs[i].sha.data);
                }
                u8cs payload = {(u8cp)pay, (u8cp)pay + plen};
                PKTu8sFeed(ws, payload);
            }
        }

        if (first_want) {
            fprintf(stderr, "keeper: nothing to want\n");
            free(wbuf);
            goto sync_done;
        }

        PKTu8sFeedFlush(ws);

        // Helper: drain the wants-pkt-line buffer to the wire.
        #define KEEP_FLUSH_BUF do {                                     \
            u64 _wl = ws[0] - wbuf;                                     \
            u64 _w = 0;                                                 \
            while (_w < _wl) {                                          \
                u64 _c = _wl - _w;                                      \
                if (_c > 32768) _c = 32768;                             \
                ssize_t _n = write(wfd, wbuf + _w, _c);                 \
                if (_n <= 0) { free(wbuf); goto sync_fail; }            \
                _w += (u64)_n;                                          \
            }                                                           \
            ws[0] = wbuf;                                               \
        } while (0)
        KEEP_FLUSH_BUF;

        {
            keep_neg_ctx wctx = {
                .ws = &ws, .wbuf = wbuf,
                .wfd = wfd,
                .total = 0,
                .io_err = OK,
            };

            ok64 neg_r = keep_sync_parent_walk(k, haves, &wctx);
            if (neg_r != OK) {
                free(wbuf); goto sync_fail;
            }
            nhave_sent = wctx.total;
        }

        if (nhave_sent > 0)
            fprintf(stderr, "keeper: sent %d have(s)\n", nhave_sent);

        // `done\n` ends negotiation; server starts sending the pack.
        u8 donepay[] = "done\n";
        u8cs donecs = {donepay, donepay + 5};
        PKTu8sFeed(ws, donecs);
        KEEP_FLUSH_BUF;

        free(wbuf);
        #undef KEEP_FLUSH_BUF
    }
    close(wfd);
    wfd = -1;

    // Read response into rbuf (may need multiple reads for ACK sequences).
    // Reuse rbuf_b's allocation; reset its DATA tracking and the scratch
    // rlen offset that the response/pack code below uses with rbuf.
    u8bReset(rbuf_b);
    u64 rlen = 0;
    for (;;) {
        ssize_t n = read(rfd, rbuf + rlen, PUSH_BUFSZ - rlen);
        if (n <= 0) { if (rlen == 0) goto sync_fail; break; }
        rlen += (u64)n;
        // Stop once we see PACK magic in the buffer
        if (rlen >= 16) {
            for (u64 i = 0; i + 4 <= rlen; i++) {
                if (memcmp(rbuf + i, "PACK", 4) == 0) goto got_pack;
            }
        }
        // Safety: stop after 1MB of ACK chatter
        if (rlen >= (1 << 20)) break;
    }
got_pack:

    // Parse response: NAK (full clone) or ACK <sha> (incremental)
    u8cs resp = {rbuf, rbuf + rlen};
    po = PKTu8sDrain(resp, line);
    if (po != OK) goto sync_fail;
    if (u8csHasPrefix(line, GIT_PKT_NAK)) {
        // Full clone response
    } else if (u8csHasPrefix(line, GIT_PKT_ACK)) {
        // Incremental: drain ACK/NAK lines until we reach the pack data
        for (;;) {
            // Check if resp[0] is at PACK magic
            if (u8csHasPrefix(resp, GIT_PACK_MAGIC)) break;
            ok64 ao = PKTu8sDrain(resp, line);
            if (ao == PKTFLUSH) break;
            if (ao != OK) break;
            if (u8csHasPrefix(line, GIT_PKT_NAK)) break;
        }
    } else {
        fprintf(stderr, "keeper: unexpected response: %.*s\n",
                (int)u8csLen(line), (char *)line[0]);
        goto sync_fail;
    }

    // Parse PACK header from the initial read
    u8cp pack_start = resp[0];  // where PACK data begins in rbuf
    pack_hdr hdr = {};
    po = PACKDrainHdr(resp, &hdr);
    if (po != OK || hdr.version != 2) goto sync_fail;
    u64 initial_pack = rlen - (u64)(pack_start - rbuf);  // pack bytes in rbuf

    // Open or create pack log file for appending.
    // Estimate VA reservation from object count (~256 bytes/obj).
    b8 appending = (kv32bDataLen(k->packs) > 0);
    u32 file_id = appending ? keep_packs_max_seqno(k) : k->next_seqno;
    u64 pack_book = 16ULL << 30;  // 16GB VA reservation
    u8bp packbuf = NULL;
    u64 append_offset = 0;  // where new objects start in the log
    {
        a_pad(u8, dst, 1024);
        a_path(kdir);
        if (keep_branch_dir(kdir, k->h, u8bDataC(k->leaf_branch)) != OK)
            goto sync_fail;
        if (keep_pack_path(dst, $path(kdir), file_id) != OK)
            goto sync_fail;

        if (appending) {
            ok64 o = FILEBook(&packbuf, $path(dst), pack_book);
            if (o != OK) goto sync_fail;
            // FILEBook sets b[2] to the real content end.
            append_offset = u8bDataLen(packbuf);
        } else {
            // New log — create
            size_t init = initial_pack;
            if (init < 4096) init = 4096;
            ok64 o = FILEBookCreate(&packbuf, $path(dst),
                                    pack_book, init);
            if (o != OK) goto sync_fail;
        }
    }

    // Copy initial pack data from rbuf into booked file.
    // On append, skip the PACK header (12 bytes) — only append objects.
    {
        u8cp copy_start = pack_start;
        if (appending) {
            // resp[0] already points past the PACK header (PACKDrainHdr consumed it)
            copy_start = resp[0];
        }
        u8cs init_data = {copy_start, rbuf + rlen};
        call(FILEBookEnsure, packbuf, u8csLen(init_data));
        u8bFeed(packbuf, init_data);
    }

    // Stream remaining pack data from rfd directly into booked file
    {
        for (;;) {
            call(FILEBookEnsure, packbuf, 1 << 20);
            ssize_t n = read(rfd, u8bIdleHead(packbuf), u8bIdleLen(packbuf));
            if (n <= 0) break;
            u8bFed(packbuf, (size_t)n);
        }
    }
    close(rfd);
    rfd = -1;

    u64 new_bytes = u8bDataLen(packbuf) - append_offset;

    fprintf(stderr, "keeper: received %u objects, %llu bytes\n",
            hdr.count, (unsigned long long)new_bytes);

    // Patch object count in PACK header (offset 8, 4 bytes big-endian).
    // On append, add new objects to existing count. On fresh clone, already correct.
    if (appending) {
        u8p phdr = u8bDataHead(packbuf);
        u32 old_count = ((u32)phdr[8] << 24) | ((u32)phdr[9] << 16) |
                        ((u32)phdr[10] << 8) | phdr[11];
        u32 new_count = old_count + hdr.count;
        phdr[8]  = (u8)(new_count >> 24);
        phdr[9]  = (u8)(new_count >> 16);
        phdr[10] = (u8)(new_count >> 8);
        phdr[11] = (u8)(new_count);
    }

    // Trim booked file to actual size, then re-mmap read-only for indexing
    FILETrimBook(packbuf);
    FILEUnBook(packbuf);
    packbuf = NULL;

    // Re-mmap the pack read-only into keeper
    // (on append, unmap the old RO mapping first)
    if (appending) {
        u8bp old = keep_pack_buf(k, file_id);
        if (old) {
            FILEUnMap(old);
            keep_pack_drop(k, file_id);
        }
    }
    {
        a_pad(u8, pp, 1024);
        a_path(kdir);
        if (keep_branch_dir(kdir, k->h, u8bDataC(k->leaf_branch)) == OK &&
            keep_pack_path(pp, $path(kdir), file_id) == OK) {
            u8bp mapped = NULL;
            if (FILEMapRO(&mapped, $path(pp)) == OK) {
                (void)keep_pack_install(k, file_id, mapped);
                if (!appending) k->next_seqno = file_id + 1;
            }
        }
    }

    u8bp tail_pack = keep_pack_buf(k, file_id);
    if (!tail_pack) goto sync_fail;
    u8cp packbase = u8bDataHead(tail_pack);
    u64 packlen = (u64)(u8bIdleHead(tail_pack) - packbase);

    //  Scan + index the pack via UNPKIndex — same code path as
    //  KEEPIngestFile, so the per-object emit hook (graf/spot fan-out
    //  installed by the keeper CLI) fires here too.  The earlier
    //  in-line DFS/delta loop has been removed; UNPKIndex is the single
    //  source of truth for pack scanning, including thin-pack REF_DELTA
    //  resolution against earlier packs in the LSM.
    {
        Bwh128 entries = {};
        if (wh128bAllocate(entries, (u64)hdr.count + 16) != OK)
            goto sync_fail;

        //  Fresh fetch starts at byte 12 (after PACK header) and ends
        //  20 bytes early to skip git's trailing SHA-1.  Append mode:
        //  pure object bytes from append_offset to packlen, no header
        //  or trailer.
        u64 scan_start = appending ? append_offset : 12;
        u64 scan_end   = appending
            ? packlen
            : (packlen >= 20 ? packlen - 20 : packlen);
        unpk_in uin = {
            .pack       = {packbase, packbase + packlen},
            .scan_start = scan_start,
            .scan_end   = scan_end,
            .count      = hdr.count,
            .file_id    = file_id,
        };
        unpk_stats ust = {};
        ok64 ux = UNPKIndex(k, &uin, entries, &ust);
        if (ux != OK) {
            fprintf(stderr, "keeper: UNPKIndex failed: %s\n", ok64str(ux));
            wh128bFree(entries);
            goto sync_fail;
        }

        u32 deltas = ust.indexed > ust.base_count
                         ? ust.indexed - ust.base_count : 0;
        fprintf(stderr, "keeper: %u base objects resolved\n", ust.base_count);
        fprintf(stderr, "keeper: DFS indexed %u deltas from %u bases\n",
                deltas, ust.base_count);
        if (ust.cross > 0)
            fprintf(stderr,
                    "keeper: cross-pack: resolved %u REF_DELTAs\n",
                    ust.cross);
        fprintf(stderr, "keeper: indexed %u objects (%u skipped)\n",
                ust.indexed, ust.skipped);

        //  Sort, dedup, persist as a new puppy.
        if (wh128bDataLen(entries) > 0) {
            a_dup(wh128, sorted, wh128bData(entries));
            wh128sSort(sorted);
            wh128sDedup(sorted);
            u32 nfinal = (u32)(sorted[1] - sorted[0]);

            a_path(kdir);
            call(keep_branch_dir, kdir, k->h, u8bDataC(k->leaf_branch));
            a_cstr(ext, KEEP_IDX_EXT);
            u8cs data = {(u8cp)sorted[0], (u8cp)(sorted[0] + nfinal)};
            ok64 cr = keep_pup_create_next(k, $path(kdir), ext, data);
            if (cr != OK) {
                wh128bFree(entries);
                goto sync_fail;
            }
            //  Compact-per-flush — keeps the 1/8 invariant.
            (void)KEEPCompact(k);
        }

        wh128bFree(entries);
    }


sync_done:
    if (packbuf) { FILETrimBook(packbuf); FILEUnBook(packbuf); }
    u8bUnMap(rbuf_b); u8bUnMap(objbuf_b);
    // Close both pipe ends before waitpid so the child sees EOF on stdin
    // and stops. Without this, the "nothing to want" path (and any other
    // early goto sync_done) would hang forever in waitpid because ssh /
    // git-upload-pack stays alive waiting on its open stdin. Each fd is
    // -1 on the success path (already closed inline), so this is a no-op
    // there.
    if (wfd >= 0) { close(wfd); wfd = -1; }
    if (rfd >= 0) { close(rfd); rfd = -1; }
    { int status; waitpid(pid, &status, 0); }

    // Record refs in the reflog. See REF.md for the format spec.
    if (nrefs > 0) {
        a_path(kdir, u8bDataC(k->h->root), KEEP_DIR_S);

        // Worst case per ref: one entry with origin_uri prefix +
        // "?heads/<name>" (~280) + "\t?<sha>" (~42). Cap at 700/ref.
        u32 cap = nrefs + 4;
        ref *refarr = calloc(cap, sizeof(ref));
        if (refarr) {
            ron60 now = RONNow();
            Bu8 strbuf = {};
            ok64 me = u8bMap(strbuf, (u64)nrefs * 700);
            if (me != OK) {
                free(refarr);
                goto sync_end;
            }

            u32 written = 0;

            //  Helper: canonicalise the uri `UK` (query set by caller)
            //  into strbuf as the ref key, then feed bare 40-hex val.
            #define APPEND_REF(UK_FN_BODY, SHA_PTR)                        \
                do {                                                       \
                    if (written >= cap) break;                             \
                    uri _uk = {};                                          \
                    UK_FN_BODY;                                            \
                    refarr[written].time = now;                            \
                    refarr[written].type = REF_SHA;                        \
                    refarr[written].key[0] = u8bIdleHead(strbuf);          \
                    if (DOGCanonURIFeed(strbuf, &_uk) != OK) break;        \
                    refarr[written].key[1] = u8bIdleHead(strbuf);          \
                    refarr[written].val[0] = u8bIdleHead(strbuf);          \
                    u8cs _sha = {(SHA_PTR), (SHA_PTR) + 40};               \
                    u8bFeed(strbuf, _sha);                                 \
                    refarr[written].val[1] = u8bIdleHead(strbuf);          \
                    written++;                                             \
                } while (0)

            //  Remote's canonical URI (auth/path from origin_uri's
            //  parse) plus each advertised ref as the query; the
            //  canonicaliser drops the transport scheme and collapses
            //  trunk aliases.  `origin_uri` is already canonical, so
            //  parse once and reuse the parse for each row.
            uri ou = {};
            if (!u8csEmpty(origin_uri)) {
                ou.data[0] = origin_uri[0];
                ou.data[1] = origin_uri[1];
                (void)URILexer(&ou);
                ou.data[0] = origin_uri[0];
                ou.data[1] = origin_uri[1];
            }

            // Remote-attributed entries for each refs/heads/* and
            // refs/tags/* (skip everything else, including upstream's
            // own refs/remotes/*). See REF.md.
            for (u32 i = 1; i < nrefs; i++) {
                char const *nm = refs[i].name;
                size_t nmlen = strlen(nm);
                char const *stripped = NULL;
                size_t stripped_len = 0;
                if (nmlen > 11 && strncmp(nm, "refs/heads/", 11) == 0) {
                    stripped = nm + 5;
                    stripped_len = nmlen - 5;
                } else if (nmlen > 10 && strncmp(nm, "refs/tags/", 10) == 0) {
                    stripped = nm + 5;
                    stripped_len = nmlen - 5;
                } else {
                    continue;
                }
                u8cs strip_s = {(u8cp)stripped, (u8cp)stripped + stripped_len};
                if (!u8csEmpty(origin_uri)) {
                    APPEND_REF({
                        u8csMv(_uk.scheme,    ou.scheme);
                        u8csMv(_uk.authority, ou.authority);
                        u8csMv(_uk.host,      ou.host);
                        u8csMv(_uk.path,      ou.path);
                        u8csMv(_uk.query,     strip_s);
                    }, refs[i].peeled.data);
                }
            }

            #undef APPEND_REF

            ok64 ro = REFSSyncRecord($path(kdir), refarr, written);
            u8bUnMap(strbuf);
            if (ro != OK)
                fprintf(stderr, "keeper: warning: failed to record refs\n");
            else
                fprintf(stderr, "keeper: recorded %u ref(s)\n", written);
            free(refarr);
        }
    }

sync_end:
    free(refs);
    fprintf(stderr, "keeper: sync complete\n");
    done;

sync_fail:
    free(refs);
    if (rbuf_b[0]) u8bUnMap(rbuf_b);
    if (objbuf_b[0]) u8bUnMap(objbuf_b);
    if (wfd >= 0) close(wfd);
    if (rfd >= 0) close(rfd);
    kill(pid, SIGTERM);
    { int status; waitpid(pid, &status, 0); }
    return KEEPFAIL;
}

// --- KEEPPush: send one new commit via git-receive-pack ---

static ok64 keep_push_write_all(int fd, u8csc data) {
    u8cp p = data[0];
    size_t n = (size_t)(data[1] - data[0]);
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w <= 0) return KEEPFAIL;
        p += w;
        n -= (size_t)w;
    }
    return OK;
}

// Recursively collect tree + blob SHAs reachable from `tree_sha`
// into `out` (capacity `cap`).  Inflates each tree via KEEPGet and
// walks its entries.  Returns count appended to *n.  Silent on fetch
// failures — they manifest later when the pack is assembled.
static ok64 keep_walk_tree(keeper *k, sha1 const *tree_sha,
                           sha1 *out, u32 *n, u32 cap) {
    sane(k && tree_sha && out && n);
    if (*n >= cap) return KEEPFAIL;
    out[(*n)++] = *tree_sha;

    Bu8 tbuf = {};
    call(u8bMap, tbuf, 1UL << 20);
    u8 ttype = 0;
    if (KEEPGetExact(k, tree_sha, tbuf, &ttype) != OK ||
        ttype != KEEP_OBJ_TREE) {
        u8bUnMap(tbuf);
        done;
    }
    u8cs tree_body = {u8bDataHead(tbuf), u8bIdleHead(tbuf)};
    u8cs walk = {tree_body[0], tree_body[1]};
    u8cs file = {}, sha = {};
    while (GITu8sDrainTree(walk, file, sha, NULL) == OK) {
        if ($len(sha) != 20) continue;
        u8 mode_buf[8] = {};
        size_t mlen = 0;
        while (mlen < 7 && mlen < $len(file) && file[0][mlen] != ' ') {
            mode_buf[mlen] = file[0][mlen];
            mlen++;
        }
        b8 is_tree = (mlen >= 5 && mode_buf[0] == '4' &&
                      mode_buf[1] == '0');
        b8 is_submodule = (mlen >= 6 && mode_buf[0] == '1' &&
                           mode_buf[1] == '6' && mode_buf[2] == '0');
        if (is_submodule) continue;
        sha1 entry_sha = {};
        sha1FromBin(&entry_sha, sha);
        if (is_tree) {
            keep_walk_tree(k, &entry_sha, out, n, cap);
        } else {
            if (*n >= cap) break;
            out[(*n)++] = entry_sha;
        }
    }
    u8bUnMap(tbuf);
    done;
}

// Collect commit + tree + blob SHAs reachable from `new_hex`.  Does not
// follow parents (remote already has those).  Writes SHAs to `out[0..*n]`.
static ok64 keep_walk_commit(keeper *k, u8csc new_hex,
                             sha1 *out, u32 *n, u32 cap) {
    sane(k && out && n && $len(new_hex) == 40);
    *n = 0;
    sha1 commit_sha = {};
    {
        a_raw(bin, commit_sha);
        u8cs hex40 = {new_hex[0], new_hex[0] + 40};
        if (HEXu8sDrainSome(bin, hex40) != OK) return KEEPFAIL;
    }
    if (*n >= cap) return KEEPFAIL;
    out[(*n)++] = commit_sha;

    Bu8 cbuf = {};
    call(u8bMap, cbuf, 1UL << 20);
    u8 ctype = 0;
    if (KEEPGetExact(k, &commit_sha, cbuf, &ctype) != OK ||
        ctype != KEEP_OBJ_COMMIT) {
        u8bUnMap(cbuf);
        return KEEPFAIL;
    }
    u8cs commit_body = {u8bDataHead(cbuf), u8bIdleHead(cbuf)};
    sha1 tree_sha = {};
    if (GITu8sCommitTree(commit_body, tree_sha.data) != OK) {
        u8bUnMap(cbuf);
        return KEEPFAIL;
    }
    u8bUnMap(cbuf);

    return keep_walk_tree(k, &tree_sha, out, n, cap);
}

ok64 KEEPPush(keeper *k, u8csc host, u8csc path, char const *ref,
              u8csc old_hex, u8csc new_hex, u8csc commit_body) {
    sane(k && ref && $len(host) > 0 && $len(path) > 0 &&
         $len(old_hex) == 40 && $len(new_hex) == 40);
    (void)commit_body;  // walker re-fetches from store; body arg kept for ABI

    fprintf(stderr, "keeper: connecting: ssh %.*s git-receive-pack %.*s\n",
            (int)$len(host), (char *)host[0],
            (int)$len(path), (char *)path[0]);

    a_cstr(ssh_path, "/usr/bin/ssh");
    u8cs argv_arr[4] = {
        u8slit("ssh"),
        {host[0], host[1]},
        u8slit("git-receive-pack"),
        {path[0], path[1]},
    };
    u8css argv = {argv_arr, argv_arr + 4};

    pid_t pid = 0;
    int wfd = -1, rfd = -1;
    if (FILESpawn(ssh_path, argv, &wfd, &rfd, &pid) != OK) return KEEPFAIL;

    Bu8 rbuf_b = {};
    Bu8 pack_b = {};
    ok64 rv = KEEPFAIL;
    if (u8bMap(rbuf_b, 1UL << 20) != OK) goto push_fail;

    // Drain the ref advertisement until flush.  We do not need to parse
    // it; the caller provided old_hex authoritatively.
    {
        u8cp start = u8bDataHead(rbuf_b);
        u8cs adv = {start, start};
        u8cs line = {};
        for (;;) {
            ok64 o = keep_sync_drain_pkt(rfd, rbuf_b, adv, line);
            if (o == PKTFLUSH) break;
            if (o != OK) goto push_fail;
        }
    }

    // Send update command: "<old> <new> <ref>\0report-status\n" then flush.
    {
        a_pad(u8, payload, 1024);
        u8bPrintf(payload, "%.40s %.40s %s",
                  old_hex[0], new_hex[0], ref);
        u8bFeed1(payload, 0);
        a_cstr(caps, "report-status");
        u8bFeed(payload, caps);
        u8bFeed1(payload, '\n');

        a_pad(u8, pktbuf, 1200);
        u8s ps = {u8bIdleHead(pktbuf), u8bIdleHead(pktbuf) + 1200};
        if (PKTu8sFeed(ps, u8bDataC(payload)) != OK) goto push_fail;
        if (PKTu8sFeedFlush(ps) != OK) goto push_fail;
        u8csc written = {u8bDataHead(pktbuf), ps[0]};
        if (keep_push_write_all(wfd, written) != OK) goto push_fail;
    }

    // Walk the reachable set from new_hex (commit + all trees + blobs).
    // Ignores parents (remote already has those) and submodule gitlinks.
    #define PUSH_MAX_OBJS 65536
    sha1 *walk_shas = calloc(PUSH_MAX_OBJS, sizeof(sha1));
    if (!walk_shas) goto push_fail;
    u32 nobjs = 0;
    if (keep_walk_commit(k, new_hex, walk_shas, &nobjs, PUSH_MAX_OBJS)
            != OK || nobjs == 0) {
        free(walk_shas);
        goto push_fail;
    }

    // Build an N-object packfile (all fetched inline, one at a time).
    {
        // Generous upper bound: 64B header + 256B trailer + per-object
        // ~32 bytes header + deflated size (<= raw size + small slack).
        u64 est = 256;
        // Probe sizes quickly via KEEPGetExact on the first few objects
        // to avoid mapping 1 GB for a tiny push; fall back to 8 MB/obj.
        Bu8 tmp = {};
        call(u8bMap, tmp, 1UL << 20);
        for (u32 i = 0; i < nobjs; i++) {
            u8bReset(tmp);
            u8 ot = 0;
            if (KEEPGetExact(k, &walk_shas[i], tmp, &ot) == OK)
                est += u8bDataLen(tmp) + 64;
            else
                est += 8UL << 20;
        }
        u8bUnMap(tmp);

        if (u8bAllocate(pack_b, est + 4096) != OK) {
            free(walk_shas);
            goto push_fail;
        }

        // PACK header: magic + version 2 + nobjs
        u8 hdr_bytes[12] = {'P','A','C','K', 0,0,0,2, 0,0,0,0};
        hdr_bytes[8]  = (u8)((nobjs >> 24) & 0xff);
        hdr_bytes[9]  = (u8)((nobjs >> 16) & 0xff);
        hdr_bytes[10] = (u8)((nobjs >> 8)  & 0xff);
        hdr_bytes[11] = (u8)(nobjs & 0xff);
        u8csc hdr_s = {hdr_bytes, hdr_bytes + 12};
        u8bFeed(pack_b, hdr_s);

        // Each object: varint header (type+size) + deflated body.
        for (u32 i = 0; i < nobjs; i++) {
            Bu8 obuf = {};
            if (u8bMap(obuf, 1UL << 24) != OK) {
                free(walk_shas);
                goto push_fail;
            }
            u8 otype = 0;
            if (KEEPGetExact(k, &walk_shas[i], obuf, &otype) != OK) {
                u8bUnMap(obuf);
                free(walk_shas);
                goto push_fail;
            }
            u64 olen = u8bDataLen(obuf);

            a_pad(u8, ohdr, 16);
            keep_feed_obj_hdr(ohdr, otype, olen);
            a_dup(u8c, oh, u8bData(ohdr));
            u8bFeed(pack_b, oh);

            a_dup(u8c, osrc, u8bData(obuf));
            ok64 zo = ZINFDeflate(u8bIdle(pack_b), osrc);
            u8bUnMap(obuf);
            if (zo != OK) {
                free(walk_shas);
                goto push_fail;
            }
        }

        free(walk_shas);

        // 20-byte SHA-1 trailer over everything so far
        sha1 psha = {};
        a_dup(u8c, pack_data, u8bData(pack_b));
        SHA1Sum(&psha, pack_data);
        u8csc psha_s = {psha.data, psha.data + 20};
        u8bFeed(pack_b, psha_s);

        a_dup(u8c, send, u8bData(pack_b));
        if (keep_push_write_all(wfd, send) != OK) goto push_fail;
    }

    close(wfd); wfd = -1;

    // Read status response until flush; look for "unpack ok" + "ok <ref>".
    b8 unpack_ok = NO, ref_ok = NO;
    u8bReset(rbuf_b);
    {
        u8cp start = u8bDataHead(rbuf_b);
        u8cs adv = {start, start};
        u8cs line = {};
        for (;;) {
            ok64 o = keep_sync_drain_pkt(rfd, rbuf_b, adv, line);
            if (o == PKTFLUSH) break;
            if (o != OK) break;
            if (u8csHasPrefix(line, GIT_PKT_UNPACK_OK))   unpack_ok = YES;
            else if (u8csHasPrefix(line, GIT_PKT_OK_PFX)) ref_ok    = YES;
            else if (u8csHasPrefix(line, GIT_PKT_NG_PFX))
                fprintf(stderr, "keeper: push rejected: %.*s",
                        (int)u8csLen(line), (char *)line[0]);
        }
    }

    close(rfd); rfd = -1;
    { int rc = 0; FILEReap(pid, &rc); }

    if (unpack_ok && ref_ok) {
        rv = OK;
    } else {
        fprintf(stderr, "keeper: push failed (unpack_ok=%d ref_ok=%d)\n",
                unpack_ok, ref_ok);
    }
    if (pack_b[0]) u8bFree(pack_b);
    u8bUnMap(rbuf_b);
    return rv;

push_fail:
    if (pack_b[0]) u8bFree(pack_b);
    if (rbuf_b[0]) u8bUnMap(rbuf_b);
    if (wfd >= 0) close(wfd);
    if (rfd >= 0) close(rfd);
    { int rc = 0; FILEReap(pid, &rc); }
    return KEEPFAIL;
}

// =====================================================================
//  KEEPEachTip — list every local branch's tip (path, sha).
// =====================================================================

typedef struct {
    KEEPTipCb cb;
    void     *ctx;
} keep_tip_walk;

static ok64 keep_tip_filter(refcp r, void *ctx_) {
    keep_tip_walk *w = (keep_tip_walk *)ctx_;

    //  Local-branch keys are exactly `?<path>` — no scheme, no
    //  authority.  Anything else (`//host?ref`, `ssh://…`) is a
    //  remote-tracking row or a host alias.
    a_dup(u8c, k, r->key);
    if (u8csEmpty(k) || *k[0] != '?') return OK;
    u8csUsed1(k);   //  strip leading '?'

    //  Value slot is the fragment bytes (sha hex).  Older / current
    //  REFSLoad emits the bare 40 hex chars; tolerate a stray leading
    //  `?` for forward-compatibility with raw-fragment writers.
    a_dup(u8c, v, r->val);
    if (u8csEmpty(v)) return OK;
    if (*v[0] == '?') u8csUsed1(v);
    if (u8csLen(v) != 40) return OK;
    b8 tomb = YES;
    $for(u8c, p, v) if (*p != '0') { tomb = NO; break; }
    if (tomb) return OK;

    keep_tip t = {};
    u8csMv(t.path, k);
    u8csMv(t.sha,  v);
    return w->cb(&t, w->ctx);
}

ok64 KEEPEachTip(keeper *k, KEEPTipCb cb, void *ctx) {
    sane(k && cb);
    a_path(keepdir, u8bDataC(k->h->root), KEEP_DIR_S);
    keep_tip_walk w = {.cb = cb, .ctx = ctx};
    return REFSEach($path(keepdir), keep_tip_filter, &w);
}

// =====================================================================
//  KEEPEachRemote — list every remote-tracking ref (key, sha).
//
//  REFS rows survive dedup separately per (URI, verb), so a single
//  remote URL fetched via `get` and pushed via `post` produces two
//  surviving rows.  For display callers want one entry per URL —
//  the latest write across verbs.  We walk REFSEach in arrival
//  order (latest-first within each verb-bucket) and use a seen-URL
//  buffer to skip URL repeats; the first occurrence wins.
// =====================================================================

typedef struct {
    KEEPRemoteCb cb;
    void        *ctx;
    Bu8         *seen;   //  newline-separated URLs already emitted
} keep_remote_walk;

static b8 keep_remote_seen(Bu8 *seen, u8csc url) {
    a_dup(u8c, scan, u8bDataC(*seen));
    while (!u8csEmpty(scan)) {
        u8cs line = {};
        if (u8csDrainLine(scan, line) != OK) break;
        if (u8csEq(line, url)) return YES;
    }
    return NO;
}

static ok64 keep_remote_filter(refcp r, void *ctx_) {
    keep_remote_walk *w = (keep_remote_walk *)ctx_;

    //  Local-branch keys start with `?` (no scheme, no authority).
    //  Remote-tracking keys carry scheme or authority bytes.
    a_dup(u8c, k, r->key);
    if (u8csEmpty(k) || *k[0] == '?') return OK;

    a_dup(u8c, v, r->val);
    if (u8csEmpty(v)) return OK;
    if (*v[0] == '?') v[0]++;
    if (u8csLen(v) != 40) return OK;
    b8 tomb = YES;
    $for(u8c, p, v) if (*p != '0') { tomb = NO; break; }
    if (tomb) return OK;

    if (keep_remote_seen(w->seen, k)) return OK;
    u8bFeed (*w->seen, k);
    u8bFeed1(*w->seen, '\n');

    keep_remote rem = {};
    u8csMv(rem.key, k);
    u8csMv(rem.sha, v);
    return w->cb(&rem, w->ctx);
}

ok64 KEEPEachRemote(keeper *k, KEEPRemoteCb cb, void *ctx) {
    sane(k && cb);
    a_path(keepdir, u8bDataC(k->h->root), KEEP_DIR_S);
    Bu8 seen = {};
    call(u8bAllocate, seen, 1UL << 14);     //  16K seen-URL set
    keep_remote_walk w = {.cb = cb, .ctx = ctx, .seen = &seen};
    ok64 rc = REFSEach($path(keepdir), keep_remote_filter, &w);
    u8bFree(seen);
    return rc;
}
