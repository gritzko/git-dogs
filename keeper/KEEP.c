//  KEEP: local git object store.
//
//  Stores git packfiles under .dogs/ (trunk-flat) indexed by u64→w64
//  in LSM sorted runs of wh128 entries.
//
#include "KEEP.h"
#include "REFS.h"

#include "DELT.h"
#include "PACK.h"
#include "SHA1.h"
#include "ZINF.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

//  Indexer fan-out hook — see UNPK.h.  A CLI that wants spot/graf to
//  track every object keeper writes installs these before performing
//  any fetch/post; KEEPIngestFile (via UNPKIndex) and KEEPPackFeed
//  both call through them.
unpk_emit_fn keep_indexer_emit = NULL;
void        *keep_indexer_ctx  = NULL;

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

// Build <h->root>/.dogs/ into `out`.  The worktree root has
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

//  Parse the leading KEEP_SEQNO_W hex chars of a filename into a u32.
//  Returns 0 on bad input — files we wrote always have valid hex
//  prefixes since keep_leaf_name produces them.
static u32 keep_parse_seqno(char const *name) {
    u32 v = 0;
    for (u32 i = 0; i < KEEP_SEQNO_W; i++) {
        u8 c = (u8)name[i];
        u32 d;
        if      (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return 0;
        v = (v << 4) | d;
    }
    return v;
}

// --- Scan helper: find and mmap files matching extension ---
//
// `seqnos` is optional: when non-NULL, parsed seqnos are appended in
// the same order as `maps` so callers can correlate run i with the
// `<seqno>.idx` filename it came from without re-listing the dir.
static ok64 keep_scan_dir(u8csc dir, char const *ext,
                          u8bp *maps, u32 *count, u32 max,
                          u32 *seqnos) {
    a_path(dpat);
    PATHu8bFeed(dpat, dir);
    DIR *dp = opendir((char *)u8bDataHead(dpat));
    if (!dp) return OK;  // dir doesn't exist yet

    size_t extlen = strlen(ext);
    char names[KEEP_MAX_FILES][64];
    u32 nfound = 0;
    struct dirent *e;
    while ((e = readdir(dp)) != NULL && nfound < max) {
        size_t nlen = strlen(e->d_name);
        if (nlen <= extlen || nlen > 63) continue;
        if (strcmp(e->d_name + nlen - extlen, ext) != 0) continue;
        memcpy(names[nfound], e->d_name, nlen + 1);
        nfound++;
    }
    closedir(dp);

    // Sort by name
    for (u32 i = 0; i + 1 < nfound; i++)
        for (u32 j = i + 1; j < nfound; j++)
            if (strcmp(names[i], names[j]) > 0) {
                char tmp[64];
                memcpy(tmp, names[i], 64);
                memcpy(names[i], names[j], 64);
                memcpy(names[j], tmp, 64);
            }

    for (u32 i = 0; i < nfound && *count < max; i++) {
        u8cs fn = {(u8cp)names[i], (u8cp)names[i] + strlen(names[i])};
        a_path(fpath, dir, fn);
        u8bp mapped = NULL;
        if (FILEMapRO(&mapped, $path(fpath)) == OK) {
            maps[*count] = mapped;
            if (seqnos) seqnos[*count] = keep_parse_seqno(names[i]);
            (*count)++;
        }
    }
    return OK;
}

static ok64 keep_scan_packs(keeper *k, u8csc keepdir) {
    sane(k);
    //  Lockless-reader invariant: scan idx BEFORE packs.  Writer
    //  publishes bytes-first then idx: any idx entry observed here
    //  points into a pack file that existed before we listed packs,
    //  so the referenced pack is guaranteed to be in k->shards[0].packs[].
    //  Scanning packs first would race: a pack created between the
    //  two scans would bring in idx entries referencing packs not in
    //  our mapping.

    u8bp idx_maps[KEEP_MAX_LEVELS] = {};
    u32  idx_seqnos[KEEP_MAX_LEVELS] = {};
    u32 nidx = 0;
    keep_scan_dir(keepdir, KEEP_IDX_EXT, idx_maps, &nidx, KEEP_MAX_LEVELS,
                  idx_seqnos);
    keep_scan_dir(keepdir, KEEP_PACK_EXT,
                  k->shards[0].packs, &k->shards[0].npacks, KEEP_MAX_FILES,
                  NULL);

    for (u32 i = 0; i < nidx && k->shards[0].nruns < KEEP_MAX_LEVELS; i++) {
        wh128cp base = (wh128cp)u8bDataHead(idx_maps[i]);
        u32 n = (u32)(u8bDataLen(idx_maps[i]) / sizeof(wh128));
        k->shards[0].runs[k->shards[0].nruns][0] = base;
        k->shards[0].runs[k->shards[0].nruns][1] = base + n;
        k->shards[0].run_maps[k->shards[0].nruns] = idx_maps[i];
        u32 sq = idx_seqnos[i];
        call(u32bPush, k->shards[0].run_seqnos, &sq);
        k->shards[0].nruns++;
    }
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

ok64 KEEPOpenBranch(home *h, u8cs branch, b8 rw) {
    sane(h != NULL && $ok(branch));

    // Phase 0 only accepts the trunk branch.  Canonical form = empty.
    a_pad(u8, nb, 256);
    call(DPATHBranchNormFeed, nb, branch);
    if (u8bDataLen(nb) != 0) return KEEPNOBR;

    // Register on the process-wide home singleton.  Idempotent — a
    // compatible re-open is silently absorbed so subsequent
    // DOGUpdate() calls can always read HOMEWriteBranch() as slot 0.
    ok64 o = HOMEOpenBranch(h, branch, rw);
    if (o != OK && o != HOMEOPEN) return o;

    return KEEPOpen(h, rw);
}

ok64 KEEPOpen(home *h, b8 rw) {
    sane(h);

    //  Already open?  Compatible if the existing mode is at least as
    //  strong as the request.  The only true conflict is an rw request
    //  against a ro-open keeper — invalidates live pointers if we
    //  reopened, so caller must reshuffle their scope.
    if (keep_is_open()) {
        if (rw && !keep_is_rw) return KEEPOPENRO;
        return KEEPOPEN;
    }

    keeper *k = &KEEP;
    zerop(k);
    k->h = h;
    //  Phase 1b: one trunk shard rooted at .dogs/ (flat layout).
    //  Shard branch slice stays empty (trunk) until Phase 1c+ introduces
    //  feature-branch subdirs.
    k->nshards = 1;
    k->shards[0].lock_fd = -1;
    call(u32bAllocate, k->shards[0].run_seqnos, KEEP_MAX_LEVELS);
    keep_is_rw = rw;

    a_path(dir);
    call(keep_resolve_dir, dir, h);
    a_path(keepdir, u8bDataC(k->h->root), KEEP_DIR_S);

    // Phase 1b flat layout: packs and indexes live directly in the
    // keeper dir; no log/ or idx/ subdirs to create.
    call(FILEMakeDirP, $path(dir));

    // Worktree sharing: `.dogs/` is the store root; two processes can
    // race on the pack store if they both open rw on the same repo.
    // flock on `.dogs/.lock` serializes writers only.
    // Readers open lockless — the idx-before-packs scan order in
    // keep_scan_packs plus idx-via-rename publication in
    // KEEPPackClose give a consistent snapshot without any lock,
    // so a reader never has to wait for a slow writer (e.g. a
    // remote-replica import holding LOCK_EX for minutes).
    if (rw) {
        a_pad(u8, lockpath, 1024);
        u8bFeed(lockpath, $path(keepdir));
        a_cstr(lockrel, "/.lock");
        u8bFeed(lockpath, lockrel);
        PATHu8bTerm(lockpath);
        call(FILECreate, &k->shards[0].lock_fd, $path(lockpath));
        call(FILELock, &k->shards[0].lock_fd, rw);
    }

    // Scan pack + idx files living directly in <keepdir>.  Pre-Phase-1b
    // stores under log/ + idx/ subdirs need `keeper migrate` first.
    call(keep_scan_packs, k, $path(keepdir));

    // Pre-allocate working buffers for KEEPGet (mmap, reset per call)
    call(u8bMap, k->buf1, KEEP_BUFSZ);
    call(u8bMap, k->buf2, KEEP_BUFSZ);
    call(u8bMap, k->buf3, KEEP_BUFSZ);
    call(u8bMap, k->buf4, KEEP_BUFSZ);

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
// Mirrors spot's CAPOCompact / graf's dag_compact, using HITwh128 as
// the merge primitive.  Drains the merged content into a fresh
// `<seqno>.idx` (atomic tmp→rename), unlinks the consumed source
// files (identified by the parallel `run_seqnos` Bu32, no rescan),
// swaps their mmaps for the new one in `shard.run_maps[]`.  No-op
// when the stack already satisfies the 1/8 invariant.
ok64 KEEPCompact(keeper *k) {
    sane(k);
    if (!keep_is_rw) done;
    keeper_shard *sh = &k->shards[0];
    if (sh->nruns < 2) done;

    wh128css stack = {sh->runs, sh->runs + sh->nruns};
    if (HITwh128IsCompact(stack)) done;

    size_t total = 0;
    for (u32 i = 0; i < sh->nruns; i++)
        total += (size_t)(sh->runs[i][1] - sh->runs[i][0]);

    Bwh128 cbuf = {};
    call(wh128bAllocate, cbuf, total);

    wh128 *base = cbuf[0];
    wh128s into = {cbuf[0], cbuf[3]};
    u32 before_n = sh->nruns;
    call(HITwh128Compact, stack, into);
    u32 after_n = (u32)$len(stack);
    u32 m = before_n - after_n + 1;
    if (m < 2) {
        wh128bFree(cbuf);
        done;
    }

    //  New seqno: 1 + max existing run seqno.  Don't reuse a value
    //  still on disk even if we're about to unlink it, since live
    //  readers may hold an open mapping under that inode.
    u32 new_seqno = 1;
    {
        u32cp sb = (u32cp)sh->run_seqnos[1];
        u32cp se = (u32cp)sh->run_seqnos[2];
        for (u32cp p = sb; p < se; p++)
            if (*p >= new_seqno) new_seqno = *p + 1;
    }

    a_path(kdir, u8bDataC(k->h->root), KEEP_DIR_S);

    //  Write merged run atomically (tmp → rename).
    a_pad(u8, idxpath, FILE_PATH_MAX_LEN);
    call(keep_idx_path, idxpath, $path(kdir), new_seqno);
    a_pad(u8, idxtmppath, FILE_PATH_MAX_LEN);
    call(u8bFeed, idxtmppath, u8bDataC(idxpath));
    a_cstr(tmpsuf, ".tmp");
    call(u8bFeed, idxtmppath, tmpsuf);
    call(PATHu8bTerm, idxtmppath);

    {
        int ifd = -1;
        call(FILECreate, &ifd, $path(idxtmppath));
        u8cs raw = {(u8cp)base, (u8cp)(into[0])};
        call(FILEFeedAll, ifd, raw);
        close(ifd);
        call(FILERename, $path(idxtmppath), $path(idxpath));
    }
    wh128bFree(cbuf);

    //  mmap the new file RO and swap in.
    u8bp idx_map = NULL;
    call(FILEMapRO, &idx_map, $path(idxpath));
    wh128cp newbase = (wh128cp)u8bDataHead(idx_map);
    u32 newlen = (u32)(u8bDataLen(idx_map) / sizeof(wh128));

    //  Unmap the old m runs and unlink their .idx files (seqnos
    //  recorded at scan / append time — no directory rescan).
    u32cp seq_base = (u32cp)sh->run_seqnos[1];
    for (u32 i = before_n - m; i < before_n; i++) {
        if (sh->run_maps[i]) FILEUnMap(sh->run_maps[i]);
        u32 sq = seq_base[i];
        a_pad(u8, ulpath, FILE_PATH_MAX_LEN);
        keep_idx_path(ulpath, $path(kdir), sq);
        unlink((char *)u8bDataHead(ulpath));
    }

    //  Splice: position (before_n - m) carries the new merged run.
    u32 slot = before_n - m;
    sh->runs[slot][0] = newbase;
    sh->runs[slot][1] = newbase + newlen;
    sh->run_maps[slot] = idx_map;
    for (u32 i = slot + 1; i < before_n; i++) {
        memset(sh->runs[i], 0, sizeof(sh->runs[i]));
        sh->run_maps[i] = NULL;
    }
    sh->nruns = slot + 1;

    //  Trim the parallel seqnos buffer: replace the tail-m entries
    //  with the single new seqno.
    sh->run_seqnos[1][slot] = new_seqno;
    sh->run_seqnos[2] = sh->run_seqnos[1] + slot + 1;
    done;
}

ok64 KEEPClose(void) {
    sane(1);
    if (!keep_is_open()) return OK;
    keeper *k = &KEEP;
    if (keep_is_rw) (void)KEEPCompact(k);
    for (u32 i = 0; i < k->shards[0].npacks; i++)
        if (k->shards[0].packs[i]) FILEUnMap(k->shards[0].packs[i]);
    for (u32 i = 0; i < k->shards[0].nruns; i++)
        if (k->shards[0].run_maps[i]) FILEUnMap(k->shards[0].run_maps[i]);
    if (k->buf1[0]) u8bUnMap(k->buf1);
    if (k->buf2[0]) u8bUnMap(k->buf2);
    if (k->buf3[0]) u8bUnMap(k->buf3);
    if (k->buf4[0]) u8bUnMap(k->buf4);
    if (!BNULL(k->shards[0].run_seqnos)) u32bFree(k->shards[0].run_seqnos);
    if (k->shards[0].lock_fd >= 0) FILEClose(&k->shards[0].lock_fd);
    zerop(k);
    keep_is_rw = NO;
    done;
}

// --- Delta-dependency DAG: shard ancestry ---
//
// A pack written into shard `dst_idx` may emit a REF_DELTA whose base
// resolves in shard `src_idx` only when src is an ancestor of dst (or
// the same shard).  "Ancestor" in canonical-form branch paths is a
// byte-level prefix: trunk ("") is an ancestor of every branch;
// "feature/" is an ancestor of "feature/fix1/" but not of "other/".
// KEEPPackFeed's REF_DELTA path consults this before emitting; a
// non-ancestor base triggers a silent fall-through to raw encoding.
// Phase 1c keeps nshards=1 so the check trivially passes; the wiring
// lights up once Phase 2 opens sibling shards.
static b8 keep_shard_visible(keeper const *k, u32 dst_idx, u32 src_idx) {
    if (dst_idx >= k->nshards || src_idx >= k->nshards) return NO;
    u8cs src = {k->shards[src_idx].branch[0], k->shards[src_idx].branch[1]};
    u8cs dst = {k->shards[dst_idx].branch[0], k->shards[dst_idx].branch[1]};
    return DPATHBranchAncestor(src, dst);
}

// --- Drop-a-dir: Phase 1c API ---

ok64 KEEPBranchDrop(keeper *k, u8cs branch) {
    sane(k && $ok(branch));

    a_pad(u8, nb, 256);
    call(DPATHBranchNormFeed, nb, branch);

    //  Trunk is never droppable — store root plus paths registry plus
    //  the root-level `refs` (which carries host aliases) live there.
    if (u8bDataLen(nb) == 0) return KEEPTRUNK;

    //  Phase 1c hard-caps nshards to 1 (trunk).  Non-trunk branches
    //  don't exist yet on disk or in the open-shard stack, so the
    //  drop is a no-op that reports KEEPNOBR.  Phase 2+ fills in:
    //    * rmdir subtree under .dogs/<branch>/
    //    * refuse if any open shard names a descendant (REF_DELTA
    //      bases would dangle) — return KEEPDIRTY
    //    * refuse if stage.sniff / WT marker still present
    return KEEPNOBR;
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

    for (u32 r = 0; r < k->shards[0].nruns; r++) {
        wh128cp base = k->shards[0].runs[r][0];
        size_t len = (size_t)(k->shards[0].runs[r][1] - base);
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

    if (file_id < 1 || file_id > k->shards[0].npacks) return KEEPNONE;
    u8bp pack_map = k->shards[0].packs[file_id - 1];
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
                // Cross-file: get base recursively, apply delta chain
                u8bReset(k->buf3);
                u8 btype = 0;
                rc = KEEPGet(k, base_hashlet, 15, k->buf3, &btype);
                if (rc != OK) goto cleanup;
                obj_type = btype;
                // buf3 has the base content; copy to buf1
                a_dup(u8c, bdata, u8bData(k->buf3));
                memcpy(buf1, bdata[0], u8csLen(bdata));
                result = buf1;
                outsz = u8csLen(bdata);
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

    // Copy result into caller's output buffer
    {
        u8cs content = {result, result + outsz};
        rc = u8bFeed(out, content);
    }

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

    for (u32 r = 0; r < k->shards[0].nruns; r++) {
        wh128cp base = k->shards[0].runs[r][0];
        size_t len = (size_t)(k->shards[0].runs[r][1] - base);
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
            if (sha1eq(&actual, sha)) {
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
    u8cp content = u8bDataHead(obj);
    u64 content_sz = u8bDataLen(obj);

    static char const *type_names[] = {
        [1] = "commit", [2] = "tree", [3] = "blob", [4] = "tag"};
    if (obj_type < 1 || obj_type > 4) {
        fprintf(stderr, "  BAD TYPE: %u\n", obj_type);
        (*failed)++;
        u8bUnMap(obj);
        return KEEPFAIL;
    }

    char hdr[64];
    int hlen = snprintf(hdr, sizeof(hdr), "%s %lu",
                        type_names[obj_type], (unsigned long)content_sz);
    u8p tmp = malloc((size_t)(hlen + 1 + content_sz));
    if (!tmp) { u8bUnMap(obj); return KEEPNOROOM; }
    memcpy(tmp, hdr, hlen);
    tmp[hlen] = 0;
    memcpy(tmp + hlen + 1, content, content_sz);

    sha1 actual_sha = {};
    { u8csc _d = {tmp, tmp + hlen + 1 + content_sz}; SHA1Sum(&actual_sha, _d); };
    free(tmp);

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
        u8cs body = {content, content + content_sz};
        u8cs field = {}, value = {};
        while (GITu8sDrainCommit(body, field, value) == OK) {
            if ($empty(field)) break;
            if ($len(field) == 4 && memcmp(field[0], "tree", 4) == 0 &&
                $len(value) >= 40) {
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
        u8cs body = {content, content + content_sz};
        while (!$empty(body)) {
            u8cs entry_field = {}, entry_sha = {};
            ok64 o = GITu8sDrainTree(body, entry_field, entry_sha);
            if (o != OK) break;
            if ($len(entry_sha) != 20) continue;
            // Skip gitlinks (submodule refs) — mode 160000, commit in another repo
            if ($len(entry_field) > 6 && memcmp(entry_field[0], "160000", 6) == 0)
                continue;
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
            memcpy(child_sha.data, entry_sha[0], 20);
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
        u8cs body = {content, content + content_sz};
        u8cs field = {}, value = {};
        while (GITu8sDrainCommit(body, field, value) == OK) {
            if ($empty(field)) break;
            if ($len(field) == 6 && memcmp(field[0], "object", 6) == 0 &&
                $len(value) >= 40) {
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

    if (file_id < 1 || file_id > k->shards[0].npacks) return KEEPNONE;
    u8cp pack = u8bDataHead(k->shards[0].packs[file_id - 1]);
    u64 packlen = (u64)(u8bIdleHead(k->shards[0].packs[file_id - 1]) - pack);

    // Skip PACK header if at start
    if (offset == 0 && packlen >= 12) {
        if (memcmp(pack, "PACK", 4) == 0)
            offset = 12;  // skip PACK + version + count
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
static ok64 keep_hex_pad(u8b out, u32 val, u32 width) {
    sane(u8bOK(out));
    test(width <= 8, KEEPFAIL);  // u32 fits in 8 hex chars
    a_cstr(digits, "0123456789abcdef");
    for (int i = (int)width - 1; i >= 0; i--) {
        call(u8bFeed1, out, digits[0][(val >> (i * 4)) & 0xf]);
    }
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
//  `kdir` is the `.dogs` prefix (absolute or relative, no trailing
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

con char *keep_type_names[] = {
    [DOG_OBJ_COMMIT] = "commit",
    [DOG_OBJ_TREE] = "tree",
    [DOG_OBJ_BLOB] = "blob",
    [DOG_OBJ_TAG] = "tag",
};

// Compute git object SHA-1: SHA1("type size\0" + content)
void KEEPObjSha(sha1 *out, u8 type, u8csc content) {
    a_pad(u8, hdr, 64);
    a_cstr(tname, keep_type_names[type]);
    u8bFeed(hdr, tname);
    u8bFeed1(hdr, ' ');
    char tmp[32];
    int nlen = snprintf(tmp, sizeof(tmp), "%llu",
                        (unsigned long long)u8csLen(content));
    u8cs ns = {(u8cp)tmp, (u8cp)tmp + nlen};
    u8bFeed(hdr, ns);
    u8bFeed1(hdr, 0);

    SHA1state ctx;
    SHA1Open(&ctx);
    a_dup(u8c, hdata, u8bData(hdr));
    SHA1Feed(&ctx, hdata);
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
    b8 appending = (k->shards[0].npacks > 0);
    p->file_id = appending ? k->shards[0].npacks : 1;

    call(wh128bAllocate, p->entries, KEEP_PACK_MAX_OBJS);
    call(u8bMap, p->delta_base,  KEEP_BUFSZ);
    call(u8bMap, p->delta_instr, KEEP_BUFSZ);

    // Build path: <kdir>/NNNNNNNNNN.keeper (Phase 1b flat layout).
    a_path(kdir, u8bDataC(k->h->root), KEEP_DIR_S);

    a_pad(u8, packpath, FILE_PATH_MAX_LEN);
    call(keep_pack_path, packpath, $path(kdir), p->file_id);

    if (appending) {
        //  Existing tail file is mapped read-only in k->shards[0].packs[];
        //  replace that mapping with a FILEBook (writable mmap with
        //  extendable file) so concurrent reads of already-written
        //  objects still work while this pack is being appended.
        if (k->shards[0].packs[p->file_id - 1]) {
            FILEUnMap(k->shards[0].packs[p->file_id - 1]);
            k->shards[0].packs[p->file_id - 1] = NULL;
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
        k->shards[0].packs[p->file_id - 1] = p->log;
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
        //  which walks k->shards[0].runs and resolves delta chains internally.
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
            if (KEEPGet(k, base_hashlet60, 15, p->delta_base,
                        &base_type) != OK) {
                u8bReset(p->delta_base);
            } else {
                //  DAG invariant: REF_DELTA bases must live in the
                //  write shard or one of its ancestors.  Phase 1c
                //  nshards=1 always resolves to shard 0 (trunk), so
                //  this check trivially passes; it becomes real once
                //  Phase 2 opens sibling shards and KEEPGet reports
                //  which shard served the hit.
                u32 base_shard = 0;
                if (!keep_shard_visible(k, p->shard_idx, base_shard)) {
                    u8bReset(p->delta_base);
                }
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

    //  Indexer fan-out: same hook UNPKIndex uses on the fetch path.
    if (keep_indexer_emit)
        keep_indexer_emit(keep_indexer_ctx, type, sha_out, content);

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
    a_path(kdir, u8bDataC(k->h->root), KEEP_DIR_S);
    a_pad(u8, packpath, FILE_PATH_MAX_LEN);
    call(keep_pack_path, packpath, $path(kdir), p->file_id);

    FILEUnBook(p->log);
    p->log = NULL;

    u8bp ro = NULL;
    call(FILEMapRO, &ro, $path(packpath));
    if (p->file_id > k->shards[0].npacks) {
        //  New file_id — append to k->shards[0].packs[].
        test(k->shards[0].npacks < KEEP_MAX_FILES, KEEPNOROOM);
        k->shards[0].packs[k->shards[0].npacks] = ro;
        k->shards[0].npacks++;
    } else {
        //  Appended into an existing file — replace its slot.
        k->shards[0].packs[p->file_id - 1] = ro;
    }

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

    // Sort index entries, write .idx file
    a_dup(wh128, sorted, wh128bData(p->entries));
    wh128sSort(sorted);

    //  Index seqno: 1 + max existing run seqno (gaps from prior
    //  compactions are fine — we never reuse a value that's still
    //  on disk, even if it's been unlinked, since live readers may
    //  hold a mapping under the old inode).
    u32 idx_seq = 1;
    {
        u32cp sb = (u32cp)k->shards[0].run_seqnos[1];
        u32cp se = (u32cp)k->shards[0].run_seqnos[2];
        for (u32cp p = sb; p < se; p++) if (*p >= idx_seq) idx_seq = *p + 1;
    }
    a_pad(u8, idxpath, FILE_PATH_MAX_LEN);
    call(keep_idx_path, idxpath, $path(kdir), idx_seq);

    //  Atomic publication: write to <seq>.idx.tmp then rename to
    //  <seq>.idx.  Concurrent lockless readers (keep_scan_packs,
    //  which keys on the ".idx" suffix) never observe a partially-
    //  written run — the idx appears in the directory only after
    //  the pack bytes it references are on disk.
    a_pad(u8, idxtmppath, FILE_PATH_MAX_LEN);
    call(u8bFeed, idxtmppath, u8bDataC(idxpath));
    a_cstr(tmpsuf, ".tmp");
    call(u8bFeed, idxtmppath, tmpsuf);
    call(PATHu8bTerm, idxtmppath);

    int ifd = -1;
    call(FILECreate, &ifd, $path(idxtmppath));
    if (ifd >= 0) {
        u8cs raw = {(u8cp)sorted[0], (u8cp)sorted[1]};
        FILEFeedAll(ifd, raw);
        close(ifd);
        call(FILERename, $path(idxtmppath), $path(idxpath));
    }

    // Mmap index
    u8bp imapped = NULL;
    if (FILEMapRO(&imapped, $path(idxpath)) == OK &&
        k->shards[0].nruns < KEEP_MAX_LEVELS) {
        wh128cp base = (wh128cp)u8bDataHead(imapped);
        u32 n = (u32)(u8bDataLen(imapped) / sizeof(wh128));
        k->shards[0].runs[k->shards[0].nruns][0] = base;
        k->shards[0].runs[k->shards[0].nruns][1] = base + n;
        k->shards[0].run_maps[k->shards[0].nruns] = imapped;
        call(u32bPush, k->shards[0].run_seqnos, &idx_seq);
        k->shards[0].nruns++;
    }

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
        a_dup(u8c, body, u8bData(k->buf1));
        u8cs field = {}, value = {};
        while (GITu8sDrainCommit(body, field, value) == OK) {
            if (u8csEmpty(field)) break;
            if (u8csLen(field) == 4 && memcmp(field[0], "tree", 4) == 0 &&
                u8csLen(value) >= 40) {
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
            a_dup(u8c, tbody, u8bData(k->buf1));
            u8cs tf = {}, tv = {};
            while (GITu8sDrainCommit(tbody, tf, tv) == OK) {
                if (u8csEmpty(tf)) break;
                if (u8csLen(tf) == 6 && memcmp(tf[0], "object", 6) == 0 &&
                    u8csLen(tv) >= 40) {
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

        a_dup(u8c, body, u8bData(k->buf1));
        u8cs field = {}, value = {};
        while (GITu8sDrainCommit(body, field, value) == OK) {
            if (u8csEmpty(field)) break;
            if (u8csLen(field) == 4 && memcmp(field[0], "tree", 4) == 0 &&
                u8csLen(value) >= 40) {
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
    size_t plen = u8bDataLen(idx_path_buf);
    if (plen >= 5 && memcmp(u8bDataHead(idx_path_buf) + plen - 5, ".pack", 5) == 0)
        ((u8 **)idx_path_buf)[2] -= 5;
    else {
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
    u32 file_id = k->shards[0].npacks + 1;
    a_path(kdir, u8bDataC(k->h->root), KEEP_DIR_S);
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

    a_path(kdir, u8bDataC(k->h->root), KEEP_DIR_S);
    call(FILEMakeDirP, $path(kdir));

    //  Append to existing tail log, or create the very first one.
    b8  appending = (k->shards[0].npacks > 0);
    u32 file_id = appending ? k->shards[0].npacks : 1;
    a_pad(u8, packpath, FILE_PATH_MAX_LEN);
    call(keep_pack_path, packpath, $path(kdir), file_id);

    u8bp log = NULL;
    u64  pack_offset = 0;
    if (appending) {
        //  Swap the existing RO mapping for an RW FILEBook view for
        //  the duration of the append.
        if (k->shards[0].packs[file_id - 1]) {
            FILEUnMap(k->shards[0].packs[file_id - 1]);
            k->shards[0].packs[file_id - 1] = NULL;
        }
        call(FILEBook, &log, $path(packpath), 16ULL << 30);
        pack_offset = u8bDataLen(log);
    } else {
        test(k->shards[0].npacks < KEEP_MAX_FILES, KEEPNOROOM);
        call(FILEBookCreate, &log, $path(packpath), 1ULL << 30, 4096);
        //  Lay down the one-and-only file-level PACK header with
        //  count=0; patched below after the append.
        call(PACKu8sFeedHdr, u8bIdle(log), 0);
        pack_offset = 12;
    }
    k->shards[0].packs[file_id - 1] = log;

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

    u8bp ro = NULL;
    call(FILEMapRO, &ro, $path(packpath));
    if (appending) {
        k->shards[0].packs[file_id - 1] = ro;
    } else {
        k->shards[0].packs[k->shards[0].npacks] = ro;
        k->shards[0].npacks++;
    }

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
        .emit = keep_indexer_emit,
        .emit_ctx = keep_indexer_ctx,
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

    //  Sort + dedup, write .idx run atomically (tmp → rename).
    a_dup(wh128, sorted, wh128bData(entries));
    wh128sSort(sorted);
    wh128sDedup(sorted);
    u64 nent = wh128sLen(sorted);

    u32 idx_seq = 1;
    {
        u32cp sb = (u32cp)k->shards[0].run_seqnos[1];
        u32cp se = (u32cp)k->shards[0].run_seqnos[2];
        for (u32cp p = sb; p < se; p++) if (*p >= idx_seq) idx_seq = *p + 1;
    }
    a_pad(u8, idxpath, FILE_PATH_MAX_LEN);
    call(keep_idx_path, idxpath, $path(kdir), idx_seq);

    a_pad(u8, idxtmppath, FILE_PATH_MAX_LEN);
    call(u8bFeed, idxtmppath, u8bDataC(idxpath));
    a_cstr(tmpsuf, ".tmp");
    call(u8bFeed, idxtmppath, tmpsuf);
    call(PATHu8bTerm, idxtmppath);

    {
        int ifd = -1;
        call(FILECreate, &ifd, $path(idxtmppath));
        u8cs raw = {(u8cp)sorted[0], (u8cp)(sorted[0] + nent)};
        call(FILEFeedAll, ifd, raw);
        close(ifd);
        call(FILERename, $path(idxtmppath), $path(idxpath));
    }
    wh128bFree(entries);

    u8bp idx_map = NULL;
    call(FILEMapRO, &idx_map, $path(idxpath));
    test(k->shards[0].nruns < KEEP_MAX_LEVELS, KEEPNOROOM);
    wh128cp base = (wh128cp)u8bDataHead(idx_map);
    u32 n = (u32)(u8bDataLen(idx_map) / sizeof(wh128));
    k->shards[0].runs[k->shards[0].nruns][0] = base;
    k->shards[0].runs[k->shards[0].nruns][1] = base + n;
    k->shards[0].run_maps[k->shards[0].nruns] = idx_map;
    call(u32bPush, k->shards[0].run_seqnos, &idx_seq);
    k->shards[0].nruns++;

    done;
}

// --- Sync: clone or update from remote via git-upload-pack ---

#include "PKT.h"
#include "ZINF.h"
#include <sys/wait.h>

// Compute git object SHA-1: hash("<type> <size>\0<content>")
// Incremental: feeds header and content separately (no copy needed).
static void keep_git_sha1(sha1 *out, u8 type, u8csc content) {
    static char const *type_str[] = {
        [1] = "commit", [2] = "tree", [3] = "blob", [4] = "tag"};
    a_pad(u8, hdr, 64);
    a_cstr(tname, type_str[type]);
    u8bFeed(hdr, tname);
    u8bFeed1(hdr, ' ');
    char tmp[32];
    int nlen = snprintf(tmp, sizeof(tmp), "%llu",
                        (unsigned long long)u8csLen(content));
    u8cs ns = {(u8cp)tmp, (u8cp)tmp + nlen};
    u8bFeed(hdr, ns);
    u8bFeed1(hdr, 0);

    SHA1state ctx;
    SHA1Open(&ctx);
    a_dup(u8c, hdata, u8bData(hdr));
    SHA1Feed(&ctx, hdata);
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
    u8cs scan = {body[0], body[1]};
    u8cs field = {}, value = {};
    *n = 0;
    while (GITu8sDrainCommit(scan, field, value) == OK) {
        if ($empty(field)) break;  // blank line → commit message follows
        if ($len(field) != 6 || memcmp(field[0], "parent", 6) != 0)
            continue;
        if ($len(value) < 40) continue;
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
    u8cs scan = {body[0], body[1]};
    u8cs field = {}, value = {};
    while (GITu8sDrainCommit(scan, field, value) == OK) {
        if ($empty(field)) break;
        if ($len(field) != 6 || memcmp(field[0], "object", 6) != 0)
            continue;
        if ($len(value) < 40) return GITBADFMT;
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
    memcpy(head_hex.data, line[0], 40);

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
                for (u32 pi = 0; pi < nrefs; pi++) {
                    if (strlen(refs[pi].name) == base_namelen &&
                        memcmp(refs[pi].name, namestart, base_namelen) == 0) {
                        memcpy(refs[pi].peeled.data, line[0], 40);
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

            memcpy(refs[nrefs].sha.data, line[0], 40);
            memcpy(refs[nrefs].peeled.data, line[0], 40);
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
    if ($len(line) >= 3 && memcmp(line[0], "NAK", 3) == 0) {
        // Full clone response
    } else if ($len(line) >= 3 && memcmp(line[0], "ACK", 3) == 0) {
        // Incremental: drain ACK/NAK lines until we reach the pack data
        for (;;) {
            // Check if resp[0] is at PACK magic
            if (resp[1] - resp[0] >= 4 && memcmp(resp[0], "PACK", 4) == 0)
                break;
            ok64 ao = PKTu8sDrain(resp, line);
            if (ao == PKTFLUSH) break;
            if (ao != OK) break;
            if ($len(line) >= 3 && memcmp(line[0], "NAK", 3) == 0) break;
        }
    } else {
        fprintf(stderr, "keeper: unexpected response: %.*s\n",
                (int)$len(line), (char *)line[0]);
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
    b8 appending = (k->shards[0].npacks > 0);
    u32 file_id = appending ? k->shards[0].npacks : 1;
    u64 pack_book = 16ULL << 30;  // 16GB VA reservation
    u8bp packbuf = NULL;
    u64 append_offset = 0;  // where new objects start in the log
    {
        a_pad(u8, dst, 1024);
        a_path(kdir, u8bDataC(k->h->root), KEEP_DIR_S);
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
    if (appending && k->shards[0].npacks > 0) {
        FILEUnMap(k->shards[0].packs[file_id - 1]);
        k->shards[0].packs[file_id - 1] = NULL;
        k->shards[0].npacks--;
    }
    {
        a_pad(u8, pp, 1024);
        a_path(kdir, u8bDataC(k->h->root), KEEP_DIR_S);
        if (keep_pack_path(pp, $path(kdir), file_id) == OK) {
            u8bp mapped = NULL;
            if (FILEMapRO(&mapped, $path(pp)) == OK) {
                k->shards[0].packs[k->shards[0].npacks] = mapped;
                k->shards[0].npacks++;
            }
        }
    }

    u8cp packbase = u8bDataHead(k->shards[0].packs[k->shards[0].npacks - 1]);
    u64 packlen = (u64)(u8bIdleHead(k->shards[0].packs[k->shards[0].npacks - 1]) - packbase);

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
            .emit       = keep_indexer_emit,
            .emit_ctx   = keep_indexer_ctx,
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

        //  Sort, dedup, persist as a new idx run.
        if (wh128bDataLen(entries) > 0) {
            a_dup(wh128, sorted, wh128bData(entries));
            wh128sSort(sorted);
            wh128sDedup(sorted);
            u32 nfinal = (u32)(sorted[1] - sorted[0]);

            a_path(kdir, u8bDataC(k->h->root), KEEP_DIR_S);
            u32 idx_id = 1;
            {
                u32cp sb = (u32cp)k->shards[0].run_seqnos[1];
                u32cp se = (u32cp)k->shards[0].run_seqnos[2];
                for (u32cp pp = sb; pp < se; pp++)
                    if (*pp >= idx_id) idx_id = *pp + 1;
            }
            a_pad(u8, idxpath, 1024);
            ok64 kpo = keep_idx_path(idxpath, $path(kdir), idx_id);
            if (kpo != OK) goto sync_fail;

            int fd = -1;
            ok64 fce = FILECreate(&fd, $path(idxpath));
            if (fce != OK) {
                fprintf(stderr, "keeper: idx create failed\n");
            } else if (fd >= 0) {
                u8cs data = {(u8cp)sorted[0],
                             (u8cp)(sorted[0] + nfinal)};
                FILEFeedAll(fd, data);
                close(fd);
            }

            u8bp mapped = NULL;
            if (FILEMapRO(&mapped, $path(idxpath)) == OK &&
                k->shards[0].nruns < KEEP_MAX_LEVELS) {
                wh128cp base = (wh128cp)u8bDataHead(mapped);
                size_t n = (u8bIdleHead(mapped) - u8bDataHead(mapped))
                           / sizeof(wh128);
                k->shards[0].runs[k->shards[0].nruns][0] = base;
                k->shards[0].runs[k->shards[0].nruns][1] = base + n;
                k->shards[0].run_maps[k->shards[0].nruns] = mapped;
                call(u32bPush, k->shards[0].run_seqnos, &idx_id);
                k->shards[0].nruns++;
            }
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
    while (GITu8sDrainTree(walk, file, sha) == OK) {
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
        memcpy(entry_sha.data, sha[0], 20);
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
        u8 payload[1024];
        int plen = snprintf((char *)payload, sizeof(payload),
            "%.40s %.40s %s", old_hex[0], new_hex[0], ref);
        if (plen < 0 || plen >= (int)sizeof(payload) - 32) goto push_fail;
        payload[plen++] = 0;
        a_cstr(caps, "report-status");
        memcpy(payload + plen, caps[0], (size_t)$len(caps));
        plen += (int)$len(caps);
        payload[plen++] = '\n';

        u8 pktbuf[1200];
        u8s ps = {pktbuf, pktbuf + sizeof(pktbuf)};
        u8csc pay_cs = {payload, payload + plen};
        if (PKTu8sFeed(ps, pay_cs) != OK) goto push_fail;
        if (PKTu8sFeedFlush(ps) != OK) goto push_fail;
        u8csc written = {pktbuf, ps[0]};
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
            if ($len(line) >= 9 && memcmp(line[0], "unpack ok", 9) == 0)
                unpack_ok = YES;
            else if ($len(line) >= 3 && memcmp(line[0], "ok ", 3) == 0)
                ref_ok = YES;
            else if ($len(line) >= 3 && memcmp(line[0], "ng ", 3) == 0)
                fprintf(stderr, "keeper: push rejected: %.*s",
                        (int)$len(line), (char *)line[0]);
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

