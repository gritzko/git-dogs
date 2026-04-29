#ifndef KEEPER_KEEP_H
#define KEEPER_KEEP_H

//  KEEP: local git object store.
//
//  Stores git pack objects in append-only log files under .dogs/.
//  Objects are looked up via an LSM index of wh128 entries:
//    key = keepKeyPack(obj_type, hashlet60)  hashlet60[60] | type[4]
//    val = wh64Pack(flags, file_id, offset)  offset[40] | file_id[20] | flags[4]
//
//  On disk (.dogs/; Phase 1b flat layout, trunk-only):
//    NNNNN.keeper — append-only pack log (FILEBook'd)
//    NNNNN.idx    — sorted wh128 run (LSM)
//    REFS         — URI→URI reflog
//
//  `NNNNN` is the 5-hex-char wh64 file_id (20 bits).  Phase 1a keeps
//  exactly one trunk shard; feature branches land in `<store>/<branch>/`
//  subdirs in Phase 1c+.

#include "abc/INT.h"
#include "abc/KV.h"
#include "abc/URI.h"
#include "dog/CLI.h"
#include "dog/HOME.h"
#include "dog/SHA1.h"
#include "dog/WHIFF.h"
#include "dog/DOG.h"

con ok64 KEEPFAIL    = 0x50e3993ca495;
con ok64 KEEPNOROOM  = 0x50e3995d86d8616;
con ok64 KEEPNONE    = 0x50e3995d85ce;
//  Returned by KEEPOpen when KEEP is already open with a compatible
//  mode.  The caller gets a usable &KEEP but must NOT call KEEPClose.
con ok64 KEEPOPEN    = 0x50e399619397;
//  Returned by KEEPOpen when caller requests rw on a ro-opened keeper.
con ok64 KEEPOPENRO  = 0x50e3996193976d8;
//  Intra-pack object order violation: commit→tree→blob→tag required.
con ok64 ORDERBAD    = 0x61b34e6cb28d;
//  KEEPOpenBranch: branch outside the Phase-0-supported set (trunk only).
con ok64 KEEPNOBR  = 0x50e3995d82db;
//  KEEPBranchDrop: refuses to drop the trunk shard.
con ok64 KEEPTRUNK = 0x1438e65d6de5d4;
//  KEEPBranchDrop: refuses a branch that still has descendants
//  referencing it via REF_DELTA, or a live staging pack.
con ok64 KEEPDIRTY = 0x1438e64d49b762;

// --- 60-bit hashlet: index key format ---
//
//  key = hashlet60[60] | obj_type[4]
//  Hashlet is big-endian: first SHA byte in MS bits.
//  60 bits = 15 hex chars of SHA prefix.
//  obj_type: 1=commit 2=tree 3=blob 4=tag (git pack types).
//  Sorts by hashlet first, type second.

// Index key uses wh64 with id=0 → 60-bit hashlet spans both fields.
// key = wh64Pack(obj_type, 0, hashlet40) but hashlet's upper 20 bits
// spill into the id field, giving 60 effective hashlet bits.

// Key pack: type in LS 4 bits, 60-bit hashlet above.
// Same as wh64Pack(type, id_hi, off) where hashlet60 = (off << 20) | id_hi.
fun u64 keepKeyPack(u8 type, u64 hashlet60) {
    return ((u64)type & WHIFF_TYPE_MASK) |
           ((hashlet60 & WHIFF_ID_MASK) << WHIFF_ID_SHIFT) |
           (((hashlet60 >> WHIFF_ID_BITS) & WHIFF_OFF_MASK) << WHIFF_OFF_SHIFT);
}
fun u8  keepKeyType(u64 key)    { return wh64Type(key); }
fun u64 keepKeyHashlet(u64 key) {
    return (wh64Off(key) << WHIFF_ID_BITS) | wh64Id(key);
}

// --- Pack bookmark val: obj_count32 | byte_len32 ---
//
//  PACK-typed index entries (key carries KEEP_TYPE_PACK + file_id +
//  offset) repurpose the val field to carry the pack's logical shape,
//  so pack-stream reconstruction is O(1) per pack and never has to
//  rescan bytes.  The old hashlet60|flags4 layout (used by the
//  retired TLV-based SYNC) is gone.  See keeper/WIRE.md Phase 0.
fun u64 keepPackBmVal(u32 count, u32 byte_len) {
    return ((u64)count << 32) | (u64)byte_len;
}
fun u32 keepPackBmCount(u64 val) { return (u32)(val >> 32); }
fun u32 keepPackBmLen(u64 val)   { return (u32)val; }

// --- Val format: same wh64 layout ---
//  val = wh64Pack(flags, file_id, offset)
//  flags[4] | file_id[20] | offset[40]

#define KEEP_VAL_FLAGS 1  // flags value for pack objects

#define HASH_MIN_HEX 4

// --- Keeper state ---

#include "abc/MSET.h"

#define KEEP_MAX_FILES   256
#define KEEP_MAX_LEVELS  MSET_MAX_LEVELS
#define KEEP_MAX_SHARDS  16              // Phase 1a hard-caps usage to 1
#define KEEP_DIR         ".dogs"
#define KEEP_PACK_EXT    ".keeper"       // pack logs live next to indexes
#define KEEP_IDX_EXT     ".idx"
#define KEEP_SEQNO_W     5               // 20-bit wh64 file_id → 5 hex chars

//  Per-branch object store.  Each shard owns the mmap'd pack log files
//  and the LSM index runs for one branch-dir.  Phase 1a keeps the on-
//  disk layout flat (single shard rooted at .dogs/); the branch
//  slice is always the trunk (empty) until Phase 1b migrates files
//  into branch subdirs.
typedef struct {
    u8cs    branch;                     // canonical branch path (slot 0 = trunk)
    int     lock_fd;                    // flock on <shard>/.lock; -1 = none
    u8bp    packs[KEEP_MAX_FILES];      // mmap'd log files
    u32     npacks;
    wh128cs runs[KEEP_MAX_LEVELS];      // LSM index runs
    u8bp    run_maps[KEEP_MAX_LEVELS];
    Bu32    run_seqnos;                 // `<seqno>.idx` per run, parallels runs[]
    u32     nruns;
} keeper_shard;

typedef struct {
    home         *h;                    // borrowed; owns root/arena/config/rw
    keeper_shard  shards[KEEP_MAX_SHARDS];
    u32           nshards;              // Phase 1a: always 1 on open
    Bu8           buf1;                 // working buffer for KEEPGet base inflate
    Bu8           buf2;                 // working buffer for KEEPGet delta apply
    Bu8           buf3;                 // working buffer for keep_resolve base
    Bu8           buf4;                 // working buffer for keep_resolve delta
} keeper;

// Relative ".dogs" slice.  Call sites compose the full dir via
//   a_path(dir, u8bDataC(k->h->root), KEEP_DIR_S);
// and use $path(dir) wherever a u8csc is needed.
extern u8c *const KEEP_DIR_S[2];

// --- Public API (DOG 4-fn) ---

//  Singleton keeper state.  Zero-initialised; population happens in
//  KEEPOpen.  All helpers that need keeper reach this symbol directly
//  rather than threading a pointer through every call chain.
extern keeper KEEP;

//  Open keeper store at `h`.  Returns:
//    OK         I opened it; caller must pair with KEEPClose.
//    KEEPOPEN   already open, compatible mode; use &KEEP, do NOT close.
//    KEEPOPENRO already open ro but caller asked for rw — real conflict;
//               propagate.  Caller's outer scope must re-architect.
//    (other)    real error — propagate, no KEEPClose.
ok64 KEEPOpen(home *h, b8 rw);

//  Branch-aware Open (new Phase-0 surface).  Normalizes `branch` via
//  DPATHBranchNormFeed and registers it on the home singleton via
//  HOMEOpenBranch before delegating to KEEPOpen.  Phase 0 accepts
//  only the trunk (canonical form = empty); other branches return
//  KEEPNOBR.  Same return semantics as KEEPOpen on trunk inputs.
ok64 KEEPOpenBranch(home *h, u8cs branch, b8 rw);

//  Drop a branch-dir and all its files (Phase 1c surface).  `branch`
//  is normalized via DPATHBranchNormFeed.  Preconditions:
//    * Trunk (empty canonical branch) cannot be dropped — KEEPTRUNK.
//    * No open shard may name a descendant of `branch` via REF_DELTA
//      into its subtree — KEEPDIRTY.
//    * No live staging pack (`stage.sniff`) may sit in the dir.
//  Phase 1c hard-caps nshards to 1, so any non-trunk branch returns
//  KEEPNOBR; full semantics light up as Phase 2+ opens sibling
//  shards.
ok64 KEEPBranchDrop(keeper *k, u8cs branch);

//  Run one CLI invocation — same effect as `keeper ...`.
ok64 KEEPExec(keeper *k, cli *c);

//  Feed a single git object (type + raw uncompressed content) into
//  the store.  Appends to the current pack log + records an index
//  entry.  obj_type uses KEEP_OBJ_* below.
ok64 KEEPUpdate(keeper *k, u8 obj_type, u8cs blob);

//  Compact the LSM run stack to satisfy the 1/8 invariant — merges
//  the youngest violators into one run, writes the merged `.idx`
//  atomically, unlinks the consumed source files, swaps mmaps in
//  the shard's `runs[]` / `run_maps[]`.  Invoked automatically from
//  KEEPClose; safe no-op when the stack is already compact or open
//  is read-only.
ok64 KEEPCompact(keeper *k);

//  Close and unmap everything.
ok64 KEEPClose(void);

//  Verb + value-flag tables for CLIParse.
extern char const *const KEEP_CLI_VERBS[];
extern char const KEEP_CLI_VAL_FLAGS[];

// Git object types (from packfile format)
#define KEEP_OBJ_COMMIT 1
#define KEEP_OBJ_TREE   2
#define KEEP_OBJ_BLOB   3
#define KEEP_OBJ_TAG    4

//  Pack bookmark index type.  Index entries whose key carries this
//  type are bookmarks for whole packs, not objects:
//    key = wh64Pack(KEEP_TYPE_PACK, file_id, offset_of_first_object)
//    val = keepPackBmVal(obj_count32, byte_len32)
//  obj_count is the number of git objects in the pack, byte_len is
//  the pack's stripped byte length (offset..offset+byte_len lives in
//  file_id).  Sits outside the 1..4 object-type range so range
//  queries for objects never see it.  See keeper/LOG.md and
//  keeper/WIRE.md.
#define KEEP_TYPE_PACK  0xF

//  Retrieve object by hashlet.  Inflates from pack, chases deltas.
//  Returns object body in `out`, type in `*out_type`.
ok64 KEEPGet(keeper *k, u64 hashlet60, size_t hexlen, u8bp out, u8p out_type);

//  Retrieve object by full 20-byte SHA-1.  Scans all hashlet matches,
//  inflates each, verifies SHA-1.  Use when the full hash is known
//  (e.g. tree entries) to avoid hashlet collisions.
ok64 KEEPGetExact(keeper *k, sha1 const *sha, u8bp out, u8p out_type);

//  Check if object exists in the store (hexlen = prefix length).
ok64 KEEPHas(keeper *k, u64 hashlet60, size_t hexlen);

//  Compute the canonical git object SHA-1 of a body: SHA1("<type>
//  <size>\0" + body).  `type` must be one of DOG_OBJ_*.
void KEEPObjSha(sha1 *out, u8 type, u8csc content);

//  Raw index lookup: hashlet → val wh64 (flags|file|offset).
//  hexlen: prefix length for partial matching (15 = full 60-bit).
ok64 KEEPLookup(keeper *k, u64 hashlet60, size_t hexlen, u64p val);

//  Verify object by full SHA-1: get from store, recompute hash,
//  compare.  For commits: also verifies tree.  For trees: verifies
//  all children recursively.  Reports errors to stderr.
ok64 KEEPVerify(keeper *k, u8cs hex_sha);

//  Import a git packfile into the store.
ok64 KEEPImport(keeper *k, u8cs pack_path);

//  Ingest a received git pack: `bytes` is the whole pack (12-byte
//  PACK header + object records + optional 20-byte SHA-1 trailer).
//  Strips header + trailer, appends the object stream to the tail
//  <kdir>/NNNNN.keeper, patches the log's file-level count,
//  UNPK-indexes just the appended slice, emits one pack bookmark
//  at the append offset, writes a fresh <NNN>.idx run, and extends
//  the trunk shard's packs[] / runs[].  An empty pack (count == 0)
//  is a no-op: zero file changes.  A new NNNNN.keeper file is only
//  created when npacks == 0 (first-ever ingest in this shard).
//  Caller holds no resources beyond the `bytes` slice.
ok64 KEEPIngestFile(keeper *k, u8csc bytes);

//  Push one new commit object to `host:path` via git-receive-pack.
//  Spawns `ssh <host> git-receive-pack <path>` (no shell).
//  `ref` is the full remote ref name, e.g. "refs/heads/master".
//  `old_hex`/`new_hex` are 40-char SHA-1 hex slices.  old_hex may be
//  "000...0" (40 zeros) to create a new ref.
//  `commit_body` is the raw commit object bytes that correspond to
//  new_hex; KEEPPush packs and sends exactly this one object.
ok64 KEEPPush(keeper *k, u8csc host, u8csc path, char const *ref,
              u8csc old_hex, u8csc new_hex, u8csc commit_body);

//  Fetch objects from remote via git-upload-pack.
//  `remote` is the parsed "host /path" form used for the ssh command.
//  `origin_uri` is the original URI the user typed (e.g.
//  "localhost:src/git" or "//localhost/path") and is used as the
//  prefix for remote-tracking entries in the refs reflog. Empty/NULL
//  is allowed — entries will then be recorded only under their local
//  bare names.
ok64 KEEPSync(keeper *k, u8cs remote, u8cs origin_uri,
              char const *const *wants, char const *const *haves);

//  Store a batch of objects (convenience wrapper over Open/Feed/Close).
ok64 KEEPPut(keeper *k, u8csc *objects, wh64 *whiffs, u32 nobjs);

// --- Incremental pack writer ---

#define KEEP_PACK_MAX_OBJS (1u << 20)

typedef struct {
    u8bp     log;                   // FILEBook'd log file (may already hold earlier packs)
    u32      file_id;               // sequence number
    u32      nobjs;                 // objects written so far by THIS pack
    u64      pack_offset;           // byte offset in log where THIS pack's first object starts
    u8       last_type;             // for commit->tree->blob->tag ordering check
    b8       strict_order;          // enforce commit->tree->blob->tag (ORDERBAD)
    u32      shard_idx;             // write shard (Phase 1c: always 0 = trunk)
    Bwh128   entries;               // index entries buffer
    Bu8      delta_base;            // scratch: inflated base content
    Bu8      delta_instr;           // scratch: encoded delta instructions
} keep_pack;

ok64 KEEPPackOpen(keeper *k, keep_pack *p);

//  Feed one object.  `sha_out` receives the 20-byte git SHA-1.
//  `path` is repo-relative for blobs (drives spot's tokenizer choice
//  and graf's PATH_VER entries via the indexer fan-out), empty for
//  commits/trees/tags.
//
//  If `base_hashlet60` is non-zero the writer tries to delta-compress
//  `content` against the object with that hashlet:
//    - Opportunistic OFS_DELTA when the base sits (raw) in this
//      in-progress pack — saves the 20-byte ref header.
//    - REF_DELTA otherwise — common case: a fresh pack usually holds
//      one version per file and the previous version lives in an
//      already-committed pack that KEEPGet resolves through any
//      internal delta chain.
//  Any mismatch (hashlet collision, delta not smaller than raw, base
//  unreachable) falls silently back to a raw record.  The index
//  entry always records the resolved object type.
ok64 KEEPPackFeed(keeper *k, keep_pack *p,
                  u8 type, u8csc content,
                  u64 base_hashlet60,
                  sha1 *sha_out);

ok64 KEEPPackClose(keeper *k, keep_pack *p);

//  Walk objects in a pack file from a given val position.
typedef ok64 (*keep_cb)(u8 type, u8cs content, u64 hashlet, void *ctx);
ok64 KEEPScan(keeper *k, u64 from_val, keep_cb cb, void *ctx);

//  Retrieve a single blob by URI.  Dispatch:
//    URI has host     → materialize from remote (TODO: not yet wired),
//    URI has query    → historical lookup via ref + path descent,
//    URI has fragment → hex SHA prefix (object lookup) + path descent,
//    otherwise        → KEEPFAIL (caller should use the filesystem).
//  `out` must be an allocated u8bp; the blob body is written into it.
ok64 KEEPGetByURI(keeper *k, uricp target, u8bp out);

//  Resolve a target URI to a root tree SHA-1 (20 bytes).
//  Accepted forms:
//    target.fragment = hex SHA prefix of a tree or commit object.
//    target.query    = ref name ("HEAD", "refs/tags/X", …) — looked up
//                      via REFS, tag-dereferenced if needed.
//  Returns KEEPNONE when the ref is unknown, KEEPFAIL on bad input.
ok64 KEEPResolveTree(keeper *k, uricp target, sha1 *tree_out);

//  KEEPLsFiles is declared in keeper/WALK.h (takes a walk_tree_fn).

#endif
