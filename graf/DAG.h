#ifndef GRAF_DAG_H
#define GRAF_DAG_H

//  DAG: graf's commit-graph + tree-shape index.
//
//  An LSM-style index of wh128 records (16 bytes each) covering
//  commit parentage, commit→tree edges, and parent-tree→child-object
//  edges.  Kept under <reporoot>/.dogs/graf/.  Stores no content —
//  actual blobs/trees/commits are retrieved via keeper using the full
//  path at query time.
//
//  Layout (mirrors keeper's branch-sharded shape):
//      .dogs/graf/<branch>/0000000001.graf.idx  sorted wh128 runs (LSM)
//      .dogs/graf/COMMIT                        last-seen ref tips
//  Trunk's `<branch>` slot is empty; nested branches live under
//  parent dirs (`.dogs/graf/feat/sub/...`).  `GRAFOpenBranch` walks
//  trunk → leaf, registering every `.graf.idx` along the way as a
//  DOGPup* puppy stack.  Writes only land in the leaf dir.
//
//  Entry format (wh128 = 2 × wh64 = 16 bytes):
//      a (key) = hashlet[60] | type[4]
//      b (val) = hashlet[60] | type[4]
//
//  Per-half types (4 bits in low nibble of each wh64):
//      1  COMMIT   refers to a commit object
//      2  TREE     refers to a tree object
//      3  BLOB     refers to a blob object
//
//  Entry kinds = (key.type, val.type) pairs:
//      (COMMIT, COMMIT)  commit → parent commit
//                        key.hl = commit_h60, val.hl = parent_h60
//      (COMMIT, TREE)    commit → root tree
//                        key.hl = commit_h60, val.hl = tree_h60
//      (TREE,   TREE)    parent-tree → child subtree
//      (TREE,   BLOB)    parent-tree → child blob (file)
//      (TREE,   COMMIT)  parent-tree → child commit (gitlink/submodule)
//                        key.hl = tree_h60 ^ RAPHashSeed60(name)
//                        val.hl = child_h60
//
//  Hashlets are 60-bit (top 60 bits of SHA-1) — the same width keeper
//  uses for its LSM keys, so a graf hashlet resolves directly in
//  keeper without prefix-lifting.
//
//  Tree-child keys are XOR-keyed on the segment name; lookup of
//  (tree, name) is a direct binary search, but callers must scan
//  forward across equal-key entries and verify against keeper to
//  defend against the (extremely rare) 60-bit collision.

#include "abc/INT.h"
#include "dog/SHA1.h"
#include "dog/WHIFF.h"
#include "keeper/KEEP.h"

con ok64 DAGFAIL     = 0xd2903ca495;
con ok64 DAGNOROOM   = 0xd2905d86d8616;
con ok64 DAGNOPATH   = 0xd2905d864a751;

// --- Per-half types (LSB of each wh64) ---

#define DAG_T_COMMIT  1
#define DAG_T_TREE    2
#define DAG_T_BLOB    3

// --- wh64 layout local to graf: hashlet[60] | type[4] (no id slot) ---
//
//  Hashlet is 60-bit, packed in the high bits so wh64 sorts by
//  hashlet primarily.  Type lives in the low nibble.

#define DAG_HL_SHIFT  4
#define DAG_HL_MASK   ((1ULL << 60) - 1)

fun wh64 DAGPack(u8 type, u64 hl) {
    return ((u64)type & 0xfULL) | ((hl & DAG_HL_MASK) << DAG_HL_SHIFT);
}
fun u8  DAGType(wh64 v)    { return (u8)(v & 0xfULL); }
fun u64 DAGHashlet(wh64 v) { return (v >> DAG_HL_SHIFT) & DAG_HL_MASK; }

fun wh128 DAGEntry(u8 ktype, u64 khash,
                   u8 vtype, u64 vhash) {
    return (wh128){
        .key = DAGPack(ktype, khash),
        .val = DAGPack(vtype, vhash),
    };
}

// --- sha1 helpers ---

fun u64 DAGsha1Hashlet(sha1 const *s) {
    return WHIFFHashlet60(s);
}

fun ok64 DAGsha1FromHex(sha1 *out, char const *hex40) {
    u8s sb = {out->data, out->data + 20};
    u8cs hx = {(u8cp)hex40, (u8cp)hex40 + 40};
    return HEXu8sDrainSome(sb, hx);
}

fun void DAGsha1ToHex(char *hex41, sha1 const *s) {
    u8 buf[41];
    u8s hx = {buf, buf + 40};
    u8cs bn = {s->data, s->data + 20};
    HEXu8sFeedSome(hx, bn);
    memcpy(hex41, buf, 40);
    hex41[40] = 0;
}

// --- LSM stack for index lookups ---
//
//  Public DAG queries take `wh128css runs` — a slice over the live
//  wh128cs runs that make up the LSM index.  graf produces it via
//  `GRAFRuns()` (a typed view over the kv32b puppy stack populated by
//  `DOGPupOpenAll`); test fixtures or other callers can build their
//  own from any source.  Newest-first scan order; per-run binary
//  search.

#include "abc/MSET.h"

//  Populate `hits` with one wh128cs slot per run that has at least
//  one entry whose key equals `key`.  Each populated slot covers
//  exactly the equal-key span in that run (binary search + forward
//  walk).  `hits[1]` carries the slot cap on the way in; the
//  function advances `hits[0]` past each filled slot — caller stashes
//  the original head before the call and recovers the populated range
//  as [stash, hits[0]).  Returns DAGNOROOM if the cap is exhausted
//  before all matching runs are scanned.
ok64 DAGRange(wh128css hits, wh128css runs, wh64 key);

//  Find the first entry matching (type, hashlet) anywhere in the
//  stack.  Returns NULL if not found.  Caller may walk forward across
//  entries with identical key (multiple parents, child-name
//  collisions, etc.) by checking `DAGType(p->key) == type &&
//  DAGHashlet(p->key) == hashlet` for each successor.
fun wh128cp DAGLookup(wh128css runs, u8 type, u64 hashlet) {
    u64 want = DAGPack(type, hashlet);
    a_dup(wh128cs, scan, runs);
    $for(wh128cs, run, scan) {
        wh128cp base = (*run)[0];
        size_t len = (size_t)((*run)[1] - base);
        size_t lo = 0, hi = len;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            if (base[mid].key < want) lo = mid + 1;
            else hi = mid;
        }
        if (lo < len && base[lo].key == want) return &base[lo];
    }
    return NULL;
}

// ==========================================================
// Graph-navigation primitives
// ==========================================================

//  Root-tree hashlet of a commit.  0 if not indexed.
//  (COMMIT, commit_h) keys cover both parent and root-tree edges;
//  caller's view is filtered on val.type == TREE inside.
u64 DAGCommitTree(wh128css runs, u64 commit_h);

//  Feed the parent edges from `commit_h` (a packed wh64 key, e.g.
//  `DAGPack(DAG_T_COMMIT, h60)`) into `parents` as full val-wh64s.
//  Each fed value carries (type, hashlet); decode with DAGType /
//  DAGHashlet.  Filters on val.type == DAG_T_COMMIT so the
//  same-key root-tree edge isn't yielded.  Returns DAGNOROOM when
//  `parents` fills.  Caller pattern:
//      wh64 storage[16];
//      wh64s parents = {storage, storage + 16};
//      DAGParents(idx, parents, DAGPack(DAG_T_COMMIT, h60));
//      // populated: [storage, parents[0])
ok64 DAGParents(wh128css index, wh64s parents, wh64 commit_h);

//  BFS from `tip` over COMMIT_PARENT edges; populate `set` with all
//  reachable commit hashlets (tip included).  `set` must be a
//  pre-allocated, power-of-two-sized Bwh128.  Pass tip=0 for a no-op.
ok64 DAGAncestors(Bwh128 set, wh128css runs, u64 tip);

//  Union of DAGAncestors across `n` tips into `set`.  Each tip is
//  walked independently; duplicates collapse on the common set.
ok64 DAGAncestorsOfMany(Bwh128 set, wh128css runs,
                        u64 const *tips, u32 n);

//  Populate `set` with every commit hashlet recorded in the index
//  (one record per (COMMIT, TREE) entry).  Use when there's no tip to
//  scope the walk to and a full-history projection is wanted.
ok64 DAGAllCommits(Bwh128 set, wh128css runs);

//  Membership check on a set populated by DAGAncestors.
b8 DAGAncestorsHas(Bwh128 set, u64 commit_h);

//  Insert a commit hashlet into a set populated by DAGAncestors.
ok64 dag_anc_put(Bwh128 set, u64 commit_h);

//  Topologically sort the commits in `set` (parents before children) by
//  walking COMMIT_PARENT edges within the set.  Writes up to `cap`
//  commit hashlets into `out`; returns the number written.  The walk is
//  ingest-order independent — depends only on the parent topology.
//  Out-of-set parents are ignored.  On stack overflow or alloc failure
//  the routine returns what it has so far.
u32 DAGTopoSort(u64 *out, u32 cap,
                Bwh128 set, wh128css runs);

// --- hashlet width bridging ---
//
//  graf's 60-bit hashlets line up exactly with keeper's 60-bit LSM
//  keys, so resolution is a direct lookup with hexlen=15.  Kept as a
//  named constant for self-documenting call sites.

#define DAG_H60_HEXLEN 15

// ==========================================================
// Tree-shape index
// ==========================================================

//  RAPHash seed for tree-segment names.  Constant, public so that
//  ingest and lookup hash the same way.  Picked from the golden ratio
//  bits — anything fixed and non-zero will do; the value just needs to
//  isolate the segment-name hash space from raw-SHA hashlets so the
//  XOR'd key doesn't accidentally collide with a same-shape COMMIT
//  key from a different entry kind.
#define GRAF_SEG_SEED 0x9e3779b97f4a7c15ULL

//  Visitor for DAGTreeChildren.  Receives one (child_h60, kind) per
//  matching wh128 record.  `kind` is DAG_T_TREE / DAG_T_BLOB /
//  DAG_T_COMMIT.  Return OK to keep iterating; return any non-OK to
//  abort the walk (the value propagates back to the caller — use it
//  to signal "found what I wanted, stop").
typedef ok64 (*DAGChildCb)(void *ctx, u64 child_h, u8 kind);

//  Look up children of `tree_h` named `name` in the index.  Computes
//  the XOR'd key, binary-searches each run, and walks every entry
//  whose key matches before invoking `cb`.  In the no-collision case
//  this is exactly one callback per matching entry; in the rare 60-bit
//  collision case it's >1 and the caller disambiguates via keeper.
ok64 DAGTreeChildren(wh128css runs, u64 tree_h, u8cs name,
                     DAGChildCb cb, void *ctx);

//  Walk path segments from `commit_h` (a packed wh64 key like
//  `DAGPack(DAG_T_COMMIT, h60)`) through the tree-shape index and
//  return the leaf object's wh64 (carries both kind and hashlet —
//  decode with DAGType / DAGHashlet).  Returns 0 (a never-valid wh64,
//  since type is always non-zero) if the commit isn't indexed, any
//  intermediate segment is missing, or an intermediate is anything
//  other than a TREE.  Hash-collision robustness: when multiple
//  candidates match a segment, the first TREE-typed (intermediate)
//  or any-typed (leaf) hit is taken.  Pure index lookups — no
//  keeper roundtrip, no allocation.
//
//  Empty `path` returns the commit's root tree wh64.
//  Trailing-slash paths are tolerated (treated as no segment after
//  the slash).
wh64 DAGCommitPathHashlet(wh128css index, wh64 commit_h, u8cs path);

#endif
