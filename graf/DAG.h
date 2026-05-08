#ifndef GRAF_DAG_H
#define GRAF_DAG_H

//  DAG: graf's commit-graph index.
//
//  An LSM-style index of wh128 records (16 bytes each) covering
//  commit parentage and commit→root-tree edges.  Tree-shape (per-
//  entry) edges are NOT recorded — git's pack-side delta compression
//  keeps tree storage cheap, while materialising every tree entry
//  here would dominate the repo footprint.  Path resolution at query
//  time goes through keeper directly (graf/BLOB.c::GRAFTreeStep).
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
//      3  BLOB     refers to a blob object   (val side only, reserved)
//
//  Entry kinds = (key.type, val.type) pairs:
//      (COMMIT, COMMIT)  commit → parent commit
//                        key.hl = commit_h60, val.hl = parent_h60
//      (COMMIT, TREE)    commit → root tree
//                        key.hl = commit_h60, val.hl = tree_h60
//
//  Hashlets are 60-bit (top 60 bits of SHA-1) — the same width keeper
//  uses for its LSM keys, so a graf hashlet resolves directly in
//  keeper without prefix-lifting.

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
//  Beagle-only edge kinds.  Recorded by GRAFDagUpdate alongside the
//  standard parent edges; a tunable walker (DAGAncestorsTunable)
//  opts in via the DAG_EDGE_* bitmask.
//      (COMMIT, FOSTER) — `foster <hex>` header on the commit.
//                         emitted by `?br#`/`?br` POSTs to record the
//                         absorbed branch tip without making it a
//                         standard parent.
//      (COMMIT, PICKED) — `picked: <hex>` trailer on the commit.
//                         emitted by `#<sha>` cherry-pick POSTs.
//                         Walked one-step only by the tunable walker:
//                         the picked target enters the reach set but
//                         its own parents/fosters/pickeds are NOT
//                         followed (per spec — picked is dedup-only).
#define DAG_T_FOSTER  4
#define DAG_T_PICKED  5

// --- Reachability edge kinds (bitmask for DAGAncestorsTunable) ---

#define DAG_EDGE_PARENT  (1u << 0)
#define DAG_EDGE_FOSTER  (1u << 1)
#define DAG_EDGE_PICKED  (1u << 2)   //  one-step only — see comment above

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

//  Tunable BFS over commit graph.  `edges` is a DAG_EDGE_* bitmask
//  picking which edge kinds to traverse:
//      DAG_EDGE_PARENT  — `parent` headers (= DAGAncestors).
//      DAG_EDGE_FOSTER  — `foster` headers (beagle-only).
//      DAG_EDGE_PICKED  — `picked: <sha>` trailers; targets are added
//                         as reach-set leaves but their own outgoing
//                         edges are NOT followed (one-step only).
//  `skip_hl[0..nskip)` are commit hashlets to omit entirely from the
//  reach set (also pruning traversal through them).  Pass nskip=0
//  with skip_hl=NULL for an unfiltered walk.  `tip` itself is added
//  unless it appears in skip.  DAGAncestors is equivalent to
//  DAGAncestorsTunable with edges=DAG_EDGE_PARENT, nskip=0.
ok64 DAGAncestorsTunable(Bwh128 set, wh128css runs, u64 tip,
                         u32 edges,
                         u64 const *skip_hl, u32 nskip);

ok64 DAGAncestorsOfManyTunable(Bwh128 set, wh128css runs,
                               u64 const *tips, u32 ntips,
                               u32 edges,
                               u64 const *skip_hl, u32 nskip);

//  Helper: enumerate edges of one kind out of a commit.
//  Caller-provided `out` (of capacity `cap`) gets target hashlets.
//  *nout is set on return.  `kind` is one of DAG_T_COMMIT (parents),
//  DAG_T_FOSTER, or DAG_T_PICKED.
ok64 DAGEdgesOf(wh128css runs, u64 commit_h, u8 kind,
                u64 *out, u32 cap, u32 *nout);

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

//  Tunable variant: respects the `edges` bitmask when ordering — a
//  commit C is held back until every edge target of the kinds in
//  `edges` has been emitted.  `DAGTopoSort` is the legacy
//  parent-only behaviour.
//
//  Foster targets (DAG_EDGE_FOSTER) order BEFORE their carrying
//  commit.  Picked targets (DAG_EDGE_PICKED) do NOT impose ordering
//  — they're leaves with no replay step of their own; callers that
//  add DAG_EDGE_PICKED to the ancestor walk should NOT add it here.
u32 DAGTopoSortTunable(u64 *out, u32 cap,
                       Bwh128 set, wh128css runs,
                       u32 edges);

// --- hashlet width bridging ---
//
//  graf's 60-bit hashlets line up exactly with keeper's 60-bit LSM
//  keys, so resolution is a direct lookup with hexlen=15.  Kept as a
//  named constant for self-documenting call sites.

#define DAG_H60_HEXLEN 15

#endif
