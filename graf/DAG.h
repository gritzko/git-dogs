#ifndef GRAF_DAG_H
#define GRAF_DAG_H

//  DAG: graf's commit-graph index.
//
//  An LSM-style index of wh128 records (16 bytes each) covering
//  commit parentage and commit→tree edges only.  Kept under
//  <reporoot>/.dogs/graf/.  Used by graf to walk history; stores
//  no content — actual blobs/trees are retrieved via keeper using
//  the full path at query time.
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
//      a = type[4] | id[20] | hashlet[40]
//      b = type[4] | id[20] | hashlet[40]
//
//  Entry types (low 4 bits of .a.type):
//      2  COMMIT_PARENT  commit → parent commit
//                        a = (2, 0, commit_h), b = (2, 0, parent_h)
//      3  COMMIT_TREE    commit → root tree hashlet
//                        a = (3, 0, commit_h), b = (3, 0, tree_h)
//
//  Type 1 (COMMIT_GEN) and type 4 (PATH_VER) are reserved: older
//  indexes may still contain those records; current code never
//  writes or reads them.  The 20-bit `id` slot is no longer
//  populated — kept zero in every record we write.

#include "abc/INT.h"
#include "dog/SHA1.h"
#include "dog/WHIFF.h"
#include "keeper/KEEP.h"

con ok64 DAGFAIL     = 0xd2903ca495;
con ok64 DAGNOROOM   = 0xd2905d86d8616;
con ok64 DAGNOPATH   = 0xd2905d864a751;

// --- Entry types ---
//
//  COMMIT_GEN (type 1) and PATH_VER (type 4) were removed:
//    - COMMIT_GEN: gens were ingest-order dependent; replaced at
//      query time by DAGTopoSort.
//    - PATH_VER: path-touch events required walking each commit's
//      tree at ingest time; query side now derives equivalent
//      information by walking COMMIT_PARENT + descending each tree
//      via keeper.

#define DAG_COMMIT_PARENT  2
#define DAG_COMMIT_TREE    3

// wh128 a/b use the wh64 layout: hashlet[40] | id[20] | type[4]
// (type in low bits; hashlet in high bits — see dog/WHIFF.h).
#define DAGPack    wh64Pack
#define DAGType    wh64Type
#define DAGId      wh64Id
#define DAGHashlet wh64Off

fun wh128 DAGEntry(u8 atype, u32 aid, u64 ahash,
                   u8 btype, u32 bid, u64 bhash) {
    return (wh128){
        .key = wh64Pack(atype, aid, ahash),
        .val = wh64Pack(btype, bid, bhash),
    };
}

// --- sha1 helpers ---

fun u64 DAGsha1Hashlet(sha1 const *s) {
    return WHIFFHashlet40(s);
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

//  Find first entry matching (type, hashlet) anywhere in the stack.
//  Returns NULL if not found.  Scans across type-interleaved entries.
fun wh128cp DAGLookup(wh128css runs, u8 type, u64 hashlet) {
    u64 key_lo = DAGPack(type, 0, hashlet);
    u64 key_hi = DAGPack(type, WHIFF_ID_MASK, hashlet);
    a_dup(wh128cs, scan, runs);
    $for(wh128cs, run, scan) {
        wh128cp base = (*run)[0];
        size_t len = (size_t)((*run)[1] - base);
        size_t lo = 0, hi = len;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            if (base[mid].key < key_lo) lo = mid + 1;
            else hi = mid;
        }
        while (lo < len && base[lo].key >= key_lo && base[lo].key <= key_hi) {
            if (DAGType(base[lo].key) == type) return &base[lo];
            lo++;
        }
    }
    return NULL;
}

// ==========================================================
// Graph-navigation primitives
// ==========================================================

//  Root-tree hashlet of a commit.  0 if not indexed.
fun u64 DAGCommitTree(wh128css runs, u64 commit_h) {
    wh128cp rec = DAGLookup(runs, DAG_COMMIT_TREE, commit_h);
    return rec ? DAGHashlet(rec->val) : 0;
}

//  Collect parent hashlets of a commit into out[0..cap).  Returns the
//  total number of parents found; only the first min(count, cap) are
//  written.  Root commits return 0.
u32 DAGParents(wh128css runs, u64 commit_h, u64 *out, u32 cap);

//  BFS from `tip` over COMMIT_PARENT edges; populate `set` with all
//  reachable commit hashlets (tip included).  `set` must be a
//  pre-allocated, power-of-two-sized Bwh128.  Pass tip=0 for a no-op.
ok64 DAGAncestors(Bwh128 set, wh128css runs, u64 tip);

//  Union of DAGAncestors across `n` tips into `set`.  Each tip is
//  walked independently; duplicates collapse on the common set.
ok64 DAGAncestorsOfMany(Bwh128 set, wh128css runs,
                        u64 const *tips, u32 n);

//  Populate `set` with every commit hashlet recorded in the index
//  (one record per COMMIT_TREE entry).  Use when there's no tip to
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
//  graf stores 40-bit hashlets (top 40 bits of SHA-1); keeper stores
//  60-bit hashlets (top 60 bits) in its LSM keys.  To resolve a graf
//  hashlet in keeper, left-align into the 60-bit space and do a
//  40-bit prefix match (hexlen = 10).  For small repos 40-bit
//  collisions are vanishingly rare; the caller further narrows by
//  checking obj_type.

#define DAG_H40_HEXLEN 10

fun u64 DAGh40ToKeeperPrefix(u64 h40) { return h40 << 20; }

#endif
