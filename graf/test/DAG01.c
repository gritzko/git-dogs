//
//  DAG01 — graf DAG primitives over an in-memory wh128 run.
//
//  Bypasses GRAFOpen / file I/O: builds a sorted wh128cs[] run by
//  hand, wraps it in `wh128css runs`, and exercises the lookup-side
//  primitives directly.  Ingest-side correctness (the GRAFDagUpdate
//  TREE/COMMIT cases) is covered by the CLI integration tests
//  (toy.sh, get.sh) since it requires the full graf state.
//

#include "DAG.h"

#include <string.h>

#include "abc/PRO.h"
#include "abc/RAP.h"
#include "abc/TEST.h"

//  Local instantiations: wh128 sort/dedup macros are declared in the
//  templated headers and instantiated per .c file that needs them.
#define X(M, name) M##wh128##name
#include "abc/QSORTx.h"
#undef X

// --- Test fixtures -------------------------------------------------

#define DAG01_MAX_RECS 64

typedef struct {
    wh128 recs[DAG01_MAX_RECS];
    u32   n;
} dag01_idx;

static void dag01_emit(dag01_idx *idx,
                       u8 ktype, u64 khash,
                       u8 vtype, u64 vhash) {
    if (idx->n >= DAG01_MAX_RECS) return;
    idx->recs[idx->n++] = DAGEntry(ktype, khash, vtype, vhash);
}

//  Sort the index in place, then build a `wh128css runs` view over it.
//  The view aliases `idx->recs` and `view`, both of which must outlive
//  any `runs` use.
static void dag01_view(dag01_idx *idx, wh128cs view[1], wh128css *runs) {
    wh128s d = {idx->recs, idx->recs + idx->n};
    wh128sSort(d);
    view[0][0] = idx->recs;
    view[0][1] = idx->recs + idx->n;
    (*runs)[0] = view;
    (*runs)[1] = view + 1;
}

//  Collect-into-buffer callback for DAGTreeChildren.
typedef struct {
    u64 child[8];
    u8  kind[8];
    u32 n;
} child_collector;

static ok64 collect_child(void *ctx, u64 child_h, u8 kind) {
    child_collector *c = (child_collector *)ctx;
    if (c->n < 8) {
        c->child[c->n] = child_h;
        c->kind[c->n]  = kind;
        c->n++;
    }
    return OK;
}

static u64 seg_h(char const *name) {
    u8cs s = {(u8cp)name, (u8cp)name + strlen(name)};
    return RAPHashSeed(s, GRAF_SEG_SEED) & DAG_HL_MASK;
}

static u64 cs_seg_h(u8cs s) {
    return RAPHashSeed(s, GRAF_SEG_SEED) & DAG_HL_MASK;
}

// --- Tests ---------------------------------------------------------

//  Test 1: single (COMMIT, TREE) edge — DAGCommitTree resolves it.
ok64 DAG01test1() {
    sane(1);
    dag01_idx idx = {};
    dag01_emit(&idx, DAG_T_COMMIT, 0xC1C1, DAG_T_TREE, 0x7777);
    wh128cs view[1]; wh128css runs = {NULL, NULL};
    dag01_view(&idx, view, &runs);

    u64 t = DAGCommitTree(runs, 0xC1C1);
    want(t == 0x7777);
    done;
}

//  Test 2: single (COMMIT, COMMIT) parent edge — DAGParents finds it
//  and DAGCommitTree returns 0 (no tree edge).
ok64 DAG01test2() {
    sane(1);
    dag01_idx idx = {};
    dag01_emit(&idx, DAG_T_COMMIT, 0xC1C1, DAG_T_COMMIT, 0xFEED);
    wh128cs view[1]; wh128css runs = {NULL, NULL};
    dag01_view(&idx, view, &runs);

    wh64 par_buf[4] = {};
    wh64s parents = {par_buf, par_buf + 4};
    wh64 *pbase = parents[0];
    want(DAGParents(runs, parents, DAGPack(DAG_T_COMMIT, 0xC1C1)) == OK);
    want(parents[0] - pbase == 1);
    want(DAGType(pbase[0]) == DAG_T_COMMIT);
    want(DAGHashlet(pbase[0]) == 0xFEED);

    want(DAGCommitTree(runs, 0xC1C1) == 0);
    done;
}

//  Test 3: same-key COMMIT_PARENT and COMMIT_TREE coexist; each
//  side filters by val.type.  Verifies the val-type filtering added
//  in this layout swap.
ok64 DAG01test3() {
    sane(1);
    dag01_idx idx = {};
    dag01_emit(&idx, DAG_T_COMMIT, 0xC1C1, DAG_T_TREE,   0xAAA);
    dag01_emit(&idx, DAG_T_COMMIT, 0xC1C1, DAG_T_COMMIT, 0x111);
    dag01_emit(&idx, DAG_T_COMMIT, 0xC1C1, DAG_T_COMMIT, 0x222);
    wh128cs view[1]; wh128css runs = {NULL, NULL};
    dag01_view(&idx, view, &runs);

    want(DAGCommitTree(runs, 0xC1C1) == 0xAAA);

    wh64 par_buf[4] = {};
    wh64s parents = {par_buf, par_buf + 4};
    wh64 *pbase = parents[0];
    want(DAGParents(runs, parents, DAGPack(DAG_T_COMMIT, 0xC1C1)) == OK);
    want(parents[0] - pbase == 2);
    want(DAGType(pbase[0]) == DAG_T_COMMIT);
    want(DAGType(pbase[1]) == DAG_T_COMMIT);
    u64 h0 = DAGHashlet(pbase[0]), h1 = DAGHashlet(pbase[1]);
    want((h0 == 0x111 && h1 == 0x222) || (h0 == 0x222 && h1 == 0x111));
    done;
}

//  Test 4: tree → blob via DAGTreeChildren.
ok64 DAG01test4() {
    sane(1);
    dag01_idx idx = {};
    u64 tree_h  = 0x1111;
    u64 child_h = 0xBABE;
    u64 sh = seg_h("hello.c");
    dag01_emit(&idx, DAG_T_TREE, tree_h ^ sh, DAG_T_BLOB, child_h);
    wh128cs view[1]; wh128css runs = {NULL, NULL};
    dag01_view(&idx, view, &runs);

    child_collector c = {};
    u8cs name = {(u8cp)"hello.c", (u8cp)"hello.c" + 7};
    ok64 r = DAGTreeChildren(runs, tree_h, name, collect_child, &c);
    want(r == OK);
    want(c.n == 1);
    want(c.child[0] == child_h);
    want(c.kind[0]  == DAG_T_BLOB);
    done;
}

//  Test 5: tree → subtree via DAGTreeChildren.
ok64 DAG01test5() {
    sane(1);
    dag01_idx idx = {};
    u64 tree_h  = 0x2222;
    u64 child_h = 0xDEAD;
    u64 sh = seg_h("subdir");
    dag01_emit(&idx, DAG_T_TREE, tree_h ^ sh, DAG_T_TREE, child_h);
    wh128cs view[1]; wh128css runs = {NULL, NULL};
    dag01_view(&idx, view, &runs);

    child_collector c = {};
    u8cs name = {(u8cp)"subdir", (u8cp)"subdir" + 6};
    want(DAGTreeChildren(runs, tree_h, name, collect_child, &c) == OK);
    want(c.n == 1);
    want(c.kind[0] == DAG_T_TREE);
    want(c.child[0] == child_h);
    done;
}

//  Test 6: tree → gitlink (commit) via DAGTreeChildren.
ok64 DAG01test6() {
    sane(1);
    dag01_idx idx = {};
    u64 tree_h  = 0x3333;
    u64 child_h = 0xC0DE;
    u64 sh = seg_h("vendor");
    dag01_emit(&idx, DAG_T_TREE, tree_h ^ sh, DAG_T_COMMIT, child_h);
    wh128cs view[1]; wh128css runs = {NULL, NULL};
    dag01_view(&idx, view, &runs);

    child_collector c = {};
    u8cs name = {(u8cp)"vendor", (u8cp)"vendor" + 6};
    want(DAGTreeChildren(runs, tree_h, name, collect_child, &c) == OK);
    want(c.n == 1);
    want(c.kind[0] == DAG_T_COMMIT);
    want(c.child[0] == child_h);
    done;
}

//  Test 7: same name "main.c" in two different parent trees — each
//  lookup returns only its own child (XOR-keying isolates parents).
ok64 DAG01test7() {
    sane(1);
    dag01_idx idx = {};
    u64 t_a = 0xAA00, t_b = 0xBB00;
    u64 sh = seg_h("main.c");
    dag01_emit(&idx, DAG_T_TREE, t_a ^ sh, DAG_T_BLOB, 0xA1);
    dag01_emit(&idx, DAG_T_TREE, t_b ^ sh, DAG_T_BLOB, 0xB2);
    wh128cs view[1]; wh128css runs = {NULL, NULL};
    dag01_view(&idx, view, &runs);

    u8cs name = {(u8cp)"main.c", (u8cp)"main.c" + 6};

    child_collector ca = {};
    want(DAGTreeChildren(runs, t_a, name, collect_child, &ca) == OK);
    want(ca.n == 1 && ca.child[0] == 0xA1);

    child_collector cb = {};
    want(DAGTreeChildren(runs, t_b, name, collect_child, &cb) == OK);
    want(cb.n == 1 && cb.child[0] == 0xB2);
    done;
}

//  Test 8: synthetic key collision — two distinct entries with
//  identical (TREE, key) hashlets must both be yielded by the scan.
//  Simulates the rare 60-bit hash-collision case the lookup must
//  tolerate.  We synthesise it directly (forcing a real RAPHashSeed
//  collision is intractable) by emitting two records under the same
//  parent-tree + same-name combo with different child hashlets.
ok64 DAG01test8() {
    sane(1);
    dag01_idx idx = {};
    u64 tree_h = 0x4444;
    u64 sh = seg_h("conflict");
    dag01_emit(&idx, DAG_T_TREE, tree_h ^ sh, DAG_T_BLOB, 0xC1);
    dag01_emit(&idx, DAG_T_TREE, tree_h ^ sh, DAG_T_TREE, 0xC2);
    wh128cs view[1]; wh128css runs = {NULL, NULL};
    dag01_view(&idx, view, &runs);

    child_collector c = {};
    u8cs name = {(u8cp)"conflict", (u8cp)"conflict" + 8};
    want(DAGTreeChildren(runs, tree_h, name, collect_child, &c) == OK);
    want(c.n == 2);
    //  Sort order is by val: (BLOB=3, 0xC1) and (TREE=2, 0xC2);
    //  TREE-typed val sorts before BLOB-typed val (lower type byte
    //  in low bits).  Either way, both kinds must be present.
    b8 saw_blob = NO, saw_tree = NO;
    for (u32 i = 0; i < c.n; i++) {
        if (c.kind[i] == DAG_T_BLOB && c.child[i] == 0xC1) saw_blob = YES;
        if (c.kind[i] == DAG_T_TREE && c.child[i] == 0xC2) saw_tree = YES;
    }
    want(saw_blob && saw_tree);
    done;
}

//  Test 9: lookup miss — DAGTreeChildren never invokes the cb when
//  no entry matches.
ok64 DAG01test9() {
    sane(1);
    dag01_idx idx = {};
    u64 tree_h = 0x5555;
    u64 sh = seg_h("present");
    dag01_emit(&idx, DAG_T_TREE, tree_h ^ sh, DAG_T_BLOB, 0xAB);
    wh128cs view[1]; wh128css runs = {NULL, NULL};
    dag01_view(&idx, view, &runs);

    child_collector c = {};
    u8cs name = {(u8cp)"absent", (u8cp)"absent" + 6};
    want(DAGTreeChildren(runs, tree_h, name, collect_child, &c) == OK);
    want(c.n == 0);
    done;
}

//  Test 10: segment-hash determinism — RAPHashSeed of the same
//  bytes must yield the same value every time (sanity check that
//  ingest and lookup will agree).
ok64 DAG01test10() {
    sane(1);
    u64 a = seg_h("foo.c");
    u64 b = seg_h("foo.c");
    u64 c = seg_h("foo.h");
    want(a == b);
    want(a != c);
    //  Slice and cstr forms equivalent.
    u8cs s = {(u8cp)"foo.c", (u8cp)"foo.c" + 5};
    want(cs_seg_h(s) == a);
    done;
}

//  Test 11: DAGCommitPathHashlet — single-segment leaf.
//  commit -> root_tree -> "foo.c" (BLOB).  Resolves to the blob's
//  wh64 (kind=BLOB, hashlet=child).
ok64 DAG01test11() {
    sane(1);
    dag01_idx idx = {};
    u64 commit_h  = 0xC0FFEE;
    u64 root_tree = 0x7700;
    u64 leaf_blob = 0xBA11;
    dag01_emit(&idx, DAG_T_COMMIT, commit_h, DAG_T_TREE, root_tree);
    dag01_emit(&idx, DAG_T_TREE,
               root_tree ^ seg_h("foo.c"),
               DAG_T_BLOB, leaf_blob);
    wh128cs view[1]; wh128css runs = {NULL, NULL};
    dag01_view(&idx, view, &runs);

    u8cs path = {(u8cp)"foo.c", (u8cp)"foo.c" + 5};
    wh64 leaf = DAGCommitPathHashlet(runs,
                                     DAGPack(DAG_T_COMMIT, commit_h),
                                     path);
    want(leaf != 0);
    want(DAGType(leaf) == DAG_T_BLOB);
    want(DAGHashlet(leaf) == leaf_blob);
    done;
}

//  Test 12: multi-segment descent — commit -> root -> "src" (TREE)
//  -> "main.c" (BLOB).
ok64 DAG01test12() {
    sane(1);
    dag01_idx idx = {};
    u64 commit_h  = 0xCC10;
    u64 root_h    = 0x1100;
    u64 src_h     = 0x2200;
    u64 leaf_h    = 0x3300;

    dag01_emit(&idx, DAG_T_COMMIT, commit_h, DAG_T_TREE, root_h);
    dag01_emit(&idx, DAG_T_TREE, root_h ^ seg_h("src"),    DAG_T_TREE, src_h);
    dag01_emit(&idx, DAG_T_TREE, src_h  ^ seg_h("main.c"), DAG_T_BLOB, leaf_h);

    wh128cs view[1]; wh128css runs = {NULL, NULL};
    dag01_view(&idx, view, &runs);

    u8cs path = {(u8cp)"src/main.c", (u8cp)"src/main.c" + 10};
    wh64 leaf = DAGCommitPathHashlet(runs,
                                     DAGPack(DAG_T_COMMIT, commit_h),
                                     path);
    want(leaf != 0);
    want(DAGType(leaf) == DAG_T_BLOB);
    want(DAGHashlet(leaf) == leaf_h);
    done;
}

//  Test 13: missing segment — descent halts and yields 0.
ok64 DAG01test13() {
    sane(1);
    dag01_idx idx = {};
    u64 commit_h = 0xCC11, root_h = 0x4400;
    dag01_emit(&idx, DAG_T_COMMIT, commit_h, DAG_T_TREE, root_h);
    //  No tree-child entry for "ghost".
    wh128cs view[1]; wh128css runs = {NULL, NULL};
    dag01_view(&idx, view, &runs);

    u8cs path = {(u8cp)"ghost", (u8cp)"ghost" + 5};
    want(DAGCommitPathHashlet(runs, DAGPack(DAG_T_COMMIT, commit_h),
                              path) == 0);
    done;
}

//  Test 14: empty path returns the root tree's wh64.
ok64 DAG01test14() {
    sane(1);
    dag01_idx idx = {};
    u64 commit_h = 0xCC12, root_h = 0x5500;
    dag01_emit(&idx, DAG_T_COMMIT, commit_h, DAG_T_TREE, root_h);
    wh128cs view[1]; wh128css runs = {NULL, NULL};
    dag01_view(&idx, view, &runs);

    u8cs empty = {NULL, NULL};
    wh64 r = DAGCommitPathHashlet(runs, DAGPack(DAG_T_COMMIT, commit_h),
                                  empty);
    want(r != 0);
    want(DAGType(r) == DAG_T_TREE);
    want(DAGHashlet(r) == root_h);
    done;
}

//  Test 15: dedup-via-equal-hashlet — two commits whose `path`
//  resolves through the index to the same leaf wh64 ⇒ "did not
//  touch the file."  This is the property graflog_file / the weave
//  builder will rely on.
ok64 DAG01test15() {
    sane(1);
    dag01_idx idx = {};
    u64 c1 = 0xCC100, c2 = 0xCC200;
    u64 root1 = 0x1000, root2 = 0x2000;
    u64 leaf  = 0x9999;          // same blob hashlet at both commits
    dag01_emit(&idx, DAG_T_COMMIT, c1, DAG_T_TREE, root1);
    dag01_emit(&idx, DAG_T_COMMIT, c2, DAG_T_TREE, root2);
    dag01_emit(&idx, DAG_T_TREE, root1 ^ seg_h("a.c"), DAG_T_BLOB, leaf);
    dag01_emit(&idx, DAG_T_TREE, root2 ^ seg_h("a.c"), DAG_T_BLOB, leaf);

    wh128cs view[1]; wh128css runs = {NULL, NULL};
    dag01_view(&idx, view, &runs);

    u8cs p = {(u8cp)"a.c", (u8cp)"a.c" + 3};
    wh64 r1 = DAGCommitPathHashlet(runs, DAGPack(DAG_T_COMMIT, c1), p);
    wh64 r2 = DAGCommitPathHashlet(runs, DAGPack(DAG_T_COMMIT, c2), p);
    want(r1 != 0 && r2 != 0);
    want(r1 == r2);   // same wh64 ⇒ index-only dedup says "untouched"
    done;
}

ok64 maintest() {
    sane(1);
    call(DAG01test1);
    call(DAG01test2);
    call(DAG01test3);
    call(DAG01test4);
    call(DAG01test5);
    call(DAG01test6);
    call(DAG01test7);
    call(DAG01test8);
    call(DAG01test9);
    call(DAG01test10);
    call(DAG01test11);
    call(DAG01test12);
    call(DAG01test13);
    call(DAG01test14);
    call(DAG01test15);
    done;
}

TEST(maintest)
