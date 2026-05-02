//  REBASE: linear-history replay primitives.  See graf/REBASE.h.
//
//  Three primitives, all keeper-read-only, no DAG dependencies:
//    GRAFPatchId       — stable diff-id of a commit vs first parent
//    GRAFMergeExplicit — 3-way blob merge with explicit base sha
//    GRAFRebase        — replay child_tip onto base_new
//
//  Implementation notes:
//    * Patch-id walks the two trees via WALKTreeLazy into per-side
//      flat (path, sha) lists, sorts each by path, and emits diff
//      tuples in path-ascending order.  Tree-walk recursion handled
//      by WALKTreeLazy; collection happens in a small heap buffer.
//    * GRAFMergeExplicit fetches three blobs through KEEPGetExact,
//      then JOINTokenize / JOINMerge.  Same fallbacks as GET.c: a
//      missing base behaves like an empty file (JOINMerge takes ours
//      in that case).
//    * GRAFRebase walks parent chain, dedups via patch-id set built
//      from base_new's ancestors, and per commit produces a new tree
//      by recursively 3-way-merging tree(parent), tree(head),
//      tree(commit).  Conflicts return GRAFCNFL with no further emits.
//
#include "REBASE.h"

#include <stdlib.h>
#include <string.h>

#include "BLOB.h"
#include "GRAF.h"
#include "JOIN.h"

#include "abc/PATH.h"
#include "abc/PRO.h"
#include "abc/RAP.h"
#include "dog/DOG.h"
#include "keeper/GIT.h"
#include "keeper/KEEP.h"
#include "keeper/WALK.h"

#define REBASE_OBJ_BUF      (1UL << 20)
#define REBASE_BLOB_MAX     (16UL << 20)
#define REBASE_PATH_MAX     4096
#define REBASE_TREE_ENTRIES 4096
#define REBASE_PIDS_MAX     8192

// ---------------------------------------------------------------------
//  Primitive 1: GRAFPatchId
//
//  We collect (path, sha) leaves of both trees lazily, sort each by
//  path, then walk them in lockstep.  Each path with a sha mismatch
//  feeds the rolling RAPHash via a stable serialised tuple.
// ---------------------------------------------------------------------

typedef struct {
    u8c *path;       //  borrowed: lives in collector arena
    u32  path_len;
    sha1 sha;
} pid_leaf;

typedef struct {
    pid_leaf *leaves;
    u32       n;
    u32       cap;
    u8       *arena;     //  path bytes
    u32       arena_len;
    u32       arena_cap;
    ok64      err;
} pid_collector;

static ok64 pid_visit(u8cs path, u8 kind, u8cp esha, u8cs blob,
                      void0p vctx) {
    (void)blob;
    pid_collector *c = (pid_collector *)vctx;
    if (c->err != OK) return WALKSTOP;
    //  Only leaves contribute.
    if (kind != WALK_KIND_REG && kind != WALK_KIND_EXE &&
        kind != WALK_KIND_LNK && kind != WALK_KIND_SUB) {
        return OK;
    }
    if (c->n >= c->cap) { c->err = GRAFFAIL; return WALKSTOP; }

    u32 plen = (u32)$len(path);
    if (c->arena_len + plen > c->arena_cap) {
        c->err = GRAFFAIL; return WALKSTOP;
    }
    u8 *dst = c->arena + c->arena_len;
    if (plen > 0) memcpy(dst, path[0], plen);
    c->arena_len += plen;

    pid_leaf *l = &c->leaves[c->n++];
    l->path = dst;
    l->path_len = plen;
    memcpy(l->sha.data, esha, 20);
    return OK;
}

static int pid_leaf_cmp(void const *a_, void const *b_) {
    pid_leaf const *a = (pid_leaf const *)a_;
    pid_leaf const *b = (pid_leaf const *)b_;
    u32 ml = a->path_len < b->path_len ? a->path_len : b->path_len;
    int c = (ml == 0) ? 0 : memcmp(a->path, b->path, ml);
    if (c != 0) return c;
    if (a->path_len < b->path_len) return -1;
    if (a->path_len > b->path_len) return 1;
    return 0;
}

static ok64 pid_collect(sha1 const *tree_sha, pid_collector *c) {
    sane(tree_sha && c);
    ok64 o = WALKTreeLazy(&KEEP, tree_sha->data, pid_visit, c);
    if (o == WALKSTOP && c->err != OK) return c->err;
    if (o != OK && o != WALKSTOP) return o;
    qsort(c->leaves, c->n, sizeof(pid_leaf), pid_leaf_cmp);
    done;
}

//  Resolve "tree <hex>" line + first "parent <hex>" line from a commit
//  body.  *got_parent stays NO when the commit is a root.
static ok64 pid_parse_commit(u8cs commit_body,
                             sha1 *tree_out,
                             sha1 *parent_out, b8 *got_parent) {
    sane(tree_out && parent_out && got_parent);
    *got_parent = NO;
    a_dup(u8c, scan, commit_body);
    u8cs field = {}, value = {};
    b8 got_tree = NO;
    while (GITu8sDrainCommit(scan, field, value) == OK) {
        if ($empty(field)) break;
        a_cstr(ft, "tree");
        a_cstr(fp, "parent");
        if ($eq(field, ft) && u8csLen(value) >= 40 && !got_tree) {
            if (DAGsha1FromHex(tree_out,
                               (char const *)value[0]) != OK)
                return GITBADFMT;
            got_tree = YES;
        } else if ($eq(field, fp) && u8csLen(value) >= 40 &&
                   !*got_parent) {
            if (DAGsha1FromHex(parent_out,
                               (char const *)value[0]) != OK)
                return GITBADFMT;
            *got_parent = YES;
        }
    }
    if (!got_tree) return GITBADFMT;
    done;
}

//  Two-tree lockstep diff producing the rolling RAPHashSeed digest.
static u64 pid_digest(pid_collector const *parent, pid_collector const *child) {
    u64 h = 0;
    u32 i = 0, j = 0;
    while (i < parent->n || j < child->n) {
        pid_leaf const *pl = (i < parent->n) ? &parent->leaves[i] : NULL;
        pid_leaf const *cl = (j < child->n)  ? &child->leaves[j]  : NULL;
        int c;
        if (pl == NULL) c = 1;
        else if (cl == NULL) c = -1;
        else {
            u32 ml = pl->path_len < cl->path_len ? pl->path_len : cl->path_len;
            c = (ml == 0) ? 0 : memcmp(pl->path, cl->path, ml);
            if (c == 0) {
                if (pl->path_len < cl->path_len) c = -1;
                else if (pl->path_len > cl->path_len) c = 1;
            }
        }

        u8c *path = NULL;
        u32 plen = 0;
        sha1 const *psha = NULL;
        sha1 const *csha = NULL;
        sha1 zero = {};
        if (c == 0) {
            path = pl->path; plen = pl->path_len;
            psha = &pl->sha; csha = &cl->sha;
            i++; j++;
            if (memcmp(psha->data, csha->data, 20) == 0) continue;
        } else if (c < 0) {
            //  parent has the path, child doesn't — deletion.
            path = pl->path; plen = pl->path_len;
            psha = &pl->sha; csha = &zero;
            i++;
        } else {
            //  child has the path, parent doesn't — addition.
            path = cl->path; plen = cl->path_len;
            psha = &zero; csha = &cl->sha;
            j++;
        }
        //  Fold (path | psha | csha) into the digest.  RAPHashSeed
        //  carries h forward without any allocation.
        u8cs ps = {path, path + plen};
        h = RAPHashSeed(ps, h);
        u8cs ss1 = {psha->data, psha->data + 20};
        h = RAPHashSeed(ss1, h);
        u8cs ss2 = {csha->data, csha->data + 20};
        h = RAPHashSeed(ss2, h);
    }
    return h;
}

u64 GRAFPatchId(u8csc commit_body) {
    if (!$ok(commit_body) || $empty(commit_body)) return 0;

    sha1 tree_c = {}, parent_sha = {};
    b8 has_parent = NO;
    a_dup(u8c, body_dup, commit_body);
    if (pid_parse_commit(body_dup, &tree_c,
                         &parent_sha, &has_parent) != OK) return 0;
    if (!has_parent) return 0;

    //  Resolve parent tree.
    Bu8 pbuf = {};
    if (u8bAllocate(pbuf, REBASE_OBJ_BUF) != OK) return 0;
    u8 ot = 0;
    if (KEEPGetExact(&KEEP, &parent_sha, pbuf, &ot) != OK
        || ot != DOG_OBJ_COMMIT) {
        u8bFree(pbuf); return 0;
    }
    sha1 tree_p = {}, dummy = {};
    b8 dummy_b = NO;
    a_dup(u8c, pcommit, u8bDataC(pbuf));
    if (pid_parse_commit(pcommit, &tree_p, &dummy, &dummy_b) != OK) {
        u8bFree(pbuf); return 0;
    }
    u8bFree(pbuf);

    //  Allocate parallel collectors.  Single arena per side.
    pid_collector pc = {}, cc = {};
    pc.cap = cc.cap = REBASE_TREE_ENTRIES;
    pc.arena_cap = cc.arena_cap = REBASE_TREE_ENTRIES * 64;
    pc.leaves = calloc(pc.cap, sizeof(pid_leaf));
    cc.leaves = calloc(cc.cap, sizeof(pid_leaf));
    pc.arena  = (u8 *)calloc(pc.arena_cap, 1);
    cc.arena  = (u8 *)calloc(cc.arena_cap, 1);
    if (!pc.leaves || !cc.leaves || !pc.arena || !cc.arena) goto fail;

    if (pid_collect(&tree_p, &pc) != OK) goto fail;
    if (pid_collect(&tree_c, &cc) != OK) goto fail;

    u64 h = pid_digest(&pc, &cc);
    free(pc.leaves); free(cc.leaves);
    free(pc.arena);  free(cc.arena);
    return h;
fail:
    if (pc.leaves) free(pc.leaves);
    if (cc.leaves) free(cc.leaves);
    if (pc.arena)  free(pc.arena);
    if (cc.arena)  free(cc.arena);
    return 0;
}

// ---------------------------------------------------------------------
//  Primitive 2: GRAFMergeExplicit
// ---------------------------------------------------------------------

//  Helper: fetch blob bytes by sha into `buf`.  Empty `buf` on
//  KEEPNONE so JOINMerge can degenerate gracefully.
static ok64 rebase_blob_at(u8 *const *buf, sha1 const *sha) {
    sane(buf);
    sha1 zero = {};
    if (memcmp(sha->data, zero.data, 20) == 0) return OK;  //  treat as empty
    u8 t = 0;
    ok64 o = KEEPGetExact(&KEEP, sha, buf, &t);
    if (o == KEEPNONE) return OK;
    if (o != OK) return o;
    if (t != DOG_OBJ_BLOB) return KEEPFAIL;
    done;
}

ok64 GRAFMergeExplicit(sha1 const *base, sha1 const *ours,
                       sha1 const *theirs, u8 *const *out) {
    sane(base && ours && theirs && out);

    Bu8 bbuf = {}, obuf = {}, tbuf = {};
    call(u8bMap, bbuf, REBASE_BLOB_MAX);
    call(u8bMap, obuf, REBASE_BLOB_MAX);
    call(u8bMap, tbuf, REBASE_BLOB_MAX);

    ok64 ret = OK;
    ret = rebase_blob_at(bbuf, base);
    if (ret == OK) ret = rebase_blob_at(obuf, ours);
    if (ret == OK) ret = rebase_blob_at(tbuf, theirs);
    if (ret != OK) goto cleanup;

    //  Tokenize each.  An empty side is fine: JOINTokenize on empty
    //  data yields zero tokens; JOINMerge handles that correctly.
    a_dup(u8c, bdata, u8bData(bbuf));
    a_dup(u8c, odata, u8bData(obuf));
    a_dup(u8c, tdata, u8bData(tbuf));

    JOINfile bjf = {}, ojf = {}, tjf = {};
    a_cstr(c_ext, "c");
    ret = JOINTokenize(&bjf, bdata, c_ext);
    if (ret == OK) ret = JOINTokenize(&ojf, odata, c_ext);
    if (ret == OK) ret = JOINTokenize(&tjf, tdata, c_ext);
    if (ret == OK) ret = JOINMerge(out, &bjf, &ojf, &tjf);

    JOINFree(&bjf);
    JOINFree(&ojf);
    JOINFree(&tjf);
cleanup:
    u8bUnMap(bbuf);
    u8bUnMap(obuf);
    u8bUnMap(tbuf);
    return ret;
}

// ---------------------------------------------------------------------
//  Primitive 3: GRAFRebase
// ---------------------------------------------------------------------

//  Tree-merge: produce a new tree body by recursively 3-way-merging
//  three input trees (base / ours / theirs).  Each entry is one of:
//    - present in all three with sha agreement       → pass-through
//    - present only in one side that diffs from base → that side's
//    - both sides diverged (modify/modify, both in base) → recurse
//      via leaf merge or sub-tree recursion
//    - exactly one side diffs from base              → that side's
//
//  Conflicts inside a leaf surface JOIN's `>>>>...||||...<<<<` markers,
//  which we detect post-merge to flag GRAFCNFL.

typedef struct {
    u8cs name;
    u8cs mode;
    sha1 sha;
    u8   kind;     //  WALK_KIND_*
    b8   present;
} tm_entry;

typedef struct {
    tm_entry *e;
    u32 n;
    u32 cap;
} tm_set;

//  Parse a tree body into entries.  `arena_out` buffer holds the
//  intern'd name+mode bytes.
static ok64 tm_parse(sha1 const *tree_sha, tm_set *out,
                     u8 *const *arena) {
    sane(out && arena);
    Bu8 tbuf = {};
    call(u8bAllocate, tbuf, REBASE_OBJ_BUF);
    u8 ot = 0;
    ok64 o = KEEPGetExact(&KEEP, tree_sha, tbuf, &ot);
    if (o != OK) { u8bFree(tbuf); return o; }
    if (ot != DOG_OBJ_TREE) { u8bFree(tbuf); fail(KEEPFAIL); }

    u8cs body = {u8bDataHead(tbuf), u8bIdleHead(tbuf)};
    u8cs file = {}, esha = {};
    while (GITu8sDrainTree(body, file, esha, NULL) == OK) {
        u8cs scan = {file[0], file[1]};
        if (u8csFind(scan, ' ') != OK) continue;
        u8cs mode_s = {file[0], scan[0]};
        u8cs name_s = {scan[0] + 1, file[1]};
        if ($empty(name_s) || u8csLen(esha) != 20) continue;
        if (out->n >= out->cap) break;

        //  Intern bytes into the arena.
        u8 *mb = u8bIdleHead(arena);
        if (u8bIdleLen(arena) < (u64)$len(mode_s) + (u64)$len(name_s)) break;
        memcpy(mb, mode_s[0], $len(mode_s));
        ((u8 **)arena)[2] += $len(mode_s);
        u8 *nb = u8bIdleHead(arena);
        memcpy(nb, name_s[0], $len(name_s));
        ((u8 **)arena)[2] += $len(name_s);

        tm_entry *e = &out->e[out->n++];
        e->mode[0] = mb;            e->mode[1] = mb + $len(mode_s);
        e->name[0] = nb;            e->name[1] = nb + $len(name_s);
        memcpy(e->sha.data, esha[0], 20);
        e->kind = WALKu8sModeKind(mode_s);
        e->present = YES;
    }
    u8bFree(tbuf);
    done;
}

static int tm_name_cmp(u8cs a, u8cs b) {
    size_t la = $len(a), lb = $len(b);
    size_t ml = la < lb ? la : lb;
    int c = (ml == 0) ? 0 : memcmp(a[0], b[0], ml);
    if (c != 0) return c;
    if (la < lb) return -1;
    if (la > lb) return 1;
    return 0;
}

static tm_entry *tm_find(tm_set *s, u8cs name) {
    for (u32 i = 0; i < s->n; i++) {
        if (tm_name_cmp(s->e[i].name, name) == 0) return &s->e[i];
    }
    return NULL;
}

//  Append one git-format tree entry "<mode> <name>\0<20-byte sha>" to `out`.
static ok64 tm_emit_entry(u8 *const *out, u8cs mode, u8cs name,
                          sha1 const *sha) {
    sane(out);
    call(u8bFeed, out, mode);
    call(u8bFeed1, out, ' ');
    call(u8bFeed, out, name);
    call(u8bFeed1, out, 0);
    u8cs sb = {sha->data, sha->data + 20};
    call(u8bFeed, out, sb);
    done;
}

//  Forward decl: recursive tree merge.
static ok64 tm_merge_trees(sha1 *tree_out_sha,
                           sha1 const *base_t, sha1 const *ours_t,
                           sha1 const *theirs_t,
                           graf_rebase_emit_cb cb, void *ctx,
                           b8 *had_conflict);

//  Detect JOIN's conflict markers in merged bytes.  JOIN emits ">>>>"
//  / "||||" / "<<<<" four-character runs around divergent inserts.
//  Scan once for a 4-byte run of '>' or '<'.
static b8 tm_has_conflict_v2(u8cs bytes) {
    if ($len(bytes) < 4) return NO;
    for (u8c *p = bytes[0]; p + 4 <= bytes[1]; p++) {
        if (p[0] == '>' && p[1] == '>' && p[2] == '>' && p[3] == '>')
            return YES;
        if (p[0] == '<' && p[1] == '<' && p[2] == '<' && p[3] == '<')
            return YES;
    }
    return NO;
}

//  Three-way leaf (blob) merge → emit a fresh blob if the merge
//  produces new bytes that don't already match base/ours/theirs.
//  Returns the canonical sha in `out_sha`; sets `*out_conflict` on
//  conflict.
static ok64 tm_merge_blob(sha1 *out_sha,
                          sha1 const *base, sha1 const *ours,
                          sha1 const *theirs,
                          graf_rebase_emit_cb cb, void *ctx,
                          b8 *out_conflict) {
    sane(out_sha && out_conflict);
    *out_conflict = NO;

    //  Trivial cases that avoid running JOIN entirely.
    if (memcmp(base->data, ours->data, 20) == 0) {
        *out_sha = *theirs; done;
    }
    if (memcmp(base->data, theirs->data, 20) == 0) {
        *out_sha = *ours;   done;
    }
    if (memcmp(ours->data, theirs->data, 20) == 0) {
        *out_sha = *ours;   done;
    }

    Bu8 mbuf = {};
    call(u8bMap, mbuf, REBASE_BLOB_MAX);
    ok64 o = GRAFMergeExplicit(base, ours, theirs, mbuf);
    if (o != OK) { u8bUnMap(mbuf); return o; }

    a_dup(u8c, mdata, u8bData(mbuf));
    if (tm_has_conflict_v2(mdata)) {
        *out_conflict = YES;
        u8bUnMap(mbuf);
        done;
    }

    KEEPObjSha(out_sha, DOG_OBJ_BLOB, mdata);
    if (cb != NULL) {
        ok64 eo = cb(ctx, DOG_OBJ_BLOB, out_sha, mdata);
        if (eo != OK) { u8bUnMap(mbuf); return eo; }
    }
    u8bUnMap(mbuf);
    done;
}

static ok64 tm_merge_trees(sha1 *tree_out_sha,
                           sha1 const *base_t, sha1 const *ours_t,
                           sha1 const *theirs_t,
                           graf_rebase_emit_cb cb, void *ctx,
                           b8 *had_conflict) {
    sane(tree_out_sha && had_conflict);

    //  Fast paths: agreement.
    if (memcmp(base_t->data, ours_t->data, 20) == 0) {
        *tree_out_sha = *theirs_t; done;
    }
    if (memcmp(base_t->data, theirs_t->data, 20) == 0) {
        *tree_out_sha = *ours_t; done;
    }
    if (memcmp(ours_t->data, theirs_t->data, 20) == 0) {
        *tree_out_sha = *ours_t; done;
    }

    //  Parse all three trees.
    tm_set bs = {}, os = {}, ts = {};
    bs.cap = os.cap = ts.cap = REBASE_TREE_ENTRIES;
    bs.e = calloc(bs.cap, sizeof(tm_entry));
    os.e = calloc(os.cap, sizeof(tm_entry));
    ts.e = calloc(ts.cap, sizeof(tm_entry));
    Bu8 arena = {};
    if (!bs.e || !os.e || !ts.e) { goto fail_alloc; }
    if (u8bAllocate(arena, REBASE_TREE_ENTRIES * 256) != OK) goto fail_alloc;

    ok64 ret = OK;
    ret = tm_parse(base_t,   &bs, arena);
    if (ret == OK) ret = tm_parse(ours_t,   &os, arena);
    if (ret == OK) ret = tm_parse(theirs_t, &ts, arena);
    if (ret != OK) goto cleanup;

    //  Build a deduplicated, sorted list of names across all three.
    u8cs *names = calloc(bs.n + os.n + ts.n + 1, sizeof(u8cs));
    if (!names) { ret = GRAFFAIL; goto cleanup; }
    u32 nnames = 0;
    for (u32 src = 0; src < 3; src++) {
        tm_set *s = (src == 0) ? &bs : (src == 1) ? &os : &ts;
        for (u32 i = 0; i < s->n; i++) {
            b8 dup = NO;
            for (u32 j = 0; j < nnames; j++) {
                if (tm_name_cmp(names[j], s->e[i].name) == 0) {
                    dup = YES; break;
                }
            }
            if (!dup) {
                names[nnames][0] = s->e[i].name[0];
                names[nnames][1] = s->e[i].name[1];
                nnames++;
            }
        }
    }
    //  Sort names.
    for (u32 i = 1; i < nnames; i++) {
        u8cs v = {names[i][0], names[i][1]};
        u32 j = i;
        while (j > 0 && tm_name_cmp(names[j - 1], v) > 0) {
            names[j][0] = names[j - 1][0];
            names[j][1] = names[j - 1][1];
            j--;
        }
        names[j][0] = v[0]; names[j][1] = v[1];
    }

    //  Build new tree body.
    Bu8 newtree = {};
    if (u8bAllocate(newtree, REBASE_OBJ_BUF) != OK) {
        free(names); ret = GRAFFAIL; goto cleanup;
    }

    for (u32 i = 0; i < nnames; i++) {
        u8cs name = {names[i][0], names[i][1]};
        tm_entry *be = tm_find(&bs, name);
        tm_entry *oe = tm_find(&os, name);
        tm_entry *te = tm_find(&ts, name);

        //  Modes / kinds: pick from any present (first found).
        tm_entry *any = oe ? oe : (te ? te : be);
        u8cs mode = {any->mode[0], any->mode[1]};

        sha1 zero = {};
        sha1 b_sha = be ? be->sha : zero;
        sha1 o_sha = oe ? oe->sha : zero;
        sha1 t_sha = te ? te->sha : zero;

        //  Modify/modify on a directory entry → recurse if it's a tree.
        u8 kind = any->kind;
        sha1 final = {};
        b8 keep = YES;

        if (kind == WALK_KIND_DIR && oe && te) {
            //  Recurse into the subtree triplet.  When `be` is absent,
            //  use empty tree sha (gives "addition both sides" semantics
            //  through the recursive function, though for now we just
            //  treat oe/te disagreement as a conflict if base absent).
            sha1 bsub = be ? be->sha : zero;
            ret = tm_merge_trees(&final, &bsub, &o_sha, &t_sha,
                                 cb, ctx, had_conflict);
            if (ret != OK) goto loop_fail;
            if (*had_conflict) { ret = GRAFCNFL; goto loop_fail; }
        } else if (oe && te) {
            //  Both sides present.
            if (memcmp(o_sha.data, t_sha.data, 20) == 0) {
                final = o_sha;
            } else if (be && memcmp(b_sha.data, o_sha.data, 20) == 0) {
                final = t_sha;
            } else if (be && memcmp(b_sha.data, t_sha.data, 20) == 0) {
                final = o_sha;
            } else if (kind == WALK_KIND_DIR) {
                ret = GRAFCNFL; *had_conflict = YES; goto loop_fail;
            } else {
                //  Both diverged from base — leaf 3-way merge.
                b8 cf = NO;
                ret = tm_merge_blob(&final, &b_sha, &o_sha, &t_sha,
                                    cb, ctx, &cf);
                if (ret != OK) goto loop_fail;
                if (cf) { *had_conflict = YES; ret = GRAFCNFL; goto loop_fail; }
            }
        } else if (oe && !te) {
            //  Only ours has it.
            if (be && memcmp(b_sha.data, o_sha.data, 20) == 0) {
                //  base had it, theirs deleted it, ours unchanged → drop.
                keep = NO;
            } else {
                final = o_sha;
            }
        } else if (!oe && te) {
            if (be && memcmp(b_sha.data, t_sha.data, 20) == 0) {
                keep = NO;
            } else {
                final = t_sha;
            }
        } else {
            //  Only base had it — both sides deleted → drop.
            keep = NO;
        }

        if (keep) {
            ret = tm_emit_entry(newtree, mode, name, &final);
            if (ret != OK) goto loop_fail;
        }
        continue;
    loop_fail:
        u8bFree(newtree);
        free(names);
        goto cleanup;
    }

    {
        a_dup(u8c, ntdata, u8bData(newtree));
        KEEPObjSha(tree_out_sha, DOG_OBJ_TREE, ntdata);
        if (cb != NULL) {
            ret = cb(ctx, DOG_OBJ_TREE, tree_out_sha, ntdata);
        }
    }

    u8bFree(newtree);
    free(names);
cleanup:
    if (u8bOK(arena)) u8bFree(arena);
    free(bs.e); free(os.e); free(ts.e);
    return ret;

fail_alloc:
    if (bs.e) free(bs.e);
    if (os.e) free(os.e);
    if (ts.e) free(ts.e);
    if (u8bOK(arena)) u8bFree(arena);
    { return GRAFFAIL; }
}

//  Walk parent chain: collect commit SHAs from `child_tip` back to
//  (but not including) `base_old`, oldest-first.
static ok64 rebase_walk_chain(sha1 const *child_tip, sha1 const *base_old,
                              sha1 *list, u32 *nlist, u32 maxlist) {
    sane(child_tip && base_old && list && nlist);
    u32 n = 0;
    sha1 cur = *child_tip;
    while (memcmp(cur.data, base_old->data, 20) != 0) {
        if (n >= maxlist) { return GRAFFAIL; }
        list[n++] = cur;
        Bu8 cbuf = {};
        if (u8bAllocate(cbuf, REBASE_OBJ_BUF) != OK) { return GRAFFAIL; }
        u8 ot = 0;
        ok64 o = KEEPGetExact(&KEEP, &cur, cbuf, &ot);
        if (o != OK || ot != DOG_OBJ_COMMIT) {
            u8bFree(cbuf); { return GRAFFAIL; }
        }
        sha1 tree_unused = {}, parent = {};
        b8 has_p = NO;
        a_dup(u8c, cbody, u8bDataC(cbuf));
        ok64 p = pid_parse_commit(cbody, &tree_unused, &parent, &has_p);
        u8bFree(cbuf);
        if (p != OK || !has_p) { return GRAFFAIL; }
        cur = parent;
    }
    //  Reverse to oldest-first.
    for (u32 i = 0; i < n / 2; i++) {
        sha1 t = list[i]; list[i] = list[n - 1 - i]; list[n - 1 - i] = t;
    }
    *nlist = n;
    done;
}

//  Build the patch-id set of every commit reachable from `base_new`
//  via parent chain.  Stops on root.  IDs are stored unsorted; lookup
//  is linear (small N typical).
static ok64 rebase_collect_pids(sha1 const *base_new, u64 *pids, u32 *n,
                                u32 maxn) {
    sane(base_new && pids && n);
    u32 cnt = 0;
    sha1 cur = *base_new;
    sha1 zero = {};
    if (memcmp(cur.data, zero.data, 20) == 0) { *n = 0; done; }
    for (;;) {
        Bu8 cbuf = {};
        if (u8bAllocate(cbuf, REBASE_OBJ_BUF) != OK) { return GRAFFAIL; }
        u8 ot = 0;
        ok64 o = KEEPGetExact(&KEEP, &cur, cbuf, &ot);
        if (o != OK || ot != DOG_OBJ_COMMIT) { u8bFree(cbuf); break; }
        a_dup(u8c, cbody, u8bDataC(cbuf));
        u64 pid = GRAFPatchId(cbody);
        if (cnt < maxn) pids[cnt++] = pid;
        sha1 tree_u = {}, parent = {};
        b8 has_p = NO;
        ok64 p = pid_parse_commit(cbody, &tree_u, &parent, &has_p);
        u8bFree(cbuf);
        if (p != OK || !has_p) break;
        cur = parent;
    }
    *n = cnt;
    done;
}

static b8 rebase_pid_seen(u64 const *pids, u32 n, u64 pid) {
    if (pid == 0) return NO;
    for (u32 i = 0; i < n; i++) if (pids[i] == pid) return YES;
    return NO;
}

//  Build a fresh commit body from an old one: replace tree, parent,
//  committer; preserve author, message; drop gpgsig.
static ok64 rebase_build_commit(u8 *const *out, u8csc old_body,
                                sha1 const *new_tree,
                                sha1 const *new_parent) {
    sane(out);

    //  Emit tree + parent first.
    a_cstr(tree_label, "tree ");
    call(u8bFeed, out, tree_label);
    a_pad(u8, thx, 40);
    a_rawc(ts, *new_tree);
    HEXu8sFeedSome(thx_idle, ts);
    call(u8bFeed, out, u8bDataC(thx));
    call(u8bFeed1, out, '\n');

    a_cstr(par_label, "parent ");
    call(u8bFeed, out, par_label);
    a_pad(u8, phx, 40);
    a_rawc(ps, *new_parent);
    HEXu8sFeedSome(phx_idle, ps);
    call(u8bFeed, out, u8bDataC(phx));
    call(u8bFeed1, out, '\n');

    //  Walk old headers — keep author* lines verbatim, replace
    //  committer with a deterministic stub, drop gpgsig+continuation.
    a_dup(u8c, scan, old_body);
    u8cs field = {}, value = {};
    u8cs body_rest = {};
    b8 in_gpgsig = NO;
    b8 emitted_committer = NO;
    while (GITu8sDrainCommit(scan, field, value) == OK) {
        if ($empty(field)) {
            //  Blank-line separator: `value` carries the body.
            body_rest[0] = value[0];
            body_rest[1] = value[1];
            break;
        }
        a_cstr(f_tree, "tree");
        a_cstr(f_par,  "parent");
        a_cstr(f_auth, "author");
        a_cstr(f_comm, "committer");
        a_cstr(f_gpg,  "gpgsig");
        if ($eq(field, f_tree) || $eq(field, f_par)) {
            in_gpgsig = NO;
            continue;
        }
        if ($eq(field, f_gpg)) { in_gpgsig = YES; continue; }
        if ($eq(field, f_comm)) {
            //  Replace committer with stub.
            in_gpgsig = NO;
            a_cstr(stub, "committer rebase <rebase@dogs> 0 +0000\n");
            call(u8bFeed, out, stub);
            emitted_committer = YES;
            continue;
        }
        if ($eq(field, f_auth)) {
            in_gpgsig = NO;
            call(u8bFeed, out, field);
            call(u8bFeed1, out, ' ');
            call(u8bFeed, out, value);
            call(u8bFeed1, out, '\n');
            continue;
        }
        //  gpgsig continuation lines start with ' '; the parser hands
        //  them back as field=" " value="…".  We rely on in_gpgsig to
        //  skip every header until the next non-continuation field.
        if (in_gpgsig && $len(field) >= 1 && *field[0] == ' ') continue;
        in_gpgsig = NO;
        //  Other arbitrary headers (encoding, mergetag, etc.) — copy.
        call(u8bFeed, out, field);
        call(u8bFeed1, out, ' ');
        call(u8bFeed, out, value);
        call(u8bFeed1, out, '\n');
    }

    if (!emitted_committer) {
        a_cstr(stub, "committer rebase <rebase@dogs> 0 +0000\n");
        call(u8bFeed, out, stub);
    }

    //  Blank line + body.
    call(u8bFeed1, out, '\n');
    if (!$empty(body_rest)) call(u8bFeed, out, body_rest);
    done;
}

ok64 GRAFRebase(sha1 const *base_old, sha1 const *base_new,
                sha1 const *child_tip,
                graf_rebase_emit_cb cb, void *ctx) {
    sane(base_old && base_new && child_tip);

    //  Trivial: child_tip == base_old → nothing to replay.
    if (memcmp(child_tip->data, base_old->data, 20) == 0) {
        done;
    }

    //  1. Walk chain.
    sha1 *chain = calloc(REBASE_PATH_MAX, sizeof(sha1));
    if (!chain) { return GRAFFAIL; }
    u32 nchain = 0;
    ok64 ret = rebase_walk_chain(child_tip, base_old,
                                 chain, &nchain, REBASE_PATH_MAX);
    if (ret != OK) { free(chain); return ret; }

    //  2. Patch-id set of base_new ancestors.
    u64 *pids = calloc(REBASE_PIDS_MAX, sizeof(u64));
    if (!pids) { free(chain); { return GRAFFAIL; } }
    u32 npids = 0;
    ret = rebase_collect_pids(base_new, pids, &npids, REBASE_PIDS_MAX);
    if (ret != OK) { free(chain); free(pids); return ret; }

    //  3. Replay loop.
    //  `head_body_cache` keeps the most-recently-emitted commit's
    //  bytes around so the next iteration can extract its tree
    //  without going through KEEPGetExact — the just-emitted commit
    //  lives in an in-progress (booked) pack that the keeper index
    //  doesn't see until the pack closes.
    sha1 head = *base_new;
    Bu8  head_body_cache = {};
    b8   head_body_cached = NO;
    for (u32 i = 0; i < nchain && ret == OK; i++) {
        sha1 const *cmt = &chain[i];

        //  Fetch commit body.
        Bu8 cbuf = {};
        if (u8bAllocate(cbuf, REBASE_OBJ_BUF) != OK) {
            { ret = GRAFFAIL; break; }
        }
        u8 ot = 0;
        if (KEEPGetExact(&KEEP, cmt, cbuf, &ot) != OK
            || ot != DOG_OBJ_COMMIT) {
            u8bFree(cbuf); { ret = GRAFFAIL; break; }
        }
        a_dup(u8c, cbody, u8bDataC(cbuf));

        //  Patch-id dedup.
        u64 pid = GRAFPatchId(cbody);
        if (rebase_pid_seen(pids, npids, pid)) {
            //  Skip this commit silently; head unchanged.
            u8bFree(cbuf);
            continue;
        }

        //  Resolve tree(parent), tree(running_head), tree(commit).
        sha1 tree_c = {}, parent_sha = {};
        b8 has_p = NO;
        ok64 p = pid_parse_commit(cbody, &tree_c,
                                  &parent_sha, &has_p);
        if (p != OK || !has_p) { u8bFree(cbuf); { ret = GRAFFAIL; break; } }

        sha1 tree_p = {}, tree_h = {};
        {
            //  Parent's tree — re-fetch parent commit body.
            Bu8 pbuf = {};
            if (u8bAllocate(pbuf, REBASE_OBJ_BUF) != OK) {
                u8bFree(cbuf); { ret = GRAFFAIL; break; }
            }
            u8 pt = 0;
            if (KEEPGetExact(&KEEP, &parent_sha, pbuf, &pt) != OK
                || pt != DOG_OBJ_COMMIT) {
                u8bFree(pbuf); u8bFree(cbuf); { ret = GRAFFAIL; break; }
            }
            sha1 dummy_par = {};
            b8 dummy_has = NO;
            a_dup(u8c, pbody, u8bDataC(pbuf));
            if (pid_parse_commit(pbody, &tree_p,
                                 &dummy_par, &dummy_has) != OK) {
                u8bFree(pbuf); u8bFree(cbuf); { ret = GRAFFAIL; break; }
            }
            u8bFree(pbuf);
        }
        {
            //  Running head's tree.  Use the cached body from the
            //  previous iteration's emit when available — the
            //  just-written commit isn't in keeper's indexed view
            //  until KEEPPackClose finalizes the pack.
            Bu8 hbuf = {};
            b8  hbuf_owned = NO;
            u8c *hbody_start = NULL;
            u8c *hbody_end   = NULL;
            if (head_body_cached) {
                hbody_start = u8bDataHead(head_body_cache);
                hbody_end   = u8bIdleHead(head_body_cache);
            } else {
                if (u8bAllocate(hbuf, REBASE_OBJ_BUF) != OK) {
                    u8bFree(cbuf); { ret = GRAFFAIL; break; }
                }
                hbuf_owned = YES;
                u8 ht = 0;
                if (KEEPGetExact(&KEEP, &head, hbuf, &ht) != OK
                    || ht != DOG_OBJ_COMMIT) {
                    u8bFree(hbuf); u8bFree(cbuf); { ret = GRAFFAIL; break; }
                }
                hbody_start = u8bDataHead(hbuf);
                hbody_end   = u8bIdleHead(hbuf);
            }
            sha1 dummy_par = {};
            b8 dummy_has = NO;
            u8cs hbody = {hbody_start, hbody_end};
            if (pid_parse_commit(hbody, &tree_h,
                                 &dummy_par, &dummy_has) != OK) {
                if (hbuf_owned) u8bFree(hbuf);
                u8bFree(cbuf); { ret = GRAFFAIL; break; }
            }
            if (hbuf_owned) u8bFree(hbuf);
        }

        //  3-way tree merge.
        sha1 new_tree = {};
        b8 conflict = NO;
        ret = tm_merge_trees(&new_tree, &tree_p, &tree_h, &tree_c,
                             cb, ctx, &conflict);
        if (ret == GRAFCNFL || conflict) {
            u8bFree(cbuf);
            ret = GRAFCNFL;
            break;
        }
        if (ret != OK) { u8bFree(cbuf); break; }

        //  Build + emit new commit.
        Bu8 cnew = {};
        if (u8bAllocate(cnew, REBASE_OBJ_BUF) != OK) {
            u8bFree(cbuf); { ret = GRAFFAIL; break; }
        }
        ret = rebase_build_commit(cnew, cbody, &new_tree, &head);
        if (ret != OK) { u8bFree(cnew); u8bFree(cbuf); break; }

        sha1 new_sha = {};
        a_dup(u8c, ndata, u8bData(cnew));
        KEEPObjSha(&new_sha, DOG_OBJ_COMMIT, ndata);
        if (cb != NULL) {
            ret = cb(ctx, DOG_OBJ_COMMIT, &new_sha, ndata);
        }
        //  Cache the emitted body so the next iteration can extract
        //  its tree without going through KEEPGetExact (the new
        //  commit lives in an in-progress pack until close).
        if (head_body_cached) {
            u8bFree(head_body_cache);
            head_body_cached = NO;
        }
        if (u8bAllocate(head_body_cache, REBASE_OBJ_BUF) == OK) {
            u8cs ndata_cs = {ndata[0], ndata[1]};
            if (u8bFeed(head_body_cache, ndata_cs) == OK) {
                head_body_cached = YES;
            } else {
                u8bFree(head_body_cache);
            }
        }
        u8bFree(cnew);
        u8bFree(cbuf);
        if (ret != OK) break;

        head = new_sha;
        //  Extend pid-set so subsequent commits in this loop don't
        //  re-emit equivalent diffs.
        if (npids < REBASE_PIDS_MAX && pid != 0) pids[npids++] = pid;
    }

    free(chain);
    free(pids);
    if (head_body_cached) u8bFree(head_body_cache);
    return ret;
}
