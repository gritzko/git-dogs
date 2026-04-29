//  DAG: graf's object-graph index, streaming ingest.
//
//  Fed via GRAFUpdate one object at a time.  Keeper drives the
//  ingest in bulk (all-commits → all-trees → all-blobs) per pack;
//  each DOGUpdate call dispatches to one of three handlers here.
//  Finish runs at DOGClose, walks each new commit's tree top-down
//  (trees cached in-memory during the tree phase), and emits
//  PATH_VER events for each leaf whose blob was also freshly
//  delivered in this pack.  No historical keeper lookups.
//
//  Layout:
//      .dogs/graf/0000000001.idx   sorted wh128 runs (LSM)
//
#include "DAG.h"
#include "GRAF.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "abc/FILE.h"
#include "abc/HEX.h"
#include "abc/KV.h"
#include "abc/PATH.h"
#include "abc/PRO.h"
#include "abc/RAP.h"
#include "abc/RON.h"
#include "dog/DPATH.h"
#include "dog/SHA1.h"
#include "keeper/GIT.h"

// Resolve a 40-bit object hashlet.  Prefer the caller-supplied SHA
// (the UNPK hot path has it) — falls back to computing it from the
// object body for callers that don't (e.g. `graf index`'s manual
// reindex walk at graf/INDEX.c).
static u64 dag_obj_hashlet(u8 obj_type, sha1 const *sha, u8cs body) {
    if (sha) return WHIFFHashlet40(sha);

    char hdr[32];
    char const *tn = "blob";
    switch (obj_type) {
        case DOG_OBJ_COMMIT: tn = "commit"; break;
        case DOG_OBJ_TREE:   tn = "tree";   break;
        case DOG_OBJ_BLOB:   tn = "blob";   break;
        case DOG_OBJ_TAG:    tn = "tag";    break;
    }
    int hlen = snprintf(hdr, sizeof(hdr), "%s %zu",
                        tn, (size_t)u8csLen(body));
    if (hlen < 0 || (size_t)hlen >= sizeof(hdr)) return 0;

    SHA1state st;
    SHA1Open(&st);
    u8cs hs = {(u8cp)hdr, (u8cp)hdr + hlen + 1};  // include trailing NUL
    SHA1Feed(&st, hs);
    SHA1Feed(&st, body);
    sha1 out = {};
    SHA1DCFinal(out.data, &st);
    return WHIFFHashlet40(&out);
}

// --- Template instantiations for wh128 (sort, merge, hash).
// Bx.h already instantiated via dog/WHIFF.h.
#define X(M, name) M##wh128##name
#include "abc/QSORTx.h"
#include "abc/HITx.h"
#include "abc/HASHx.h"
#undef X

// --- HASHkv64: used for commit_h → tree_h side table during ingest ---

#define X(M, name) M##kv64##name
#include "abc/HASHx.h"
#undef X

// --- Constants ---

#define DAG_DIR         ".dogs/graf"
#define DAG_IDX_EXT     ".idx"
#define DAG_SEQNO_W     10
#define DAG_BATCH       (1 << 18)   // 256K entries per flush
#define DAG_OWNER_SIZE  (1 << 16)   // 64K slots in owner hashmap
#define DAG_TREEC_SIZE  (1 << 14)   // 16K slots in tree_cache
#define DAG_CTREE_SIZE  (1 << 12)   // 4K slots in commit_tree kv64
#define DAG_ENTRIES_CAP (1UL << 24) // 16MB tree-entries arena
#define DAG_MAX_TREE_ENTRIES 8192
#define DAG_PATH_BUF_SZ 4096

// Owner-map tag in key.type: only fresh-blob markers live here now.
// commit→gen and tree_h→(offset,nent) moved to separate kv64 maps.
#define DAG_OWN_FRESH   2   // key.off = blob_hashlet; val = 0

// --- Ingest state (opaque to callers) ---
//
//  Hash maps: `owner` is a wh128 set used only for "blob is fresh in
//  this session" — val is always 0 so wh128's (key+val) equality
//  works cleanly.  `commit_gen` and `tree_cache` carry non-zero
//  payloads in val and therefore must use kv64, whose equality and
//  hash are key-only.  Mixing key-payload wh128 with kv64 caused
//  `owner_get_commit` and `tree_cache_get` to silently miss — the
//  put-time hash differed from the get-time probe because wh128hash
//  folds val in.

struct dag_ingest {
    Bwh128  owner;          // set of fresh-in-session blob hashlets
    Bkv64   tree_cache;     // tree_h → (nent << 32) | arena_offset
    Bu8     entries;        // packed tree entries
    Bkv64   commit_tree;    // commit_h → tree_h
    Bkv64   commit_gen;     // commit_h → gen

    wh128  *batch;          // belt128 emit buffer
    size_t  batch_len;
    size_t  batch_cap;

    u64     seqno;
    u8      phase;          // 0=init, 1=commits, 2=trees, 3=blobs, 4=finished
    u8      finished;

    u8cs    dagdir;         // borrowed; points into graf state
    char    dagdir_buf[512];
};

#define DAG_PHASE_INIT    0
#define DAG_PHASE_COMMITS 1
#define DAG_PHASE_TREES   2
#define DAG_PHASE_BLOBS   3
#define DAG_PHASE_DONE    4

// --- COMMIT bookmark dir existence helpers ---

static b8 dag_is_hex_sha(char const *s, size_t len) {
    if (len < 40) return NO;
    for (int i = 0; i < 40; i++) {
        u8 c = (u8)s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return NO;
    }
    return YES;
}

// --- LSM file I/O ---

static ok64 dag_index_write(u8cs dagdir, wh128cs run, u64 seqno) {
    sane($ok(dagdir));
    if ($empty(run)) done;

    a_cstr(idxext, DAG_IDX_EXT);
    a_cstr(tmpsuf, ".tmp");

    //  Atomic publication: write <seqno>.idx.tmp, rename to
    //  <seqno>.idx.  Lockless readers in dag_stack_open filter by
    //  the exact ".idx" suffix, so the tmp file is invisible to
    //  them during the write window.
    a_pad(u8, path, FILE_PATH_MAX_LEN);
    call(u8bFeed, path, dagdir);
    call(u8bFeed1, path, '/');
    call(RONu8sFeedPad, u8bIdle(path), seqno, DAG_SEQNO_W);
    ((u8 **)path)[2] += DAG_SEQNO_W;
    call(u8bFeed, path, idxext);
    call(PATHu8bTerm, path);

    a_pad(u8, tmppath, FILE_PATH_MAX_LEN);
    call(u8bFeed, tmppath, dagdir);
    call(u8bFeed1, tmppath, '/');
    call(RONu8sFeedPad, u8bIdle(tmppath), seqno, DAG_SEQNO_W);
    ((u8 **)tmppath)[2] += DAG_SEQNO_W;
    call(u8bFeed, tmppath, idxext);
    call(u8bFeed, tmppath, tmpsuf);
    call(PATHu8bTerm, tmppath);

    int fd = -1;
    call(FILECreate, &fd, $path(tmppath));
    size_t bytes = $len(run) * sizeof(wh128);
    u8cs data = {(u8cp)run[0], (u8cp)run[0] + bytes};
    call(FILEFeedAll, fd, data);
    close(fd);
    call(FILERename, $path(tmppath), $path(path));
    done;
}

static ok64 dag_next_seqno(u64 *seqno, u8cs dagdir) {
    sane(seqno && $ok(dagdir));
    *seqno = 1;

    a_path(dpat);
    call(PATHu8bFeed, dpat, dagdir);

    DIR *d = opendir((char *)u8bDataHead(dpat));
    if (!d) done;
    u64 maxseq = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        size_t nlen = strlen(e->d_name);
        if (nlen != DAG_SEQNO_W + 4) continue;
        if (memcmp(e->d_name + DAG_SEQNO_W, DAG_IDX_EXT, 4) != 0) continue;
        u8cs numslice = {(u8cp)e->d_name, (u8cp)e->d_name + DAG_SEQNO_W};
        u64 val = 0;
        ok64 r = RONutf8sDrain(&val, numslice);
        if (r == OK && val > maxseq) maxseq = val;
    }
    closedir(d);
    *seqno = maxseq + 1;
    done;
}

// --- dag_stack (LSM read-side) ---

ok64 dag_stack_open(dag_stack *st, u8cs dagdir) {
    sane(st && $ok(dagdir));
    memset(st, 0, sizeof(*st));

    //  Lockless reader: list + mmap is racy against dag_compact,
    //  which unlinks old runs after writing the new merged one.
    //  If a just-listed run is missing at mmap time, the listing
    //  is stale — drop what we have and relist.  After compaction
    //  the merged run subsumes the unlinked ones, so a fresh scan
    //  is correct.  Bounded retries guard a pathological writer.
    ok64 last = OK;
    for (u32 attempt = 0; attempt < 4; attempt++) {
        dag_stack_close(st);
        memset(st, 0, sizeof(*st));

        a_path(dpat);
        call(PATHu8bFeed, dpat, dagdir);

        DIR *d = opendir((char *)u8bDataHead(dpat));
        if (!d) done;

        char names[MSET_MAX_LEVELS][64];
        char *namep[MSET_MAX_LEVELS];
        u32 count = 0;
        struct dirent *e;
        while ((e = readdir(d)) != NULL && count < MSET_MAX_LEVELS) {
            size_t nlen = strlen(e->d_name);
            if (nlen != DAG_SEQNO_W + 4) continue;
            if (memcmp(e->d_name + DAG_SEQNO_W, DAG_IDX_EXT, 4) != 0) continue;
            memcpy(names[count], e->d_name, nlen + 1);
            namep[count] = names[count];
            count++;
        }
        closedir(d);

        // Sort by name (oldest first)
        for (u32 i = 0; i + 1 < count; i++)
            for (u32 j = i + 1; j < count; j++)
                if (strcmp(namep[i], namep[j]) > 0) {
                    char *t = namep[i]; namep[i] = namep[j]; namep[j] = t;
                }

        b8 retry = NO;
        for (u32 i = 0; i < count; i++) {
            u8cs fn = {(u8cp)namep[i], (u8cp)namep[i] + strlen(namep[i])};
            a_path(fpath, dagdir, fn);

            u8bp mapped = NULL;
            ok64 mo = FILEMapRO(&mapped, $path(fpath));
            if (mo == FILENOENT) {
                retry = YES;
                break;
            }
            if (mo != OK) { last = mo; continue; }
            wh128cp base = (wh128cp)u8bDataHead(mapped);
            size_t nentries = (u8bIdleHead(mapped) - u8bDataHead(mapped)) / sizeof(wh128);
            st->runs[st->n][0] = base;
            st->runs[st->n][1] = base + nentries;
            st->maps[st->n] = mapped;
            st->n++;
        }
        if (!retry) done;
        last = FILENOENT;
    }
    dag_stack_close(st);
    memset(st, 0, sizeof(*st));
    return last;
}

void dag_stack_close(dag_stack *st) {
    if (!st) return;
    for (u32 i = 0; i < st->n; i++)
        if (st->maps[i]) FILEUnMap(st->maps[i]);
    st->n = 0;
}

// Look up COMMIT_GEN for a given commit hashlet in the persistent LSM.
// Returns 0 if not present.
static u32 dag_stack_commit_gen(dag_stack const *st, u64 commit_h) {
    return DAGCommitGen(st, commit_h);
}

// --- Graph-navigation primitives ---

u32 DAGParents(dag_stack const *idx, u64 commit_h, u64 *out, u32 cap) {
    if (!idx) return 0;
    u64 lo = DAGPack(DAG_COMMIT_PARENT, 0, commit_h);
    u64 hi = DAGPack(DAG_COMMIT_PARENT, WHIFF_ID_MASK, commit_h);
    u32 total = 0;
    for (u32 r = 0; r < idx->n; r++) {
        wh128cp base = idx->runs[r][0];
        size_t len = (size_t)(idx->runs[r][1] - base);
        size_t lo_i = 0, hi_i = len;
        while (lo_i < hi_i) {
            size_t mid = lo_i + (hi_i - lo_i) / 2;
            if (base[mid].key < lo) lo_i = mid + 1;
            else hi_i = mid;
        }
        while (lo_i < len && base[lo_i].key >= lo && base[lo_i].key <= hi) {
            if (DAGType(base[lo_i].key) == DAG_COMMIT_PARENT) {
                if (total < cap && out) {
                    out[total] = DAGHashlet(base[lo_i].val);
                }
                total++;
            }
            lo_i++;
        }
    }
    return total;
}

static ok64 dag_anc_put(Bwh128 set, u64 commit_h) {
    wh128 rec = {.key = wh64Pack(0, 0, commit_h), .val = 0};
    wh128s tab = {wh128bHead(set), wh128bTerm(set)};
    return HASHwh128Put(tab, &rec);
}

b8 DAGAncestorsHas(Bwh128 set, u64 commit_h) {
    wh128 probe = {.key = wh64Pack(0, 0, commit_h), .val = 0};
    wh128s tab = {wh128bHead(set), wh128bTerm(set)};
    return HASHwh128Get(&probe, tab) == OK;
}

ok64 DAGAncestors(Bwh128 set, dag_stack const *idx,
                  u64 tip, u32 cutoff_gen) {
    sane(idx);
    if (tip == 0) done;

    // BFS queue sized to match the set's capacity (the queue never
    // outgrows the set — every queue entry also lives in the set).
    size_t cap = (size_t)(wh128bTerm(set) - wh128bHead(set));
    if (cap == 0) return DAGFAIL;

    Bwh128 queue = {};
    call(wh128bMap, queue, cap);

    u32 tip_gen = DAGCommitGen(idx, tip);
    dag_anc_put(set, tip);
    wh128 q0 = {
        .key = wh64Pack(0, 0, tip),
        .val = wh64Pack(0, tip_gen, 0),
    };
    wh128bFeed1(queue, q0);

    size_t head = 0;
    u64 parents[16];
    while (head < wh128bDataLen(queue)) {
        wh128cp cur = wh128bDataHead(queue) + head;
        u64 c = DAGHashlet(cur->key);
        u32 c_gen = wh64Id(cur->val);
        head++;

        if (cutoff_gen && c_gen < cutoff_gen) continue;

        u32 np = DAGParents(idx, c, parents, 16);
        if (np > 16) np = 16;
        for (u32 i = 0; i < np; i++) {
            if (DAGAncestorsHas(set, parents[i])) continue;
            if (dag_anc_put(set, parents[i]) != OK) continue;
            u32 pg = DAGCommitGen(idx, parents[i]);
            wh128 qr = {
                .key = wh64Pack(0, 0, parents[i]),
                .val = wh64Pack(0, pg, 0),
            };
            if (wh128bFeed1(queue, qr) != OK) break;
        }
    }

    wh128bUnMap(queue);
    done;
}

ok64 DAGAncestorsOfMany(Bwh128 set, dag_stack const *idx,
                        u64 const *tips, u32 n) {
    sane(idx);
    for (u32 i = 0; i < n; i++) {
        if (tips[i] == 0) continue;
        call(DAGAncestors, set, idx, tips[i], 0);
    }
    done;
}

u32 DAGPathVers(graf_pathver *out, u32 maxvers,
                dag_stack const *idx,
                u8cs filepath,
                Bwh128 ancestors) {
    u64 path_h = RAPHash(filepath) & WHIFF_OFF_MASK;
    b8 has_filter = wh128bHead(ancestors) != wh128bTerm(ancestors);
    u32 count = 0;
    for (u32 r = 0; r < idx->n && count < maxvers; r++) {
        wh128cp base = idx->runs[r][0];
        size_t len = (size_t)(idx->runs[r][1] - base);
        for (size_t i = 0; i < len && count < maxvers; i++) {
            if (DAGType(base[i].key) != DAG_PATH_VER) continue;
            if (DAGHashlet(base[i].key) != path_h) continue;
            u64 c_h = DAGHashlet(base[i].val);
            if (has_filter && !DAGAncestorsHas(ancestors, c_h)) continue;
            out[count].gen = DAGGen(base[i].key);
            out[count].commit_hashlet = c_h;
            count++;
        }
    }

    // Sort by gen descending (newest first).
    for (u32 i = 1; i < count; i++) {
        for (u32 j = i; j > 0 && out[j].gen > out[j - 1].gen; j--) {
            graf_pathver tmp = out[j];
            out[j] = out[j - 1];
            out[j - 1] = tmp;
        }
    }
    return count;
}

// --- Compaction (merges multiple runs when newer is large vs older) ---

static ok64 dag_compact(u8cs dagdir) {
    sane($ok(dagdir));

    dag_stack st = {};
    call(dag_stack_open, &st, dagdir);
    if (st.n < 2) { dag_stack_close(&st); done; }

    wh128css stack = {st.runs, st.runs + st.n};
    if (HITwh128IsCompact(stack)) { dag_stack_close(&st); done; }

    size_t total = 0;
    for (u32 i = 0; i < st.n; i++)
        total += (size_t)(st.runs[i][1] - st.runs[i][0]);

    Bwh128 cbuf = {};
    call(wh128bAllocate, cbuf, total);

    //  HITCompact merges the youngest violators in-place against the
    //  stack, advancing `into` past the new run.  We need the merged
    //  slice for the .idx write; capture `into[0]` before the call so
    //  the [base, into[0]) range identifies the merged run after.
    wh128 *base = cbuf[0];
    wh128s into = {cbuf[0], cbuf[3]};
    size_t before_len = $len(stack);
    call(HITwh128Compact, stack, into);
    size_t m = before_len - $len(stack) + 1;
    if (m < 2) {
        wh128bFree(cbuf);
        dag_stack_close(&st);
        done;
    }

    u64 seqno = 0;
    call(dag_next_seqno, &seqno, dagdir);
    wh128cs merged = {(wh128cp)base, (wh128cp)(into[0])};
    call(dag_index_write, dagdir, merged, seqno);

    // Collect and unlink the old files (skip the one we just wrote).
    char fnames[MSET_MAX_LEVELS][64];
    u32 fcount = 0;
    {
        a_path(dpat);
        call(PATHu8bFeed, dpat, dagdir);
        DIR *d2 = opendir((char *)u8bDataHead(dpat));
        if (d2) {
            struct dirent *e2;
            while ((e2 = readdir(d2)) != NULL && fcount < MSET_MAX_LEVELS) {
                size_t nlen = strlen(e2->d_name);
                if (nlen != DAG_SEQNO_W + 4) continue;
                if (memcmp(e2->d_name + DAG_SEQNO_W, DAG_IDX_EXT, 4) != 0) continue;
                memcpy(fnames[fcount], e2->d_name, nlen + 1);
                fcount++;
            }
            closedir(d2);
        }
    }
    for (u32 i = 0; i + 1 < fcount; i++)
        for (u32 j = i + 1; j < fcount; j++)
            if (strcmp(fnames[i], fnames[j]) > 0) {
                char tmp[64];
                memcpy(tmp, fnames[i], 64);
                memcpy(fnames[i], fnames[j], 64);
                memcpy(fnames[j], tmp, 64);
            }

    dag_stack_close(&st);

    u32 unlinked = 0;
    for (u32 i = 0; i < fcount && unlinked < m; i++) {
        u8cs numslice = {(u8cp)fnames[i], (u8cp)fnames[i] + DAG_SEQNO_W};
        u64 fseq = 0;
        RONutf8sDrain(&fseq, numslice);
        if (fseq == seqno) continue;
        u8cs fn = {(u8cp)fnames[i], (u8cp)fnames[i] + strlen(fnames[i])};
        a_path(ulpath, dagdir, fn);
        unlink((char *)u8bDataHead(ulpath));
        unlinked++;
    }

    wh128bFree(cbuf);
    done;
}

// --- Ingest state management ---

static ok64 dag_ingest_alloc(dag_ingest **out, u8cs dagdir) {
    sane(out && $ok(dagdir));
    *out = NULL;

    dag_ingest *g = calloc(1, sizeof(*g));
    if (!g) return DAGFAIL;

    // dagdir copy (caller's buffer may be transient)
    size_t dlen = $len(dagdir);
    if (dlen >= sizeof(g->dagdir_buf)) { free(g); return DAGFAIL; }
    memcpy(g->dagdir_buf, dagdir[0], dlen);
    g->dagdir_buf[dlen] = 0;
    g->dagdir[0] = (u8p)g->dagdir_buf;
    g->dagdir[1] = (u8p)g->dagdir_buf + dlen;

    if (wh128bAllocate(g->owner, DAG_OWNER_SIZE) != OK) goto fail;
    if (kv64bAllocate(g->tree_cache, DAG_TREEC_SIZE) != OK) goto fail;
    if (u8bMap(g->entries, DAG_ENTRIES_CAP) != OK) goto fail;
    if (kv64bAllocate(g->commit_tree, DAG_CTREE_SIZE) != OK) goto fail;
    if (kv64bAllocate(g->commit_gen, DAG_CTREE_SIZE) != OK) goto fail;

    g->batch_cap = DAG_BATCH;
    g->batch = calloc(g->batch_cap, sizeof(wh128));
    if (!g->batch) goto fail;

    g->phase = DAG_PHASE_INIT;
    call(dag_next_seqno, &g->seqno, g->dagdir);

    *out = g;
    done;

fail:
    if (g->owner[0])       wh128bFree(g->owner);
    if (g->tree_cache[0])  kv64bFree(g->tree_cache);
    if (g->entries[0])     u8bUnMap(g->entries);
    if (g->commit_tree[0]) kv64bFree(g->commit_tree);
    if (g->commit_gen[0])  kv64bFree(g->commit_gen);
    free(g->batch);
    free(g);
    return DAGFAIL;
}

static void dag_ingest_free(dag_ingest *g) {
    if (!g) return;
    if (g->owner[0])       wh128bFree(g->owner);
    if (g->tree_cache[0])  kv64bFree(g->tree_cache);
    if (g->entries[0])     u8bUnMap(g->entries);
    if (g->commit_tree[0]) kv64bFree(g->commit_tree);
    if (g->commit_gen[0])  kv64bFree(g->commit_gen);
    free(g->batch);
    free(g);
}

// --- Emit helpers ---

static void dag_emit(dag_ingest *g,
                     u8 atype, u32 agen, u64 ahash,
                     u8 btype, u32 bgen, u64 bhash) {
    if (g->batch_len >= g->batch_cap) return;  // overflow; handled by flush
    g->batch[g->batch_len++] = DAGEntry(atype, agen, ahash,
                                        btype, bgen, bhash);
}

static ok64 dag_flush_batch(dag_ingest *g) {
    sane(g);
    if (g->batch_len == 0) done;
    wh128s d = {g->batch, g->batch + g->batch_len};
    wh128sSort(d);
    wh128sDedup(d);
    g->batch_len = (size_t)(d[1] - d[0]);
    wh128cs run = {g->batch, g->batch + g->batch_len};
    call(dag_index_write, g->dagdir, run, g->seqno);
    g->seqno++;
    g->batch_len = 0;
    done;
}

static void dag_batch_maybe_flush(dag_ingest *g) {
    if (g->batch_len + 64 >= g->batch_cap) dag_flush_batch(g);
}

// --- commit_gen map (kv64: key=commit_h, val=gen) ---

static ok64 commit_gen_put(dag_ingest *g, u64 commit_h, u32 gen) {
    kv64 rec = {.key = commit_h, .val = (u64)gen};
    kv64s tab = {kv64bHead(g->commit_gen), kv64bTerm(g->commit_gen)};
    return HASHkv64Put(tab, &rec);
}

static u32 commit_gen_get(dag_ingest *g, u64 commit_h) {
    kv64 probe = {.key = commit_h, .val = 0};
    kv64s tab = {kv64bHead(g->commit_gen), kv64bTerm(g->commit_gen)};
    if (HASHkv64Get(&probe, tab) != OK) return 0;
    return (u32)probe.val;
}

// --- Owner map ops (fresh-blob set only) ---

// Insert (OWN_FRESH, blob_h) → presence.
static ok64 owner_mark_fresh(dag_ingest *g, u64 blob_h) {
    wh128 rec = {
        .key = wh64Pack(DAG_OWN_FRESH, 0, blob_h),
        .val = 0,
    };
    wh128s tab = {wh128bHead(g->owner), wh128bTerm(g->owner)};
    return HASHwh128Put(tab, &rec);
}

static b8 owner_is_fresh(dag_ingest *g, u64 blob_h) {
    wh128 probe = {
        .key = wh64Pack(DAG_OWN_FRESH, 0, blob_h),
        .val = 0,
    };
    wh128s tab = {wh128bHead(g->owner), wh128bTerm(g->owner)};
    ok64 o = HASHwh128Get(&probe, tab);
    return o == OK;
}

// --- Tree cache: tree_h → (arena offset, entry count) ---
//
//  Entry record packed in `entries` arena per tree:
//    [u32 n_entries]
//    repeated: { u8 kind (1=tree,0=blob), u8 name_len,
//                u64 child_hashlet, char name[name_len] }
//
//  Map type is kv64; val packs (nent << 32) | offset.  Offset fits
//  in 32 bits by the arena's 16 MB cap, nent is capped at
//  DAG_MAX_TREE_ENTRIES which is well under 2^32.

static ok64 tree_cache_put(dag_ingest *g, u64 tree_h, u32 offset, u32 nent) {
    kv64 rec = {.key = tree_h,
                .val = ((u64)nent << 32) | (u64)offset};
    kv64s tab = {kv64bHead(g->tree_cache), kv64bTerm(g->tree_cache)};
    return HASHkv64Put(tab, &rec);
}

static ok64 tree_cache_get(dag_ingest *g, u64 tree_h,
                            u32 *offset, u32 *nent) {
    kv64 probe = {.key = tree_h, .val = 0};
    kv64s tab = {kv64bHead(g->tree_cache), kv64bTerm(g->tree_cache)};
    if (HASHkv64Get(&probe, tab) != OK) return HASHNONE;
    *offset = (u32)(probe.val & 0xFFFFFFFFull);
    *nent   = (u32)(probe.val >> 32);
    return OK;
}

// --- Phase transitions ---

static ok64 dag_phase_to(dag_ingest *g, u8 target) {
    sane(g);
    if (g->phase >= target) done;
    g->phase = target;
    done;
}

// --- Tree ingest: parse entries, stash in tree_cache. ---

static ok64 dag_ingest_tree(dag_ingest *g, u8cs tree_blob, u64 tree_h) {
    sane(g && $ok(tree_blob));
    call(dag_phase_to, g, DAG_PHASE_TREES);

    u8p base = u8bIdleHead(g->entries);
    if (u8bIdleLen(g->entries) < 4) return DAGNOROOM;

    // Reserve 4 bytes for entry count (written at end).
    u32 *nent_slot = (u32 *)base;
    u32 nent = 0;
    ((u8 **)g->entries)[2] += 4;

    a_dup(u8c, scan, tree_blob);
    u8cs file = {}, sha = {};
    while (nent < DAG_MAX_TREE_ENTRIES &&
           GITu8sDrainTree(scan, file, sha) == OK) {
        // Split "<mode> <name>" at space.
        u8cp spc = file[0];
        while (spc < file[1] && *spc != ' ') spc++;
        if (spc >= file[1]) continue;
        u8cp mode_p = file[0];
        u8cp name_p = spc + 1;
        u8cp name_e = file[1];

        size_t nlen = (size_t)(name_e - name_p);
        if (nlen == 0 || nlen > 255) continue;
        if (u8csLen(sha) != 20) continue;

        // Layout: 1 byte kind, 1 byte name_len, 8 bytes hashlet, nlen name bytes.
        size_t need = 10 + nlen;
        if (u8bIdleLen(g->entries) < need) return DAGNOROOM;

        u8 kind = (*mode_p == '4') ? 1 : 0;  // "40000" → subtree
        u64 ch = WHIFFHashlet40((sha1cp)sha[0]);

        u8p w = u8bIdleHead(g->entries);
        w[0] = kind;
        w[1] = (u8)nlen;
        memcpy(w + 2, &ch, 8);
        memcpy(w + 10, name_p, nlen);
        ((u8 **)g->entries)[2] += need;
        nent++;
    }

    *nent_slot = nent;
    u32 offset = (u32)(base - u8bDataHead(g->entries));
    return tree_cache_put(g, tree_h, offset, nent);
}

// --- Blob ingest: mark fresh. ---

static ok64 dag_ingest_blob(dag_ingest *g, u64 blob_h) {
    sane(g);
    call(dag_phase_to, g, DAG_PHASE_BLOBS);
    return owner_mark_fresh(g, blob_h);
}

// --- Finish walk: DFS each commit's root tree, emit PATH_VER. ---

typedef struct {
    u8 kind;
    u8 name_len;
    u64 child_h;
    u8cp name;
} tree_entry;

static b8 tree_entry_read(dag_ingest *g, u32 *off, u32 remain,
                          tree_entry *out) {
    u8cp base = u8bDataHead(g->entries);
    u8cp end = u8bIdleHead(g->entries);
    (void)remain;
    if (base + *off + 10 > end) return NO;
    u8cp p = base + *off;
    out->kind = p[0];
    out->name_len = p[1];
    memcpy(&out->child_h, p + 2, 8);
    out->name = p + 10;
    if (p + 10 + out->name_len > end) return NO;
    *off += 10 + out->name_len;
    return YES;
}

static ok64 dag_walk_tree(dag_ingest *g, u64 tree_h,
                           u32 gen, u64 commit_h,
                           u8p pbuf, size_t pcap, size_t path_off);

static ok64 dag_walk_leaf(dag_ingest *g, tree_entry const *e,
                           u32 gen, u64 commit_h,
                           u8p pbuf, size_t pcap, size_t path_off) {
    sane(g && e);
    if (!owner_is_fresh(g, e->child_h)) return OK;

    if (path_off + 1 + e->name_len >= pcap) return DAGNOROOM;

    size_t w = path_off;
    if (w > 0 && pbuf[w - 1] != '/') {
        pbuf[w++] = '/';
    }
    memcpy(pbuf + w, e->name, e->name_len);
    w += e->name_len;

    u8csc path = {pbuf, pbuf + w};
    u64 path_h = RAPHash(path) & WHIFF_OFF_MASK;

    dag_emit(g, DAG_PATH_VER, gen, path_h,
                DAG_PATH_VER, gen, commit_h);
    dag_batch_maybe_flush(g);
    return OK;
}

static ok64 dag_walk_tree(dag_ingest *g, u64 tree_h,
                           u32 gen, u64 commit_h,
                           u8p pbuf, size_t pcap, size_t path_off) {
    sane(g);
    u32 offset = 0, nent = 0;
    if (tree_cache_get(g, tree_h, &offset, &nent) != OK) {
        return OK;
    }
    u32 cur = offset + 4;
    for (u32 i = 0; i < nent; i++) {
        tree_entry e = {};
        if (!tree_entry_read(g, &cur, 0, &e)) break;
        if (e.kind == 0) {
            dag_walk_leaf(g, &e, gen, commit_h, pbuf, pcap, path_off);
        } else {
            size_t w = path_off;
            if (w > 0 && pbuf[w - 1] != '/') {
                if (w + 1 >= pcap) continue;
                pbuf[w++] = '/';
            }
            if (w + e.name_len >= pcap) continue;
            memcpy(pbuf + w, e.name, e.name_len);
            w += e.name_len;
            dag_walk_tree(g, e.child_h, gen, commit_h, pbuf, pcap, w);
        }
    }
    done;
}

static ok64 dag_finish(dag_ingest *g) {
    sane(g);
    if (g->finished) done;

    // Walk each commit's root tree.  commit_tree is a kv64 open-addressed
    // hash; iterate the whole buffer and skip zero cells.
    size_t n = (size_t)(kv64bTerm(g->commit_tree) - kv64bHead(g->commit_tree));
    u8 path_buf[DAG_PATH_BUF_SZ];
    kv64 *base = kv64bHead(g->commit_tree);
    for (size_t i = 0; i < n; i++) {
        kv64 *cell = base + i;
        if (cell->key == 0 && cell->val == 0) continue;
        u64 commit_h = cell->key;
        u64 tree_h = cell->val;
        u32 gen = commit_gen_get(g, commit_h);
        if (gen == 0) continue;
        dag_walk_tree(g, tree_h, gen, commit_h,
                      path_buf, DAG_PATH_BUF_SZ, 0);
    }

    call(dag_flush_batch, g);
    dag_compact(g->dagdir);
    g->finished = 1;
    done;
}

// ============================================================
// Public entry: GRAFUpdate
// ============================================================

// This is the real meat the GRAFUpdate wrapper calls into.  `state`
// is graf's own state (struct graf from GRAF.h).  We reach into
// state->ing to lazily allocate the ingest context.  Forward-decl
// of struct graf comes from GRAF.h include above.

ok64 GRAFDagUpdate(u8 obj_type, sha1 const *sha, u8cs blob) {
    sane(1);
    graf *state = &GRAF;

    // Lazy allocate ingest state on first call.
    if (!state->ing) {
        a_dup(u8c, root_s, u8bDataC(state->h->root));
        a_path(dp, root_s);
        a_cstr(rel, "/" DAG_DIR);
        call(u8bFeed, dp, rel);
        call(PATHu8bTerm, dp);
        a_dup(u8c, dagdir, u8bDataC(dp));
        call(FILEMakeDirP, $path(dp));
        call(dag_ingest_alloc, &state->ing, dagdir);
    }

    dag_ingest *g = state->ing;

    switch (obj_type) {
    case DOG_OBJ_COMMIT: {
        // Parse commit header for tree_h and parents[].
        a_dup(u8c, scan, blob);
        u8cs field = {}, value = {};
        sha1 tree_sha = {};
        sha1 parents[16] = {};
        u32 npar = 0;
        b8 got_tree = NO;
        while (GITu8sDrainCommit(scan, field, value) == OK) {
            if (u8csEmpty(field)) break;
            a_cstr(ft, "tree");
            a_cstr(fp, "parent");
            if ($eq(field, ft) && u8csLen(value) >= 40) {
                DAGsha1FromHex(&tree_sha, (char const *)value[0]);
                got_tree = YES;
            } else if ($eq(field, fp) && u8csLen(value) >= 40 && npar < 16) {
                DAGsha1FromHex(&parents[npar], (char const *)value[0]);
                npar++;
            }
        }
        if (!got_tree) return DAGFAIL;

        u64 commit_h = dag_obj_hashlet(DOG_OBJ_COMMIT, sha, blob);

        u64 tree_h = WHIFFHashlet40(&tree_sha);

        // Compute gen = max(parent gens) + 1.  Look up via owner map
        // (this pack) then via LSM (prior packs).
        u32 gen = 1;
        u64 parent_hs[16] = {};
        u32 parent_gens[16] = {};
        for (u32 i = 0; i < npar; i++) {
            parent_hs[i] = WHIFFHashlet40(&parents[i]);
            u32 pg = commit_gen_get(g, parent_hs[i]);
            if (pg == 0) pg = dag_stack_commit_gen(&state->idx, parent_hs[i]);
            parent_gens[i] = pg;
            if (pg >= gen) gen = pg + 1;
        }

        // Emit COMMIT_GEN, COMMIT_TREE, COMMIT_PARENT[].
        dag_emit(g, DAG_COMMIT_GEN, gen, commit_h,
                    DAG_COMMIT_GEN, gen, commit_h);
        dag_emit(g, DAG_COMMIT_TREE, gen, commit_h,
                    DAG_COMMIT_TREE, gen, tree_h);
        for (u32 i = 0; i < npar; i++) {
            dag_emit(g, DAG_COMMIT_PARENT, gen, commit_h,
                        DAG_COMMIT_PARENT, parent_gens[i], parent_hs[i]);
        }

        // Stash commit→tree and commit→gen.
        kv64 ct = {.key = commit_h, .val = tree_h};
        kv64s ctab = {kv64bHead(g->commit_tree), kv64bTerm(g->commit_tree)};
        HASHkv64Put(ctab, &ct);
        commit_gen_put(g, commit_h, gen);

        dag_batch_maybe_flush(g);
        done;
    }

    case DOG_OBJ_TREE: {
        u64 tree_h = dag_obj_hashlet(DOG_OBJ_TREE, sha, blob);
        return dag_ingest_tree(g, blob, tree_h);
    }

    case DOG_OBJ_BLOB: {
        //  Path is recovered later by the finish-time tree walk.
        u64 blob_h = dag_obj_hashlet(DOG_OBJ_BLOB, sha, blob);
        return dag_ingest_blob(g, blob_h);
    }

    default:
        done;  // ignore DOG_OBJ_TAG etc.
    }
}

ok64 GRAFDagFinish(void) {
    sane(1);
    graf *state = &GRAF;
    if (!state->ing) done;
    ok64 r = dag_finish(state->ing);
    dag_ingest_free(state->ing);
    state->ing = NULL;
    return r;
}
