//  LOG: render commit history one-per-line for `be log:[path]?<ref>#<N>`.
//
//  Two shapes:
//    log:?<ref>#<N>           — branch history; walks parent chain
//                               from tip via the COMMIT_PARENT DAG.
//    log:./path/file.c?<ref>#<N>
//                             — file history; topo-walks the tip's
//                               ancestor closure newest-first, fetches
//                               the blob at `path` for each commit, and
//                               emits a row only when the blob bytes
//                               differ from the next-walked commit.
//
//  Output: one line per commit, "<sha7> <7-date> <message> (<author>)".
//
//  Streaming model: every commit is emitted as its own small hunk,
//  not one fat hunk at the end.  GRAFHunkEmit's `write()` to the bro
//  pipe blocks once the kernel buffer fills, so the producer is paced
//  by pager consumption — `be log:` can walk an arbitrarily long
//  history without buffering it.  When bro exits, write returns
//  EPIPE; GRAFHunkEmit zeroes graf_out_fd, and we detect that to
//  break the walk.
//
#include "GRAF.h"
#include "BLOB.h"
#include "DAG.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "abc/B.h"
#include "abc/FILE.h"
#include "abc/HEX.h"
#include "abc/PATH.h"
#include "abc/PRO.h"
#include "abc/URI.h"
#include "dog/DOG.h"
#include "dog/FRAG.h"
#include "dog/HUNK.h"
#include "dog/TOK.h"
#include "dog/WHIFF.h"
#include "keeper/GIT.h"
#include "keeper/KEEP.h"
#include "keeper/REFS.h"

//  No artificial cap on default `be log:` — backpressure (pipe write
//  blocks once the pager kernel-buffer fills) paces the producer.
//  `#N` is a hard ceiling when the caller wants one.
#define LOG_DEFAULT_COUNT 0xffffffffu
#define LOG_OBJ_BUF       (1UL << 20)
#define LOG_TEXT_BUF      (4UL << 20)   // one big hunk; ~40k commits @ 100B
#define LOG_TOKS_CAP      (1u << 16)    // tok32 entries (~9 per commit)
#define LOG_FILE_VERS_CAP (1u << 16)
#define LOG_ANC_SIZE      (1u << 18)

// --- Accumulator context ----------------------------------------------
//
//  Append-only render buffers shared across the whole walk.  Each
//  commit's row appends to `text` (and tok32 spans to `toks` in TLV
//  mode); GRAFHunkEmit is called once at the end with the merged
//  hunk, so HUNKu8sFeedText emits a single trailing blank line for
//  the whole log rather than one per commit.

typedef struct {
    Bu8   text;
    Bu32  toks;
    b8    tlv;
    i64   now;
} log_ctx;

// --- Helpers -----------------------------------------------------------

//  Resolve URI's `#hex`, `?ref`, or absent-query (use the wt's current
//  tip from sniff/at.log) to a 20-byte commit SHA-1.  Public so other
//  graf verbs (blame, etc.) can reuse the same resolution policy.
ok64 GRAFResolveTip(keeper *k, uricp u, sha1 *out) {
    sane(k && u && out);
    a_path(keepdir, u8bDataC(k->h->root), KEEP_DIR_S);

    if (!u8csEmpty(u->fragment) && u8csLen(u->fragment) >= 40) {
        u8s sb = {out->data, out->data + 20};
        u8cs hx = {u->fragment[0], u->fragment[0] + 40};
        return HEXu8sDrainSome(sb, hx);
    }

    //  Bare `log:` with no query — fall back to the wt's current tip
    //  parked in `k->h->cur_sha` by HOMEOpen (sourced from `--at`
    //  forwarded by `be`).  Mirrors `git log` defaulting to HEAD with
    //  no args.  Empty `cur_sha` (no `--at` forwarded — direct CLI
    //  invocation) falls through to REFS so a fresh clone still
    //  resolves trunk.
    if (u->query[0] == NULL) {
        if (u8bDataLen(k->h->cur_sha) == 40) {
            u8s sb = {out->data, out->data + 20};
            a_dup(u8c, hx, u8bData(k->h->cur_sha));
            return HEXu8sDrainSome(sb, hx);
        }
    }

    a_pad(u8, arena_buf, 1024);
    uri resolved = {};
    a_dup(u8c, in_uri, u->data);
    ok64 ro = REFSResolve(&resolved, arena_buf, $path(keepdir), in_uri);
    if (ro != OK) return ro;
    if (u8csLen(resolved.query) < 40) fail(GRAFFAIL);
    u8s sb = {out->data, out->data + 20};
    u8cs hx = {resolved.query[0], resolved.query[0] + 40};
    return HEXu8sDrainSome(sb, hx);
}

//  `#N` → cap; missing or non-numeric fragment → unlimited.
static u32 graflog_count_from_frag(uricp u) {
    if (u8csEmpty(u->fragment)) return LOG_DEFAULT_COUNT;
    frag f = {};
    a_dup(u8c, fr, u->fragment);
    if (FRAGu8sDrain(fr, &f) != OK) return LOG_DEFAULT_COUNT;
    if (f.type != FRAG_LINE || f.line == 0) return LOG_DEFAULT_COUNT;
    return f.line;
}

//  Parse "Name <email> ts tz" into (name, ts).  Best-effort.
static void graflog_parse_author(u8cs value, u8cs name_out, i64 *ts_out) {
    name_out[0] = name_out[1] = NULL;
    *ts_out = 0;
    if ($empty(value)) return;

    u8cp lt = value[0];
    while (lt < value[1] && *lt != '<') lt++;
    u8cp ne = lt;
    while (ne > value[0] && *(ne - 1) == ' ') ne--;
    name_out[0] = value[0];
    name_out[1] = ne;

    u8cp gt = lt;
    while (gt < value[1] && *gt != '>') gt++;
    if (gt < value[1]) gt++;
    while (gt < value[1] && *gt == ' ') gt++;
    i64 ts = 0;
    while (gt < value[1] && *gt >= '0' && *gt <= '9') {
        ts = ts * 10 + (*gt - '0');
        gt++;
    }
    *ts_out = ts;
}

static void graflog_pack(u32b toks, u8b out, u8 tag) {
    if (!$ok(toks)) return;
    (void)u32bFeed1(toks, tok32Pack(tag, (u32)u8bDataLen(out)));
}

//  Emit "<sha7> <7-date> <summary> (<author>)\n" with matching tok32
//  spans (toks may be the zero slice for plain-ASCII paths).  Tags
//  borrow dog/TOK.h: 'L' literal-shaped columns (sha + date), 'S'
//  message word, 'P' parens, 'D' de-emphasised author, 'W' whitespace.
static ok64 graflog_render_commit(u8b out, u32b toks,
                                  sha1 const *csha,
                                  u8cs commit_body, i64 now) {
    sane(csha);

    u8 hex[40];
    u8s hs = {hex, hex + 40};
    u8cs ss = {csha->data, csha->data + 20};
    HEXu8sFeedSome(hs, ss);
    u8cs sha7 = {hex, hex + 7};
    (void)u8bFeed(out, sha7);
    graflog_pack(toks, out, 'L');
    (void)u8bFeed1(out, ' ');
    graflog_pack(toks, out, 'W');

    u8cs author_val = {};
    u8cs message = {};
    a_dup(u8c, body, commit_body);
    u8cs field = {}, value = {};
    while (GITu8sDrainCommit(body, field, value) == OK) {
        if (u8csEmpty(field)) { $mv(message, value); break; }
        a_cstr(fa, "author");
        if ($eq(field, fa) && u8csEmpty(author_val)) $mv(author_val, value);
    }

    u8cs author_name = {};
    i64 ts = 0;
    graflog_parse_author(author_val, author_name, &ts);

    u8 date_buf[8];
    u8s date_into = {date_buf, date_buf + sizeof(date_buf)};
    u8cp date_start = date_into[0];
    (void)DOGutf8sFeedDate(date_into, ts, now);
    u8cs date_slice = {date_start, date_into[0]};
    (void)u8bFeed(out, date_slice);
    graflog_pack(toks, out, 'L');
    (void)u8bFeed1(out, ' ');
    graflog_pack(toks, out, 'W');

    u8cp ms = message[0];
    while (ms < message[1] && (*ms == '\n' || *ms == '\r')) ms++;
    u8cp me = ms;
    while (me < message[1] && *me != '\n' && *me != '\r') me++;
    if (me > ms) {
        u8cs summary = {ms, me};
        (void)u8bFeed(out, summary);
    }
    graflog_pack(toks, out, 'S');

    a_cstr(open_paren, " (");
    (void)u8bFeed(out, open_paren);
    graflog_pack(toks, out, 'P');
    if (!$empty(author_name)) (void)u8bFeed(out, author_name);
    graflog_pack(toks, out, 'D');
    (void)u8bFeed1(out, ')');
    graflog_pack(toks, out, 'P');

    (void)u8bFeed1(out, '\n');
    graflog_pack(toks, out, 'W');
    done;
}

//  Append one commit's row to the shared accumulator.  No emission
//  here — GRAFHunkEmit fires once at the end of GRAFLog with the
//  whole batch as a single hunk so HUNKu8sFeedText doesn't insert
//  a separator blank line between every commit.
static ok64 graflog_emit_one(log_ctx *lx, sha1 const *csha, u8cs body) {
    sane(lx);
    return graflog_render_commit(lx->text,
                                 lx->tlv ? lx->toks : NULL,
                                 csha, body, lx->now);
}

static void graflog_strip_dotslash(u8cs path) {
    if ($len(path) >= 2 && path[0][0] == '.' && path[0][1] == '/') {
        path[0] += 2;
    }
}

//  Branch-history: walk parent chain from tip via COMMIT_PARENT.
static ok64 graflog_branch(log_ctx *lx, keeper *k, sha1 const *tip,
                           u32 count) {
    sane(k && tip);
    Bu8 cbuf = {};
    call(u8bMap, cbuf, LOG_OBJ_BUF);

    u64 cur_h40 = WHIFFHashlet60(tip);
    for (u32 i = 0; i < count && cur_h40 != 0; i++) {
        if (graf_out_fd < 0) break;

        u8bReset(cbuf);
        u8 ot = 0;
        if (KEEPGet(k, cur_h40, DAG_H60_HEXLEN,
                    cbuf, &ot) != OK || ot != DOG_OBJ_COMMIT) break;
        a_dup(u8c, body, u8bData(cbuf));
        sha1 csha = {};
        KEEPObjSha(&csha, DOG_OBJ_COMMIT, body);

        if (graflog_emit_one(lx, &csha, body) != OK) break;

        //  First-parent walk via the DAG index (linear-history
        //  invariant — `parents[1+]` only appears for git-imported
        //  merges, which a `--first-parent`-style log skips by design).
        wh64 par_buf[2] = {};
        wh64s parents = {par_buf, par_buf + 2};
        wh64 *pbase = parents[0];
        wh128css runs = {NULL, NULL};
        GRAFRuns(runs);
        DAGParents(runs, parents, DAGPack(DAG_T_COMMIT, cur_h40));
        if (parents[0] == pbase) break;   // no parents → root commit
        cur_h40 = DAGHashlet(*pbase);
    }
    u8bUnMap(cbuf);
    done;
}

//  Walk commit `h40`'s tree to the entry at `path`; on success write its
//  20-byte SHA-1 to `*out` and set `*present = YES`.  On any miss
//  (commit absent, no tree header, path component missing) set
//  `*present = NO` and return OK — caller compares the (present, sha)
//  pair across commit/parents.  Uses caller-owned `cbuf` and `tbuf`
//  as reusable scratch so the hot loop allocates nothing.
static ok64 graflog_path_sha(sha1 *out, b8 *present, keeper *k, u64 h40,
                             u8cs path, Bu8 cbuf, Bu8 tbuf) {
    sane(out && present && k);
    *present = NO;

    u8bReset(cbuf);
    u8 ct = 0;
    if (KEEPGet(k, h40, DAG_H60_HEXLEN, cbuf, &ct) != OK ||
        ct != DOG_OBJ_COMMIT) done;

    sha1 cur = {};
    {
        a_dup(u8c, scan, u8bDataC(cbuf));
        u8cs field = {}, value = {};
        b8 got = NO;
        while (GITu8sDrainCommit(scan, field, value) == OK) {
            if (u8csEmpty(field)) break;
            a_cstr(ft, "tree");
            if ($eq(field, ft) && u8csLen(value) >= 40) {
                DAGsha1FromHex(&cur, (char const *)value[0]);
                got = YES;
                break;
            }
        }
        if (!got) done;
    }

    //  Walk down each tree level reusing `tbuf`.
    u8cs rest = {path[0], path[1]};
    while (!$empty(rest)) {
        u8cp slash = rest[0];
        while (slash < rest[1] && *slash != '/') slash++;
        u8cs name = {rest[0], slash};

        u8bReset(tbuf);
        u8 otype = 0;
        if (KEEPGetExact(k, &cur, tbuf, &otype) != OK) done;
        if (otype != DOG_OBJ_TREE) done;

        u8cs body = {u8bDataHead(tbuf), u8bIdleHead(tbuf)};
        u8cs field = {}, esha = {};
        b8 found = NO;
        while (GITu8sDrainTree(body, field, esha, NULL) == OK) {
            u8cs scan = {field[0], field[1]};
            if (u8csFind(scan, ' ') != OK) continue;
            u8cs entry_name = {scan[0] + 1, field[1]};
            if ($len(entry_name) != $len(name)) continue;
            if (memcmp(entry_name[0], name[0], $len(name)) != 0) continue;
            memcpy(cur.data, esha[0], 20);
            found = YES;
            break;
        }
        if (!found) done;
        rest[0] = (slash < rest[1]) ? slash + 1 : slash;
    }

    *out = cur;
    *present = YES;
    done;
}

//  File-history: walk the tip's ancestor closure and keep commits whose
//  leaf SHA at `path` differs from EVERY parent's leaf SHA at `path`,
//  mirroring `git log <path>`'s default simplification
//  (TREESAME-to-any-parent drops the commit).  Both presence-flips
//  count: parent-absent/child-present is an add, parent-present/
//  child-absent is a delete, SHA-difference is a modify.  Root commits
//  (no parents) are kept iff the file exists.  Bounded by `count`.
//
//  Per-commit leaf SHAs are cached in a parallel array indexed by
//  topo position; parents (always at lower topo idx) are looked up
//  via a flat back-scan so a parent's tree is walked only once across
//  the whole history — the dominant cost for long linear chains is one
//  tree-fetch per commit, not per (commit, parent) edge.
static ok64 graflog_file(log_ctx *lx, keeper *k, sha1 const *tip,
                         u8cs path, u32 count) {
    sane(k && tip && $ok(path));

    u64 tip_h40 = WHIFFHashlet60(tip);

    Bwh128 ancestors = {};
    call(wh128bAllocate, ancestors, LOG_ANC_SIZE);
    wh128css runs = {NULL, NULL};
    GRAFRuns(runs);
    DAGAncestors(ancestors, runs, tip_h40);

    //  Topo-sort parents-before-children, then walk in reverse for
    //  newest-first emission.
    size_t anc_cap = (size_t)(wh128bTerm(ancestors) - wh128bHead(ancestors));
    Bu8 ord_buf = {};
    if (u8bMap(ord_buf, anc_cap * sizeof(u64)) != OK) {
        if (wh128bHead(ancestors) != wh128bTerm(ancestors))
            wh128bFree(ancestors);
        fail(GRAFFAIL);
    }
    u64 *ordered = (u64 *)u8bDataHead(ord_buf);
    u32 nord = DAGTopoSort(ordered, (u32)anc_cap, ancestors, runs);

    Bu8 cbuf = {}, tbuf = {}, sha_buf = {}, keep_buf = {};
    if (u8bMap(cbuf,     LOG_OBJ_BUF)            != OK ||
        u8bMap(tbuf,     LOG_OBJ_BUF)            != OK ||
        u8bMap(sha_buf,  anc_cap * 21)           != OK ||
        u8bMap(keep_buf, anc_cap * sizeof(u64))  != OK) {
        if (cbuf[0])     u8bUnMap(cbuf);
        if (tbuf[0])     u8bUnMap(tbuf);
        if (sha_buf[0])  u8bUnMap(sha_buf);
        if (keep_buf[0]) u8bUnMap(keep_buf);
        u8bUnMap(ord_buf);
        if (wh128bHead(ancestors) != wh128bTerm(ancestors))
            wh128bFree(ancestors);
        fail(GRAFFAIL);
    }
    //  Per-commit leaf cache: 21 bytes = 1 present-flag + 20 SHA bytes,
    //  indexed by topo position.
    u8 *leaf = (u8 *)u8bDataHead(sha_buf);
    u64 *keep = (u64 *)u8bDataHead(keep_buf);
    u32 nkeep = 0;

    for (u32 i = 0; i < nord; i++) {
        u64 h40 = ordered[i];
        u8 *slot = leaf + (size_t)i * 21;
        slot[0] = 0;
        if (h40 == 0) continue;

        sha1 csha = {};
        b8   c_present = NO;
        (void)graflog_path_sha(&csha, &c_present, k, h40, path, cbuf, tbuf);
        slot[0] = c_present ? 1 : 0;
        if (c_present) memcpy(slot + 1, csha.data, 20);

        wh64  par_buf[16] = {};
        wh64s parents = {par_buf, par_buf + 16};
        wh64 *pbase = parents[0];
        DAGParents(runs, parents, DAGPack(DAG_T_COMMIT, h40));
        u32 npar = (u32)(parents[0] - pbase);

        b8 keep_it;
        if (npar == 0) {
            keep_it = c_present;
        } else {
            //  Differs from every parent → real change.  Bail to NO
            //  the moment a parent is TREESAME for `path`.  Parents
            //  always sit at a lower topo idx; back-scan ordered[].
            keep_it = YES;
            for (u32 pi = 0; pi < npar; pi++) {
                u64 ph40 = DAGHashlet(pbase[pi]);
                b8 found_idx = NO;
                u8 *p_slot = NULL;
                for (u32 j = i; j > 0; j--) {
                    if (ordered[j - 1] == ph40) {
                        p_slot = leaf + (size_t)(j - 1) * 21;
                        found_idx = YES;
                        break;
                    }
                }
                b8 p_present = (found_idx && p_slot[0]);
                b8 same = (c_present == p_present) &&
                          (!c_present ||
                           memcmp(slot + 1, p_slot + 1, 20) == 0);
                if (same) { keep_it = NO; break; }
            }
        }

        if (keep_it && nkeep < anc_cap) keep[nkeep++] = h40;
    }

    //  Emit newest-first.
    u32 emitted = 0;
    for (u32 ki = nkeep; ki > 0 && emitted < count; ki--) {
        if (graf_out_fd < 0) break;
        u64 h40 = keep[ki - 1];
        u8bReset(cbuf);
        u8 ot = 0;
        if (KEEPGet(k, h40, DAG_H60_HEXLEN,
                    cbuf, &ot) != OK || ot != DOG_OBJ_COMMIT) continue;
        a_dup(u8c, body, u8bData(cbuf));
        sha1 csha = {};
        KEEPObjSha(&csha, DOG_OBJ_COMMIT, body);
        if (graflog_emit_one(lx, &csha, body) != OK) break;
        emitted++;
    }

    u8bUnMap(tbuf);
    u8bUnMap(sha_buf);
    u8bUnMap(cbuf);
    u8bUnMap(keep_buf);
    u8bUnMap(ord_buf);
    if (wh128bHead(ancestors) != wh128bTerm(ancestors))
        wh128bFree(ancestors);
    done;
}

// --- Entry -------------------------------------------------------------

ok64 GRAFLog(keeper *k, uricp u) {
    sane(k && u);

    //  GRAFHunkEmit serialises into the legacy `graf_arena` global
    //  (separate from GRAF.arena).  Without init the arena is NULL
    //  and emission silently no-ops, so bro pages zero hunks.
    call(GRAFArenaInit);

    sha1 tip = {};
    call(GRAFResolveTip, k, u, &tip);

    u32 count = graflog_count_from_frag(u);

    log_ctx lx = {};
    lx.tlv = (graf_emit == HUNKu8sFeed);
    lx.now = (i64)time(NULL);

    call(u8bAllocate, lx.text, LOG_TEXT_BUF);
    if (lx.tlv) {
        ok64 to = u32bAllocate(lx.toks, LOG_TOKS_CAP);
        if (to != OK) { u8bFree(lx.text); return to; }
    }

    a_pad(u8, title, 256);
    a_cstr(prefix, "log:");
    (void)u8bFeed(title, prefix);
    if (!u8csEmpty(u->path)) (void)u8bFeed(title, u->path);
    if (!u8csEmpty(u->query)) {
        (void)u8bFeed1(title, '?');
        (void)u8bFeed(title, u->query);
    }

    u8cs path = {};
    u8csMv(path, u->path);
    graflog_strip_dotslash(path);

    ok64 go = GRAFOpen(k->h, NO);
    b8 own_open = (go == OK);
    if (go != OK && go != GRAFOPEN && go != GRAFOPENRO) {
        if (lx.tlv) u32bFree(lx.toks);
        u8bFree(lx.text);
        return go;
    }

    ok64 wo = $empty(path)
        ? graflog_branch(&lx, k, &tip, count)
        : graflog_file(&lx, k, &tip, path, count);

    if (wo == OK) {
        //  Single hunk for the whole walk — graf_emit (TLV via bro
        //  pipe, or HUNKu8sFeedText for terminal/pipe) picks bytes.
        hunk hk = {};
        hk.uri[0]  = u8bDataHead(title);
        hk.uri[1]  = u8bIdleHead(title);
        hk.text[0] = u8bDataHead(lx.text);
        hk.text[1] = u8bIdleHead(lx.text);
        if (lx.tlv) {
            hk.toks[0] = (u32 const *)u32bDataHead(lx.toks);
            hk.toks[1] = (u32 const *)u32bIdleHead(lx.toks);
        }
        (void)GRAFHunkEmit(&hk, NULL);
    }

    if (own_open) GRAFClose();
    if (lx.tlv) u32bFree(lx.toks);
    u8bFree(lx.text);
    return wo;
}
