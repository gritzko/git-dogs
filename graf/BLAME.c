//  BLAME: token-level blame via keeper object store + DAG index.
//
//  Walks file history via DAG index (PATH_VER + PREV_BLOB chain),
//  fetches blobs via KEEPGet, builds a weave from successive blob
//  versions, renders blame annotations per line.
//
//  WEAVE DIFF: resolves refs via KEEPWalk, fetches blobs, runs
//  pairwise token-level diff via DIFFu8cs.
//
#include "GRAF.h"
#include "BLOB.h"
#include "DAG.h"
#include "TDIFF.h"
#include "WEAVE.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "abc/FILE.h"
#include "abc/HEX.h"
#include "abc/PATH.h"
#include "abc/PRO.h"
#include "abc/RAP.h"
#include "abc/UTF8.h"
#include "dog/HUNK.h"
#include "dog/WHIFF.h"
#include "keeper/GIT.h"
#include "keeper/REFS.h"

#define BLAME_MAX_VERS 256
#define BLAME_MAX_AUTHORS 256

//  Sentinel `src` for the worktree shadow version (uncommitted edits).
//  Real WHIFFHashlet40 truncations land in the bottom 32 bits — full
//  0xFFFFFFFF is overwhelmingly likely to be free.
#define BLAME_WT_SRC 0xFFFFFFFFu

// --- Author table: gen → author + date ---

typedef struct {
    u32  gen;
    u64  commit_hashlet;
    char author[48];
    char date[12];   // YYYY-MM-DD
} blame_author;

// --- UTF-8 aware fixed-width field: truncate to N codepoints, pad right ---

static void blame_fixfield(char *out, size_t outsz,
                            char const *src, int maxcols, char const *after) {
    char *w = out;
    char *wend = out + outsz - 1;
    int cols = 0;
    char const *p = src;
    while (*p && cols < maxcols) {
        u8 len = UTF8_LEN[((u8)*p) >> 4];
        if (w + len >= wend) break;
        for (u8 j = 0; j < len && *p; j++) *w++ = *p++;
        cols++;
    }
    while (cols < maxcols && w < wend) { *w++ = ' '; cols++; }
    while (*after && w < wend) *w++ = *after++;
    *w = 0;
}

// --- Compact date: "3Jun" if same year, "2023" if different ---

static char const *MONTH_ABBR[] = {
    "Jan","Feb","Mar","Apr","May","Jun",
    "Jul","Aug","Sep","Oct","Nov","Dec"
};

static void blame_compact_date(char *out, size_t outsz,
                                char const *iso_date, int current_year) {
    out[0] = 0;
    if (!iso_date || strlen(iso_date) < 10) return;
    int y = 0, m = 0, d = 0;
    if (sscanf(iso_date, "%d-%d-%d", &y, &m, &d) != 3) return;
    if (y == current_year) {
        if (m >= 1 && m <= 12)
            snprintf(out, outsz, "%d%s", d, MONTH_ABBR[m - 1]);
        else
            snprintf(out, outsz, "%d/%d", d, m);
    } else {
        snprintf(out, outsz, "%d", y);
    }
}

// --- Fetch author + date from commit via keeper ---

static void blame_fetch_author(blame_author *ba, keeper *k,
                                u64 commit_hashlet) {
    ba->author[0] = 0;
    ba->date[0] = 0;

    Bu8 cbuf = {};
    if (u8bMap(cbuf, 1UL << 20) != OK) return;
    u8 obj_type = 0;
    if (KEEPGet(k, DAGh40ToKeeperPrefix(commit_hashlet),
                DAG_H40_HEXLEN, cbuf, &obj_type) != OK ||
        obj_type != DOG_OBJ_COMMIT) {
        u8bUnMap(cbuf);
        return;
    }

    // Parse commit headers looking for "author"
    
a_dup(u8c, scan, u8bDataC(cbuf));
    u8cs field = {}, value = {};
    while (GITu8sDrainCommit(scan, field, value) == OK) {
        if (u8csEmpty(field)) break;  // blank line = body
        a_cstr(author_f, "author");
        if (!$eq(field, author_f)) continue;

        // value = "Name <email> timestamp tz"
        // Find last '<' to split name from rest
        u8cp lt = value[1];
        while (lt > value[0] && *(lt - 1) != '<') lt--;
        if (lt > value[0]) {
            // Name is before '<', trim trailing space
            u8cp ne = lt - 1;
            while (ne > value[0] && *(ne - 1) == ' ') ne--;
            size_t nl = (size_t)(ne - value[0]);
            if (nl >= sizeof(ba->author)) nl = sizeof(ba->author) - 1;
            memcpy(ba->author, value[0], nl);
            ba->author[nl] = 0;
        }

        // Extract timestamp (after '> ')
        u8cp gt = lt;
        while (gt < value[1] && *gt != '>') gt++;
        if (gt < value[1]) gt++;  // past '>'
        while (gt < value[1] && *gt == ' ') gt++;
        // gt now at timestamp digits
        if (gt < value[1]) {
            long ts = 0;
            while (gt < value[1] && *gt >= '0' && *gt <= '9') {
                ts = ts * 10 + (*gt - '0');
                gt++;
            }
            if (ts > 0) {
                time_t t = (time_t)ts;
                struct tm *tm = gmtime(&t);
                if (tm)
                    snprintf(ba->date, sizeof(ba->date), "%04d-%02d-%02d",
                             tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);
            }
        }
        break;
    }
    u8bUnMap(cbuf);
}

// Forward decl: ref-scoped blob fetch lives at end of file.
static ok64 blame_read_blob(u8bp buf, keeper *k, u8cs ref, u8cs filepath);

#define BLAME_ANC_SIZE  (1u << 18)   // 256K slots ≈ 4MB, power of 2

// --- Find author for a token by its u32 hashlet (low 32 of commit_hashlet) ---

static blame_author const *blame_lookup_in(blame_author const *authors,
                                            u32 nauthors, u32 in_h32) {
    for (u32 i = 0; i < nauthors; i++)
        if ((u32)authors[i].commit_hashlet == in_h32) return &authors[i];
    return NULL;
}

static blame_author const blame_unknown = {.gen = 0, .commit_hashlet = 0, .author = "?", .date = ""};

// --- Public entry ---

ok64 GRAFBlame(keeper *k, u8cs filepath, u64 tip_h, u8cs reporoot) {
    sane(k && $ok(filepath) && $ok(reporoot));

    call(GRAFArenaInit);

    //  Open the DAG index.  The CLI entry point may already have
    //  opened graf in rw mode — GRAFOpen then returns GRAFOPEN (or
    //  GRAFOPENRO on a downgrade attempt), which is NOT an error.
    //  We only own the handle (and must close it ourselves) when the
    //  open actually succeeded here.
    ok64 go = GRAFOpen(k->h, NO);
    b8 own_open = (go == OK);
    if (go != OK && go != GRAFOPEN && go != GRAFOPENRO) return go;

    //  Ancestor closure of the tip, topologically sorted parents-first.
    //  No PATH_VER pre-filter — the blob fetch loop below skips commits
    //  where the path is absent and dedups byte-identical adjacent
    //  versions.  When tip_h == 0 (caller couldn't resolve a tip), fall
    //  back to all commits recorded in the index.  No size cap on the
    //  ordered list: the heap buffer scales with the index, and the
    //  fetch+dedup loop drops commits that don't touch this path.
    Bwh128 ancestors = {};
    call(wh128bAllocate, ancestors, BLAME_ANC_SIZE);
    wh128css runs = {NULL, NULL};
    GRAFRuns(runs);
    if (tip_h != 0) {
        DAGAncestors(ancestors, runs, tip_h);
    } else {
        DAGAllCommits(ancestors, runs);
    }

    size_t anc_cap = (size_t)(wh128bTerm(ancestors) -
                              wh128bHead(ancestors));
    Bu8 ord_buf = {};
    u64 *ordered = NULL;
    u32  nord    = 0;
    if (anc_cap > 0 && u8bMap(ord_buf, anc_cap * sizeof(u64)) == OK) {
        ordered = (u64 *)u8bDataHead(ord_buf);
        nord = DAGTopoSort(ordered, (u32)anc_cap, ancestors, runs);
    }

    // Build author table + fetch blob bytes + build weave
    blame_author authors[BLAME_MAX_AUTHORS] = {};
    u32 nauthors = 0;

    //  Three weave instances per the WEAVE.h API: src holds the
    //  accumulated history, dst receives each step's composition,
    //  nu is rebuilt fresh for every blob version.  After WEAVEDiff,
    //  we swap src/dst so src always points at the latest state.
    weave wA = {}, wB = {}, wnu = {};
    call(WEAVEInit, &wA);
    call(WEAVEInit, &wB);
    call(WEAVEInit, &wnu);
    weave *wsrc = &wA, *wdst = &wB;

    // Two mapped blob buffers, swap each iteration
    #define BLAME_BLOB_MAX (16UL << 20)  // 16 MB per blob
    Bu8 blob_a = {}, blob_b = {};
    call(u8bMap, blob_a, BLAME_BLOB_MAX);
    call(u8bMap, blob_b, BLAME_BLOB_MAX);
    Bu8 *cur_blob = &blob_a, *prev_blobp = &blob_b;

    u8cs ext = {};
    PATHu8sExt(ext, filepath);

    b8 have_prev = NO;
    for (u32 i = 0; i < nord; i++) {
        u64 commit_h = ordered[i];
        u8bReset(*cur_blob);
        ok64 fo = GRAFBlobAtCommit(*cur_blob, k, commit_h, filepath);
        if (fo != OK) continue;

        // Byte-level dedup: skip blobs identical to last kept version.
        if (have_prev) {
            size_t cl = u8bDataLen(*cur_blob);
            size_t pl = u8bDataLen(*prev_blobp);
            if (cl == pl && (cl == 0 ||
                memcmp(u8bDataHead(*cur_blob),
                       u8bDataHead(*prev_blobp), cl) == 0)) continue;
        }


        if (commit_h && nauthors < BLAME_MAX_AUTHORS) {
            authors[nauthors].gen = 0;
            authors[nauthors].commit_hashlet = commit_h;
            blame_fetch_author(&authors[nauthors], k, commit_h);
            nauthors++;
        }

        u8cs new_data = {u8bDataHead(*cur_blob),
                         u8bDataHead(*cur_blob) + u8bDataLen(*cur_blob)};

        u32 sc = (u32)commit_h;
        call(WEAVEFromBlob, &wnu, new_data, ext, sc);
        call(WEAVEDiff, wdst, wsrc, &wnu, sc);
        weave *wtmp = wsrc; wsrc = wdst; wdst = wtmp;

        // Swap blob buffers (prev kept for next iter's byte-dedup).
        Bu8 *tmp = cur_blob; cur_blob = prev_blobp; prev_blobp = tmp;
        have_prev = YES;
    }

    //  --- Worktree shadow version ---
    //  Read the on-disk file at reporoot/filepath, fold it into the
    //  weave with src=BLAME_WT_SRC.  Skipped silently if the file is
    //  missing (deleted in worktree) or identical to the last kept
    //  committed version.
    {
        a_path(wt_path, reporoot, filepath);
        u8bp wt_mapped = NULL;
        ok64 wto = FILEMapRO(&wt_mapped, $path(wt_path));
        if (wto == OK && wt_mapped) {
            u8cs wt_data = {u8bDataHead(wt_mapped),
                            u8bDataHead(wt_mapped) + u8bDataLen(wt_mapped)};
            b8 same = NO;
            if (have_prev) {
                size_t cl = (size_t)$len(wt_data);
                size_t pl = u8bDataLen(*prev_blobp);
                if (cl == pl && (cl == 0 || memcmp(wt_data[0],
                                                   u8bDataHead(*prev_blobp),
                                                   cl) == 0))
                    same = YES;
            }
            if (!same) {
                if (nauthors < BLAME_MAX_AUTHORS) {
                    authors[nauthors].gen = 0;
                    authors[nauthors].commit_hashlet = (u64)BLAME_WT_SRC;
                    snprintf(authors[nauthors].author,
                             sizeof(authors[nauthors].author),
                             "(worktree)");
                    authors[nauthors].date[0] = 0;
                    nauthors++;
                }
                ok64 fbo = WEAVEFromBlob(&wnu, wt_data, ext, BLAME_WT_SRC);
                if (fbo == OK) {
                    ok64 dfo = WEAVEDiff(wdst, wsrc, &wnu, BLAME_WT_SRC);
                    if (dfo == OK) {
                        weave *wtmp = wsrc; wsrc = wdst; wdst = wtmp;
                    }
                }
            }
            u8bUnMap(wt_mapped);
        }
    }

    u8bUnMap(blob_a);
    u8bUnMap(blob_b);

    // Render blame: "hashlet name date code"
    #define BLAME_HW 7   // hashlet width
    #define BLAME_NW 12  // name width
    #define BLAME_DW 5   // date width
    #define BLAME_PW (BLAME_HW + 1 + BLAME_NW + 1 + BLAME_DW + 1)
    #define CLR_HASH "\033[38;5;108m"
    #define CLR_NAME "\033[38;5;103m"
    #define CLR_DATE "\033[38;5;245m"
    #define CLR_OFF  "\033[0m"

    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    int cur_year = tm ? tm->tm_year + 1900 : 2026;
    b8 tty = graf_out_fd >= 0 && graf_emit == HUNKu8sFeed;

    u32cp w_toks   = (u32cp)wsrc->toks[1];
    u32cp w_toks_e = (u32cp)wsrc->toks[2];
    u32   wlen     = (u32)(w_toks_e - w_toks);
    inrmcp w_irm   = (inrmcp)wsrc->inrm[1];
    u8cp  w_text   = (u8cp)wsrc->text[1];

    Bu8 outbuf = {};
    call(u8bMap, outbuf, 16UL << 20);

    u32 prev_in = 0;        // 0 means "no previous row yet"
    b8  have_prev_in = NO;
    b8  at_bol = YES;

    char blank_pre[BLAME_PW + 1];
    memset(blank_pre, ' ', BLAME_PW);
    blank_pre[BLAME_PW] = 0;

    #define EMIT_BLANK do { \
        u8cs _s = {(u8cp)blank_pre, (u8cp)blank_pre + BLAME_PW}; \
        u8bFeed(outbuf, _s); \
    } while(0)

    for (u32 wi = 0; wi < wlen; wi++) {
        if (w_irm[wi].rm != 0) continue;

        u32 tlo = (wi == 0) ? 0 : tok32Offset(w_toks[wi - 1]);
        u32 thi = tok32Offset(w_toks[wi]);
        u8cp tp = w_text + tlo;
        u8cp te = w_text + thi;

        if (at_bol) {
            blame_author const *ba = blame_lookup_in(authors, nauthors, w_irm[wi].in);
            if (!ba) ba = &blame_unknown;
            b8 diff_commit = !have_prev_in || prev_in != w_irm[wi].in;

            char pre[256];
            if (diff_commit) {
                char hexlet[12] = "       ";
                if (ba->commit_hashlet == (u64)BLAME_WT_SRC) {
                    snprintf(hexlet, sizeof(hexlet), "wt     ");
                    hexlet[BLAME_HW] = 0;
                } else if (ba->commit_hashlet) {
                    snprintf(hexlet, sizeof(hexlet), "%010llx",
                             (unsigned long long)ba->commit_hashlet);
                    hexlet[BLAME_HW] = 0;
                }
                char cd[16];
                blame_compact_date(cd, sizeof(cd), ba->date, cur_year);
                char fhash[16], fname[32], fdate[16];
                blame_fixfield(fhash, sizeof(fhash), hexlet, BLAME_HW, " ");
                blame_fixfield(fname, sizeof(fname), ba->author, BLAME_NW, " ");
                blame_fixfield(fdate, sizeof(fdate), cd, BLAME_DW, " ");
                if (tty)
                    snprintf(pre, sizeof(pre),
                             CLR_HASH "%s" CLR_NAME "%s" CLR_DATE "%s" CLR_OFF,
                             fhash, fname, fdate);
                else
                    snprintf(pre, sizeof(pre), "%s%s%s", fhash, fname, fdate);
                prev_in = w_irm[wi].in;
                have_prev_in = YES;
            } else {
                snprintf(pre, sizeof(pre), "%s", blank_pre);
            }
            u8cs ps = {(u8cp)pre, (u8cp)pre + strlen(pre)};
            u8bFeed(outbuf, ps);
            at_bol = NO;
        }

        while (tp < te) {
            u8cp nl = tp;
            while (nl < te && *nl != '\n') nl++;
            if (nl < te) {
                u8cs chunk = {tp, nl + 1};
                u8bFeed(outbuf, chunk);
                tp = nl + 1;
                at_bol = YES;
                if (tp < te) { EMIT_BLANK; at_bol = NO; }
            } else {
                u8cs chunk = {tp, te};
                u8bFeed(outbuf, chunk);
                tp = te;
            }
        }
    }

    if (!at_bol) {
        u8cs nl = {(u8cp)"\n", (u8cp)"\n" + 1};
        u8bFeed(outbuf, nl);
    }

    #undef EMIT_BLANK

    {
        char title[128];
        snprintf(title, sizeof(title), "%.*s (blame)",
                 (int)$len(filepath), (char *)filepath[0]);

        u8cs fdata = {u8bDataHead(outbuf),
                      u8bDataHead(outbuf) + u8bDataLen(outbuf)};
        hunk hk = {};
        hk.uri[0] = (u8cp)title;
        hk.uri[1] = (u8cp)title + strlen(title);
        $mv(hk.text, fdata);
        call(GRAFHunkEmit, &hk, NULL);
    }

    u8bUnMap(outbuf);
    WEAVEFree(&wA);
    WEAVEFree(&wB);
    WEAVEFree(&wnu);
    if (ord_buf[0]) u8bUnMap(ord_buf);
    if (wh128bHead(ancestors) != wh128bTerm(ancestors)) wh128bFree(ancestors);
    if (own_open) GRAFClose();
    GRAFArenaCleanup();
    done;
}

// --- Weave diff: resolve (ref, filepath) → blob via path descent ---

// Resolve `ref` + `filepath` to the blob content at that path.
// Descends path segments one at a time (O(depth) tree loads) rather
// than walking the full tree.
static ok64 blame_read_blob(u8bp buf, keeper *k, u8cs ref, u8cs filepath) {
    sane(buf && k);

    uri target = {};
    a_pad(u8, ubuf, 512);
    u8bFeed1(ubuf, '?');
    call(u8bFeed, ubuf, ref);
    a_dup(u8c, udata, u8bData(ubuf));
    target.data[0] = udata[0];
    target.data[1] = udata[1];
    target.query[0] = udata[0] + 1;
    target.query[1] = udata[1];

    sha1 cur = {};
    call(KEEPResolveTree, k, &target, &cur);

    u8cs rest = {filepath[0], filepath[1]};
    while (!$empty(rest)) {
        u8cp slash = rest[0];
        while (slash < rest[1] && *slash != '/') slash++;
        u8cs name = {rest[0], slash};
        call(GRAFTreeStep, k, &cur, name);
        rest[0] = (slash < rest[1]) ? slash + 1 : slash;
    }

    u8 btype = 0;
    call(KEEPGetExact, k, &cur, buf, &btype);
    if (btype != DOG_OBJ_BLOB) fail(KEEPNONE);
    done;
}

ok64 GRAFWeaveDiff(keeper *k, u8cs filepath, u8cs reporoot,
                   u8cs from, u8cs to) {
    sane(k && $ok(filepath) && $ok(reporoot));

    call(GRAFArenaInit);

    u8cs ext = {};
    PATHu8sExt(ext, filepath);

    Bu8 from_buf = {}, to_buf = {};
    call(u8bMap, from_buf, 16UL << 20);
    call(u8bMap, to_buf, 16UL << 20);

    // Fetch to-blob (HEAD or specified ref)
    {
        u8cs to_ref = {};
        if (!$empty(to))
            u8csMv(to_ref, to);
        else {
            a_cstr(head, "HEAD");
            to_ref[0] = head[0];
            to_ref[1] = head[1];
        }
        blame_read_blob(to_buf, k, to_ref, filepath);
    }

    // Fetch from-blob (if specified)
    if (!$empty(from))
        blame_read_blob(from_buf, k, from, filepath);

    // Run the standard token-level diff
    {
        u8cs old_data = {u8bDataHead(from_buf),
                         u8bDataHead(from_buf) + u8bDataLen(from_buf)};
        u8cs new_data = {u8bDataHead(to_buf),
                         u8bDataHead(to_buf) + u8bDataLen(to_buf)};

        char dispname[512];
        snprintf(dispname, sizeof(dispname), "%.*s",
                 (int)$len(filepath), (char *)filepath[0]);

        call(DIFFu8cs, graf_arena, old_data, new_data,
             ext, dispname, GRAFHunkEmit, NULL);
    }

    u8bUnMap(from_buf);
    u8bUnMap(to_buf);
    GRAFArenaCleanup();
    done;
}
