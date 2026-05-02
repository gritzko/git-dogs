#include "CAPOi.h"

#include <dirent.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

b8 CAPO_COLOR = NO;
b8 CAPO_TERM = NO;

// --- Forward decls used before their definitions further below ---
static b8   spot_is_open(void);
static ok64 spot_branch_dir(path8b out, home *h, u8cs leaf_branch);

// Guard against assert() crashes in library code
static sigjmp_buf capo_jmpbuf;
static volatile sig_atomic_t capo_in_match = 0;

static void capo_abrt_handler(int sig) {
    (void)sig;
    if (capo_in_match) siglongjmp(capo_jmpbuf, 1);
    _exit(134);
}

#include "abc/ANSI.h"
#include "abc/PRO.h"
#include "abc/SORT.h"
#include "dog/DEF.h"
#include "dog/DOG.h"
#include "dog/DPATH.h"
#include "dog/HOME.h"
#include "dog/IGNO.h"
#include "keeper/KEEP.h"
#include "keeper/WALK.h"
#include "spot/SPOT.h"

// kv64 hashtable for blob staging (hashlet32 → off+len)
#define X(M, name) M##kv64##name
#include "abc/HASHx.h"
#undef X

// --- Language detection via tok/ ---

b8 CAPOKnownExt(u8csc ext) {
    if ($empty(ext)) return NO;
    u8cs nodot = {};
    if (ext[0][0] == '.') {
        nodot[0] = ext[0] + 1;
        nodot[1] = ext[1];
    } else {
        nodot[0] = ext[0]; nodot[1] = ext[1];
    }
    return TOKKnownExt(nodot);
}

// Simple ext-to-name for display (replaces BASTCodec)
static void CAPOCodecName(u8csp codec, u8csc ext) {
    if ($empty(ext)) {
        codec[0] = (u8cp)"text";
        codec[1] = (u8cp)"text" + 4;
        return;
    }
    // Strip dot, use extension as codec name
    if (ext[0][0] == '.') {
        codec[0] = ext[0] + 1;
        codec[1] = ext[1];
    } else {
        $mv(codec, ext);
    }
}

// --- Resolve spot index directory ---
// Spot files live in <reporoot>/.dogs/spot/, where <reporoot> is the
// workspace dir containing .git (file or directory). Caller is responsible
// for creating the dir via FILEMakeDirP if it does not yet exist.

ok64 CAPOResolveDir(path8b out, u8csc reporoot) {
    sane($ok(reporoot) && out != NULL);
    // If caller supplied a reporoot, feed it; otherwise walk up via HOME.
    if (!u8csEmpty(reporoot)) {
        a_dup(u8c, r, reporoot);
        call(PATHu8bFeed, out, r);
    } else {
        home rh = {};
        uri none = {};
        call(HOMEOpen, &rh, &none, NO);
        a_dup(u8c, r, u8bDataC(rh.root));
        ok64 fo = PATHu8bFeed(out, r);
        HOMEClose(&rh);
        if (fo != OK) return fo;
    }
    a_cstr(dotdogs, ".dogs");
    call(PATHu8bPush, out, dotdogs);
    done;
}

// --- Trigram extraction from tok/ tokens ---

typedef struct {
    u64 **idle;
    u64 *end;
    u32 path_hash;
} CAPOTriCtx;

static ok64 CAPOTriCB(void0p arg, u8cs tri) {
    CAPOTriCtx *ctx = (CAPOTriCtx *)arg;
    if (*ctx->idle >= ctx->end) return CAPONOROOM;
    u64 entry = CAPOTriPack(tri) | (u64)ctx->path_hash;
    **ctx->idle = entry;
    (*ctx->idle)++;
    return OK;
}

// Walk packed tokens, extract RON64 trigrams from source text
static ok64 CAPOTriExtractToks(u32cs toks, u8cp base,
                                ok64 (*cb)(void0p, u8cs), void0p arg) {
    sane(cb != NULL);
    int len = (int)$len(toks);
    for (int i = 0; i < len; i++) {
        u8cs val = {}; tok32Val(val,toks,base,i);
        if ($len(val) < 3) continue;
        u8cp p = val[0];
        u8cp end = val[1] - 2;
        while (p <= end) {
            if (CAPOTriChar(p[0]) && CAPOTriChar(p[1]) &&
                CAPOTriChar(p[2])) {
                u8cs tri = {p, p + 3};
                ok64 r = cb(arg, tri);
                if (r != OK) return r;
            }
            p++;
        }
    }
    return OK;
}

ok64 CAPOIndexFile(u64bp entries, u8csc source, u8csc ext, u8csc path) {
    sane(entries != NULL && $ok(source) && $ok(ext) && $ok(path));
    if ($empty(source)) done;

    // Tokenize
    Bu32 toks = {};
    size_t maxlen = $len(source) + 1;  // at most 1 token per byte
    vcall("mmap toks", u32bMap, toks, maxlen);
    ok64 o = SPOTTokenize(toks, source, ext);
    if (o != OK) {
        u32bUnMap(toks);
        return o;
    }

    // Mark definitions (S→N) before extraction
    {
        u32 *dts[2] = {u32bDataHead(toks), u32bIdleHead(toks)};
        u8cs nodot = {};
        if (!$empty(ext) && ext[0][0] == '.') {
            nodot[0] = ext[0] + 1; nodot[1] = ext[1];
        } else {
            nodot[0] = ext[0]; nodot[1] = ext[1];
        }
        DEFMark(dts, source, nodot);
    }

    u32cp td = u32bDataHead(toks);
    u32cp ti = u32bIdleHead(toks);
    u32cs tokslice = {(u32cp)td, (u32cp)ti};

    u32 phash = CAPOPathHash(path);
    CAPOTriCtx ctx = {
        .idle = u64bIdle(entries),
        .end = entries[3],
        .path_hash = phash,
    };
    o = CAPOTriExtractToks(tokslice, source[0], CAPOTriCB, &ctx);
    if (o != OK) { u32bUnMap(toks); return o; }

    // Emit symbol mention/definition entries
    int ntoks = (int)$len(tokslice);
    for (int i = 0; i < ntoks; i++) {
        u8 tag = tok32Tag(tokslice[0][i]);
        if (tag != 'S' && tag != 'N' && tag != 'C') continue;
        u8cs val = {}; tok32Val(val, tokslice, source[0], i);
        if ($len(val) < 2) continue;
        if (*ctx.idle >= ctx.end) break;
        u64 type = (tag == 'N') ? IDX64_DEF : IDX64_MEN;
        u64 entry = (type << 62) | CAPOSymKey(val) | (u64)phash;
        *(*ctx.idle) = entry;
        (*ctx.idle)++;
    }

    u32bUnMap(toks);
    done;
}

// --- Stack management ---
//
//  The puppy stack is owned by the SPOT singleton (set up by
//  SPOTOpenBranch walking trunk → … → leaf).  CAPOStackOpen builds a
//  typed `u64cs[]` view over `SPOT.puppies` — no per-call fs scan,
//  no per-call mmap.  `dir` is ignored (kept for API stability;
//  every caller already targets the spot dir resolved from the
//  same singleton's home).  The matching CAPOStackClose is a no-op:
//  mappings are unmapped at SPOTClose.

ok64 CAPOStackOpen(u64css stack, u8bp *maps, u32p nfiles, u8csc dir) {
    sane($ok(stack) && maps != NULL && nfiles != NULL && $ok(dir));
    (void)dir;
    *nfiles = 0;
    if (!spot_is_open()) done;
    spot *s = &SPOT;
    u32 n = DOGPupCount(s->puppies);
    for (u32 i = 0; i < n && *nfiles < CAPO_MAX_LEVELS; i++) {
        u8cs raw = {};
        DOGPupData(raw, s->puppies, i);
        if (raw[0] == NULL) continue;
        u64cp base = (u64cp)raw[0];
        size_t bytes = (size_t)(raw[1] - raw[0]);
        stack[0][*nfiles][0] = base;
        stack[0][*nfiles][1] = base + bytes / sizeof(u64);
        maps[*nfiles] = NULL;  // owned by SPOT.puppies; not per-call
        (*nfiles)++;
    }
    done;
}

ok64 CAPOStackClose(u8bp *maps, u32 nfiles) {
    //  No-op: SPOT.puppies owns the mmaps now.
    (void)maps; (void)nfiles;
    return OK;
}

// --- Compaction ---

ok64 CAPOCompact(spot *s) {
    sane(s);

    u32 nfiles = DOGPupCount(s->puppies);
    if (nfiles < 2) done;

    //  Build typed view from puppy data slices.
    u64cs runs[CAPO_MAX_LEVELS] = {};
    u32 nview = 0;
    for (u32 i = 0; i < nfiles && nview < CAPO_MAX_LEVELS; i++) {
        u8cs raw = {};
        DOGPupData(raw, s->puppies, i);
        if (raw[0] == NULL) continue;
        runs[nview][0] = (u64cp)raw[0];
        runs[nview][1] = (u64cp)raw[1];
        nview++;
    }
    u64css stack = {runs, runs + nview};

    if (HITu64IsCompact(stack)) done;

    size_t total = 0;
    for (u32 i = 0; i < nview; i++) total += $len(runs[i]);

    Bu64 cbuf = {};
    call(u64bAlloc, cbuf, total);
    u64 *base = cbuf[0];
    u64s into = {cbuf[0], cbuf[3]};
    size_t before_len = $len(stack);
    call(HITu64Compact, stack, into);
    size_t m = before_len - $len(stack) + 1;
    if (m < 2) { u64bFree(cbuf); done; }

    a_pad(u8, leafdir, FILE_PATH_MAX_LEN);
    a_dup(u8c, leaf, u8bDataC(s->leaf_branch));
    call(spot_branch_dir, leafdir, s->h, leaf);
    a_cstr(ext, CAPO_IDX_EXT);
    u8cs merged = {(u8cp)base, (u8cp)(into[0])};
    //  Thin first (unlinks the m sources), then create.
    call(DOGPupThinTail, s->puppies, $path(leafdir), ext, (u32)m);
    call(DOGPupCreate,   s->puppies, $path(leafdir), ext, merged);

    u64bFree(cbuf);
    done;
}


// --- Compact all into one ---

ok64 CAPOCompactAll(spot *s) {
    sane(s);

    u32 nfiles = DOGPupCount(s->puppies);
    if (nfiles <= 1) done;

    //  Build typed view over the whole stack.
    u64cs runs[CAPO_MAX_LEVELS] = {};
    u32 nview = 0;
    size_t total = 0;
    for (u32 i = 0; i < nfiles && nview < CAPO_MAX_LEVELS; i++) {
        u8cs raw = {};
        DOGPupData(raw, s->puppies, i);
        if (raw[0] == NULL) continue;
        runs[nview][0] = (u64cp)raw[0];
        runs[nview][1] = (u64cp)raw[1];
        total += $len(runs[nview]);
        nview++;
    }
    u64css stack = {runs, runs + nview};
    fprintf(stderr, "spot: merging %u runs, %zu total entries\n",
            nview, total);

    Bu64 mbuf = {};
    call(u64bMap, mbuf, total);
    u64s into = {u64bIdleHead(mbuf), mbuf[3]};

    HITu64Start(stack);
    u64p out = into[0];
    HITu64Merge(stack, &out);
    into[0] = out;

    u8cs merged = {(u8cp)mbuf[0], (u8cp)out};
    fprintf(stderr, "spot: writing %zu deduplicated entries\n",
            $len(merged) / sizeof(u64));

    a_pad(u8, leafdir, FILE_PATH_MAX_LEN);
    a_dup(u8c, leaf, u8bDataC(s->leaf_branch));
    call(spot_branch_dir, leafdir, s->h, leaf);
    a_cstr(ext, CAPO_IDX_EXT);
    //  Drop ALL existing puppies, then create the merged single run.
    call(DOGPupThinTail, s->puppies, $path(leafdir), ext, nview);
    call(DOGPupCreate,   s->puppies, $path(leafdir), ext, merged);

    u64bUnMap(mbuf);
    done;
}

// --- Trigram query helpers ---

// Seek a HIT to a prefix range [prefix, prefix + 1<<32).
// After this, the HIT only contains entries within the prefix.
static ok64 CAPOSeekPrefix(u64css iter, u64 prefix) {
    u64 lo = prefix;
    u64 hi = prefix + (1ULL << 32);
    return HITu64SeekRange(iter, &lo, &hi);
}

ok64 CAPOCollectPaths(u64css iter, u64 tri_prefix, u32g hashes) {
    ok64 o = CAPOSeekPrefix(iter, tri_prefix);
    if (o != OK) return OK;

    while (!$empty(iter)) {
        u32gFeed1(hashes, (u32)(*(*iter[0])[0]));
        HITu64Step(iter);
    }
    return OK;
}

// In-place intersect hashbuf against a range-seeked HIT's path hashes.
// Both hashbuf data and the HIT output are sorted by path hash.
void CAPOFilterInPlace(u32bp hashbuf, u64css iter, u64 prefix) {
    CAPOSeekPrefix(iter, prefix);
    u32s data = {};
    $mv(data, u32bData(hashbuf));
    u32 *r = data[0], *w = data[0];

    while (r < data[1] && !$empty(iter)) {
        u32 ph = (u32)(*(*iter[0])[0]);
        if (*r < ph) { r++; continue; }
        if (*r > ph) { HITu64Step(iter); continue; }
        u32 matched = *r;
        *w++ = matched;
        while (r < data[1] && *r == matched) r++;
        while (!$empty(iter) && (u32)(*(*iter[0])[0]) == matched)
            HITu64Step(iter);
    }
    u32bShed(hashbuf, (size_t)(data[1] - w));
}


u32 CAPOIntersect(u32s a, u32csc b) {
    u32 na = (u32)$len(a), nb = (u32)$len(b);
    u32 i = 0, j = 0, k = 0;
    while (i < na && j < nb) {
        if (a[0][i] < b[0][j]) i++;
        else if (a[0][i] > b[0][j]) j++;
        else { a[0][k++] = a[0][i]; i++; j++; }
    }
    return k;
}

int CAPOu32cmp(const void *a, const void *b) {
    u32 x = *(const u32 *)a, y = *(const u32 *)b;
    return (x > y) - (x < y);
}

void CAPOProgress(const char *line) {
    if (!CAPO_TERM) return;
    fprintf(stderr, "\r\033[K");
    if (line != NULL)
        fprintf(stderr, "\033[%dm%s\033[0m", GRAY, line);
}

// --- Function name finder (heuristic) ---

// Check if ext (with dot) matches one of the given suffixes.
b8 CAPOExtIs(u8csc ext, const char *a, const char *b) {
    u8cs nodot = {};
    if ($empty(ext)) return NO;
    if (ext[0][0] == '.') { nodot[0] = ext[0] + 1; nodot[1] = ext[1]; }
    else { nodot[0] = ext[0]; nodot[1] = ext[1]; }
    size_t n = (size_t)$len(nodot);
    size_t al = strlen(a);
    if (n == al && memcmp(nodot[0], a, al) == 0) return YES;
    if (b != NULL) {
        size_t bl = strlen(b);
        if (n == bl && memcmp(nodot[0], b, bl) == 0) return YES;
    }
    return NO;
}

// Walk backward from `pos` looking for a section header line.
// Heuristic depends on file extension:
//   md/markdown/rst/txt: line starting with '#'
//   py: col-0 'def ' or 'class '
//   default (C-like): col-0 identifier + '('
void CAPOFindFunc(u8csc source, u32 pos, u8csc ext,
                   char *out, size_t outsz) {
    out[0] = 0;
    if ($empty(source) || pos == 0 || outsz < 2) return;
    u8cp base = source[0];
    u32 slen = (u32)$len(source);
    if (pos > slen) pos = slen;

    b8 is_md = CAPOExtIs(ext, "md", "markdown") ||
               CAPOExtIs(ext, "rst", "txt");
    b8 is_py = CAPOExtIs(ext, "py", NULL);

    // Find start of current line
    u32 ls = pos;
    while (ls > 0 && base[ls - 1] != '\n') ls--;

    // Walk backward up to 200 lines looking for a header line
    for (int tries = 0; tries < 200 && ls > 0; tries++) {
        // Move to previous line
        ls--;
        while (ls > 0 && base[ls - 1] != '\n') ls--;

        // Skip empty lines
        u32 le = ls;
        while (le < slen && base[le] != '\n') le++;
        if (le == ls) continue;

        u8 ch = base[ls];
        u32 linelen = le - ls;

        if (is_md) {
            // Markdown: line starting with '#'
            if (ch != '#') continue;
        } else if (is_py) {
            // Python: col-0 'def ' or 'class '
            if (linelen >= 4 && memcmp(base + ls, "def ", 4) == 0) {}
            else if (linelen >= 6 && memcmp(base + ls, "class ", 6) == 0) {}
            else continue;
        } else {
            // C-like: col-0 identifier + '('
            // Skip comment lines
            if (ch == '/' || ch == '*' || ch == '#') continue;
            // Must start with identifier char at column 0
            if (!((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
                  ch == '_'))
                continue;
            // Must contain '('
            b8 has_paren = NO;
            for (u32 j = ls; j < le; j++)
                if (base[j] == '(') { has_paren = YES; break; }
            if (!has_paren) continue;
        }

        // Copy line, trim trailing { / : and whitespace
        u32 copylen = linelen;
        if (copylen >= outsz) copylen = (u32)(outsz - 1);
        memcpy(out, base + ls, copylen);
        out[copylen] = 0;
        while (copylen > 0 &&
               (out[copylen - 1] == '{' || out[copylen - 1] == ':' ||
                out[copylen - 1] == ' ' || out[copylen - 1] == '\t' ||
                out[copylen - 1] == '\r'))
            out[--copylen] = 0;
        return;
    }
}

// --- Hunk building ---

ok64 CAPOBuildHunk(u8csc source, u32cs htoks, u32 ctx_lo, u32 ctx_hi,
                   range32 const *hls, int nhl,
                   u8csc file_ext, const char *filepath,
                   b8 needs_title, b8 *first_hunk) {
    sane(less_nhunks < LESS_MAX_HUNKS);
    LESShunk *hk = &less_hunks[less_nhunks];
    *hk = (LESShunk){};

    // Compose URI: path#symbol:lineno
    {
        char funcname[256] = {};
        if (needs_title || *first_hunk)
            CAPOFindFunc(source, ctx_lo, file_ext,
                         funcname, sizeof(funcname));
        u32 ln = 1;
        $for(u8c, ch, source) {
            if (ch >= source[0] + ctx_lo) break;
            if (*ch == '\n') ln++;
        }
        u8cs fp = {};
        if (filepath) {
            fp[0] = (u8cp)filepath;
            fp[1] = (u8cp)filepath + strlen(filepath);
        }
        u8cs fn = {};
        if (funcname[0]) {
            fn[0] = (u8cp)funcname;
            fn[1] = (u8cp)funcname + strlen(funcname);
        }
        u8gp ug = u8aOpen(less_arena);
        HUNKu8sMakeURI(u8gRest(ug), fp, fn, ln);
        u8cs uri_s = {};
        u8aClose(less_arena, uri_s);
        $mv(hk->uri, uri_s);
    }

    hk->text[0] = source[0] + ctx_lo;
    hk->text[1] = source[0] + ctx_hi;

    // Clip file-level toks to context region
    HUNKu32sClip(less_arena, hk->toks, htoks, ctx_lo, ctx_hi);

    // Build sparse hili from match ranges
    if (CAPO_COLOR) {
        u32gp g = u32aOpen(less_arena);
        u32 prev_end = 0;
        for (int i = 0; i < nhl; i++) {
            u32 mlo = hls[i].lo < ctx_lo
                          ? 0
                          : hls[i].lo - ctx_lo;
            u32 mhi = hls[i].hi > ctx_hi
                          ? ctx_hi - ctx_lo
                          : hls[i].hi - ctx_lo;
            if (mlo > prev_end)
                u32gFeed1(g, tok32Pack('A', mlo));
            u32gFeed1(g, tok32Pack('I', mhi));
            prev_end = mhi;
        }
        u32 region_len = ctx_hi - ctx_lo;
        if (prev_end < region_len)
            u32gFeed1(g, tok32Pack('A', region_len));
        u32cs hili = {};
        u32aClose(less_arena, hili);
        if (!$empty(hili)) {
            hk->hili[0] = hili[0];
            hk->hili[1] = hili[1];
        }
    }

    LESSHunkEmit();
    *first_hunk = NO;
    done;
}

// --- Per-file replacement ---

static ok64 CAPOSpotReplace(u8csc source, u8bp mapped, u32cs htoks,
                             u8csc needle, u8csc replace, u8csc file_ext,
                             u8bp fpbuf, const char *line,
                             int *total_replacements,
                             int *total_files_replaced) {
    sane(!$empty(replace));
    size_t obuflen = $len(source) * 2 + 4096;
    Bu8 obufm = {};
    ok64 o = u8bMap(obufm, obuflen);
    if (o == OK) {
        u8s rout = {u8bIdleHead(obufm), obufm[3]};
        int file_matches = 0;
        o = SPOTReplace(rout, source, htoks, needle,
                        replace, file_ext, &file_matches);
        if (o == OK) {
            u8cs result = {u8bIdleHead(obufm), rout[0]};
            FILEUnMap(mapped);
            mapped = NULL;
            int fd = -1;
            ok64 wo = FILECreate(&fd, $path(fpbuf));
            if (wo == OK) {
                FILEFeedAll(fd, result);
                close(fd);
                CAPOProgress(NULL);
                fprintf(stderr, "replaced: %s (%d)\n",
                        line, file_matches);
                *total_replacements += file_matches;
                (*total_files_replaced)++;
            }
        }
        u8bUnMap(obufm);
    }
    done;
}

// --- Per-file search+display ---

static ok64 CAPOSpotFile(u8csc source, u32cs htoks, u8csc needle,
                          u8csc file_ext, const char *line) {
    sane(!$empty(needle));
    aBpad(u32, nbuf, 4096);
    SPOTstate st = {};
    ok64 o = SPOTInit(&st, nbuf, needle, file_ext, htoks, source);
    if (o != OK) done;
    b8 found_any = NO;
    b8 first_hunk = YES;
    u32 prev_ctx_hi = 0;
    b8 have_pending = NO;
    range32 pending = {};
    for (;;) {
        u32 slo, shi;
        if (have_pending) {
            slo = pending.lo;
            shi = pending.hi;
            have_pending = NO;
        } else {
            if (SPOTNext(&st) != OK) break;
            slo = st.src_rng.lo;
            shi = st.src_rng.hi;
        }
        if (shi <= slo || shi > (u32)$len(source)) continue;

        if (!found_any) {
            CAPOProgress(NULL);
            found_any = YES;
        }

        // Compute context around match
        u32 ctx_lo = 0, ctx_hi = 0;
        CAPOGrepCtx(source, slo, 3, &ctx_lo, &ctx_hi);
        if (shi > slo) {
            u32 lo2 = 0, hi2 = 0;
            CAPOGrepCtx(source, shi - 1, 3, &lo2, &hi2);
            if (hi2 > ctx_hi) ctx_hi = hi2;
        }

        // Collect subsequent matches within this context.
        // The SPOT engine may report the same logical match multiple
        // times with different uppercase-placeholder anchor positions
        // (a wider span first, then a narrower one).  Dedupe by keeping
        // the narrowest match: when a new entry is contained within the
        // previous one, replace; otherwise append.
        range32 hls[CAPO_MAX_HLS];
        int nhl = 0;
        hls[nhl++] = (range32){slo, shi};
        while (nhl <= CAPO_MAX_HLS && SPOTNext(&st) == OK) {
            u32 s2 = st.src_rng.lo;
            u32 e2 = st.src_rng.hi;
            if (e2 <= s2 || e2 > (u32)$len(source)) continue;
            if (s2 >= ctx_hi) {
                pending = (range32){s2, e2};
                have_pending = YES;
                break;
            }
            // If the new range is contained in the previous one
            // (same end, narrower start), replace — not append.
            range32 *prev = &hls[nhl - 1];
            if (s2 >= prev->lo && e2 <= prev->hi) {
                *prev = (range32){s2, e2};
            } else if (nhl < CAPO_MAX_HLS) {
                hls[nhl++] = (range32){s2, e2};
            }
            u32 lo2 = 0, hi2 = 0;
            CAPOGrepCtx(source, s2, 3, &lo2, &hi2);
            if (hi2 > ctx_hi) ctx_hi = hi2;
        }

        b8 contiguous = (ctx_lo <= prev_ctx_hi);
        if (ctx_lo < prev_ctx_hi) ctx_lo = prev_ctx_hi;
        if (ctx_lo < ctx_hi) {
            call(CAPOBuildHunk, source, htoks, ctx_lo, ctx_hi,
                 hls, nhl, file_ext, line,
                 !contiguous, &first_hunk);
        }
        prev_ctx_hi = ctx_hi;
    }
    done;
}

// --- SPOT search ---

// --- Spot per-file callback ---

typedef struct {
    u8cs needle;
    u8cs replace;
    u8cs ext;
    int  total_replacements;
    int  total_files_replaced;
} capo_spot_ctx;

static ok64 capo_spot_file_cb(void *ctx, u8csc relpath, u8csc source,
                               u8csc file_ext, u8bp mapped, path8p fpbuf) {
    sane(ctx != NULL);
    capo_spot_ctx *sc = ctx;

    Bu32 toks = {};
    ok64 o = u32bMap(toks, $len(source) + 1);
    if (o != OK) { if (mapped) FILEUnMap(mapped); return OK; }
    o = SPOTTokenize(toks, source, file_ext);
    if (o != OK) { u32bUnMap(toks); if (mapped) FILEUnMap(mapped); return OK; }
    {
        u32 *dts[2] = {u32bDataHead(toks), u32bIdleHead(toks)};
        a_dup(u8c,dext,file_ext);
        if (!$empty(dext) && dext[0][0] == '.') dext[0]++;
        DEFMark(dts, source, dext);
    }
    u32cs htoks = {(u32cp)u32bDataHead(toks),
                   (u32cp)u32bIdleHead(toks)};

    char rpz[FILE_PATH_MAX_LEN] = {};
    size_t rlen = (size_t)$len(relpath);
    if (rlen >= sizeof(rpz)) rlen = sizeof(rpz) - 1;
    memcpy(rpz, relpath[0], rlen);

    signal(SIGABRT, capo_abrt_handler);
    capo_in_match = 1;
    if (sigsetjmp(capo_jmpbuf, 1) == 0) {
        if (!$empty(sc->replace))
            CAPOSpotReplace(source, mapped, htoks, sc->needle,
                            sc->replace, file_ext, fpbuf, rpz,
                            &sc->total_replacements,
                            &sc->total_files_replaced);
        else
            CAPOSpotFile(source, htoks, sc->needle, file_ext, rpz);
    }
    capo_in_match = 0;
    signal(SIGABRT, SIG_DFL);

    if ($empty(sc->replace)) {
        if (mapped)
            LESSDefer(mapped, toks);
        else
            u32bUnMap(toks);
    } else {
        u32bUnMap(toks);
        if (mapped) FILEUnMap(mapped);
    }
    return OK;
}

ok64 CAPOSpot(u8csc needle, u8csc replace, u8csc ext, u8csc reporoot,
              u8css files, uri const *ref) {
    sane($ok(needle) && $ok(ext) && $ok(reporoot));

    if (!CAPOKnownExt(ext)) return SPOTBAD;
    if (ref != NULL && !$empty(replace)) {
        fprintf(stderr, "spot: --replace with ?ref is not supported\n");
        return SPOTBAD;
    }

    Bu32 hashbuf1 = {};
    b8 has_trigrams = NO;
    if ($len(files) == 0 && ref == NULL)
        CAPOTrigramFilter(hashbuf1, &has_trigrams, needle, reporoot);

    if ($empty(replace))
        call(LESSArenaInit);

    capo_spot_ctx sc = {};
    $mv(sc.needle, needle);
    $mv(sc.replace, replace);
    $mv(sc.ext, ext);

    CAPOScanOpts opts = {
        .has_trigrams = has_trigrams,
        .file_fn = capo_spot_file_cb,
        .file_ctx = &sc,
    };
    if (!$empty(ext)) $mv(opts.target_ext, ext);
    if (has_trigrams) $mv(opts.tri_hashes, u32bDataC(hashbuf1));

    if (ref != NULL) {
        home *h = SPOT.h;
        ok64 ko = KEEPOpen(h, NO);
        if (ko != OK && ko != KEEPOPEN) {
            fprintf(stderr, "spot: keeper open failed: %s\n", ok64str(ko));
            if (!BNULL(hashbuf1)) u32bUnMap(hashbuf1);
            if ($empty(replace)) LESSArenaCleanup();
            return ko;
        }
        CAPOScanRef(&KEEP, ref, &opts);
        if (ko == OK) KEEPClose();
    } else if ($len(files) > 0) {
        CAPOScanFiles(files, &opts);
    } else {
        CAPOScan(reporoot, &opts);
    }

    CAPOProgress(NULL);

    if ($empty(replace) && less_nhunks > 0)
        LESSRun(less_hunks, less_nhunks);
    if ($empty(replace))
        LESSArenaCleanup();

    if (!$empty(replace))
        fprintf(stderr, "%d replacements in %d files\n",
                sc.total_replacements, sc.total_files_replaced);

    if (!BNULL(hashbuf1)) u32bUnMap(hashbuf1);
    done;
}

// --- File scan ---

typedef struct {
    CAPOScanOpts const *opts;
    u8cs root;
    size_t root_len;
    igno ig;
    b8   has_igno;
} capo_scan_st;

static ok64 capo_scan_cb(void *arg, path8p path) {
    capo_scan_st *st = arg;
    CAPOScanOpts const *opts = st->opts;
    u8cs data = {};
    $mv(data, u8bDataC(path));
    if ($empty(data)) return OK;

    // Directory: trailing '/' appended by FILEScan
    if (data[1][-1] == '/') {
        // Extract basename (between last two '/' or start)
        u8cp p = data[1] - 2;  // before trailing /
        while (p > data[0] && p[-1] != '/') p--;
        // Skip hidden dirs (.git, .dogs, etc.)
        if (*p == '.') return FILESKIP;
        // Check .gitignore
        if (st->has_igno) {
            u8cs rel = {data[0] + st->root_len, data[1] - 1};
            if (!$empty(rel) && rel[0][0] == '/')
                u8csFed(rel, 1);
            if (!$empty(rel) && IGNOMatch(&st->ig, rel, YES))
                return FILESKIP;
        }
        return OK;
    }

    // File: apply filters
    u8cs file_ext = {};
    PATHu8sExt(file_ext, data);
    if ($empty(file_ext)) return OK;
    if (!CAPOKnownExt(file_ext)) return OK;
    if (!$empty(opts->target_ext)) {
        if (!TOKSameLexer(file_ext, opts->target_ext)) return OK;
    }

    // Compute relpath
    u8cs relpath = {data[0] + st->root_len, data[1]};
    if (!$empty(relpath) && relpath[0][0] == '/')
        u8csFed(relpath, 1);

    // Check .gitignore
    if (st->has_igno && IGNOMatch(&st->ig, relpath, NO))
        return OK;

    // Trigram filter
    if (opts->has_trigrams && !$empty(opts->tri_hashes)) {
        u32 phash = CAPOPathHash(relpath);
        u32s th = {(u32p)opts->tri_hashes[0], (u32p)opts->tri_hashes[1]};
        if (!u32sBsearch(&phash, th))
            return OK;
    }

    // NUL-terminated relpath for progress
    char relpathz[FILE_PATH_MAX_LEN] = {};
    size_t rlen = (size_t)$len(relpath);
    if (rlen >= sizeof(relpathz)) rlen = sizeof(relpathz) - 1;
    memcpy(relpathz, relpath[0], rlen);
    CAPOProgress(relpathz);

    // Map file
    u8bp mapped = NULL;
    ok64 o = FILEMapRO(&mapped, $path(path));
    if (o != OK) return OK;  // skip unreadable files

    u8cs source = {};
    $mv(source, u8bDataC(mapped));

    o = opts->file_fn(opts->file_ctx, relpath, source,
                      file_ext, mapped, path);
    if (o != OK) {
        FILEUnMap(mapped);
        return o;
    }
    return OK;
}

ok64 CAPOScan(u8csc reporoot, CAPOScanOpts const *opts) {
    sane(!$empty(reporoot) && opts != NULL && opts->file_fn != NULL);

    capo_scan_st st = {
        .opts = opts,
    };
    $mv(st.root, reporoot);
    st.root_len = (size_t)$len(reporoot);

    // Load .gitignore
    u8cs igroot = {(u8cp)reporoot[0], (u8cp)reporoot[1]};
    if (IGNOLoad(&st.ig, igroot) == OK)
        st.has_igno = YES;

    a_path(wp);
    call(PATHu8bFeed, wp, reporoot);

    ok64 o = FILEScan(wp, (FILE_SCAN)(FILE_SCAN_ALL | FILE_SCAN_DEEP),
                      capo_scan_cb, &st);

    CAPOProgress(NULL);
    if (st.has_igno) IGNOFree(&st.ig);

    if (o == FILESKIP) o = OK;  // normal completion
    return o;
}

// --- Scan a historic ref via keeper: walk tree, pull matching-ext blobs ---
//
//  `target` is a parsed URI with `?ref` (or `#sha`) identifying the
//  commit/tree to search.  For each regular-file entry whose extension
//  is known (and matches opts->target_ext if set), the blob is pulled
//  via KEEPGetExact and handed to opts->file_fn with mapped=NULL and
//  fpbuf=NULL — the callback must not defer the buffer (no mmap to
//  survive across hunks) and must not attempt on-disk replacement.
typedef struct {
    keeper             *k;
    CAPOScanOpts const *opts;
    ok64                last_err;
} capo_ref_scan_ctx;

static ok64 capo_ref_visit(u8cs path, u8 kind, u8cp esha,
                            u8cs blob, void0p ctx) {
    (void)blob;
    capo_ref_scan_ctx *cx = (capo_ref_scan_ctx *)ctx;
    if (kind != WALK_KIND_REG && kind != WALK_KIND_EXE) return OK;
    if ($empty(path)) return OK;

    size_t plen = (size_t)$len(path);
    u8cs file_ext = {};
    CAPOFindExt(file_ext, path[0], plen);
    if ($empty(file_ext) || !CAPOKnownExt(file_ext)) return OK;
    if (!$empty(cx->opts->target_ext) &&
        !TOKSameLexer(file_ext, cx->opts->target_ext)) return OK;

    sha1 bsha = {};
    memcpy(bsha.data, esha, 20);

    Bu8 bbuf = {};
    if (u8bAllocate(bbuf, 1UL << 22) != OK) return OK;
    u8 btype = 0;
    ok64 gr = KEEPGetExact(cx->k, &bsha, bbuf, &btype);
    if (gr != OK || btype != DOG_OBJ_BLOB) {
        u8bFree(bbuf);
        return OK;
    }
    u8cs source = {u8bDataHead(bbuf), u8bIdleHead(bbuf)};

    //  NUL-terminate the path for CAPOProgress.
    char pnul[FILE_PATH_MAX_LEN] = {};
    size_t cp = plen < sizeof(pnul) - 1 ? plen : sizeof(pnul) - 1;
    memcpy(pnul, path[0], cp);
    CAPOProgress(pnul);

    ok64 fo = cx->opts->file_fn(cx->opts->file_ctx, path, source,
                                 file_ext, NULL, NULL);
    u8bFree(bbuf);
    if (fo != OK) cx->last_err = fo;
    return OK;
}

ok64 CAPOScanRef(keeper *k, uri const *target,
                  CAPOScanOpts const *opts) {
    sane(k && target && opts && opts->file_fn);
    capo_ref_scan_ctx cx = {k, opts, OK};
    //  KEEPLsFiles takes a non-const uri*, but the function body only
    //  reads from it.  Cast away const — the callee does not mutate.
    ok64 o = KEEPLsFiles(k, (uricp)target, capo_ref_visit, &cx);
    CAPOProgress(NULL);
    if (cx.last_err != OK) return cx.last_err;
    return o;
}

ok64 CAPOScanFiles(u8css files, CAPOScanOpts const *opts) {
    sane(opts != NULL && opts->file_fn != NULL);
    int nf = (int)$len(files);
    for (int i = 0; i < nf; i++) {
        u8cs *fp = u8cssAtP(files, i);
        size_t flen = (size_t)$len(*fp);
        if (flen == 0) continue;

        char line[FILE_PATH_MAX_LEN] = {};
        if (flen >= sizeof(line)) continue;
        memcpy(line, (*fp)[0], flen);

        u8cs file_ext = {};
        PATHu8sExt(file_ext, *fp);
        if ($empty(file_ext)) continue;
        if (!CAPOKnownExt(file_ext)) continue;
        if (!$empty(opts->target_ext)) {
            if (!TOKSameLexer(file_ext, opts->target_ext)) continue;
        }

        CAPOProgress(line);

        a_path(fpbuf);
        u8cs fps = {(u8cp)line, (u8cp)line + flen};
        if (PATHu8bFeed(fpbuf, fps) != OK) continue;

        u8bp mapped = NULL;
        if (FILEMapRO(&mapped, $path(fpbuf)) != OK) continue;

        u8cs source = {};
        $mv(source, u8bDataC(mapped));
        u8cs relpath = {(u8cp)line, (u8cp)line + flen};

        ok64 o = opts->file_fn(opts->file_ctx, relpath, source,
                               file_ext, mapped, fpbuf);
        if (o != OK) {
            FILEUnMap(mapped);
            if (o != OK) return o;
        }
    }
    CAPOProgress(NULL);
    return OK;
}

// --- Trigram filter ---

ok64 CAPOTrigramFilter(Bu32 hashbuf, b8 *has_trigrams,
                        u8csc text, u8csc reporoot) {
    sane(hashbuf != NULL && has_trigrams != NULL);
    *has_trigrams = NO;

    a_path(capodir);
    ok64 ro = CAPOResolveDir(capodir, reporoot);
    if (ro != OK) return OK;  // no index, skip filtering
    a_dup(u8c, dirslice, u8bDataC(capodir));

    size_t maxhashes = 1ULL << 28;
    call(u32bMap, hashbuf, maxhashes);

    u64cs runs[CAPO_MAX_LEVELS] = {};
    u64css stack = {runs, runs};
    u8bp mmaps[CAPO_MAX_LEVELS] = {};
    u32 nidxfiles = 0;
    call(CAPOStackOpen, stack, mmaps, &nidxfiles, dirslice);
    stack[1] = stack[0] + nidxfiles;

    if (nidxfiles == 0) {
        CAPOStackClose(mmaps, nidxfiles);
        return OK;
    }

    u8cp p = text[0];
    u8cp end = text[1] - 2;
    while (p <= end) {
        if (CAPOTriChar(p[0]) && CAPOTriChar(p[1]) &&
            CAPOTriChar(p[2])) {
            u8cs tri = {p, p + 3};
            u64 tri_prefix = CAPOTriPack(tri);

            u64cs seek_runs[CAPO_MAX_LEVELS];
            for (u32 i = 0; i < nidxfiles; i++) {
                seek_runs[i][0] = runs[i][0];
                seek_runs[i][1] = runs[i][1];
            }
            u64css seek_iter = {seek_runs, seek_runs + nidxfiles};
            HITu64Start(seek_iter);

            if (!*has_trigrams) {
                u32bReset(hashbuf);
                CAPOCollectPaths(seek_iter, tri_prefix,
                                 u32bDataIdle(hashbuf));
                *has_trigrams = YES;
            } else {
                u32sSort(u32bData(hashbuf));
                CAPOFilterInPlace(hashbuf, seek_iter, tri_prefix);
            }
        }
        p++;
    }

    CAPOStackClose(mmaps, nidxfiles);

    if (*has_trigrams && u32bDataLen(hashbuf) > 0)
        u32sSort(u32bData(hashbuf));

    return OK;
}

// --- DOG control struct ---

spot SPOT = {};

static b8 spot_is_open(void) { return SPOT.h != NULL; }
static b8 spot_is_rw = NO;

// --- Branch-dir composition ---

//  Compose `<root>/.dogs/spot/<leaf_branch>` into `out`
//  (NUL-terminated).  Mirrors `keep_branch_dir` /
//  `graf_branch_dir`.
static ok64 spot_branch_dir(path8b out, home *h, u8cs leaf_branch) {
    sane(h && out);
    u8bReset(out);
    a_dup(u8c, root_s, u8bDataC(h->root));
    call(PATHu8bFeed, out, root_s);
    a_cstr(rel, CAPO_DIR);
    call(PATHu8bAdd, out, rel);
    if ($ok(leaf_branch) && !u8csEmpty(leaf_branch)) {
        a_dup(u8c, br, leaf_branch);
        if (!$empty(br) && *u8csLast(br) == '/') u8csShed1(br);
        if (!$empty(br)) call(PATHu8bAdd, out, br);
    }
    call(PATHu8bTerm, out);
    done;
}

//  YES iff `path` is an existing directory.
static b8 spot_dir_exists(path8s path) {
    struct stat st = {};
    if (FILEStat(&st, path) != OK) return NO;
    return (st.st_mode & S_IFMT) == S_IFDIR;
}

typedef ok64 (*spot_dir_cb)(spot *s, u8cs dir, void0p ctx);

//  Walk one branch path component at a time, calling `cb` per prefix
//  dir (trunk first → leaf last).  Mirrors `keep_walk_branch` /
//  `graf_walk_branch`.
static ok64 spot_walk_branch(spot *s, u8cs leaf, spot_dir_cb cb,
                              void0p ctx) {
    sane(s && cb);
    a_pad(u8, sdir, FILE_PATH_MAX_LEN);
    a_dup(u8c, root_s, u8bDataC(s->h->root));
    call(PATHu8bFeed, sdir, root_s);
    a_cstr(rel, CAPO_DIR);
    call(PATHu8bAdd, sdir, rel);
    call(PATHu8bTerm, sdir);
    {
        a_pad(u8, d, FILE_PATH_MAX_LEN);
        a_dup(u8c, sd, u8bDataC(sdir));
        call(PATHu8bFeed, d, sd);
        call(PATHu8bTerm, d);
        call(cb, s, $path(d), ctx);
    }
    if (u8csEmpty(leaf)) done;
    a_pad(u8, d, FILE_PATH_MAX_LEN);
    a_dup(u8c, sd, u8bDataC(sdir));
    call(PATHu8bFeed, d, sd);
    u8cp p = leaf[0];
    u8cp seg_start = p;
    while (p <= leaf[1]) {
        b8 at_end = (p == leaf[1]);
        if (at_end || *p == '/') {
            if (p > seg_start) {
                u8cs seg = {seg_start, p};
                call(PATHu8bPush, d, seg);
                call(PATHu8bTerm, d);
                call(cb, s, $path(d), ctx);
                ((u8 **)d)[2]--;  // drop the terminator NUL
            }
            seg_start = p + 1;
        }
        p++;
    }
    done;
}

static ok64 spot_open_dir_cb(spot *s, u8cs dir, void0p ctx) {
    (void)ctx;
    if (!spot_dir_exists(dir)) return SPOTNOPATH;
    a_cstr(ext, CAPO_IDX_EXT);
    return DOGPupOpenAll(s->puppies, dir, ext);
}

ok64 SPOTOpenBranch(home *h, u8cs branch, b8 rw) {
    sane(h != NULL && $ok(branch));

    if (spot_is_open()) {
        if (rw && !spot_is_rw) return SPOTOPENRO;
        return SPOTOPEN;
    }

    //  Normalize: trunk aliases → empty; non-trunk gains trailing '/'.
    a_pad(u8, nb, SPOT_LEAF_BRANCH_MAX);
    call(DPATHBranchNormFeed, nb, branch);
    a_dup(u8c, norm, u8bDataC(nb));

    //  Register on home (idempotent re-opens absorbed).
    {
        ok64 o = HOMEOpenBranch(h, branch, rw);
        if (o != OK && o != HOMEOPEN && o != HOMEROBR && o != HOMEMAX)
            return o;
    }

    spot *s = &SPOT;
    zerop(s);
    s->h = h;
    s->lock_fd = -1;
    s->out_fd = -1;
    s->rw = rw;
    spot_is_rw = rw;
    s->color = isatty(STDOUT_FILENO) ? YES : NO;
    s->term = (isatty(STDERR_FILENO) && isatty(STDOUT_FILENO)) ? YES : NO;

    call(kv32bAllocate, s->puppies, FILE_MAX_OPEN);

    if (u8csLen(norm) >= SPOT_LEAF_BRANCH_MAX) return CAPONOROOM;
    call(u8bAllocate, s->leaf_branch, SPOT_LEAF_BRANCH_MAX);
    call(PATHu8bTerm, s->leaf_branch);
    if (!u8csEmpty(norm)) call(PATHu8bFeed, s->leaf_branch, norm);

    //  Trunk dir always exists after this — first writer creates it.
    a_pad(u8, trunkdir, FILE_PATH_MAX_LEN);
    {
        u8cs empty = {};
        ok64 to = spot_branch_dir(trunkdir, h, empty);
        if (to != OK) {
            DOGPupClose(s->puppies);
            u8bFree(s->leaf_branch);
            zerop(s); spot_is_rw = NO;
            return to;
        }
    }
    call(FILEMakeDirP, $path(trunkdir));

    //  Walk trunk → leaf, scanning each dir for `<seqno>.spot.idx`.
    {
        a_dup(u8c, leaf, u8bDataC(s->leaf_branch));
        ok64 wo = spot_walk_branch(s, leaf, spot_open_dir_cb, NULL);
        if (wo != OK) {
            DOGPupClose(s->puppies);
            u8bFree(s->leaf_branch);
            zerop(s); spot_is_rw = NO;
            return wo;
        }
    }

    //  Lock the LEAF dir on rw (writes only land deepest).  Readers
    //  go lockless — DOGPupCreate publishes via tmp+rename.
    if (rw) {
        a_pad(u8, leafdir, FILE_PATH_MAX_LEN);
        a_dup(u8c, leaf, u8bDataC(s->leaf_branch));
        call(spot_branch_dir, leafdir, h, leaf);
        a_pad(u8, lockpath, FILE_PATH_MAX_LEN);
        a_dup(u8c, lds, u8bDataC(leafdir));
        call(PATHu8bFeed, lockpath, lds);
        a_cstr(lockrel, CAPO_LOCK_S);
        call(PATHu8bAdd, lockpath, lockrel);
        call(PATHu8bTerm, lockpath);
        call(FILECreate, &s->lock_fd, $path(lockpath));
        call(FILELock,   &s->lock_fd, rw);
    }

    call(u8bMap, s->arena, LESS_ARENA_SIZE);

    less_arena[0] = s->arena[0];
    less_arena[1] = s->arena[1];
    less_arena[2] = s->arena[2];
    less_arena[3] = s->arena[3];
    CAPO_COLOR = s->color;
    CAPO_TERM  = s->term;

    //  Allocate ingestion scratch.  rw only — read-only spot never
    //  writes to the index stack.  Seqno is owned by the puppy stack
    //  itself (DOGPupCreate picks max+1), so no separate counter.
    if (rw) {
        call(u64bMap, s->entries, CAPO_SCRATCH_LEN);
        call(u8bMap,  s->blob_stage, CAPO_BLOB_STAGE_LEN);
        call(kv64bAllocate, s->blob_offsets, CAPO_BLOB_OFFSETS_CAP);
        memset(s->blob_offsets[0], 0,
               (size_t)(s->blob_offsets[3] - s->blob_offsets[0])
                   * sizeof(kv64));
        s->blob_offsets[1] = s->blob_offsets[0];
        s->blob_offsets[2] = s->blob_offsets[3];
        call(u8bMap, s->pending_commits, CAPO_PENDING_COMMITS_LEN);
    }

    done;
}

ok64 SPOTOpen(home *h, b8 rw) {
    static u8c const _zero = 0;
    u8cs trunk = {(u8cp)&_zero, (u8cp)&_zero};
    return SPOTOpenBranch(h, trunk, rw);
}

//  Sort + dedup pending postings and write them out as a new puppy
//  in the leaf branch dir.  Leaves `entries` reset.  Seqno is owned
//  by the puppy stack — DOGPupCreate picks max(seqno)+1 internally.
static ok64 CAPOFlushRun(spot *s) {
    sane(s);
    if (u64bDataLen(s->entries) == 0) done;
    u64sp data = u64bData(s->entries);
    u64sSort(data);
    u64sDedup(data);
    a_pad(u8, leafdir, FILE_PATH_MAX_LEN);
    a_dup(u8c, leaf, u8bDataC(s->leaf_branch));
    call(spot_branch_dir, leafdir, s->h, leaf);
    call(FILEMakeDirP, $path(leafdir));
    a_cstr(ext, CAPO_IDX_EXT);
    size_t bytes = (size_t)((u8cp)data[1] - (u8cp)data[0]);
    u8cs raw = {(u8cp)data[0], (u8cp)data[0] + bytes};
    call(DOGPupCreate, s->puppies, $path(leafdir), ext, raw);
    u64bReset(s->entries);
    //  Maintain the 1/8 LSM ladder every flush — same discipline as
    //  graf's dag_flush_batch and keeper's pack-write sites.  Without
    //  this, repeated CAPOFlushRun calls in a long session pile up
    //  equal-sized puppies past the runs[CAPO_MAX_LEVELS] view cap.
    call(CAPOCompact, s);
    done;
}

// --- Close-pass tree walk: tokenize new commits' blobs ---
//
// Drains s->pending_commits (recorded by SPOTUpdate(COMMIT)) and walks
// each tree via KEEPLsFiles.  Per leaf with a known extension, fetches
// the blob's bytes from s->blob_stage (zero-copy if hashlet32 hit) or
// from KEEPGetExact (cold fallback for blobs ingested in earlier
// packs), runs CAPOIndexFile to emit trigram/MEN/DEF postings, then
// emits the tag-3 pair record (blob_hashlet30, path_hash) so the LSM's
// row-dedup absorbs unchanged-file-at-unchanged-path repeats.

typedef struct {
    spot   *s;
    keeper *k;
    Bkv64   seen_pairs;   // key=(hashlet30<<32|path_hash), dedup the walk
} capo_close_ctx;

static ok64 capo_close_visit(u8cs path, u8 kind, u8cp esha,
                              u8cs blob_unused, void0p ctx) {
    (void)blob_unused;
    capo_close_ctx *cx = (capo_close_ctx *)ctx;
    if (kind != WALK_KIND_REG && kind != WALK_KIND_EXE) return OK;
    if ($empty(path)) return OK;

    u8cs ext = {};
    PATHu8sExt(ext, path);
    if ($empty(ext) || !CAPOKnownExt(ext)) return OK;

    spot *s = cx->s;

    //  Try staged bytes first (zero-copy view into blob_stage).
    u32 hashlet32 = 0;
    memcpy(&hashlet32, esha, sizeof(u32));

    //  Dedup: skip if (hashlet30, path_hash) already tokenised this
    //  Close-pass.  Multiple commits sharing an unchanged file would
    //  otherwise re-tokenise it once per commit.
    u32 phash0 = CAPOPathHash(path);
    u32 hl30_0 = hashlet32 & 0x3FFFFFFFu;
    u64 pair_key = ((u64)hl30_0 << 32) | (u64)phash0;
    {
        kv64s tbl = {cx->seen_pairs[0], cx->seen_pairs[3]};
        kv64 probe = {.key = pair_key, .val = 0};
        if (HASHkv64Get(&probe, tbl) == OK) return OK;
    }
    u8cs source = {};
    Bu8 fetched = {};
    {
        kv64s tbl = {s->blob_offsets[0], s->blob_offsets[3]};
        kv64 probe = {.key = (u64)hashlet32, .val = 0};
        if (HASHkv64Get(&probe, tbl) == OK) {
            u32 off = (u32)(probe.val >> 32);
            u32 len = (u32)(probe.val & 0xFFFFFFFFUL);
            u8cp base = u8bDataHead(s->blob_stage);
            source[0] = base + off;
            source[1] = base + off + len;
        }
    }
    if ($empty(source)) {
        //  Cold path: blob lives in an earlier pack — pay the inflate.
        sha1 bsha = {};
        memcpy(bsha.data, esha, 20);
        if (u8bAllocate(fetched, 1UL << 22) != OK) return OK;
        u8 btype = 0;
        if (KEEPGetExact(cx->k, &bsha, fetched, &btype) != OK ||
            btype != DOG_OBJ_BLOB) {
            u8bFree(fetched);
            return OK;
        }
        source[0] = u8bDataHead(fetched);
        source[1] = u8bIdleHead(fetched);
    }

    //  Tokenise + emit trigram/MEN/DEF postings.
    (void)CAPOIndexFile(s->entries, source, ext, path);

    //  Emit pair record for LSM-level dedup of repeat (blob, path).
    idx64 pair = CAPOPairEntry(hl30_0, phash0);
    (void)u64bPush(s->entries, &pair);

    //  Record the pair in the per-walk seen set so subsequent commits
    //  visiting the same (blob, path) skip the tokeniser.
    {
        kv64s tbl = {cx->seen_pairs[0], cx->seen_pairs[3]};
        kv64 e = {.key = pair_key, .val = 1};
        HASHkv64Put(tbl, &e);
    }

    if (!BNULL(fetched)) u8bFree(fetched);
    return OK;
}

static ok64 capo_close_pass(spot *s) {
    sane(s);
    if (BNULL(s->pending_commits)) done;
    a_dup(u8c, commits, u8bData(s->pending_commits));
    if ($empty(commits)) done;

    capo_close_ctx cx = {s, &KEEP, {}};
    //  Sized for the union of (blob, path) pairs across all commits in
    //  this Close-pass.  16x the staged-blob count is a safe upper bound
    //  (most blobs land at ≤16 distinct paths via renames over history).
    u64 pair_cap = (u64)kv64bDataLen(s->blob_offsets) * 16;
    if (pair_cap < 4096) pair_cap = 4096;
    pair_cap = (pair_cap + 15) & ~(u64)15;
    call(kv64bAllocate, cx.seen_pairs, pair_cap);
    memset(cx.seen_pairs[0], 0,
           (size_t)(cx.seen_pairs[3] - cx.seen_pairs[0]) * sizeof(kv64));
    cx.seen_pairs[1] = cx.seen_pairs[0];
    cx.seen_pairs[2] = cx.seen_pairs[3];

    for (u8cp p = commits[0]; p + 20 <= commits[1]; p += 20) {
        a_pad(u8, hexbuf, 41);
        u8s hs = {u8bIdleHead(hexbuf), u8bTerm(hexbuf)};
        u8cs raw = {p, p + 20};
        HEXu8sFeedSome(hs, raw);
        u8bFed(hexbuf, 40);
        a_dup(u8c, hex, u8bData(hexbuf));

        uri u = {};
        u.fragment[0] = hex[0];
        u.fragment[1] = hex[1];
        (void)KEEPLsFiles(&KEEP, &u, capo_close_visit, &cx);
    }
    if (!BNULL(cx.seen_pairs)) kv64bFree(cx.seen_pairs);
    done;
}

void SPOTClose(void) {
    if (!spot_is_open()) return;
    spot *s = &SPOT;
    if (s->rw && s->entries[0]) {
        (void)capo_close_pass(s);
        CAPOFlushRun(s);
        //  Maintain the LSM 1/8 ladder: each fresh run on top of
        //  comparable-sized older runs needs to merge them.  Without
        //  this, every fetch dropped a new ~17MB run on disk and
        //  the stack grew unbounded.
        CAPOCompact(s);
        u64bUnMap(s->entries);
        if (!BNULL(s->blob_stage))      u8bUnMap(s->blob_stage);
        if (!BNULL(s->blob_offsets))    kv64bFree(s->blob_offsets);
        if (!BNULL(s->pending_commits)) u8bUnMap(s->pending_commits);
    }
    for (u32 i = 0; i < s->nmaps; i++) {
        if (s->toks[i][0] != NULL) u32bUnMap(s->toks[i]);
        if (s->maps[i] != NULL)    FILEUnMap(s->maps[i]);
    }
    if (!BNULL(s->puppies))     DOGPupClose(s->puppies);
    if (!BNULL(s->leaf_branch)) u8bFree(s->leaf_branch);
    if (s->arena[0]) u8bUnMap(s->arena);
    if (s->lock_fd >= 0) FILEClose(&s->lock_fd);
    s->nhunks = 0;
    s->nmaps  = 0;
    less_nhunks = 0;
    less_nmaps  = 0;
    s->h = NULL;
    spot_is_rw = NO;
}
