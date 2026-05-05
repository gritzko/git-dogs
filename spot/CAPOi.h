#ifndef SPOT_CAPOi_H
#define SPOT_CAPOi_H

#include "CAPO.h"
#include "abc/FILE.h"
#include "spot/LESS.h"

// --- Helper: find file extension ---

#define CAPOFindExt(ext, path, len)                      \
    do {                                                 \
        (ext)[0] = NULL; (ext)[1] = NULL;                \
        for (size_t _i = (len); _i > 0; _i--) {         \
            if ((path)[_i - 1] == '/') break;            \
            if ((path)[_i - 1] == '.') {                 \
                (ext)[0] = (u8cp)(path) + _i - 1;       \
                (ext)[1] = (u8cp)(path) + (len);         \
                break;                                   \
            }                                            \
        }                                                \
    } while (0)

// --- Display helpers ---
void CAPOProgress(const char *line);
b8 CAPOExtIs(u8csc ext, const char *a, const char *b);
void CAPOFindFunc(u8csc source, u32 pos, u8csc ext,
                   char *out, size_t outsz);
void CAPOGrepCtx(u8csc source, u32 match_pos, u32 nctx,
                  u32 *lo, u32 *hi);

// --- Trigram query helpers ---
ok64 CAPOCollectPaths(u64css iter, u64 tri_prefix, u64g hashes);
void CAPOFilterInPlace(u64bp hashbuf, u64css iter, u64 prefix);

// --- HIT instantiation for u64cs ---

// Manual Swap for u64cs (array type, can't use Sx.h)
fun void u64csSwap(u64cs *a, u64cs *b) {
    u64c *t0 = (*a)[0], *t1 = (*a)[1];
    (*a)[0] = (*b)[0];
    (*a)[1] = (*b)[1];
    (*b)[0] = t0;
    (*b)[1] = t1;
}

#define X(M, name) M##u64##name
#include "abc/HITx.h"
#undef X
//  BOXx.h and HASHx.h use PRO.h's `sane()` / `done` macros, so they
//  can only be instantiated in .c files that include PRO.h.  Each
//  consumer (CAPO.c, the test driver) instantiates BOXu64 — and,
//  with BOX_DIRTY_HASH=1, HASHu64 — itself.

#define CAPO_MAX_HLS 64

// --- File scan callback ---

// Per-file callback for CAPOScan/CAPOScanFiles.
// relpath: relative to worktree root (e.g. "abc/FILE.h")
// source: mmapped file content (borrowed, valid for duration of call)
// file_ext: detected extension including dot (e.g. ".c")
// mapped: mmap handle — callback may LESSDefer() or FILEUnMap()
// fpbuf: absolute path buffer (for replace-mode file rewriting)
typedef ok64 (*CAPOFileFn)(void *ctx, u8csc relpath, u8csc source,
                            u8csc file_ext, u8bp mapped, path8p fpbuf);

typedef struct {
    u8cs       target_ext;   // language filter (empty = all known)
    u64cs      tri_hashes;   // sorted candidate fn_rap40 set
    b8         has_trigrams;  // tri_hashes is active
    CAPOFileFn file_fn;      // per-file callback
    void      *file_ctx;     // opaque context for file_fn
} CAPOScanOpts;

// Walk worktree via FILEScan + IGNO, call opts->file_fn per file.
ok64 CAPOScan(u8csc reporoot, CAPOScanOpts const *opts);

// Walk explicit file list, call opts->file_fn per file.
ok64 CAPOScanFiles(u8css files, CAPOScanOpts const *opts);

#include "abc/URI.h"
#include "keeper/KEEP.h"

// Walk a historic ref's tree via keeper (KEEPLsFiles), pulling each
// matching-ext blob, calling opts->file_fn with mapped=NULL.  Replace
// mode is not supported (no on-disk path); callers must check and
// reject spot --replace when the URI has a ref query.
ok64 CAPOScanRef(keeper *k, uri const *target,
                  CAPOScanOpts const *opts);

// Pre-compute candidate fn_rap40 set from literal text.
ok64 CAPOTrigramFilter(Bu64 hashbuf, b8 *has_trigrams,
                        u8csc text, u8csc reporoot);

// Same for regex patterns (extracts literal runs first).
ok64 CAPOTrigramFilterRegex(Bu64 hashbuf, b8 *has_trigrams,
                             u8csc pattern, u8csc reporoot);

// --- Hunk building (shared by SPOT/GREP) ---
ok64 CAPOBuildHunk(u8csc source, u32cs htoks, u32 ctx_lo, u32 ctx_hi,
                   range32 const *hls, int nhl,
                   u8csc file_ext, const char *filepath,
                   b8 needs_title, b8 *first_hunk);

#endif
