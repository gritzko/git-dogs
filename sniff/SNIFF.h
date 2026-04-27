#ifndef SNIFF_SNIFF_H
#define SNIFF_SNIFF_H

//  SNIFF — worktree state backed by an append-only URI log.
//
//  On disk: a single file `<wt>/.sniff` — a ULOG (see dog/ULOG.md):
//  `<ron60-ms>\t<verb>\t<uri>\n` rows record every op that changed
//  the worktree.  Row 0 is a `repo` anchor naming the store's
//  `.dogs/` via a `file://` URI.  Every file sniff writes is
//  `futimens`-stamped to the op's ts, so `mtime ∈ {row timestamps}`
//  means "clean, attributed".
//
//  No per-path hashlet cache lives across process invocations anymore
//  — the baseline tree is re-walked on demand (POST/PATCH) through
//  the URI abstraction (keeper for single-hash, graf for merge URIs),
//  and the change-set is computed from the ULOG alone.
//
//  The path index is owned by keeper (`<store>/.dogs/paths.log`,
//  shared across sniff/graf/spot).  SNIFFIntern / SNIFFPath / SNIFFCount
//  are thin wrappers over KEEP's registry.

#include "abc/BUF.h"
#include "abc/INT.h"
#include "abc/PATH.h"
#include "dog/CLI.h"
#include "dog/HOME.h"
#include "dog/IGNO.h"
#include "dog/ULOG.h"
#include "keeper/KEEP.h"

con ok64 SNIFFFAIL     = 0x1c5d23cf3ca495;
con ok64 SNIFFNOROM    = 0x71748f3d761b616;
con ok64 SNIFFOPEN     = 0x1c5d23cf619397;
con ok64 SNIFFOPRO     = 0x1c5d23cf6196d8;
con ok64 SNIFFDRTY     = 0x1c5d23cf35b762;
con ok64 SNIFFOVRL     = 0x1c5d23cf61f6d5;
con ok64 SNIFFNOFF     = 0x1c5d23cf5d83cf;
con ok64 SNIFFNOOP     = 0x1c5d23cf5d8619;     // legacy alias, prefer SNIFFPOSTNONE
con ok64 SNIFFCLOCKBAD = 0x23cf31560c50b28d;
con ok64 SNIFFPUTNONE  = 0x748f3d979d5d85ce;
con ok64 SNIFFDELDIRTY = 0x23cf34e54d49b762;
con ok64 SNIFFPOSTNONE = 0x23cf65871d5d85ce;

#define SNIFF_FILE ".sniff"

// --- State ---

typedef struct {
    home   *h;       // borrowed
    ulog    log;     // <wt>/.sniff (persistent URI log)
    Bu32    sorted;  // per-process path-index sort (rebuilt each call)
    igno    ignores; // wt-root .gitignore, loaded once at SNIFFOpen
} sniff;

extern sniff SNIFF;

// --- Public API ---

ok64 SNIFFOpen(home *h, b8 rw);
ok64 SNIFFClose(void);

ok64 SNIFFExec(cli *c);

//  Verb + value-flag tables for CLIParse.
extern char const *const SNIFF_VERBS[];
extern char const SNIFF_VAL_FLAGS[];

// --- Path registry (delegates to keeper) ---

u32  SNIFFIntern(u8cs path);
u32  SNIFFInternDir(u8cs path);
ok64 SNIFFPath(u8csp out, u32 index);
u32  SNIFFCount(void);
u32  SNIFFRootIdx(void);

fun b8 SNIFFIsDir(u32 index) {
    u8cs p = {};
    if (SNIFFPath(p, index) != OK) return NO;
    return (!$empty(p) && *$last(p) == '/');
}

fun ok64 SNIFFFullpath(path8b out, u8cs reporoot, u8cs rel) {
    a_cstr(sep, "/");
    u8bFeed(out, reporoot);
    u8bFeed(out, sep);
    u8bFeed(out, rel);
    return PATHu8bTerm(out);
}

//  Sort the keeper path registry by lexical path.  Rebuilt per
//  invocation; no persistence.  POST/DEL walk sorted indices to
//  assemble tree objects bottom-up.
ok64 SNIFFSort(void);

//  YES iff `rel` names one of sniff/keeper's on-disk metadata
//  entries (`.sniff`, `.dogs`) — either exactly or as a directory
//  prefix.  All wt-scan callbacks route through this so metadata
//  never leaks into commits / prune / status / mod rows.
b8   SNIFFSkipMeta(u8cs rel);

//  Resolve a path reported by FILEScan into a reporoot-relative
//  slice.  Fills `rel_out` with the stripped slice (no leading '/').
//  Returns NO when the absolute path is outside the reporoot or
//  resolves to the wt root itself.  `full` is the NUL-terminated
//  absolute path FILEScan delivers (via path8bp → u8bData).
b8   SNIFFRelFromFull(u8csp rel_out, u8cs reporoot, u8cs full);

#endif
