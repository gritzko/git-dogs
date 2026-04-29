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

#include "abc/BUF.h"
#include "abc/INT.h"
#include "abc/LSM.h"   // LSM_MAX_INPUTS for SNIFFMergeWalk's group cap
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
con ok64 SNIFFNOOP     = 0x1c5d23cf5d8619;     // legacy alias, prefer POSTNONE
con ok64 CLOCKBAD      = 0x31560c50b28d;
con ok64 PUTNONE       = 0x1979d5d85ce;
con ok64 DELDIRTY      = 0x34e54d49b762;
con ok64 POSTNONE      = 0x65871d5d85ce;
con ok64 MERGEFAIL     = 0x1639b40e3ca495;

#define SNIFF_FILE ".sniff"

// --- State ---

typedef struct {
    home   *h;        // borrowed
    u8bp    log_data; // pointer to FILE_WANT_BUFS slot for <wt>/.sniff
    Bkv64   log_idx;  // ts → byte-offset index over log_data
    b8      log_rw;   // YES iff log was opened RW (Close must trim)
    igno    ignores;  // wt-root .gitignore, loaded once at SNIFFOpen
} sniff;

extern sniff SNIFF;

// --- Public API ---

ok64 SNIFFOpen(home *h, b8 rw);
ok64 SNIFFClose(void);

ok64 SNIFFExec(cli *c);

//  Verb + value-flag tables for CLIParse.
extern char const *const SNIFF_VERBS[];
extern char const SNIFF_VAL_FLAGS[];

fun ok64 SNIFFFullpath(path8b out, u8cs reporoot, u8cs rel) {
    a_cstr(sep, "/");
    u8bFeed(out, reporoot);
    u8bFeed(out, sep);
    u8bFeed(out, rel);
    return PATHu8bTerm(out);
}

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

// --- N-way ULOG-row merge -------------------------------------------
//
//  Heap-walk a set of ULOG-shaped path/mode/sha streams, fan into a
//  per-path-key step callback.  Each input cursor is a `u8cs` view
//  over a sorted ULOG row buffer (one row per leaf,
//  `<ts>\t<verb>\t<path>?<mode>#<sha>\n`, produced by `KEEPTreeULog`,
//  `SNIFFWtULog`, or sliced from the `.sniff` log).  Inputs are
//  distinguished by their row verb — callers normally emit each
//  source with its own verb (`base`, `ours`, `theirs`, `wt`, `put`,
//  …) so the step callback can dispatch per record.
//
//  Capacity: $len(cursors) ≤ LSM_MAX_INPUTS (64).  Tie groups are
//  bounded by the same — one row per cursor per step.

//  Step callback.  `recs[0..n)` are all the records whose paths are
//  equal under `ULOGu8csZbyUri` for this step.  Order within the
//  group is heap-pop order (not the input-array order).  Caller
//  dispatches on `recs[i].verb` to identify each contributor.
//  A non-OK return aborts the walk.
typedef ok64 (*sniff_step_fn)(ulogreccp recs, u32 n, void *ctx);

//  Drain `cursors` to exhaustion, calling `cb` once per distinct
//  path-key.  `cursors` must have capacity for in-place heap ops
//  (the function calls `u8cssHeapZ` and mutates the array).
ok64 SNIFFMergeWalk(u8css cursors, sniff_step_fn cb, void *ctx);

#endif
