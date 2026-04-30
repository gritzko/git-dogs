#ifndef SNIFF_CLASS_H
#define SNIFF_CLASS_H

//  CLASS — baseline ⊕ worktree path classifier.
//
//  Single chokepoint for "is this path tracked / untracked / on-disk
//  but absent / both?".  Builds two parallel ULOG streams (baseline
//  tree via `KEEPTreeULog`, wt via `SNIFFWtULog`), heap-merges them
//  by URI path through `SNIFFMergeWalk`, and dispatches one step per
//  distinct path to the caller's callback.
//
//  Replaces the per-caller "build a path-set in memory + linear
//  scan" pattern that PUT, DEL, and bare `sniff` were duplicating.
//  Same primitives POST already uses for its commit-time merge —
//  this file is just the read-only flavour with no decision rows.
//
//  Usage: caller provides a step callback; one call per distinct
//  path with the path slice, the kind, and pointers to the matching
//  baseline / wt ULOG records.  Slices and record pointers stay
//  valid only for the duration of the callback.

#include "abc/INT.h"
#include "abc/URI.h"
#include "dog/ULOG.h"

con ok64 CLASSFAIL = 0xc1a5503ca495;

typedef enum {
    CLASS_BASE_ONLY = 1,   // path in baseline tree, not on disk
    CLASS_WT_ONLY   = 2,   // path on disk, not in baseline tree
    CLASS_BOTH      = 3,   // path in both
} class_kind;

typedef struct {
    u8cs        path;       // borrowed slice into ULOG buffers
    class_kind  kind;       // base/wt presence
    ulogreccp   base_rec;   // baseline tree row (NULL if absent)
    ulogreccp   wt_rec;     // wt scan row       (NULL if absent)
    ulogreccp   put_rec;    // .sniff `put`  row since last post (NULL if none)
    ulogreccp   del_rec;    // .sniff `del`  row since last post (NULL if none)
} class_step;

typedef ok64 (*class_cb)(class_step const *step, void *ctx);

//  Build baseline + wt + staged-put + staged-delete ULOG streams,
//  heap-merge by URI key, fan to `cb` per distinct path.  Skips
//  submodule entries (`gitlinks`).  Empty / no-baseline → all wt
//  paths surface as `CLASS_WT_ONLY`.  `cb` may return any non-OK to
//  abort the walk; OK to continue.
//
//  Reads the keeper + sniff singletons (caller has both open).
ok64 SNIFFClassify(class_cb cb, void *ctx);

#endif
