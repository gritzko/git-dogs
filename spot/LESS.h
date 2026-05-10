#ifndef SPOT_LESS_H
#define SPOT_LESS_H

#include "abc/INT.h"
#include "dog/HUNK.h"

// Producer-side staging: build hunks in `less_arena`, emit them to
// `spot_out_fd` via `spot_emit` (HUNKu8sFeed for TLV → bro pager,
// HUNKu8sFeedText for plain text → stdout).

// LESShunk kept as alias for hunk during transition.
typedef hunk LESShunk;

#define LESS_ARENA_SIZE (1UL << 24)   // 16MB
#define LESS_MAX_HUNKS  4              // tiny scratch ring
#define LESS_MAX_MAPS   1024

extern Bu8      less_arena;
extern LESShunk less_hunks[LESS_MAX_HUNKS];
extern u8bp     less_maps[LESS_MAX_MAPS];
extern Bu32     less_toks[LESS_MAX_MAPS];
extern u32      less_nhunks;
extern u32      less_nmaps;

// File descriptor for outgoing hunks.  STDOUT_FILENO when piped, else
// the write end of a pipe to bro.  -1 = uninitialized.
extern int spot_out_fd;

// Hunk → bytes serializer.  Either HUNKu8sFeed (TLV) or
// HUNKu8sFeedText (plain ASCII).  Selected by the CLI at startup.
typedef ok64 (*spot_emit_fn)(u8s into, hunk const *hk);
extern spot_emit_fn spot_emit;

ok64 LESSArenaInit(void);
void LESSArenaCleanup(void);
void LESSDefer(u8bp mapped, u32bp toks);

// Serialize less_hunks[less_nhunks] via spot_emit, write to spot_out_fd,
// rewind the staging arena.  Single-buffered: each emit reuses the slot.
void LESSHunkEmit(void);

// End-of-producer flush: cleans up deferred maps; the fd lifecycle
// (close + waitpid) is handled by the CLI.
ok64 LESSRun(LESShunk const *hunks, u32 nhunks);

#endif
