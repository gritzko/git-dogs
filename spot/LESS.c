#include "LESS.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "abc/FILE.h"
#include "abc/PRO.h"
#include "dog/HUNK.h"

// --- Producer-side staging state ---
Bu8      less_arena = {};
LESShunk less_hunks[LESS_MAX_HUNKS];
u8bp     less_maps[LESS_MAX_MAPS];
Bu32     less_toks[LESS_MAX_MAPS];
u32      less_nhunks = 0;
u32      less_nmaps  = 0;

int          spot_out_fd = -1;
spot_emit_fn spot_emit   = NULL;

ok64 LESSArenaInit(void) {
    less_nhunks = 0;
    less_nmaps  = 0;
    memset(less_hunks, 0, sizeof(less_hunks));
    memset(less_maps,  0, sizeof(less_maps));
    memset(less_toks,  0, sizeof(less_toks));
    if (less_arena[0] != NULL) {
        u8bShedAll(less_arena);  // empty DATA, IDLE spans full buffer
        return OK;
    }
    return u8bMap(less_arena, LESS_ARENA_SIZE);
}

void LESSArenaCleanup(void) {
    for (u32 i = 0; i < less_nmaps; i++) {
        if (less_toks[i][0] != NULL) u32bUnMap(less_toks[i]);
        if (less_maps[i] != NULL)    FILEUnMap(less_maps[i]);
    }
    less_nhunks = 0;
    less_nmaps  = 0;
}

//  Take ownership of `mapped` and `toks` (4-pointer buffer
//  descriptors).  Caller must not use them after the call —
//  buffers are single-owner; LESS will unmap them at cleanup.
void LESSDefer(u8bp mapped, u32bp toks) {
    if (less_nmaps >= LESS_MAX_MAPS) return;
    less_maps[less_nmaps] = mapped;
    for (int i = 0; i < 4; i++) less_toks[less_nmaps][i] = toks[i];
    less_nmaps++;
}

// Serialize the just-built hunk via spot_emit, write to spot_out_fd,
// then rewind the entire arena.  After emission the hunk's title, toks
// and hili slices (which live in the arena) are dead — the pipe owns
// the bytes now.  Full rewind keeps the arena from filling up across
// hundreds of streaming hunks.
void LESSHunkEmit(void) {
    if (spot_emit == NULL || spot_out_fd < 0) {
        // No output set up yet — accumulate nhunks for LESSRun.
        less_nhunks++;
        return;
    }
    LESShunk *hk = &less_hunks[less_nhunks];

    // TLV/text serialization goes into arena idle space (past title/toks/hili).
    u8cp start = u8bIdleHead(less_arena);
    if (spot_emit(u8bIdle(less_arena), hk) != OK) {
        // Reset arena: drop this hunk's title/toks/hili + failed TLV.
        u8bShedAll(less_arena);
        return;
    }

    u8cs ser = {start, u8bIdleHead(less_arena)};
    while (!$empty(ser)) {
        ssize_t w = write(spot_out_fd, ser[0], $len(ser));
        if (w > 0) { u8csFed(ser, (size_t)w); continue; }
        if (w < 0 && errno == EINTR) continue;
        break;  // EAGAIN with non-blocking, EPIPE, etc — drop the rest
    }

    // Full arena rewind: title, toks, hili, and serialized bytes are
    // all consumed.  The hunk struct in less_hunks[0] will be reused
    // next time CAPOBuildHunk runs.
    u8bShedAll(less_arena);
}

ok64 LESSRun(LESShunk const *hunks, u32 nhunks) {
    sane(1);
    (void)hunks;
    (void)nhunks;
    LESSArenaCleanup();
    done;
}
