#ifndef DOG_HOME_H
#define DOG_HOME_H

#include "abc/B.h"
#include "abc/BUF.h"
#include "abc/PATH.h"
#include "abc/URI.h"

con ok64 NOHOME    = 0x5d845858e;
con ok64 NOCONF    = 0x5d83185cf;
con ok64 HOMEOPEN  = 0x45858e619397;       // branch already open
con ok64 HOMEROBR  = 0x45858e6d82db;       // rw asked after a ro open
con ok64 HOMENOBR  = 0x45858e5d82db;       // no writable branch opened
con ok64 HOMEMAX   = 0x116163962a1;        // open-branch capacity exhausted

#define HOME_ARENA_SIZE         (1ULL << 32)   // 4 GB VA, pages on demand
#define HOME_CONFIG_MAX         (1UL  << 16)   // 64 KB is plenty for .dogs/config
#define HOME_OPEN_BRANCHES_MAX  16             // slot 0 + up to 15 merge parents
#define HOME_BRANCHES_DATA_SIZE 1024           // interned branch path bytes

// Per-invocation ambient state for every dog.  Owned by the top of
// the call chain; each dog embeds a `home *base` in its state struct
// and propagates it through DOGOpen.  All HOME functions take `home
// *` as their first argument.
//
// Branch-sharding scaffolding (Phase 0):
//   * `branches_data` is an interning buffer for canonical branch
//     path bytes.  Each slice in `open_branches` points into it.
//   * `open_branches` is a `u8csb` of normalized branch paths; slot
//     0 is the writable branch (set on the first rw Open, frozen for
//     the life of the process).  Remaining slots are ro branches
//     opened for merge / read.
//   * `write_frozen` is YES once slot 0 is held by an rw Open.  If
//     the first Open was ro, `write_frozen` stays NO and no later
//     Open can claim the write slot.
typedef struct {
    path8b root;     // repo root (where `.dogs/` lives), NUL-termed.
                     // Colocated default: equals `wt`.  Secondary
                     // worktrees override this from their `.sniff`
                     // file's `repo` URI so keeper/graf/spot open the
                     // shared store.
    path8b wt;       // worktree root (where `.sniff` lives).  May
                     // differ from `root` for secondary worktrees
                     // sharing a primary store.
    u8b    config;   // mmap of <root>/.dogs/config (empty if none)
    u8b    arena;    // scratch: 4 GB VA, stack-like consumption.  Each
                     // dog function must rewind the arena to its entry
                     // state before returning.  Use Bu8mark + Bu8rewind
                     // around any cross-dog call as a safety net.
    b8     rw;       // initial open mode; Phase 1 retires this in favour
                     // of the per-branch rw tracked via open_branches.

    u8b    branches_data;
    u8cs   open_branches[HOME_OPEN_BRANCHES_MAX];
    size_t open_branches_count;
    b8     write_frozen;

    //  Worktree tip — the (branch, sha) pair learned from `.sniff` at
    //  the top of the call chain (`be`) and forwarded to every dog
    //  via the `--at <root>?<branch>#<sha>` flag.  Empty when no tip
    //  is known (fresh clone, direct sub-dog invocation without
    //  `--at`).  `cur_branch` is the be-side branch path (empty =
    //  trunk).  `cur_sha` is 40 hex bytes (or empty).
    u8b    cur_branch;
    u8b    cur_sha;
} home;

// Initialize a `home` in place.  `at` is a URI carrying everything
// the home needs to know about its anchor:
//   path     → repo root (where `.dogs/` lives).  Empty → auto-detect
//              via HOMEFindDogs from cwd.
//   query    → current be-side branch path.  Empty == trunk.  When
//              non-empty (or path is set), HOMEOpenBranch is called
//              internally so slot 0 is claimed in one step.
//   fragment → current commit sha as 40 hex.  Empty when no tip is
//              recorded (fresh clone).
// rw=YES allows downstream dogs to create their `.dogs/<name>/` dirs.
// Reserves the arena, mmaps `.dogs/config` if present.
//
// Pass an empty `uri` for the historical "empty `at`" behaviour.
ok64 HOMEOpen(home *h, uricp at, b8 rw);

// Path-only shim for tests / fixtures that have a repo root but no
// branch / sha to forward.  Wraps `HOMEOpen` with a URI carrying just
// `path = root`.  Empty `root` triggers the same cwd-walk fallback.
fun ok64 HOMEOpenAt(home *h, u8cs root, b8 rw) {
    uri at = {};
    if ($ok(root) && !u8csEmpty(root)) {
        at.path[0] = root[0];
        at.path[1] = root[1];
    }
    return HOMEOpen(h, &at, rw);
}

// Release arena, config mmap, and path buffer.
ok64 HOMEClose(home *h);

// Walk up from cwd to the first ancestor directory containing `.dogs/`.
// Feeds the found path into h->root.  Returns NOHOME if the walk
// reaches / without finding one.
ok64 HOMEFind(home *h);

// Alias of HOMEFind kept for callers that want intent-named lookup.
// Finds the directory where `.dogs/` lives.
ok64 HOMEFindDogs(home *h);

// Resolve a peer binary into `out`: same directory as `argv0`
// (preserving symlinks), or, if `argv0` has no '/', the PATH entry
// that holds it.  Falls back to feeding just `name`.
ok64 HOMEResolveSibling(home *h, path8b out, u8csc name, u8csc argv0);

// Read one value from <root>/.dogs/config (TOML) addressed by a dotted
// path-style `needle` — e.g. for `[a.b] c = "v"` caller builds
// `a_path(n, "a", "b", "c")` and passes `$path(n)`.  Feeds the value
// bytes into `value`, advancing value[0] past them.  Returns NOCONF if
// the file is absent or the needle doesn't resolve.  Lexer errors
// propagate.
ok64 HOMEGetConfig(home *h, u8s value, path8s needle);

// Local host name used as prefix for local-origin ref keys (e.g.
// `//<host>?master`, `//<host>?HEAD`).  Resolution order:
//   1. config `user.host`   (explicit override)
//   2. config `user.email`  (default identity)
//   3. NOCONF (caller decides what to do)
// Feeds the raw bytes into `out` and advances `out[0]` past them.
ok64 HOMEHost(home *h, u8s out);

// --- Branch-sharding (Phase 0 scaffolding) ---
//
// Opens `branch` in the process-wide home singleton.  Normalizes the
// input (trunk aliases `""`, `main`, `master`, `trunk`, and their
// `heads/` forms → `""`; non-trunk branches gain a trailing `/`) and
// interns the canonical form into `h->branches_data`.  Appends a
// slice to `h->open_branches`.
//
// Mode rule: the *first* call to this function decides whether the
// session is writable.  If `rw=YES` on the first call, slot 0 is
// claimed as the write branch and `h->write_frozen` is set; later
// rw calls are refused with HOMEROBR.  If the first call was
// `rw=NO`, no subsequent call can claim rw either.
//
// Returns:
//   OK            newly opened
//   HOMEOPEN      already open (same normalized branch)
//   HOMEROBR  rw requested but the write slot is unavailable
//                 (first open was ro, or a different branch owns it)
//   HOMEMAX  open-branch capacity exhausted, or branches_data full
ok64 HOMEOpenBranch(home *h, u8cs branch, b8 rw);

// Feeds the writable branch slice into `out` (slice endpoints
// pointing into `h->branches_data`).  Returns HOMENOBR if no
// rw Open has happened in this process.
ok64 HOMEWriteBranch(home const *h, u8cs out);

// YES iff `branch` is an ancestor (prefix in canonical form) of any
// currently-opened branch, or equals one.  Used by resolvers to
// decide whether a flat-stack entry's home branch is in scope.
// `branch` must already be canonical (trunk=`""`, else trailing `/`).
b8 HOMEBranchVisible(home const *h, u8cs branch);

#endif
