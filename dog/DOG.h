#ifndef DOG_DOG_H
#define DOG_DOG_H

#include "abc/KV.h"
#include "abc/PATH.h"
#include "abc/RAP.h"
#include "abc/RON.h"
#include "abc/URI.h"

// Git object types (from packfile format)
#define DOG_OBJ_COMMIT 1
#define DOG_OBJ_TREE   2
#define DOG_OBJ_BLOB   3
#define DOG_OBJ_TAG    4

// --- Path hash ---
//
// A 64-bit positional identifier for a tree node.  The root hash is
// the ron60 encoding of the literal "ROOT"; every child's hash is
// RAPHashSeed(name, parent_hash), where `name` is just the leaf
// segment — no slashes, no parent prefix.  
con ok64 ROOT	= 0x6d861d;

// One step: child of `parent` named `name` (leaf, no slashes).
fun u64 DOGChildPathHash(u8csc name, u64 parent) {
    return RAPHashSeed(name, parent);
}

// Whole path: walk non-empty segments from the root, folding each
// one through DOGChildPathHash.  Empty path returns ROOT.
fun u64 DOGPathHash(path8s path) {
    u64 h = ROOT;
    $eachseg(seg, path) h = DOGChildPathHash(seg, h);
    return h;
}

// Given the path of a `.dogs/` directory (the row-0 `repo`-anchor URI
// path; with or without trailing slash), feed the parent repo-root
// path into `out`.  E.g. `/abs/path/.dogs/` → `/abs/path`.  Strips
// trailing slashes, then the `.dogs` segment, then any further
// trailing slashes.  Caller's `out` buffer is reset before the feed.
fun void DOGRepoFromDogs(u8cs in, u8bp out) {
    a_dup(u8c, p, in);
    if (!$empty(p) && *u8csLast(p) == '/') u8csShed1(p);
    a_cstr(dogs, ".dogs");
    size_t dl = $len(dogs);
    if ($len(p) >= dl && memcmp($atp(p, $len(p) - dl), dogs[0], dl) == 0)
        for (size_t i = 0; i < dl; i++) u8csShed1(p);
    while ($len(p) > 1 && *u8csLast(p) == '/') u8csShed1(p);
    u8bReset(out);
    u8bFeed(out, p);
}

// Shared error code for branch-scoped Open entry points that receive
// a branch path outside the supported set.  Phase 0 accepts only the
// trunk (canonical form = empty slice); later phases widen this.
con ok64 DOGNOBR = 0xd6105d82db;

// --- View-projector schemes (VERBS.md §"View projectors") ---
//
// One shared table for the whole repo.  DOGParseURI uses it to skip
// the scheme→authority promotion for projector schemes.  BE uses it
// to dispatch `be <scheme>:<URI>` to the dog that produces that
// projection.  Each dog's CLI recognises the schemes it owns and
// dispatches internally.  Adding a projector = one row here + the
// producing dog's internal dispatch branch; no further wiring.

typedef struct {
    char const *scheme;   // "ls", "tree", "sha1", ...
    char const *dog;      // "sniff" | "keeper" | "graf"
} DOGProjRoute;

// YES iff `scheme` names a registered view-projector scheme.
b8 DOGIsProjector(u8cs scheme);

// Dog name that handles `scheme:` projections, or NULL if `scheme`
// isn't a projector.  The returned cstr has static lifetime.
char const *DOGProjectorDog(u8cs scheme);

// YES iff `scheme` names a known transport (`ssh`, `https`, `file`,
// `be`, …).  Used by the CLI tokenizer to decide whether `<word>:`
// at the start of an arg is a URI scheme or a prose colon.
b8 DOGIsTransport(u8cs scheme);

// Parse a URI string with dog-specific normalization:
//   1. Invoke abc/URILexer for strict RFC 3986 parsing.
//   2. If the parsed URI has a scheme but no authority and its
//      path has no leading slash (i.e. the text is `word:path...`
//      rather than `proto://host/path`), treat the scheme as a
//      remote alias: move scheme → authority.  View-projector
//      schemes (`sha1:`, `blob:`, `tree:`, `commit:`, `log:`,
//      `refs:`, `diff:`, `size:`, `type:`, `ls:` — see VERBS.md)
//      are exempt: they stay as the scheme so `ls:subdir` and
//      `tree:src/?heads/feat` round-trip intact.
//   3. Non-numeric "ports" (`ssh://host:src/...` — `src` isn't a
//      port) get glued back onto the front of the path.
//   4. If the path's head-segment contains `@` (`user@host/rest`),
//      promote that prefix to authority/host/user.
//
// Rationale: users routinely type `localhost:src/git/protocol.h`
// or `origin:docs/README.md`.  Per RFC 3986 this parses as
// scheme="localhost", path="src/git/protocol.h".  For the dogs,
// the first token before a bare `:` almost always names a remote,
// not a protocol.
//
// True URIs with protocol schemes (`https://`, `file:///`) are
// unaffected — they have leading-`/` paths or populated authority.
//
// Path convention for remote transports (ssh/https/etc.): the
// path is always treated as **relative to the user's home on the
// remote**.  `ssh://host:src/repo` means `~/src/repo` on `host`.
// No `~` expansion in the grammar; no `/absolute/path` escape.
// Absolute local paths must use `file:///abs/path`.
ok64 DOGParseURI(urip uri, u8csc text);

// Canonicalise a URI in place — the single chokepoint every
// ULOG/REFS writer must go through so the on-disk form never
// carries redundant or ambiguous spellings.
//
//   Query (slice mutated on `u`):
//     - opaque hierarchical local branch path (no `refs/`, no `heads/`
//       prefix — those are git wire conventions handled by
//       keeper/GIT.h GITParseRef/GITFeedRef, not by us)
//     - trunk = empty query (`?`); bare `?/` folds to `?`
//     - everything else left alone
//
//   Fragment (slice mutated on `u`):
//     - strip a single leading `?` (value is bare 40-hex SHA or empty)
//     - empty fragment means deletion / tombstone
//
//   Presence is preserved: a query/fragment that was in the input
//   stays present-but-empty (non-NULL zero-length slice) rather than
//   reverting to absent, so `?#<sha>` (trunk move) and `?branch#`
//   (deletion) round-trip through the canonicaliser unchanged.
//
// Shape-only transform: slices are shrunk or pointed at their tail;
// no reallocation, no validation of contents.  `u->data` is not
// rewritten and will be out of sync with the mutated components.
ok64 DOGCanonURI(urip u);

// Emit the canonical byte form of a URI to `out`.  Thin wrapper:
// calls DOGCanonURI to canonicalise in place, then serialises.
// Transport schemes (ssh, https, git) are dropped as fungible;
// `file:` is preserved.  Present-but-empty query/fragment emit a
// bare `?` / `#` so `?#<sha>` (trunk move) and `?branch#` (deletion)
// round-trip.  This is the single entry point every ULOG/REFS
// writer goes through.
ok64 DOGCanonURIFeed(u8bp out, urip u);

// --- Puppies: stack of `<seqno>.<ext>` files ---
//
// A "puppy" is one git-pack-style file (mmap'd, contents are bytes
// of fixed-size sorted records — wh128, u64, etc.).  Keeper's pack
// indexes, graf's DAG runs, and spot's posting runs are all stacks
// of puppies under their respective `.dogs/<dog>/` dirs, named
// `<seqno>.<ext>` where `<seqno>` is a 10-char zero-padded RON64
// integer and `<ext>` is dog-specific (`.keeper.idx`, `.graf.idx`,
// `.spot.idx`, `.keeper` for raw pack data).
//
// State is one `kv32b`: each entry is `(key=seqno, val=fd)` with the
// mmap'd bytes living in `FILE_WANT_BUFS[fd]`.  Path and ext are
// caller-owned and re-passed per call so the same primitive serves
// multiple stacks per dog (keeper has both `.keeper` packs and
// `.keeper.idx` runs).  The typed merge during compaction stays
// caller-side (HIT*Compact); this API only does fs-level housekeeping.
#define DOG_PUP_SEQNO_W 10

con ok64 DOGPUPFAIL = 0x3584197993ca495;

// Scan `dir` for files matching `<10-RON64><ext>`, sort by seqno,
// FILEMapRO each, push (seqno, fd) into `pups`.  Empty dir → OK with
// pups left empty.  Caller must have allocated `pups` first.
ok64 DOGPupOpenAll(kv32b pups, path8s dir, u8cs ext);

// Atomically write `bytes` to `<max(seqno)+1>.<ext>` (tmp+rename),
// FILEMapRO, push (new_seqno, fd) onto `pups`.
ok64 DOGPupCreate(kv32b pups, path8s dir, u8cs ext, u8cs bytes);

// Unmap and unlink the youngest `m` puppies; trim `pups` by `m`.
ok64 DOGPupThinTail(kv32b pups, path8s dir, u8cs ext, u32 m);

// Unmap every puppy and free `pups` itself.
ok64 DOGPupClose(kv32b pups);

// Number of live puppies in the stack.
fun u32 DOGPupCount(kv32b pups) { return (u32)kv32bDataLen(pups); }

// Byte slice of the i-th puppy's contents (lookup via FILE_WANT_BUFS).
// Writes [data_start, data_end) into `out`; out becomes empty when
// `i` is out-of-range or the file's mapping has been released.
void DOGPupData(u8csp out, kv32b pups, u32 i);

// Fill `out` with one [data_start, data_end) slice per live puppy
// (oldest → newest, matching the kv32b's seqno order from
// DOGPupOpenAll).  Resets `out` first.  Skips puppies whose slot has
// been released — the resulting slice count may be less than
// DOGPupCount.  Used by the LSM merge / lookup loops in keeper, graf,
// spot to view the whole stack as one `u8css`.
ok64 DOGPupAllData(u8csb out, kv32b pups);

// Seqno of the i-th puppy.  Returns 0 when out-of-range.
fun u32 DOGPupSeqno(kv32b pups, u32 i) {
    if (i >= kv32bDataLen(pups)) return 0;
    kv32 const *base = (kv32 const *)kv32bDataHead(pups);
    return base[i].key;
}

// Append a short human date for unix timestamp `ts` (seconds) into
// `into`, picking the coarsest representation that still resolves
// `now - ts` unambiguously:
//
//   < 12hr past, or same calendar day → "HH:MM"   ("12:34")
//   < 7 days past                     → "WdyDD"   ("Tue05")
//   < ~6 months past, or same year    → "DDMon"   ("01Jan")
//   else                              → "DDMonYY" ("01Jan25")
//   ts <= 0                           → "?"
//
// Output is always centred-padded to exactly 7 ASCII columns so a
// column of dates lines up cleanly.  `now` is caller-supplied
// (typically `time(NULL)`) so tests can pin a moment.
ok64 DOGutf8sFeedDate(u8s into, i64 ts, i64 now);

// Classify a CLI arg: parse it as a URI, and when the parse is
// degenerate (bare token, no structure), back-fill the URI's `query`
// or `fragment` slot from the raw text per this table:
//
//   contains whitespace  → fragment  (commit msg, search phrase)
//   40 hex chars         → query     (SHA)
//   ref-safe (alnum _-.) → query     (branch/tag shorthand)
//   starts with /,./,../ → leave as path
//   anything else        → fragment
//
// DOGParseURI is attempted first; args that already have scheme,
// authority, rooted path, `?`, or `#` pass through unchanged.
ok64 DOGNormalizeArg(urip u, u8csc arg);

#endif
