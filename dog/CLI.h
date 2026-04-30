#ifndef DOG_CLI_H
#define DOG_CLI_H

#include "abc/FILE.h"
#include "abc/URI.h"
#include "dog/HOME.h"

//  CLI_MAX_URIS — caps the URI count per invocation.  Glob expansions
//  (`be put test/*/*/*.txt`) routinely produce dozens of paths, so 16
//  was too tight; bumped to 1024.  uri is ~80B so the cli struct is
//  ~80KB on stack — large but fine for the entry frame.
#define CLI_MAX_URIS  1024
#define CLI_MAX_FLAGS 32  // pairs: 16 flags max

// Parsed CLI state.
//
//   dog [verb] [--flags] [URI] [free-form tail...]
//
// Most slices borrow from argv (no allocation).  The exception is the
// fragment-tail buffer — when a non-flag arg has none of `/.:?#` (i.e.
// is not URI-shaped), that arg and all remaining non-flag args are
// joined with ' ' into _tail and surfaced as a synthetic URI with just
// the fragment set.  This is how commit messages, search strings, and
// other free-form text reach the dogs without needing a flag like -m
// or quoting tricks.
//
// flags[] is interleaved: [flag0, val0, flag1, val1, ...].
// Boolean flags have an empty val. nuris/nflags count entries,
// not pairs — nflags is always even (flag + val = 2 entries).
typedef struct {
    u8cs   verb;                     // first non-flag non-URI arg, or empty
    u8cs   flags[CLI_MAX_FLAGS * 2]; // interleaved [flag, val] pairs
    u32    nflags;                   // count of entries (= 2 * npairs)
    uri    uris[CLI_MAX_URIS];       // parsed URI targets
    u32    nuris;
    char   _repo[1024];              // owned storage for repo root
    u8cs   repo;                     // repo root (points into _repo)
    char   _tail[4096];              // owned storage for fragment-tail
    u32    _tail_len;                // bytes used in _tail
    b8     tty_out;                  // isatty(STDOUT)
} cli;

// Parse $args into cli struct. verb_names is a NULL-terminated
// array of known verb strings (or NULL to disable verb detection).
// Flags start with '-'; everything else is a URI.
// Flags that take values: if the flag appears in val_flags
// (e.g. "-g\0-C\0-r\0"), the next arg is consumed as value.
// Otherwise value is set to an empty (non-NULL) sentinel.
ok64 CLIParse(cli *c, char const *const *verb_names,
              char const *val_flags);

// Check if a flag is set. Returns the value slice (non-empty
// for value flags, empty-but-non-NULL for boolean flags).
// Returns a NULL slice if not found.
fun void CLIFlag(u8csp out, cli const *c, char const *flag) {
    out[0] = NULL; out[1] = NULL;
    a_cstr(fs, flag);
    for (u32 i = 0; i + 1 < c->nflags; i += 2) {
        if ($eq(c->flags[i], fs)) {
            $mv(out, c->flags[i + 1]);
            return;
        }
    }
}

// Check if a flag is present (boolean test).
fun b8 CLIHas(cli const *c, char const *flag) {
    u8cs v = {};
    CLIFlag(v, c, flag);
    return v[0] != NULL;
}

// Compose `at` URI for `HOMEOpen`.  When `--at <uri>` is in `c->flags`,
// URILexer it into `*at`; the slices borrow from the cli's flag
// storage (stable for the lifetime of `c`).  When the flag is absent,
// `*at` stays zero (HOMEOpen will then auto-detect via cwd-walk).
//
// The flag's payload follows the at-log row shape:
//   `<root>?<branch>#<sha>` — path = repo root, query = current
//   branch (empty == trunk), fragment = 40-hex commit sha.
// `be` (the verb owner) is the producer; sub-dogs read it here.
fun void CLIAtURI(uri *at, cli const *c) {
    u8cs v = {};
    CLIFlag(v, c, "--at");
    memset(at, 0, sizeof(*at));
    if (v[0] == NULL || u8csEmpty(v)) return;
    u8csMv(at->data, v);
    URILexer(at);
}

#endif
