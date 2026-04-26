#ifndef DOG_QURY_H
#define DOG_QURY_H

#include "abc/INT.h"

con ok64 QURYFAIL = 0x69e6e23ca495;
con ok64 QURYBAD  = 0x1a79b88b28d;

// Ref type after parsing.
#define QURY_NONE 0
#define QURY_REF  1   // branch/tag/ref name
#define QURY_SHA  2   // hex SHA prefix (>=6 hex chars, all hex)

#define QURY_MIN_SHA 6

// Relative-prefix kind set when the spec starts with `./` or `..`.
//   QURY_REL_NONE — absolute (default; body holds the full path).
//   QURY_REL_DOWN — `./body`: child of the current branch.
//   QURY_REL_UP   — `../body`: sibling of the current branch
//                   (parent of current + body); also covers bare
//                   `..` (parent of current with empty body).
#define QURY_REL_NONE 0
#define QURY_REL_DOWN 1
#define QURY_REL_UP   2

// One parsed ref spec from a URI query.
//
// Grammar (single spec, between '&' separators):
//   spec     = relprefix? path ancestry?  |  '..'
//   relprefix= './'  |  '../'
//   path     = seg ('/' seg)*
//   seg      = atom+ ('.' atom+)*
//   atom     = alnum | [_\-]
//   ancestry = ('~' | '^') digit*
//
// SHA vs REF decided at parse time: all hex and len >= 6 → SHA.
//
// Examples:
//   main                   REF, rel=NONE
//   refs/tags/v2.8.6       REF, rel=NONE
//   ./fix                  REF, rel=DOWN, body="fix"
//   ../sibling             REF, rel=UP,   body="sibling"
//   ..                     REF, rel=UP,   body=empty
//   HEAD~3                 REF, anc_type='~', ancestry=3
//   main^                  REF, anc_type='^', ancestry=0
//   a1b2c3d4               SHA
typedef struct {
    u8cs body;       // ref path or SHA hex (points into input)
    u8   type;       // QURY_NONE/REF/SHA
    u8   rel;        // QURY_REL_NONE/DOWN/UP
    u8   anc_type;   // '~' or '^' or 0
    u32  ancestry;   // N value (0 if bare ~/^)
} qref;

typedef qref *qrefp;
typedef qref const *qrefcp;

// Slice types for iteration.
typedef qrefp  qrefs[2];
typedef qrefcp qrefcs[2];

// Drain one ref spec from input.  Advances input past the
// parsed spec and any trailing '&' separator.
// Returns OK on success, QURYFAIL on bad syntax.
// On empty input, returns OK with out->type = QURY_NONE.
ok64 QURYu8sDrain(u8cs input, qrefp out);

// Resolve a parsed spec to an absolute branch path.  Writes the
// absolute path into `out` (without leading `?` or trailing `/`).
//
//   spec->rel == NONE → writes spec->body verbatim (the absolute
//                       branch path the user typed).
//   spec->rel == DOWN → writes "<current>/<body>", or just <body>
//                       when current is empty (trunk).
//   spec->rel == UP   → writes "<parent>/<body>", where <parent>
//                       is the dirname of <current>; if <body> is
//                       empty, writes just <parent>.  At top level
//                       (current empty or no '/'), <parent> is
//                       empty (= trunk).
//
// Returns OK on success.  Returns QURYFAIL if spec is QURY_NONE or
// QURY_SHA (this helper handles ref paths only).
ok64 QURYBuildAbsolute(u8bp out, qrefcp spec, u8cs current);

#endif
