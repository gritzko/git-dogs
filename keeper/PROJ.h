#ifndef KEEPER_PROJ_H
#define KEEPER_PROJ_H

//  PROJ: keeper-owned view projectors (VERBS.md §"View projectors").
//
//  Each handler takes a pre-parsed URI whose `scheme` matches the
//  projector and emits a formatted view to stdout.  When `tlv` is YES
//  the bytes go through dog/HUNK as a TLV record (consumed by `bro`);
//  otherwise plain text / raw bytes are written.
//
//  Wired through KEEPProjDispatch, which KEEP.exe.c invokes when the
//  CLI parsed a verb-less arg and DOG_PROJECTORS routes its scheme to
//  "keeper".

#include "KEEP.h"

con ok64 PROJFAIL = 0xb1083ca495;
con ok64 PROJNONE = 0xb1085d85ce;

//  tree:[<path>]?<ref|sha>  — list one directory's entries
//  (mode, type, sha, name).  Non-recursive.
ok64 KEEPProjTree(keeper *k, uricp u, b8 tlv);

//  commit:?<ref|sha>  — render a commit object: header lines
//  (commit/tree/parents/author/committer) + message body.
ok64 KEEPProjCommit(keeper *k, uricp u, b8 tlv);

//  blob:[<path>]?<ref|sha>  — emit blob bytes.  In TLV mode, the bytes
//  are tokenized via dog/TOK using the URI path's extension and packed
//  into a hunk so `bro` can render syntax highlighting.
ok64 KEEPProjBlob(keeper *k, uricp u, b8 tlv);

//  Dispatch on `u->scheme`.  Returns PROJNONE for schemes the keeper
//  table claims but no handler is wired (helpful diagnostic).
ok64 KEEPProjDispatch(keeper *k, uricp u, b8 tlv);

#endif
