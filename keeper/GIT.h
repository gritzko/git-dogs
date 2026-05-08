#ifndef KEEPER_GIT_H
#define KEEPER_GIT_H

//  GIT: parsers for git objects (blob, tree, commit) and git refnames.
//
//  Blob: raw content, no parsing needed.
//
//  Tree format:  (<mode> <filename>\0<20-byte-sha1>)*
//  GITu8sDrainTree() consumes one entry per call.
//
//  Commit format:  (<field> <value>\n)*  \n  <body>
//  GITu8sDrainCommit() consumes one header per call;
//  on the blank line separator it returns empty field
//  and the commit body as value.
//
//  Refnames: GITParseRef / GITFeedRef are the single point of
//  translation between be-style ref strings and git's wire form
//  (`refs/heads/<X>` etc.).  Callers above this layer treat the
//  query slice as opaque; only the wire boundary uses these.

#include "abc/B.h"
#include "abc/INT.h"
#include "abc/OK.h"
#include "abc/S.h"

#define GIT_SHA1_LEN 20

con ok64 GITFAIL = 0x1049d3ca495;
con ok64 GITBADFMT = 0x1049d2ca34f59d;

//  Wire-protocol fixed strings — defined here so call sites compare
//  against a single source of truth instead of redeclaring literals.
//  Use with u8csEq / u8csHasPrefix.
extern u8csc GIT_FIELD_TREE;
extern u8csc GIT_FIELD_PARENT;
//  Beagle-only commit header — emitted by sniff/POST.c on absorb-tip
//  rebases (`?br#`) and squashes (`?br`).  Same wire shape as `parent`
//  but doesn't participate in standard git first-parent walks; the DAG
//  indexer keys it as DAG_T_FOSTER so reachability walks can opt in.
extern u8csc GIT_FIELD_FOSTER;
extern u8csc GIT_FIELD_AUTHOR;
extern u8csc GIT_FIELD_COMMITTER;
extern u8csc GIT_FIELD_GPGSIG;
extern u8csc GIT_FIELD_OBJECT;
//  Beagle-only commit-message trailer — emitted by sniff/POST.c on
//  cherry-pick.  `picked: <40-hex>\n` lines after the message body
//  record the cherry-picked source commit; per spec these do NOT
//  participate in standard reachability, but a tunable walk may opt
//  in (one-step only — picked targets are leaves, their own ancestors
//  are NOT followed).
extern u8csc GIT_TRAILER_PICKED;

extern u8csc GIT_REFS_HEADS_PFX;
extern u8csc GIT_REFS_TAGS_PFX;
extern u8csc GIT_REFS_REMOTES_PFX;
extern u8csc GIT_TAGS_PFX;
extern u8csc GIT_HEAD_LIT;
extern u8csc GIT_MAIN_LIT;
extern u8csc GIT_PACK_MAGIC;
extern u8csc GIT_PKT_NAK;
extern u8csc GIT_PKT_ACK;
extern u8csc GIT_PKT_UNPACK_OK;
extern u8csc GIT_PKT_OK_PFX;
extern u8csc GIT_PKT_NG_PFX;
extern u8csc GIT_PKT_UNPACK_PFX;

//  Loose-object type names ("commit"/"tree"/"blob"/"tag"), indexed by
//  the DOG_OBJ_* tag.  These are the literal ASCII words git's
//  loose-object framing prepends to content before SHA-1 hashing.
extern u8csc GIT_TYPE_COMMIT;
extern u8csc GIT_TYPE_TREE;
extern u8csc GIT_TYPE_BLOB;
extern u8csc GIT_TYPE_TAG;

//  Lookup by DOG_OBJ_* tag.  Out-of-range tags fill `out` with the
//  empty slice and return GITBADFMT.  Index 0 is intentionally empty
//  (no DOG_OBJ_* uses 0).
ok64 GITTypeName(u8csp out, u8 obj_type);

//  Kind of a git ref.  GITREF_NONE = unparseable / empty input.
typedef enum {
    GITREF_NONE   = 0,
    GITREF_HEAD,    //  "HEAD"
    GITREF_BRANCH,  //  refs/heads/<name>          (name may contain '/')
    GITREF_TAG,     //  refs/tags/<name>
    GITREF_REMOTE,  //  refs/remotes/<remote>/<branch>  (name = "<r>/<b>")
    GITREF_OTHER,   //  refs/<sub>/<name>  for sub ∉ {heads,tags,remotes}
} gitref_kind;

//  Parse any refname shape into (kind, bare-name).  `name` is a
//  sub-slice of `in`; no allocation.
//
//    "HEAD"                 → (HEAD,   "HEAD")
//    "refs/heads/X"         → (BRANCH, "X")
//    "heads/X"              → (BRANCH, "X")
//    "refs/tags/X"          → (TAG,    "X")
//    "tags/X"               → (TAG,    "X")
//    "refs/remotes/o/b"     → (REMOTE, "o/b")
//    "remotes/o/b"          → (REMOTE, "o/b")
//    "refs/<sub>/X"         → (OTHER,  "<sub>/X")
//    bare "vN..." (v\d.*)   → (TAG,    "vN...")
//    bare "X/Y..."          → (REMOTE, "X/Y...")
//    bare "X" (no '/')      → (BRANCH, "X")
//
//  Returns OK on success, GITBADFMT for empty / malformed input.
ok64 GITParseRef(u8csc in, gitref_kind *kind, u8csp name);

//  Emit the canonical wire form of a (kind, name) pair into `out`:
//    HEAD                   → "HEAD"
//    (BRANCH, X)            → "refs/heads/X"
//    (TAG, X)               → "refs/tags/X"
//    (REMOTE, o/b)          → "refs/remotes/o/b"
//    (OTHER, sub/X)         → "refs/sub/X"
//
//  `out` is a pre-reset buffer.  Returns GITBADFMT if name is empty
//  for a kind that requires it, or kind is unrecognised.
ok64 GITFeedRef(u8b out, gitref_kind kind, u8csc name);

//  Drain one tree entry: file mode+name into `file`, raw SHA1 into
//  `sha1`, and the parsed octal mode into `*mode` (NULL allowed when
//  the caller doesn't need it).  Advances `obj`; returns NODATA when
//  exhausted.
ok64 GITu8sDrainTree(u8cs obj, u8csp file, u8csp sha1, u32 *mode);

//  Drain one commit header: field name into `field`, value into `value`.
//  On the blank-line separator, returns empty `field` and commit body
//  as `value`.  Returns NODATA when exhausted.
ok64 GITu8sDrainCommit(u8cs obj, u8csp field, u8csp value);

//  Parse the "tree <hex>" header from a commit body and write the
//  20-byte binary SHA-1 into tree_sha.  Returns GITBADFMT if the
//  tree line is missing or malformed.
ok64 GITu8sCommitTree(u8cs commit, u8 tree_sha[20]);

#endif
