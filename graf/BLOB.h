#ifndef GRAF_BLOB_H
#define GRAF_BLOB_H

//  BLOB: resolve (commit, path) or (tree, name) to object bytes via
//  the keeper singleton.  Helpers shared by BLAME and GET — both need
//  to pull a file's bytes at a specific commit using graf's 60-bit
//  hashlets.

#include "abc/INT.h"
#include "dog/SHA1.h"
#include "keeper/KEEP.h"

//  Descend one tree entry by name.  On entry `*cur` is a tree sha;
//  on OK it is replaced by the child entry's sha.  Returns KEEPNONE
//  if no entry with `name` exists, KEEPFAIL on malformed tree.
ok64 GRAFTreeStep(keeper *k, sha1 *cur, u8cs name);

//  Resolve (commit_hashlet60, filepath) → blob body into `buf`.
//  Reads the commit object via KEEPGet (60-bit hashlet, hexlen=15),
//  parses its tree header, then walks `filepath` segment by segment
//  via GRAFTreeStep.  Returns KEEPNONE when the commit is missing,
//  the path is absent, or a hashlet collision tripped a wrong commit
//  type.
ok64 GRAFBlobAtCommit(u8bp buf, keeper *k,
                      u64 commit_hashlet60, u8cs filepath);

#endif
