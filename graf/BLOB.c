//  BLOB: shared (commit, path) → blob + (tree, name) → sha helpers.
//  Lifted from graf/BLAME.c so GRAFGet can reuse them.
//
#include "BLOB.h"

#include <string.h>

#include "abc/PRO.h"
#include "dog/DOG.h"
#include "graf/DAG.h"
#include "keeper/GIT.h"

ok64 GRAFTreeStep(keeper *k, sha1 *cur, u8cs name) {
    sane(k && cur);
    Bu8 tbuf = {};
    call(u8bAllocate, tbuf, 1UL << 20);
    u8 otype = 0;
    ok64 o = KEEPGetExact(k, cur, tbuf, &otype);
    if (o != OK) { u8bFree(tbuf); return o; }
    if (otype != DOG_OBJ_TREE) { u8bFree(tbuf); fail(KEEPFAIL); }

    u8cs body = {u8bDataHead(tbuf), u8bIdleHead(tbuf)};
    u8cs field = {}, esha = {};
    ok64 result = KEEPNONE;
    while (GITu8sDrainTree(body, field, esha, NULL) == OK) {
        u8cs scan = {field[0], field[1]};
        if (u8csFind(scan, ' ') != OK) continue;
        u8cs entry_name = {scan[0] + 1, field[1]};
        if ($len(entry_name) != $len(name)) continue;
        if (memcmp(entry_name[0], name[0], $len(name)) != 0) continue;
        memcpy(cur->data, esha[0], 20);
        result = OK;
        break;
    }
    u8bFree(tbuf);
    return result;
}

ok64 GRAFBlobAtCommit(u8bp buf, keeper *k,
                      u64 commit_hashlet60, u8cs filepath) {
    sane(buf && k);

    Bu8 cbuf = {};
    call(u8bAllocate, cbuf, 1UL << 20);
    u8 ct = 0;
    ok64 o = KEEPGet(k, commit_hashlet60,
                     DAG_H60_HEXLEN, cbuf, &ct);
    if (o != OK || ct != DOG_OBJ_COMMIT) { u8bFree(cbuf); return KEEPNONE; }

    sha1 tree_sha = {};
    b8 got_tree = NO;
    {
        a_dup(u8c, scan, u8bDataC(cbuf));
        u8cs field = {}, value = {};
        while (GITu8sDrainCommit(scan, field, value) == OK) {
            if (u8csEmpty(field)) break;
            a_cstr(ft, "tree");
            if ($eq(field, ft) && u8csLen(value) >= 40) {
                DAGsha1FromHex(&tree_sha, (char const *)value[0]);
                got_tree = YES;
                break;
            }
        }
    }
    u8bFree(cbuf);
    if (!got_tree) return KEEPNONE;

    sha1 cur = tree_sha;
    u8cs rest = {filepath[0], filepath[1]};
    while (!$empty(rest)) {
        u8cp slash = rest[0];
        while (slash < rest[1] && *slash != '/') slash++;
        u8cs name = {rest[0], slash};
        ok64 s = GRAFTreeStep(k, &cur, name);
        if (s != OK) return s;
        rest[0] = (slash < rest[1]) ? slash + 1 : slash;
    }

    u8 btype = 0;
    call(KEEPGetExact, k, &cur, buf, &btype);
    if (btype != DOG_OBJ_BLOB) return KEEPNONE;
    done;
}
