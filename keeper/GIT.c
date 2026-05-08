//  GIT: parsers for git objects
//
#include "GIT.h"

#include <string.h>

#include "abc/HEX.h"
#include "abc/PRO.h"

// --- Wire-protocol fixed strings (one global per literal) -----------

#define GITLIT(NAME, BYTES)                                          \
    static u8 const NAME##_BYTES[] = BYTES;                          \
    u8csc NAME = {                                                   \
        NAME##_BYTES,                                                \
        NAME##_BYTES + sizeof(NAME##_BYTES) - 1                      \
    }

GITLIT(GIT_FIELD_TREE,       "tree");
GITLIT(GIT_FIELD_PARENT,     "parent");
GITLIT(GIT_FIELD_FOSTER,     "foster");
GITLIT(GIT_FIELD_AUTHOR,     "author");
GITLIT(GIT_FIELD_COMMITTER,  "committer");
GITLIT(GIT_FIELD_GPGSIG,     "gpgsig");
GITLIT(GIT_FIELD_OBJECT,     "object");
GITLIT(GIT_TRAILER_PICKED,   "picked: ");

GITLIT(GIT_REFS_HEADS_PFX,   "refs/heads/");
GITLIT(GIT_REFS_TAGS_PFX,    "refs/tags/");
GITLIT(GIT_REFS_REMOTES_PFX, "refs/remotes/");
GITLIT(GIT_TAGS_PFX,         "tags/");
GITLIT(GIT_HEAD_LIT,         "HEAD");
GITLIT(GIT_MAIN_LIT,         "main");
GITLIT(GIT_PACK_MAGIC,       "PACK");
GITLIT(GIT_PKT_NAK,          "NAK");
GITLIT(GIT_PKT_ACK,          "ACK");
GITLIT(GIT_PKT_UNPACK_OK,    "unpack ok");
GITLIT(GIT_PKT_OK_PFX,       "ok ");
GITLIT(GIT_PKT_NG_PFX,       "ng ");
GITLIT(GIT_PKT_UNPACK_PFX,   "unpack ");

GITLIT(GIT_TYPE_COMMIT,      "commit");
GITLIT(GIT_TYPE_TREE,        "tree");
GITLIT(GIT_TYPE_BLOB,        "blob");
GITLIT(GIT_TYPE_TAG,         "tag");

#undef GITLIT

#include "dog/DOG.h"

ok64 GITTypeName(u8csp out, u8 obj_type) {
    switch (obj_type) {
        case DOG_OBJ_COMMIT: u8csMv(out, GIT_TYPE_COMMIT); return OK;
        case DOG_OBJ_TREE:   u8csMv(out, GIT_TYPE_TREE);   return OK;
        case DOG_OBJ_BLOB:   u8csMv(out, GIT_TYPE_BLOB);   return OK;
        case DOG_OBJ_TAG:    u8csMv(out, GIT_TYPE_TAG);    return OK;
    }
    out[0] = out[1] = NULL;
    return GITBADFMT;
}

//  Tree entry: <mode SP name>\0<20-byte-sha1>.  Find the NUL via
//  u8csFind; slice before = "<mode> <name>"; the 20 bytes that follow
//  are the raw SHA-1.
//
//  `mode` is optional — pass NULL when the caller doesn't need it.
//  When non-NULL, parses the leading octal-ascii digits into *mode
//  (e.g. "100644" → 0100644).  *mode is set to 0 on parse failure.
//  Mode is what graf needs to classify a child as TREE (040000),
//  BLOB (100xxx, 120000), or COMMIT/gitlink (160000).
ok64 GITu8sDrainTree(u8cs obj, u8csp file, u8csp sha1, u32 *mode) {
    sane(u8csOK(obj) && file && sha1);
    if (u8csEmpty(obj)) return NODATA;

    u8cp start = obj[0];
    a_dup(u8c, scan, obj);
    if (u8csFind(scan, 0) != OK) return GITBADFMT;

    file[0] = start;
    file[1] = scan[0];
    u8csUsed(scan, 1);  // consume NUL

    if ((u64)u8csLen(scan) < GIT_SHA1_LEN) return GITBADFMT;
    sha1[0] = scan[0];
    sha1[1] = scan[0] + GIT_SHA1_LEN;

    if (mode) {
        u32 m = 0;
        u8cp p = file[0];
        while (p < file[1] && *p >= '0' && *p <= '7') {
            m = (m << 3) | (u32)(*p - '0');
            p++;
        }
        //  Require at least one digit followed by space (or end).
        *mode = (p > file[0] && (p == file[1] || *p == ' ')) ? m : 0;
    }

    obj[0] = sha1[1];  // advance past this entry
    done;
}

//  Commit header iterator:
//    - blank line (leading '\n') → field empty, value = body, obj consumed.
//    - otherwise one "<field> <value>\n" line per call.  RFC-822 folding:
//      lines starting with ' ' continue the previous header (git uses this
//      for multi-line `gpgsig` signature blobs); the folded continuation
//      bytes are absorbed into `value` so they don't surface as bogus
//      empty-field "headers" with an empty body following.
ok64 GITu8sDrainCommit(u8cs obj, u8csp field, u8csp value) {
    sane(u8csOK(obj) && field && value);
    if (u8csEmpty(obj)) return NODATA;

    if (*obj[0] == '\n') {
        field[0] = field[1] = obj[0];        // empty field
        u8csUsed(obj, 1);                    // skip blank line
        u8csMv(value, obj);
        u8csUsedAll(obj);                    // body consumed whole
        done;
    }

    //  End-of-line via u8csFind; the line (excluding '\n') is
    //  [obj[0], nl).  Inside that line, find the mandatory space.
    a_dup(u8c, nl_scan, obj);
    b8   has_nl  = (u8csFind(nl_scan, '\n') == OK);
    u8cp nl      = has_nl ? nl_scan[0] : obj[1];

    u8cs sp_scan = {obj[0], nl};
    if (u8csFind(sp_scan, ' ') != OK) return GITBADFMT;

    field[0] = obj[0];
    field[1] = sp_scan[0];
    value[0] = sp_scan[0] + 1;               // skip space
    value[1] = nl;

    obj[0] = nl;
    if (has_nl) u8csUsed(obj, 1);            // skip '\n'

    //  Fold continuation lines (RFC-822: leading SP).  Extend `value`
    //  through each one so the caller sees a single header.
    while (!u8csEmpty(obj) && *obj[0] == ' ') {
        a_dup(u8c, cont_scan, obj);
        b8   c_nl      = (u8csFind(cont_scan, '\n') == OK);
        u8cp c_end     = c_nl ? cont_scan[0] : obj[1];
        value[1] = c_end;
        obj[0]   = c_end;
        if (c_nl) u8csUsed(obj, 1);
    }
    done;
}

ok64 GITu8sCommitTree(u8cs commit, u8 tree_sha[20]) {
    sane(u8csOK(commit) && tree_sha);
    a_dup(u8c, body, commit);
    u8cs field = {}, value = {};
    while (GITu8sDrainCommit(body, field, value) == OK) {
        if (u8csEmpty(field)) break;
        if (u8csEq(field, GIT_FIELD_TREE)) {
            if (u8csLen(value) < 40) return GITBADFMT;
            u8s bin = {tree_sha, tree_sha + 20};
            u8cs hex = {value[0], value[0] + 40};
            return HEXu8sDrainSome(bin, hex);
        }
    }
    return GITBADFMT;
}

// --- Refname parser / emitter -----------------------------------------

//  Try to consume `pfx` from the head of `s`.  Returns YES on match
//  (and advances `s` past the prefix); NO leaves `s` untouched.
static b8 git_eat_prefix(u8cs s, char const *pfx, size_t plen) {
    u8cs pfx_s = {(u8 const *)pfx, (u8 const *)pfx + plen};
    if (!u8csHasPrefix(s, pfx_s)) return NO;
    u8csUsed(s, plen);
    return YES;
}

ok64 GITParseRef(u8csc in, gitref_kind *kind, u8csp name) {
    sane(kind && name);
    *kind = GITREF_NONE;
    name[0] = name[1] = NULL;
    if (!u8csOK(in) || u8csEmpty(in)) return GITBADFMT;

    a_dup(u8c, s, in);

    //  "HEAD" (only as the bare literal — "refs/HEAD" is not a thing
    //  in modern git advertisements).
    if (u8csEq(s, GIT_HEAD_LIT)) {
        *kind = GITREF_HEAD;
        u8csMv(name, s);
        done;
    }

    //  Optional `refs/` prefix.  Once stripped, a `<sub>/...` head whose
    //  `<sub>` is none of {heads, tags, remotes} routes to OTHER (the
    //  whole remainder, including `<sub>/`, becomes the name).
    b8 had_refs = git_eat_prefix(s, "refs/", 5);
    if (had_refs && u8csEmpty(s)) return GITBADFMT;

    if (git_eat_prefix(s, "heads/", 6)) {
        if (u8csEmpty(s)) return GITBADFMT;
        *kind = GITREF_BRANCH;
    } else if (git_eat_prefix(s, "tags/", 5)) {
        if (u8csEmpty(s)) return GITBADFMT;
        *kind = GITREF_TAG;
    } else if (git_eat_prefix(s, "remotes/", 8)) {
        if (u8csEmpty(s)) return GITBADFMT;
        *kind = GITREF_REMOTE;
    } else if (had_refs) {
        //  `refs/<other>/...` — keep the whole remainder as name.
        *kind = GITREF_OTHER;
    } else {
        //  Bare name disambiguation.
        //    "vN..." (v\d.*)   → TAG
        //    contains '/'      → REMOTE
        //    otherwise         → BRANCH
        b8 v_tag = (u8csLen(s) >= 2 && s[0][0] == 'v' &&
                    s[0][1] >= '0' && s[0][1] <= '9');
        a_dup(u8c, slash_scan, s);
        b8 has_slash = (u8csFind(slash_scan, '/') == OK);
        if (v_tag)          *kind = GITREF_TAG;
        else if (has_slash) *kind = GITREF_REMOTE;
        else                *kind = GITREF_BRANCH;
    }

    u8csMv(name, s);
    done;
}

ok64 GITFeedRef(u8b out, gitref_kind kind, u8csc name) {
    sane(u8bOK(out));

    if (kind == GITREF_HEAD) {
        u8bFeed(out, GIT_HEAD_LIT);
        done;
    }

    if (!u8csOK(name) || u8csEmpty(name)) return GITBADFMT;

    a_cstr(refs_s, "refs/");
    u8bFeed(out, refs_s);
    switch (kind) {
        case GITREF_BRANCH: { a_cstr(p, "heads/");   u8bFeed(out, p); break; }
        case GITREF_TAG:    { a_cstr(p, "tags/");    u8bFeed(out, p); break; }
        case GITREF_REMOTE: { a_cstr(p, "remotes/"); u8bFeed(out, p); break; }
        case GITREF_OTHER:  break;  // name carries "<sub>/..."
        default:            return GITBADFMT;
    }
    u8bFeed(out, name);
    done;
}
