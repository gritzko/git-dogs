//  PROJ: keeper view projectors — tree:, commit:, blob:.
//
#include "PROJ.h"
#include "GIT.h"
#include "REFS.h"
#include "WALK.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "abc/B.h"
#include "abc/HEX.h"
#include "abc/PATH.h"
#include "abc/PRO.h"

#include "dog/DOG.h"
#include "dog/HUNK.h"
#include "dog/TOK.h"

// =====================================================================
//  Helpers
// =====================================================================

//  20-byte SHA → 40 hex bytes appended to out.
static void proj_feed_sha_hex(u8b out, sha1 const *s) {
    sha1hex hex = {};
    sha1hexFromSha1(&hex, s);
    a_rawc(hs, hex);
    (void)u8bFeed(out, hs);
}

//  Append a NUL-terminated literal.
static void proj_feed_lit(u8b out, char const *s) {
    size_t n = strlen(s);
    u8cs sl = {(u8 const *)s, (u8 const *)s + n};
    (void)u8bFeed(out, sl);
}

//  Resolve `u` (#hex or ?ref) to a binary commit/tree SHA.  Mirrors
//  the early half of KEEPResolveTree but stops at the commit (or
//  whatever object the URI points at — caller filters by type).
//  On success returns OK; *out is the 20-byte SHA-1.
static ok64 proj_resolve_object_sha(keeper *k, uricp u, sha1 *out) {
    sane(k && u && out);
    a_path(keepdir, u8bDataC(k->h->root), KEEP_DIR_S);

    //  #hex — convert prefix to a full SHA via KEEPGet (which scans
    //  hashlet matches and verifies).  We don't need the body here,
    //  so use a scratch buffer and discard.
    if (!u8csEmpty(u->fragment)) {
        if (u8csLen(u->fragment) >= 40) {
            u8s sb = {out->data, out->data + 20};
            u8cs hx = {u->fragment[0], u->fragment[0] + 40};
            return HEXu8sDrainSome(sb, hx);
        }
        //  Short prefix: fetch object to confirm and recompute its sha.
        Bu8 tmp = {};
        call(u8bAllocate, tmp, 1UL << 20);
        u64 hashlet = WHIFFHexHashlet60(u->fragment);
        u8 type = 0;
        ok64 go = KEEPGet(k, hashlet, u8csLen(u->fragment), tmp, &type);
        if (go == OK) {
            a_dup(u8c, body, u8bData(tmp));
            KEEPObjSha(out, type, body);
        }
        u8bFree(tmp);
        return go;
    }

    if (u8csEmpty(u->query)) fail(KEEPFAIL);

    //  REFSResolve handles `?ref`, full URIs, alias chains.
    a_pad(u8, arena_buf, 1024);
    uri resolved = {};
    a_dup(u8c, in_uri, u->data);
    ok64 ro = REFSResolve(&resolved, arena_buf, $path(keepdir), in_uri);
    if (ro == OK && u8csLen(resolved.query) >= 40) {
        u8s sb = {out->data, out->data + 20};
        u8cs hx = {resolved.query[0], resolved.query[0] + 40};
        return HEXu8sDrainSome(sb, hx);
    }
    fail(PROJNONE);
}

//  Descend a '/'-separated subpath inside a tree.  Caller owns `pathbuf`
//  (used as scratch).  Returns the final entry's sha + kind in *out_*.
//  Empty / "." subpath returns the input tree as a DIR.
static ok64 proj_descend(keeper *k, sha1 const *root_tree, u8cs subpath,
                          sha1 *out_sha, u8 *out_kind) {
    sane(k && root_tree && out_sha && out_kind);
    sha1 cur = *root_tree;
    u8 cur_kind = WALK_KIND_DIR;

    u8cs scan = {};
    u8csMv(scan, subpath);
    //  Tolerate "." / "./" for "this directory" — both shapes come
    //  from the bareword promotion in dog/DOG.c (`be tree:./` vs
    //  `be tree:.`) and should collapse to the empty-path root walk.
    if (u8csLen(scan) == 1 && scan[0][0] == '.') scan[0] = scan[1];
    else if (u8csLen(scan) == 2 && scan[0][0] == '.' && scan[0][1] == '/')
        scan[0] = scan[1];

    while (!$empty(scan)) {
        while (!$empty(scan) && *scan[0] == '/') scan[0]++;
        if ($empty(scan)) break;

        u8cs seg = {scan[0], scan[0]};
        while (seg[1] < scan[1] && *seg[1] != '/') seg[1]++;
        if (seg[0] == seg[1]) break;
        scan[0] = seg[1];

        if (cur_kind != WALK_KIND_DIR) fail(PROJNONE);

        Bu8 tbuf = {};
        call(u8bAllocate, tbuf, 1UL << 20);
        u8 otype = 0;
        ok64 go = KEEPGetExact(k, &cur, tbuf, &otype);
        if (go != OK || otype != DOG_OBJ_TREE) {
            u8bFree(tbuf);
            return go == OK ? PROJNONE : go;
        }

        u8cs tree_s = {u8bDataHead(tbuf), u8bIdleHead(tbuf)};
        u8cs file = {}, esha = {};
        b8 found = NO;
        sha1 next_sha = {};
        u8 next_kind = 0;
        while (GITu8sDrainTree(tree_s, file, esha, NULL) == OK) {
            u8cs fscan = {file[0], file[1]};
            if (u8csFind(fscan, ' ') != OK) continue;
            u8cs mode_s = {file[0], fscan[0]};
            u8cs name_s = {fscan[0] + 1, file[1]};
            if (u8csLen(name_s) != u8csLen(seg)) continue;
            if (memcmp(name_s[0], seg[0], u8csLen(name_s)) != 0) continue;
            next_kind = WALKu8sModeKind(mode_s);
            (void)sha1Drain(esha, &next_sha);
            found = YES;
            break;
        }
        u8bFree(tbuf);
        if (!found || next_kind == 0) fail(PROJNONE);
        cur = next_sha;
        cur_kind = next_kind;
    }
    *out_sha = cur;
    *out_kind = cur_kind;
    done;
}

//  Title for the hunk header bar: "<scheme>:<path>?<query>" or
//  "<scheme>:#<frag>".  Display label only — not a protocol URI.
static void proj_feed_title(u8b out, uricp u) {
    if (!u8csEmpty(u->scheme)) {
        (void)u8bFeed(out, u->scheme);
        (void)u8bFeed1(out, ':');
    }
    if (!u8csEmpty(u->path)) (void)u8bFeed(out, u->path);
    if (!u8csEmpty(u->query)) {
        (void)u8bFeed1(out, '?');
        (void)u8bFeed(out, u->query);
    }
    if (!u8csEmpty(u->fragment)) {
        (void)u8bFeed1(out, '#');
        (void)u8bFeed(out, u->fragment);
    }
}

//  Emit `text` as a hunk: TLV via HUNKu8sFeed (bro will render), or
//  raw bytes otherwise.  Used by tree: and commit: where there's no
//  tokenization.  `toks` may be empty.
static ok64 proj_emit_hunk(uricp u, Bu8 text, tok32cs toks, b8 tlv) {
    sane(u);
    if (!tlv) {
        fwrite(u8bDataHead(text), 1, u8bDataLen(text), stdout);
        fflush(stdout);
        done;
    }
    a_pad(u8, title, 512);
    proj_feed_title(title, u);

    hunk hk = {};
    hk.uri[0]  = u8bDataHead(title);
    hk.uri[1]  = u8bIdleHead(title);
    hk.text[0] = u8bDataHead(text);
    hk.text[1] = u8bIdleHead(text);
    if (toks != NULL) {
        hk.toks[0] = toks[0];
        hk.toks[1] = toks[1];
    }

    size_t tlen = u8bDataLen(text);
    Bu8 outbuf = {};
    call(u8bAllocate, outbuf, tlen + (1UL << 16));
    ok64 fo = HUNKu8sFeed(u8bIdle(outbuf), &hk);
    if (fo != OK) { u8bFree(outbuf); return fo; }
    fwrite(u8bDataHead(outbuf), 1, u8bDataLen(outbuf), stdout);
    fflush(stdout);
    u8bFree(outbuf);
    done;
}

// =====================================================================
//  tree:
// =====================================================================

//  git mode prefix → display columns ("100644 blob", "040000 tree", …).
//  Wide-enough fixed columns so names line up.
static void proj_tree_mode_type(u8b out, u8 kind) {
    char const *mode = "??????";
    char const *type = "?????";
    switch (kind) {
        case WALK_KIND_DIR: mode = "040000"; type = "tree";   break;
        case WALK_KIND_REG: mode = "100644"; type = "blob";   break;
        case WALK_KIND_EXE: mode = "100755"; type = "blob";   break;
        case WALK_KIND_LNK: mode = "120000"; type = "blob";   break;
        case WALK_KIND_SUB: mode = "160000"; type = "commit"; break;
        default: break;
    }
    proj_feed_lit(out, mode);
    (void)u8bFeed1(out, ' ');
    proj_feed_lit(out, type);
    //  Pad type to a stable 6-char column ("commit" is the widest).
    size_t tn = strlen(type);
    while (tn++ < 6) (void)u8bFeed1(out, ' ');
}

ok64 KEEPProjTree(keeper *k, uricp u, b8 tlv) {
    sane(k && u);

    //  Resolve URI → root tree SHA.  KEEPResolveTree handles ?ref,
    //  #hex, and commit→tree dereference.
    sha1 root_tree = {};
    call(KEEPResolveTree, k, u, &root_tree);

    //  Descend the URI's path inside that tree.  Empty path stays at
    //  the root; trailing '/' is fine.
    sha1 target = {};
    u8 target_kind = 0;
    u8cs sub = {};
    u8csMv(sub, u->path);
    call(proj_descend, k, &root_tree, sub, &target, &target_kind);
    if (target_kind != WALK_KIND_DIR) fail(PROJFAIL);

    //  Fetch the target tree's bytes and walk one level.
    Bu8 tbuf = {};
    call(u8bAllocate, tbuf, 1UL << 20);
    u8 otype = 0;
    ok64 go = KEEPGetExact(k, &target, tbuf, &otype);
    if (go != OK || otype != DOG_OBJ_TREE) {
        u8bFree(tbuf);
        return go == OK ? PROJFAIL : go;
    }

    //  Format each entry into `text`.
    Bu8 text = {};
    ok64 ao = u8bAllocate(text, 1UL << 20);
    if (ao != OK) { u8bFree(tbuf); return ao; }

    u8cs scan = {u8bDataHead(tbuf), u8bIdleHead(tbuf)};
    u8cs file = {}, esha = {};
    while (GITu8sDrainTree(scan, file, esha, NULL) == OK) {
        u8cs fscan = {file[0], file[1]};
        if (u8csFind(fscan, ' ') != OK) continue;
        u8cs mode_s = {file[0], fscan[0]};
        u8cs name_s = {fscan[0] + 1, file[1]};
        u8 kind = WALKu8sModeKind(mode_s);
        if (kind == 0) continue;

        proj_tree_mode_type(text, kind);
        (void)u8bFeed1(text, ' ');
        sha1 esh = {};
        (void)sha1Drain(esha, &esh);
        proj_feed_sha_hex(text, &esh);
        (void)u8bFeed1(text, '\t');
        (void)u8bFeed(text, name_s);
        if (kind == WALK_KIND_DIR) (void)u8bFeed1(text, '/');
        (void)u8bFeed1(text, '\n');
    }
    u8bFree(tbuf);

    ok64 eo = proj_emit_hunk(u, text, NULL, tlv);
    u8bFree(text);
    return eo;
}

// =====================================================================
//  commit:
// =====================================================================

ok64 KEEPProjCommit(keeper *k, uricp u, b8 tlv) {
    sane(k && u);

    sha1 csha = {};
    call(proj_resolve_object_sha, k, u, &csha);

    Bu8 obj = {};
    call(u8bAllocate, obj, 1UL << 20);
    u8 otype = 0;
    ok64 go = KEEPGetExact(k, &csha, obj, &otype);
    if (go != OK) { u8bFree(obj); return go; }

    //  Tag → dereference once to its target object.
    if (otype == DOG_OBJ_TAG) {
        a_dup(u8c, tbody, u8bData(obj));
        u8cs tf = {}, tv = {};
        sha1 tgt = {};
        b8 found = NO;
        while (GITu8sDrainCommit(tbody, tf, tv) == OK) {
            if (u8csEmpty(tf)) break;
            if (u8csLen(tf) == 6 && memcmp(tf[0], "object", 6) == 0 &&
                u8csLen(tv) >= 40) {
                u8s sb = {tgt.data, tgt.data + 20};
                u8cs hx = {tv[0], tv[0] + 40};
                if (HEXu8sDrainSome(sb, hx) == OK) found = YES;
                break;
            }
        }
        if (found) {
            csha = tgt;
            u8bReset(obj);
            otype = 0;
            go = KEEPGetExact(k, &csha, obj, &otype);
            if (go != OK) { u8bFree(obj); return go; }
        }
    }

    if (otype != DOG_OBJ_COMMIT) {
        fprintf(stderr, "keeper: commit: object is not a commit (type=%u)\n",
                (unsigned)otype);
        u8bFree(obj);
        fail(PROJFAIL);
    }

    Bu8 text = {};
    ok64 ao = u8bAllocate(text, 1UL << 20);
    if (ao != OK) { u8bFree(obj); return ao; }

    //  Header: "commit <sha40>\n".  The remaining headers (tree,
    //  parent, author, committer) are emitted verbatim from the
    //  object body — same shape as `git cat-file -p`.
    proj_feed_lit(text, "commit ");
    proj_feed_sha_hex(text, &csha);
    (void)u8bFeed1(text, '\n');

    a_dup(u8c, body, u8bData(obj));
    u8cs field = {}, value = {};
    while (GITu8sDrainCommit(body, field, value) == OK) {
        if (u8csEmpty(field)) {
            //  Blank-line separator — `value` is the message body.
            (void)u8bFeed1(text, '\n');
            (void)u8bFeed(text, value);
            //  Ensure a trailing newline so the message terminates
            //  cleanly even when the commit body lacks one.
            if (!u8csEmpty(value) && *(value[1] - 1) != '\n')
                (void)u8bFeed1(text, '\n');
            break;
        }
        (void)u8bFeed(text, field);
        (void)u8bFeed1(text, ' ');
        (void)u8bFeed(text, value);
        (void)u8bFeed1(text, '\n');
    }
    u8bFree(obj);

    ok64 eo = proj_emit_hunk(u, text, NULL, tlv);
    u8bFree(text);
    return eo;
}

// =====================================================================
//  blob:
// =====================================================================

ok64 KEEPProjBlob(keeper *k, uricp u, b8 tlv) {
    sane(k && u);

    //  KEEPGetByURI handles both `?<sha>` (bare blob) and
    //  `<path>?<ref|sha>` (path-in-tree), so we don't duplicate
    //  resolution here.
    Bu8 text = {};
    call(u8bAllocate, text, 64UL << 20);
    ok64 go = KEEPGetByURI(k, u, text);
    if (go != OK) { u8bFree(text); return go; }

    if (!tlv) {
        a_dup(u8c, data, u8bData(text));
        write(STDOUT_FILENO, data[0], u8csLen(data));
        u8bFree(text);
        done;
    }

    //  TLV: tokenize via dog/TOK using the path's extension so bro
    //  can render syntax highlighting.  Without an extension (bare
    //  `blob:?<sha>` or unknown ext) there's no language hint and we
    //  ship the bytes unhighlighted — bro still pages them via HUNK.
    Bu32 tok_arena = {};
    ok64 ta = u32bAllocate(tok_arena, (size_t)(u8bDataLen(text) + 16));
    if (ta != OK) { u8bFree(text); return ta; }

    tok32cs toks_slice = {NULL, NULL};
    if (!u8csEmpty(u->path)) {
        u8cs ext = {};
        a_dup(u8c, ps, u->path);
        PATHu8sExt(ext, ps);
        if (!$empty(ext) && TOKKnownExt(ext)) {
            u8cs source = {u8bDataHead(text), u8bIdleHead(text)};
            u32 *begin = u32bIdleHead(tok_arena);
            ok64 to = HUNKu32bTokenize(tok_arena, source, ext);
            if (to == OK) {
                u32 *end = u32bIdleHead(tok_arena);
                toks_slice[0] = (u32 const *)begin;
                toks_slice[1] = (u32 const *)end;
            }
        }
    }

    ok64 eo = proj_emit_hunk(u, text, toks_slice, YES);
    u32bFree(tok_arena);
    u8bFree(text);
    return eo;
}

// =====================================================================
//  Dispatch
// =====================================================================

//  YES iff `s` is hex-only and at least HASH_MIN_HEX, at most 40 chars.
//  Used to spot a sha-prefix query (e.g. `?abc1234`) so it can be
//  routed through keeper's hashlet index — which accepts any prefix
//  ≥ HASH_MIN_HEX — by promoting it into the fragment slot.
static b8 proj_is_hex_prefix(u8cs s) {
    size_t n = (size_t)u8csLen(s);
    if (n < HASH_MIN_HEX || n > 40) return NO;
    $for(u8c, p, s) {
        u8 c = *p;
        if (!((c >= '0' && c <= '9') ||
              (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F'))) return NO;
    }
    return YES;
}

ok64 KEEPProjDispatch(keeper *k, uricp u, b8 tlv) {
    sane(k && u);
    if (u8csEmpty(u->scheme)) fail(PROJFAIL);

    a_cstr(s_tree,   "tree");
    a_cstr(s_commit, "commit");
    a_cstr(s_blob,   "blob");

    //  Per VERBS.md §"Ref resolution", `?<hex-prefix>` is a sha
    //  lookup.  KEEPResolveTree (used by tree:/commit: and the
    //  path-bearing blob: form) only special-cases the fragment slot;
    //  mirror the user's intent into the fragment so any prefix from
    //  HASH_MIN_HEX through 40 chars routes through KEEPGet's hashlet
    //  index.  `blob:?<hex>` (bare blob, empty path) stays untouched —
    //  KEEPGetByURI has its own hashlet branch for that shape.
    uri local = *u;
    b8 bare_blob = $eq(local.scheme, s_blob) && u8csEmpty(local.path);
    if (!bare_blob && u8csEmpty(local.fragment) &&
        proj_is_hex_prefix(local.query)) {
        u8csMv(local.fragment, local.query);
        local.query[0] = NULL;
        local.query[1] = NULL;
    }
    uricp un = (uricp)&local;

    if ($eq(un->scheme, s_tree))   return KEEPProjTree(k, un, tlv);
    if ($eq(un->scheme, s_commit)) return KEEPProjCommit(k, un, tlv);
    if ($eq(un->scheme, s_blob))   return KEEPProjBlob(k, un, tlv);

    //  DOG_PROJECTORS routed this scheme to keeper but no handler is
    //  wired here.  Surface that explicitly so the gap is obvious.
    fprintf(stderr, "keeper: projector '%.*s:' not implemented\n",
            (int)$len(un->scheme), (char *)un->scheme[0]);
    fail(PROJNONE);
}
