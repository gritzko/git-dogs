//  KEEPExec — run a parsed CLI against an open keeper state.
//  Same effect as invoking `keeper ...` as a separate process.
//
#include "KEEP.h"
#include "PROJ.h"
#include "REFS.h"
#include "WIRE.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "abc/FILE.h"
#include "abc/HEX.h"
#include "abc/PRO.h"
#include "dog/CLI.h"
#include "dog/DOG.h"
#include "dog/WHIFF.h"

// --- Verb / flag tables ---

char const *const KEEP_CLI_VERBS[] = {
    "get", "put", "post", "delete", "status", "import", "verify",
    "refs", "tips", "ls-files",
    "upload-pack", "receive-pack",
    "help", NULL
};

char const KEEP_CLI_VAL_FLAGS[] = "--want\0--have\0--at\0";

// --- Usage ---

static void keep_usage(void) {
    fprintf(stderr,
        "Usage: keeper <verb> [flags] [URI...]\n"
        "\n"
        "  Verbs:\n"
        "    get //remote[?ref]         fetch objects from remote\n"
        "    get .#hashprefix           cat object to stdout\n"
        "    get .?refname              resolve ref to SHA\n"
        "    put .?ref .#sha            move local ref pointer\n"
        "    put //remote?ref           push to remote (stub)\n"
        "    post //remote              create+push a commit on HEAD\n"
        "    delete //remote?ref        push-delete a remote ref\n"
        "    delete //remote            drop alias (tombstone host rows)\n"
        "    status                     show store stats\n"
        "    import <packfile>          import a git packfile\n"
        "    verify .#sha               verify object + recurse\n"
        "    refs                       list known refs\n"
        "    ls-files [URI]             list files reachable from ref/sha\n"
        "    upload-pack <repo-path>    git-upload-pack drop-in (stdin/stdout)\n"
        "    receive-pack <repo-path>   git-receive-pack drop-in (stdin/stdout)\n"
        "    help                       this message\n"
    );
}

// --- Helpers ---

static ok64 refs_print_cb(refcp r, void *ctx) {
    int *count = (int *)ctx;
    fprintf(stdout, "  %.*s\t→ %.*s\n",
            (int)$len(r->key), (char *)r->key[0],
            (int)$len(r->val), (char *)r->val[0]);
    (*count)++;
    return OK;
}

// --- Verb: status ---

static ok64 keeper_status(keeper *k) {
    sane(k);
    u32 nruns = DOGPupCount(k->puppies);
    u32 npacks = (u32)kv32bDataLen(k->packs);
    fprintf(stdout, "keeper: %u pack file(s), %u index run(s)\n",
            npacks, nruns);
    u64 total_pack = 0;
    {
        kv32 const *db = (kv32 const *)kv32bDataHead(k->packs);
        kv32 const *de = (kv32 const *)kv32bIdleHead(k->packs);
        for (kv32 const *p = db; p < de; p++) {
            u8bp slot = FILE_WANT_BUFS[p->val];
            if (slot && slot[0]) total_pack += (u64)u8bDataLen(slot);
        }
    }
    u64 total_idx = 0;
    for (u32 i = 0; i < nruns; i++) {
        u8cs raw = {NULL, NULL};
        DOGPupData(raw, k->puppies, i);
        total_idx += (u64)(raw[1] - raw[0]);
    }
    fprintf(stdout, "  packs: %llu bytes\n", (unsigned long long)total_pack);
    fprintf(stdout, "  index: %llu entries\n",
            (unsigned long long)(total_idx / sizeof(wh128)));
    done;
}

// --- Verb: import ---

static ok64 keeper_import(keeper *k, u8cs path) {
    sane(k && $ok(path));
    call(KEEPImport, k, path);
    done;
}

// --- Verb: verify ---

static ok64 keeper_verify(keeper *k, u8cs hex) {
    sane(k && $ok(hex));
    return KEEPVerify(k, hex);
}

// --- Verb: ls-files ---

#include "WALK.h"

//  Visitor for `keeper ls-files`.  Prints one line per leaf entry in
//  `git ls-tree -r` format:  "<mode> <type> <sha40>\t<path>\n".
//  Skips intermediate tree events (we only want leaves).
static ok64 keeper_lsfiles_visit(u8cs path, u8 kind, u8cp esha,
                                  u8cs blob, void0p ctx) {
    (void)blob; (void)ctx;
    char const *mode = NULL;
    char const *type = NULL;
    switch (kind) {
        case WALK_KIND_REG: mode = "100644"; type = "blob";   break;
        case WALK_KIND_EXE: mode = "100755"; type = "blob";   break;
        case WALK_KIND_LNK: mode = "120000"; type = "blob";   break;
        case WALK_KIND_SUB: mode = "160000"; type = "commit"; break;
        case WALK_KIND_DIR:
            //  Skip directory events: git ls-tree -r omits them.
            //  The root visit also arrives with empty path; either way
            //  we only surface leaves.
            return OK;
        default:
            return OK;
    }
    char hex[41];
    for (int i = 0; i < 20; i++)
        snprintf(hex + 2 * i, 3, "%02x", esha[i]);
    fprintf(stdout, "%s %s %s\t%.*s\n",
            mode, type, hex,
            (int)$len(path), (char *)path[0]);
    return OK;
}

static ok64 keeper_lsfiles(keeper *k, uricp target) {
    sane(k && target);
    return KEEPLsFiles(k, target, keeper_lsfiles_visit, NULL);
}

// --- Verb: refs ---

static ok64 keeper_refs(keeper *k) {
    sane(k);
    a_path(keepdir, u8bDataC(k->h->root), KEEP_DIR_S);
    int rcount = 0;
    ok64 o = REFSEach($path(keepdir), refs_print_cb, &rcount);
    if (o != OK && o != REFSNONE)
        fprintf(stderr, "keeper: refs: %s\n", ok64str(o));
    fprintf(stdout, "keeper: %d ref(s)\n", rcount);
    done;
}

// --- Verb: tips ---
//
//  Print every local-branch tip via KEEPEachTip.  Trunk renders as a
//  bare `?` row; child branches as `?<path>`.  One row per branch,
//  tab-separated `<path>\t<sha40>`, terminated by `keeper: N tip(s)`.

static ok64 keeper_tips_print_cb(keep_tipcp t, void *ctx) {
    int *n = (int *)ctx;
    fprintf(stdout, "?%.*s\t%.*s\n",
            (int)$len(t->path), (char *)t->path[0],
            (int)$len(t->sha),  (char *)t->sha[0]);
    (*n)++;
    return OK;
}

static ok64 keeper_tips(keeper *k) {
    sane(k);
    int n = 0;
    ok64 o = KEEPEachTip(k, keeper_tips_print_cb, &n);
    if (o != OK && o != REFSNONE)
        fprintf(stderr, "keeper: tips: %s\n", ok64str(o));
    fprintf(stdout, "keeper: %d tip(s)\n", n);
    done;
}

// --- Verb: get ---

//  Build a transport URI `[<scheme>:]//<host>/<path>` from `g` into
//  `out`.  When `g`'s authority is a substring of any stored origin in
//  REFS (e.g. `//github` matches `https://github.com/…?…`), that row's
//  scheme/host/path win.  Drops query/fragment — those carry the
//  ref/object selector, not the transport target.  `rarena_out` is a
//  caller-owned buffer backing the resolved slices; caller u8bUnMap's
//  it after finishing with the resolved URI bytes.
static ok64 keeper_remote_uri(keeper *k, uri *g, u8b out, u8b rarena_out) {
    sane(k && g && u8bOK(out) && u8bOK(rarena_out));
    a_path(keepdir, u8bDataC(k->h->root), KEEP_DIR_S);

    u8cs rscheme = {};
    u8cs rhost = {};
    u8cs rpath = {};
    u8csMv(rscheme, g->scheme);
    u8csMv(rhost, g->host);
    u8csMv(rpath, g->path);

    if (!u8csEmpty(g->authority)) {
        uri resolved = {};
        a_dup(u8c, in_uri, g->data);
        ok64 rr = REFSResolve(&resolved, rarena_out, $path(keepdir), in_uri);
        if (rr == OK && !u8csEmpty(resolved.host)) {
            if (!u8csEmpty(resolved.scheme)) u8csMv(rscheme, resolved.scheme);
            u8csMv(rhost, resolved.host);
            if (!u8csEmpty(resolved.path))   u8csMv(rpath, resolved.path);
        } else if (u8csEmpty(rscheme) && u8csEmpty(rpath)) {
            //  Alias miss on a bare `//host` URI with no in-place
            //  transport — the user named a remote that's not
            //  registered.  Emit a friendly hint instead of letting
            //  wcli_spawn bail later with a cryptic ENOENT/empty-path.
            fprintf(stderr,
                "keeper: unknown remote //%.*s — register first with "
                "`be get scheme://host/path?ref`, or pass a full URL\n",
                (int)$len(rhost), (char const *)rhost[0]);
            return KEEPNONE;
        }
    }

    if (!u8csEmpty(rscheme)) {
        u8bFeed(out, rscheme);
        u8bFeed1(out, ':');
    }
    a_cstr(slashes, "//");
    u8bFeed(out, slashes);
    u8bFeed(out, rhost);
    if (!u8csEmpty(rpath)) {
        //  Make sure exactly one '/' separates host from path.  ssh
        //  HOME-relative stripping is wcli_spawn's job (it knows the
        //  transport).
        if (*rpath[0] != '/') u8bFeed1(out, '/');
        u8bFeed(out, rpath);
    }
    done;
}

//  `keeper get //remote[?ref]` — fetch via WIREFetch.  Empty ?ref means
//  fast-forward the current worktree branch (per VERBS.md `be get //origin`).
ok64 KEEPGetRemote(uri *g) {
    sane(g);
    keeper *k = &KEEP;

    Bu8 rarena = {};
    call(u8bMap, rarena, (size_t)REFS_MAX_REFS * 320);
    a_pad(u8, ubuf, FILE_PATH_MAX_LEN);
    ok64 ru = keeper_remote_uri(k, g, ubuf, rarena);
    if (ru != OK) {
        u8bUnMap(rarena);
        return ru;
    }
    a_dup(u8c, remote_uri, u8bData(ubuf));

    //  Default ref: current worktree branch (`be get //origin` semantics).
    u8cs want_ref = {};
    u8csMv(want_ref, g->query);

    //  `?*` wildcard: bulk-fetch every advertised heads/tags ref in
    //  one upload-pack session (multi-want).  See VERBS.md §HEAD —
    //  `be head ssh://origin?*` mirrors `git fetch`.
    if ($len(want_ref) == 1 && want_ref[0][0] == '*') {
        ok64 fa = WIREFetchAll(k, remote_uri);
        u8bUnMap(rarena);
        return fa;
    }

    //  Local short-circuit for `?<40hex>` queries: plain git peers
    //  reject `want <sha>` without uploadpack.allowReachableSHA1InWant,
    //  so the supported flow is "seed with a named ref first, then
    //  look up by sha".  If the object is already in the local store,
    //  skip the wire round-trip entirely.
    if ($len(want_ref) == 40) {
        b8 all_hex = YES;
        $for(u8c, p, want_ref) {
            u8 c = *p;
            if (!((c >= '0' && c <= '9') ||
                  (c >= 'a' && c <= 'f') ||
                  (c >= 'A' && c <= 'F'))) { all_hex = NO; break; }
        }
        if (all_hex) {
            u8csc wr = {want_ref[0], want_ref[1]};
            u64 hashlet = WHIFFHexHashlet60(wr);
            u64 val = 0;
            if (KEEPLookup(k, hashlet, 40, &val) == OK) {
                u8bUnMap(rarena);
                return OK;
            }
        }
    }

    a_pad(u8, branch_buf, 256);
    u8cs cur_branch = {};
    if (u8csEmpty(want_ref)) {
        //  No explicit ref → default to the worktree's current branch
        //  as forwarded by `be` via `--at <root>?<branch>#<sha>` and
        //  parked in `h->cur_branch` by `HOMEOpen`.  Strip a redundant
        //  `heads/` prefix and re-attach a canonical one so we emit
        //  exactly `heads/<branch>` on the wire.  When no `--at` was
        //  forwarded (direct `keeper get //origin` invocation), leave
        //  `want_ref` empty — `wcli_match_advert` then picks the
        //  peer's HEAD-mapped branch (mirrors `git clone`).
        a_dup(u8c, at_branch, u8bData(k->h->cur_branch));
        if (!u8csEmpty(at_branch)) {
            a_cstr(heads_pfx, "heads/");
            u8cs src = {};
            u8csMv(src, at_branch);
            if ($len(src) > 6 && memcmp(src[0], heads_pfx[0], 6) == 0)
                u8csUsed(src, 6);
            u8bFeed(branch_buf, heads_pfx);
            u8bFeed(branch_buf, src);
            cur_branch[0] = u8bDataHead(branch_buf);
            cur_branch[1] = u8bIdleHead(branch_buf);
            want_ref[0] = cur_branch[0];
            want_ref[1] = cur_branch[1];
        }
    }

    ok64 fo = WIREFetch(k, remote_uri, want_ref);
    if (fo != OK) {
        //  Journal the failed fetch so recovery / audit tooling sees a
        //  `get_fail <peer-uri>?<branch>` row alongside the success
        //  rows already emitted by wcli_record_ref.  Best-effort write
        //  — we still return the underlying fetch error.
        a_path(keepdir, u8bDataC(k->h->root), KEEP_DIR_S);
        a_pad(u8, key_buf, 512);
        u8bFeed(key_buf, remote_uri);
        u8bFeed1(key_buf, '?');
        if (!u8csEmpty(want_ref)) u8bFeed(key_buf, want_ref);
        a_dup(u8c, key, u8bData(key_buf));
        a_cstr(empty_to, "");
        (void)REFSAppendVerb($path(keepdir), REFSVerbGetFail(),
                             key, empty_to);
    }
    u8bUnMap(rarena);
    return fo;
}

static ok64 keeper_get_object(keeper *k, u8cs prefix) {
    sane(k && $ok(prefix));
    if (u8csLen(prefix) < HASH_MIN_HEX) {
        fprintf(stderr, "keeper: hash too short (min %d)\n",
                HASH_MIN_HEX);
        return KEEPFAIL;
    }
    size_t hexlen = u8csLen(prefix);
    u64 hashlet = WHIFFHexHashlet60(prefix);
    Bu8 out = {};
    call(u8bMap, out, 64UL << 20);
    u8 obj_type = 0;
    ok64 o = KEEPGet(k, hashlet, hexlen, out, &obj_type);
    if (o == OK) {
        a_dup(u8c, data, u8bData(out));
        write(STDOUT_FILENO, data[0], u8csLen(data));
    } else {
        fprintf(stderr, "keeper: object not found\n");
    }
    u8bUnMap(out);
    return o;
}

static ok64 keeper_get_ref(keeper *k, u8cs query) {
    sane(k && $ok(query));
    a_path(keepdir, u8bDataC(k->h->root), KEEP_DIR_S);

    a_pad(u8, qbuf, 256);
    u8bFeed1(qbuf, '?');
    u8bFeed(qbuf, query);
    a_dup(u8c, qkey, u8bData(qbuf));

    a_pad(u8, arena, 1024);
    uri resolved = {};
    ok64 ro = REFSResolve(&resolved, arena, $path(keepdir), qkey);
    if (ro == OK && !u8csEmpty(resolved.query)) {
        fprintf(stdout, "%.*s\n",
                (int)u8csLen(resolved.query),
                (char *)resolved.query[0]);
        done;
    }
    fprintf(stderr, "keeper: ref not found\n");
    return REFSNONE;
}

//  Blob projector: `keeper get <path>?<ref>` — resolves the path inside
//  the ref's tree via KEEPGetByURI and writes the blob bytes to stdout.
//  No sniff, no checkout, no worktree side effects.
static ok64 keeper_get_blob(keeper *k, uri *g) {
    sane(k && g);
    Bu8 out = {};
    call(u8bAlloc, out, 64UL << 20);
    ok64 go = KEEPGetByURI(k, g, out);
    if (go == OK) {
        a_dup(u8c, data, u8bData(out));
        write(STDOUT_FILENO, data[0], u8csLen(data));
    } else {
        fprintf(stderr, "keeper: blob not found: %s\n", ok64str(go));
    }
    u8bFree(out);
    return go;
}

static ok64 keeper_get(keeper *k, cli *c) {
    sane(k && c);
    if (c->nuris == 0) {
        fprintf(stderr, "keeper: get requires a URI\n");
        return KEEPFAIL;
    }
    uri *g = &c->uris[0];

    if (!u8csEmpty(g->authority))
        return KEEPGetRemote(g);
    if (!u8csEmpty(g->fragment))
        return keeper_get_object(k, g->fragment);
    //  path+query (no authority) is a blob projector: resolve `path` in
    //  `?ref`'s tree and cat its bytes.  Disambiguates from a bare ref
    //  resolution (query-only), which only prints the resolved sha.
    if (!u8csEmpty(g->path) && !u8csEmpty(g->query))
        return keeper_get_blob(k, g);
    if (!u8csEmpty(g->query))
        return keeper_get_ref(k, g->query);

    fprintf(stderr, "keeper: get: need //remote, #hash, ?ref, or path?ref\n");
    return KEEPFAIL;
}

// --- Verb: put ---

static ok64 keeper_put(keeper *k, cli *c) {
    sane(k && c);
    if (c->nuris == 0) {
        fprintf(stderr, "keeper: put requires a URI\n");
        return KEEPFAIL;
    }
    uri *g = &c->uris[0];

    if (!u8csEmpty(g->authority)) {
        fprintf(stderr, "keeper: remote push not yet implemented\n");
        return KEEPFAIL;
    }

    u8cs ref_name = {};
    u8cs sha_frag = {};

    for (u32 i = 0; i < c->nuris; i++) {
        if (!u8csEmpty(c->uris[i].query) && !$ok(ref_name))
            u8csMv(ref_name, c->uris[i].query);
        if (!u8csEmpty(c->uris[i].fragment) && !$ok(sha_frag))
            u8csMv(sha_frag, c->uris[i].fragment);
    }

    if (!$ok(ref_name) || !$ok(sha_frag)) {
        fprintf(stderr, "keeper: put requires ?ref and #sha\n");
        return KEEPFAIL;
    }

    a_path(keepdir, u8bDataC(k->h->root), KEEP_DIR_S);

    //  Canonical key: build a query-only URI with the user's ref
    //  name and canonicalise — strips `refs/` and collapses the
    //  trunk aliases so `heads/master` / `master` / `refs/heads/main`
    //  all become bare `?` (trunk).
    uri uk = {};
    uk.query[0] = ref_name[0];
    uk.query[1] = ref_name[1];
    a_pad(u8, fbuf, 256);
    call(DOGCanonURIFeed, fbuf, &uk);
    a_dup(u8c, from, u8bData(fbuf));

    //  Canonical value: strip a leading `?` if the user supplied one
    //  in the URI fragment; otherwise the sha is already bare.
    u8cs sha = {sha_frag[0], sha_frag[1]};
    if (!u8csEmpty(sha) && sha[0][0] == '?') u8csUsed(sha, 1);
    a_dup(u8c, to, sha);

    //  `keeper put` is a local-move verb (user setting a ref).
    ok64 o = REFSAppendVerb($path(keepdir), REFSVerbPost(), from, to);
    if (o != OK) return o;

    fprintf(stdout, "keeper: %.*s → %.*s\n",
            (int)u8csLen(from), (char *)from[0],
            (int)u8csLen(to), (char *)to[0]);
    done;
}

// --- Verb: post ---

//  Extract the tree SHA-1 (as 40 hex chars) from a commit object body.
//  A git commit always starts with "tree <40hex>\n" per object format.
static ok64 post_extract_tree_hex(u8 *out40, u8csc body) {
    if ($len(body) < 46) return KEEPFAIL;
    if (memcmp(body[0], "tree ", 5) != 0) return KEEPFAIL;
    memcpy(out40, body[0] + 5, 40);
    return OK;
}

//  Push the current worktree commit to a remote.  Nothing is staged
//  locally (sniff already committed if anything was).  Flow:
//    1. Determine target branch from URI query (`?main` / `?heads/X`)
//       or fall back to the worktree's current branch.
//    2. Build the transport URI from the URI's authority/scheme (with
//       alias resolution).
//    3. Hand off to WIREPush — it harvests our local tip via REFADV,
//       speaks the git wire protocol to the peer's receive-pack, and
//       on success the caller advances the cached peer-tip ref below.
//  No URI → this verb is a no-op (sniff already wrote the commit).
static ok64 keeper_post(keeper *k, cli *c) {
    sane(k && c);
    uri *g = (c->nuris > 0) ? &c->uris[0] : NULL;
    if (!g || u8csEmpty(g->host)) {
        fprintf(stderr, "keeper: post needs a remote URI "
                        "(ssh://host/path[?branch])\n");
        return KEEPFAIL;
    }
    a_path(keepdir, u8bDataC(k->h->root), KEEP_DIR_S);

    //  1. Worktree's current branch + tip (used both as the WIREPush
    //     local_branch default and to record the new peer-side ref).
    //     Sourced from `--at <root>?<branch>#<sha>` forwarded by `be`
    //     and parked in `h->cur_branch` / `h->cur_sha` by HOMEOpen.
    //     Empty when `--at` was not forwarded (direct `keeper post`
    //     without sniff in the loop).
    if (u8bDataLen(k->h->cur_sha) != 40) {
        fprintf(stderr, "keeper: post: worktree commit not set\n");
        return KEEPFAIL;
    }
    a_dup(u8c, at_branch, u8bData(k->h->cur_branch));
    a_dup(u8c, at_sha,    u8bData(k->h->cur_sha));

    //  2. Target branch.  Precedence:
    //       a. explicit URI `?query`           — user said which branch.
    //       b. refs-log host-prefix match      — `be post //sniff` after
    //          a prior `be get ssh://sniff/...?feat` recovers `feat`
    //          from `<store>/refs` via REFSResolve.
    //       c. worktree current branch (h->cur_branch) — last-resort default.
    //     Branch is be-side and may be empty (= trunk).  WIREPush's
    //     wcli_be_to_wire applies the trunk⇔refs/heads/main alias.
    a_pad(u8, peer_arena, 1024);
    u8cs peer_refname = {};
    if (u8csEmpty(g->query) && !u8csEmpty(g->authority)) {
        uri resolved = {};
        a_dup(u8c, in_uri, g->data);
        if (REFSResolve(&resolved, peer_arena,
                        $path(keepdir), in_uri) == OK) {
            u8cs r_q = {resolved.fragment[0], resolved.fragment[1]};
            if (!u8csEmpty(r_q)) {
                peer_refname[0] = r_q[0];
                peer_refname[1] = r_q[1];
            }
        }
    }
    a_pad(u8, branch_buf, 256);
    {
        u8cs src = {};
        if (!u8csEmpty(peer_refname)) {
            src[0] = peer_refname[0];
            src[1] = peer_refname[1];
        } else if (u8csEmpty(g->query)) {
            src[0] = at_branch[0];
            src[1] = at_branch[1];
        } else {
            src[0] = g->query[0];
            src[1] = g->query[1];
        }
        if (!u8csEmpty(src)) u8bFeed(branch_buf, src);
    }
    a_dup(u8c, branch, u8bData(branch_buf));
    //  Empty branch = trunk; WIREPush handles it (wire alias to main).

    //  WIREPush takes the be-side branch directly — it walks REFADV
    //  and translates to refs/heads/<X> (or refs/heads/main for trunk)
    //  internally via wcli_be_to_wire.
    a_dup(u8c, local_branch, branch);

    //  3. Build the remote transport URI (substring-resolved origin).
    Bu8 rarena = {};
    call(u8bMap, rarena, (size_t)REFS_MAX_REFS * 320);
    a_pad(u8, ubuf, FILE_PATH_MAX_LEN);
    ok64 ru = keeper_remote_uri(k, g, ubuf, rarena);
    if (ru != OK) {
        u8bUnMap(rarena);
        return ru;
    }
    a_dup(u8c, remote_uri, u8bData(ubuf));

    //  4. Push.  WIREPush handles peer-tip advert + pack build + status.
    //  We pass at_sha (decoded from sniff's at-log) as the authoritative
    //  local_tip — keeper REFS may lag, and a stale REFADV would make
    //  WIREPush's peer==local short-circuit no-op a real push.
    sha1 at_tip = {};
    {
        u8s bin = {at_tip.data, at_tip.data + 20};
        a_dup(u8c, hx, at_sha);
        if (HEXu8sDrainSome(bin, hx) != OK || bin[0] != at_tip.data + 20) {
            fprintf(stderr,
                    "keeper: post: bad at_sha (%lld bytes)\n",
                    (long long)$len(at_sha));
            u8bUnMap(rarena);
            return KEEPFAIL;
        }
    }
    ok64 pu = WIREPush(k, remote_uri, local_branch, &at_tip);
    u8bUnMap(rarena);
    if (pu != OK) return pu;

    //  5. Advance local `<peer-uri>?<branch> → <new-sha>` so
    //     subsequent fetches know the peer's tip.  Use the RESOLVED
    //     transport URI (host+path from alias resolution), not `g`:
    //     `be post //sniff` arrives with empty path, and recording a
    //     pathless `//sniff?<branch>` row would mask the original
    //     `ssh://sniff/src/dogs?<branch>` row in later REFSResolve
    //     lookups, breaking subsequent pushes.  Branch is be-side
    //     (empty for trunk → key ends in bare `?`).
    uri gk = {};
    {
        a_dup(u8c, ru, remote_uri);
        gk.data[0] = ru[0];
        gk.data[1] = ru[1];
        (void)URILexer(&gk);
        gk.data[0] = ru[0];
        gk.data[1] = ru[1];
    }
    if ($empty(branch)) {
        //  Present-but-empty query so DOGCanonURIFeed emits the `?`.
        gk.query[0] = remote_uri[1];
        gk.query[1] = remote_uri[1];
    } else {
        u8csMv(gk.query, branch);
    }
    gk.fragment[0] = NULL;
    gk.fragment[1] = NULL;
    a_pad(u8, rkey, 1280);
    call(DOGCanonURIFeed, rkey, &gk);
    a_dup(u8c, remote_key, u8bData(rkey));
    //  `at_sha` is a slice (a_dup u8c *[2]), not a Bu8 — copy by
    //  slice, not by buffer, and read its length / head accordingly.
    a_dup(u8c, v, at_sha);
    //  Push is a local move (we updated the peer's tip), so record
    //  with verb `post`, not the back-compat `get` shim.
    REFSAppendVerb($path(keepdir), REFSVerbPost(), remote_key, v);

    fprintf(stdout, "keeper: pushed %s%.*s → %.*s\n",
            $empty(branch) ? "(trunk)" : "?",
            (int)$len(branch), (char *)branch[0],
            (int)$len(at_sha), (char *)at_sha[0]);
    done;
}

// --- Verb: delete ---
//
//  Two arms keyed off the URI shape:
//    `//host?branch`       — push-delete: WIREPushDelete the remote
//                            ref then tombstone the cached row.
//    `//host` (no `?ref`)  — alias drop: walk REFS, tombstone every
//                            row whose authority is the named host.
//                            No network.
//
//  VERBS.md spec stores aliases in `<store>/ALIAS`; the current
//  keeper folds aliases into REFS rows keyed by host (REFS.h:16),
//  so dropping the alias is the same as tombstoning every row that
//  carries that authority.

#define KEEP_DEL_ZERO_HEX                                            \
    "0000000000000000000000000000000000000000"

typedef struct {
    u8cs  host;
    u8b  *keys;       // packed NUL-terminated row-keys to tombstone
    ok64  err;
} keeper_delete_alias_ctx;

static ok64 keeper_delete_alias_collect(refcp r, void *vctx) {
    sane(r && vctx);
    keeper_delete_alias_ctx *ctx = vctx;
    if (ctx->err != OK) done;

    //  r->key is the URI (minus fragment) re-emitted by URIutf8Feed;
    //  re-parse to extract its host slice.  Skip rows whose host
    //  isn't a byte-exact match against the requested host — alias
    //  drop is precise; substring matching is REFSResolve's job, not
    //  this verb's.
    uri ku = {};
    u8csMv(ku.data, r->key);
    if (URILexer(&ku) != OK) done;
    u8cs row_host = {ku.host[0], ku.host[1]};
    if (u8csEmpty(row_host)) done;
    if (u8csLen(row_host) != u8csLen(ctx->host)) done;
    if (memcmp(row_host[0], ctx->host[0],
               (size_t)u8csLen(ctx->host)) != 0) done;

    u8bFeed(*ctx->keys, r->key);
    u8bFeed1(*ctx->keys, '\0');
    done;
}

static ok64 keeper_delete_alias(keeper *k, u8cs host) {
    sane(k && !u8csEmpty(host));
    a_path(keepdir, u8bDataC(k->h->root), KEEP_DIR_S);

    Bu8 keys = {};
    call(u8bAllocate, keys, 1UL << 16);

    keeper_delete_alias_ctx ctx = {.host = {host[0], host[1]},
                                   .keys = &keys, .err = OK};
    ok64 eo = REFSEach($path(keepdir),
                       keeper_delete_alias_collect, &ctx);
    if (eo != OK) {
        u8bFree(keys);
        return eo;
    }
    if (ctx.err != OK) {
        u8bFree(keys);
        return ctx.err;
    }

    if (!u8bHasData(keys)) {
        u8bFree(keys);
        fprintf(stderr,
                "keeper: delete: no rows for //%.*s\n",
                (int)u8csLen(host), (char const *)host[0]);
        return KEEPNONE;
    }

    a_cstr(zeros, KEEP_DEL_ZERO_HEX);
    //  Canonical tombstone shape: one row per key under verb
    //  `delete`.  REFSLoad / REFSResolve dedup by URI key only
    //  (ULOGeachLatestKey), so a single `delete` row supersedes any
    //  earlier `get`/`post` row for the same key.
    u32 dropped = 0;
    u8cp p = u8bDataHead(keys);
    u8cp end = u8bIdleHead(keys);
    while (p < end) {
        u8cp q = p;
        while (q < end && *q != '\0') q++;
        u8cs row_key = {p, q};
        if (!u8csEmpty(row_key)) {
            ok64 ao = REFSAppendVerb($path(keepdir), REFSVerbDelete(),
                                     row_key, zeros);
            if (ao != OK) {
                u8bFree(keys);
                return ao;
            }
            dropped++;
        }
        p = (q < end) ? q + 1 : end;
    }
    u8bFree(keys);
    fprintf(stdout, "keeper: dropped alias //%.*s (%u row(s))\n",
            (int)u8csLen(host), (char const *)host[0], dropped);
    done;
}

static ok64 keeper_delete(keeper *k, cli *c) {
    sane(k && c);
    if (c->nuris == 0) {
        fprintf(stderr, "keeper: delete requires a //host[?ref] URI\n");
        return KEEPFAIL;
    }
    uri *g = &c->uris[0];
    if (u8csEmpty(g->host)) {
        fprintf(stderr,
                "keeper: delete needs a remote URI (//host[?ref])\n");
        return KEEPFAIL;
    }

    //  Bare `//host` → alias drop.  No wire, no transport spawn.
    if (u8csEmpty(g->query)) {
        u8cs host = {g->host[0], g->host[1]};
        return keeper_delete_alias(k, host);
    }

    //  `//host?branch` → push-delete via receive-pack.  Resolve the
    //  alias to its full transport URI just like keeper_post does;
    //  delete-only commands are accepted without a packfile body.
    Bu8 rarena = {};
    call(u8bMap, rarena, (size_t)REFS_MAX_REFS * 320);
    a_pad(u8, ubuf, FILE_PATH_MAX_LEN);
    ok64 ru = keeper_remote_uri(k, g, ubuf, rarena);
    if (ru != OK) {
        u8bUnMap(rarena);
        return ru;
    }
    a_dup(u8c, remote_uri, u8bData(ubuf));

    a_dup(u8c, branch, g->query);
    ok64 pu = WIREPushDelete(k, remote_uri, branch);
    u8bUnMap(rarena);
    if (pu != OK) return pu;

    //  Tombstone the local cached `<peer-uri>?<branch>` row so future
    //  cached reads stop returning the now-deleted tip.  Mirrors the
    //  REFS-write at the end of keeper_post (KEEP.exe.c:620+).
    a_path(keepdir, u8bDataC(k->h->root), KEEP_DIR_S);
    {
        a_pad(u8, kbuf, 1280);
        uri gk = {};
        a_dup(u8c, ru2, remote_uri);
        gk.data[0] = ru2[0];
        gk.data[1] = ru2[1];
        (void)URILexer(&gk);
        gk.data[0] = ru2[0];
        gk.data[1] = ru2[1];
        u8csMv(gk.query, branch);
        gk.fragment[0] = NULL;
        gk.fragment[1] = NULL;
        if (DOGCanonURIFeed(kbuf, &gk) == OK) {
            a_dup(u8c, key, u8bData(kbuf));
            a_cstr(zeros, KEEP_DEL_ZERO_HEX);
            //  Canonical tombstone: one row, verb=`delete`.  REFS's
            //  URI-key-only dedup ensures it masks any prior write.
            (void)REFSAppendVerb($path(keepdir), REFSVerbDelete(),
                                 key, zeros);
        }
    }

    fprintf(stdout, "keeper: deleted //%.*s?%.*s\n",
            (int)u8csLen(g->host), (char const *)g->host[0],
            (int)u8csLen(branch), (char const *)branch[0]);
    done;
}

// --- Entry ---

ok64 KEEPExec(keeper *k, cli *c) {
    sane(k && c);

    a_cstr(v_help,   "help");
    a_cstr(v_get,    "get");
    a_cstr(v_put,    "put");
    a_cstr(v_post,   "post");
    a_cstr(v_delete, "delete");
    a_cstr(v_status, "status");
    a_cstr(v_import, "import");
    a_cstr(v_verify, "verify");
    a_cstr(v_refs,   "refs");
    a_cstr(v_tips,   "tips");

    if ($eq(c->verb, v_help) || CLIHas(c, "-h") || CLIHas(c, "--help")) {
        keep_usage(); done;
    }

    //  Verb-less projector invocation (VERBS.md §"View projectors"):
    //  `keeper <proj>:<URI>` — no verb.  Scheme selects the projector;
    //  dog/DOG.c owns the scheme→dog table so we dispatch only when
    //  the URI's scheme resolves to this dog ("keeper").  `--tlv`
    //  switches the emitter from raw bytes to a HUNK TLV record so
    //  `bro` (started by BE on a TTY) can render it.
    if ($empty(c->verb) && c->nuris > 0) {
        uri *pu = &c->uris[0];
        char const *dog = DOGProjectorDog(pu->scheme);
        if (dog != NULL && strcmp(dog, "keeper") == 0) {
            b8 tlv = CLIHas(c, "--tlv");
            return KEEPProjDispatch(k, pu, tlv);
        }
    }

    if ($empty(c->verb)) {
        keep_usage();
        fail(KEEPFAIL);
    }

    if ($eq(c->verb, v_status))  return keeper_status(k);
    if ($eq(c->verb, v_refs))    return keeper_refs(k);
    if ($eq(c->verb, v_tips))    return keeper_tips(k);

    //  `be://` and `file://` dispatch.  Phase 8: route through WIRE
    //  (git wire protocol) so client and server are symmetric across
    //  every transport.  The keeper-protocol case (`be://`, `keeper://`,
    //  `file://`) execs `keeper upload-pack` / `receive-pack` on the
    //  peer end via wcli_spawn.
    if (c->nuris >= 1) {
        uri *u = &c->uris[0];
        a_cstr(be_sch,     "be");
        a_cstr(file_sch,   "file");
        a_cstr(keeper_sch, "keeper");
        b8 plain = $eq(u->scheme, be_sch) || $eq(u->scheme, file_sch) ||
                   $eq(u->scheme, keeper_sch);
        if (plain && $eq(c->verb, v_get))  return KEEPGetRemote(u);
        if (plain && $eq(c->verb, v_post)) return keeper_post(k, c);
    }

    if ($eq(c->verb, v_get))     return keeper_get(k, c);
    if ($eq(c->verb, v_put))     return keeper_put(k, c);
    if ($eq(c->verb, v_post))    return keeper_post(k, c);
    if ($eq(c->verb, v_delete))  return keeper_delete(k, c);

    if ($eq(c->verb, v_import)) {
        if (c->nuris < 1) {
            fprintf(stderr, "keeper: import requires a packfile path\n");
            return KEEPFAIL;
        }
        return keeper_import(k, c->uris[0].path);
    }

    if ($eq(c->verb, v_verify)) {
        if (c->nuris < 1 || u8csEmpty(c->uris[0].fragment)) {
            fprintf(stderr, "keeper: verify requires #sha\n");
            return KEEPFAIL;
        }
        return keeper_verify(k, c->uris[0].fragment);
    }

    a_cstr(v_lsfiles, "ls-files");
    if ($eq(c->verb, v_lsfiles)) {
        uri default_uri = {};
        uri *u = (c->nuris > 0) ? &c->uris[0] : &default_uri;
        if (c->nuris == 0) {
            //  Default: local HEAD.  Construct a minimal URI with query = "HEAD".
            a_cstr(head_q, "HEAD");
            default_uri.query[0] = head_q[0];
            default_uri.query[1] = head_q[1];
        }
        return keeper_lsfiles(k, u);
    }

    fprintf(stderr, "keeper: unknown verb '%.*s'\n",
            (int)$len(c->verb), (char *)c->verb[0]);
    return KEEPFAIL;
}
