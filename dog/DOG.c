#include "DOG.h"

#include <dirent.h>
#include <string.h>
#include <unistd.h>

#include "abc/B.h"
#include "abc/FILE.h"
#include "abc/PRO.h"

// kv32 buffer ops via Bx (instantiated in abc/KV.h).

//  Known view-projector schemes (VERBS.md §"View projectors") with
//  the dog that implements each.  Shared source of truth: DOGParseURI
//  uses the scheme column to exempt these from the scheme→authority
//  promotion; BE (beagle/BE.cli.c) uses the dog column to dispatch
//  `be <proj>:<URI>` to the right dog.  Projectors are *never*
//  transports — the scheme selects what shape of bytes to emit.
static DOGProjRoute const DOG_PROJECTORS[] = {
    {"sha1",   "keeper"},
    {"blob",   "keeper"},
    {"tree",   "keeper"},
    {"commit", "keeper"},
    {"log",    "keeper"},
    {"refs",   "keeper"},
    {"size",   "keeper"},
    {"type",   "keeper"},
    {"diff",   "graf"},
    {"ls",     "sniff"},
    {NULL,     NULL}
};

static DOGProjRoute const *dog_proj_lookup(u8cs scheme) {
    if ($empty(scheme)) return NULL;
    size_t n = (size_t)$len(scheme);
    for (DOGProjRoute const *p = DOG_PROJECTORS; p->scheme; p++) {
        size_t pl = strlen(p->scheme);
        if (pl == n && memcmp(scheme[0], p->scheme, pl) == 0) return p;
    }
    return NULL;
}

b8 DOGIsProjector(u8cs scheme) {
    return dog_proj_lookup(scheme) != NULL;
}

char const *DOGProjectorDog(u8cs scheme) {
    DOGProjRoute const *r = dog_proj_lookup(scheme);
    return r ? r->dog : NULL;
}

//  Known transport schemes (VERBS.md §"Transport schemes").  Kept as a
//  table next to DOG_PROJECTORS so adding a transport is a one-row
//  edit.  CLI.c uses this to disambiguate `word:` — known scheme = URI,
//  unknown = prose (e.g. a `cli:` conventional-commit prefix).
static char const *const DOG_TRANSPORTS[] = {
    "ssh", "https", "http", "git", "file", "be", NULL
};

b8 DOGIsTransport(u8cs scheme) {
    if ($empty(scheme)) return NO;
    size_t n = (size_t)$len(scheme);
    for (char const *const *t = DOG_TRANSPORTS; *t; t++) {
        size_t pl = strlen(*t);
        if (pl == n && memcmp(scheme[0], *t, pl) == 0) return YES;
    }
    return NO;
}

static b8 dog_is_projector(u8cs scheme) {
    return DOGIsProjector(scheme);
}

ok64 DOGParseURI(urip uri, u8csc text) {
    sane(uri != NULL);
    memset(uri, 0, sizeof(*uri));
    uri->data[0] = text[0];
    uri->data[1] = text[1];
    call(URILexer, uri);

    // Dog normalization: bare `host:path` with no `//` ends up
    // as scheme="host", path="path".  Promote scheme to authority
    // when authority is empty and the path has no leading slash
    // (proper RFC schemes have either an authority or a path
    // starting with '/').  Projector schemes are exempt — `tree:src/`,
    // `ls:subdir`, etc. keep `tree` / `ls` as the scheme.
    if (!$empty(uri->scheme) && $empty(uri->authority)
        && !dog_is_projector(uri->scheme)) {
        b8 rooted = !$empty(uri->path) && $at(uri->path, 0) == '/';
        if (!rooted) {
            u8csMv(uri->authority, uri->scheme);
            u8csMv(uri->host, uri->scheme);
            uri->scheme[0] = NULL;
            uri->scheme[1] = NULL;
        }
    }

    // Dog normalization: `user@host/path` (no `//`) parses as one big
    // path.  If path's head-segment contains `@`, promote it to
    // authority+host and leave `/rest` as path.  Handles the ergonomic
    // `gritzko@pm.me/dogs-sniff?ref` form without requiring `//`.
    if ($empty(uri->authority) && !$empty(uri->path)) {
        u8cp slash = NULL;
        u8cp at    = NULL;
        for (u8cp p = uri->path[0]; p < uri->path[1]; p++) {
            if (*p == '/' && slash == NULL) { slash = p; break; }
            if (*p == '@' && at == NULL)    at = p;
        }
        u8cp head_end = slash ? slash : uri->path[1];
        if (at != NULL && at < head_end) {
            u8cp auth_start = uri->path[0];
            uri->authority[0] = auth_start;
            uri->authority[1] = head_end;
            uri->user[0] = auth_start;
            uri->user[1] = at;
            uri->host[0] = at + 1;
            uri->host[1] = head_end;
            if (slash != NULL) {
                uri->path[0] = slash;      // keep leading '/'
            } else {
                uri->path[0] = NULL;
                uri->path[1] = NULL;
            }
        }
    }

    // Dog normalization: symbolic "ports" are overwhelmingly path
    // segments that got eaten by RFC 3986 (`ssh://host:src/dogs-sniff`
    // — `src` is not a port).  If the port slice has any non-digit
    // byte, glue it onto the front of the path and clear the port.
    if (!$empty(uri->port)) {
        b8 numeric = YES;
        $for(u8c, p, uri->port) {
            if (*p < '0' || *p > '9') { numeric = NO; break; }
        }
        if (!numeric) {
            // port and path slices are contiguous in the original
            // text (port ends exactly where path begins), so the
            // union slice is {port[0], old_path_end_or_port_end}.
            u8cp new_path_end = $empty(uri->path) ? uri->port[1]
                                                  : uri->path[1];
            uri->path[0] = uri->port[0];
            uri->path[1] = new_path_end;
            // Trim the ':' from authority/host by pointing their
            // end at port[0]-1 (one byte back over the colon).
            if (!$empty(uri->host))      uri->host[1]      = uri->port[0] - 1;
            if (!$empty(uri->authority)) uri->authority[1] = uri->port[0] - 1;
            uri->port[0] = NULL;
            uri->port[1] = NULL;
        }
    }

    done;
}

ok64 DOGNormalizeArg(urip u, u8csc arg) {
    sane(u != NULL);
    zerop(u);
    if (u8csEmpty(arg)) done;

    // If the arg contains `?` or `#` or `/` it's already URI-shaped;
    // if it contains whitespace it can't be a URI at all.  Classify
    // up front so we don't feed whitespace to URILexer.
    b8 has_ws     = NO;
    b8 has_mark   = NO;   // ? or #
    b8 has_slash  = NO;
    b8 has_colon  = NO;
    $for(u8c, p, arg) {
        u8 c = *p;
        if (c <= 0x20 || c == 0x7f) { has_ws = YES; continue; }
        if (c == '?' || c == '#')   { has_mark = YES; }
        if (c == '/')               { has_slash = YES; }
        if (c == ':')               { has_colon = YES; }
    }

    // Whitespace wins immediately: not a URI, synthesize #<arg>.
    if (has_ws) {
        u->data[0]      = arg[0];
        u->data[1]      = arg[1];
        u->fragment[0]  = arg[0];
        u->fragment[1]  = arg[1];
        done;
    }

    // Structural char → try the URI parser.
    if (has_mark || has_slash || has_colon) {
        return DOGParseURI(u, arg);
    }

    // Bare single token — classify.
    b8 is_hex40 = ($len(arg) == 40);
    if (is_hex40) {
        $for(u8c, p, arg) {
            u8 c = *p;
            if (!((c >= '0' && c <= '9') ||
                  (c >= 'a' && c <= 'f') ||
                  (c >= 'A' && c <= 'F'))) { is_hex40 = NO; break; }
        }
    }
    b8 ref_safe = !$empty(arg);
    $for(u8c, p, arg) {
        u8 c = *p;
        if (!((c >= 'A' && c <= 'Z') ||
              (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') ||
              c == '_' || c == '-' || c == '.')) {
            ref_safe = NO; break;
        }
    }

    u->data[0] = arg[0];
    u->data[1] = arg[1];
    if (is_hex40 || ref_safe) {
        u->query[0] = arg[0];
        u->query[1] = arg[1];
    } else {
        u->fragment[0] = arg[0];
        u->fragment[1] = arg[1];
    }
    done;
}

//  Presence vs emptiness for query / fragment slices:
//    s[0] == NULL                  → component absent (no `?` / no `#`)
//    s[0] != NULL, $empty(s)       → present-but-empty (bare `?` / `#`)
//    non-empty                     → component with text
//  Collapse/strip must preserve the present-but-empty state (point
//  both endpoints at the tail of the original text), not wipe it to
//  absent, or the row shape (`?#sha`, `?branch#`) is lost.
ok64 DOGCanonURI(urip u) {
    sane(u != NULL);

    //  Query is an opaque hierarchical local branch path.  Trunk =
    //  empty (`?`) or a lone `/` (`?/`) — the latter folds to the
    //  former so the on-disk key is unique.  No name-aware aliasing
    //  (no `refs/`, `heads/`, `main`/`master`/`trunk` collapsing) —
    //  git refname conventions live behind keeper/GIT.h's
    //  GITParseRef / GITFeedRef and apply only on the wire.
    if (!u8csEmpty(u->query)) {
        u8cs q = {u->query[0], u->query[1]};
        if ($len(q) == 1 && *q[0] == '/') {
            u->query[0] = q[1];
            u->query[1] = q[1];
        }
    }

    //  Fragment: drop a leading `?` so the value slot is a bare
    //  40-hex SHA (or empty = deletion).
    if (!u8csEmpty(u->fragment)) {
        u8cs f = {u->fragment[0], u->fragment[1]};
        if ($len(f) >= 1 && *f[0] == '?')
            u8csUsed1(f);
        if ($empty(f)) {
            u->fragment[0] = u->fragment[1];
        } else {
            u->fragment[0] = f[0];
            u->fragment[1] = f[1];
        }
    }

    done;
}

ok64 DOGCanonURIFeed(u8bp out, urip u) {
    sane(out != NULL && u != NULL);
    call(DOGCanonURI, u);

    //  Emit scheme verbatim (if any): cross-scheme identity is the
    //  job of the lookup-side host-substring matcher, not the
    //  storage key.  Keeping the scheme preserves access method info
    //  (ssh vs https vs file vs be://) for debugging and re-fetch.
    if (!u8csEmpty(u->scheme)) {
        u8bFeed(out, u->scheme);
        u8bFeed1(out, ':');
    }
    if (!u8csEmpty(u->authority) || !u8csEmpty(u->host)) {
        a_cstr(slashes, "//");
        u8bFeed(out, slashes);
        u8cs auth = {u->authority[0], u->authority[1]};
        if ($len(auth) >= 2 && auth[0][0] == '/' && auth[0][1] == '/')
            u8csUsed(auth, 2);
        u8bFeed(out, auth);
        //  `host`+`/path` stays as-is; `host`+`path` gets a `/`.
        //  `ssh://host:x` and `ssh://host/x` thus produce the same key.
        if (!u8csEmpty(u->path)) {
            if ($at(u->path, 0) != '/') u8bFeed1(out, '/');
            u8bFeed(out, u->path);
        }
    } else if (!u8csEmpty(u->path)) {
        u8bFeed(out, u->path);
    }
    //  Presence check is [0] != NULL (empty-but-present still emits
    //  the sigil so `?#sha` and `?branch#` round-trip).
    if (u->query[0] != NULL) {
        u8bFeed1(out, '?');
        if (!u8csEmpty(u->query)) u8bFeed(out, u->query);
    }
    if (u->fragment[0] != NULL) {
        u8bFeed1(out, '#');
        if (!u8csEmpty(u->fragment)) u8bFeed(out, u->fragment);
    }
    done;
}

// =============================================================
// --- Puppies: stack of <seqno>.<ext> files ---
// =============================================================

//  Compose `<dir>/<10-RON64-seqno><ext>` into `out` (reset first).
static ok64 dog_pup_path(path8b out, path8s dir, u32 seqno, u8cs ext) {
    sane(u8bOK(out));
    call(PATHu8bDup, out, dir);
    a_pad(u8, name, DOG_PUP_SEQNO_W + 32);
    call(RONu8sFeedPad, u8bIdle(name), (ok64)seqno, DOG_PUP_SEQNO_W);
    ((u8 **)name)[2] += DOG_PUP_SEQNO_W;
    call(u8bFeed, name, ext);
    call(PATHu8bPush, out, u8bDataC(name));
    done;
}

//  Parse "<10-RON64><ext>" filename → seqno; 0 on bad fmt.
static u32 dog_pup_parse_seqno(char const *name, size_t nlen, u8cs ext) {
    size_t elen = (size_t)$len(ext);
    if (nlen != DOG_PUP_SEQNO_W + elen) return 0;
    if (memcmp(name + DOG_PUP_SEQNO_W, ext[0], elen) != 0) return 0;
    u8c const *p = (u8c const *)name;
    ok64 v = 0;
    if (RONutf8sDrain(&v, &p) != OK) return 0;
    return (u32)v;
}

ok64 DOGPupOpenAll(kv32b pups, path8s dir, u8cs ext) {
    sane(pups != NULL && $ok(dir) && $ok(ext));

    a_path(dpat);
    PATHu8bFeed(dpat, dir);
    DIR *d = opendir((char *)u8bDataHead(dpat));
    if (!d) done;  // empty stack — dir not yet created

    char names[FILE_MAX_OPEN][DOG_PUP_SEQNO_W + 64];
    u32 nfound = 0;
    size_t elen = (size_t)$len(ext);
    struct dirent *e;
    while ((e = readdir(d)) != NULL && nfound < FILE_MAX_OPEN) {
        size_t nlen = strlen(e->d_name);
        if (nlen != DOG_PUP_SEQNO_W + elen) continue;
        if (memcmp(e->d_name + DOG_PUP_SEQNO_W, ext[0], elen) != 0) continue;
        memcpy(names[nfound], e->d_name, nlen + 1);
        nfound++;
    }
    closedir(d);

    //  Sort lexicographically — name order matches seqno order since
    //  `<seqno>` is fixed-width zero-padded RON64.
    for (u32 i = 0; i + 1 < nfound; i++)
        for (u32 j = i + 1; j < nfound; j++)
            if (strcmp(names[i], names[j]) > 0) {
                char t[DOG_PUP_SEQNO_W + 64];
                memcpy(t, names[i], sizeof(t));
                memcpy(names[i], names[j], sizeof(t));
                memcpy(names[j], t, sizeof(t));
            }

    for (u32 i = 0; i < nfound; i++) {
        u32 sq = dog_pup_parse_seqno(names[i], strlen(names[i]), ext);
        u8cs fn = {(u8cp)names[i], (u8cp)names[i] + strlen(names[i])};
        a_path(fpath, dir);
        if (PATHu8bPush(fpath, fn) != OK) continue;
        u8bp buf = NULL;
        if (FILEMapRO(&buf, $path(fpath)) != OK) continue;
        int fd = FILEBookedFD(buf);
        if (fd < 0) { FILEUnMap(buf); continue; }
        kv32 kv = {.key = sq, .val = (u32)fd};
        call(kv32bPush, pups, &kv);
    }
    done;
}

ok64 DOGPupCreate(kv32b pups, path8s dir, u8cs ext, u8cs bytes) {
    sane(pups != NULL && $ok(dir) && $ok(ext));

    //  new_seqno = 1 + max(existing seqnos), default 1 for empty stack.
    u32 new_seqno = 1;
    {
        kv32 const *db = (kv32 const *)kv32bDataHead(pups);
        kv32 const *de = (kv32 const *)kv32bIdleHead(pups);
        for (kv32 const *p = db; p < de; p++)
            if (p->key >= new_seqno) new_seqno = p->key + 1;
    }

    a_path(idxpath);
    call(dog_pup_path, idxpath, dir, new_seqno, ext);
    a_path(tmppath);
    call(dog_pup_path, tmppath, dir, new_seqno, ext);
    a_cstr(tmpsuf, ".tmp");
    call(u8bFeed, tmppath, tmpsuf);
    call(PATHu8bTerm, tmppath);

    int wfd = -1;
    call(FILECreate, &wfd, $path(tmppath));
    if (wfd >= 0) {
        FILEFeedAll(wfd, bytes);
        close(wfd);
    }
    call(FILERename, $path(tmppath), $path(idxpath));

    u8bp buf = NULL;
    call(FILEMapRO, &buf, $path(idxpath));
    int fd = FILEBookedFD(buf);
    if (fd < 0) { FILEUnMap(buf); return DOGPUPFAIL; }
    kv32 kv = {.key = new_seqno, .val = (u32)fd};
    call(kv32bPush, pups, &kv);
    done;
}

ok64 DOGPupThinTail(kv32b pups, path8s dir, u8cs ext, u32 m) {
    sane(pups != NULL && $ok(dir) && $ok(ext));
    u32 n = (u32)kv32bDataLen(pups);
    if (m > n) m = n;
    if (m == 0) done;
    kv32 *base = (kv32 *)kv32bDataHead(pups);
    for (u32 i = n - m; i < n; i++) {
        u32 fd = base[i].val;
        u32 sq = base[i].key;
        u8bp slot = FILE_WANT_BUFS[fd];
        if (slot && slot[0]) FILEUnMap(slot);
        a_path(ulpath);
        dog_pup_path(ulpath, dir, sq, ext);
        unlink((char *)u8bDataHead(ulpath));
    }
    //  Trim data end back by m records.  pups[2] is data end.
    ((kv32 **)pups)[2] = base + (n - m);
    done;
}

ok64 DOGPupClose(kv32b pups) {
    sane(pups != NULL);
    if (BNULL(pups)) done;
    kv32 *base = (kv32 *)kv32bDataHead(pups);
    u32 n = (u32)kv32bDataLen(pups);
    for (u32 i = 0; i < n; i++) {
        u32 fd = base[i].val;
        u8bp slot = FILE_WANT_BUFS[fd];
        if (slot && slot[0]) FILEUnMap(slot);
    }
    kv32bFree(pups);
    done;
}

void DOGPupData(u8csp out, kv32b pups, u32 i) {
    out[0] = NULL; out[1] = NULL;
    if (i >= kv32bDataLen(pups)) return;
    kv32 *base = (kv32 *)kv32bDataHead(pups);
    u32 fd = base[i].val;
    u8bp slot = FILE_WANT_BUFS[fd];
    if (!slot || !slot[0]) return;
    out[0] = slot[0];
    out[1] = slot[2];
}
