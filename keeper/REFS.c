//  REFS — thin ULOG glue for keeper's per-branch reflog.
//  See REFS.h for the API and REF.md for the on-disk format.

#include "REFS.h"

#include <string.h>
#include <unistd.h>

#include "abc/PATH.h"
#include "abc/PRO.h"
#include "abc/RON.h"
#include "abc/URI.h"
#include "dog/DOG.h"
#include "dog/ULOG.h"

// --- tombstone detection ---
//
//  A "tombstone" row records branch deletion as `?<branch>#<zeros>`,
//  where the fragment is 40 ASCII '0' chars.  This shape round-trips
//  through git's wire-protocol delete-via-push (`<old> 000…0
//  refs/heads/X`) without translation.  Resolvers and advertisers
//  treat zero-sha values as "branch absent".

static b8 refs_is_tombstone(u8cs frag) {
    if (u8csLen(frag) != 40) return NO;
    for (u8cp p = frag[0]; p < frag[1]; p++)
        if (*p != '0') return NO;
    return YES;
}

// --- verb RON60 constants (cached) ---

//  Every REFS row carries one of these HTTP-shaped verbs:
//    `get`  — remote observation (fetch, receive-pack).  Row says
//             "at time T, peer's ref named K was at sha V".
//    `post` — local move (sniff commit, keeper put, sniff checkout).
//             Row says "at time T, this repo's ref K moved to V".
//    Legacy `set` rows from older writers are still read, but new
//    writes use `get`/`post`.

static ron60 refs_verb_cached(char const *name, ron60 *cache) {
    if (*cache) return *cache;
    u8cs src = {(u8cp)name, (u8cp)name + strlen(name)};
    RONutf8sDrain(cache, src);
    return *cache;
}

ron60 REFSVerbGet(void) {
    static ron60 c = 0;
    return refs_verb_cached("get", &c);
}

ron60 REFSVerbPost(void) {
    static ron60 c = 0;
    return refs_verb_cached("post", &c);
}

ron60 REFSVerbSet(void) {
    static ron60 c = 0;
    return refs_verb_cached("set", &c);
}

// --- path builder ---

#define REFS_LOG_PATH(name, dir)                                \
    a_cstr(name##_fname, REFS_FILE);                            \
    a_path(name##_pbuf, dir, name##_fname);                     \
    a_dup(u8c, name, u8bDataC(name##_pbuf))

// --- append ---

//  Populate a `uri` component-wise so URIutf8Feed re-emits
//  `<from-uri>#<sha>`.  `from` is lexed to pick up scheme/auth/path/
//  query; `to` lands in the fragment as bare 40-hex (or empty for a
//  deletion row).  Callers MUST pass canonical `from` / `to` — this
//  is a storage primitive, not a canonicaliser.
static ok64 refs_uri_for_row(urip u_out, u8csc from, u8csc to,
                             u8 *frag_bytes, size_t frag_cap,
                             size_t *frag_len_out) {
    sane(u_out && from && to && frag_bytes);
    memset(u_out, 0, sizeof(*u_out));

    //  Lex `from` into components.  URILexer consumes `u.data`; re-seed
    //  afterwards so URIutf8Feed can walk the components.
    u_out->data[0] = from[0];
    u_out->data[1] = from[1];
    call(URILexer, u_out);
    u_out->data[0] = from[0];
    u_out->data[1] = from[1];

    //  Copy `to` verbatim into caller-owned fragment storage.  Empty
    //  `to` means a deletion row (`?branch#`) — represent as a
    //  present-but-empty fragment slice so URIutf8Feed emits the
    //  bare `#`.
    size_t need = (size_t)$len(to);
    if (need > frag_cap) fail(REFSBAD);
    if (need > 0) memcpy(frag_bytes, to[0], need);
    u_out->fragment[0] = frag_bytes;
    u_out->fragment[1] = frag_bytes + need;
    *frag_len_out = need;
    done;
}

//  Return max(RONNow(), tail_ts + 1).  ULOG enforces strict
//  monotonicity; RONNow()'s ms resolution means two rapid appends
//  would collide, so clamp past the tail.
static ron60 refs_next_ts(ulogcp l) {
    ron60 now = RONNow();
    u32 n = ULOGCount(l);
    if (n == 0) return now;
    ron60 ts = 0, verb = 0;
    uri u = {};
    if (ULOGTail(l, &ts, &verb, &u) != OK) return now;
    return now > ts ? now : ts + 1;
}

ok64 REFSAppendVerb(u8csc dir, ron60 verb, u8csc from_uri, u8csc to_uri) {
    sane($ok(dir) && $ok(from_uri) && $ok(to_uri));
    //  `from_uri` must be non-empty (the ref key is mandatory);
    //  `to_uri` may be empty — that's the deletion row (`?branch#`).
    if (u8csEmpty(from_uri)) fail(REFSBAD);

    REFS_LOG_PATH(log_path, dir);
    ulog l = {};
    call(ULOGOpen, &l, log_path);

    a_pad(u8, fragb, 256);
    uri u = {};
    size_t fl = 0;
    ok64 bo = refs_uri_for_row(&u, from_uri, to_uri,
                               u8bIdleHead(fragb), u8bIdleLen(fragb), &fl);
    if (bo != OK) { ULOGClose(&l); return bo; }

    ok64 o = ULOGAppendAt(&l, refs_next_ts(&l), verb, &u);
    ULOGClose(&l);
    return o;
}

//  Back-compat shim: old callers without a verb parameter get `get`
//  (the common case — remote observations from wire operations).
//  Local-move writers (sniff POST, keeper put) use REFSAppendVerb
//  directly with REFSVerbPost.
ok64 REFSAppend(u8csc dir, u8csc from_uri, u8csc to_uri) {
    return REFSAppendVerb(dir, REFSVerbGet(), from_uri, to_uri);
}

ok64 REFSSyncRecord(u8csc dir, refcp arr, u32 nrefs) {
    sane($ok(dir) && nrefs > 0);
    REFS_LOG_PATH(log_path, dir);
    ulog l = {};
    call(ULOGOpen, &l, log_path);

    ron60 ts = refs_next_ts(&l);
    ron60 verb_get = REFSVerbGet();
    for (u32 i = 0; i < nrefs; i++) {
        u8csc from = {arr[i].key[0], arr[i].key[1]};
        u8csc to   = {arr[i].val[0], arr[i].val[1]};
        a_pad(u8, fragb, 256);
        uri u = {};
        size_t fl = 0;
        ok64 bo = refs_uri_for_row(&u, from, to,
                                   u8bIdleHead(fragb), u8bIdleLen(fragb), &fl);
        if (bo != OK) { ULOGClose(&l); return bo; }
        ok64 ao = ULOGAppendAt(&l, ts++, verb_get, &u);
        if (ao != OK) { ULOGClose(&l); return ao; }
    }
    ULOGClose(&l);
    done;
}

// --- load / each ---

typedef struct {
    refp  arr;
    u32   cnt;
    u32   max;
    u8bp  arena;
} refs_load_ctx;

//  Callback fed by ULOGeachLatest: capture (key = URI minus fragment,
//  val = fragment bytes) into the caller's arena, push a `ref` entry.
static ok64 refs_each_store(ron60 ts, ron60 verb, uricp u, void *ctx) {
    sane(u && ctx);
    (void)verb;
    refs_load_ctx *c = (refs_load_ctx *)ctx;
    if (c->cnt >= c->max) done;

    //  Skip tombstoned keys: zero-sha fragment means the branch was
    //  deleted (`?<branch>#0000…`).  Loaders/advertisers must not
    //  surface ghost branches whose latest write was a delete.
    {
        u8cs r_frag = {u->fragment[0], u->fragment[1]};
        if (!u8csEmpty(r_frag) && r_frag[0][0] == '?')
            u8csUsed(r_frag, 1);
        if (refs_is_tombstone(r_frag)) done;
    }

    //  Key: URI with fragment elided, serialised straight into
    //  arena's IDLE (URIutf8Feed advances the idle slice in place).
    //  NULL (not empty-non-NULL) so URIutf8Feed drops the `#`.
    uri ku = *u;
    ku.fragment[0] = NULL;
    ku.fragment[1] = NULL;
    u8 *kb = u8bIdleHead(c->arena);
    call(URIutf8Feed, u8bIdle(c->arena), &ku);
    u8 *ke = u8bIdleHead(c->arena);
    u8cs key_s = {kb, ke};

    //  Val: `?<sha>` — u.fragment is stored with the `?` already.
    u8 *vb = u8bIdleHead(c->arena);
    u8cs frag = {u->fragment[0], u->fragment[1]};
    call(u8bFeed, c->arena, frag);
    u8 *ve = u8bIdleHead(c->arena);
    u8cs val_s = {vb, ve};

    ref *e = &c->arr[c->cnt++];
    e->time   = ts;
    e->type   = REF_SHA;
    e->key[0] = key_s[0]; e->key[1] = key_s[1];
    e->val[0] = val_s[0]; e->val[1] = val_s[1];
    done;
}

ok64 REFSLoad(refp arr, u32p out_n, u32 max, u8b arena, u8csc dir) {
    sane(arr && out_n && u8bOK(arena));
    *out_n = 0;

    REFS_LOG_PATH(log_path, dir);
    ulog l = {};
    ok64 oo = ULOGOpen(&l, log_path);
    if (oo != OK) done;  // missing file ⇒ 0 refs, not an error

    refs_load_ctx ctx = {arr, 0, max, arena};
    //  verb_filter=0: include `get`, `post`, and legacy `set` rows.
    //  Dedup keys on the URI-minus-fragment, so peer-observed (get)
    //  and local-move (post) rows dedup separately per their distinct
    //  URI keys.
    ok64 eo = ULOGeachLatest(&l, 0, refs_each_store, &ctx);
    ULOGClose(&l);
    if (eo != OK) return eo;
    *out_n = ctx.cnt;
    done;
}

ok64 REFSEach(u8csc dir, refs_cb cb, void *ctx) {
    sane($ok(dir) && cb != NULL);

    Bu8 arena = {};
    call(u8bMap, arena, (size_t)REFS_MAX_REFS * 320);

    ref *arr = calloc(REFS_MAX_REFS, sizeof(ref));
    if (!arr) { u8bUnMap(arena); fail(REFSFAIL); }

    u32 n = 0;
    ok64 o = REFSLoad(arr, &n, REFS_MAX_REFS, arena, dir);
    if (o != OK) { free(arr); u8bUnMap(arena); return o; }

    for (u32 i = 0; i < n; i++) {
        o = cb(&arr[i], ctx);
        if (o != OK) break;
    }

    free(arr);
    u8bUnMap(arena);
    done;
}

// --- resolve ---

//  Matcher state for ULOGFindLatest's predicate.
typedef struct {
    u8cs host_needle;   // substring to match against row's host (or empty)
    u8cs in_query;      // query to match (heads|tags variant-aware)
    b8   auth_is_dot;   // input was `.?…` — accept any host
    b8   query_wildcard;// input had no `?` at all — match any ref on host
} match_ctx;

static b8 refs_host_match(u8csc host, u8csc needle) {
    if (u8csEmpty(needle)) return YES;
    size_t nl = u8csLen(needle);
    size_t hl = u8csLen(host);
    if (hl < nl) return NO;
    for (size_t off = 0; off + nl <= hl; off++)
        if (memcmp(host[0] + off, needle[0], nl) == 0) return YES;
    return NO;
}

//  Local query is an opaque path: trunk = empty, anything else is a
//  literal branch path.  Plain string equality, no name aliasing —
//  git refname conventions live behind keeper/GIT.h and apply at the
//  wire boundary only.
static b8 refs_query_match(u8csc in_query, u8csc r_query) {
    if (u8csLen(in_query) != u8csLen(r_query)) return NO;
    if (u8csEmpty(in_query)) return YES;
    return memcmp(in_query[0], r_query[0], u8csLen(in_query)) == 0;
}

static b8 refs_match_pred(uricp u, void *ctx) {
    match_ctx *m = (match_ctx *)ctx;
    u8cs r_host  = {u->host[0],  u->host[1]};
    u8cs r_query = {u->query[0], u->query[1]};
    //  Input had no `?` at all → match any ref whose host fits the
    //  needle (fresh clone: `be get //peer` with no branch spec).
    //  Otherwise apply the normal query match.
    if (!m->query_wildcard &&
        !refs_query_match(m->in_query, r_query)) return NO;
    if (m->auth_is_dot) return YES;
    if (!u8csEmpty(m->host_needle))
        return refs_host_match(r_host, m->host_needle);
    //  No host needle and not `.` — restrict to local rows (rows
    //  without a host).  Otherwise a bare `?main` lookup would
    //  randomly match a remote trunk observation.
    return u8csEmpty(r_host);
}

static ok64 refs_capture_cs(u8bp arena, u8csc src, u8csp out) {
    sane(arena && out);
    u8 *head = u8bIdleHead(arena);
    call(u8bFeed, arena, src);
    out[0] = head;
    out[1] = u8bIdleHead(arena);
    done;
}

ok64 REFSResolve(urip resolved, u8bp arena, u8csc dir, u8csc input) {
    sane($ok(dir) && $ok(input) && resolved != NULL && arena != NULL);
    memset(resolved, 0, sizeof(*resolved));

    //  Parse the input URI.  Query is opaque (local branch path); no
    //  `refs/` strip, no name aliasing.  Wire-side translation is
    //  GITParseRef/GITFeedRef's job.
    uri in = {};
    in.data[0] = input[0]; in.data[1] = input[1];
    call(URILexer, &in);
    u8cs in_query = {in.query[0], in.query[1]};

    match_ctx m = {};
    //  Presence test (not emptiness): input `?` = match trunk only;
    //  input with no `?` = match any ref on the host (wildcard).
    m.query_wildcard = (in.query[0] == NULL);
    u8csMv(m.in_query, in_query);
    if (!u8csEmpty(in.host)) {
        m.host_needle[0] = in.host[0];
        m.host_needle[1] = in.host[1];
        if (u8csLen(m.host_needle) == 1 && m.host_needle[0][0] == '.')
            m.auth_is_dot = YES;
    } else if (!u8csEmpty(in.authority)) {
        u8cs a = {in.authority[0], in.authority[1]};
        if ($len(a) >= 2 && a[0][0] == '/' && a[0][1] == '/') u8csUsed(a, 2);
        m.host_needle[0] = a[0];
        m.host_needle[1] = a[1];
        if (u8csLen(m.host_needle) == 1 && m.host_needle[0][0] == '.')
            m.auth_is_dot = YES;
    } else if (!u8csEmpty(in.path)) {
        if ($len(in.path) == 1 && in.path[0][0] == '.') m.auth_is_dot = YES;
    }
    if (m.auth_is_dot) {
        m.host_needle[0] = NULL;
        m.host_needle[1] = NULL;
    }

    //  No discriminator — bare text with no URI sigils (`?`, `//`,
    //  `.`) has nothing to match on.  Use presence (`[0] != NULL`)
    //  not emptiness: a canonical trunk lookup has present-but-empty
    //  query (`?` with nothing after) and is a legitimate request.
    if (in.query[0] == NULL && u8csEmpty(m.host_needle) && !m.auth_is_dot)
        fail(REFSNONE);

    REFS_LOG_PATH(log_path, dir);
    ulog l = {};
    ok64 oo = ULOGOpen(&l, log_path);
    if (oo != OK) fail(REFSNONE);

    ron60 ts = 0;
    uri u = {};
    ok64 fo = ULOGFindLatest(&l, refs_match_pred, &m, &ts, &u);
    if (fo != OK) { ULOGClose(&l); fail(REFSNONE); }

    //  Fill resolved.query = fragment bytes (minus leading `?`).
    u8cs frag = {u.fragment[0], u.fragment[1]};
    if (!u8csEmpty(frag) && frag[0][0] == '?') u8csUsed(frag, 1);
    //  Zero-sha tombstone: branch was deleted; report as absent.
    if (refs_is_tombstone(frag)) { ULOGClose(&l); fail(REFSNONE); }
    if (!u8csEmpty(frag))
        call(refs_capture_cs, arena, frag, resolved->query);
    if (!u8csEmpty(u.scheme))
        call(refs_capture_cs, arena, u.scheme, resolved->scheme);
    u8cs r_host = {u.host[0], u.host[1]};
    if (!u8csEmpty(r_host))
        call(refs_capture_cs, arena, r_host, resolved->host);
    if (!u8csEmpty(u.path))
        call(refs_capture_cs, arena, u.path, resolved->path);
    //  Matched row's `?query` (peer-side refname, e.g. `heads/main`)
    //  → resolved->fragment.  Lets remote-target callers recover the
    //  branch name when the input URI omits `?ref` (e.g.
    //  `be post //sniff` after a prior `be get //sniff?heads/feat`).
    u8cs r_query = {u.query[0], u.query[1]};
    if (!u8csEmpty(r_query))
        call(refs_capture_cs, arena, r_query, resolved->fragment);

    ULOGClose(&l);
    done;
}

// --- compact ---

ok64 REFSCompact(u8csc dir) {
    sane($ok(dir));
    REFS_LOG_PATH(log_path, dir);
    ulog l = {};
    ok64 oo = ULOGOpen(&l, log_path);
    if (oo != OK) done;  // nothing to compact

    //  verb_filter=0: compact across get/post/set; keeps latest per
    //  URI-minus-fragment key regardless of verb.
    ok64 co = ULOGCompactLatest(&l, log_path, 0);
    ULOGClose(&l);
    return co;
}
