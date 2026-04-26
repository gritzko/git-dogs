//  WIRECLI: client side of the git wire protocol (WIRE.md Phase 7).
//
//  WIREFetch — spawn ssh/local upload-pack, drain refs advertisement,
//              send wants/haves, ingest the returned packfile into the
//              local keeper, append a fresh REFS tip entry.
//  WIREPush  — spawn ssh/local receive-pack, drain its advertisement,
//              build a packfile from our reachable closure for the
//              chosen branch, send a single ref update, drain the
//              unpack/per-ref status reply.
//
//  Transport dispatch lives here (URI parsing → ssh argv | local
//  argv).  Everything else is shared with the server-side WIRE.c
//  through library primitives (PKT, REFADV, KEEPIngestFile,
//  KEEPGetExact, ZINFDeflate).

#include "WIRE.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "abc/FILE.h"
#include "abc/HEX.h"
#include "abc/PRO.h"
#include "abc/URI.h"
#include "dog/DOG.h"
#include "dog/SHA1.h"
#include "keeper/GIT.h"
#include "keeper/KEEP.h"
#include "keeper/PKT.h"
#include "keeper/REFADV.h"
#include "keeper/REFS.h"
#include "keeper/SHA1.h"
#include "keeper/ZINF.h"

// --- small slice helpers ------------------------------------------------

static b8 wcli_starts_with(u8csc s, u8c const *pfx, size_t plen) {
    if ((size_t)u8csLen(s) < plen) return NO;
    return memcmp(s[0], pfx, plen) == 0;
}

static b8 wcli_eq_lit(u8csc s, u8c const *lit, size_t llen) {
    if ((size_t)u8csLen(s) != llen) return NO;
    return memcmp(s[0], lit, llen) == 0;
}

static b8 wcli_decode_sha(sha1 *out, u8csc hex) {
    if (u8csLen(hex) != 40) return NO;
    a_dup(u8c, hex_dup, hex);
    u8s bin = {out->data, out->data + 20};
    if (HEXu8sDrainSome(bin, hex_dup) != OK) return NO;
    if (bin[0] != out->data + 20) return NO;
    return YES;
}

static void wcli_sha_to_hex(u8 *out40, sha1 const *s) {
    u8s hs = {out40, out40 + 40};
    u8cs bs = {s->data, s->data + 20};
    HEXu8sFeedSome(hs, bs);
}

// --- pkt-line drain with refill ----------------------------------------

#define WCLI_BUF (1u << 16)

//  Drain one pkt-line, refilling from in_fd via FILEDrain on NODATA.
//  Returns OK / PKTFLUSH / PKTDELIM / WIRECLFL.
//
//  When IDLE runs out we compact: bytes already consumed via `adv` head
//  are reclaimed into IDLE so further reads have room.  Without this
//  the fixed-size WCLI_BUF (64 KiB) overruns on large advertisements —
//  vanilla git's `~/src/git` advertises ~1000 refs (≈100 KiB), enough
//  to fail mid-parse; the parent then closes pipes and the upstream
//  ssh git-upload-pack dies with SIGPIPE.
static ok64 wcli_read_pkt(int in_fd, u8b buf, u8cs adv, u8csp line) {
    for (;;) {
        ok64 o = PKTu8sDrain(adv, line);
        if (o != NODATA) return o;
        if (!u8bHasRoom(buf)) {
            size_t consumed = (size_t)(adv[0] - u8bDataC(buf)[0]);
            if (consumed == 0) return WIRECLFL;
            u8bUsed(buf, consumed);
            u8bShift(buf, 0);
            adv[0] = u8bDataC(buf)[0];
            adv[1] = u8csTerm(u8bDataC(buf));
            if (!u8bHasRoom(buf)) return WIRECLFL;
        }
        u8s fill;
        u8sFork(u8bIdle(buf), fill);
        ok64 fr = FILEDrain(in_fd, fill);
        if (fr == FILEEND) return WIRECLFL;
        if (fr != OK) return WIRECLFL;
        u8sJoin(u8bIdle(buf), fill);
        adv[1] = u8csTerm(u8bDataC(buf));
    }
}

// --- transport spawn (ssh / local) -------------------------------------
//
//  Parse `remote_uri` and decide what to exec:
//    file:///P or keeper://local/P    → exec `keeper <verb> P` locally.
//    keeper://host/P or be://host/P   → exec `ssh host keeper <verb> P`
//                                       (keeper-protocol over ssh).
//    //host/P or //host/P.git         → exec `ssh host git-<verb> P` so
//                                       a vanilla git server still works.
//                                       Bare-ssh defaults to git protocol
//                                       since most peers will be plain git
//                                       (mill-tags.sh against ~/src/git);
//                                       use keeper:// to force keeper.
//
//  `verb` is "upload-pack" (fetch) or "receive-pack" (push).  Sets
//  *out_pid + parent's stdin_w / stdout_r ends on success.

static u8c const WCLI_KEEPER_BIN_S[] = "keeper";
static u8c const WCLI_SSH_BIN_S[]    = "/usr/bin/ssh";
static u8c const WCLI_GIT_DOT_S[]    = ".git";

//  Locate the keeper binary to exec for local transport.  Honors the
//  KEEPER_BIN env var so tests can point at the just-built binary
//  without it being on $PATH.  Writes the chosen path slice into
//  `out_path` (alias of either env or the default literal).
static void wcli_keeper_bin(u8cs out_path) {
    char const *env = getenv("KEEPER_BIN");
    if (env && *env) {
        out_path[0] = (u8cp)env;
        out_path[1] = (u8cp)env + strlen(env);
        return;
    }
    out_path[0] = WCLI_KEEPER_BIN_S;
    out_path[1] = WCLI_KEEPER_BIN_S + sizeof(WCLI_KEEPER_BIN_S) - 1;
}

//  Path "P.git" (suffix) → choose vanilla git binary instead of keeper.
static b8 wcli_path_is_git(u8csc path) {
    if ((size_t)u8csLen(path) < sizeof(WCLI_GIT_DOT_S) - 1) return NO;
    u8c const *tail = path[1] - (sizeof(WCLI_GIT_DOT_S) - 1);
    return memcmp(tail, WCLI_GIT_DOT_S, sizeof(WCLI_GIT_DOT_S) - 1) == 0;
}

static ok64 wcli_spawn(u8csc remote_uri, char const *verb,
                       int *wfd, int *rfd, pid_t *pid) {
    sane(verb && wfd && rfd && pid);

    uri u = {};
    a_dup(u8c, ru, remote_uri);
    if (URIutf8Drain(ru, &u) != OK) return WIRECLFL;

    //  Path is what the peer's upload-pack sees as argv[1].  URI parser
    //  delivers it with a leading '/' for absolute forms (file:///foo,
    //  //host/foo) which is exactly what the peer expects.
    u8cs path = {u.path[0], u.path[1]};
    if (u8csEmpty(path)) return WIRECLFL;

    a_cstr(file_s,    "file");
    a_cstr(keeper_s,  "keeper");
    a_cstr(be_s,      "be");
    b8 is_file   = wcli_eq_lit(u.scheme, file_s[0],   (size_t)$len(file_s));
    b8 is_keeper = wcli_eq_lit(u.scheme, keeper_s[0], (size_t)$len(keeper_s));
    b8 is_be     = wcli_eq_lit(u.scheme, be_s[0],     (size_t)$len(be_s));
    b8 has_host  = !u8csEmpty(u.host);

    //  Build a verb slice to pass into argv.
    u8csc verb_s = {(u8cp)verb, (u8cp)verb + strlen(verb)};

    //  Local exec branch: file://, keeper://local, or no host at all.
    if (is_file || (is_keeper && (!has_host ||
                                  wcli_eq_lit(u.host, (u8c *)"local", 5))) ||
        (!has_host && u8csEmpty(u.scheme))) {
        u8cs kbin = {};
        wcli_keeper_bin(kbin);
        u8cs argv_arr[3] = {
            {(u8cp)"keeper", (u8cp)"keeper" + 6},
            {verb_s[0], verb_s[1]},
            {path[0], path[1]},
        };
        u8css argv = {argv_arr, argv_arr + 3};
        u8csc kbin_cs = {kbin[0], kbin[1]};
        return FILESpawn(kbin_cs, argv, wfd, rfd, pid);
    }

    //  ssh remote.  Default to vanilla `git-<verb>` so plain git peers
    //  (the common case — mill-tags.sh against ~/src/git, GitHub, etc.)
    //  work transparently.  Use `keeper://host/path` (or `be://`) to
    //  force the keeper protocol when both ends speak it.  `.git` suffix
    //  is honored as an extra git marker.
    a_cstr(ssh_path_s, "/usr/bin/ssh");
    u8cs host = {u.host[0], u.host[1]};
    if (u8csEmpty(host)) return WIRECLFL;

    //  HOME-relative convention: //host/path delivers `path` with the
    //  URI parser's leading '/' attached.  ssh peers expect a path
    //  relative to the remote login's HOME, so strip it.  Absolute
    //  remote paths need to come through file:/// or be encoded
    //  differently — matching what KEEPSync/keeper_get_remote did pre-Phase8.
    if (!u8csEmpty(path) && *path[0] == '/') path[0]++;
    if (u8csEmpty(path)) return WIRECLFL;

    b8 use_keeper_ssh = is_keeper || is_be;
    b8 force_git      = wcli_path_is_git(path);

    if (use_keeper_ssh && !force_git) {
        //  ssh <host> [PATH=...] keeper <verb> <path>
        //
        //  $DOG_REMOTE_PATH is prepended to the remote shell's PATH so
        //  test harnesses can point at an out-of-tree `keeper` binary
        //  without touching the remote's login rc.  When set, we have
        //  to invoke the remote command via `sh -c` so the assignment
        //  takes effect in the same process that exec()s keeper.
        char const *rpath = getenv("DOG_REMOTE_PATH");
        if (rpath && *rpath) {
            a_pad(u8, rcmd, 1024);
            a_cstr(pre1, "PATH='");
            u8bFeed(rcmd, pre1);
            a_cstr(rp_s, rpath);
            u8bFeed(rcmd, rp_s);
            a_cstr(pre2, "':\"$PATH\" exec keeper ");
            u8bFeed(rcmd, pre2);
            u8bFeed(rcmd, verb_s);
            u8bFeed1(rcmd, ' ');
            u8bFeed(rcmd, path);
            u8cs argv_arr[3] = {
                {(u8cp)"ssh", (u8cp)"ssh" + 3},
                {host[0], host[1]},
                {u8bDataHead(rcmd), u8bIdleHead(rcmd)},
            };
            u8css argv = {argv_arr, argv_arr + 3};
            return FILESpawn(ssh_path_s, argv, wfd, rfd, pid);
        }
        u8cs argv_arr[5] = {
            {(u8cp)"ssh", (u8cp)"ssh" + 3},
            {host[0], host[1]},
            {(u8cp)"keeper", (u8cp)"keeper" + 6},
            {verb_s[0], verb_s[1]},
            {path[0], path[1]},
        };
        u8css argv = {argv_arr, argv_arr + 5};
        return FILESpawn(ssh_path_s, argv, wfd, rfd, pid);
    }
    //  ssh <host> git-<verb> <path>
    a_pad(u8, gitverb, 32);
    a_cstr(git_dash, "git-");
    u8bFeed(gitverb, git_dash);
    u8bFeed(gitverb, verb_s);
    u8cs argv_arr[4] = {
        {(u8cp)"ssh", (u8cp)"ssh" + 3},
        {host[0], host[1]},
        {u8bDataHead(gitverb), u8bIdleHead(gitverb)},
        {path[0], path[1]},
    };
    u8css argv = {argv_arr, argv_arr + 4};
    return FILESpawn(ssh_path_s, argv, wfd, rfd, pid);
}

// --- be ↔ git wire ref translation -------------------------------------
//
//  Be-side branches are opaque local paths (`""` = trunk, `"feature"`,
//  `"feat/fix"`, …).  Git wire-side refnames are `refs/heads/<X>`.  The
//  one wire alias: trunk (`""`) ⇔ git's default `refs/heads/main`.
//  Tag / remote / OTHER ref kinds are not exposed locally yet — they
//  flow through unchanged when we record a peer-observed row but have
//  no first-class be-branch counterpart.

//  be branch → wire refname into `out`.  Pre-reset.
//      ""        → "refs/heads/main"
//      "X"       → "refs/heads/X"
static ok64 wcli_be_to_wire(u8b out, u8csc be_branch) {
    sane(u8bOK(out));
    a_cstr(main_s, "main");
    u8cs name = {};
    u8csMv(name, $empty(be_branch) ? main_s : be_branch);
    return GITFeedRef(out, GITREF_BRANCH, name);
}

//  Wire refname → be branch.  Sets *kind_out to the parsed kind so
//  callers can decide what to do with non-branch refs (tags, HEAD, …).
//  For BRANCH: returns the bare name; trunk alias `main` collapses to
//  empty (be-side trunk).  Unsupported kinds set name to `bare`.
static ok64 wcli_wire_to_be(u8csc wire_refname, gitref_kind *kind_out,
                            u8csp name_out) {
    sane(kind_out && name_out);
    name_out[0] = name_out[1] = NULL;
    *kind_out = GITREF_NONE;
    u8cs bare = {};
    ok64 po = GITParseRef(wire_refname, kind_out, bare);
    if (po != OK) return po;
    if (*kind_out != GITREF_BRANCH) {
        u8csMv(name_out, bare);
        done;
    }
    //  Trunk alias: wire-side `main` is the be-side empty branch.
    a_cstr(main_s, "main");
    if (u8csLen(bare) == u8csLen(main_s) &&
        memcmp(bare[0], main_s[0], (size_t)u8csLen(main_s)) == 0) {
        name_out[0] = bare[1];
        name_out[1] = bare[1];
        done;
    }
    u8csMv(name_out, bare);
    done;
}

//  Match a peer-advertised wire refname against a be-side want_branch.
//  Both go through the be ↔ wire translator so spelling differences
//  don't matter.  `want_branch` is be-side (empty = trunk).
static b8 wcli_refname_match(u8csc adv_name, u8csc want_branch) {
    gitref_kind k = GITREF_NONE;
    u8cs adv_be = {};
    if (wcli_wire_to_be(adv_name, &k, adv_be) != OK) return NO;
    if (k != GITREF_BRANCH) return NO;
    if (u8csLen(adv_be) != u8csLen(want_branch)) return NO;
    if ($empty(want_branch)) return $empty(adv_be);
    return memcmp(adv_be[0], want_branch[0],
                  (size_t)u8csLen(want_branch)) == 0;
}

// --- WIREFetch ---------------------------------------------------------

//  Drain a peer's refs advertisement, looking for the entry that
//  matches `want_branch` (be-side; empty = trunk).  Sets *out_sha on
//  success and copies the matched be-side branch into `name_out`
//  (empty bytes for trunk).  If `want_branch` is empty, the wire entry
//  that follows the symref HEAD (matching by sha) wins — git's `clone`
//  default-branch discovery; falls back to the first non-HEAD entry.
static ok64 wcli_match_advert(int rfd, u8b buf, u8csc want_branch,
                              sha1 *out_sha, u8b name_out) {
    sane(rfd >= 0 && out_sha && u8bOK(name_out));
    u8cs adv = {u8bDataHead(buf), u8bDataHead(buf)};
    b8   picked = NO;
    sha1 head_sha = {};
    b8   have_head = NO;
    sha1 first_sha = {};
    u8cs first_name = {NULL, NULL};
    b8   first_seen = NO;
    a_cstr(head_lit, "HEAD");

    //  Helper: translate the wire refname to its be-side branch and
    //  capture it.  Trunk wire-name `main` collapses to empty bytes.
    //  Unsupported kinds (TAG, REMOTE, OTHER, HEAD) leave name_out
    //  empty — caller must not call this for them.
    #define WCLI_RECORD_NAME(name) do {                                      \
        u8bReset(name_out);                                                  \
        gitref_kind _k = GITREF_NONE;                                        \
        u8cs _be = {};                                                       \
        if (wcli_wire_to_be((u8csc){(name)[0], (name)[1]},                   \
                            &_k, _be) == OK) {                               \
            if (!$empty(_be)) u8bFeed(name_out, _be);                        \
        }                                                                    \
    } while (0)

    for (;;) {
        u8cs line = {};
        ok64 d = wcli_read_pkt(rfd, buf, adv, line);
        if (d == PKTFLUSH) break;
        if (d == PKTDELIM) continue;
        if (d != OK) return WIRECLFL;

        //  Trim trailing '\n'.
        if (u8csLen(line) > 0 && line[1][-1] == '\n') line[1]--;
        if (u8csLen(line) < 41) continue;          // not "<sha> <name>"

        u8csc hex = {line[0], line[0] + 40};
        sha1 sha = {};
        if (!wcli_decode_sha(&sha, hex)) continue;
        if (line[0][40] != ' ') continue;

        u8cs name = {line[0] + 41, line[1]};
        //  Strip everything from the first NUL (capability list).
        u8c *nul = name[0];
        while (nul < name[1] && *nul != 0) nul++;
        name[1] = nul;
        //  Strip "^{}" peeled-tag suffix (we want the tag's own sha here).
        if (u8csLen(name) >= 3 &&
            name[1][-1] == '}' && name[1][-2] == '{' && name[1][-3] == '^')
            continue;

        //  Track HEAD separately — git advertises "HEAD" + capability
        //  list as the very first entry, and the matching branch ref
        //  follows with the same sha.
        if (wcli_eq_lit(name, head_lit[0], (size_t)$len(head_lit))) {
            head_sha = sha;
            have_head = YES;
            continue;
        }

        //  Skip peer's own remote-tracking refs (`refs/remotes/*`) —
        //  those are git-ism leakage, not real branches of the repo.
        //  Only `refs/heads/*` and `refs/tags/*` are meaningful.
        {
            a_cstr(remotes_pfx, "refs/remotes/");
            if (wcli_starts_with(name, remotes_pfx[0],
                                 (size_t)$len(remotes_pfx)))
                continue;
            a_cstr(heads_pfx_s, "refs/heads/");
            a_cstr(tags_pfx_s,  "refs/tags/");
            if (!wcli_starts_with(name, heads_pfx_s[0],
                                  (size_t)$len(heads_pfx_s)) &&
                !wcli_starts_with(name, tags_pfx_s[0],
                                  (size_t)$len(tags_pfx_s)))
                continue;
        }

        if (!first_seen) {
            first_sha = sha;
            first_name[0] = name[0];
            first_name[1] = name[1];
            first_seen = YES;
        }
        //  Caller wants trunk (empty) and didn't bind to a specific
        //  branch: take the entry whose sha matches the symref HEAD.
        //  Otherwise compare be-side branch names via the translator.
        if ($empty(want_branch)) {
            if (have_head && sha1eq(&sha, &head_sha)) {
                *out_sha = sha;
                WCLI_RECORD_NAME(name);
                picked = YES;
            }
        } else if (wcli_refname_match(name, want_branch)) {
            *out_sha = sha;
            WCLI_RECORD_NAME(name);
            picked = YES;
        }
    }
    if (!picked) {
        if ($empty(want_branch) && first_seen) {
            *out_sha = first_sha;
            u8cs fn = {first_name[0], first_name[1]};
            WCLI_RECORD_NAME(fn);
            done;
        }
        return WIRECLNRF;
    }
    #undef WCLI_RECORD_NAME
    done;
}

//  Harvest local-tip have shas from the keeper's REFADV.  Caps at
//  WIRE_MAX_HAVES to bound the request size.
static u32 wcli_collect_haves(refadvcp adv, sha1 *out, u32 cap) {
    if (!adv) return 0;
    u32 n = 0;
    for (u32 i = 0; i < adv->count && n < cap; i++) {
        out[n++] = adv->ents[i].tip;
    }
    return n;
}

//  Send the upload-pack request: want <sha> caps + flush + haves +
//  flush + done.  No multi_ack — server replies with one NAK + pack.
static ok64 wcli_send_request(int wfd, sha1 const *want_sha,
                              sha1 const *haves, u32 nhaves) {
    sane(wfd >= 0 && want_sha);

    Bu8 frame = {};
    call(u8bAllocate, frame, (1u << 16));

    //  want line.
    {
        a_pad(u8, line, 256);
        a_cstr(want_pfx, "want ");
        u8bFeed(line, want_pfx);
        u8 hex[40];
        wcli_sha_to_hex(hex, want_sha);
        u8csc hexs = {hex, hex + 40};
        u8bFeed(line, hexs);
        a_cstr(caps_s, " no-progress ofs-delta\n");
        u8bFeed(line, caps_s);
        a_dup(u8c, payload, u8bData(line));
        ok64 po = PKTu8sFeed(u8bIdle(frame), payload);
        if (po != OK) { u8bFree(frame); return po; }
    }
    ok64 fo = PKTu8sFeedFlush(u8bIdle(frame));
    if (fo != OK) { u8bFree(frame); return fo; }

    //  have lines.
    for (u32 i = 0; i < nhaves; i++) {
        a_pad(u8, line, 64);
        a_cstr(have_pfx, "have ");
        u8bFeed(line, have_pfx);
        u8 hex[40];
        wcli_sha_to_hex(hex, &haves[i]);
        u8csc hexs = {hex, hex + 40};
        u8bFeed(line, hexs);
        u8bFeed1(line, '\n');
        a_dup(u8c, payload, u8bData(line));
        ok64 po = PKTu8sFeed(u8bIdle(frame), payload);
        if (po != OK) { u8bFree(frame); return po; }
    }

    //  done.
    {
        a_cstr(done_s, "done\n");
        ok64 po = PKTu8sFeed(u8bIdle(frame), done_s);
        if (po != OK) { u8bFree(frame); return po; }
    }

    a_dup(u8c, fdata, u8bData(frame));
    ok64 wo = FILEFeedAll(wfd, fdata);
    u8bFree(frame);
    return wo;
}

//  Drain everything from rfd to a 1 GiB-mapped Bu8.  Returns OK on
//  EOF (clean) and *bytes_out is the captured slice.
static ok64 wcli_drain_response(int rfd, Bu8 buf) {
    sane(rfd >= 0);
    for (;;) {
        if (!u8bHasRoom(buf)) return WIRECLFL;
        u8s fill;
        u8sFork(u8bIdle(buf), fill);
        ok64 fr = FILEDrain(rfd, fill);
        if (fr == FILEEND) return OK;
        if (fr != OK) return WIRECLFL;
        u8sJoin(u8bIdle(buf), fill);
    }
}

//  Walk past any leading pkt-lines (NAK / ACK / progress) inside
//  `data`, writing the slice that starts at the raw pack bytes into
//  `out`.  A pkt-line whose payload starts with "PACK" is the pack's
//  first 4 bytes inlined into a side-band frame the way some servers
//  do it; treat that case the same as raw bytes.
static void wcli_strip_status(u8cs out, u8cs data) {
    out[0] = data[0];
    out[1] = data[1];
    for (;;) {
        u8cs line = {};
        u8cs probe = {out[0], out[1]};
        ok64 d = PKTu8sDrain(probe, line);
        if (d == PKTFLUSH) {
            out[0] = probe[0];
            return;
        }
        if (d != OK) return;
        if (u8csLen(line) >= 4 && memcmp(line[0], "PACK", 4) == 0) {
            out[0] = line[0];
            out[1] = line[1];
            return;
        }
        if (u8csLen(line) >= 3 &&
            (memcmp(line[0], "NAK", 3) == 0 ||
             memcmp(line[0], "ACK", 3) == 0)) {
            out[0] = probe[0];
            continue;
        }
        return;
    }
}

//  Append `<peer-uri>?<be-branch> → <40-hex>` to local REFS.
//  `be_branch` is be-side (empty for trunk).  Peer's scheme / authority
//  / path land in the row so later lookups (`be get //peer`) can filter
//  by host.  No canonicalisation aliasing — the query is stored as the
//  literal be-branch path (DOGCanonURIFeed only folds shape, not name).
static ok64 wcli_record_ref(keeper *k, u8csc remote_uri, u8csc be_branch,
                             sha1 const *new_sha) {
    sane(k);
    a_path(keepdir, u8bDataC(k->h->root), KEEP_DIR_S);

    uri pu = {};
    pu.data[0] = remote_uri[0];
    pu.data[1] = remote_uri[1];
    (void)URILexer(&pu);

    //  Always present (even if empty) so DOGCanonURIFeed emits the `?`
    //  separator — `<peer-uri>?` is the trunk-on-peer key.
    if ($empty(be_branch)) {
        pu.query[0] = remote_uri[1];
        pu.query[1] = remote_uri[1];
    } else {
        u8csMv(pu.query, be_branch);
    }
    pu.fragment[0] = NULL;
    pu.fragment[1] = NULL;

    a_pad(u8, kbuf, 512);
    call(DOGCanonURIFeed, kbuf, &pu);
    a_dup(u8c, key, u8bData(kbuf));

    u8 hex[40];
    wcli_sha_to_hex(hex, new_sha);
    u8csc val = {hex, hex + 40};

    return REFSAppend($path(keepdir), key, val);
}

ok64 WIREFetch(keeper *k, u8csc remote_uri, u8csc want_ref) {
    sane(k);
    if (u8csEmpty(remote_uri)) return WIRECLFL;

    //  Empty want_ref → let wcli_match_advert pick the peer's HEAD or
    //  first advertised ref (mirrors `git clone`'s default-branch
    //  discovery).  Callers that want an explicit fallback should pass
    //  e.g. "heads/main" themselves.
    u8cs effective_ref = {want_ref[0], want_ref[1]};

    int wfd = -1, rfd = -1;
    pid_t pid = 0;
    ok64 so = wcli_spawn(remote_uri, "upload-pack", &wfd, &rfd, &pid);
    if (so != OK) return WIRECLFL;

    Bu8 advbuf = {};
    ok64 rv = WIRECLFL;
    if (u8bAllocate(advbuf, WCLI_BUF) != OK) goto fetch_close;

    //  1.  Drain refs advertisement; pick the want sha + capture the
    //      matched ref name (used for the local REFS write below).
    sha1 want_sha = {};
    a_pad(u8, matched_ref_buf, 256);
    ok64 mo = wcli_match_advert(rfd, advbuf, effective_ref, &want_sha,
                                matched_ref_buf);
    if (mo != OK) { rv = mo; goto fetch_close; }
    u8cs matched_ref = {u8bDataHead(matched_ref_buf),
                        u8bIdleHead(matched_ref_buf)};
    if (u8csEmpty(matched_ref)) {
        matched_ref[0] = effective_ref[0];
        matched_ref[1] = effective_ref[1];
    }

    //  2.  Harvest haves from local REFADV.
    sha1 haves[WIRE_MAX_HAVES] = {};
    u32  nhaves = 0;
    {
        refadv adv = {};
        ok64 ao = REFADVOpen(&adv, k);
        if (ao == OK) {
            nhaves = wcli_collect_haves(&adv, haves, WIRE_MAX_HAVES);
            REFADVClose(&adv);
        }
    }

    //  3.  Send want + haves + done.
    if (wcli_send_request(wfd, &want_sha, haves, nhaves) != OK)
        goto fetch_close;
    close(wfd); wfd = -1;

    //  4.  Drain the response (NAK + pack).
    Bu8 respbuf = {};
    if (u8bMap(respbuf, 1ULL << 30) != OK) goto fetch_close;
    if (wcli_drain_response(rfd, respbuf) != OK) {
        u8bUnMap(respbuf);
        goto fetch_close;
    }
    close(rfd); rfd = -1;

    //  5.  Strip leading status lines, then ingest.
    u8cs all = {u8bDataHead(respbuf), u8bIdleHead(respbuf)};
    u8cs pack = {};
    wcli_strip_status(pack, all);
    if (u8csLen(pack) >= 12) {
        a_dup(u8c, packdup, pack);
        ok64 io = KEEPIngestFile(k, packdup);
        if (io != OK) {
            u8bUnMap(respbuf);
            goto fetch_close;
        }
    }
    u8bUnMap(respbuf);

    //  6.  Record the ref locally under the actually-matched name,
    //  attributed to the peer URI.
    if (wcli_record_ref(k, remote_uri, matched_ref, &want_sha) != OK)
        goto fetch_close;

    rv = OK;

fetch_close:
    if (advbuf[0]) u8bFree(advbuf);
    if (wfd >= 0) close(wfd);
    if (rfd >= 0) close(rfd);
    if (pid > 0) {
        int rc = 0;
        FILEReap(pid, &rc);
    }
    return rv;
}

// --- WIREPush ----------------------------------------------------------
//
//  MVP: build a packfile carrying the full reachable closure of our
//  local tip (commit + tree + blobs).  No DAG diff against the peer's
//  advertised tip yet — over-ship is the failure mode (the server
//  ingests the whole pack anyway and refs are FF-checked separately).

#define WPUSH_MAX_OBJS 65536

//  Recursively collect tree + blob SHAs reachable from `tree_sha` into
//  `out` (capacity `cap`).  Mirrors keep_walk_tree (KEEP.c) but lives
//  here so WIRECLI doesn't depend on KEEP.c's static helpers.
// --- have-set (sorted sha array; binary-search membership) ---

typedef struct {
    sha1 *items;
    u32   n;
    u32   cap;
} sha_set;

static b8 sha_set_has(sha_set const *s, sha1 const *q) {
    if (!s || s->n == 0) return NO;
    u32 lo = 0, hi = s->n;
    while (lo < hi) {
        u32 mid = (lo + hi) >> 1;
        int c = sha1cmp(&s->items[mid], q);
        if (c == 0) return YES;
        if (c < 0) lo = mid + 1;
        else       hi = mid;
    }
    return NO;
}

static void sha_set_add(sha_set *s, sha1 const *v) {
    if (!s || s->n >= s->cap) return;
    //  Insertion sort: find the position and shift.
    u32 i = s->n;
    while (i > 0 && sha1cmp(&s->items[i - 1], v) > 0) {
        s->items[i] = s->items[i - 1];
        i--;
    }
    if (i > 0 && sha1eq(&s->items[i - 1], v)) return;  //  dup
    s->items[i] = *v;
    s->n++;
}

//  Walk a tree's closure into `out` (skip-list-aware: a sha already
//  present in `have` is not added and its sub-objects are not
//  enumerated).  When `add_to_have` is non-NULL, also record visited
//  shas into that set — used by the "collect have-set from peer_tip"
//  pass before the local walk.
static ok64 wpush_walk_tree(keeper *k, sha1 const *tree_sha,
                            sha1 *out, u32 *n, u32 cap,
                            sha_set const *have, sha_set *add_to_have) {
    sane(k && tree_sha && n);
    if (have && sha_set_has(have, tree_sha)) done;
    //  Dedup against `add_to_have` too — without this check, a merge
    //  history (a commit reachable through two parent paths) re-walks
    //  the same trees / blobs through every alternative path,
    //  exploding O(N) into O(2^depth).
    if (add_to_have && sha_set_has(add_to_have, tree_sha)) done;
    if (out) {
        if (*n >= cap) return WIRECLFL;
        out[(*n)++] = *tree_sha;
    }
    if (add_to_have) sha_set_add(add_to_have, tree_sha);

    Bu8 tbuf = {};
    ok64 mo = u8bMap(tbuf, 1UL << 20);
    if (mo != OK) return mo;
    u8 ttype = 0;
    if (KEEPGetExact(k, tree_sha, tbuf, &ttype) != OK ||
        ttype != KEEP_OBJ_TREE) {
        u8bUnMap(tbuf);
        done;
    }
    u8cs walk = {u8bDataHead(tbuf), u8bIdleHead(tbuf)};
    u8cs file = {}, sha = {};
    while (GITu8sDrainTree(walk, file, sha) == OK) {
        if ($len(sha) != 20) continue;
        b8 is_tree = NO;
        b8 is_submodule = NO;
        if ($len(file) >= 5 && file[0][0] == '4' && file[0][1] == '0')
            is_tree = YES;
        if ($len(file) >= 6 && file[0][0] == '1' && file[0][1] == '6' &&
            file[0][2] == '0')
            is_submodule = YES;
        if (is_submodule) continue;
        sha1 entry_sha = {};
        memcpy(entry_sha.data, sha[0], 20);
        if (have && sha_set_has(have, &entry_sha)) continue;
        if (add_to_have && sha_set_has(add_to_have, &entry_sha)) continue;
        if (is_tree) {
            wpush_walk_tree(k, &entry_sha, out, n, cap, have, add_to_have);
        } else {
            if (out) {
                if (*n >= cap) break;
                out[(*n)++] = entry_sha;
            }
            if (add_to_have) sha_set_add(add_to_have, &entry_sha);
        }
    }
    u8bUnMap(tbuf);
    done;
}

//  Collect commit + tree + blob SHAs reachable from `commit_sha`,
//  walking the parent chain too (so multi-commit FF pushes carry the
//  intermediate commits).  When `have` is non-NULL, any sha (commit,
//  tree, blob, or parent commit) already in the set is treated as
//  closed: it is not added to `out` and its sub-graph is not
//  enumerated — the assumption is the peer already has it.
//
//  When `add_to_have` is non-NULL (and `out` is NULL), the function
//  populates the haveset instead — used for the peer-tip closure pass
//  before the local walk.
static ok64 wpush_walk_commit(keeper *k, sha1 const *commit_sha,
                              sha1 *out, u32 *n, u32 cap,
                              sha_set const *have, sha_set *add_to_have) {
    sane(k && commit_sha && n);
    if (have && sha_set_has(have, commit_sha)) done;
    //  See wpush_walk_tree: without this check, a merge-history
    //  closure re-walks ancestors through every alternate path.
    if (add_to_have && sha_set_has(add_to_have, commit_sha)) done;
    if (out) {
        if (*n >= cap) return WIRECLFL;
        out[(*n)++] = *commit_sha;
    }
    if (add_to_have) sha_set_add(add_to_have, commit_sha);

    Bu8 cbuf = {};
    ok64 mo = u8bMap(cbuf, 1UL << 20);
    if (mo != OK) return mo;
    u8 ctype = 0;
    if (KEEPGetExact(k, commit_sha, cbuf, &ctype) != OK ||
        ctype != KEEP_OBJ_COMMIT) {
        u8bUnMap(cbuf);
        return WIRECLFL;
    }
    u8cs commit_body = {u8bDataHead(cbuf), u8bIdleHead(cbuf)};
    sha1 tree_sha = {};
    if (GITu8sCommitTree(commit_body, tree_sha.data) != OK) {
        u8bUnMap(cbuf);
        return WIRECLFL;
    }

    //  Walk parents.  Each `parent <40-hex>` header line names another
    //  commit that must also be in the pack unless the peer has it.
    {
        u8cs body = {u8bDataHead(cbuf), u8bIdleHead(cbuf)};
        u8cs field = {}, value = {};
        while (GITu8sDrainCommit(body, field, value) == OK) {
            if ($empty(field)) break;
            if ($len(field) == 6 && memcmp(field[0], "parent", 6) == 0 &&
                $len(value) >= 40) {
                sha1 par = {};
                u8s bin = {par.data, par.data + 20};
                u8cs hx = {value[0], value[0] + 40};
                a_dup(u8c, hx_dup, hx);
                if (HEXu8sDrainSome(bin, hx_dup) != OK) continue;
                if (bin[0] != par.data + 20) continue;
                if (have && sha_set_has(have, &par)) continue;
                if (add_to_have && sha_set_has(add_to_have, &par)) continue;
                wpush_walk_commit(k, &par, out, n, cap, have, add_to_have);
            }
        }
    }
    u8bUnMap(cbuf);

    return wpush_walk_tree(k, &tree_sha, out, n, cap, have, add_to_have);
}

//  Append a pack object header (type + size varint, big-endian-ish) to
//  `buf`.  Mirrors keep_feed_obj_hdr in KEEP.c.
static void wpush_feed_obj_hdr(u8b buf, u8 type, u64 size) {
    u8 first = (u8)((type << 4) | (size & 0x0f));
    size >>= 4;
    if (size > 0) first |= 0x80;
    u8bFeed1(buf, first);
    while (size > 0) {
        u8 c = (u8)(size & 0x7f);
        size >>= 7;
        if (size > 0) c |= 0x80;
        u8bFeed1(buf, c);
    }
}

//  Build a v2 packfile containing the listed objects, in order, into
//  `pack_out` (caller pre-mapped).  Each object is fetched via
//  KEEPGetExact and zlib-deflated inline.  Adds the 12-byte PACK
//  header up front and the 20-byte SHA-1 trailer at the end.
static ok64 wpush_build_pack(keeper *k, sha1 const *shas, u32 nshas,
                             u8b pack_out) {
    sane(k && shas && u8bOK(pack_out));

    //  PACK header.
    u8 hdr[12] = {'P','A','C','K', 0,0,0,2, 0,0,0,0};
    hdr[8]  = (u8)((nshas >> 24) & 0xff);
    hdr[9]  = (u8)((nshas >> 16) & 0xff);
    hdr[10] = (u8)((nshas >>  8) & 0xff);
    hdr[11] = (u8) (nshas        & 0xff);
    u8csc hdr_s = {hdr, hdr + 12};
    u8bFeed(pack_out, hdr_s);

    for (u32 i = 0; i < nshas; i++) {
        Bu8 obuf = {};
        ok64 mo = u8bMap(obuf, 1UL << 24);
        if (mo != OK) return mo;
        u8 otype = 0;
        if (KEEPGetExact(k, &shas[i], obuf, &otype) != OK) {
            u8bUnMap(obuf);
            return WIRECLFL;
        }
        u64 olen = u8bDataLen(obuf);

        a_pad(u8, ohdr, 16);
        wpush_feed_obj_hdr(ohdr, otype, olen);
        a_dup(u8c, oh, u8bData(ohdr));
        u8bFeed(pack_out, oh);

        a_dup(u8c, osrc, u8bData(obuf));
        ok64 zo = ZINFDeflate(u8bIdle(pack_out), osrc);
        u8bUnMap(obuf);
        if (zo != OK) return zo;
    }

    //  20-byte SHA-1 trailer over the whole pack so far.
    sha1 psha = {};
    a_dup(u8c, pack_data, u8bData(pack_out));
    SHA1Sum(&psha, pack_data);
    u8csc psha_s = {psha.data, psha.data + 20};
    u8bFeed(pack_out, psha_s);
    done;
}

//  Look up our local tip for `local_branch` via REFADV.  `local_branch`
//  is be-side (empty for trunk).  Sets *have=YES if found, *out filled.
static void wpush_local_tip(refadvcp adv, u8csc local_branch,
                            sha1 *out, b8 *have) {
    *have = NO;
    if (!adv) return;
    a_pad(u8, full, 256);
    if (wcli_be_to_wire(full, local_branch) != OK) return;
    u8cs target = {u8bDataHead(full), u8bIdleHead(full)};
    for (u32 i = 0; i < adv->count; i++) {
        u8cs r = {adv->ents[i].refname[0], adv->ents[i].refname[1]};
        if (u8csLen(r) != u8csLen(target)) continue;
        if (memcmp(r[0], target[0], (size_t)u8csLen(target)) != 0) continue;
        *out  = adv->ents[i].tip;
        *have = YES;
        return;
    }
}

//  Drain peer's refs advertisement; if `branch_refname` matches an
//  advertised entry, capture its sha and set *have=YES.  Otherwise
//  (creation case) leave *have=NO with sha untouched.
static ok64 wpush_peer_tip(int rfd, u8b advbuf, u8csc branch_refname,
                           sha1 *out_sha, b8 *out_have) {
    sane(rfd >= 0 && out_sha && out_have);
    *out_have = NO;
    u8cs adv = {u8bDataHead(advbuf), u8bDataHead(advbuf)};
    for (;;) {
        u8cs line = {};
        ok64 d = wcli_read_pkt(rfd, advbuf, adv, line);
        if (d == PKTFLUSH) break;
        if (d == PKTDELIM) continue;
        if (d != OK) return WIRECLFL;
        if (u8csLen(line) > 0 && line[1][-1] == '\n') line[1]--;
        if (u8csLen(line) < 41) continue;
        u8csc hex = {line[0], line[0] + 40};
        sha1 sha = {};
        if (!wcli_decode_sha(&sha, hex)) continue;
        if (line[0][40] != ' ') continue;
        u8cs name = {line[0] + 41, line[1]};
        u8c *nul = name[0];
        while (nul < name[1] && *nul != 0) nul++;
        name[1] = nul;
        if (u8csLen(name) == u8csLen(branch_refname) &&
            memcmp(name[0], branch_refname[0],
                   (size_t)u8csLen(branch_refname)) == 0) {
            *out_sha  = sha;
            *out_have = YES;
        }
    }
    done;
}

//  Send "<old> <new> <refname>\0report-status\n" + flush.
static ok64 wpush_send_update(int wfd, sha1 const *old_sha,
                              sha1 const *new_sha, u8csc refname,
                              b8 have_old) {
    sane(wfd >= 0 && new_sha);
    Bu8 frame = {};
    call(u8bAllocate, frame, 1024);

    a_pad(u8, line, 512);
    u8 oh[40], nh[40];
    if (have_old) {
        wcli_sha_to_hex(oh, old_sha);
    } else {
        memset(oh, '0', 40);
    }
    wcli_sha_to_hex(nh, new_sha);
    u8csc oh_s = {oh, oh + 40};
    u8csc nh_s = {nh, nh + 40};
    u8bFeed(line, oh_s);
    u8bFeed1(line, ' ');
    u8bFeed(line, nh_s);
    u8bFeed1(line, ' ');
    u8bFeed(line, refname);
    u8bFeed1(line, 0);
    a_cstr(caps, "report-status");
    u8bFeed(line, caps);
    u8bFeed1(line, '\n');
    a_dup(u8c, payload, u8bData(line));
    ok64 po = PKTu8sFeed(u8bIdle(frame), payload);
    if (po != OK) { u8bFree(frame); return po; }
    ok64 fo = PKTu8sFeedFlush(u8bIdle(frame));
    if (fo != OK) { u8bFree(frame); return fo; }

    a_dup(u8c, fdata, u8bData(frame));
    ok64 wo = FILEFeedAll(wfd, fdata);
    u8bFree(frame);
    return wo;
}

//  Drain push response, scanning for "unpack ok" + "ok <refname>".
static ok64 wpush_drain_status(int rfd, u8csc refname) {
    sane(rfd >= 0);
    Bu8 buf = {};
    call(u8bAllocate, buf, WCLI_BUF);
    u8cs adv = {u8bDataHead(buf), u8bDataHead(buf)};
    b8 unpack_ok = NO;
    b8 ref_ok    = NO;

    a_pad(u8, ok_line, 512);
    a_cstr(ok_pfx, "ok ");
    u8bFeed(ok_line, ok_pfx);
    u8bFeed(ok_line, refname);
    a_dup(u8c, ok_match, u8bData(ok_line));

    a_pad(u8, ng_line, 512);
    a_cstr(ng_pfx, "ng ");
    u8bFeed(ng_line, ng_pfx);
    u8bFeed(ng_line, refname);
    a_dup(u8c, ng_match, u8bData(ng_line));

    for (;;) {
        u8cs line = {};
        ok64 d = wcli_read_pkt(rfd, buf, adv, line);
        if (d == PKTFLUSH) break;
        if (d == PKTDELIM) continue;
        if (d != OK) break;
        if (u8csLen(line) >= 9 && memcmp(line[0], "unpack ok", 9) == 0)
            unpack_ok = YES;
        if (u8csLen(line) >= (ssize_t)u8csLen(ok_match) &&
            memcmp(line[0], ok_match[0],
                   (size_t)u8csLen(ok_match)) == 0)
            ref_ok = YES;
        if (u8csLen(line) >= (ssize_t)u8csLen(ng_match) &&
            memcmp(line[0], ng_match[0],
                   (size_t)u8csLen(ng_match)) == 0) {
            //  ng — keep draining but flag failure.
            ref_ok = NO;
        }
    }
    u8bFree(buf);
    return (unpack_ok && ref_ok) ? OK : WIRECLFL;
}

ok64 WIREPush(keeper *k, u8csc remote_uri, u8csc local_branch) {
    sane(k);
    //  `local_branch` is be-side; empty (NULL or zero-length) selects
    //  the trunk shard, which goes on the wire as `refs/heads/main`.
    if (u8csEmpty(remote_uri)) return WIRECLFL;

    //  Resolve our local tip via REFADV (one-shot snapshot).
    sha1 local_tip = {};
    b8   have_local = NO;
    {
        refadv adv = {};
        ok64 ao = REFADVOpen(&adv, k);
        if (ao != OK) return ao;
        wpush_local_tip(&adv, local_branch, &local_tip, &have_local);
        REFADVClose(&adv);
    }
    if (!have_local) return WIRECLNRF;

    //  Build the wire refname (refs/heads/X, trunk → main) once.
    a_pad(u8, refname_buf, 256);
    call(wcli_be_to_wire, refname_buf, local_branch);
    u8cs refname = {u8bDataHead(refname_buf), u8bIdleHead(refname_buf)};

    //  Spawn receive-pack on the peer.
    fprintf(stderr, "wpush: spawning receive-pack, remote=%.*s\n",
            (int)u8csLen(remote_uri), (char const *)remote_uri[0]);
    int wfd = -1, rfd = -1;
    pid_t pid = 0;
    ok64 so = wcli_spawn(remote_uri, "receive-pack", &wfd, &rfd, &pid);
    if (so != OK) {
        fprintf(stderr, "wpush: spawn failed (so=%llx)\n",
                (unsigned long long)so);
        return WIRECLFL;
    }
    fprintf(stderr, "wpush: spawned ok, pid=%d\n", (int)pid);

    Bu8 advbuf = {};
    ok64 rv = WIRECLFL;
    if (u8bAllocate(advbuf, WCLI_BUF) != OK) {
        fprintf(stderr, "wpush: advbuf alloc failed\n");
        goto push_close;
    }

    //  Drain peer advert; capture old tip if peer already has the ref.
    sha1 peer_tip = {};
    b8   have_peer = NO;
    if (wpush_peer_tip(rfd, advbuf, refname, &peer_tip, &have_peer) != OK) {
        fprintf(stderr, "wpush: peer_tip drain failed\n");
        goto push_close;
    }
    fprintf(stderr, "wpush: peer advert drained, have_peer=%d\n",
            (int)have_peer);

    //  Short-circuit: peer already at our tip — nothing to push.
    if (have_peer && sha1eq(&peer_tip, &local_tip)) {
        rv = OK;
        //  Still need to send a flush so the peer closes cleanly.
        Bu8 flush_b = {};
        if (u8bAllocate(flush_b, 8) == OK) {
            PKTu8sFeedFlush(u8bIdle(flush_b));
            a_dup(u8c, fdata, u8bData(flush_b));
            FILEFeedAll(wfd, fdata);
            u8bFree(flush_b);
        }
        goto push_close;
    }

    //  Build the have-set (objects the peer already has) when peer
    //  advertised our branch.  Walking peer_tip's commit + tree
    //  closure locally gives us every sha we don't need to ship —
    //  cuts a 580-object full-snapshot pack down to the 5-10 objects
    //  actually new in a typical FF.
    sha_set haveset = {};
    sha_set *have = NULL;
    if (have_peer) {
        haveset.items = calloc(WPUSH_MAX_OBJS, sizeof(sha1));
        haveset.cap   = WPUSH_MAX_OBJS;
        if (haveset.items) {
            (void)wpush_walk_commit(k, &peer_tip, NULL, &(u32){0}, 0,
                                    NULL, &haveset);
            have = &haveset;
        }
    }

    //  Walk the local commit's reachable closure, skipping anything
    //  the peer already advertised (via `have`) and following the
    //  parent chain so multi-commit FF pushes carry intermediate
    //  commits.
    sha1 *shas = calloc(WPUSH_MAX_OBJS, sizeof(sha1));
    if (!shas) {
        if (haveset.items) free(haveset.items);
        goto push_close;
    }
    u32 nshas = 0;
    if (wpush_walk_commit(k, &local_tip, shas, &nshas, WPUSH_MAX_OBJS,
                          have, NULL) != OK || nshas == 0) {
        free(shas);
        if (haveset.items) free(haveset.items);
        goto push_close;
    }
    if (haveset.items) free(haveset.items);
    fprintf(stderr, "wpush: walked %u objects\n", nshas);

    //  Build the pack.
    Bu8 packbuf = {};
    if (u8bAllocate(packbuf, 1ULL << 26) != OK) {
        fprintf(stderr, "wpush: packbuf alloc failed\n");
        free(shas);
        goto push_close;
    }
    if (wpush_build_pack(k, shas, nshas, packbuf) != OK) {
        fprintf(stderr, "wpush: build_pack failed\n");
        free(shas);
        u8bFree(packbuf);
        goto push_close;
    }
    free(shas);
    fprintf(stderr, "wpush: pack built (%llu bytes)\n",
            (unsigned long long)u8bDataLen(packbuf));

    //  Send the ref-update line + flush.
    if (wpush_send_update(wfd, &peer_tip, &local_tip, refname,
                          have_peer) != OK) {
        fprintf(stderr, "wpush: send_update failed\n");
        u8bFree(packbuf);
        goto push_close;
    }
    //  Send the pack bytes.
    {
        a_dup(u8c, pdata, u8bData(packbuf));
        ok64 wo = FILEFeedAll(wfd, pdata);
        u8bFree(packbuf);
        if (wo != OK) {
            fprintf(stderr, "wpush: pack send failed\n");
            goto push_close;
        }
    }
    close(wfd); wfd = -1;

    //  Drain status.
    rv = wpush_drain_status(rfd, refname);
    if (rv != OK) fprintf(stderr, "wpush: drain_status returned non-OK\n");
    close(rfd); rfd = -1;

push_close:
    if (advbuf[0]) u8bFree(advbuf);
    if (wfd >= 0) close(wfd);
    if (rfd >= 0) close(rfd);
    if (pid > 0) {
        int rc = 0;
        FILEReap(pid, &rc);
    }
    return rv;
}
