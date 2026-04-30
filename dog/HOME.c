#include "HOME.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "DPATH.h"
#include "abc/FILE.h"
#include "abc/PRO.h"
#include "TOMLT.h"

// --- HOMEOpen / HOMEClose ---

// Capture stdout of `git config --global --get <key>` into out.
// Returns NODATA if git exits non-zero (key unset) or the subprocess
// cannot be spawned.  Trailing '\n' is trimmed.
static ok64 home_git_config_get(char const *key, u8s out) {
    sane($ok(out));
    a_cstr(gitp, "/usr/bin/git");
    u8cs av[] = {
        u8slit("git"),
        u8slit("config"),
        u8slit("--global"),
        u8slit("--get"),
        u8scstr(key),
    };
    u8css argv = {av, av + 5};

    pid_t pid = 0;
    int rfd = -1;
    if (FILESpawn(gitp, argv, NULL, &rfd, &pid) != OK) return NODATA;

    a_pad(u8, buf, 256);
    FILEEnsureSoft(rfd, buf, u8bIdleLen(buf));
    FILEClose(&rfd);

    int rc = -1;
    FILEReap(pid, &rc);
    if (rc != 0) return NODATA;

    u8cs raw = {u8bDataHead(buf), u8bIdleHead(buf)};
    while (!$empty(raw) && (raw[1][-1] == '\n' || raw[1][-1] == '\r'))
        raw[1]--;
    if ($empty(raw)) return NODATA;
    return u8sFeed(out, raw);
}

// Fresh clones: seed .dogs/config from git's global config so commits
// and ref authorities get a sensible default identity without manual
// setup.  Called from HOMEOpen when rw=YES and config is absent.
// Best-effort — silent on any failure.
static void home_bootstrap_config(home *h) {
    if (!h->rw) return;

    a_pad(u8, emailbuf, 256);
    a_pad(u8, namebuf,  256);
    u8s email = {emailbuf[0], emailbuf[3]};
    u8s name  = {namebuf[0],  namebuf[3]};
    u8cp email_start = email[0];
    u8cp name_start  = name[0];
    b8 got_email = (home_git_config_get("user.email", email) == OK);
    b8 got_name  = (home_git_config_get("user.name",  name)  == OK);
    if (!got_email && !got_name) return;

    a_path(dotdogs);
    a_dup(u8c, root_s, u8bDataC(h->root));
    if (PATHu8bFeed(dotdogs, root_s) != OK) return;
    a_cstr(dd, ".dogs");
    if (PATHu8bPush(dotdogs, dd) != OK) return;
    if (FILEMakeDirP($path(dotdogs)) != OK) return;

    a_path(cfgp);
    a_dup(u8c, dd_s, u8bDataC(dotdogs));
    if (PATHu8bFeed(cfgp, dd_s) != OK) return;
    a_cstr(cfg_name, "config");
    if (PATHu8bPush(cfgp, cfg_name) != OK) return;

    a_pad(u8, body, 1024);
    a_cstr(hdr, "[user]\n");
    u8bFeed(body, hdr);
    if (got_name) {
        a_cstr(key, "name = \"");
        a_cstr(eol, "\"\n");
        u8cs v = {name_start, name[0]};
        u8bFeed(body, key);
        u8bFeed(body, v);
        u8bFeed(body, eol);
    }
    if (got_email) {
        a_cstr(key, "email = \"");
        a_cstr(eol, "\"\n");
        u8cs v = {email_start, email[0]};
        u8bFeed(body, key);
        u8bFeed(body, v);
        u8bFeed(body, eol);
    }

    int fd = -1;
    if (FILECreate(&fd, $path(cfgp)) != OK) return;
    u8cs data = {u8bDataHead(body), u8bIdleHead(body)};
    FILEFeedAll(fd, data);
    FILEClose(&fd);
}

ok64 HOMEOpen(home *h, uricp at, b8 rw) {
    sane(h != NULL);
    zerop(h);
    h->rw = rw;

    // 0. Branch-sharding scaffolding: interning buffer + open-branch
    // slice stack.  Empty until the first HOMEOpenBranch call.
    call(u8bAllocate, h->branches_data, HOME_BRANCHES_DATA_SIZE);
    h->open_branches_count = 0;
    h->write_frozen = NO;

    // 1. Path buffers for wt and repo root, 1 KB each; tip buffers
    // for branch path (interning size) and sha (40-hex).
    call(u8bAllocate, h->root,       FILE_PATH_MAX_LEN);
    call(u8bAllocate, h->wt,         FILE_PATH_MAX_LEN);
    call(u8bAllocate, h->cur_branch, 256);
    call(u8bAllocate, h->cur_sha,    64);

    // 2. Resolve root: explicit URI path → feed; absent → HOMEFindDogs.
    u8cs at_path  = {};
    u8cs at_query = {};
    u8cs at_frag  = {};
    if (at != NULL) {
        u8csMv(at_path,  at->path);
        u8csMv(at_query, at->query);
        u8csMv(at_frag,  at->fragment);
    }
    if (!u8csEmpty(at_path)) {
        call(PATHu8bFeed, h->root, at_path);
    } else {
        call(HOMEFindDogs, h);
    }
    //  wt: where `.sniff` lives.
    //    * URI carries query OR fragment → call came from `be`'s
    //      `--at <root>?<branch>#<sha>` forward; the wt is the
    //      *subprocess cwd*, which may differ from `root` (secondary
    //      worktree symlinking into a primary's `.dogs/`).
    //    * URI path only (test fixture / HOMEOpenAt shim) or empty
    //      (cwd-walk) → wt == root, the colocated default.
    if (!u8csEmpty(at_query) || !u8csEmpty(at_frag)) {
        a_path(cwdp);
        if (FILEGetCwd(cwdp) == OK) {
            a_dup(u8c, cwd_s, u8bDataC(cwdp));
            call(PATHu8bFeed, h->wt, cwd_s);
        } else {
            a_dup(u8c, r, u8bDataC(h->root));
            call(PATHu8bFeed, h->wt, r);
        }
    } else {
        a_dup(u8c, r, u8bDataC(h->root));
        call(PATHu8bFeed, h->wt, r);
    }

    // 3. Scratch arena — 4 GB VA, pages on demand.
    call(u8bMap, h->arena, HOME_ARENA_SIZE);

    // 4. Config mmap (best-effort).  Missing file is not an error.
    a_path(cfg);
    a_dup(u8c, root_s, u8bDataC(h->root));
    call(PATHu8bFeed, cfg, root_s);
    a_cstr(rel, ".dogs/config");
    ok64 po = PATHu8bAdd(cfg, rel);
    if (po == OK) {
        u8bp mapped = NULL;
        if (FILEMapRO(&mapped, $path(cfg)) != OK && rw) {
            // Fresh clone: seed from git's global config, then retry.
            home_bootstrap_config(h);
            FILEMapRO(&mapped, $path(cfg));
        }
        if (mapped != NULL) {
            for (int i = 0; i < 4; i++)
                ((u8 **)h->config)[i] = mapped[i];
        }
    }

    // 5. Tip from URI: query → cur_branch + claim slot 0 via
    //    HOMEOpenBranch; fragment → cur_sha.  Trunk maps to the
    //    canonical empty branch — feed an empty slice when query is
    //    absent so HOMEOpenBranch's normalizer claims slot 0 anyway.
    //    No tip yet (fresh clone, direct sub-dog without --at) →
    //    leave both buffers empty and skip the branch claim.
    if (!u8csEmpty(at_query) || !u8csEmpty(at_frag)) {
        u8bFeed(h->cur_branch, at_query);
        if (!u8csEmpty(at_frag)) u8bFeed(h->cur_sha, at_frag);
        a_dup(u8c, br, u8bDataC(h->cur_branch));
        ok64 bo = HOMEOpenBranch(h, br, rw);
        if (bo != OK && bo != HOMEOPEN) return bo;
    }
    done;
}

ok64 HOMEClose(home *h) {
    sane(h != NULL);
    if (h->config[0]        != NULL) FILEUnMap(h->config);
    if (h->arena[0]         != NULL) u8bUnMap(h->arena);
    if (h->root[0]          != NULL) u8bFree(h->root);
    if (h->wt[0]            != NULL) u8bFree(h->wt);
    if (h->cur_branch[0]    != NULL) u8bFree(h->cur_branch);
    if (h->cur_sha[0]       != NULL) u8bFree(h->cur_sha);
    if (h->branches_data[0] != NULL) u8bFree(h->branches_data);
    zerop(h);
    done;
}

// --- Branch-sharding (Phase 0) ---

ok64 HOMEOpenBranch(home *h, u8cs branch, b8 rw) {
    sane(h != NULL && $ok(branch));

    // Normalize into a scratch buffer first so we can dedup without
    // polluting the interning store on a hit.
    a_pad(u8, normbuf, 256);
    call(DPATHBranchNormFeed, normbuf, branch);
    a_dup(u8c, norm, u8bDataC(normbuf));

    // Already open?
    for (size_t i = 0; i < h->open_branches_count; i++) {
        u8cs slot = {h->open_branches[i][0], h->open_branches[i][1]};
        if (u8csEq(slot, norm)) {
            if (rw && (i != 0 || !h->write_frozen))
                return HOMEROBR;
            return HOMEOPEN;
        }
    }

    size_t before_n = h->open_branches_count;

    // rw is only grantable on the very first open.
    if (rw && before_n > 0) return HOMEROBR;

    // Capacity checks: slot array + interning buffer.
    if (before_n >= HOME_OPEN_BRANCHES_MAX) return HOMEMAX;
    if (u8csLen(norm) > u8bIdleLen(h->branches_data))
        return HOMEMAX;

    // Intern the canonical bytes and append the resulting slice.
    u8cp at = u8bIdleHead(h->branches_data);
    call(u8bFeed, h->branches_data, norm);
    h->open_branches[before_n][0] = at;
    h->open_branches[before_n][1] = u8bIdleHead(h->branches_data);
    h->open_branches_count = before_n + 1;

    if (before_n == 0 && rw) h->write_frozen = YES;
    done;
}

ok64 HOMEWriteBranch(home const *h, u8cs out) {
    sane(h != NULL);
    if (!h->write_frozen || h->open_branches_count == 0)
        return HOMENOBR;
    out[0] = h->open_branches[0][0];
    out[1] = h->open_branches[0][1];
    done;
}

b8 HOMEBranchVisible(home const *h, u8cs branch) {
    for (size_t i = 0; i < h->open_branches_count; i++) {
        u8cs slot = {h->open_branches[i][0], h->open_branches[i][1]};
        if (DPATHBranchAncestor(branch, slot)) return YES;
    }
    return NO;
}

// --- Workspace finders ---

// Walk up from cwd to the first dir that looks like a sniff/keeper
// anchor: either a `.sniff` regular file (a worktree) or a `.dogs`
// subdirectory (the colocated store).  Fills h->root with the found
// path.  Returns NOHOME if the walk reaches / without finding either.
static ok64 home_walk_up(home *h) {
    sane(h != NULL);

    u8bReset(h->root);
    char cwdbuf[FILE_PATH_MAX_LEN];
    test(getcwd(cwdbuf, sizeof(cwdbuf)) != NULL, NOHOME);
    u8cs cwds = {(u8cp)cwdbuf, (u8cp)cwdbuf + strlen(cwdbuf)};
    call(PATHu8bFeed, h->root, cwds);

    a_cstr(dotsniff, ".sniff");
    a_cstr(dotdogs,  ".dogs");
    for (;;) {
        struct stat sb = {};
        {
            a_path(probe);
            a_dup(u8c, cur, u8bDataC(h->root));
            call(PATHu8bFeed, probe, cur);
            call(PATHu8bPush, probe, dotsniff);
            if (stat((char const *)*$path(probe), &sb) == 0 &&
                (sb.st_mode & S_IFREG)) {
                done;
            }
        }
        {
            a_path(probe);
            a_dup(u8c, cur, u8bDataC(h->root));
            call(PATHu8bFeed, probe, cur);
            call(PATHu8bPush, probe, dotdogs);
            if (stat((char const *)*$path(probe), &sb) == 0 &&
                (sb.st_mode & S_IFDIR)) {
                done;
            }
        }

        size_t before = $len(u8bDataC(h->root));
        call(PATHu8bPop, h->root);
        size_t after = $len(u8bDataC(h->root));
        if (after >= before) return NOHOME;
    }
}

ok64 HOMEFind(home *h) {
    sane(h != NULL);
    return home_walk_up(h);
}

ok64 HOMEFindDogs(home *h) {
    sane(h != NULL);
    return home_walk_up(h);
}

// --- Resolve sibling binary ---

static b8 home_is_exe(path8s p) {
    struct stat sb;
    if (FILEStat(&sb, p) != OK) return NO;
    return (sb.st_mode & S_IXUSR) ? YES : NO;
}

// If <dir>/<name> is executable, feed its full path into `out`.
static ok64 home_try_sibling(path8b out, u8csc dir, u8csc name) {
    sane(out != NULL && $ok(dir) && $ok(name));
    a_path(tmp);
    a_dup(u8c, dir_s, dir);
    a_dup(u8c, name_s, name);
    call(PATHu8bFeed, tmp, dir_s);
    call(PATHu8bPush, tmp, name_s);
    if (!home_is_exe($path(tmp))) return NONE;
    a_dup(u8c, src, u8bDataC(tmp));
    call(PATHu8bFeed, out, src);
    done;
}

ok64 HOMEResolveSibling(home *h, path8b out, u8csc name, u8csc argv0) {
    sane(out != NULL && $ok(name));
    (void)h;   // unused — sibling lookup is ambient (argv0 + PATH)

    if ($ok(argv0) && !u8csEmpty(argv0)) {
        // "Has a directory" means argv0 literally contains '/'.
        // PATHu8sDir synthesizes "." for bare names; that's the PATH
        // case, not the dirname case.
        a_dup(u8c, a0_scan, argv0);
        b8 has_slash = u8csFind(a0_scan, '/') == OK;
        if (has_slash) {
            a_dup(u8c, a0, argv0);
            u8cs dir = {};
            PATHu8sDir(dir, a0);
            u8csc dir_c = {dir[0], dir[1]};
            if (home_try_sibling(out, dir_c, name) == OK) done;
        } else {
            // Bare argv0 → scan PATH for it, then look beside it.
            char const *env = getenv("PATH");
            if (env != NULL) {
                a_cstr(env_s, env);
                a_dup(u8c, scan, env_s);
                while (!u8csEmpty(scan)) {
                    u8cs entry = {scan[0], scan[1]};
                    a_dup(u8c, probe, scan);
                    if (u8csFind(probe, ':') == OK) {
                        //  u8csFind advances probe[0] *to* the ':'.
                        //  entry is half-open [scan_start, colon);
                        //  advance scan past the ':' for next iter.
                        entry[1] = probe[0];
                        scan[0]  = probe[0] + 1;
                    } else {
                        scan[0]  = scan[1];
                    }
                    if (u8csEmpty(entry)) continue;

                    a_path(exe);
                    u8csc entry_c = {entry[0], entry[1]};
                    a_dup(u8c, a0_s, argv0);
                    if (PATHu8bFeed(exe, entry)   != OK) continue;
                    if (PATHu8bPush(exe, a0_s)    != OK) continue;
                    if (!home_is_exe($path(exe))) continue;
                    if (home_try_sibling(out, entry_c, name) == OK) done;
                    break;
                }
            }
        }
    }

    // Fallback: feed just `name` — caller can still hand it to execvp.
    a_dup(u8c, name_s, name);
    call(PATHu8bFeed, out, name_s);
    done;
}

// --- Config: .dogs/config (TOML) ---

// The TOML header `[a.b.c]` and dotted keys `a.b = "v"` both express the
// same dotted hierarchy.  We track the full active path in `current`
// (a path8b, segments joined by '/') and match it against `needle`
// supplied by the caller as a path8s.  On a match the cb feeds `out`
// and returns NODATA so TOMLTLexer `fbreak`s immediately.
typedef struct {
    path8s  needle;    // caller-supplied, e.g. $path(a_path(..,"a","b","c"))
    path8bp current;   // active dotted path, borrowed from caller (a_path)
    size_t  hdr_end;   // current's DATA length at end of last header
    u8s     out;
    u8      in_hdr;    // 1 between '[' and ']'
    u8      await_val; // 1 after '=' — next string is the value
} home_cfg_ctx;

static ok64 home_cfg_cb(u8 tag, u8cs tok, void *ctx) {
    sane(ctx != NULL);
    home_cfg_ctx *c = (home_cfg_ctx *)ctx;
    if (tag == 'D') return OK;   // comment

    // Whitespace with a newline closes a kv line; rewind `current`
    // back to the header root so the next line starts fresh.
    if (tag == 'W') {
        b8 nl = NO;
        for (u8cp p = tok[0]; p < tok[1]; p++)
            if (*p == '\n') { nl = YES; break; }
        if (nl && !c->in_hdr) {
            size_t dl = u8bDataLen(c->current);
            if (dl > c->hdr_end) u8bShed(c->current, dl - c->hdr_end);
            c->await_val = 0;
        }
        return OK;
    }

    // Header framing
    if ($len(tok) == 1 && tok[0][0] == '[') {
        c->in_hdr = 1;
        u8bReset(c->current);
        return OK;
    }
    if ($len(tok) == 1 && tok[0][0] == ']') {
        c->in_hdr = 0;
        c->hdr_end = u8bDataLen(c->current);
        return OK;
    }

    // Dotted separator between segments (inside or outside a header).
    // TOMLT tags it 'P' outside headers and 'R' inside (TOKSplitText).
    if ($len(tok) == 1 && tok[0][0] == '.')
        return OK;

    // '='
    if (tag == 'P' && $len(tok) == 1 && tok[0][0] == '=') {
        c->await_val = 1;
        return OK;
    }

    // Identifier: extends the active path (in header or building a key).
    if ((tag == 'S' || tag == 'R') && !c->await_val) {
        PATHu8bPush(c->current, tok);
        return OK;
    }

    // Quoted string value — match → feed, then NODATA to stop the lexer.
    if (c->await_val && tag == 'G' && $len(tok) >= 2) {
        a_dup(u8c, cu, u8bDataC(c->current));
        if ($eq(c->needle, cu)) {
            u8cs val = {tok[0] + 1, tok[1] - 1};
            call(u8sFeed, c->out, val);
            return NODATA;
        }
        return OK;
    }

    return OK;
}

ok64 HOMEHost(home *h, u8s out) {
    sane(h != NULL && $ok(out));
    a_cstr(user_s, "user");
    a_cstr(host_s, "host");
    a_cstr(mail_s, "email");
    a_path(needle, user_s, host_s);
    ok64 o = HOMEGetConfig(h, out, $path(needle));
    if (o == OK) done;
    if (o != NOCONF) return o;
    a_path(email, user_s, mail_s);
    return HOMEGetConfig(h, out, $path(email));
}

ok64 HOMEGetConfig(home *h, u8s value, path8s needle) {
    sane(h != NULL && $ok(value) && $ok(needle));

    if (h->config[0] == NULL) return NOCONF;

    a_path(current);
    home_cfg_ctx ctx = {
        .needle  = {needle[0], needle[1]},
        .current = current,
        .out     = {value[0], value[1]},
    };
    TOMLTstate st = {
        .data = {u8bDataHead(h->config), u8bIdleHead(h->config)},
        .cb   = home_cfg_cb,
        .ctx  = &ctx,
    };
    ok64 lo = TOMLTLexer(&st);
    if (lo != OK && lo != NODATA) return lo;
    if (ctx.out[0] == value[0]) return NOCONF;   // nothing fed
    value[0] = ctx.out[0];
    done;
}
