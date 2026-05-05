//  SPOTExec — run a parsed CLI against an open spot state.
//  Same effect as invoking `spot ...` as a separate process.
//
#include "CAPO.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "abc/FILE.h"
#include "abc/PATH.h"
#include "abc/PRO.h"
#include "dog/CLI.h"
#include "dog/DOG.h"
#include "dog/HOME.h"
#include "dog/HUNK.h"
#include "dog/SHA1.h"
#include "keeper/KEEP.h"
#include "keeper/REFS.h"
#include "keeper/WALK.h"
#include "spot/CAPOi.h"
#include "spot/LESS.h"

//  Per-session indexing stats — drained by SPOTClose.  Counts how
//  many blobs the tip-walker tokenised vs skipped via the BLOBFN memo.
u64 SPOT_DBG_TOKENISED     = 0;
u64 SPOT_DBG_MEMO_HIT      = 0;
u64 SPOT_DBG_BLOB_NO_EXT   = 0;

// --- Verb / flag tables ---

char const *const SPOT_CLI_VERBS[] = {
    "get", "status", "help", NULL
};

//  Spot val-flags: -g -s -r -p -C --grep --spot --replace --pcre --context
//  `spot get URI` walks the URI's tip(s) over keeper's read APIs and
//  tokenises every leaf blob whose (blob, path) pair isn't already
//  in the BLOBFN memo (DOG.md §10a).
char const SPOT_CLI_VAL_FLAGS[] =
    "-g\0-s\0-r\0-p\0-C\0"
    "--grep\0--spot\0--replace\0--pcre\0--context\0--at\0";

// --- Helpers ---

static void spot_usage(void) {
    fprintf(stderr,
        "Usage: spot [--flags] [URI...]\n"
        "\n"
        "  spot status                        index stack summary\n"
        "  spot -s \"pattern\" .ext             code snippet search\n"
        "  spot -s \"pat\" -r \"repl\" .ext       code snippet search + replace\n"
        "  spot -g \"text\" [.ext]              grep (substring)\n"
        "  spot -p \"regex\" [.ext]             regex grep\n"
        "  spot '#pattern.ext'                URI-style search\n"
        "\n"
        "Patterns: single-letter placeholders (a-z match one token/group,\n"
        "A-Z match multiple tokens). Two spaces = skip gap.\n"
        "\n"
        "Indexing is driven by keeper (pack ingest) — no spot CLI flags.\n"
        "Diff/merge tools live in graf — see `graf --help`.\n"
    );
}

static b8 argIsExt(u8csc a) {
    if ($len(a) < 2 || a[0][0] != '.') return NO;
    return CAPOKnownExt(a);
}

// --- Entry ---

ok64 SPOTExec(cli *c) {
    sane(c);
    spotp dog = &SPOT;

    if (getenv("SPOT_COLOR")) { dog->color = YES; CAPO_COLOR = YES; }

    a_dup(u8c, reporoot, u8bDataC(dog->h->root));

    u8cs v = {};

    if (CLIHas(c, "-h") || CLIHas(c, "--help")) {
        spot_usage(); done;
    }

    a_cstr(v_get, "get");
    a_cstr(v_status_verb, "status");
    a_cstr(v_help_verb, "help");

    if ($eq(c->verb, v_help_verb)) { spot_usage(); done; }
    if ($eq(c->verb, v_status_verb)) {
        a_path(capodir);
        CAPOResolveDir(capodir, reporoot);
        a_dup(u8c, dirslice, u8bDataC(capodir));
        u64cs runs[CAPO_MAX_LEVELS] = {};
        u64css stack = {runs, runs};
        u8bp mmaps[CAPO_MAX_LEVELS] = {};
        u32 nidxfiles = 0;
        CAPOStackOpen(stack, mmaps, &nidxfiles, dirslice);
        u64 total = 0;
        for (u32 i = 0; i < nidxfiles; i++)
            total += (u64)$len(runs[i]);
        CAPOStackClose(mmaps, nidxfiles);
        fprintf(stderr, "spot: %u index files, %llu entries\n",
                nidxfiles, (unsigned long long)total);
        done;
    }
    //  `spot get URI` — invoked by `be` in parallel with keeper/graf/
    //  sniff after keeper finishes its own update (DOG.md §10a).
    //  Walks the URI's tip(s) over keeper's read APIs and tokenises
    //  every leaf blob whose (blob, path) pair isn't already in the
    //  BLOBFN memo.  Bare `spot get` (no URI) walks the worktree's
    //  current tip via `--at`'s fragment.
    if ($eq(c->verb, v_get)) {
        uri empty = {};
        uri *u = (c->nuris > 0) ? &c->uris[0] : &empty;
        call(KEEPOpen, dog->h, NO);
        ok64 igr = SPOTIndexFromTips(&KEEP, u);
        KEEPClose();
        return igr;
    }

    b8 do_status = CLIHas(c, "--status");
    b8 force_tlv = CLIHas(c, "-t") || CLIHas(c, "--tlv");

    u32 grep_ctx = 3;
    CLIFlag(v, c, "-C");
    if (!$empty(v)) grep_ctx = (u32)atoi((char *)v[0]);
    CLIFlag(v, c, "--context");
    if (!$empty(v)) grep_ctx = (u32)atoi((char *)v[0]);

    u8cs spot_ndl = {}, spot_rep = {}, grep_ndl = {}, pcre_ndl = {};
    CLIFlag(v, c, "-s");
    if (!$empty(v)) { $mv(spot_ndl, v); }
    CLIFlag(v, c, "--spot");
    if (!$empty(v)) { $mv(spot_ndl, v); }
    CLIFlag(v, c, "-r");
    if (!$empty(v)) { $mv(spot_rep, v); }
    CLIFlag(v, c, "--replace");
    if (!$empty(v)) { $mv(spot_rep, v); }
    CLIFlag(v, c, "-g");
    if (!$empty(v)) { $mv(grep_ndl, v); }
    CLIFlag(v, c, "--grep");
    if (!$empty(v)) { $mv(grep_ndl, v); }
    CLIFlag(v, c, "-p");
    if (!$empty(v)) { $mv(pcre_ndl, v); }
    CLIFlag(v, c, "--pcre");
    if (!$empty(v)) { $mv(pcre_ndl, v); }

    //  Projector dispatch (VERBS.md §"View projectors"):
    //    be spot:#body[.ext]   structural search
    //    be grep:#body[.ext]   literal grep
    //    be regex:#body[.ext]  PCRE
    //  Scheme picks the backend; the URI fragment carries the search
    //  body (URI subresource semantics).  Path stays available for
    //  file/dir narrowing (e.g. `grep:src/#body`).  A trailing `.ext`
    //  on the fragment splits off as an extension filter
    //  (`spot:#'body'.c`).  Surrounding `'…'` quotes around the body
    //  are stripped so shell quoting doesn't leak in.
    u8cs proj_ext = {};
    b8 proj_search_uri0 = NO;
    if ($empty(c->verb) && c->nuris > 0) {
        uri *pu = &c->uris[0];
        a_cstr(s_spot,  "spot");
        a_cstr(s_grep,  "grep");
        a_cstr(s_regex, "regex");
        b8 is_search_proj = $eq(pu->scheme, s_spot)
                         || $eq(pu->scheme, s_grep)
                         || $eq(pu->scheme, s_regex);
        if (is_search_proj) proj_search_uri0 = YES;
        if (is_search_proj && !$empty(pu->fragment)) {
            u8cs body = {pu->fragment[0], pu->fragment[1]};

            //  Path-side `.ext` (e.g. `spot:.c#u8sFeed`) — when the
            //  whole path is just `.<ext-chars>`, treat it as the
            //  extension filter and clear the path slot so it doesn't
            //  also get used as a file-narrowing constraint below.
            if (!$empty(pu->path)) {
                u8cs p = {pu->path[0], pu->path[1]};
                b8 path_is_ext = ($len(p) >= 2) && (p[0][0] == '.');
                for (u8cp q = p[0] + 1; path_is_ext && q < p[1]; q++) {
                    u8 ch = *q;
                    if (!((ch >= 'a' && ch <= 'z') ||
                          (ch >= 'A' && ch <= 'Z') ||
                          (ch >= '0' && ch <= '9'))) {
                        path_is_ext = NO;
                    }
                }
                if (path_is_ext) {
                    $mv(proj_ext, p);
                    pu->path[0] = pu->path[1] = NULL;
                }
            }

            //  Trailing `.ext` on the fragment (e.g. `'body'.c`) —
            //  split body off ext.  Skipped if the path slot already
            //  carries the ext.  Scan from the end for a `.` followed
            //  by ext-legal chars.
            if ($empty(proj_ext)) {
                u8cp dot = NULL;
                for (u8cp p = body[1]; p > body[0]; ) {
                    p--;
                    u8 ch = *p;
                    if (ch == '.') { dot = p; break; }
                    if (!((ch >= 'a' && ch <= 'z') ||
                          (ch >= 'A' && ch <= 'Z') ||
                          (ch >= '0' && ch <= '9'))) break;
                }
                if (dot != NULL && dot > body[0] && dot < body[1] - 1) {
                    proj_ext[0] = dot;
                    proj_ext[1] = body[1];
                    body[1]     = dot;
                }
            }
            //  Strip a single pair of surrounding `'…'` from the body.
            if ($len(body) >= 2 && body[0][0] == '\'' &&
                body[1][-1] == '\'') {
                body[0]++; body[1]--;
            }
            if ($eq(pu->scheme, s_spot)) {
                $mv(spot_ndl, body);
            } else if ($eq(pu->scheme, s_grep)) {
                $mv(grep_ndl, body);
            } else {
                $mv(pcre_ndl, body);
            }
            //  Fragment consumed; clear so the trailing-args loop
            //  doesn't reprocess it.  Path is left intact — it stays
            //  available as a file/dir narrowing constraint.
            pu->fragment[0] = pu->fragment[1] = NULL;
        }
    }

    u8cs trail[16] = {};
    int ntrail = 0;
    if (!$empty(proj_ext)) { $mv(trail[ntrail], proj_ext); ntrail++; }
    uri const *ref_uri = NULL;   // first URI with a real `?ref` query
    for (u32 ui = 0; ui < c->nuris && ntrail < 16; ui++) {
        uri *u = &c->uris[ui];
        //  Projector consumed the fragment.  Path stays for narrowing
        //  (e.g. `spot:/graf?feat#sym` ⇒ search `sym` under `/graf` on
        //  branch `feat`); the loop below picks it up via u->path.
        //  URILexer can classify a leading-dot arg like `.c` as the
        //  "query" component even without a `?`.  A real ref URI has an
        //  explicit `?` in its input text — require that for has_ref.
        //  URILexer can classify a leading-dot arg like `.c` as the
        //  "query" component even without a `?`.  A real ref URI has an
        //  explicit `?` in its input text — require that for has_ref.
        b8 has_ref = NO;
        if (!u8csEmpty(u->query) && !u8csEmpty(u->data)) {
            for (u8cp p = u->data[0]; p < u->data[1]; p++) {
                if (*p == '?') { has_ref = YES; break; }
            }
        }
        if (has_ref && ref_uri == NULL) ref_uri = u;
        //  Path is a file/dir narrowing constraint.  Skip it only when
        //  the URI carries an authority (`//host/repo?ref`) where the
        //  path is the *remote* repo location, not a local subtree.
        b8 remote = !$empty(u->authority);
        //  Search-projector URIs already had their fragment consumed
        //  above; don't let their full data string ("grep:#body") leak
        //  into trail[] as a bogus file filter.  Path stays valid.
        b8 is_search_uri = (ui == 0 && proj_search_uri0);
        if (!remote) {
            u8cs dat = {};
            if (!$empty(u->path)) {
                $mv(dat, u->path);
            } else if (!has_ref && !is_search_uri && !$empty(u->data)) {
                //  No structured slot set — fall back to raw arg
                //  (e.g. a bare `.c` ext token written without `?`/`#`).
                $mv(dat, u->data);
            }
            if (!$empty(dat) && ntrail < 16) {
                $mv(trail[ntrail], dat);
                ntrail++;
            }
        }
    }

    if (!$empty(spot_rep) && $empty(spot_ndl)) {
        fprintf(stderr, "spot: --replace requires --spot\n");
        return FAILSANITY;
    }

    pid_t bro_pid = -1;
    b8 produces_hunks =
        (!$empty(grep_ndl) || !$empty(pcre_ndl) || !$empty(spot_ndl)) &&
        $empty(spot_rep);
    if (produces_hunks) {
        if (force_tlv) {
            spot_out_fd = STDOUT_FILENO;
            spot_emit   = HUNKu8sFeed;
            signal(SIGPIPE, SIG_IGN);
        } else if (c->tty_out) {
            a_path(bropath);
            a$rg(a0, 0);
            a_cstr(bro_name, "bro");
            HOMEResolveSibling(NULL, bropath, bro_name, a0);
            u8cs bargs[] = {u8slit("bro")};
            u8css bargv = {bargs, bargs + 1};
            int wfd = -1;
            call(FILESpawn, $path(bropath), bargv, &wfd, NULL, &bro_pid);
            dog->out_fd = wfd;
            dog->emit   = HUNKu8sFeed;
            spot_out_fd = dog->out_fd;
            spot_emit   = dog->emit;
            signal(SIGPIPE, SIG_IGN);
        } else {
            dog->out_fd = STDOUT_FILENO;
            dog->emit   = HUNKu8sFeedText;
            spot_out_fd = dog->out_fd;
            spot_emit   = dog->emit;
        }
    }

    ok64 ret = OK;

    if (do_status) {
        a_path(capodir);
        vcall("resolve_dir", CAPOResolveDir, capodir, reporoot);
        a_dup(u8c, dirslice, u8bDataC(capodir));
        u64cs runs[CAPO_MAX_LEVELS] = {};
        u64css stack = {runs, runs};
        u8bp mmaps[CAPO_MAX_LEVELS] = {};
        u32 nidxfiles = 0;
        vcall("stack_open", CAPOStackOpen, stack, mmaps, &nidxfiles, dirslice);
        u64 total = 0;
        for (u32 i = 0; i < nidxfiles; i++)
            total += (u64)$len(runs[i]);
        CAPOStackClose(mmaps, nidxfiles);
        fprintf(stderr, "spot: %u index files, %llu entries\n",
                nidxfiles, (unsigned long long)total);
    } else if (!$empty(grep_ndl)) {
        u8cs ext = {};
        u8cs gfiles[16] = {};
        int gnf = 0;
        for (int i = 0; i < ntrail; i++) {
            if (argIsExt(trail[i])) {
                $mv(ext, trail[i]);
            } else if (gnf < 16) {
                $mv(gfiles[gnf], trail[i]);
                gnf++;
            }
        }
        if ($empty(ext) && gnf > 0) {
            u8cs pe = {};
            PATHu8sExt(pe, gfiles[0]);
            if (!$empty(pe)) {
                ext[0] = pe[0] - 1;
                ext[1] = pe[1];
            }
        }
        a_dup(u8c, ndl, grep_ndl);
        u8css gf = {gfiles, gfiles + gnf};
        ret = CAPOGrep(ndl, ext, reporoot, grep_ctx, gf, ref_uri);
    } else if (!$empty(pcre_ndl)) {
        u8cs ext = {};
        u8cs gfiles[16] = {};
        int gnf = 0;
        for (int i = 0; i < ntrail; i++) {
            if (argIsExt(trail[i])) {
                $mv(ext, trail[i]);
            } else if (gnf < 16) {
                $mv(gfiles[gnf], trail[i]);
                gnf++;
            }
        }
        if ($empty(ext) && gnf > 0) {
            u8cs pe = {};
            PATHu8sExt(pe, gfiles[0]);
            if (!$empty(pe)) {
                ext[0] = pe[0] - 1;
                ext[1] = pe[1];
            }
        }
        a_dup(u8c, ndl, pcre_ndl);
        u8css gf = {gfiles, gfiles + gnf};
        ret = CAPOPcreGrep(ndl, ext, reporoot, grep_ctx, gf, ref_uri);
    } else if (!$empty(spot_ndl)) {
        u8cs ext = {};
        u8cs sfiles[16] = {};
        int snf = 0;
        for (int i = 0; i < ntrail; i++) {
            if (argIsExt(trail[i])) {
                $mv(ext, trail[i]);
            } else if (snf < 16) {
                $mv(sfiles[snf], trail[i]);
                snf++;
            }
        }
        if ($empty(ext) && snf > 0) {
            u8cs pe = {};
            PATHu8sExt(pe, sfiles[0]);
            if (!$empty(pe)) {
                ext[0] = pe[0] - 1;
                ext[1] = pe[1];
            }
        }
        if ($empty(ext)) {
            fprintf(stderr, "spot: --spot requires a .ext argument\n");
            ret = FAILSANITY;
        } else {
            a_dup(u8c, ndl, spot_ndl);
            a_dup(u8c, rep, spot_rep);
            u8css sf = {sfiles, sfiles + snf};
            ret = CAPOSpot(ndl, rep, ext, reporoot, sf, ref_uri);
        }
    } else if (c->nuris > 0) {
        //  A search projector with no body (e.g. `spot:`, `spot:#name`)
        //  is the most likely cause — body belongs in the URI path slot,
        //  not the fragment.  Catch that case with a targeted hint.
        uri *u0 = &c->uris[0];
        a_cstr(s_spot,  "spot");
        a_cstr(s_grep,  "grep");
        a_cstr(s_regex, "regex");
        b8 is_search = $eq(u0->scheme, s_spot)
                    || $eq(u0->scheme, s_grep)
                    || $eq(u0->scheme, s_regex);
        if (is_search) {
            //  Body lives in the fragment slot (`spot:#body`); a search
            //  URI with only a path (`spot:body`) means the user put the
            //  body in the wrong slot — point them at the right shape.
            if (!$empty(u0->path)) {
                u8cs path = {u0->path[0], u0->path[1]};
                if (!$empty(path) && *path[0] == '/') u8csFed(path, 1);
                fprintf(stderr,
                    "spot: search body goes in the URI fragment, not "
                    "the path\n  try: %.*s:#%.*s\n",
                    (int)$len(u0->scheme), (char *)u0->scheme[0],
                    (int)$len(path), (char *)path[0]);
            } else {
                fprintf(stderr,
                    "spot: %.*s: needs a search body\n  try: "
                    "%.*s:#<body>\n",
                    (int)$len(u0->scheme), (char *)u0->scheme[0],
                    (int)$len(u0->scheme), (char *)u0->scheme[0]);
            }
        } else {
            fprintf(stderr, "spot: file display moved to bro\n");
        }
        ret = FAILSANITY;
    } else {
        spot_usage();
    }

    // Cleanup bro pipe (globals)
    if (spot_out_fd >= 0 && spot_out_fd != STDOUT_FILENO) {
        close(spot_out_fd);
        spot_out_fd = -1;
    }
    if (bro_pid > 0) {
        int rc = 0;
        FILEReap(bro_pid, &rc);
        if (rc == 127)
            fprintf(stderr, "spot: bro pager not found\n");
    }

    return ret;
}

// --- Tip-walk indexer (DOG.md §10a, called from `spot get URI`) ---
//
// Walks the URI's tip(s) over keeper's read APIs (KEEPLsFiles).  For
// each leaf blob with a tokenizable extension, looks up the BLOBFN
// memo (`off=blob_hl40, type=BLOBFN, id=path_h20`); a hit means we
// already indexed this exact (blob, path) pair on a prior walk —
// skip both tokenisation and emission.  Otherwise pull the blob via
// KEEPGetExact, tokenise it via CAPOIndexBlob with the path hash as
// the posting `id`, and write a fresh BLOBFN row so the next walk
// can short-circuit.
//
// Renames are caught by the path-hash key: same blob + new path =
// different path_h20 = no memo hit = re-tokenise under the new path.

#include "abc/RAP.h"

// Append `ext` to s->ext_arena if not already present; return its
// offset (>= 1).  Offset 0 is reserved as a sentinel "missing".
// Linear scan over an arena that holds ~50 distinct exts in practice.
static u32 capo_ext_intern(spot *s, u8cs ext) {
    if ($empty(ext)) return 0;
    u8cp base = u8bDataHead(s->ext_arena);
    u8cp idle = u8bIdleHead(s->ext_arena);
    size_t want = (size_t)$len(ext);
    for (u8cp p = base + 1; p < idle; ) {
        u8cp end = p;
        while (end < idle && *end != 0) end++;
        if ((size_t)(end - p) == want &&
            memcmp(p, ext[0], want) == 0)
            return (u32)(p - base);
        p = end + 1;
    }
    if (u8bIdleLen(s->ext_arena) < want + 1) return 0;
    u32 off = (u32)u8bDataLen(s->ext_arena);
    u8bFeed(s->ext_arena, ext);
    u8bFeed1(s->ext_arena, 0);
    return off;
}

//  YES iff a row `(off=blob_hl40, type=BLOBFN, id=path_h20)` already
//  exists in any open run.  Pure binary search on the natural u64
//  layout — no allocation.
static b8 spot_memo_hit(u64css runs, u64 blob_hl40, u32 path_h20) {
    u64 want = wh64Pack(SPOT_BLOBFN, path_h20, blob_hl40);
    a_dup(u64cs, scan, runs);
    $for(u64cs, run, scan) {
        u64cp base = (*run)[0];
        size_t len = (size_t)((*run)[1] - base);
        size_t lo = 0, hi = len;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            if (base[mid] < want) lo = mid + 1;
            else hi = mid;
        }
        if (lo < len && base[lo] == want) return YES;
    }
    return NO;
}

typedef struct {
    spot   *s;
    keeper *k;
    u64css  runs;       // pre-opened LSM stack for memo lookups
} spot_walk_ctx;

static ok64 spot_walk_visit(u8cs path, u8 kind, u8cp esha,
                            u8cs blob, void0p ctx) {
    (void)blob;       // KEEPLsFiles uses lazy mode — blob is empty
    spot_walk_ctx *cx = (spot_walk_ctx *)ctx;
    if (kind != WALK_KIND_REG && kind != WALK_KIND_EXE &&
        kind != WALK_KIND_LNK) return OK;
    if ($empty(path)) return OK;

    u8cs ext = {};
    PATHu8sExt(ext, path);
    if ($empty(ext) || !CAPOKnownExt(ext)) {
        SPOT_DBG_BLOB_NO_EXT++;
        return OK;
    }

    sha1 bsha = {};
    memcpy(bsha.data, esha, 20);
    u64 blob_hl40 = WHIFFHashlet40(&bsha);
    u32 path_h20  = CAPOFnRap20(path);

    //  Memo: same (blob, path) on a prior walk → nothing to do.
    if (spot_memo_hit(cx->runs, blob_hl40, path_h20)) {
        SPOT_DBG_MEMO_HIT++;
        return OK;
    }

    u32 ext_off = capo_ext_intern(cx->s, ext);
    if (ext_off == 0) return OK;

    Bu8 bbuf = {};
    if (u8bAllocate(bbuf, 1UL << 22) != OK) return OK;
    u8 btype = 0;
    ok64 gr = KEEPGetExact(cx->k, &bsha, bbuf, &btype);
    if (gr != OK || btype != DOG_OBJ_BLOB) {
        u8bFree(bbuf);
        return OK;
    }
    u8cs source = {u8bDataHead(bbuf), u8bIdleHead(bbuf)};

    (void)CAPOIndexBlob(source, ext, path_h20);
    SPOT_DBG_TOKENISED++;

    //  Persist the (blob, path) row so the next walk can short-circuit.
    (void)CAPOEmit(wh64Pack(SPOT_BLOBFN, path_h20, blob_hl40));

    u8bFree(bbuf);
    return OK;
}

ok64 SPOTIndexFromTips(keeper *k, uricp u) {
    sane(k && u);
    spotp s = &SPOT;
    if (!s->rw) done;

    //  Snapshot the current LSM runs once — used as the per-blob
    //  memo lookup.  Postings emitted during this walk go through
    //  the BOX scratch and are not visible here; the walk's own
    //  visitor would have seen the prior path for any rename.
    a_path(capodir);
    a_dup(u8c, reporoot, u8bDataC(s->h->root));
    if (CAPOResolveDir(capodir, reporoot) != OK) done;
    a_dup(u8c, dirslice, u8bDataC(capodir));

    u64cs runs[CAPO_MAX_LEVELS] = {};
    u64css stack = {runs, runs};
    u8bp mmaps[CAPO_MAX_LEVELS] = {};
    u32 nidxfiles = 0;
    (void)CAPOStackOpen(stack, mmaps, &nidxfiles, dirslice);
    stack[1] = stack[0] + nidxfiles;

    spot_walk_ctx cx = {.s = s, .k = k};
    cx.runs[0] = stack[0];
    cx.runs[1] = stack[1];

    //  Promote a 40-hex query (`?<sha>`) or path (`<sha>`) to the
    //  fragment slot so KEEPResolveTree takes the direct-sha branch
    //  — its query path only resolves named refs / aliases.
    uri raw_probe = *u;
    u8cs hex_src = {};
    if (u8csEmpty(raw_probe.fragment) &&
        u8csLen(raw_probe.query) == 40) {
        $mv(hex_src, raw_probe.query);
    } else if (u8csEmpty(raw_probe.fragment) &&
               u8csEmpty(raw_probe.query) &&
               u8csLen(raw_probe.path) == 40) {
        $mv(hex_src, raw_probe.path);
    }
    if (!u8csEmpty(hex_src)) {
        b8 hex = YES;
        for (u8cp p = hex_src[0]; p < hex_src[1]; p++) {
            u8 ch = *p;
            b8 d = (ch >= '0' && ch <= '9');
            b8 l = (ch >= 'a' && ch <= 'f');
            b8 u_ = (ch >= 'A' && ch <= 'F');
            if (!(d || l || u_)) { hex = NO; break; }
        }
        if (hex) {
            raw_probe.fragment[0] = hex_src[0];
            raw_probe.fragment[1] = hex_src[1];
            raw_probe.query[0] = raw_probe.query[1] = NULL;
            raw_probe.path[0]  = raw_probe.path[1]  = NULL;
        }
    }
    u = &raw_probe;

    //  Pick a URI that KEEPLsFiles can resolve to a tip.  Strategy:
    //
    //    1. Caller URI has a fragment / non-empty query / path?ref
    //       shape that KEEPResolveTree handles → use it as-is.
    //    2. `--at` parked a 40-hex sha in `h->cur_sha` (BE forwards
    //       this) → synthesise `#<cur_sha>` so KEEPResolveTree takes
    //       the fragment branch.
    //    3. Try REFSResolve on the original URI's data slice — this
    //       picks up keeper's just-written `?#<sha>` trunk row after
    //       a fresh remote fetch (URI = `ssh://host/path`, query
    //       empty, but keeper has the resolved tip on file).
    //    4. Last resort: probe `?` as a trunk lookup (legacy shape
    //       sniff's GET also uses post-fetch).
    //
    //  Each fallback synthesises a `#<sha>` URI and dispatches to
    //  KEEPLsFiles.  No-op silently when none of the above resolves.
    uri probe = *u;
    a_pad(u8, frag_buf, 64);
    b8 has_resolvable =
        !u8csEmpty(u->fragment) ||
        (!u8csEmpty(u->query) && u8csLen(u->query) > 0) ||
        (!u8csEmpty(u->path)   && !u8csEmpty(u->query));

    if (!has_resolvable && u8bDataLen(k->h->cur_sha) == 40) {
        a_dup(u8c, cs, u8bData(k->h->cur_sha));
        u8bFeed(frag_buf, cs);
        probe.fragment[0] = u8bDataHead(frag_buf);
        probe.fragment[1] = u8bIdleHead(frag_buf);
        probe.query[0] = probe.query[1] = NULL;
        probe.data[0] = probe.data[1] = NULL;
        has_resolvable = YES;
    }

    if (!has_resolvable) {
        //  Fall back to keeper REFS — picks up the `?#<sha>` trunk
        //  row keeper writes after a fresh fetch, even when the
        //  caller's URI has no explicit query.
        a_path(keepdir, u8bDataC(k->h->root), KEEP_DIR_S);
        a_pad(u8, arena_buf, 1024);
        uri resolved = {};
        static u8c const q_lit[] = "?";
        u8cs probe_uri = {q_lit, q_lit + 1};
        if (!u8csEmpty(u->data)) {
            probe_uri[0] = u->data[0];
            probe_uri[1] = u->data[1];
        }
        a_dup(u8c, in_uri, probe_uri);
        if (REFSResolve(&resolved, arena_buf, $path(keepdir), in_uri) == OK
            && u8csLen(resolved.query) >= 40) {
            u8bFeed(frag_buf, resolved.query);
            probe.fragment[0] = u8bDataHead(frag_buf);
            probe.fragment[1] = u8bIdleHead(frag_buf);
            probe.query[0] = probe.query[1] = NULL;
            probe.data[0] = probe.data[1] = NULL;
            has_resolvable = YES;
        }
    }

    //  TODO: same swallow as graf/INDEX.c — KEEPLsFiles failures are
    //  silently treated as "nothing to walk" so BE's parallel reindex
    //  doesn't abort on relative refs (`?..`) it forwards before sniff
    //  rewrites them, or on a fresh-clone bootstrap with no REFS yet.
    //  Right fix is for BE to pre-resolve and skip the reindex when
    //  there's nothing to walk.
    if (has_resolvable) {
        (void)KEEPLsFiles(k, &probe, spot_walk_visit, &cx);
    }

    CAPOStackClose(mmaps, nidxfiles);
    done;
}
