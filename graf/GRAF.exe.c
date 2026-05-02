//  GRAFExec — run a parsed CLI against an open graf state.
//  Same effect as invoking `graf ...` as a separate process.
//
#include "GRAF.h"
#include "DAG.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

#include "abc/FILE.h"
#include "abc/HEX.h"
#include "abc/PATH.h"
#include "abc/PRO.h"
#include "dog/CLI.h"
#include "dog/DOG.h"
#include "dog/HOME.h"
#include "dog/HUNK.h"
#include "dog/WHIFF.h"
#include "keeper/KEEP.h"

// --- Verb / flag tables ---

char const *const GRAF_CLI_VERBS[] = {
    "get", "diff", "merge", "blame", "weave", "index",
    "log", "map", "status", "help", NULL
};

char const GRAF_CLI_VAL_FLAGS[] = "-o\0--at\0";

// --- Usage ---

static void graf_usage(void) {
    fprintf(stderr,
        "Usage: graf <verb> [flags] [URI...]\n"
        "\n"
        "  Verbs:\n"
        "    get path?sha1&sha2[&...]     deterministic blob/tree merge\n"
        "    diff old new                 token-level colored diff\n"
        "    merge base ours theirs       3-way merge\n"
        "    blame file                   token-level blame\n"
        "    weave file?from..to          weave diff between refs\n"
        "    log [path]?ref[#N]           commit history (one per line)\n"
        "    index                        index object graph from keeper\n"
        "    status                       show index stats\n"
        "    help                         this message\n"
        "\n"
        "  Flags:\n"
        "    -o <file>                    merge output file\n"
        "    -t | --tlv                   force TLV output\n"
    );
}

// --- Bro pager setup ---
//
//  Three output shapes — all producers emit `hunk` records via
//  GRAFHunkEmit; the formatter pinned in `graf_emit` decides bytes:
//
//    tty_out=YES               → spawn bro, formatter = HUNKu8sFeed (TLV)
//    tty_out=NO, force_tlv=YES → BE→bro pipe upstream, formatter = HUNKu8sFeed
//    tty_out=NO, force_tlv=NO  → no bro downstream, formatter =
//                                 HUNKu8sFeedLineBased (proper unified
//                                 diff `+`/`-`/' ' shape per line —
//                                 right default for diff/blame/weave).
//
//  Projectors whose hunk is plain text (`log:`, `map:`, `ls:`, etc.)
//  override `graf_emit` to `HUNKu8sFeedText` after this call so the
//  hunk text is emitted verbatim instead of getting the `' '` prefix.
static pid_t graf_start_pager(b8 tty_out, b8 force_tlv) {
    if (!tty_out) {
        graf_out_fd = STDOUT_FILENO;
        graf_emit   = force_tlv ? HUNKu8sFeed : HUNKu8sFeedLineBased;
        if (force_tlv) signal(SIGPIPE, SIG_IGN);
        return -1;
    }
    a_path(bropath);
    a$rg(a0, 0);
    a_cstr(bro_name, "bro");
    HOMEResolveSibling(NULL, bropath, bro_name, a0);
    u8cs args[] = {u8slit("bro")};
    u8css argv = {args, args + 1};
    pid_t pid = 0;
    int wfd = -1;
    if (FILESpawn($path(bropath), argv, &wfd, NULL, &pid) != OK) {
        graf_out_fd = STDOUT_FILENO;
        graf_emit   = HUNKu8sFeedLineBased;
        return -1;
    }
    graf_out_fd = wfd;
    graf_emit   = HUNKu8sFeed;
    signal(SIGPIPE, SIG_IGN);
    return pid;
}

//  Override the non-TLV formatter to plain text — for projectors
//  whose hunk is grep/cat-shaped (no `+`/`-` line prefixes).  Called
//  by log/map/ls dispatch after graf_start_pager.  No-op when bro is
//  downstream (graf_emit is already HUNKu8sFeed).
static void graf_pager_plain_text(void) {
    if (graf_emit != HUNKu8sFeed) graf_emit = HUNKu8sFeedText;
}

static void graf_stop_pager(pid_t pid) {
    if (graf_out_fd >= 0 && graf_out_fd != STDOUT_FILENO) {
        close(graf_out_fd);
        graf_out_fd = -1;
    }
    if (pid > 0) {
        int rc = 0;
        FILEReap(pid, &rc);
        if (rc == 127)
            fprintf(stderr, "graf: bro pager not found\n");
    }
}

// --- URI path helper ---

static void graf_uri_path(u8cs out, uri *u) {
    if (!u8csEmpty(u->path))
        u8csMv(out, u->path);
    else
        u8csMv(out, u->data);
}

// --- Entry ---

ok64 GRAFExec(cli *c) {
    sane(c);
    graf *g = &GRAF;

    a_cstr(v_get,    "get");
    a_cstr(v_diff,   "diff");
    a_cstr(v_merge,  "merge");
    a_cstr(v_blame,  "blame");
    a_cstr(v_weave,  "weave");
    a_cstr(v_index,  "index");
    a_cstr(v_log,    "log");
    a_cstr(v_map,    "map");
    a_cstr(v_status, "status");
    a_cstr(v_help,   "help");

    if ($eq(c->verb, v_help) || CLIHas(c, "-h") || CLIHas(c, "--help")) {
        graf_usage(); done;
    }

    //  Verb-less projector invocation (VERBS.md §"View projectors"):
    //  `graf <proj>:<URI>` — no verb.  The URI's scheme must resolve
    //  through DOG_PROJECTORS to "graf"; today that's only `diff:`.
    //  We synthesize the matching verb so the existing dispatch below
    //  runs unchanged.  BE wires this up by spawning `graf [--tlv] <URI>`
    //  on `be get diff:<URI>` (and verb-less `be diff:<URI>`).
    a_cstr(s_diff,  "diff");
    a_cstr(s_log,   "log");
    a_cstr(s_map,   "map");
    a_cstr(s_blame, "blame");
    a_cstr(s_weave, "weave");
    if ($empty(c->verb) && c->nuris > 0) {
        uri *pu = &c->uris[0];
        char const *dog = DOGProjectorDog(pu->scheme);
        if (dog != NULL && strcmp(dog, "graf") == 0) {
            if      ($eq(pu->scheme, s_diff))  u8csMv(c->verb, s_diff);
            else if ($eq(pu->scheme, s_log))   u8csMv(c->verb, s_log);
            else if ($eq(pu->scheme, s_map))   u8csMv(c->verb, s_map);
            else if ($eq(pu->scheme, s_blame)) u8csMv(c->verb, s_blame);
            else if ($eq(pu->scheme, s_weave)) u8csMv(c->verb, s_weave);
        }
    }

    if ($empty(c->verb)) {
        graf_usage();
        return FAILSANITY;
    }

    //  `--tlv` (or `-t`) forces HUNK TLV emission on a non-TTY stdout.
    //  Used when BE pipes graf's stdout into bro on a TTY: graf sees a
    //  pipe (not a TTY) but must still emit TLV so bro can render.
    b8 force_tlv = CLIHas(c, "--tlv") || CLIHas(c, "-t");

    u8cs reporoot = {};
    u8csMv(reporoot, c->repo);
    // If CLI parsing didn't supply a repo, fall back to h->root.
    if ($empty(reporoot) && g->h && g->h->root[0]) {
        a_dup(u8c, hs, u8bDataC(g->h->root));
        u8csMv(reporoot, hs);
    }

    // --- status: uses graf state only ---

    if ($eq(c->verb, v_status)) {
        u64 total_entries = 0;
        for (u32 i = 0; i < g->runs_n; i++)
            total_entries += (u64)(g->runs[i][1] - g->runs[i][0]);
        fprintf(stdout, "graf: %u index run(s), %llu entries\n",
                g->runs_n, (unsigned long long)total_entries);
        done;
    }

    // --- diff: dispatch on URI shape ---
    //
    //   2 URIs, no projector intent on URI[0]   → legacy file-pair
    //                                             (no keeper needed)
    //   1 URI with diff: scheme / ?query / path → URI-driven projector,
    //                                             falls through to the
    //                                             keeper-open block below

    if ($eq(c->verb, v_diff)) {
        uri *u0 = (c->nuris >= 1) ? &c->uris[0] : NULL;
        //  Legacy file-pair `graf diff a.c b.c`: two URIs with no
        //  projector intent on the first (no scheme, no query).  A
        //  single URI is always projector — even bare `diff:<path>`.
        b8 file_pair = (c->nuris >= 2 && u0 != NULL &&
                        u8csEmpty(u0->scheme) &&
                        u8csEmpty(u0->query));
        if (c->nuris < 1) {
            fprintf(stderr,
                "graf: diff requires 2 files, or 1 URI"
                " (diff:[<path>][?<ref>])\n");
            return FAILSANITY;
        }
        if (file_pair) {
            pid_t pager = graf_start_pager(c->tty_out, force_tlv);
            u8cs op = {}, np = {};
            graf_uri_path(op, &c->uris[0]);
            graf_uri_path(np, &c->uris[1]);
            u8cs nomode = {};
            ok64 ret = GRAFDiff(op, np, np, nomode, nomode);
            graf_stop_pager(pager);
            return ret;
        }
        // fall through to keeper-open block below
    }

    // --- merge: file-based, no keeper needed ---

    if ($eq(c->verb, v_merge)) {
        if (c->nuris < 3) {
            fprintf(stderr, "graf: merge requires 3 files: base ours theirs\n");
            return FAILSANITY;
        }
        u8cs bp = {}, op = {}, tp = {};
        graf_uri_path(bp, &c->uris[0]);
        graf_uri_path(op, &c->uris[1]);
        graf_uri_path(tp, &c->uris[2]);
        u8cs merge_out = {};
        CLIFlag(merge_out, c, "-o");
        return GRAFMerge(bp, op, tp, merge_out);
    }

    // --- index, blame, weave: require keeper ---

    if (!reporoot[0]) {
        fprintf(stderr, "graf: %.*s requires .dogs/keeper\n",
                (int)$len(c->verb), (char *)c->verb[0]);
        return FAILSANITY;
    }


    call(KEEPOpen, g->h, YES);
    ok64 ret = OK;

    if ($eq(c->verb, v_index)) {
        //  Pull every keeper object through graf's DOG.md §8 streaming
        //  ingest: COMMIT → TREE → BLOB → finish.  Idempotent.
        ret = GRAFIndex(&KEEP);

    } else if ($eq(c->verb, v_get)) {
        if (c->nuris < 1) {
            fprintf(stderr, "graf: get requires a URI\n");
            KEEPClose();
            return FAILSANITY;
        }
        uri *u = &c->uris[0];
        Bu8 out = {};
        ret = u8bMap(out, 16UL << 20);
        if (ret == OK) {
            a_dup(u8c, uri_in, u->data);
            ret = GRAFGet(out, uri_in);
            if (ret == OK) {
                a_dup(u8c, obytes, u8bData(out));
                ret = FILEFeedAll(STDOUT_FILENO, obytes);
            }
            u8bUnMap(out);
        }

    } else if ($eq(c->verb, v_blame)) {
        if (c->nuris < 1) {
            fprintf(stderr, "graf: blame requires a file URI\n");
            KEEPClose();
            return FAILSANITY;
        }
        pid_t pager = graf_start_pager(c->tty_out, force_tlv);
        u8cs path = {};
        graf_uri_path(path, &c->uris[0]);
        //  Resolve URI's #hex/?ref/absent-query to a tip commit
        //  hashlet so blame can scope its history walk.  A failure
        //  here just yields an unscoped (full-index) blame.
        u64 tip_h = 0;
        {
            sha1 tip = {};
            if (GRAFResolveTip(&KEEP, &c->uris[0], &tip) == OK)
                tip_h = WHIFFHashlet60(&tip);
        }
        ret = GRAFBlame(&KEEP, path, tip_h, reporoot);
        graf_stop_pager(pager);

    } else if ($eq(c->verb, v_diff)) {
        //  URI-driven diff (VERBS.md §"View projectors", `diff:`).  The
        //  right-hand side of every diff is *ours* (the changed state).
        //  URI shape table:
        //
        //    diff:                  → wt vs base    (whole tree)
        //    diff:file.c            → wt vs base    (single file)
        //    diff:?branch           → branch vs base (whole tree, ref-to-ref)
        //    diff:file.c?branch     → branch vs base (single file, ref-to-ref)
        //    diff:?h1..h2           → h1 vs h2      (whole tree, explicit)
        //    diff:file.c?h1..h2     → h1 vs h2      (single file, explicit)
        //
        //  The base sha comes from `--at`'s fragment (the worktree's
        //  current baseline, forwarded by `be`).  Every form except the
        //  explicit `?h1..h2` range needs it; missing → `GRAFNOAT`.
        pid_t pager = graf_start_pager(c->tty_out, force_tlv);
        uri *u = &c->uris[0];

        uri at = {};
        CLIAtURI(&at, c);
        u8cs base_hex = {};
        $mv(base_hex, at.fragment);

        u8cs path = {};
        u8csMv(path, u->path);

        u8cs wf = {}, wt = {};
        a_dup(u8c, q, u->query);
        u8cs dots = {(u8cp)"..", (u8cp)".." + 2};
        b8 has_range = !$empty(q) && (u8csFindS(q, dots) == OK);

        if (has_range) {
            //  Explicit `?h1..h2` — no baseline needed.
            wf[0] = u->query[0]; wf[1] = q[0];
            wt[0] = q[0] + 2;    wt[1] = u->query[1];
            if (!$empty(path)) {
                ret = GRAFWeaveDiff(&KEEP, path, reporoot, wf, wt);
            } else {
                ret = GRAFDiffTreeRefs(&KEEP, wf, wt, reporoot);
            }
        } else {
            if ($empty(base_hex)) {
                fprintf(stderr,
                    "graf: diff: no --at baseline; need explicit"
                    " 'diff:?<h1>..<h2>' or a sniff anchor\n");
                graf_stop_pager(pager);
                KEEPClose();
                return GRAFNOAT;
            }
            sha1 base_sha = {};
            a_dup(u8c, base_dup, base_hex);
            u8s sb = {(u8p)base_sha.data, (u8p)base_sha.data + 20};
            ok64 ho = HEXu8sDrainSome(sb, base_dup);
            u64 base_h40 = (ho == OK) ? WHIFFHashlet60(&base_sha) : 0;

            if (!u8csEmpty(u->query)) {
                //  `?branch` → branch vs base (ref-to-ref).
                u8cs branch = {};
                u8csMv(branch, u->query);
                if (!$empty(path)) {
                    ret = GRAFWeaveDiff(&KEEP, path, reporoot,
                                        branch, base_hex);
                } else {
                    ret = GRAFDiffTreeRefs(&KEEP, branch, base_hex,
                                           reporoot);
                }
            } else {
                //  No query → wt vs base (weave-based).
                if (!$empty(path)) {
                    ret = GRAFDiffWtFile(&KEEP, path, base_h40, reporoot);
                } else {
                    ret = GRAFDiffWtTree(&KEEP, base_h40, base_hex,
                                         reporoot);
                }
            }
        }
        graf_stop_pager(pager);

    } else if ($eq(c->verb, v_map)) {
        pid_t pager = graf_start_pager(c->tty_out, force_tlv);
        graf_pager_plain_text();
        ret = GRAFMap(c->nuris > 0 ? &c->uris[0] : NULL);
        graf_stop_pager(pager);

    } else if ($eq(c->verb, v_log)) {
        if (c->nuris < 1) {
            fprintf(stderr, "graf: log requires a URI\n");
            KEEPClose();
            return FAILSANITY;
        }
        pid_t pager = graf_start_pager(c->tty_out, force_tlv);
        graf_pager_plain_text();
        ret = GRAFLog(&KEEP, &c->uris[0]);
        graf_stop_pager(pager);

    } else if ($eq(c->verb, v_weave)) {
        if (c->nuris < 1) {
            fprintf(stderr, "graf: weave requires a file URI\n");
            KEEPClose();
            return FAILSANITY;
        }
        pid_t pager = graf_start_pager(c->tty_out, force_tlv);
        uri *u = &c->uris[0];
        u8cs wf = {}, wt = {};
        if (!u8csEmpty(u->query)) {
            a_dup(u8c, q, u->query);
            u8cs dots = {(u8cp)"..", (u8cp)".." + 2};
            if (u8csFindS(q, dots) == OK) {
                wf[0] = u->query[0];
                wf[1] = q[0];
                wt[0] = q[0] + 2;
                wt[1] = u->query[1];
            } else {
                u8csMv(wt, u->query);
            }
        }
        u8cs path = {};
        graf_uri_path(path, u);
        ret = GRAFWeaveDiff(&KEEP, path, reporoot, wf, wt);
        graf_stop_pager(pager);

    } else {
        fprintf(stderr, "graf: unknown verb '%.*s'\n",
                (int)$len(c->verb), (char *)c->verb[0]);
        ret = FAILSANITY;
    }

    KEEPClose();
    return ret;
}
