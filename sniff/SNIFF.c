//  SNIFF — worktree state singleton + path-registry wrappers.
//
//  The only cross-invocation state is `<wt>/.be/wtlog` (dog/ULOG).
//  The per-process in-RAM state is a path-index sort over keeper's
//  registry, rebuilt lazily by callers (POST, DEL) that walk sorted
//  paths to assemble tree objects.  Nothing else survives.
//
#include "SNIFF.h"

#include <string.h>

#include "abc/BUF.h"
#include "abc/FILE.h"
#include "abc/LSM.h"     // u8cssHeapZ for SNIFFMergeWalk
#include "abc/PATH.h"
#include "abc/PRO.h"

#include "graf/GRAF.h"

#include "AT.h"

// --- Wtlog path resolver --------------------------------------------

ok64 SNIFFMaybeSwitchKeeper(u8cs target_branch) {
    sane(1);
    if (!$ok(target_branch)) done;

    keeper *k = &KEEP;
    if (k->h == NULL) done;  // keeper not open — nothing to switch.

    //  Same as current leaf?  No-op.
    a_dup(u8c, cur, u8bDataC(k->leaf_branch));
    if (u8csLen(cur) == u8csLen(target_branch) &&
        (u8csLen(target_branch) == 0 ||
         memcmp(cur[0], target_branch[0],
                u8csLen(target_branch)) == 0)) done;

    //  Empty target == trunk-leaf.  Trunk's shard dir is always the
    //  store root (`<root>/.be/`), so the on-disk probe below is
    //  trivially true; skip the probe and switch directly.  This lets
    //  cross-shard ops (cross-branch POST, KEEP migrate) re-target
    //  trunk-leaf without bypass.
    if (u8csEmpty(target_branch)) {
        return KEEPSwitchBranch(k->h, target_branch);
    }

    //  Probe `<root>/.be/<target_branch>/` — skip if it's not a real
    //  branch shard dir (tags, peer-prefixed refs, etc. all share the
    //  cur branch's view).
    a_path(probe, u8bDataC(k->h->root), KEEP_DIR_S);
    if (PATHu8bAdd(probe, target_branch) != OK) done;
    filestat fs = {};
    if (FILEStat(&fs, $path(probe)) != OK ||
        fs.kind != FILE_KIND_DIR) done;

    return KEEPSwitchBranch(k->h, target_branch);
}

ok64 SNIFFMaybeSwitchGraf(u8cs target_branch) {
    sane(1);
    if (!$ok(target_branch) || u8csEmpty(target_branch)) done;

    graf *g = &GRAF;
    if (g->h == NULL) done;  // graf not open.

    //  Probe the on-disk shard (same gating as keeper).
    a_path(probe, u8bDataC(g->h->root), KEEP_DIR_S);
    if (PATHu8bAdd(probe, target_branch) != OK) done;
    filestat fs = {};
    if (FILEStat(&fs, $path(probe)) != OK ||
        fs.kind != FILE_KIND_DIR) done;

    return GRAFSwitchBranch(g->h, target_branch);
}

ok64 SNIFFWtlogPath(path8b out, u8cs wt_root) {
    sane(out && $ok(wt_root));
    u8bReset(out);
    call(PATHu8bFeed, out, wt_root);
    call(PATHu8bPush, out, DOG_BE_S);

    //  Stat `<wt>/.be` (follow symlinks so a symlinked dir counts as
    //  primary).  If it's a regular file, this wt is a secondary —
    //  the `.be` file IS the wtlog.  Otherwise fall through to the
    //  primary layout `<wt>/.be/wtlog` (covers dir, missing, and
    //  broken-symlink — the caller mkdir's `.be/` before open).
    filestat fs = {};
    if (FILEStat(&fs, $path(out)) == OK && fs.kind == FILE_KIND_REG) {
        done;                                // secondary: out = <wt>/.be
    }
    call(PATHu8bPush, out, DOG_WTLOG_S);     // primary: out = <wt>/.be/wtlog
    done;
}

// --- Singleton ---

sniff SNIFF = {};

static b8 sniff_is_open(void) { return SNIFF.h != NULL; }
static b8 sniff_is_rw = NO;
static b8 sniff_opened_keep = NO;

// --- Open / close ---

//  Write the initial `repo` row into a freshly-created wtlog.  The
//  URI anchors the wt to its store; default is colocated (`<wt>/.be/`).
//  `wt_root` is the wt path (where `.be/` lives).
static ok64 sniff_write_repo_row(u8cs wt_root) {
    sane(SNIFF.h);
    //  Compose `file:<wt_root>/.be/` via URI component fields;
    //  ULOGAppend serializes through URIutf8Feed.
    a_path(pathbuf, wt_root, DOG_BE_S);
    //  URI path for a directory carries a trailing slash.
    call(u8bFeed1, pathbuf, '/');
    call(PATHu8bTerm, pathbuf);

    uri urow = {};
    a_cstr(scheme, "file");
    urow.scheme[0] = scheme[0];
    urow.scheme[1] = scheme[1];
    {
        a_dup(u8c, pb, u8bData(pathbuf));
        urow.path[0] = pb[0];
        urow.path[1] = pb[1];
    }
    ron60 vrepo = SNIFFAtVerbRepo();
    ulogrec rec = {.verb = vrepo, .uri = urow};
    return ULOGAppend(SNIFF.log_data, SNIFF.log_idx, &rec);
}

ok64 SNIFFOpen(home *h, b8 rw) {
    sane(h);

    if (sniff_is_open()) {
        if (rw && !sniff_is_rw) return SNIFFOPRO;
        return SNIFFOPEN;
    }

    sniff *s = &SNIFF;
    zerop(s);
    s->h = h;
    sniff_is_rw = rw;

    //  The ULOG lives at either `<wt>/.be/wtlog` (primary / colocated
    //  wt) or `<wt>/.be` (secondary wt — the `.be` file IS the wtlog,
    //  with row 0's `repo` URI naming the shared primary store).
    //  `SNIFFWtlogPath` dispatches on the on-disk shape; for RW opens
    //  on a fresh wt we also pre-create `.be/` so the primary path
    //  resolves cleanly.  RW callers page-align the file via FILEBook
    //  (ULOGClose trims on dirty close); RO callers (status, list,
    //  dry-run post) go through ULOGOpenRO which never extends the
    //  on-disk size.
    a_dup(u8c, wt_root, u8bDataC(h->wt));
    if (rw) {
        //  Primary-wt mkdir: harmless if `.be/` already exists,
        //  no-op (EEXIST as a file) if this is a secondary wt.
        a_path(bedir, wt_root, DOG_BE_S);
        (void)FILEMakeDirP($path(bedir));
    }
    a_path(atpath);
    call(SNIFFWtlogPath, atpath, wt_root);
    ok64 uo = rw ? ULOGOpen  (&s->log_data, &s->log_idx, $path(atpath))
                 : ULOGOpenRO(&s->log_data, &s->log_idx, $path(atpath));
    if (uo != OK) { zerop(s); return uo; }
    s->log_rw = rw;

    //  Wall-clock guard: refuse on entry if the system clock is before
    //  the latest log row.  RW only — read-only paths (status, list)
    //  don't append rows or stamp files, so a backwards clock can't
    //  corrupt anything they observe.
    if (rw) {
        ok64 co = SNIFFCheckClock();
        if (co != OK) {
            ULOGClose(s->log_data, &s->log_idx, s->log_rw);
            zerop(s); return co;
        }
    }

    //  Row-0 `repo` anchor.  Bootstrap on a fresh log (writes the
    //  colocated default `file:<wt>/.be/`); honour an existing
    //  anchor for secondary worktrees by redirecting h->root to the
    //  store before keeper opens.
    if (ULOGCount(s->log_idx) == 0) {
        if (!rw) {
            //  Read-only open against an empty log — there is no state
            //  yet; leave the row unwritten and treat h->root as the
            //  colocated default.
        } else {
            ok64 wr = sniff_write_repo_row(wt_root);
            if (wr != OK) {
                ULOGClose(s->log_data, &s->log_idx, s->log_rw);
                zerop(s); return wr;
            }
        }
    }

    //  If we have a repo row, resolve the store path and redirect
    //  h->root to it so keeper / graf / spot open the correct .be/.
    //  (h->wt stays pointed at the worktree where the wtlog lives.)
    {
        uri ru = {};
        ok64 rr = SNIFFAtRepo(&ru);
        if (rr == OK && !u8csEmpty(ru.path)) {
            a_dup(u8c, up, ru.path);
            a_path(storebuf);
            DOGRepoFromBe(up, storebuf);
            if (u8bDataLen(storebuf) > 0) {
                u8bReset(h->root);
                a_dup(u8c, sb, u8bData(storebuf));
                call(PATHu8bFeed, h->root, sb);
            }
        }
    }

    //  Open keeper on the wt's current branch (PAST = trunk +
    //  ancestors, DATA = active leaf).  Pack writes land at
    //  `<root>/.be/<branch>/NNNN.keeper`; cross-branch reads route
    //  through `SNIFFMaybeSwitchKeeper` / `SNIFFMaybeSwitchGraf`.
    a_pad(u8, br_buf, 256);
    {
        ron60 bts = 0, bverb = 0;
        uri bu = {};
        if (SNIFFAtCurTip(&bts, &bverb, &bu) == OK)
            u8bFeed(br_buf, bu.query);
    }
    a_dup(u8c, branch, u8bData(br_buf));
    ok64 kr = KEEPOpenBranch(h, branch, rw);
    if (kr != OK && kr != KEEPOPEN) {
        ULOGClose(s->log_data, &s->log_idx, s->log_rw);
        zerop(s); return kr;
    }
    sniff_opened_keep = (kr == OK);

    //  Load wt-root .gitignore (single file, no nested cascade) into
    //  `s->ignores`.  Absent file is not an error — IGNOMatch still
    //  rejects .git/.be unconditionally.
    {
        a_dup(u8c, wt_for_ig, u8bDataC(h->wt));
        (void)IGNOLoad(&s->ignores, wt_for_ig);
    }
    done;
}

ok64 SNIFFClose(void) {
    sane(1);
    if (!sniff_is_open()) return OK;
    sniff *s = &SNIFF;
    ULOGClose(s->log_data, &s->log_idx, s->log_rw);
    IGNOFree(&s->ignores);
    zerop(s);
    sniff_is_rw = NO;
    if (sniff_opened_keep) {
        sniff_opened_keep = NO;
        KEEPClose();
    }
    done;
}

// --- Shared wt-scan helpers ---

//  One gate for every wt-scan callback: delegates to IGNOMatch, which
//  rejects metadata (.git/.be) unconditionally and applies any
//  .gitignore patterns loaded into SNIFF.ignores at open time.
b8 SNIFFSkipMeta(u8cs rel) {
    return IGNOMatch(&SNIFF.ignores, rel, NO);
}

b8 SNIFFRelFromFull(u8csp rel_out, u8cs reporoot, u8cs full) {
    if (!rel_out) return NO;
    if (u8csLen(full) <= u8csLen(reporoot)) return NO;
    if (!u8csHasPrefix(full, reporoot)) return NO;
    u8cs rel = {$atp(full, u8csLen(reporoot)), full[1]};
    //  Skip leading slash(es) between reporoot and the first segment.
    while (!u8csEmpty(rel) && *rel[0] == '/') u8csUsed1(rel);
    if (u8csEmpty(rel)) return NO;
    u8csMv(rel_out, rel);
    return YES;
}

// --- N-way ULOG-row merge -------------------------------------------

//  Compare two ulogrec URIs by path-key (same rule as ULOGu8csZbyUri,
//  applied directly to parsed records — no peek-drain needed since
//  the records are already in hand).
static b8 merge_path_eq(ulogreccp a, ulogreccp b) {
    u8cs ka = {}, kb = {};
    if (u8csEmpty(a->uri.path)) u8csMv(ka, a->uri.query);
    else                        u8csMv(ka, a->uri.path);
    if (u8csEmpty(b->uri.path)) u8csMv(kb, b->uri.query);
    else                        u8csMv(kb, b->uri.path);
    if (u8csLen(ka) != u8csLen(kb)) return NO;
    return memcmp(ka[0], kb[0], u8csLen(ka)) == 0;
}

ok64 SNIFFMergeWalk(u8css cursors, sniff_step_fn cb, void *ctx) {
    sane(cursors && cb);
    if ($empty(cursors)) done;

    //  Heapify in place — cursors[0] becomes the root (smallest URI key).
    u8cssHeapZ(cursors, ULOGu8csZbyUri);

    ulogrec group[LSM_MAX_INPUTS];
    u32     n = 0;

    for (;;) {
        ulogrec next = {};
        ok64 d = ULOGu8ssDrainHeap(cursors, ULOGu8csZbyUri, &next);
        if (d == ULOGNONE) break;
        if (d != OK) return d;

        if (n == 0) {
            group[0] = next;
            n = 1;
            continue;
        }
        if (merge_path_eq(&group[0], &next)) {
            if (n < LSM_MAX_INPUTS) group[n++] = next;
            continue;
        }
        //  Mismatch: fire current group, then seed the next group with
        //  `next` as its first member.
        ok64 cr = cb(group, n, ctx);
        if (cr != OK) return cr;
        group[0] = next;
        n = 1;
    }

    //  Flush trailing group, if any.
    if (n > 0) {
        ok64 cr = cb(group, n, ctx);
        if (cr != OK) return cr;
    }
    done;
}
