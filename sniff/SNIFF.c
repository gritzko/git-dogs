//  SNIFF — worktree state singleton + path-registry wrappers.
//
//  The only cross-invocation state is `<wt>/.sniff` (dog/ULOG).
//  The per-process in-RAM state is a path-index sort over keeper's
//  registry, rebuilt lazily by callers (POST, DEL) that walk sorted
//  paths to assemble tree objects.  Nothing else survives.
//
#include "SNIFF.h"

#include <string.h>

#include "abc/FILE.h"
#include "abc/PATH.h"
#include "abc/PRO.h"
#include "keeper/PATHS.h"

#include "AT.h"

// --- Singleton ---

sniff SNIFF = {};

static b8 sniff_is_open(void) { return SNIFF.h != NULL; }
static b8 sniff_is_rw = NO;
static b8 sniff_opened_keep = NO;

// --- Open / close ---

//  Write the initial `repo` row into a freshly-created at.log.  The
//  URI anchors the wt to its store; default is colocated (`<wt>/.dogs/`).
//  `wt_root` is the wt path (where `.sniff` lives).
static ok64 sniff_write_repo_row(u8cs wt_root) {
    sane(SNIFF.h);
    //  Compose `file:///<wt_root>/.dogs/` via URI component fields;
    //  ULOGAppend serializes through URIutf8Feed.
    a_pad(u8, pathbuf, 2048);
    a_cstr(slash, "/");
    u8bFeed(pathbuf, wt_root);
    //  Guarantee exactly one trailing slash before we append ".dogs/".
    if (u8bDataLen(pathbuf) == 0 || *u8bLast(pathbuf) != '/')
        u8bFeed(pathbuf, slash);
    a_cstr(dogs, ".dogs/");
    u8bFeed(pathbuf, dogs);

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
    return ULOGAppend(&SNIFF.log, vrepo, &urow);
}

//  Resolve the store root from the repo-row URI.  The URI's path is
//  `/abs/path/.dogs/`; the store root is `/abs/path` (what h->root
//  must point at so KEEPOpen finds `.dogs/` as a child).
static void sniff_store_root_from_repo(u8cs uri_path, u8bp out) {
    a_dup(u8c, p, uri_path);
    //  Strip trailing slash, then the `.dogs` segment, then any
    //  further slashes — all via the Sx.h shed primitives.
    if (!$empty(p) && *u8csLast(p) == '/') u8csShed1(p);
    a_cstr(dogs, ".dogs");
    size_t dl = $len(dogs);
    if ($len(p) >= dl && memcmp($atp(p, $len(p) - dl), dogs[0], dl) == 0)
        for (size_t i = 0; i < dl; i++) u8csShed1(p);
    while ($len(p) > 1 && *u8csLast(p) == '/') u8csShed1(p);
    u8bReset(out);
    u8bFeed(out, p);
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

    //  The ULOG lives at `<wt>/.sniff` — one plain file, the whole of
    //  sniff's per-worktree state.  `h->wt` points at the worktree
    //  root; for colocated setups it equals `h->root`.  RW callers
    //  page-align the file via FILEBook (ULOGClose trims on dirty
    //  close); RO callers (status, list, dry-run post) go through
    //  ULOGOpenRO which never extends the on-disk size.
    a_dup(u8c, wt_root, u8bDataC(h->wt));
    a_cstr(sniffname, SNIFF_FILE);
    a_path(atpath, wt_root, sniffname);
    ok64 uo = rw ? ULOGOpen(&s->log, $path(atpath))
                 : ULOGOpenRO(&s->log, $path(atpath));
    if (uo != OK) { zerop(s); return uo; }

    //  Row-0 `repo` anchor.  Bootstrap on a fresh log (writes the
    //  colocated default `file:///<wt>/.dogs/`); honour an existing
    //  anchor for secondary worktrees by redirecting h->root to the
    //  store before keeper opens.
    if (ULOGCount(&s->log) == 0) {
        if (!rw) {
            //  Read-only open against an empty log — there is no state
            //  yet; leave the row unwritten and treat h->root as the
            //  colocated default.
        } else {
            ok64 wr = sniff_write_repo_row(wt_root);
            if (wr != OK) { ULOGClose(&s->log); zerop(s); return wr; }
        }
    }

    //  If we have a repo row, resolve the store path and redirect
    //  h->root to it so keeper / graf / spot open the correct .dogs/.
    //  (h->wt stays pointed at the worktree where `.sniff` lives.)
    {
        uri ru = {};
        ok64 rr = SNIFFAtRepo(&ru);
        if (rr == OK && !u8csEmpty(ru.path)) {
            a_dup(u8c, up, ru.path);
            a_pad(u8, storebuf, 2048);
            sniff_store_root_from_repo(up, storebuf);
            if (u8bDataLen(storebuf) > 0) {
                u8bReset(h->root);
                a_dup(u8c, sb, u8bData(storebuf));
                call(PATHu8bFeed, h->root, sb);
            }
        }
    }

    //  Now open keeper — h->root is the store root, colocated or
    //  redirected as appropriate.
    ok64 kr = KEEPOpen(h, rw);
    if (kr != OK && kr != KEEPOPEN) {
        ULOGClose(&s->log); zerop(s); return kr;
    }
    sniff_opened_keep = (kr == OK);

    //  Reserve the root-dir "/" path at its stable index.
    if (rw) (void)SNIFFRootIdx();

    //  Load wt-root .gitignore (single file, no nested cascade) into
    //  `s->ignores`.  Absent file is not an error — IGNOMatch still
    //  rejects .git/.dogs/.sniff unconditionally.
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
    ULOGClose(&s->log);
    u32bFree(s->sorted);
    IGNOFree(&s->ignores);
    zerop(s);
    sniff_is_rw = NO;
    if (sniff_opened_keep) {
        sniff_opened_keep = NO;
        KEEPClose();
    }
    done;
}

// --- Path registry (delegates to keeper) ---

u32 SNIFFIntern(u8cs path) {
    return KEEPIntern(&KEEP, path);
}

u32 SNIFFInternDir(u8cs path) {
    if ($empty(path)) return SNIFFRootIdx();
    if (*$last(path) == '/') return SNIFFIntern(path);
    a_pad(u8, tmp, 2048);
    u8bFeed(tmp, path);
    u8bFeed1(tmp, '/');
    u8cs dp = {u8bDataHead(tmp), tmp[2]};
    return SNIFFIntern(dp);
}

u32 SNIFFRootIdx(void) {
    a_cstr(root, "/");
    return SNIFFIntern(root);
}

ok64 SNIFFPath(u8csp out, u32 index) {
    sane(out);
    return KEEPPath(&KEEP, index, out);
}

u32 SNIFFCount(void) {
    return KEEPPathCount(&KEEP);
}

// --- Shared wt-scan helpers ---

//  One gate for every wt-scan callback: delegates to IGNOMatch, which
//  rejects metadata (.git/.dogs/.sniff) unconditionally and applies
//  any .gitignore patterns loaded into SNIFF.ignores at open time.
b8 SNIFFSkipMeta(u8cs rel) {
    return IGNOMatch(&SNIFF.ignores, rel, NO);
}

b8 SNIFFRelFromFull(u8csp rel_out, u8cs reporoot, u8cs full) {
    if (!rel_out) return NO;
    size_t rlen = $len(reporoot);
    if ($len(full) <= rlen) return NO;
    if (memcmp(full[0], reporoot[0], rlen) != 0) return NO;
    u8cs rel = {$atp(full, rlen), full[1]};
    //  Skip leading slash(es) between reporoot and the first segment.
    while (!$empty(rel) && *rel[0] == '/') u8csUsed1(rel);
    if ($empty(rel)) return NO;
    rel_out[0] = rel[0];
    rel_out[1] = rel[1];
    return YES;
}

// --- Sort (per-invocation) ---

static int sniff_cmp_idx(void const *a, void const *b) {
    u8cs pa = {}, pb = {};
    SNIFFPath(pa, *(u32 const *)a);
    SNIFFPath(pb, *(u32 const *)b);
    return u8cscmp(&pa, &pb);
}

ok64 SNIFFSort(void) {
    sane(1);
    sniff *s = &SNIFF;
    u32 n = SNIFFCount();
    if (u32bDataLen(s->sorted) > 0) u32bReset(s->sorted);
    if (n == 0) done;
    if (u32bLen(s->sorted) < n) {
        u32bFree(s->sorted);
        call(u32bAllocate, s->sorted, n);
    }
    for (u32 i = 0; i < n; i++) u32bFeed1(s->sorted, i);
    qsort(u32bDataHead(s->sorted), n, sizeof(u32), sniff_cmp_idx);
    done;
}
