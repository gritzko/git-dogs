//  PATCH: 3-way worktree merge via graf.
//
//  See PATCH.h for the public surface.  Implementation walks three
//  trees (fork, ours, theirs) in tandem by fetching tree bytes via
//  graf for each directory level, classifies every leaf path by
//  the {fork, ours, theirs} sha triple, and applies a worktree
//  action.  Merged bytes come from `GRAFGet <path>?<ours>&<theirs>`;
//  pass-through bytes come from `GRAFGet <path>?<theirs>`.  Sniff
//  never reads keeper directly here.
//
//  Per VERBS.md §PATCH and Invariant 2, PATCH absorbs the target
//  branch's full (fork_commit..tip) stack into cur's wt as a single
//  squash with `base = tree(arg.fork_commit)`.  `arg.fork_commit` is
//  the LCA of the target's parent-branch tip and the target's tip —
//  the commit on the parent branch where the target was forked.
//  Provenance for the commit graph is erased: the next POST emits a
//  single-parent commit anchored on the wt's pre-patch get/post tip,
//  not the absorbed branch.  The patch row itself records `theirs`
//  in its fragment so POST's bare-no-msg path can recover the
//  absorbed commits' messages and authors as defaults; this is
//  metadata only and never participates in the commit topology.
//
#include "PATCH.h"

#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "abc/FILE.h"
#include "abc/HEX.h"
#include "abc/PATH.h"
#include "abc/PRO.h"
#include "abc/URI.h"
#include "dog/QURY.h"
#include "dog/WHIFF.h"
#include "graf/GRAF.h"
#include "keeper/GIT.h"
#include "keeper/KEEP.h"
#include "keeper/REFS.h"

#include "AT.h"
#include "SNIFF.h"

#define PATCH_TREE_BUF   (4UL << 20)   // 4 MB per tree body
#define PATCH_BLOB_BUF   (16UL << 20)  // 16 MB per blob
#define PATCH_MAX_ENTRIES 4096         // per directory

// --- Entry extracted from a git-format tree body ------------------

typedef struct {
    u8cs name;       // points into the owning tree-body buffer
    u8cs mode;       // same
    sha1 sha;        // raw 20 bytes
    b8   present;    // has this side got an entry with this name?
    b8   is_dir;     // mode starts with '4' (git tree-of-trees)
} entry;

static ok64 parse_tree(entry *out, u32 *nout, u32 cap, u8cs body) {
    sane(out && nout);
    u32 n = 0;
    u8cs obj = {body[0], body[1]};
    u8cs file = {}, esha = {};
    while (n < cap && GITu8sDrainTree(obj, file, esha, NULL) == OK) {
        //  `file` is `<mode> <name>`.  csFind consumes `scan` up to
        //  the space; mode is [file[0]..scan[0]), name is [scan[0]+1..file[1]).
        a_dup(u8c, scan, file);
        if (u8csFind(scan, ' ') != OK) continue;
        u8cs mode_s = {file[0], scan[0]};
        u8csUsed1(scan);                                  // skip the space
        u8cs name_s = {scan[0], file[1]};
        if ($empty(name_s) || u8csLen(esha) != 20) continue;
        entry *e = &out[n++];
        e->name[0] = name_s[0]; e->name[1] = name_s[1];
        e->mode[0] = mode_s[0]; e->mode[1] = mode_s[1];
        e->is_dir = ($len(mode_s) > 0 && *mode_s[0] == '4');
        e->present = YES;
        sha1Mv(&e->sha, (sha1 const *)esha[0]);
    }
    *nout = n;
    done;
}

static int entry_name_cmp(u8cs a, u8cs b) {
    size_t la = $len(a), lb = $len(b);
    size_t ml = la < lb ? la : lb;
    int c = (ml == 0) ? 0 : memcmp(a[0], b[0], ml);
    if (c != 0) return c;
    if (la < lb) return -1;
    if (la > lb) return 1;
    return 0;
}

static void sort_entries(entry *arr, u32 n) {
    for (u32 i = 1; i < n; i++) {
        entry v = arr[i];
        u32 j = i;
        while (j > 0 && entry_name_cmp(arr[j - 1].name, v.name) > 0) {
            arr[j] = arr[j - 1];
            j--;
        }
        arr[j] = v;
    }
}

fun b8 sha_eq(sha1 const *a, sha1 const *b) {
    return memcmp(a->data, b->data, 20) == 0;
}

// --- graf fetch wrappers -------------------------------------------
//  URIs are assembled via abc/URI's `a_uri` macro so the `path?query`
//  shape stays canonical.  Query is one 40-hex sha for a tip fetch or
//  `<hex_a>&<hex_b>` for a 2-way merge fetch.

//  Fetch a tree body via graf.  Path is `<dir>/` (or `/` at the root),
//  query is the commit sha hex.  Returns OK with `into` populated, or
//  any GRAFFAIL / KEEPNONE variant on failure (caller treats those as
//  "dir absent at that commit").
static ok64 fetch_tree(u8b into, u8cs dir, sha1 const *sha) {
    sane(into && sha);
    u8bReset(into);

    a_pad(u8, pbuf, 1024);
    if ($empty(dir)) {
        call(u8bFeed1, pbuf, '/');
    } else {
        call(u8bFeed, pbuf, dir);
        if (*u8csLast(dir) != '/') call(u8bFeed1, pbuf, '/');
    }
    a_dup(u8c, path, u8bData(pbuf));

    sha1hex hex;
    sha1hexFromSha1(&hex, sha);
    u8cs query = {hex.data, hex.data + 40};

    a_uri(u, 0, 0, path, query, 0);
    return GRAFGet(into, u);
}

static ok64 fetch_blob(u8b into, u8cs path, sha1 const *sha) {
    sane(into && sha && !$empty(path));
    u8bReset(into);

    sha1hex hex;
    sha1hexFromSha1(&hex, sha);
    u8cs query = {hex.data, hex.data + 40};

    a_uri(u, 0, 0, path, query, 0);
    return GRAFGet(into, u);
}

static ok64 fetch_merge(u8b into, u8cs path,
                        sha1 const *ours, sha1 const *thrs) {
    sane(into && ours && thrs && !$empty(path));
    u8bReset(into);

    sha1hex ha, hb;
    sha1hexFromSha1(&ha, ours);
    sha1hexFromSha1(&hb, thrs);

    a_pad(u8, qbuf, 128);
    u8cs ha_s = {ha.data, ha.data + 40};
    u8cs hb_s = {hb.data, hb.data + 40};
    call(u8bFeed,  qbuf, ha_s);
    call(u8bFeed1, qbuf, '&');
    call(u8bFeed,  qbuf, hb_s);
    a_dup(u8c, query, u8bData(qbuf));

    a_uri(u, 0, 0, path, query, 0);
    return GRAFGet(into, u);
}

// --- Worktree writes -----------------------------------------------

//  Write `data` to `<reporoot>/<relpath>`.  `mode` is a git-style
//  ascii mode string: `"100644"` / `"100755"` / `"120000"` (symlink).
//  Creates parent dirs as needed.  Caller is responsible for stamping
//  the file's mtime via stamp_wrote after a successful write.
static ok64 write_blob(u8cs reporoot, u8csc relpath_in,
                       u8csc mode, u8csc data) {
    sane(!$empty(relpath_in));
    a_dup(u8c, relpath, relpath_in);

    a_path(fp);
    call(SNIFFFullpath, fp, reporoot, relpath);

    //  Parent dir may need creating if this is a freshly-added file
    //  living in a new subdir.
    {
        a_path(dp);
        u8cs dir = {};
        PATHu8sDir(dir, relpath);
        if (!$empty(dir)) {
            call(SNIFFFullpath, dp, reporoot, dir);
            FILEMakeDirP($path(dp));
        }
    }

    b8 is_link = ($len(mode) >= 1 && *mode[0] == '1' &&
                  $len(mode) >= 6 && mode[0][1] == '2');
    b8 is_exe  = ($len(mode) >= 6 && mode[0][1] == '0' &&
                  mode[0][2] == '0' && mode[0][3] == '7' &&
                  mode[0][4] == '5' && mode[0][5] == '5');

    if (is_link) {
        FILEUnLink($path(fp));
        //  The "blob" for a symlink is its target path; NUL-terminate
        //  in a scratch buffer so $path(target) is C-string-safe.
        a_pad(u8, target, PATH_MAX);
        size_t dl = $len(data);
        if (dl >= u8bIdleLen(target)) dl = u8bIdleLen(target) - 1;
        u8cs trim = {data[0], data[0] + dl};
        u8bFeed(target, trim);
        u8bFeed1(target, 0);
        if (FILESymLink($path(target), $path(fp)) != OK)
            fail(PATCHFAIL);
    } else {
        int fd = -1;
        call(FILECreate, &fd, $path(fp));
        call(FILEFeedAll, fd, data);
        FILEClose(&fd);
        if (is_exe) FILEChmod($path(fp), 0755);
    }

    done;
}

//  Remove `<reporoot>/<relpath>` from disk.  Treats a missing file as
//  success — the net state is the same as if we'd unlinked it.
static ok64 delete_blob(u8cs reporoot, u8csc relpath_in) {
    sane(!$empty(relpath_in));
    a_dup(u8c, relpath, relpath_in);

    a_path(fp);
    call(SNIFFFullpath, fp, reporoot, relpath);
    ok64 o = FILEUnLink($path(fp));
    if (o != OK && o != FILENOENT) return o;
    done;
}

// --- Merge stats ---------------------------------------------------

typedef struct {
    u32   noop;
    u32   take_theirs;
    u32   merged;
    u32   merged_conflict;   // merged bytes contained <<<<<<< markers
    u32   added;
    u32   deleted;
    u32   mod_del_conflict;  // one side deleted, the other modified
    u32   failed;
    //  The patch row's ts, picked up-front in PATCHApply and threaded
    //  through the walk.  Every file write_blob lays down gets stamped
    //  with this ts right after the write, so the ULOG row's ts and
    //  the on-disk mtimes stay in lock-step (stamp-set invariant).
    ron60 ts;
} patch_stats;

//  Stamp the just-written file with the patch row's ts.  Silent on
//  error — callers are best-effort.
static void stamp_wrote(u8cs reporoot, u8cs childpath, patch_stats *st) {
    if (!st || $empty(childpath)) return;
    a_path(fp);
    if (SNIFFFullpath(fp, reporoot, childpath) != OK) return;
    (void)SNIFFAtStampPath(fp, st->ts);
}

//  Scan `bytes` for conflict markers (JOIN emits a literal
//  `<<<<<<<` at column 0).  Any hit → conflict.
static b8 has_conflict_marker(u8cs bytes) {
    u8cp p = bytes[0];
    u8cp e = bytes[1];
    //  Inline token-level markers emitted by JOIN: >>>>theirs||||ours<<<<
    while (p + 4 <= e) {
        if (p[0] == '<' && p[1] == '<' && p[2] == '<' && p[3] == '<')
            return YES;
        p++;
    }
    return NO;
}

// --- Per-level walk ------------------------------------------------

//  Apply the patch recursively.  `dir_path` is the current subtree's
//  repo-relative path (empty at the root).  `fork` is the merge base
//  — `tree(arg.fork_commit)` per VERBS.md §PATCH, computed by the
//  caller as `LCA(arg_parent_tip, thr)`.
static ok64 patch_walk(u8cs reporoot, u8cs dir_path,
                       sha1 const *fork, sha1 const *our, sha1 const *thr,
                       patch_stats *st) {
    sane(fork && our && thr && st);

    Bu8 lbuf = {}, obuf = {}, tbuf = {};
    call(u8bAllocate, lbuf, PATCH_TREE_BUF);
    call(u8bAllocate, obuf, PATCH_TREE_BUF);
    call(u8bAllocate, tbuf, PATCH_TREE_BUF);

    //  Missing-at-commit is not fatal — the dir just didn't exist
    //  on that side, we treat its entry set as empty.
    ok64 lo = fetch_tree(lbuf, dir_path, fork);
    ok64 oo = fetch_tree(obuf, dir_path, our);
    ok64 to = fetch_tree(tbuf, dir_path, thr);
    fprintf(stderr,
            "PATCHDBG walk dir='%.*s' lo=%llx(%zu) oo=%llx(%zu) to=%llx(%zu)\n",
            (int)$len(dir_path), (char *)dir_path[0],
            (unsigned long long)lo, u8bDataLen(lbuf),
            (unsigned long long)oo, u8bDataLen(obuf),
            (unsigned long long)to, u8bDataLen(tbuf));

    entry *le = calloc(PATCH_MAX_ENTRIES, sizeof(entry));
    entry *oe = calloc(PATCH_MAX_ENTRIES, sizeof(entry));
    entry *te = calloc(PATCH_MAX_ENTRIES, sizeof(entry));
    if (!le || !oe || !te) {
        free(le); free(oe); free(te);
        u8bFree(lbuf); u8bFree(obuf); u8bFree(tbuf);
        return PATCHFAIL;
    }
    u32 ln = 0, on = 0, tn = 0;
    {
        a_dup(u8c, lb, u8bData(lbuf));
        a_dup(u8c, ob, u8bData(obuf));
        a_dup(u8c, tb, u8bData(tbuf));
        parse_tree(le, &ln, PATCH_MAX_ENTRIES, lb);
        parse_tree(oe, &on, PATCH_MAX_ENTRIES, ob);
        parse_tree(te, &tn, PATCH_MAX_ENTRIES, tb);
    }
    sort_entries(le, ln);
    sort_entries(oe, on);
    sort_entries(te, tn);

    Bu8 mbuf = {};
    call(u8bAllocate, mbuf, PATCH_BLOB_BUF);

    //  Lockstep walk over three sorted arrays.  At each iteration
    //  we pick the smallest head-of-arrays name, collect the
    //  triple, and advance matching heads.
    u32 li = 0, oi = 0, ti = 0;
    ok64 ret = OK;
    while (ret == OK && (li < ln || oi < on || ti < tn)) {
        u8cs *cand[3] = {
            li < ln ? &le[li].name : NULL,
            oi < on ? &oe[oi].name : NULL,
            ti < tn ? &te[ti].name : NULL,
        };
        u8cs name = {NULL, NULL};
        for (int k = 0; k < 3; k++) {
            if (!cand[k]) continue;
            if ($empty(name) || entry_name_cmp(*cand[k], name) < 0) {
                name[0] = (*cand[k])[0];
                name[1] = (*cand[k])[1];
            }
        }
        entry const *l = NULL, *o = NULL, *t = NULL;
        if (li < ln && entry_name_cmp(le[li].name, name) == 0) l = &le[li++];
        if (oi < on && entry_name_cmp(oe[oi].name, name) == 0) o = &oe[oi++];
        if (ti < tn && entry_name_cmp(te[ti].name, name) == 0) t = &te[ti++];

        //  Compose the child's full relative path into a local buffer.
        a_path(childp);
        if (!$empty(dir_path)) {
            u8bFeed(childp, dir_path);
            if (*u8csLast(dir_path) != '/') u8bFeed1(childp, '/');
        }
        u8bFeed(childp, name);
        PATHu8bTerm(childp);
        a_dup(u8c, childpath, u8bData(childp));

        //  Sniff-meta paths (.sniff, .dogs/*, .git*) never participate
        //  in a 3-way merge: they may sit in legacy trees but PATCH
        //  must not classify or write them.  Skip the entry on every
        //  side; the next POST drops them from the result tree.
        if (SNIFFSkipMeta(childpath)) continue;

        b8 any_dir = (l && l->is_dir) || (o && o->is_dir) ||
                     (t && t->is_dir);
        if (any_dir) {
            //  For MVP: only recurse when all present sides agree
            //  it's a dir.  Mixed blob/tree at the same name is a
            //  type conflict; deferred.
            if ((l && !l->is_dir) || (o && !o->is_dir) ||
                (t && !t->is_dir)) {
                fprintf(stderr,
                    "sniff: patch: type conflict at %.*s — skipped\n",
                    (int)$len(childpath), (char *)childpath[0]);
                st->failed++;
                continue;
            }
            sha1 lsub = l ? l->sha : (sha1){};
            sha1 osub = o ? o->sha : (sha1){};
            sha1 tsub = t ? t->sha : (sha1){};
            //  Subtree-level short-circuit: when all three sides
            //  agree on the subtree sha, every leaf below is XXX-
            //  noop by construction — skip the whole recursion.
            //  Requires all three sides present (a missing side has
            //  a zero sha that would never match a real tree sha).
            if (l && o && t &&
                sha_eq(&lsub, &osub) && sha_eq(&osub, &tsub)) {
                fprintf(stderr,
                        "PATCHDBG short-circuit dir='%.*s'\n",
                        (int)$len(childpath), (char *)childpath[0]);
                continue;
            }
            fprintf(stderr,
                    "PATCHDBG recurse dir='%.*s' l=%d o=%d t=%d\n",
                    (int)$len(childpath), (char *)childpath[0],
                    l ? 1 : 0, o ? 1 : 0, t ? 1 : 0);
            //  If either subtree is missing AND absent on LCA, the
            //  whole subtree is a pure add/delete — for MVP skeleton
            //  we still descend with empty-stand-in.  Real add/delete
            //  handling comes with the structural-delete pass.
            //  Pass the subtree shas unconditionally — absent sides
            //  have zeroed sha1 and fetch_tree returns empty, which
            //  the next level interprets as "dir absent on that side".
            ret = patch_walk(reporoot, childpath,
                             &lsub, &osub, &tsub, st);
            continue;
        }

        //  --- Leaf classification (MVP skeleton) ---
        //  le  oe  te    → action
        //  --  --  --      -----------------------------------
        //   X   X   X    → noop (unchanged on both sides)
        //   X   X   Y    → take theirs
        //   X   Y   X    → noop (ours changed; disk already has it)
        //   X   Y   Z    → merge (Y≠X, Z≠X)
        //   X   Y   Y    → both made same change → noop (== Y==disk)
        //  --   X   X    → noop (present on both; unchanged)
        //  --   --  X    → add theirs
        //  --   X   --   → noop
        //  --   X   Y    → merge (both added different content)
        //  X    --  X    → ours deleted; noop (skeleton defers)
        //  X    --  Y    → modify/delete conflict (defer)
        //  X    X  --    → theirs deleted (defer)
        //  X    Y  --    → modify/delete conflict (defer)

        b8 o_eq_l = l && o && sha_eq(&l->sha, &o->sha);
        b8 t_eq_l = l && t && sha_eq(&l->sha, &t->sha);
        b8 o_eq_t = o && t && sha_eq(&o->sha, &t->sha);

        if (l && o && t && o_eq_l && t_eq_l) {
            //  Unchanged on both sides — skip.
            st->noop++;
            continue;
        }
        if (l && o && t && o_eq_l && !t_eq_l) {
            //  Only theirs changed.  GRAFGet needs the commit sha in
            //  the URI query — `t->sha` is the blob-level entry sha,
            //  so we pass `thr` (the tip commit) and let graf walk
            //  to the blob via the path.
            (void)fetch_blob(mbuf, childpath, thr);
            a_dup(u8c, bytes, u8bData(mbuf));
            ok64 wo = write_blob(reporoot, childpath,
                                 t->mode, bytes);
            if (wo == OK) { st->take_theirs++; stamp_wrote(reporoot, childpath, st); }
            else          st->failed++;
            u8bReset(mbuf);
            continue;
        }
        if (l && o && t && !o_eq_l && t_eq_l) {
            //  Only ours changed — disk already has the right bytes.
            st->noop++;
            continue;
        }
        if (l && o && t && o_eq_t) {
            //  Both made the same change.  Disk has ours already.
            st->noop++;
            continue;
        }
        if (l && o && t && !o_eq_l && !t_eq_l && !o_eq_t) {
            //  Both changed differently → 3-way merge via graf.
            //  Commit-level shas, not the leaf blob shas.
            (void)fetch_merge(mbuf, childpath, our, thr);
            a_dup(u8c, bytes, u8bData(mbuf));
            b8 conflict = has_conflict_marker(bytes);
            //  Write result using theirs' mode when ours == fork mode,
            //  else ours' mode.  MVP: always ours' mode.
            ok64 wo = write_blob(reporoot, childpath,
                                 o->mode, bytes);
            if (wo == OK) {
                stamp_wrote(reporoot, childpath, st);
                if (conflict) {
                    fprintf(stderr,
                        "sniff: patch: CONFLICT (content) %.*s\n",
                        (int)$len(childpath), (char *)childpath[0]);
                    st->merged_conflict++;
                } else {
                    st->merged++;
                }
            } else {
                st->failed++;
            }
            u8bReset(mbuf);
            continue;
        }
        if (!l && !o && t) {
            //  Target added a new file — write it.
            (void)fetch_blob(mbuf, childpath, thr);
            a_dup(u8c, bytes, u8bData(mbuf));
            ok64 wo = write_blob(reporoot, childpath,
                                 t->mode, bytes);
            if (wo == OK) { st->added++; stamp_wrote(reporoot, childpath, st); }
            else          st->failed++;
            u8bReset(mbuf);
            continue;
        }
        if (!l && o && !t) {
            //  Ours added, theirs doesn't know — leave it.
            st->noop++;
            continue;
        }
        if (!l && o && t && !o_eq_t) {
            //  Both added the same path, different content → merge.
            (void)fetch_merge(mbuf, childpath, our, thr);
            a_dup(u8c, bytes, u8bData(mbuf));
            b8 conflict = has_conflict_marker(bytes);
            ok64 wo = write_blob(reporoot, childpath,
                                 o->mode, bytes);
            if (wo == OK) {
                stamp_wrote(reporoot, childpath, st);
                if (conflict) {
                    fprintf(stderr,
                        "sniff: patch: CONFLICT (add/add) %.*s\n",
                        (int)$len(childpath), (char *)childpath[0]);
                    st->merged_conflict++;
                } else {
                    st->merged++;
                }
            } else {
                st->failed++;
            }
            u8bReset(mbuf);
            continue;
        }
        //  Structural: one side absent at leaf, LCA had the path.
        if (l && o && !t) {
            if (sha_eq(&l->sha, &o->sha)) {
                //  Theirs deleted; ours unchanged → delete from wt.
                ok64 d = delete_blob(reporoot, childpath);
                if (d == OK) st->deleted++; else st->failed++;
            } else {
                //  Theirs deleted; ours modified → modify/delete.
                //  MVP: keep ours on disk, log it.
                fprintf(stderr,
                    "sniff: patch: CONFLICT (modify/delete, ours kept) %.*s\n",
                    (int)$len(childpath), (char *)childpath[0]);
                st->mod_del_conflict++;
            }
            continue;
        }
        if (l && !o && t) {
            if (sha_eq(&l->sha, &t->sha)) {
                //  Ours deleted; theirs unchanged → leave deleted.
                st->noop++;
            } else {
                //  Ours deleted; theirs modified → modify/delete.
                //  MVP: materialise theirs on disk + log conflict.
                (void)fetch_blob(mbuf, childpath, &t->sha);
                a_dup(u8c, bytes, u8bData(mbuf));
                ok64 wo = write_blob(reporoot, childpath,
                                     t->mode, bytes);
                if (wo == OK) {
                    stamp_wrote(reporoot, childpath, st);
                    fprintf(stderr,
                        "sniff: patch: CONFLICT (delete/modify, theirs written) %.*s\n",
                        (int)$len(childpath), (char *)childpath[0]);
                    st->mod_del_conflict++;
                } else {
                    st->failed++;
                }
                u8bReset(mbuf);
            }
            continue;
        }
        if (l && !o && !t) {
            //  Both sides removed it — nothing to do on disk.
            st->noop++;
            continue;
        }
    }

    u8bFree(mbuf);
    u8bFree(lbuf); u8bFree(obuf); u8bFree(tbuf);
    free(le); free(oe); free(te);
    return ret;
}

// --- Ref resolution -----------------------------------------------

//  Forward decl: needed by absolutise_query (which calls into the
//  baseline reader) and by resolve_parent_tip below.
static ok64 resolve_current_branch(u8cs out_branch);

//  Materialise the target's absolute branch path when `target_query`
//  uses a relative prefix (`./X`, `../X`, `..`).  On entry `qbuf` is
//  reset; on success `*out_q` is the slice the caller should use for
//  REFS lookup — either pointing into `qbuf` (when relative) or back
//  into the original `target_query` (when absolute / SHA / unparsable).
//  Mirrors sniff/SNIFF.exe.c:sniff_resolve_rel which does the same
//  dance for POST/GET.  Output slice's lifetime matches qbuf's data.
static ok64 absolutise_query(u8cs out_q, u8b qbuf, u8cs target_query) {
    sane(out_q && qbuf);
    u8csMv(out_q, target_query);
    if (u8csEmpty(target_query)) done;

    a_dup(u8c, q_in, target_query);
    qref qspec = {};
    if (QURYu8sDrain(q_in, &qspec) != OK) done;
    if (qspec.type != QURY_REF || qspec.rel == QURY_REL_NONE) done;

    u8cs current = {};
    (void)resolve_current_branch(current);
    u8bReset(qbuf);
    if (QURYBuildAbsolute(qbuf, &qspec, current) != OK) fail(PATCHFAIL);
    u8csMv(out_q, u8bDataC(qbuf));
    done;
}

//  Resolve `target_query` ("heads/main", "tags/v1", or a 40-hex
//  commit sha) to the 20-byte commit sha.  Annotated tags are
//  dereferenced.  Relative refs (`./X`, `../X`, `..`) are absolutised
//  against the wt's current branch before REFS lookup.
static ok64 resolve_target(sha1 *out, u8cs reporoot, u8cs target_query_in) {
    sane(out && u8csOK(target_query_in));

    //  Absolutise `?./X` / `?../X` / `?..` before any further
    //  processing so the rest of the function sees a canonical query.
    //  abs_qbuf must outlive every use of target_query below — keep it
    //  in this stack frame.
    a_pad(u8, abs_qbuf, 256);
    u8cs target_query = {};
    call(absolutise_query, target_query, abs_qbuf, target_query_in);

    //  Full 40-hex input: decode directly.
    if (u8csLen(target_query) == 40) {
        u8 ok_hex = 1;
        for (size_t i = 0; i < 40 && ok_hex; i++) {
            u8 c = target_query[0][i];
            if (!((c >= '0' && c <= '9') ||
                  (c >= 'a' && c <= 'f') ||
                  (c >= 'A' && c <= 'F'))) ok_hex = 0;
        }
        if (ok_hex) {
            u8s sb = {out->data, out->data + 20};
            a_dup(u8c, hx, target_query);
            call(HEXu8sDrainSome, sb, hx);
            //  Dereference annotated tag if present.
            Bu8 cbuf = {};
            call(u8bAllocate, cbuf, 1UL << 16);
            u8 ct = 0;
            ok64 ko = KEEPGetExact(&KEEP, out, cbuf, &ct);
            if (ko == OK && ct == DOG_OBJ_TAG) {
                //  Extract "object <40hex>".
                a_dup(u8c, body, u8bDataC(cbuf));
                u8cs field = {}, value = {};
                a_cstr(obj_kw, "object");
                while (GITu8sDrainCommit(body, field, value) == OK) {
                    if (u8csEmpty(field)) break;
                    if (u8csEq(field, obj_kw) &&
                        u8csLen(value) >= 40) {
                        u8s sb2 = {out->data, out->data + 20};
                        u8cs hx2 = {value[0], value[0] + 40};
                        HEXu8sDrainSome(sb2, hx2);
                        break;
                    }
                }
            }
            u8bFree(cbuf);
            done;
        }
    }

    //  Symbolic ref: look up via REFS.  Compose the lookup URI via
    //  abc/URI — a query-only ref like `?heads/main`.
    a_path(keepdir, reporoot, KEEP_DIR_S);
    a_uri(qkey, 0, 0, 0, target_query, 0);

    a_pad(u8, arena, 512);
    uri resolved = {};
    ok64 ro = REFSResolve(&resolved, arena, $path(keepdir), qkey);

    //  Local lookup miss → retry with `refs/` / `heads/` prefixes
    //  peeled and a `.` authority needle so peer-observed tracking
    //  rows participate.  Mirror of sniff_get's resolution chain.
    if (ro != OK || u8csLen(resolved.query) < 40) {
        char const *strips[] = {"", "heads/", "refs/", "refs/heads/", NULL};
        for (u32 si = 0; strips[si] != NULL &&
                         (ro != OK || u8csLen(resolved.query) < 40); si++) {
            a_dup(u8c, q, target_query);
            a_cstr(strip_s, strips[si]);
            if (!u8csEmpty(strip_s)) {
                if (u8csLen(q) <= u8csLen(strip_s)) continue;
                if (!u8csHasPrefix(q, strip_s)) continue;
                u8csUsed(q, u8csLen(strip_s));
            }
            a_pad(u8, retry_buf, 512);
            a_cstr(dot_q, ".?");
            u8bFeed(retry_buf, dot_q);
            u8bFeed(retry_buf, q);
            a_dup(u8c, retry_uri, u8bDataC(retry_buf));
            memset(&resolved, 0, sizeof(resolved));
            ro = REFSResolve(&resolved, arena, $path(keepdir), retry_uri);
        }
    }
    if (ro != OK) return ro;
    if (u8csLen(resolved.query) < 40) fail(PATCHFAIL);
    u8s sb = {out->data, out->data + 20};
    u8cs hx = {resolved.query[0], resolved.query[0] + 40};
    call(HEXu8sDrainSome, sb, hx);
    done;
}

//  Read the current worktree's branch tip from sniff's ULOG.  The
//  wt's anchor commit (`ours`) lives in the most recent get/post
//  row — patch rows are skipped via SNIFFAtCurTip because their
//  fragment carries `theirs`, not `ours`.
static ok64 resolve_ours(sha1 *out) {
    sane(out);
    ron60 ts = 0, verb = 0;
    uri u = {};
    call(SNIFFAtCurTip, &ts, &verb, &u);
    sha1hex hex = {};
    if (SNIFFAtQueryFirstSha(&u, &hex) != OK) fail(PATCHFAIL);
    call(sha1FromSha1hex, out, &hex);
    done;
}

//  Pull the wt's current absolute branch path from the latest
//  baseline row.  The query carries `<branch>&<sha>...` per dog/QURY;
//  the first qref's body (when type==REF) is the branch path.  On
//  detached / branchless baselines, returns OK with `*out_branch`
//  empty (= trunk).
static ok64 resolve_current_branch(u8cs out_branch) {
    sane(out_branch);
    out_branch[0] = NULL;
    out_branch[1] = NULL;
    ron60 bts = 0, bverb = 0;
    uri bu = {};
    ok64 br = SNIFFAtCurTip(&bts, &bverb, &bu);
    if (br != OK) done;        //  no baseline → trunk
    a_dup(u8c, q, bu.query);
    while (!u8csEmpty(q)) {
        qref spec = {};
        if (QURYu8sDrain(q, &spec) != OK) break;
        if (spec.type == QURY_NONE) {
            if ($empty(q)) break;
            continue;
        }
        if (spec.type == QURY_REF) {
            //  body slice points into the ULOG mmap; same lifetime
            //  as the caller's `bu` reference.  Slices live until
            //  ULOGClose / ULOGTruncate (per SNIFFAtBaseline contract).
            out_branch[0] = spec.body[0];
            out_branch[1] = spec.body[1];
            done;
        }
    }
    done;
}

//  Compute `parent_path` from an absolute branch path: drop the last
//  `/`-segment.  Empty input (trunk) yields empty (which the caller
//  treats as "no parent").  Output slice points into the input.
static void path_parent(u8cs out, u8cs abs_branch) {
    out[0] = abs_branch[0];
    out[1] = abs_branch[0];
    if ($empty(abs_branch)) return;
    u8cp last_slash = NULL;
    $for(u8c, p, abs_branch) {
        if (*p == '/') last_slash = p;
    }
    if (last_slash != NULL) out[1] = last_slash;
}

//  Resolve the target's parent-branch tip sha.  `target_query` is the
//  raw query string PATCHApply received (no leading `?`); we parse it
//  through dog/QURY against the wt's current branch to produce the
//  target's absolute branch path, take its parent (`dirname`), and
//  resolve_target on that.  Returns:
//    OK        — `*out` is the parent tip sha
//    PATCHURELT — target is a sha (no parent branch concept), or the
//                 target is at the trunk (no parent), or the parent
//                 branch can't be resolved.
static ok64 resolve_parent_tip(sha1 *out, u8cs reporoot,
                               u8cs target_query) {
    sane(out);
    qref qspec = {};
    a_dup(u8c, q_in, target_query);
    if (QURYu8sDrain(q_in, &qspec) != OK) return PATCHURELT;
    if (qspec.type != QURY_REF) return PATCHURELT;  //  sha target

    //  Build the target's absolute branch path.
    u8cs current = {};
    (void)resolve_current_branch(current);
    a_pad(u8, abs_buf, 256);
    if (QURYBuildAbsolute(abs_buf, &qspec, current) != OK)
        return PATCHURELT;
    a_dup(u8c, abs_path, u8bData(abs_buf));

    //  Parent path = dirname(abs_path).  An empty abs_path means
    //  the target IS the trunk — there is no parent branch to fork
    //  from, so we cannot derive a fork commit.
    if ($empty(abs_path)) return PATCHURELT;
    u8cs parent = {};
    path_parent(parent, abs_path);

    //  Re-run resolve_target on the parent path's query.  parent
    //  is a slice into abs_buf; copy it into a local pad so the
    //  query bytes are stable for resolve_target's REFSResolve call.
    //  When `parent` is empty (target is a top-level branch like
    //  ?feat), the resolver looks up trunk's tip via the bare `?`
    //  REFS key — which is exactly the target's parent.
    a_pad(u8, par_buf, 256);
    if (!$empty(parent)) call(u8bFeed, par_buf, parent);
    a_dup(u8c, par_q, u8bData(par_buf));
    return resolve_target(out, reporoot, par_q);
}

// --- Public entries -------------------------------------------------

//  Worktree scan: any file whose mtime is not in the ULOG stamp-set
//  counts as dirty.  Mirrors `git merge`'s "your local changes would
//  be overwritten" guard.

static ok64 patch_dirty_report(u8cs rel, void *ctx) {
    sane(ctx);
    enum { MAX_DIRTY_REPORT = 8 };
    u32 *n = (u32 *)ctx;
    (*n)++;
    if (*n <= MAX_DIRTY_REPORT)
        fprintf(stderr, "sniff: patch: dirty %.*s\n",
                (int)$len(rel), (char *)rel[0]);
    return OK;
}

static ok64 refuse_if_dirty(u8cs reporoot) {
    sane($ok(reporoot));
    u32 dirty = 0;
    call(SNIFFAtScanDirty, reporoot, patch_dirty_report, &dirty);
    if (dirty == 0) return OK;
    fprintf(stderr, "sniff: patch: refusing merge — %u dirty file(s). "
                    "stash or commit first.\n", dirty);
    return PATCHDIRTY;
}

//  TODO: PATCH-on-PATCH overlapping files (VERBS.md §PATCH).
//  Today the dirty scan refuses any file that a prior patch touched,
//  so two patches in a row must edit disjoint file sets.  The proper
//  composition is per-file weave-driven:
//
//    1. Seed a weave with the file's full ancestor-closure replay at
//       the wt's base get/post tip (spine).
//    2. For each prior patch row's tip, append the file's full
//       ancestor-closure replay as additional layers (one src per
//       commit, via GRAFFileWeave).
//    3. Render the weave into bytes; if those bytes differ from
//       what's on disk, fold the on-disk bytes in as the next layer
//       (WEAVE_WT_SRC) — captures hand-edits made between patches.
//    4. Append the new patch tip's ancestor-closure replay as the
//       final stack of layers.
//    5. WEAVEEmitMerged → write to disk; conflicts framed by the
//       4-char `<<<<` / `||||` / `>>>>` markers in the usual way.
//
//  Until that lands, the dirty refusal above gates overlapping
//  PATCH-on-PATCH so the user sees a clear error rather than a
//  silently corrupt 3-way against the wrong base.

//  Decode a 40-hex commit sha into `out`.  Returns PATCHFAIL when
//  `hex` is not exactly 40 hex chars.
static ok64 patch_hex40_to_sha1(sha1 *out, u8cs hex) {
    sane(out);
    if ($len(hex) != 40) fail(PATCHFAIL);
    for (size_t i = 0; i < 40; i++) {
        u8 c = hex[0][i];
        b8 ok_hex = (c >= '0' && c <= '9') ||
                    (c >= 'a' && c <= 'f') ||
                    (c >= 'A' && c <= 'F');
        if (!ok_hex) fail(PATCHFAIL);
    }
    u8s sb = {out->data, out->data + 20};
    a_dup(u8c, hx, hex);
    call(HEXu8sDrainSome, sb, hx);
    done;
}

//  Cherry-pick prep: theirs = `frag` (40-hex commit sha), fork =
//  parent(theirs).  Reads theirs's commit body from keeper and parses
//  the first `parent <hex>` field.  Refuses on root commits (no
//  parent).  Caller has already verified `frag` is non-empty.
static ok64 resolve_cherry(sha1 *thr_out, sha1 *fork_out, u8cs frag) {
    sane(thr_out && fork_out);

    ok64 hr = patch_hex40_to_sha1(thr_out, frag);
    if (hr != OK) {
        fprintf(stderr,
            "sniff: patch: #hash must be exactly 40 hex chars\n");
        return hr;
    }

    Bu8 cbuf = {};
    call(u8bAllocate, cbuf, 1UL << 16);

    u8 ct = 0;
    ok64 ko = KEEPGetExact(&KEEP, thr_out, cbuf, &ct);
    if (ko != OK) { u8bFree(cbuf); return ko; }
    if (ct != DOG_OBJ_COMMIT) { u8bFree(cbuf); fail(PATCHFAIL); }

    u8cs body = {u8bDataHead(cbuf), u8bIdleHead(cbuf)};
    u8cs field = {}, value = {};
    b8 found_parent = NO;
    while (GITu8sDrainCommit(body, field, value) == OK) {
        if ($empty(field)) break;
        if ($len(field) == 6 &&
            memcmp(field[0], "parent", 6) == 0 &&
            $len(value) >= 40) {
            u8s sb = {fork_out->data, fork_out->data + 20};
            u8cs hx = {value[0], value[0] + 40};
            HEXu8sDrainSome(sb, hx);
            found_parent = YES;
            break;
        }
    }
    u8bFree(cbuf);

    if (!found_parent) {
        fprintf(stderr,
            "sniff: patch: cherry-pick of root commit unsupported\n");
        fail(PATCHFAIL);
    }
    done;
}

ok64 PATCHApply(u8cs reporoot, u8cs target_query, u8cs frag) {
    b8 cherry = $empty(target_query) && !$empty(frag);
    sane($ok(reporoot) && (cherry || $ok(target_query)));

    call(refuse_if_dirty, reporoot);

    sha1 our_sha = {};
    call(resolve_ours, &our_sha);

    sha1 thr_sha = {};
    sha1 fork_sha = {};

    if (cherry) {
        call(resolve_cherry, &thr_sha, &fork_sha, frag);
    } else {
        call(resolve_target, &thr_sha, reporoot, target_query);
        //  Clamp form (`?branch#hash`): override theirs to the
        //  fragment-supplied sha.  The branch path stays unchanged,
        //  so the resolve_parent_tip / GRAFLca step below still
        //  computes the correct fork — only the upper bound moves
        //  from `tip(branch)` to `hash`.  Reachability of `hash`
        //  from the branch is not validated here yet (TODO); a
        //  hash on a different branch will silently produce a
        //  surprising 3-way result.
        if (!u8csEmpty(frag)) {
            sha1 clamp_sha = {};
            call(patch_hex40_to_sha1, &clamp_sha, frag);
            thr_sha = clamp_sha;
        }
    }

    //  Lazy-index both branches' commit chains into graf so the LCA
    //  query below sees their ancestors.  When the user invoked
    //  `keeper get` directly (no `be get` orchestration), graf hasn't
    //  seen the freshly-fetched commits yet — without this,
    //  `GRAFLca(&our, &thr)` returns 0 and PATCH refuses with
    //  PATCHURELT.  The indexer is idempotent on already-known tips.
    {
        sha1 const *tips[2] = {&our_sha, &thr_sha};
        for (u32 i = 0; i < 2; i++) {
            sha1hex tip_hex = {};
            sha1hexFromSha1(&tip_hex, tips[i]);
            a_rawc(hex_bytes, tip_hex);
            uri tip_uri = {};
            $mv(tip_uri.fragment, hex_bytes);
            $mv(tip_uri.data,     hex_bytes);
            (void)GRAFIndexFromTips(&KEEP, &tip_uri);
        }
    }

    //  Branch-form base resolution.  Cherry-pick already filled
    //  `fork_sha` from theirs's parent edge, so we skip this for
    //  cherry-pick.
    //
    //  Per VERBS.md §PATCH and Invariant 2: the merge base is
    //  `tree(arg.fork_commit)`, the commit on arg's parent branch
    //  where arg was forked.  We model that as
    //  `LCA(arg_parent_tip, arg_tip)` — the most recent shared
    //  ancestor between the parent branch and the target branch.
    //  This excludes ancestor commits already in cur's history,
    //  which a plain `LCA(our, theirs)` would otherwise re-revert.
    //
    //  Fallback: when the target has no parent branch in the dogs
    //  hierarchy (e.g. peer-imported flat git branches), drop down
    //  to `LCA(our, theirs)`.  The WEAVE-based merge engine in graf
    //  no longer needs an exact base — its inrm provenance recovers
    //  the spine — so the fork_sha here only steers the per-path
    //  classification in `patch_walk` (only-ours / only-theirs /
    //  diverged) and is forgiving of an over-inclusive base.
    if (!cherry) {
        sha1 parent_tip = {};
        ok64 pr = resolve_parent_tip(&parent_tip, reporoot, target_query);
        if (pr == OK) {
            call(GRAFLca, &fork_sha, &parent_tip, &thr_sha);
        }
        if (sha1empty(&fork_sha)) {
            //  No parent-branch base, or LCA returned zero.  Fall
            //  back to direct DAG-LCA of ours and theirs.
            call(GRAFLca, &fork_sha, &our_sha, &thr_sha);
        }
    }
    if (sha1empty(&fork_sha)) {
        fprintf(stderr, "sniff: patch: no common ancestor\n");
        fail(PATCHURELT);
    }

    //  Pick the patch row ts up-front.  SNIFFAtNow guarantees
    //  monotonicity against the ULOG tail (tail_ts+1 on tie).  We thread
    //  this ts through patch_walk and stamp each file SNIFFAtStampPath-
    //  style immediately after writing, so the row's ts equals every
    //  written file's mtime — the stamp-set invariant the rest of sniff
    //  (status, POST, the watch daemon) relies on.
    ron60 ts = 0;
    struct timespec tv = {};
    SNIFFAtNow(&ts, &tv);

    patch_stats st = { .ts = ts };
    u8cs root = {NULL, NULL};   // empty dir_path → root tree
    call(patch_walk, reporoot, root,
         &fork_sha, &our_sha, &thr_sha, &st);

    //  Append a `patch` ULOG row.  The row's fragment carries
    //  `theirs` — the absorbed commit's sha.  The wt's anchor
    //  commit (`ours`) is implicit: it lives in the most recent
    //  get/post row and is recovered via SNIFFAtCurTip.  No
    //  `&<theirs>` chain in the query — the chain is reconstructed
    //  by walking the tail of patch rows back to the latest
    //  get/post (SNIFFAtPatchChain), each row contributing its own
    //  `theirs`.  Per-file forensic tracking lives in stamp_wrote
    //  (the row's ts matches every touched file's mtime).
    a_pad(u8, thex, 40);
    a_rawc(tsha, thr_sha);
    HEXu8sFeedSome(thex_idle, tsha);

    uri urow = {};
    {
        a_dup(u8c, h, u8bDataC(thex));
        urow.fragment[0] = h[0];
        urow.fragment[1] = h[1];
    }

    ron60 verb = SNIFFAtVerbPatch();
    (void)SNIFFAtAppendAt(ts, verb, &urow);

    fprintf(stderr,
            "sniff: patch: noop=%u take-theirs=%u merged=%u "
            "added=%u deleted=%u content-conflict=%u mod/del=%u failed=%u\n",
            st.noop, st.take_theirs, st.merged,
            st.added, st.deleted, st.merged_conflict,
            st.mod_del_conflict, st.failed);

    if (st.merged_conflict > 0 || st.mod_del_conflict > 0 ||
        st.failed > 0) {
        return PATCHCFLCT;
    }
    done;
}

ok64 PATCHApplyFile(u8cs reporoot, u8cs filepath,
                    u8cs target_query, u8cs frag) {
    b8 cherry = $empty(target_query) && !$empty(frag);
    sane($ok(reporoot) && $ok(filepath) &&
         (cherry || $ok(target_query)));
    //  Single-file mode: just run a merge on that one path using
    //  graf's 3-way merge — no tree walk, no classification.
    sha1 our_sha = {};
    call(resolve_ours, &our_sha);
    sha1 thr_sha = {};
    if (cherry) {
        sha1 fork_unused = {};
        call(resolve_cherry, &thr_sha, &fork_unused, frag);
    } else {
        call(resolve_target, &thr_sha, reporoot, target_query);
    }

    Bu8 mbuf = {};
    call(u8bAllocate, mbuf, PATCH_BLOB_BUF);
    ok64 mo = fetch_merge(mbuf, filepath, &our_sha, &thr_sha);
    if (mo != OK) { u8bFree(mbuf); return mo; }
    a_dup(u8c, bytes, u8bData(mbuf));
    b8 conflict = has_conflict_marker(bytes);

    //  Mode fallback: reuse whatever's on disk.  Not perfect (a
    //  newly-added file has no on-disk mode yet) — fine for MVP.
    a_cstr(default_mode, "100644");
    ok64 wo = write_blob(reporoot, filepath, default_mode, bytes);
    u8bFree(mbuf);
    if (wo != OK) return wo;
    if (conflict) {
        fprintf(stderr, "sniff: patch: CONFLICT (content) %.*s\n",
                (int)$len(filepath), (char *)filepath[0]);
        return PATCHCFLCT;
    }
    done;
}
