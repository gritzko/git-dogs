//  PATCH: 3-way worktree merge via graf.
//
//  See PATCH.h for the public surface.  Implementation walks three
//  trees (lca, ours, theirs) in tandem by fetching tree bytes via
//  graf for each directory level, classifies every leaf path by
//  the {lca, ours, theirs} sha triple, and applies a worktree
//  action.  Merged bytes come from `GRAFGet <path>?<ours>&<theirs>`;
//  pass-through bytes come from `GRAFGet <path>?<theirs>`.  Sniff
//  never reads keeper directly here.
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
    while (n < cap && GITu8sDrainTree(obj, file, esha) == OK) {
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
        memcpy(e->sha.data, esha[0], 20);
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
        PATHu8sDir(&dir, relpath);
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
        unlink((char *)u8bDataHead(fp));
        //  The "blob" for a symlink is its target path; NUL-terminate
        //  by copying into a scratch buffer.
        char target[PATH_MAX];
        size_t dl = $len(data);
        if (dl >= sizeof(target)) dl = sizeof(target) - 1;
        memcpy(target, data[0], dl);
        target[dl] = 0;
        if (symlink(target, (char *)u8bDataHead(fp)) != 0)
            fail(PATCHFAIL);
    } else {
        int fd = -1;
        call(FILECreate, &fd, $path(fp));
        call(FILEFeedAll, fd, data);
        FILEClose(&fd);
        if (is_exe) chmod((char *)u8bDataHead(fp), 0755);
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
//  repo-relative path (empty at the root).
static ok64 patch_walk(u8cs reporoot, u8cs dir_path,
                       sha1 const *lca, sha1 const *our, sha1 const *thr,
                       patch_stats *st) {
    sane(lca && our && thr && st);

    Bu8 lbuf = {}, obuf = {}, tbuf = {};
    call(u8bAllocate, lbuf, PATCH_TREE_BUF);
    call(u8bAllocate, obuf, PATCH_TREE_BUF);
    call(u8bAllocate, tbuf, PATCH_TREE_BUF);

    //  Missing-at-commit is not fatal — the dir just didn't exist
    //  on that side, we treat its entry set as empty.
    (void)fetch_tree(lbuf, dir_path, lca);
    (void)fetch_tree(obuf, dir_path, our);
    (void)fetch_tree(tbuf, dir_path, thr);

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
            //  Write result using theirs' mode when ours == lca mode,
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

//  Resolve `target_query` ("heads/main", "tags/v1", or a 40-hex
//  commit sha) to the 20-byte commit sha.  Annotated tags are
//  dereferenced.
static ok64 resolve_target(sha1 *out, u8cs reporoot, u8cs target_query) {
    sane(out && $ok(target_query));

    //  Full 40-hex input: decode directly.
    if ($len(target_query) == 40) {
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
                u8cs body = {u8bDataHead(cbuf), u8bIdleHead(cbuf)};
                u8cs field = {}, value = {};
                while (GITu8sDrainCommit(body, field, value) == OK) {
                    if ($empty(field)) break;
                    if ($len(field) == 6 &&
                        memcmp(field[0], "object", 6) == 0 &&
                        $len(value) >= 40) {
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
    call(REFSResolve, &resolved, arena, $path(keepdir), qkey);
    if ($len(resolved.query) < 40) fail(PATCHFAIL);
    u8s sb = {out->data, out->data + 20};
    u8cs hx = {resolved.query[0], resolved.query[0] + 40};
    call(HEXu8sDrainSome, sb, hx);
    done;
}

//  Read the current worktree's branch tip from sniff's ULOG.  The
//  baseline URI's query carries one REF plus one or more SHAs
//  (dog/QURY); "ours" is always the first 40-hex SHA spec — later
//  SHAs are merge participants layered on top by prior `patch` rows.
static ok64 resolve_ours(sha1 *out) {
    sane(out);
    ron60 ts = 0, verb = 0;
    uri u = {};
    call(SNIFFAtBaseline, &ts, &verb, &u);
    u8 hex40[40];
    if (SNIFFAtQueryFirstSha(&u, hex40) != OK) fail(PATCHFAIL);
    u8s sb = {out->data, out->data + 20};
    u8cs head = {hex40, hex40 + 40};
    call(HEXu8sDrainSome, sb, head);
    done;
}

// --- Public entries -------------------------------------------------

//  Worktree scan: any file whose mtime is not in the ULOG stamp-set
//  counts as dirty.  Mirrors `git merge`'s "your local changes would
//  be overwritten" guard.  Metadata entries (`.sniff`, `.dogs`) are
//  skipped via SNIFFSkipMeta.

typedef struct { u32 dirty; u8cs reporoot; } dirty_ctx;

static ok64 dirty_scan_cb(void *varg, path8bp path) {
    sane(varg && path);
    dirty_ctx *c = (dirty_ctx *)varg;
    enum { MAX_DIRTY_REPORT = 8 };

    a_dup(u8c, full, u8bData(path));
    u8cs rel = {};
    if (!SNIFFRelFromFull(&rel, c->reporoot, full)) return OK;
    if (SNIFFSkipMeta(rel))                         return OK;

    struct stat sb = {};
    if (lstat((char const *)full[0], &sb) != 0) return OK;
    struct timespec ts = {.tv_sec = sb.st_mtim.tv_sec,
                          .tv_nsec = sb.st_mtim.tv_nsec};
    ron60 r = SNIFFAtOfTimespec(ts);
    if (SNIFFAtKnown(r)) return OK;
    c->dirty++;
    if (c->dirty <= MAX_DIRTY_REPORT)
        fprintf(stderr, "sniff: patch: dirty %.*s\n",
                (int)$len(rel), (char *)rel[0]);
    return OK;
}

static ok64 refuse_if_dirty(u8cs reporoot) {
    sane($ok(reporoot));
    dirty_ctx ctx = {.dirty = 0};
    ctx.reporoot[0] = reporoot[0];
    ctx.reporoot[1] = reporoot[1];
    a_path(root_path);
    u8bFeed(root_path, reporoot);
    call(PATHu8bTerm, root_path);
    call(FILEScan, root_path,
         (FILE_SCAN)(FILE_SCAN_FILES | FILE_SCAN_LINKS | FILE_SCAN_DEEP),
         dirty_scan_cb, &ctx);
    if (ctx.dirty == 0) return OK;
    fprintf(stderr, "sniff: patch: refusing merge — %u dirty file(s). "
                    "stash or commit first.\n", ctx.dirty);
    return PATCHDIRTY;
}

ok64 PATCHApply(u8cs reporoot, u8cs target_query) {
    sane($ok(reporoot) && $ok(target_query));

    call(refuse_if_dirty, reporoot);

    sha1 our_sha = {};
    call(resolve_ours, &our_sha);

    sha1 thr_sha = {};
    call(resolve_target, &thr_sha, reporoot, target_query);

    sha1 lca_sha = {};
    call(GRAFLca, &lca_sha, &our_sha, &thr_sha);
    {
        u8 zero[20] = {};
        if (memcmp(lca_sha.data, zero, 20) == 0) {
            fprintf(stderr, "sniff: patch: no common ancestor\n");
            fail(PATCHURELT);
        }
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
         &lca_sha, &our_sha, &thr_sha, &st);

    //  Append a `patch` ULOG row.  Canonical at-log shape is
    //  `?<branch>#<curhash>` everywhere; `patch` extends the query
    //  with `&<theirs>` so the next `post` (squash-merge) finds the
    //  extra parent commit there.  Result: `?<branch>&<theirs>#<ours>`.
    uri baseline_u = {};
    {
        ron60 bts = 0, bverb = 0;
        ok64 br = SNIFFAtBaseline(&bts, &bverb, &baseline_u);
        if (br != OK) {
            //  No prior baseline: rare (you can't patch into a fresh
            //  worktree), but be defensive — emit `?#<ours>` with no
            //  branch and `theirs` chained below.
            memset(&baseline_u, 0, sizeof(baseline_u));
        }
    }

    //  Build the query: copy prior baseline query (branch + any prior
    //  `&<theirs>` chain), then append the new `&<theirs>`.
    a_pad(u8, qbuf, 512);
    if (!u8csEmpty(baseline_u.query)) {
        u8cs oldq = {baseline_u.query[0], baseline_u.query[1]};
        u8bFeed(qbuf, oldq);
    }
    u8bFeed1(qbuf, '&');
    a_pad(u8, thex, 40);
    a_rawc(tsha, thr_sha);
    HEXu8sFeedSome(thex_idle, tsha);
    u8bFeed(qbuf, u8bDataC(thex));

    //  Fragment carries `ours` — the current tree the wt is on.
    a_pad(u8, ohex, 40);
    a_rawc(osha, our_sha);
    HEXu8sFeedSome(ohex_idle, osha);

    uri urow = {};
    {
        a_dup(u8c, q, u8bData(qbuf));
        urow.query[0] = q[0];
        urow.query[1] = q[1];
    }
    {
        a_dup(u8c, h, u8bDataC(ohex));
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

ok64 PATCHApplyFile(u8cs reporoot, u8cs filepath, u8cs target_query) {
    sane($ok(reporoot) && $ok(filepath) && $ok(target_query));
    //  Single-file mode: just run a merge on that one path using
    //  graf's 3-way merge — no tree walk, no classification.
    sha1 our_sha = {};
    call(resolve_ours, &our_sha);
    sha1 thr_sha = {};
    call(resolve_target, &thr_sha, reporoot, target_query);

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
