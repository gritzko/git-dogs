# sniff — worktree management

Checkout, status, stage, commit.  State is a single append-only
ULOG file at `<wt>/.sniff`; no pack files, no caches, no path
registry (keeper owns paths).  The worktree's files-on-disk plus the
ULOG plus keeper's object store are the ground truth.

Worktrees may share a store: each wt has its own `.sniff` but the
`repo` row (row 0) points them all at the same `.dogs/`.  Colocated
wts set it to their own sibling `.dogs/`; secondary wts set it to
the primary's store.

## The one-paragraph model

Every row sniff writes (`get`, `post`, `patch`, `put`) stamps
its files with the row's ts via `utimensat`.  A file's mtime is
therefore a pointer back into the ULOG: lookup-by-ts identifies
the row that owns the file's content.  ∉ stamp-set means the
user edited it since.  POST walks the wt, classifies each file
via stamp lookup, emits one keeper pack `commit → trees → blobs`,
stamps every surviving wt file with the new post row's ts, and
appends a `post` row.  Per VERBS.md Invariant 2, every commit POST
emits is single-parent — PATCH absorbs without recording provenance
(history erased), so the parent of the new commit is always cur's
prior tip.

## Wall-clock guard

Every sniff command checks `now ≥ last_log_ts` on entry and
refuses with `CLOCKBAD` if the system clock has moved backwards.
One ts is reserved per command, shared by every row + file
stamp it writes.

## Change-set at commit time

For each candidate path, look up the on-disk mtime in the ULOG:

| `mtime` lookup       | Selective (any put/delete in scope) | Implicit |
|----------------------|------------------------------|----------|
| `< last_get_ts`      | KEEP (untouched since reset) | KEEP |
| `get` / `post` row   | KEEP (baseline content)      | KEEP |
| `patch` row          | REWRITE (merged bytes)       | REWRITE (merged bytes) |
| `put` row            | REWRITE (current bytes)      | REWRITE (current bytes) |
| ∉ stamp-set          | ignore unless explicit `put` named it (warn if so; current bytes win) | REWRITE (auto-stage) |
| `delete <path>` row  | DROP (file already unlinked at `be delete` time) | DROP |

Parents = `[ours]` — single-parent per VERBS.md Invariant 2.
PATCH-merged content contributes to the new tree but **not** to the
parent set; provenance is erased at PATCH time.  Cross-branch
deduplication (when cur eventually flows toward trunk) relies on
patch-id matching, not recorded parents.

### Boundaries in `.sniff`

  * **pd boundary** = most recent `get` *or* `post` row.  `put` /
    `delete` rows after this are in scope.
  * **patch boundary** = most recent `get` *or* commit-all `post`.
    `patch` rows after this are in scope.

A `post` row is commit-all iff no put/delete rows lie between its
own pd boundary and itself.  Detected on the fly during a forward
scan; no new ULOG verb required.

## Headers

| Header | Role |
|--------|------|
| SNIFF.h | Singleton state (open/close, ULOG handle), `SNIFFFullpath` path joiner. |
| AT.h | ULOG façade: verb constants (`SNIFFAtVerbGet/Post/Patch/Put/Delete`), append (`SNIFFAtAppend`, `SNIFFAtAppendAt`), baseline/post-ts/scan lookups (`SNIFFAtBaseline`, `SNIFFAtLastPostTs`, `SNIFFAtScanPutDelete`), stamp I/O (`SNIFFAtNow`, `SNIFFAtStampPath`, `SNIFFAtOfTimespec`, `SNIFFAtKnown`).  Wt path enumeration: `SNIFFWtListPaths` (sorted via `FILEScanSorted` + `FILEentryZ`, mirrors `KEEPTreeListLeaves` shape — `(paths, kinds)` ready to feed `KEEPu8ssDrain`). |
| GET.h | Checkout: resolve baseline tree from latest get/post/patch row, run a 2-input merge (`KEEPTreeListLeaves` + `KEEPu8ssDrain`) against the target tree to classify each path as no-op overlay / real change / add / delete; refuse on dirty ∩ real-change.  Then walk target via keeper → materialise files (skipping no-op overlays so dirty wt content is preserved), futimens every write to a shared ts.  Prune: drain the merge's clean-baseline-only list, unlinking each entry — no wt scan, no path-bitmap.  Finally append one `get` row. |
| PUT.h | `put <path>` — one row per URI, no pack I/O, no tree work. |
| DEL.h | `delete <path>` — mirror of PUT. |
| POST.h | Commit: resolve baseline URI to a tree sha; classify per-path via a 2-input merge (`KEEPTreeListLeaves` baseline ↔ `SNIFFWtListPaths` wt) through `KEEPu8ssDrain`; ULOG put/delete rows layered on top.  Compute change-set per the rules above, pre-hash blobs, build dirty-spine trees, emit one pack `commit → trees → blobs`, advance keeper REFS, unlink explicit-deletes, append `post` row, stamp surviving files.  `POSTPromote` (no-msg `be post ?<X>`) routes per VERBS.md §POST: `?..` upstream auto-sync, `?./fix` promote-into-child, `?./newleaf` create-on-miss, `?<absolute>` peer/upstream promote, `?<absolute>/<newleaf>` create-leaf-under-existing (rebase cur's stack onto absolute parent), `?<absolute>/` trailing-slash basename reuse (rewrite to `?<absolute>/<basename(cur)>`) — operates on REFS via `REFSCompareAndAppend` + cascade walker. |
| PATCH.h | 3-way wt merge via graf with `base = tree(arg.fork_commit) = LCA(arg_parent_tip, arg_tip)`, `ours = cur.tip`, `theirs = arg.tip`; `refuse_if_dirty` is a wt-scan against the stamp-set.  On success appends a `patch` row that copies the prior baseline's query verbatim and records `ours` in the fragment — single-tip baseline, no `&<theirs>` chain (history erased per VERBS.md §PATCH). |

## CLI (`sniff`)

| Command | Effect |
|---------|--------|
| `sniff get <hex>` | Checkout commit (alias `checkout`) |
| `sniff put [files]` | Append `put <path>` rows (no-op without args) |
| `sniff delete [files]` | Append `delete <path>` rows (no-op without args) |
| `sniff post -m <msg>` | Commit (alias `commit`).  Auto-selects change-set per the rules above. |
| `sniff patch ?<ref>` | 3-way merge into wt |
| `sniff status` | List mtime-dirty files (M) |
| `sniff list` | List keeper-interned paths |
| `sniff watch` | Start the inotify daemon (fork, pidfile at `.sniff.pid`).  Appends one `mod <relpath>` row to `.sniff` for every file whose mtime leaves the stamp-set.  Dedup'd per-path so repeated edits to the same file share one row until a commit stamps it clean. |
| `sniff stop` | Stop the watch daemon |

Flags: `-m <msg>` commit message, `--author <who>` author string.

## On-disk layout

Per worktree (at the wt root):

| Path | Format |
|------|--------|
| `.sniff` | `<ron60-ts>\t<verb>\t<uri>\n` — see `dog/ULOG.md`.  Row 0 is a `repo` anchor whose `file://` URI names the store.  Subsequent rows are `get`/`post`/`patch`/`put`/`delete`. |
| `.sniff.pid` | Watch daemon PID (if `sniff watch` is running; dead weight in the ULOG-only model and may be retired). |

Nothing else.  The store (`.dogs/`) is the keeper's; sniff never
writes there directly — it hands objects to keeper via `KEEPPackFeed`.

## Tests

C (`test/SNIFF.c`):

| Test | What |
|------|------|
| `SNIFFAtHelpers` | Verb constants are distinct; empty-log invariants; seeded-log baseline pick (most recent get/post/patch with multi-hash fragment recognised); stamp-set membership; last-post-ts lookup; `SNIFFAtScanPutDelete` forward-scan across different floors. |
| `SNIFFCheckoutCommit` | Hand-built initial commit → `GETCheckout` → modify file → `POSTCommit` produces a new commit object keeper can retrieve (verifies the full GET + POST integration on the ULOG-only path). |

Scripts:

| Script | Scope |
|--------|-------|
| `test/workflow.sh` (`SNIFFworkflow`) | The 6 canonical scenarios against the `sniff` CLI: initial post, get, accumulating put+post, implicit all-dirty via bare post, explicit delete, implicit-delete via vanished file. |
| `../beagle/test/workflow.sh` (`BEworkflow`) | Same scenarios through the `be` dispatcher — covers keeper + spot + graf pipeline wiring. |
| `../beagle/test/history.sh` (`BEhistory`) | Three tagged commits with a delete and an add, then round-trip every tag through `be get` and verify files appear and disappear.  This is the regression that motivated the rewrite — the old per-path cache incorrectly re-added deleted files across processes; mtime attribution fixes it architecturally. |

## Dependencies

Links `keeplib`, `gitcompat`, `dog`, `abc-core`.  Uses `abc/FSW` for
inotify in the `watch` daemon.
