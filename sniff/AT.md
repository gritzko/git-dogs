# sniff attribution log — `<wt>/.be/wtlog`

The worktree's authoritative per-wt state is the ULOG file at
`<wt>/.be/wtlog`.  It is a single plain append-only text file in
`dog/ULOG.md` format:

    <ron60-ms>\t<verb>\t<uri>\n

and it holds everything the worktree needs to know about itself:
which branch it's on, which commits/patches have touched it, which
files are staged-but-not-committed, and (via row timestamps) which
on-disk files are "clean" vs user-edited.

## Row vocabulary

| Verb | URI shape | Stamps files? |
|------|-----------|---------------|
| `repo`   | `file:///abs/path/.be/` (row 0 only; worktree → store anchor) | no |
| `get`    | `?<branch>#<sha>` (or `?<sha>` detached)              | yes |
| `post`   | `?<branch>#<sha>` (or `?<sha>` detached)              | yes |
| `patch`  | one of four shapes — see "Patch row shapes" below     | yes |
| `put`    | `<path>`  *or* `<old>#<new>` (move; see below)        | yes (the staged file / move dst) |
| `delete` | `<path>`                                              | no (file unlinked) |
| `mod`    | `<path>`  (watch daemon hint — inotify observed edit) | no |

Stamping every owning row means a file's mtime points back into
the ULOG by ts: `lstat → ron60 → row → verb` is the canonical
classification.  `put` joining the stamping verbs is what enables
"all-changed + some-new" via `be put && be put new1.c && be post`.

### Wall-clock guard

Every sniff command checks `now ≥ last_log_ts` on entry.  If the
system clock has moved backwards (NTP step, suspend/resume drift),
refuse with `CLOCKBAD` rather than write rows whose ts would alias
or precede an existing stamp's owning row.  One ts is reserved
per command, shared by every row + file stamp written.

Version info — branch ref plus tip/merge-participant SHAs — lives in
the URI **query** (`?`-side), parsed by `dog/QURY`.  The **fragment**
(`#`-side) is reserved for content-locator syntax parsed by `dog/FRAG`
(symbol / line / regex / spot).  Never mix SHAs into the fragment: a
query like `bro ?heads/main#func:foo` only makes sense if the `#`-side
is reserved for in-tree navigation.

### Move-form put rows

`put` rows carve out one exception to the fragment rule above.  A
move recorded by `be put <old>#<new>` (or by the bare-put auto-pair
that detects system `mv`) writes its row as `put <old>#<new>` —
path slot = source, fragment slot = the resolved dest path (not a
content-locator).  The trailing-slash dir-target form (`<old>#<dir>/`)
is expanded to `<dir>/<basename(old)>` at row-write time, so the
fragment is always the literal final dest.  Consumers see:

  * `POST` (`sniff/POST.c:post_pd_cb`) expands a put-with-fragment
    row to `del <old>` + `put <new>` intent rows; the merge then
    drops `<old>` from the new tree and adds `<new>` from the wt.
  * Status display (`SNIFF.exe.c`) renders the pair as one `mov`
    line — `<src> -> <dst>` — and suppresses the dest's own
    `WT_ONLY` step by looking up the wt-mtime against the put
    row (`status_wt_is_mov_dst`).
  * `CLASS_pd_cb` preserves the fragment slot when sorting put rows
    into the merge buffer — without that, status couldn't see the
    move at all.

Only the `put` verb carries this overload.  `delete`, `get`, `post`,
`patch`, `mod` keep the fragment as canonical content-locator.

The `mod` rows are advisory: the `sniff watch` daemon appends one
per file whose mtime drifts out of the ULOG stamp-set, dedup'd by
in-memory per-path-idx last-emitted-mtime.  POST may use them as a
fast-path for locating the change-set, but still falls back to the
authoritative wt-scan.  Daemon-generated rows race with foreground
writers; do not run `sniff watch` concurrently with commits unless
the ULOG writer path is protected by a `flock` — currently it is
not (see `dog/ULOG.md` §"No concurrent writers").

Row 0 must be `repo`; no other verb may appear at row 0, and `repo`
must not appear elsewhere.  Walk-up discovery (`dog/HOME`) treats a
`.be/wtlog` file in an ancestor as a worktree anchor and records its
dir as `h->wt`; SNIFFOpen reads the `repo` URI to set `h->root`
(the store path where `.be/` lives).  For colocated wts the two
are the same directory.

"Stamps files" means sniff calls `utimensat` on every file it wrote
during the op with a `struct timespec` derived from the row's `ts`.
A subsequent `lstat` converted back to ron60 (via `SNIFFAtOfTimespec`)
round-trips to exactly the row's `ts`, and `SNIFFAtKnown` answers YES.

## Branch tracking

Whatever branch the wt is on is encoded as the first REF spec in the
query of the most recent `get` / `post` / `patch` row (`heads/main`,
`heads/feat`, ...).  A detached checkout's query has only SHA specs
and no ref.  `SNIFFAtBaseline` parses the latest such row; callers
walk `u.query` with `QURYu8sDrain` to pull out the ref and SHA(s).

## Baseline URI

The most recent `get` / `post` row names the current baseline tree.
The canonical shape is `?<branch>#<curhash>`: query carries the
absolute branch path (one REF spec per dog/QURY), fragment carries
the wt's current 40-hex commit sha.  `patch` rows do **not** redefine
the baseline; they record absorbed work since the last `get`/`post`
and are consumed by the next POST (see "Patch row shapes" below).

Readers that only need "current tip" take the fragment via
`SNIFFAtQueryFirstSha(u, hex40)`.

## Patch row shapes

Per VERBS.md §PATCH, PATCH has four URI shapes; each maps to a row
that POST consumes when assembling the next commit's headers.  All
user inputs (branch names, hashlets, msg-substring searches) are
resolved at PATCH time into the canonical 40-hex sha of the commit
actually applied; the row's query/fragment slot then holds that
sha verbatim (a single `QURY_SHA` spec).  The branch name / search
string is **not** logged — it doesn't survive renames, and POST
doesn't need it to assemble headers.

| User input         | Op           | Patch row URI       | POST consumes as          |
|--------------------|--------------|---------------------|---------------------------|
| `?<br>`            | squash       | `?<sha>`            | one foster header         |
| `#<hashlet>` / `#<msg>` | cherry-pick | `#<sha>`         | `picked` trailer          |
| `?<br>#<msg>`      | merge        | `?<sha>#<msg>`      | parent header + msg       |
| `?<br>#`           | rebase one   | `?<sha>#`           | foster header + reused msg|

Shape classification is by URI form: query-only → squash; non-empty
fragment alongside query → merge; empty-fragment alongside query →
rebase-one; fragment-only → cherry-pick.  The empty-fragment
marker (`#` with no body) is significant and must be preserved by
ULOG writers (`DOGCanonURI` does this already).

A `patch` row whose URI carries a path slot (e.g.
`./<path>?<sha>`) is **path-scoped**: it records the absorbed
bytes for those paths only.  POST emits no header for such rows
and counts them as zero applied commits during message resolution.

Multiple `patch` rows may accumulate between two POSTs; POST scans
forward from the pd boundary (most recent `get`/`post`) and assembles
all foster/parent headers and `picked` trailers in row order.
Per-file forensic tracking of which files came from which PATCH
lives in the row's `ts` (every touched file's mtime equals the row's
ts), not in the URI.

## Stamp-set

`ULOGHas(mtime)` tests membership in `{row.ts : row ∈ log}`.
Every `get` / `post` / `patch` adds exactly one stamp.  A file's
on-disk mtime matches that set iff sniff wrote the file during one
of those ops and nothing has edited it since.

## Retired pointer-pair

An earlier plan replaced `.be/wtlog` with two cooperating
pointer files — `<wt>/.be` and `<branch-dir>/WT` — on the theory
that per-branch single-wt and store-side back-pointers were worth
the split.  That plan is not in the code; `.be/wtlog` is the
whole of the per-wt state and is expected to stay that way.  The
`<store>/ALIAS` + per-branch `REFS` infrastructure on the keeper
side is unchanged.
