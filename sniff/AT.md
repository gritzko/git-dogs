# sniff attribution log — `<wt>/.sniff`

The worktree's authoritative per-wt state is the ULOG file at
`<wt>/.sniff`.  It is a single plain append-only text file in
`dog/ULOG.md` format:

    <ron60-ms>\t<verb>\t<uri>\n

and it holds everything the worktree needs to know about itself:
which branch it's on, which commits/patches have touched it, which
files are staged-but-not-committed, and (via row timestamps) which
on-disk files are "clean" vs user-edited.

## Row vocabulary

| Verb | URI shape | Stamps files? |
|------|-----------|---------------|
| `repo`   | `file:///abs/path/.dogs/` (row 0 only; worktree → store anchor) | no |
| `get`    | `?<branch>#<sha>` (or `?<sha>` detached)              | yes |
| `post`   | `?<branch>#<sha>` (or `?<sha>` detached)              | yes |
| `patch`  | `?<branch>#<ours>` (single-tip; copies prior query)   | yes |
| `put`    | `<path>`                                              | yes (the staged file) |
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
`.sniff` file in an ancestor as a worktree anchor and records its
dir as `h->wt`; SNIFFOpen reads the `repo` URI to set `h->root`
(the store path where `.dogs/` lives).  For colocated wts the two
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

The most recent `get` / `post` / `patch` row names the current
baseline tree.  The canonical shape is `?<branch>#<curhash>`: the
query carries the absolute branch path (one REF spec per dog/QURY)
and the fragment carries the wt's current 40-hex commit sha.

Per VERBS.md §PATCH and Invariant 2 (linear branches, single-parent
commits), PATCH erases provenance — its row copies the prior
baseline's query verbatim and writes the wt's tip into the fragment.
No `&<theirs>` chain is appended; the baseline stays single-tip
across PATCH and POST.  Per-file forensic tracking of which files
came from a PATCH lives in the row's `ts` (every touched file's
mtime equals the PATCH row's ts), not in the URI query.

Readers that only need "current tip" take the fragment via
`SNIFFAtQueryFirstSha(u, hex40)`.

## Stamp-set

`ULOGHas(mtime)` tests membership in `{row.ts : row ∈ log}`.
Every `get` / `post` / `patch` adds exactly one stamp.  A file's
on-disk mtime matches that set iff sniff wrote the file during one
of those ops and nothing has edited it since.

## Retired pointer-pair

An earlier plan replaced `.sniff` with two cooperating
pointer files — `<wt>/.dogs` and `<branch-dir>/WT` — on the theory
that per-branch single-wt and store-side back-pointers were worth
the split.  That plan is not in the code; `.sniff` is the
whole of the per-wt state and is expected to stay that way.  The
`<store>/ALIAS` + per-branch `REFS` infrastructure on the keeper
side is unchanged.
