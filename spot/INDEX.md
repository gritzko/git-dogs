# spot/ — code search, replace, grep

Spot is a producer of hunks for search results. Display lives in
[bro/](../bro/INDEX.md). Diff and merge live in
[graf/](../graf/INDEX.md). When stdout is a tty, spot forks bro as
a pager and writes TLV hunks (see [dog/HUNK.h](../dog/HUNK.h)) to
the pipe. Otherwise it writes plain ASCII directly to stdout via
`HUNKu8sFeedText`.

## Headers

| Header | Purpose |
|--------|---------|
| CAPO.h | Main API: index, search, grep |
| CAPOi.h | Internal: shared helpers, CAPOFindExt macro, HIT u64cs template |
| LESS.h | Producer staging: scratch arena, `spot_out_fd`, `spot_emit`, `LESSHunkEmit` |
| SPOT.h | Structural pattern matching: tokenize, init, next, replace |

## Source files

| File | Purpose |
|------|---------|
| CAPO.c | Index management, SPOT search, hunk-building helpers |
| GREP.c | Substring grep (CAPOGrep), regex grep (CAPOPcreGrep) |
| CAPO.cli.c | CLI entry point: arg parsing, fork bro, pick `spot_emit` |
| LESS.c | Staging arena + `LESSHunkEmit` (serialize via `spot_emit` → `spot_out_fd`) |
| SPOT.c | SPOT pattern matching engine, needle flattening, replacement |

## Key functions (CAPO.h)

| Function | Purpose |
|----------|---------|
| `CAPOSpot` | Structural search (and replace) across repo |
| `CAPOGrep` | Substring grep with syntax-highlighted context (GREP.c) |
| `CAPOPcreGrep` | Regex grep via Thompson NFA + trigram filtering (GREP.c) |
| `CAPOCompact` / `CAPOCompactAll` | Compact LSM index runs |
| `CAPOResolveDir` | Resolve `<workspace>/.dogs/spot` dir |
| `CAPOIndexBlob` | Tokenize a streaming blob, emit `spot64` postings keyed by precomputed `path_h20` (truncated full-path RAP) |
| `CAPOIndexFile` | Search-time wrapper: hash full repo-relative path, delegate to `CAPOIndexBlob` |
| `CAPOFnRap20` | `RAPHash(full_path) & ((1<<20)-1)` — the 20-bit posting key |
| `SPOTIndexFromTips` | `spot get URI` entry — walks tip tree(s) via keeper, dedups against the BLOBFN memo, tokenises new (blob, path) pairs |

Ingestion is driven by `spot get URI` (DOG.md §10a): under the new
arrangement `be get URI` spawns spot in parallel with keeper, and
spot walks the URI's tip(s) over keeper's read APIs (KEEPLsFiles +
KEEPGetExact).  For each leaf blob with a tokenizable extension:

- Compute `blob_hl40 = WHIFFHashlet40(blob_sha)` and
  `path_h20 = CAPOFnRap20(full_repo_relative_path)`.
- Look up the `BLOBFN` memo (`off=blob_hl40, type=BLOBFN, id=path_h20`)
  in the open LSM runs.  A hit means we already indexed this exact
  (blob, path) pair on a prior walk — skip.
- Otherwise pull the blob via `KEEPGetExact`, tokenise via
  `CAPOIndexBlob` keying postings on `path_h20`, then emit a fresh
  `BLOBFN` row so the next walk can short-circuit.

Renames are caught automatically: same blob bytes + new path → new
`path_h20` → no memo hit → re-tokenise under the new path.  No
TREE/BLOB chain, no buffering, no order assumptions.

Historic search (`spot … ?ref`) goes through `CAPOScanRef`: resolves
the ref via keeper, walks the tree, pulls each blob-of-matching-ext,
and runs the usual grep/pcre/snippet callbacks on the blob content.
`spot --replace` is refused when `?ref` is set (no on-disk file).

Worktree search uses the path-RAP filter for speed: paths whose
full-path `fn_rap20` carries no needle-trigram entry are skipped.
Two paths sharing a 20-bit bucket both pass the filter and the
worktree scan rescans each.  Strictly-untracked brand-new files
with novel trigrams stay candidates as long as their full path
hashes into the indexed posting set.

## Key functions (SPOT.h)

| Function | Purpose |
|----------|---------|
| `SPOTTokenize` | Tokenize source into packed u32 buffer via tok/ |
| `SPOTInit` | Initialize pattern matcher (tokenizes needle) |
| `SPOTNext` | Find next structural match (OK or SPOTEND) |
| `SPOTReplace` | Apply replacement to all matches in one file |

## Internal helpers (CAPO.c, static)

| Function | Purpose |
|----------|---------|
| `CAPOFindFunc` | Walk backward to find enclosing function name |
| `CAPOGrepCtx` | Compute context line range around a byte position |

## Index format

Index lives in `.dogs/spot/*.spot.idx` (under the workspace's
`.dogs/`).  Each entry is one `wh64` (see `dog/WHIFF.h`) with the
layout

```
[ off:40 | id:20 | type:4 ]   (high → low, natural u64 sort)
```

| `type` | `off` payload | `id` payload |
|--------|---------------|--------------|
| `SPOT_TRI`    (0) | 18-bit packed RON64 trigram (top 22 bits zero) | `path_h20` |
| `SPOT_MEN`    (1) | `RAPHash(symbol_name) & ((1<<40)-1)` (S/C tags) | `path_h20` |
| `SPOT_DEF`    (2) | `RAPHash(symbol_name) & ((1<<40)-1)` (N tag)    | `path_h20` |
| `SPOT_BLOBFN` (3) | `WHIFFHashlet40(blob_sha)`                       | `path_h20` (memo: this blob lived at this path) |
| 4..15             | reserved                                         |              |

`id` carries the 20-bit basename hash for every record type — the
worktree-side filter picks files whose basename hashes into the
posting set.  Sorting clusters by `off` first (so range-scan by an
`off`-prefix is a contiguous `1<<24` window), then by `id`, then by
`type`.  Within an off-block the iterator filters by `type` to pick
out TRI vs MEN vs DEF (rare cross-type collisions when a symbol
hash's top 22 bits happen to match a trigram value).

The `BLOBFN` record is the dedup memo: `(blob_hl40, path_h20)`
records "this blob has been indexed at this full path".  When a blob
shows up at multiple paths (rename, copy, vendored duplicate), every
path gets its own row, and the tip-walker's per-blob lookup uses an
exact-key bsearch on `wh64Pack(SPOT_BLOBFN, path_h20, blob_hl40)` to
short-circuit unchanged (blob, path) pairs without re-tokenisation.

### LSM stack

- **In-RAM** : a `BOXu64` memtable over a 128 KB mmap (1 KB dirty +
  1, 2, 4, 8, 16, 32, 64 KB sorted ladder).  Ratio is 2× — every
  cascade fills its target chunk exactly (1/2 + 1/4 + … = 1), so no
  intermediate-level slack.  `CAPOEmit` feeds postings; cascade is
  automatic.  `BOXFULL` triggers `CAPOFlushRun`.
- **On-disk**: sorted runs in `<seqno>.spot.idx` files; the standard
  puppy 1/8 ladder.  `CAPOFlushRun` is `BOXu64Flush → DOGPupCreate
  → CAPOCompact`.  The BOX's 2× ratio differs from the disk side's
  8× — they don't need to align since flushed runs go through
  `MSETCompact` anyway.
- **Lookups** see the BOX's sorted slices alongside disk puppies via
  `CAPOStackOpen`; the BOX's dirty region (unsorted, ≤ 1 KB) is
  excluded — searches that need it run after `CAPOFlushRun`.
