# graf/ — token-level diff, merge, blame, history indexing

`graf` is a dog: it owns `.dogs/graf/` under a repo root and speaks
the four-function contract from [dog/DOG.md](../dog/DOG.md) §8
(`DOGOpen` / `DOGExec` / `DOGUpdate` / `DOGClose`).

Indexing is **streaming**: keeper feeds every commit/tree/blob it
ingests into `GRAFUpdate(obj_type, blob, path)`.  graf parses
commit headers, caches trees, and emits `wh128` DAG entries into
LSM-sorted runs.  No git CLI is ever invoked; no `.git/` is ever
read.  The only source of object data is keeper's pack store.

## Verbs

```
graf get    path?sha1[&sha2...]    URI-driven deterministic blob merge
graf diff   old new                token-level colored diff (files on disk)
graf merge  base ours theirs       3-way merge; -o <file> to write out
graf blame  path                   token-level blame (reads keeper + DAG)
graf weave  path?from..to          weave diff across a ref range
graf log    [path]?ref[#N]         commit history, one per line
graf index                         no-op; indexing is pushed by keeper
graf status                        index run/entry counts
```

## Files

| File          | Purpose |
|---------------|---------|
| `GRAF.h`      | Singleton state, arena, `graf_emit`, public API. Phase 3 adds `GRAFOpenBranch(h, branch, rw)` — trunk-only, returns `GRAFNOBR` for anything else |
| `GRAF.c`      | `GRAFOpen` / `GRAFOpenBranch` / `GRAFUpdate` / `GRAFClose`, arena init, `GRAFHunkEmit` |
| `GRAF.exe.c`  | `GRAFExec` — verb dispatch (get / diff / merge / blame / weave / index / status) |
| `GRAF.cli.c`  | `main()` — parse argv, open singleton, call `GRAFExec` |
| `BLOB.{h,c}`  | `GRAFTreeStep` / `GRAFBlobAtCommit` — shared (commit, path)→blob resolution via keeper, used by BLAME and GET |
| `DAG.{h,c}`   | LSM of `wh128` records under `.dogs/graf/` driven by `GRAFUpdate`. Types: COMMIT_GEN, COMMIT_PARENT, COMMIT_TREE, PATH_VER. PATH_VER keys on 40-bit `RAPHash(path)`; collisions verified by query-side keeper tree-walk. graf caches freshly-ingested blobs + trees per session; at `GRAFClose` it walks each new commit's root tree top-down and emits PATH_VER for leaves whose blob was freshly delivered. Also hosts shared graph helpers `DAGAncestors` / `DAGAncestorsOfMany` / `DAGPathVers` used by both BLAME and GET |
| `GET.c`       | `GRAFGet(u8b into, u8csc uri)` — URI-driven deterministic blob/tree merge. Blob mode (`file?sha1&sha2`): N=1 identity via `GRAFBlobAtCommit`; **N=2 true 3-way merge** via `get_lca` (DAG ancestor intersection, max-gen) + `JOINMerge`; N≥3 falls back to a weave-union approximation (`DAGAncestorsOfMany`, `DAGPathVers`, linear oldest-first replay). Tree mode (`dir/?sha1&sha2`, `/?sha...` for root): resolves each tip's tree at `path`, unions child names across tips, recurses via GRAFGet on disagreeing children (hashing merged bytes as blob or tree via `KEEPObjSha`), emits git-tree-format bytes (`<mode> <name>\0<20-byte sha>`) sorted bytewise by name — see graf/GET.md |
| `JOIN.{h,c}`  | `JOINTokenize` / `JOINMerge` — 3-way merge primitive over u64-hash token streams via abc/DIFFx LCS |
| `REBASE.{h,c}` | Linear-history replay primitives for the upcoming POST rewrite (Stage 2): `GRAFPatchId(commit_body)` (stable u64 diff-id vs first parent, RAPHashSeed-folded over sorted (path, parent_sha, child_sha) tuples; 0 for root/empty/error so dedup never matches), `GRAFMergeExplicit(base, ours, theirs, out)` (3-way blob merge via `KEEPGetExact` + `JOINMerge`, base supplied directly — bypasses LCA walk), `GRAFRebase(base_old, base_new, child_tip, cb, ctx)` (replay child_tip → base_old onto base_new, oldest-first, patch-id dedup against base_new ancestors, conflict aborts with `GRAFCNFL`, all object emission goes through caller-supplied `graf_rebase_emit_cb`). Keeper-read-only — no DAG dependency, no keeper mutation |
| `TDIFF.{h,c}` | Token-level diff: LCS on RAPHash, NEIL cleanup, emits hunks via `HUNKcb`.  Pure — no globals, no IO |
| `NEIL.{h,c}`  | Edit-list semantic cleanup: removes false short equalities, lossless boundary shifts |
| `DIFF.c`      | `GRAFDiff` — maps two files, calls `DIFFu8cs` with `GRAFHunkEmit` as callback |
| `MERGE.c`     | `GRAFMerge` — 3-way merge using `JOIN`, writes resolved bytes to file or stdout |
| `BLAME.c`     | `GRAFFileWeave` (shared file-history weave builder: ancestor-closure walk, byte-dedup, optional wt-as-final-layer with `WEAVE_WT_SRC`, per-layer step callback) + `GRAFBlame` (renders attribution rows over the built weave) + `GRAFWeaveDiff` |
| `WEAVE.{h,c}` | Double-buffered weave of token versions with intro/del gens; `WEAVEEmitDiff` walks a built weave and emits one HUNK with `I`/`D`/` ` hili spans per token, classified by caller-supplied `(in_from, in_to)` reachability predicates |
| `LOG.c`       | `GRAFLog` — `be log:[path]?ref[#N]` projector. Branch history walks COMMIT_PARENT via the DAG index; file history (`./path/file?ref`) reads PATH_VER under the tip's ancestor set. Commit body fetched from keeper for the `<sha7> <date> <author> <summary>` render |

## Pager

When diff/weave/blame runs with a tty stdout, graf forks `bro`
(resolved via `HOMEResolveSibling`) and writes TLV hunks to the
pipe.  With non-tty stdout, graf writes plain ASCII via
`HUNKu8sFeedText` directly.  `merge` does not page.
