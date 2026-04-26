# `be` HTTP-verb command syntax

The `be` dispatcher uses an HTTP-like verb vocabulary —
GET, POST, PUT, PATCH, DELETE — over the URI grammar from
`dog/DOG.md` and `beagle/GURI.md`.  The verb says direction and
intent; the URI picks the resource.

    be <verb> [--flags] [scheme:][//auth][path][?ref][#frag]

This document is the canonical reference for that mapping.  It
assumes the branch-sharded storage model from `keeper/README.md`
and the worktree pointer pair from `sniff/AT.md`.

##  URI recap

    [scheme:] [//authority] [path] [?ref] [#fragment]

  - `scheme:`   — transport (`ssh:`, `https:`, `file:`, `be:`) or
                  a **view projector** (`sha1:`, `blob:`, `tree:`,
                  …).  See "Schemes" below.  No scheme = act
                  locally on the resource per the verb.
  - `//auth`    — remote host or alias (`//origin`, `//github`).
  - `path`      — file or directory inside the branch's tree.
                  With a `file:` scheme, the path is a filesystem
                  path to another store/wt on this host.
  - `?ref`      — branch / tag / sha / range. Branch refs mirror
                  the on-disk tree: `?heads/feature/fix1`
                  ⇢ `<store>/heads/feature/fix1/`.  `heads/` is
                  optional for short lookups.
  - `#frag`     — object hash (`#abc1234`) or spot search
                  fragment (see `dog/FRAG.h`).

Branch sharding means every ref has a directory.  "Create a
branch" = "create a dir under a parent branch".  History is
**linear per branch**; cross-branch merges land as one squashed
commit on the destination branch, with merge provenance recorded
in `REFS` rather than in a DAG merge node.

##  Ref resolution

A `?ref` resolves in this order:

 1. Exact absolute path (`?heads/feat`, `?tags/v1.0`) ⇒ that
    dir under the store root.
 2. Relative path (`?./fix`, `?../fix`) ⇒ rooted at the current
    branch dir.  See table below.
 3. Short name (`?fix`, `?v1.2.4`) ⇒ tried as `heads/fix`, then
    `tags/fix`, then a sha prefix.
 4. **Fallback for verbs that create** (GET, POST): if none of
    the above match, `be get ?NAME` / `be post ?NAME` forks a new
    branch `heads/<current>/NAME` (i.e. a child of the current
    branch) at the current tip.  For other verbs, an unresolved
    ref is an error.

| URI | From `heads/feature` |
|---|---|
| `?./fix`            | Fork sub-branch `heads/feature/fix` at current tip. |
| `?../fix`           | Sibling branch `heads/fix` at parent's tip. |
| `?..`               | Switch to parent `heads/`. |
| `?fix`              | Lookup then create fallback — equivalent to `?./fix` if nothing resolves. |
| `?heads/feat/fix`   | Absolute path; same regardless of current branch. |

Relative refs (`./`, `../`) from a detached wt are refused — pick
an explicit branch first.

##  Schemes

Two kinds.

### Transport schemes

Select **where** the resource lives.

| Scheme  | Meaning |
|---------|---------|
| *(none)*| Local store, current branch dir. |
| `ssh:`  | Remote host over ssh; use with `//host/path`. |
| `https:`| Remote host over https. |
| `be:`   | Peer dog over `keeper upload-pack` / `receive-pack` (`keeper/WIRE.md`). |
| `file:` | **Local sibling worktree/store** at the given path (see §Worktree management).  Equivalent to passing the path directly, but makes "this is a local repo, wire me as a worktree" explicit. |

### View projectors

Read-only views.  Orthogonal to the verb — the verb still says
what to do, the projector says **what shape of bytes to emit**
instead of performing the action.

| Scheme    | Emits                                            | Example |
|-----------|--------------------------------------------------|---------|
| `sha1:`   | 40-hex sha of the resource                       | `be get sha1:?heads/feat` |
| `blob:`   | raw bytes of a blob                              | `be get blob:file.c?123abc` |
| `tree:`   | tree listing (mode, sha, name)                   | `be get tree:src/?heads/feat` |
| `commit:` | commit object body                               | `be get commit:?123abc` |
| `log:`    | `REFS` tail, newest-first (`@N` = last N)        | `be get log:?heads/feat@10` |
| `refs:`   | list refs under a dir (`**` = recursive)         | `be get refs:?tags/**` |
| `diff:`   | unified diff of wt vs ref                        | `be get diff:file.c?heads/main` |
| `size:`   | byte size of the resource                        | `be get size:?#abc1234` |
| `type:`   | object type (`commit`/`tree`/`blob`/`tag`)       | `be get type:?#abc1234` |

Projectors are pure — they never mutate.  They compose with
`//auth` (`be get sha1://origin?heads/main` is a cheap
reachability probe that requests just the tip sha) and with
`path+ref` (the path says what, the ref says from where, the
projector says in what form).

##  Remote resolution is lazy

When a verb takes a remote:

  - `be get //origin?v1.2.3` — "v1.2.3 from origin"; origin's
    concrete URL is resolved from `<store>/ALIAS`.
  - `be get ssh://host/path?v1.2.3` — explicit URL; on first use
    it is recorded as an alias (default name derived from host or
    user-supplied with `--as=origin`).
  - `be get //origin` — fast-forward the **current branch** from
    origin's counterpart.
  - `be get ?v1.2.4` — **local**: resolve per §"Ref resolution",
    forking a new branch if no match.  No network.

Alias lookup walks up the dir tree to the store root, same as
`<store>/ALIAS` in `keeper/REF.md`.

##  GET — repo → worktree

GET reads from the repo into the worktree, or projects a view of
a repo resource.

| Form | Effect |
|---|---|
| `be get ?heads/feat`           | Open/create a wt on `heads/feat`, reset files from its tip.  Default: dedicated wt dir per branch. |
| `be get -1 ?heads/feat`        | **In-place** switch: move the *current* wt's `.dogs` pointer to `heads/feat`.  Old branch dir loses its `WT`. |
| `be get ?./fix`                | Fork sub-branch `fix` under current branch at current tip; open a wt there. |
| `be get ?../fix`               | Fork sibling branch at current's parent tip. |
| `be get ?v1.2.4`               | Local lookup; if nothing matches, fork a new branch `heads/<current>/v1.2.4` at current tip. |
| `be get ?abc1234`              | Detached checkout on a sha.  `put`/`delete`/`post` refuse until re-attached. |
| `be get file.c?heads/main`     | Overwrite one file in the wt from another branch's tip (no staging). |
| `be get //origin`              | Fast-forward the **current branch** from its `//origin` counterpart.  Refuses on divergence — resolve with `be patch //origin`. |
| `be get //origin?v1.2.3`       | Lazy-remote: fetch `v1.2.3` from origin (pack + REFS). |
| `be get //origin?heads/feat`   | Same, explicit branch path. |
| `be get ssh://host/path?v1.2.3`| Explicit URL; same effect, registers an alias on first use. |
| `be get file:../proj?v1.2.3`   | **Local worktree**: wire this empty cwd as a wt sharing `../proj`'s store, reset files to `v1.2.3`. |
| `be get //origin?*`            | Fetch every branch origin advertises (opt-in bulk form). |
| `be get sha1:?heads/feat`      | Print tip sha of `heads/feat`. |
| `be get sha1:file.c`           | Print sha-1 of the wt file's on-disk bytes (git-hash-object). |
| `be get sha1:file.c?`          | Print sha-1 of the tracked blob (per sniff's index). |
| `be get blob:file.c?abc1234`   | Cat file contents at that commit. |
| `be get tree:?heads/feat`      | List the branch-tip tree. |
| `be get log:?heads/feat@20`    | Last 20 `REFS` entries on feat. |
| `be get refs:?heads/**`        | List every branch recursively. |

Rule: `be get` with no ref and no remote = no-op status.
`be get //origin` = fast-forward current branch from its
counterpart.  `be get ?X` = local resolve-or-create.  Switching
to a different local branch always takes a ref (new wt by
default, `-1` for in-place).

##  POST — worktree → repo

POST commits the current base tree or pushes it to a peer.

Free-form trailing words after the verb (and any URI) are joined
with `' '` and folded into the URI's `#fragment` — that's where the
commit message lives.  No quoting tricks, no `-m` flag.  A token
counts as a URI only if it contains one of `/`, `.`, `:`, `?`, `#`,
or is a 40-hex object id; otherwise it kicks off the message tail.
Bare names like `README` need a leading `./` to be parsed as paths.
(Legacy: `-m "msg"` is still accepted.)

| Form | Effect |
|---|---|
| `be post fix the parser`           | Commit the staged base tree; message is the trailing words. |
| `be post . fix the parser`         | Bulk-stage subtree then commit. |
| `be post ./file.c fix the parser`  | Stage the one file then commit. |
| `be post ?./fix add fix1`          | Commit to sub-branch `fix` off the current branch (create the dir if missing). |
| `be post ?heads/feat/fix1 land it` | Same, absolute path. |
| `be post //origin`                 | Push current branch's pack-log tail + REFS to origin via git's receive-pack wire (`keeper/WIRE.md`).  Fast-forward only. |
| `be post //origin?heads/feat`      | Push that branch specifically. |

Rule: history is linear per branch — POST always appends one
commit to `<branch>/REFS`.  Branching happens via the path (post
to a deeper ref creates a child dir), not via a merge commit.

##  PUT — stage additions

PUT is strictly local — it updates the branch's staging pack.
No commit, no `REFS` write, no remote.

| Form | Effect |
|---|---|
| `be put`          | Stage every dirty file (sniff walks the watch log). |
| `be put file.c`   | Stage one file. |
| `be put src/`     | Stage a subtree. |

PUT touches `stage.sniff` + `stage.idx` in the current branch
dir (see `sniff/STAGE.md`).  Pushing to a peer is POST's job.

##  DELETE — remove

DELETE's meaning depends on URI shape.  In-tree paths stage
removals; a ref URI drops the branch or tag dir.

| Form | Effect |
|---|---|
| `be delete file.c`                  | Stage a file removal (next POST drops it). |
| `be delete`                         | Stage every tracked file missing from disk. |
| `be delete src/`                    | Stage subtree removal. |
| `be delete ?heads/feat/fix1`        | **Drop a branch dir.**  Leaf-only; refused if `WT` is live, descendants exist, or staging is open.  See `keeper/README.md` §"Delta-dependency DAG" and `sniff/AT.md` §"Drop-a-dir interaction". |
| `be delete ?tags/v1.0`              | Drop a tag dir. |
| `be delete //origin?heads/feat`     | Push a delete (`<old-sha> 000…0 refs/heads/feat`) via `keeper receive-pack` — same wire git uses for `git push -d`. |

##  PATCH — cross-branch merge into the worktree

PATCH does not create a merge commit.  It is a worktree-level
3-way merge: conflicts mark up files in place, the result stays
in the wt, and a subsequent POST lands it as one linear commit.

| Form | Effect |
|---|---|
| `be patch ?heads/trunk`             | 3-way merge trunk's tip into the wt. |
| `be patch ?./fix`                   | Pull a child sub-branch's changes into the current branch. |
| `be patch ?heads/feat..heads/feat2` | Apply a range diff to the wt (replay another branch's delta). |
| `be patch //origin?heads/main`      | Fetch + 3-way merge remote tip into wt.  ≈ `git pull --no-commit`. |
| `be patch file.c?heads/feat`        | Merge one file's version from another branch into the wt. |
| `be patch #'Old'->'New'.c`          | Delegated to spot: in-place structural rewrite across `.c` files. |

Merges along the branch tree (parent↔child, siblings via LCA)
are the common case and land as one squashed commit on POST.
Merge provenance is recorded in `REFS` as a remote-attributed
entry pointing at the source branch tip.

##  Worktree management

A **store** is the `.dogs/` directory holding packs, indexes,
REFS, and aliases.  A **worktree (wt)** is a checked-out tree on
disk.  One wt per branch dir; many wts per store.  A secondary
wt shares the primary's store via a `.dogs` symlink; its
per-branch pointer still lives in `<wt>/.dogs` and
`<branch-dir>/WT` (see `sniff/AT.md`).

The guiding rule: **a machine only needs one store per upstream
repo**.  Every extra wt is just another dir with a `.dogs`
symlink back.

### Example 1 — same tree, flip between two tags

```sh
mkdir proj && cd proj

# clone + checkout v1.2.3 into this tree
be get ssh://server/proj?v1.2.3

# fetch v1.2.4 from the same origin (lazy alias resolution)
be get //origin?v1.2.4

# flip this tree to v1.2.4 in place
be get -1 ?v1.2.4

# …inspect…
be get -1 ?v1.2.3
```

Tag checkouts are read-only; `put`/`delete`/`post` refuse on
them (same rule as detached shas — see `sniff/STAGE.md`).

### Example 2 — one worktree per tag

```sh
# primary store + wt
mkdir proj && cd proj
be get ssh://server/proj?v1.2.3
be get //origin?v1.2.4                 # populate v1.2.4 in the shared store

# spawn sibling wts — each gets its own dir
cd ..
mkdir v1.2.3 && (cd v1.2.3 && be get file:../proj?v1.2.3)
mkdir v1.2.4 && (cd v1.2.4 && be get file:../proj?v1.2.4)
```

Now `proj/`, `v1.2.3/`, and `v1.2.4/` each have a `.dogs`
symlink to the primary store.  The tag dirs
`<proj>/.dogs/tags/v1.2.3/` and `…/v1.2.4/` each own a `WT`
line naming the sibling dir.

The `file:` scheme makes the "I want a worktree of that local
repo" intent explicit.  Without it, `be get ../proj?v1.2.3` does
the same thing by heuristic (path points at an existing store).

### Example 3 — feature branch workflow across two wts

```sh
# on trunk wt
cd proj
be get ?./feat              # fork heads/<trunk>/feat; new wt in sibling dir
cd ../proj-feat             # …which landed here (convention)
# hack, stage, commit
echo patch > new.c
be post . feat stub
be post //origin            # push the branch

# back on trunk wt
cd ../proj
be patch ?heads/feat        # pull feat's delta into trunk's wt
be post merge feat          # squash-merge onto trunk
```

### Example 4 — close a worktree

```sh
cd proj-feat
be delete .dogs             # remove wt pointer; clears <branch-dir>/WT
cd .. && rm -rf proj-feat
```

Closing a wt clears only the pointer pair.  Branch dirs (packs,
REFS) stay put in the primary store.  Use
`be delete ?heads/<current>/feat` from another wt to actually
drop the branch.

##  Common-task cheat sheet

| git | be |
|---|---|
| `git clone URL`                        | `be get //URL` |
| `git fetch`                            | `be get //origin?*` |
| `git pull --ff-only`                   | `be get //origin` |
| `git pull`                             | `be patch //origin` then `be post merge` |
| `git checkout -b feat` (from trunk)    | `be get ?./feat` |
| `git checkout -b feat` (short)         | `be get ?feat` |
| `git checkout feat`                    | `be get -1 ?heads/feat` |
| `git worktree add ../feat feat`        | `cd ../feat && be get file:../proj?heads/feat` |
| `git add file && git commit -m`        | `be put ./file && be post msg` |
| `git commit -am "…"`                   | `be post . msg` |
| `git rm file && commit`                | `be delete ./file && be post msg` |
| `git branch -d feat`                   | `be delete ?heads/feat` |
| `git merge trunk`                      | `be patch ?heads/trunk && be post merge trunk` |
| `git cherry-pick <sha>`                | `be patch ?<sha>^..?<sha>` |
| `git push`                             | `be post //origin` |
| `git push -d origin feat`              | `be delete //origin?heads/feat` |
| `git rev-parse HEAD`                   | `be get sha1:?` |
| `git cat-file -p <sha>:file.c`         | `be get blob:file.c?<sha>` |
| `git log -n 20 feat`                   | `be get log:?heads/feat@20` |
| `git branch -a`                        | `be get refs:?heads/**` |
| `git ls-remote origin main`            | `be get sha1://origin?heads/main` |

##  Design invariants

 1. **Verb × URI shape is unambiguous.**  A ref-only URI targets
    the branch/tag dir (create/drop/switch).  A path+ref URI
    targets a file in that branch.  `//auth` reaches out to a
    peer.  The projector scheme only reshapes the output.
 2. **Linear history per branch** ⇒ POST is always an append;
    PATCH never creates a merge commit; merge provenance lives
    in `REFS` as gossiped tip entries.
 3. **Tree-sharded branches** ⇒ sub-branch creation is
    path-implicit (`?heads/a/b/c`, `?./c`, or `?name` fallback).
    No `-b` flag needed.
 4. **One store per machine, many worktrees.**  Secondary wts
    symlink `.dogs` back to the primary; the `file:` scheme is
    the explicit "wire me as a worktree" marker.
 5. **Worktree default = dedicated dir per branch** (see
    `sniff/AT.md` §"`<branch-dir>/WT`").  `-1` is the escape
    hatch for a single-wt classic-git workflow.
 6. **Detached mode is explicit** (`?<sha>` with no branch);
    `put`/`delete`/`post` refuse on detached wts.
 7. **Projector schemes are read-only.**  They never mutate —
    safe to compose with any verb and with `//auth` without side
    effects on the peer.
 8. **Remote operations are fast-forward only.**  Divergence is
    resolved client-side with PATCH + POST, never by the peer.
 9. **Remote resolution is lazy.**  `//origin` resolves through
    `<store>/ALIAS`; a bare URL registers an alias on first use.

##  Open edges

  - **`?./x` when the wt is detached** — refuse; detached +
    relative is ambiguous.
  - **`sha1:file.c` without a ref** — defined as the sha-1 of
    the wt's on-disk bytes (git-hash-object semantics).  The
    empty-ref form `sha1:file.c?` returns the tracked-blob sha
    via sniff's index.
  - **`be delete //origin?heads/feat`** — uses git's standard
    delete-via-push (`<old> 000…0 refs/heads/feat`) over keeper's
    receive-pack; behaviour unchanged from vanilla git.
  - **Bulk fetch (`?*`)** — ordering rule:
    parents-before-children, per the delta-dependency DAG
    (`keeper/README.md`); the client walks the ancestor chain
    and runs N upload-pack sessions (`keeper/WIRE.md`).
  - **Projector on non-`get` verbs** — treat as read-only even
    there (e.g. `be post sha1:?heads/feat` = "print what would be
    committed" without committing).  Not specified yet; keep the
    shape reserved.
  - **Auto-wt dir naming for `be get ?./feat`** — convention:
    sibling dir `<primary>-<branch-leaf>`.  Override with
    `--wt=<path>`.  Not yet implemented in `BEGetWorktree`.
