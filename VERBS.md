# `be` HTTP-verb command syntax

The `be` dispatcher uses an HTTP-like verb vocabulary —
GET, POST, PUT, PATCH, DELETE — over the URI grammar from
`dog/DOG.md` and `beagle/GURI.md`.  The verb says direction and
intent; the URI picks the resource.

    be <verb> [--flags] [scheme:][//auth][path][?ref][#frag]

This document is the canonical reference for that mapping.  It
assumes the branch-sharded storage model from `keeper/README.md`
and the per-wt `.sniff` state from `sniff/AT.md`.

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
  - `?ref`      — branch path or sha/range.  Branch refs mirror
                  the on-disk tree: `?feature/fix1` ⇢
                  `<store>/feature/fix1/`.  Bare `?A` is absolute
                  (≡ `?/A`); `?./A` means a child of the current
                  branch, `?../A` a sibling.
  - `#frag`     — object hash (`#abc1234`) or spot search
                  fragment (see `dog/FRAG.h`).

Branches form a tree; the **trunk** is the root.  "Create a
branch" = "create a dir under a parent branch".  History is
**first-parent-linear per branch** — POST appends one commit to
the target's `REFS`.  The commit object itself can be
multi-parent: GET seeds the first parent, each subsequent PATCH
appends another via `.sniff`, and POST drains those into the new
commit.

##  Ref resolution

A `?ref` resolves in this order:

 1. Absolute path (`?A`, `?A/B`, `?/A/B`) ⇒ that dir under the
    store root.  Bare `?A` is **absolute**, not relative to the
    current branch.
 2. Relative path (`?./A`, `?../A`, `?..`) ⇒ rooted at the
    current branch dir.  Refused from a detached wt (ambiguous —
    pick an explicit branch first).
 3. Sha prefix (`?abc1234`) ⇒ object lookup; attaches as a
    detached wt.

For the create case (GET, POST), the **relative** forms create
on miss: `be get ?./fix` / `be post ?./fix` fork the child branch
at the current tip.  Absolute and sha forms never auto-create —
unresolved is an error.

| URI | From branch `feature` |
|---|---|
| `?./fix`            | Child branch `feature/fix` at current tip (forked on miss). |
| `?../fix`           | Sibling branch `fix` at parent's tip (forked on miss). |
| `?..`               | Parent branch (the trunk if `feature` is top-level). |
| `?fix`              | Absolute lookup of root-level branch `fix`; error if missing. |
| `?feat/fix`         | Absolute path; same regardless of current branch. |

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
| `sha1:`   | 40-hex sha of the resource                       | `be get sha1:?feat` |
| `blob:`   | raw bytes of a blob                              | `be get blob:file.c?123abc` |
| `tree:`   | tree listing (mode, sha, name)                   | `be get tree:src/?feat` |
| `commit:` | commit object body                               | `be get commit:?123abc` |
| `log:`    | `REFS` tail, newest-first (`@N` = last N)        | `be get log:?feat@10` |
| `refs:`   | list refs under a dir (`**` = recursive)         | `be get refs:?**` |
| `diff:`   | unified diff of wt vs ref                        | `be get diff:file.c?main` |
| `size:`   | byte size of the resource                        | `be get size:?#abc1234` |
| `type:`   | object type (`commit`/`tree`/`blob`/`tag`)       | `be get type:?#abc1234` |

Projectors are pure — they never mutate.  They compose with
`//auth` (`be get sha1://origin?main` is a cheap reachability
probe that requests just the tip sha) and with `path+ref` (the
path says what, the ref says from where, the projector says in
what form).

##  Remote resolution is lazy

When a verb takes a remote:

  - `be get //origin?feat` — "feat from origin"; origin's
    concrete URL is resolved from `<store>/ALIAS`.
  - `be get ssh://host/path?feat` — explicit URL; on first use
    it is recorded as an alias (default name derived from host or
    user-supplied with `--as=origin`).
  - `be get //origin` — fast-forward the **current branch** from
    origin's counterpart.
  - `be get ?A` — **local**: resolve per §"Ref resolution"; no
    network.  The relative forms `?./A` / `?../A` create on miss.

Alias lookup walks up the dir tree to the store root, same as
`<store>/ALIAS` in `keeper/REF.md`.

##  GET — repo → worktree

GET reads from the repo into the worktree, or projects a view of
a repo resource.  GET is **repo-read-only**: it never modifies a
branch's history.  Like git, GET refuses if any wt file with
local edits would be overwritten — abort up front, no partial
reset.

For the **remote** forms (`be get //origin`, `be get //origin?A`),
GET is also **fast-forward-only** on the *local branch's tip*:
it refuses if the local tip is not an ancestor of the incoming
remote tip.  This rule applies only when GET is syncing a local
branch from its remote counterpart, not to local branch switches.

| Form | Effect |
|---|---|
| `be get ?feat`                 | Switch the wt to branch `feat`, reset files from its tip.  Refuses on dirty overlap. |
| `be get ?./fix`                | Child branch `fix` under current at current tip (fork on miss); switch the wt to it. |
| `be get ?../fix`               | Sibling branch at parent's tip (fork on miss). |
| `be get ?abc1234`              | Detached checkout on a sha.  `post`/`patch` refuse until re-attached. |
| `be get file.c?feat`           | Overwrite one file in the wt from another branch's tip (no staging). |
| `be get //origin`              | Fast-forward the **current branch** from its `//origin` counterpart.  Refuses on divergence — resolve with `be patch //origin`. |
| `be get //origin?feat`         | Lazy-remote: fetch `feat` from origin (pack + REFS). |
| `be get ssh://host/path?feat`  | Explicit URL; same effect, registers an alias on first use. |
| `be get file:../proj?feat`     | **Local worktree**: wire this empty cwd as a wt sharing `../proj`'s store, reset files to `feat`'s tip. |
| `be get //origin?*`            | Fetch every branch origin advertises (opt-in bulk form). |
| `be get sha1:?feat`            | Print tip sha of `feat`. |
| `be get sha1:file.c`           | Print sha-1 of the wt file's on-disk bytes (git-hash-object). |
| `be get sha1:file.c?`          | Print sha-1 of the tracked blob (per sniff's index). |
| `be get blob:file.c?abc1234`   | Cat file contents at that commit. |
| `be get tree:?feat`            | List the branch-tip tree. |
| `be get log:?feat@20`          | Last 20 `REFS` entries on feat. |
| `be get refs:?**`              | List every branch recursively. |

After a successful GET, `.sniff` records the new base as
`(branch, tip-sha)` and clears any pending PATCH parents.  Bare
`be get` (no ref, no remote) is a no-op status.

##  POST — worktree → repo

POST commits the wt's current state to a branch, or pushes a
branch to a peer.  POST is **fast-forward-only**: refused if the
target branch's tip is not an ancestor of the wt's recorded
base.  Empty POSTs (no changes since base) are also refused.

POST drains the `.sniff` tail to populate the commit's parent
list — the base entry is the first parent, each PATCH appended
since adds another.  After commit, `.sniff` resets to
`(target-branch, new-tip)` with no pending patches.

The wt's branch pointer moves to the target on a successful POST
(its on-disk file state already matches; only the recorded
branch changes).  Cross-branch POST (`be post ?A` while wt is on
B) is allowed: A's lineage records the fork via first-parent.

If the target tip is not an ancestor of the wt's base, POST
refuses.  The user recovers manually: switch the wt off the
target (`be get ?..` or `be get ?other`), drop the branch via
`be delete ?<branch>`, then `be post ?<branch> msg` to recreate
at the wt's lineage.  No automatic delete-and-recreate — that
keeps destructive ref moves explicit.

Free-form trailing words after the verb (and any URI) are joined
with `' '` and folded into the URI's `#fragment` — that's where
the commit message lives.  No quoting tricks, no `-m` flag.  A
token counts as a URI only if it contains one of `/`, `.`, `:`,
`?`, `#`, or is a 40-hex object id; otherwise it kicks off the
message tail.  Bare names like `README` need a leading `./` to
be parsed as paths.  (Legacy: `-m "msg"` is still accepted.)

| Form | Effect |
|---|---|
| `be post fix the parser`           | Commit the wt to the current branch; message is the trailing words. |
| `be post . fix the parser`         | Bulk-stage subtree then commit. |
| `be post ./file.c fix the parser`  | Stage the one file then commit. |
| `be post ?./fix add fix1`          | Commit to child branch `fix` off the current branch (create on miss). |
| `be post ?feat/fix1 land it`       | Commit to absolute branch path. |
| `be post //origin`                 | Push current branch's pack-log tail + REFS to origin via `keeper receive-pack` (`keeper/WIRE.md`).  Ff-only; on divergence: `be patch //origin` then retry. |
| `be post //origin?feat`            | Push that branch specifically. |

Each POST appends exactly one entry to the target branch's
`REFS`.  The branch's first-parent history stays linear; any
extra parents come from `.sniff`.

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
removals; a ref URI drops the branch dir.

| Form | Effect |
|---|---|
| `be delete file.c`                  | Stage a file removal (next POST drops it). |
| `be delete`                         | Stage every tracked file missing from disk. |
| `be delete src/`                    | Stage subtree removal. |
| `be delete ?feat/fix1`              | **Drop a branch dir.**  Leaf-only; refused if descendants exist or any wt's `.sniff` records this branch as base.  Reclaims unreachable shards (current GC path).  See `keeper/README.md` §"Delta-dependency DAG" and `sniff/AT.md`. |
| `be delete //origin?feat`           | Push a delete (`<old-sha> 000…0 refs/heads/feat`) via `keeper receive-pack` — same wire git uses for `git push -d`. |

##  PATCH — cross-branch merge into the worktree

PATCH does not commit.  It does a wt-level 3-way merge of the
named source's tip into the current wt and appends the source
tip to `.sniff` as an additional parent.  The next POST drains
those parents into a real multi-parent commit.

PATCH refuses if any file it would touch is dirty in the wt.
For now, files modified by a previous PATCH count as dirty too,
so PATCH-on-PATCH only works on disjoint file sets.
Distinguishing "merge-result-clean" from "user-edited" is TODO.

Conflicts are marked **token-level** with 4-character delimiters
(`<<<<` / `>>>>`), not the line-level 7-char markers git uses.
Existing diff/merge UIs and `git mergetool` won't recognize
them; hand-edit, or use a `diff:?` projection to enumerate.

| Form | Effect |
|---|---|
| `be patch ?trunk`                   | 3-way merge `trunk`'s tip into the wt. |
| `be patch ?./fix`                   | Merge a child branch's changes into the current branch's wt. |
| `be patch ?feat..?feat2`            | Apply a range diff to the wt (replay another branch's delta). |
| `be patch //origin?main`            | Fetch + 3-way merge remote tip into wt.  ≈ `git pull --no-commit`. |
| `be patch file.c?feat`              | Merge one file's version from another branch into the wt. |
| `be patch #'Old'->'New'.c`          | Delegated to spot: in-place structural rewrite across `.c` files. |

Multiple PATCHes accumulate parents in `.sniff`.  The next POST
writes a commit with `[base, source1, source2, …]` as parents;
first-parent stays the base, so the branch's first-parent
history remains linear.

##  Worktree management

A **store** is the `.dogs/` directory holding packs, indexes,
REFS, and aliases.  A **worktree (wt)** is a checked-out tree on
disk; per-wt state — base branch, base tip, pending PATCH
parents — lives in `<wt>/.sniff` (see `sniff/AT.md`).  A
secondary wt shares the primary's store via a `.dogs` symlink.

Multiple wts may sit on the same branch; the ff-only POST rule
resolves write races.  Whichever POSTs first wins; the loser
must `be patch ?<branch>` to absorb the new tip before its own
POST can ff.

The guiding rule: **a machine only needs one store per upstream
repo**.  Every extra wt is just another dir with a `.dogs`
symlink back.

### Example 1 — same tree, flip between two named refs

```sh
mkdir proj && cd proj

# clone + checkout v1.2.3 into this tree
be get ssh://server/proj?v1.2.3

# fetch v1.2.4 from the same origin (lazy alias resolution)
be get //origin?v1.2.4

# flip this tree to v1.2.4
be get ?v1.2.4

# …inspect…
be get ?v1.2.3
```

### Example 2 — sibling worktrees on different branches

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
symlink to the primary store and their own `.sniff` recording
the branch they sit on.

The `file:` scheme makes the "I want a worktree of that local
repo" intent explicit.  Without it, `be get ../proj?v1.2.3` does
the same thing by heuristic (path points at an existing store).

### Example 3 — feature branch workflow

```sh
# on trunk wt
cd proj
be get ?./feat              # fork child branch `feat`; this wt switches to it
echo patch > new.c
be post . feat stub
be post //origin            # push the branch

# back on trunk
be get ?..                  # parent of `feat` is the trunk
be patch ?./feat            # merge feat's delta into trunk's wt
be post merge feat          # multi-parent commit; first parent = trunk's old tip
```

### Example 4 — close a worktree

```sh
cd ..
rm -rf proj-feat            # the .dogs symlink and .sniff go with the dir
```

Closing a wt is just removing its dir.  Branch dirs (packs,
REFS) stay put in the primary store.  Use `be delete ?feat` from
another wt to actually drop the branch.

##  Common-task cheat sheet

| git | be |
|---|---|
| `git clone URL`                        | `be get //URL` |
| `git fetch`                            | `be get //origin?*` |
| `git pull --ff-only`                   | `be get //origin` |
| `git pull`                             | `be patch //origin` then `be post merge` |
| `git checkout -b feat` (child of trunk)| `be get ?./feat` |
| `git checkout feat`                    | `be get ?feat` |
| `git worktree add ../feat feat`        | `cd ../feat && be get file:../proj?feat` |
| `git add file && git commit -m`        | `be put ./file && be post msg` |
| `git commit -am "…"`                   | `be post . msg` |
| `git rm file && commit`                | `be delete ./file && be post msg` |
| `git branch -d feat`                   | `be delete ?feat` |
| `git merge trunk`                      | `be patch ?trunk && be post merge trunk` |
| `git cherry-pick <sha>`                | `be patch ?<sha>^..?<sha>` |
| `git push`                             | `be post //origin` |
| `git push -d origin feat`              | `be delete //origin?feat` |
| `git rev-parse HEAD`                   | `be get sha1:?` |
| `git cat-file -p <sha>:file.c`         | `be get blob:file.c?<sha>` |
| `git log -n 20 feat`                   | `be get log:?feat@20` |
| `git branch -a`                        | `be get refs:?**` |
| `git ls-remote origin main`            | `be get sha1://origin?main` |

##  Design invariants

 1. **Verb × URI shape is unambiguous.**  A ref-only URI targets
    the branch dir (create/drop/switch).  A path+ref URI targets
    a file in that branch.  `//auth` reaches out to a peer.  The
    projector scheme only reshapes the output.
 2. **First-parent-linear history per branch.**  POST appends
    exactly one commit to the target's `REFS`.  The commit
    object can be multi-parent (first = base, additional from
    PATCHes drained from `.sniff`); only the first-parent chain
    is the branch's recorded history.
 3. **GET is repo-read-only; POST is fast-forward-only.**  GET
    refuses on dirty-overlap (all-or-nothing pre-flight) and, in
    its remote form, refuses if the local tip isn't an ancestor
    of the incoming remote tip.  POST refuses on non-ff (the
    target's tip must be an ancestor of the wt's base); recovery
    is manual via `be delete ?<branch>` + `be post ?<branch>`.
    Empty POSTs are refused.
 4. **Tree-sharded branches.**  Sub-branch creation is
    path-implicit: `?./A` for a child, `?../A` for a sibling.
    Bare `?A` is absolute (≡ `?/A`); only the relative forms
    create on miss.
 5. **One store per machine, many worktrees.**  Per-wt state
    lives in `<wt>/.sniff` (base branch, base tip, pending PATCH
    parents).  Secondary wts symlink `.dogs` back to the
    primary.  Multiple wts on the same branch are allowed; the
    ff rule resolves write races.
 6. **Detached mode is explicit** (`?<sha>` with no branch);
    `post`/`patch` refuse on detached wts.
 7. **Projector schemes are read-only.**  They never mutate —
    safe to compose with any verb and with `//auth` without side
    effects on the peer.
 8. **Remote operations are fast-forward only.**  Divergence is
    resolved client-side with PATCH + POST, never by the peer.
 9. **Remote resolution is lazy.**  `//origin` resolves through
    `<store>/ALIAS`; a bare URL registers an alias on first use.
10. **Git-peer interop: byte-faithful, topology-flat.**  Branch
    paths roundtrip as slashy ref names; the dogs branch tree
    collapses to a flat namespace on the git side.  Trunk maps
    to git's `main` (fallback `master`, or remote `HEAD`).
    Naming collisions (`feature` as a leaf vs `feature/fix` as
    a branch with a child) are git-side errors; we relay them
    unchanged.

##  Open edges

  - **`?./x` when the wt is detached** — refuse; detached +
    relative is ambiguous.
  - **`sha1:file.c` without a ref** — defined as the sha-1 of
    the wt's on-disk bytes (git-hash-object semantics).  The
    empty-ref form `sha1:file.c?` returns the tracked-blob sha
    via sniff's index.
  - **`be delete //origin?feat`** — uses git's standard
    delete-via-push (`<old> 000…0 refs/heads/feat`) over keeper's
    receive-pack; behaviour unchanged from vanilla git.
  - **Bulk fetch (`?*`)** — ordering rule:
    parents-before-children, per the delta-dependency DAG
    (`keeper/README.md`); the client walks the ancestor chain
    and runs N upload-pack sessions (`keeper/WIRE.md`).
  - **Projector on non-`get` verbs** — treat as read-only even
    there (e.g. `be post sha1:?feat` = "print what would be
    committed" without committing).  Not specified yet; keep the
    shape reserved.
  - **PATCH-on-PATCH state.**  Today PATCH treats files
    previously merged by an earlier PATCH as "dirty," so multi-
    PATCH only works on disjoint file sets.  TODO: distinguish
    "merge-result-clean" from "user-edited" so an arbitrary
    chain of PATCHes can compose.
  - **Squashing / repacking.**  The current GC path is "delete
    branch" (drops shards reachable only from that branch dir).
    A real squash (consolidate a branch's REFS into a single
    commit without dropping the branch) is TODO.
  - **Trunk for git peers.**  First contact reads the remote's
    `HEAD`; if absent, prefer `main` then `master`.  Re-binding
    on a remote default-branch rename is TODO (today the alias
    snapshot wins).
