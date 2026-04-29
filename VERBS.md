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
branch" = "create a dir under a parent branch", and that's
**POST's** job — GET never auto-creates.  Each branch is a
**linear** stack from its fork commit to its tip, and every
commit has **exactly one parent**.  POST is *with-history*
(ff or rebase) and never produces a merge commit; PATCH is
*history-erased* (absorbs another branch's delta into the wt as
a single-parent commit on the next POST).

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

Branch creation is **POST-only**.  `be post ?./fix` forks a
child at the current tip; `be post ?feat/new` or `be post ?feat/`
creates a new leaf under existing `feat`.  GET never creates —
unresolved refs (relative, absolute, or sha) are errors.

| URI | From branch `feature` |
|---|---|
| `?./fix`            | Child branch `feature/fix`; error if missing (POST creates). |
| `?../fix`           | Sibling branch `fix`; error if missing (POST creates). |
| `?..`               | Parent branch (the trunk if `feature` is top-level). |
| `?fix`              | Absolute lookup of root-level branch `fix`; error if missing. |
| `?feat/fix`         | Absolute path; same regardless of current branch. |
| `?feat/`            | Absolute path with **trailing slash**: in POST, "create a leaf under `feat` reusing cur's basename"; elsewhere, error. |

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
| `be get ?./fix`                | Switch the wt to child branch `fix`; error if missing (POST creates). |
| `be get ?../fix`               | Switch the wt to sibling branch `fix`; error if missing. |
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

##  POST — publish, with history

POST advances a branch with cur's content, **preserving commit
history** (ff or rebase, never a merge commit).  Two phases per
invocation:

  1. **Commit-if-staged**: any wt edits or PATCH-staged content
     land first as a new single-parent commit on cur (trailing
     words = message).  `commit_all`, `commit`, and the merged
     tree from prior PATCHes all collapse into one new commit.
  2. **Promote**: if the URI names another branch, rebase cur's
     stack onto that branch's tip and ff it.  When the URI is
     bare or names cur, only phase 1 runs.

POST does **fast-forward when the target tip is at the expected
base, otherwise rebases** cur's stack on top of the new tip.
The CAS is on the *expected* tip — concurrent posters that
move the target between fetch and post are rejected and the
client retries.  Force-rewrite of a non-trunk branch is via
`be delete ?<branch>` then `be post` (explicit).  Empty POSTs
(no commit to make, no promotion possible) are refused with
`POSTNONE`.

### Per-file classification via stamps

Every row sniff writes (`get`, `post`, `patch`, `put`) stamps
each file it touched with the row's `ts` via `utimensat`.  At
POST time we read each on-disk file's mtime and look up the
owning row by ts:

| `mtime` lookup       | Fate (selective mode¹) | Fate (implicit mode²) |
|----------------------|------------------------|------------------------|
| `< last_get_ts`      | KEEP (unchanged since reset) | KEEP |
| `get` / `post` row   | KEEP (baseline content)      | KEEP |
| `patch` row          | REWRITE (merged bytes)       | REWRITE (merged bytes) |
| `put` row            | REWRITE (current bytes)      | REWRITE (current bytes) |
| ∉ stamp-set (edited) | ignore unless explicit `put` named it (warn if put exists; current bytes win) | REWRITE |

¹ Selective = at least one explicit `put` / `delete` row since
last post.  ² Implicit (a.k.a. commit-all) = none.

### Single-parent commits

The new commit's parent is always cur's previous tip — period.
PATCH-merged content contributes to the new tree but **not** to
the parent set; provenance is erased at PATCH time.  Cross-
branch deduplication (when cur eventually flows toward trunk)
relies on patch-id matching, not recorded parents.

### ULOG scope and boundaries

Two boundaries in `.sniff`, both anchored at the most recent `get`
row (a `get` is a hard reset of the world):

  * **pd boundary** — most recent `get` *or* `post`.  `put` /
    `delete` rows after this are in scope for the next POST.
  * **patch boundary** — most recent `get` *or* commit-all `post`.
    `patch` rows after this are in scope.

A `post` row classifies as commit-all iff no put/delete rows lie
between its own pd boundary and itself; determinable on the fly
from a single forward scan, so no new ULOG verb is needed.

### Wall-clock guard

Every command checks `now ≥ last_log_ts` on entry and refuses
with `CLOCKBAD` if the system clock has moved backwards.  One
`ts` is reserved per command, shared by every row + file stamp
written in that invocation.

After a successful POST that promoted cur into another branch,
cur's `fork_commit` advances iff the target was cur's upstream
(parent or self) — otherwise cur is unchanged and the target
holds rebased copies of cur's commits (which dedup via patch-id
on later flows).  Whether the wt re-binds to the target or stays
on cur depends on the URI: see the form table below.

Free-form trailing words after the verb (and any URI) are joined
with `' '` and folded into the URI's `#fragment` — that's where
the commit message lives for the commit-if-staged step.  No
quoting tricks, no `-m` flag.  A token counts as a URI only if
it contains one of `/`, `.`, `:`, `?`, `#`, or is a 40-hex
object id; otherwise it kicks off the message tail.  Bare names
like `README` need a leading `./` to be parsed as paths.
(Legacy: `-m "msg"` is still accepted.)

| Form | Effect |
|---|---|
| `be post fix the parser`           | Bare: commit-if-staged on cur, single-parent, message = trailing words.  No promotion. |
| `be post ?..`                      | Commit-if-staged, then promote cur into parent (rebase + ff parent).  Cur auto-syncs to parent's new tip. |
| `be post ?./fix`                   | Commit-if-staged, then pull child `fix` up onto cur (rebase fix's stack onto cur's tip, ff fix).  Cur unchanged. |
| `be post ?./fix`  *(missing)*      | Create child branch `fix` at cur's tip, content = cur's stack.  Cur unchanged. |
| `be post ?feat`                    | Promote cur into existing branch `feat` (rebase + ff feat).  Cur auto-syncs only if `feat` is cur's upstream. |
| `be post ?feat/new`                | Create new leaf `feat/new` under existing `feat`, content = cur's stack rebased on `feat`'s tip.  Cur unchanged. |
| `be post ?feat/`                   | Same; leaf name reused from cur's basename. |
| `be post //origin`                 | Push current branch to origin via `keeper receive-pack` (`keeper/WIRE.md`).  Ff or rebase, same rules as local. |
| `be post //origin?feat`            | Push that branch specifically. |

Each POST appends one or more entries to the target branch's
`REFS` — one for the commit-if-staged step on cur, plus the
rebased equivalents when promoting onto a target.  Every commit
written is single-parent.  When cur's stack is rebased over
existing commits on the target, **patch-id dedup** silently
skips replays whose normalized diff is already reachable from
the target tip.  See §"Cascade rebase" (TODO) for what happens
to descendants of a branch whose stack got rewritten.

##  PUT — stage additions

PUT records explicit staging intent.  Each `put` row also stamps
its file via `utimensat` to the row's ts, so the file's mtime
points back to the put row that owns its content.

| Form | Effect |
|---|---|
| `be put`          | Walk the wt; stage every tracked-and-dirty file (one `put` row per path).  Refuses with `PUTNONE` if no tracked file is dirty. |
| `be put file.c`   | Stage one file.  Refuses with `PUTNONE` if the file is missing, or if it is already clean and matches baseline.  Re-stamps the file. |
| `be put src/`     | Stage a subtree.  If `src/` is **tracked** (any baseline entry under it): tracked-dirty files only.  If **untracked**: every non-ignored file under it. |

PUT only writes to `<wt>/.sniff` (the ULOG) and stamps files;
no pack writes happen until POST.  Pushing to a peer is POST's
job.

A `put` on a clean baseline-stamped file is refused — re-stamping
it under a `put` row would shift its provenance from baseline to
put for no semantic gain.

##  DELETE — remove

DELETE's meaning depends on URI shape.  In-tree paths actually
unlink files **immediately** (after a dirty-safety check) and
append a `delete <path>` row; a ref URI drops the branch dir.

The dirty check refuses (`DELDIRTY`) if the file's mtime is out
of the stamp-set **and** its content differs from the baseline
sha (cheap mtime check, content-hash only on drift).  Already-
absent paths are an OK no-op.

| Form | Effect |
|---|---|
| `be delete file.c`                  | Unlink the file (refused as `DELDIRTY` if user-edited); append `delete file.c` row. |
| `be delete src/`                    | Atomic pre-flight: scan all descendants; refuse if **any** is dirty.  On pass, unlink all + append one `delete src/` row. |
| `be delete ?feat/fix1`              | **Drop a branch dir.**  Leaf-only; refused if descendants exist or any wt's `.sniff` records this branch as base.  Reclaims unreachable shards (current GC path).  See `keeper/README.md` §"Delta-dependency DAG" and `sniff/AT.md`. |
| `be delete //origin?feat`           | Push a delete (`<old-sha> 000…0 refs/heads/feat`) via `keeper receive-pack` — same wire git uses for `git push -d`. |

##  PATCH — absorb, history erased

PATCH takes another branch as a whole — its full
`(fork_commit..tip)` stack — and absorbs the delta into cur's
wt as a single 3-way merge: `base = tree(arg.fork_commit)`,
`ours = tree(cur.tip)`, `theirs = tree(arg.tip)`.  The result
lands in the wt; PATCH does **not** commit.  The next POST
turns it into one new single-parent commit on cur.  No
multi-parent commit is ever produced and no provenance is
recorded — cross-branch dedup later relies on patch-id matching
or an explicit `cherry-picked-from` trailer in the commit
message.

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
| `be patch ?..`                      | Absorb parent's progress (parent's stack `fork..tip`) as a single squash on cur. |
| `be patch ?./fix`                   | Absorb child branch `fix` (its stack) into cur. |
| `be patch ?feat/fix`                | Absorb absolute branch `feat/fix` into cur as one commit. |
| `be patch ?trunk`                   | Absorb trunk's stack into cur (sync from trunk). |
| `be patch ?feat..?feat2`            | Apply a range diff to the wt (replay another branch's delta between two named refs). |
| `be patch //origin?main`            | Fetch + absorb remote branch into wt.  ≈ `git pull --squash --no-commit`. |
| `be patch file.c?feat`              | Absorb one file's version from another branch into the wt. |
| `be patch #'Old'->'New'.c`          | Delegated to spot: in-place structural rewrite across `.c` files. |

Multiple PATCHes compose into the wt; the next POST emits one
single-parent commit with the merged tree.  Branch identity of
the absorbed sources is **not** recorded — they survive on their
own branches with their own commit history, untouched by PATCH.

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
be post ?./feat             # POST creates child branch `feat` at trunk's tip
be get ?./feat              # GET switches the wt to it
echo patch > new.c
be put . && be post feat stub  # stage + commit on `feat`
be post //origin            # push the branch

# back on trunk
be get ?..                  # parent of `feat` is the trunk
be patch ?./feat            # absorb feat's delta into trunk's wt (history erased)
be post sync feat           # single-parent commit on trunk with feat's content folded in
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
| `git pull`                             | `be patch //origin` then `be post sync` (single-parent absorb, not a merge commit) |
| `git checkout -b feat` (child of trunk)| `be post ?./feat` then `be get ?./feat` (POST creates, GET switches) |
| `git checkout feat`                    | `be get ?feat` |
| `git worktree add ../feat feat`        | `cd ../feat && be get file:../proj?feat` |
| `git add file && git commit -m`        | `be put ./file && be post msg` |
| `git commit -am "…"`                   | `be put . && be post msg` |
| `git rm file && commit`                | `be delete ./file && be post msg` |
| `git branch -d feat`                   | `be delete ?feat` |
| `git merge trunk`                      | `be patch ?trunk && be post sync trunk` (single-parent on cur; no merge commit) |
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
 2. **Linear branches, single-parent commits.**  Each branch is
    a linear stack from its `fork_commit` to its `tip`; every
    commit has exactly one parent.  POST never produces a merge
    commit; PATCH absorbs without recording provenance.
 3. **GET is repo-read-only; POST is ff-or-rebase.**  GET
    refuses on dirty-overlap (all-or-nothing pre-flight) and, in
    its remote form, refuses non-ff (use `be patch //origin` to
    absorb divergence).  POST does fast-forward when the target
    is at the expected base, otherwise rebases cur's stack onto
    the new tip.  CAS on the expected tip; concurrent posters
    that move the target are rejected and retry.  Force-rewrite
    of a non-trunk branch is `be delete ?<branch>` then
    `be post`.  Empty POSTs are refused.
 4. **Tree-sharded branches; POST creates, GET reads.**
    Sub-branch creation: `be post ?./A` (child), `be post ?../A`
    (sibling), `be post ?feat/new` or `be post ?feat/` (absolute
    under existing parent).  Bare `?A` is absolute (≡ `?/A`).
    GET never auto-creates — unresolved refs are errors.
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
  - **Cascade rebase.**  When a POST rewrites branch B's stack
    (the rebase case, not ff), every descendant of B holds a
    stale `fork_commit` pointing at an orphaned SHA.  The
    cascade walks descendants depth-first: for each child C,
    replay C's stack `(C.fork_commit..C.tip)` onto B's new tip
    via per-commit 3-way merge (base = `tree(parent(Cᵢ))`,
    ours = running HEAD starting at B's new tip, theirs =
    `tree(Cᵢ)`); patch-id check against ancestors of B's new
    tip skips already-present commits; update C's record
    (`fork_commit = B.new_tip`, `tip = last replayed`); recurse
    into C's children.  **Atomic**: any conflict during the
    cascade rejects the entire POST — the offending branch and
    conflict paths are returned, no partial-cascade state is
    persisted, the user resolves the named child locally
    (typically by `be post`-ing it first to absorb the conflict
    explicitly) and retries.  Trigger condition is narrow —
    cascade runs only when the POST actually rewrote B's stack
    (i.e., when `that` is `this`'s upstream, the same predicate
    that drives auto-sync of cur); ff posts and posts to a
    sibling/cousin/new-branch leave B's stack untouched, so
    descendants stay valid.  Cost is dominated by leaf branches
    (no descendants → no-op); deep subtrees pay one rebase per
    descendant, with patch-id dedup keeping per-step cost near
    zero when descendants share commits with the new spine.
  - **Trunk for git peers.**  First contact reads the remote's
    `HEAD`; if absent, prefer `main` then `master`.  Re-binding
    on a remote default-branch rename is TODO (today the alias
    snapshot wins).
