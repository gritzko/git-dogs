# `be` HTTP-verb command syntax

The `be` dispatcher uses an HTTP-like verb vocabulary —
HEAD, GET, POST, PUT, DELETE, PATCH — over the URI grammar from
`dog/DOG.md` and `beagle/GURI.md`.  The verb says direction and
intent; the URI picks the resource.

    be <verb> [--flags] [scheme:][//auth][path][?ref][#frag]

This document is the canonical reference for that mapping.  It
assumes the branch-sharded storage model from `keeper/README.md`
and the per-wt `.sniff` state from `sniff/AT.md`.

##  Verb semantics in one paragraph

POST creates commits; PUT writes refs.  POST is the only
commit-maker — it advances **cur** (the current branch's tip),
reading any `patch` rows since the last `get`/`post` to assemble
multi-parent commits.  PUT is the only ref-writer — it sets a
(ref, sha) row in `.dogs/REFS`, optionally staging blobs into
keeper for the next POST, and never produces a commit object on
its own.  GET moves wt+cur (`cd`); PUT mints labels (`mkdir`);
HEAD peeks; PATCH absorbs another branch's work into the wt and
records the absorbed sha for POST to consume; DELETE removes
things.

##  URI recap

    [scheme:] [//authority] [path] [?ref] [#fragment]

  - `scheme:`   — transport (`ssh:`, `https:`, `be:`, `file:`)
                  — see "Schemes — cached vs transport" below — or
                  a **view projector** (`sha1:`, `blob:`, `tree:`,
                  …).  No scheme = act locally on the resource per
                  the verb.
  - `//auth`    — remote alias (`//origin`, `//github`).  A bare
                  `//host` resolves through `<store>/ALIAS` and
                  reads only the **cached** remote-tracking refs
                  in `.dogs/refs`; it never opens a network
                  connection.  To talk to the wire, attach a
                  transport scheme (`ssh://origin`, `be://github`).
  - `path`      — file or directory inside the branch's tree.
                  With a `file:` scheme, the path is a filesystem
                  path to another store/wt on this host.
  - `?ref`      — branch path or sha/range.  Branch refs mirror
                  the on-disk tree: `?feature/fix1` ⇢
                  `<store>/feature/fix1/`.  Bare `?A` is absolute
                  (≡ `?/A`); `?./A` means a child of the current
                  branch, `?../A` a sibling.
  - `#frag`     — object hash (`#abc1234`), commit-message search
                  (`#parallel` finds the commit reachable from cur
                  whose message contains "parallel"), line jump
                  (`#42`, `#10-20`), or extension filter
                  (`#.c.h`).  Search bodies live in their own
                  projector schemes (`spot:`, `grep:`, `regex:`),
                  not in the fragment slot.

Branches form a tree; the **trunk** is the root.  Branches are
`mkdir`-cheap: an **empty branch is one row in the reflog and an
empty pack log**.  Creating one is `be put ?./feat` (mkdir);
entering it is `be get ?./feat` (cd).  The two are deliberately
separate — workflow-by-fork stays explicit.

Each branch is **first-parent linear**: walking from cur's tip
along the first-parent chain reaches the fork commit in a
straight line.  Additional parents (from merge) and `foster`
headers (from squash / rebase-one) attach at POST time when
`patch` rows since the pd boundary contributed work; cherry-pick
records the picked sha as a `picked` trailer with no DAG edge.
POST is the only commit-maker; PATCH does not commit — it stages
the absorbed sha(s) in `.sniff` for the next POST.

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

Branch creation goes through PUT only.  GET refuses on a missing
ref (mirror of `cd nonexistent`).  `be put ?./fix` mints the
empty leaf; `be get ?./fix` then enters it.  Force-rewrite of an
existing branch is `be delete ?<branch>` then `be put ?<branch>`.

| URI | From branch `feature` |
|---|---|
| `?./fix`            | Child branch `feature/fix`.  GET refuses if absent; PUT creates. |
| `?../fix`           | Sibling branch `fix`.  GET refuses if absent; PUT creates. |
| `?..`               | Parent branch (the trunk if `feature` is top-level). |
| `?fix`              | Absolute lookup of root-level branch `fix`; error if missing. |
| `?feat/fix`         | Absolute path; same regardless of current branch. |

##  Verb × URI aspect

Each URI component contributes one aspect; verbs combine them
orthogonally.  Pick the verb, then each populated URI part adds
its effect.

|        | `?branch` (source/scope)               | `./path`                       | `//remote`                                 | `#frag`                              |
|--------|----------------------------------------|--------------------------------|--------------------------------------------|--------------------------------------|
| HEAD   | diff cur vs branch (ahead/behind, files) | scope diff to path           | cached-only with `//host`; transport scheme fetches first | sha pin / commit-msg search |
| GET    | switch wt+cur to branch                | restore one file in wt         | (transport scheme) clone / fetch + checkout | sha pin / detach                    |
| POST   | FF-advance ?branch to cur.tip          | —                              | FF-advance remote's counterpart to cur.tip | commit msg                           |
| PUT    | name the ref to write                  | stage path (blob + reflog row) | FF-push to remote                          | sha to reset ref to                  |
| DELETE | drop branch                            | unlink + stage delete          | drop alias / push delete                   | —                                    |
| PATCH  | source branch — squash whole stack     | scope absorption to path (no header recorded) | (transport scheme) fetch + absorb | empty `#` = rebase one; `#msg` = merge; bare `#hash` = cherry-pick |

The default for an empty `?branch` slot is **cur**.  POST commits
on cur; with a populated `?branch` or `//remote` slot it
additionally **FF-advances** that ref to cur's new tip after the
commit.  POST never rewrites cur's history (rebase is
`patch ?br#` + `post`, looped).  PATCH's `?branch` picks the
*source* of absorption — different role from POST's *target*.
Cross-branch commits do not exist in this model; if you want a
commit elsewhere, switch cur there first (see §"Eager branching"
under §"Worktree management").

Argument shape: every non-flag argv token becomes one URI via
`DOGNormalizeArg`.  Tokens with whitespace classify as fragment
(commit messages: `be post 'fix the typo'`).  Tokens with `?`,
`#`, `/`, or a known scheme go through the URI lexer.  Bare
tokens (`README`, `feat`, `v1.2.3`) land in the verb's default
slot — see §"Bareword defaults" below.

##  Bareword defaults

A **bareword** is a single argv token with no URI markers — no
whitespace, no `?`, `#`, `/`, or `:` (and no `<scheme>:` prefix).
After `DOGNormalizeArg` parks it in `u->path`, the dispatcher
moves it into the verb's natural slot via `DOGPromoteBareword`
(`dog/DOG.c`):

| Verb       | Bareword lands in | Example          | Equivalent           |
|------------|-------------------|------------------|----------------------|
| POST       | fragment (msg)    | `be post fix`    | `be post '#fix'`     |
| GET        | query (branch)    | `be get feat`    | `be get ?feat`       |
| HEAD       | query (branch)    | `be head main`   | `be head ?main`      |
| PATCH      | query (branch)    | `be patch trunk` | `be patch ?trunk`    |
| PUT        | path (file)       | `be put file.c`  | `be put ./file.c`    |
| DELETE     | path (file)       | `be delete README` | `be delete ./README` |
| verbless   | path (file)       | `be file.c`      | `be ./file.c` (bro)  |

Tokens with explicit markers bypass the bareword default and
parse as URIs per `dog/DOG.md`:

  - `?token` — force query slot.
  - `#token` — force fragment.
  - `./token`, `/token`, or any token containing `/` — force path
    (URILexer reads it as a real path).
  - `'token with space'` — auto-fragment (whitespace heuristic).
  - `scheme:token` — URI lexer.

The promotion is idempotent and shape-aware: any token with a
`/` in it stays a path regardless of verb (so `be patch
feat/fix` is the path `feat/fix`, not the branch — type
`?feat/fix` for the branch).

##  Schemes — cached vs transport

`//host` is a **label**; `scheme://host` is a **wire**.

  - **Cached form (no transport scheme)**: `be ... //origin` reads
    only the locally-cached remote-tracking refs in
    `.dogs/refs`.  No network.  Useful for "what does the cache
    say" inspection and for verbs that can use the last-known
    remote tip without refresh (rebase, ahead/behind diff).
  - **Transport form (`ssh:`, `https:`, `be:`)**: opens a
    connection.  `be get ssh://origin?feat` fetches `feat`'s pack
    and updates the cached refs.  `be head ssh://origin?feat`
    fetches refs (and just enough pack to compute the diff).

| Scheme  | Meaning |
|---------|---------|
| *(none)*| Local store, current branch dir.  `//host` alone is the local-cached view of remote `host`. |
| `ssh:`  | Remote host over ssh; opens a wire. |
| `https:`| Remote host over https. |
| `be:`   | Peer dog over `keeper upload-pack` / `receive-pack` (`keeper/WIRE.md`). |
| `file:` | Local sibling worktree/store at the given path (see §"Worktree management"). |

PUT-to-remote (`be put //origin`) is the one exception that
opens the wire from a `//host` URI — PUT-to-remote is by
definition a write, never a read; the cached form would have
nothing to write to.

###  View projectors

Read-only verbs in their own right.  Projectors emit `dog/HUNK`
streams for bro to page; they never mutate.

| Scheme    | Emits                                            | Example |
|-----------|--------------------------------------------------|---------|
| `sha1:`   | 40-hex sha of the resource                       | `be sha1:?feat` |
| `blob:`   | raw bytes of a blob                              | `be blob:file.c?123abc` |
| `tree:`   | tree listing (mode, sha, name)                   | `be tree:src/?feat` |
| `commit:` | commit object body                               | `be commit:?123abc` |
| `log:`    | `REFS` tail, newest-first, one commit per line (`#N` = last N) | `be log:?feat#10` |
| `refs:`   | list refs under a dir (`**` = recursive)         | `be refs:?**` |
| `diff:`   | weave-based unified diff; right-hand side is *ours* (the changed state).  `diff:` and `diff:<path>` use the wt as *ours* and the sniff `--at` baseline as the from-side; `diff:?<branch>` and `diff:<path>?<branch>` use the baseline as *ours* and `<branch>` as the from-side; `diff:?<from>#<to>` is explicit (query = from-rev, fragment = to-rev). | `be diff:file.c`, `be diff:?main`, `be diff:?v1#v2` |
| `size:`   | byte size of the resource                        | `be size:?#abc1234` |
| `type:`   | object type (`commit`/`tree`/`blob`/`tag`)       | `be type:?#abc1234` |
| `spot:`   | structural search; body in fragment, optional `.ext` filter | `be spot:#'u8sFeed( a, b )'.c` |
| `grep:`   | literal substring search                         | `be grep:#u8sFeed.c` |
| `regex:`  | PCRE search                                      | `be regex:#'u\d+sFeed'.c` |

Search projectors compose: `be spot:/graf?feature#HASHu64Put`
is "structural search for `HASHu64Put` under `/graf` on branch
`feature`".  All four URI slots compose; any combination is
valid.

##  Verbless invocations

`be <bareword>` with no verb opens the resource in `bro`, the
syntax-highlighted pager:

| Form | Effect |
|---|---|
| `be path/to/file.c`     | Open file in bro. |
| `be path/to/dir/`       | Browse directory in bro (tree listing). |
| `be ?feat`              | Browse branch's tree at its tip. |

Verbless `be <projector:>` runs the projector (see §"View
projectors").  Bare `be` (no args) is shorthand for `be head` —
context-aware ahead/behind diff: cur vs trunk when cur ≠ trunk;
cur vs cur's remote counterpart when cur = trunk.

##  Remote resolution

Aliases live in `<store>/ALIAS`, looked up by walking up the dir
tree to the store root.  Cached remote-tracking refs live in
`.dogs/refs` keyed by alias.

  - `be ... //origin?feat` — read only the cache.
  - `be get ssh://origin?feat` — fetch + checkout; on first use,
    register the URL as alias `origin` (default name from host
    or from `--as=origin`).
  - `be head ssh://origin?feat` — fetch refs + minimal pack to
    compute the ahead/behind diff; cache updated, no checkout.
  - `be put ssh://host/path` — register an alias (no `?ref`,
    no other side-effect).
  - `be put //origin` — FF-push our cur to origin's counterpart
    trunk.  Wire goes through the registered transport.

##  HEAD — peek / dry-run

HEAD is the read-only "what changed and what would change" verb.
It never modifies a branch's history or the wt; with a transport
scheme on a `//host` URI, HEAD does update `.dogs/refs` (the
remote-tracking cache) and pulls just enough pack data to render
the diff.

| Form | Effect |
|---|---|
| `be head`                          | **Implicit target.**  When cur ≠ trunk: ahead/behind cur vs trunk.  When cur = trunk: ahead/behind cur vs the cached remote counterpart (no fetch — use `be head ssh://origin` for that).  Equivalent to bare `be`. |
| `be head ?br`                      | **Explicit target.**  Ahead/behind commits between cur and `?br`, plus list of files that differ. |
| `be head ./path?br`                | Same diff scoped to `path`. |
| `be head '#parallel'`              | Find the commit reachable from cur whose message contains "parallel"; show diff cur vs that commit. |
| `be head //origin`                 | Print cached diff cur vs origin's cur counterpart.  No network. |
| `be head ssh://origin`             | Fetch refs + minimal pack from origin, update `.dogs/refs`, print diff cur vs origin's cur. |
| `be head ssh://origin?feat`        | Same scoped to `feat`. |
| `be head ssh://origin?*`           | Fetch every branch origin advertises (≈ `git fetch`); print summary. |

##  GET — repo → worktree

GET reads from the repo into the worktree: clone (transport
scheme), checkout, switch branch.  GET is **repo-read-only**:
it never modifies a branch's history.  Like git, GET refuses if
any wt file with local edits would be overwritten — abort up
front, no partial reset.  Projector views are **not** GET — see
§"View projectors"; each one (`sha1:`, `blob:`, `log:`, …) is
its own verb.

GET refuses on a missing ref (mirror of `cd nonexistent`); use
PUT to mint the leaf first.

For the **transport-scheme remote** form (`be get
ssh://origin?A`), GET is also **fast-forward-only** on the
*local branch's tip*: it refuses if the local tip is not an
ancestor of the incoming remote tip.  This rule applies only
when GET is syncing a local branch from its remote counterpart,
not to local branch switches.

| Form | Effect |
|---|---|
| `be get ?feat`                    | Switch wt+cur to branch `feat`, reset files from its tip.  Refuses on dirty overlap or missing ref. |
| `be get ?./fix`                   | Switch wt+cur to child branch `fix`; error if missing (PUT first). |
| `be get ?abc1234`                 | Detached checkout on a sha.  POST/PATCH refuse until re-attached. |
| `be get '#~1'`                    | Rewind cur ref by one commit and reset wt.  Stays attached to cur. |
| `be get file.c?feat`              | Overwrite one file in the wt from another branch's tip (no staging). |
| `be get //origin?feat`            | Cached read of origin's `feat` ref + pack already in store; reset wt to its tip.  No network. |
| `be get ssh://host/path?feat`     | Open wire, fetch `feat` (pack + REFS), checkout, register alias on first use. |
| `be get file:../proj?feat`        | Local sibling: wire this empty cwd as a wt sharing `../proj`'s store, reset files to `feat`'s tip. |

After a successful GET, `.sniff` records the new base as
`(branch, tip-sha)` and clears any pending PATCH parents.  Bare
`be get` is a no-op status (≡ bare `be`).

##  POST — advance cur

POST is the **commit-mover**: it creates one new commit and
advances **cur** (the current branch's tip).  Cur is the only
ref POST advances — never another branch.  POST scans `patch`
rows since the pd boundary (most recent `get`/`post`) and
assembles the new commit's headers from them; URI components on
POST itself supply only the message and remote hint:

  - **`#frag`** — commit message.  Without a fragment, POST
    derives the message from `patch` rows (see "Message
    resolution" below).
  - **`?branch`** — after committing on cur, **FF-advance**
    `?branch` to cur's new tip.  Refused (`POSTNOFF`) if cur is
    not a descendant of `?branch.tip`.  Cur is *not* rewritten;
    only the named ref moves.  This is the cross-branch promote
    flow (e.g. `be post ?..` after eager branching brings the
    sub-branch's work up to its parent).
  - **`//remote`** — after committing on cur, FF-push cur's new
    tip to the remote's counterpart ref (transport scheme opens
    a wire; cached form refuses since push needs the wire).
    Same FF check as `?branch`.

###  Parent / foster / picked assembly

For each `patch` row in scope, POST classifies by URI shape and
emits the corresponding header on the new commit:

| Patch row URI       | Op           | Emitted on commit            |
|---------------------|--------------|------------------------------|
| `?<sha>`            | squash       | one `foster <sha>` header    |
| `?<sha>#<msg>`      | merge        | `parent <sha>` header        |
| `?<sha>#`           | rebase one   | `foster <sha>` header        |
| `#<sha>`            | cherry-pick  | `picked: <sha>` trailer      |

First parent is always cur's previous tip.  Headers are emitted
in the order patch rows were appended.  Multiple patch rows
compose freely (e.g. two rebase-ones plus a cherry-pick =
two foster headers + one picked trailer).

###  Message resolution

POST picks the commit message in this order:

 1. POST's own `#frag` if present — wins.
 2. Else count commits applied across in-scope patch rows: if
    **exactly one** carries a usable msg (rebase-one's reused,
    cherry-pick's reused, or merge's explicit `?br#msg`), use it.
 3. Else refuse with `POSTNOMSG`.

Squash never auto-supplies a message (multiple commits
collapsed); the user must provide one on POST or the command
refuses.

Empty POSTs (no patch rows in scope and no `#frag`) are refused
with `POSTNONE`.

###  Per-file classification via stamps

Every row sniff writes (`get`, `post`, `patch`, `put`) stamps
each file it touched with the row's `ts` via `utimensat`.  At
POST time we read each on-disk file's mtime and look up the
owning row by ts:

| `mtime` lookup            | Fate (selective mode¹) | Fate (implicit mode²) |
|---------------------------|------------------------|------------------------|
| `< last_get_ts`           | KEEP (unchanged since reset) | KEEP |
| `get` / `post` row        | KEEP (baseline content)      | KEEP |
| `patch` row               | REWRITE (merged bytes)       | REWRITE (merged bytes) |
| `put` row                 | REWRITE (current bytes)      | REWRITE (current bytes) |
| ∉ stamp-set, **tracked**  | ignore unless explicit `put` named it | REWRITE (commit-all-tracked) |
| ∉ stamp-set, **untracked**| ignore (needs explicit `put`) | ignore (needs explicit `put`) |

¹ Selective = at least one explicit `put` / `delete` row since
last post.  ² Implicit (a.k.a. commit-all) = none.  An untracked
file (one that's not in the baseline tree) **never** sweeps into
a commit by accident — even bare `be post 'msg'` requires
`be put <path>` first to add a new file.  Edited *tracked* files,
on the other hand, do flow into the implicit-mode commit (mirrors
git's `commit -a`).

###  First-parent linearity

The new commit's **first** parent is always cur's previous tip
— period.  Walking first-parents from any commit reaches its
fork point in a straight line.  Additional parents and `foster`
headers come from in-scope `patch` rows (see "Parent / foster /
picked assembly" above); their reachability participates in the
ancestor-skip walk on subsequent PATCHes.  Cross-branch
deduplication has two sources: foster/parent reachability when
the absorbed work is now in the DAG, and patch-id matching as a
safety net for replays.

###  ULOG scope and boundaries

Two boundaries in `.sniff`, both anchored at the most recent
`get` row (a `get` is a hard reset of the world):

  * **pd boundary** — most recent `get` *or* `post`.  `put` /
    `delete` rows after this are in scope for the next POST.
  * **patch boundary** — most recent `get` *or* commit-all
    `post`.  `patch` rows after this are in scope.

A `post` row classifies as commit-all iff no put/delete rows
lie between its own pd boundary and itself; determinable on the
fly from a single forward scan, so no new ULOG verb is needed.

###  Wall-clock guard

Every command checks `now ≥ last_log_ts` on entry and refuses
with `CLOCKBAD` if the system clock has moved backwards.  One
`ts` is reserved per command, shared by every row + file stamp
written in that invocation.

Commit-message channel: a quoted whitespace-bearing arg
classifies as fragment automatically (`be post 'fix the
typo'`).  Single-word messages need explicit `#`:
`be post '#fix'`.  Legacy `-m "msg"` is still accepted.

| Form | Effect |
|---|---|
| `be post`                          | Commit on cur using msg derived from in-scope patch rows (see "Message resolution"); refused if none/ambiguous. |
| `be post 'fix the typo'`           | Commit on cur (msg = "fix the typo"); cur advances.  Patch rows in scope contribute parent/foster/picked headers. |
| `be post '#fix'`                   | Commit on cur (msg = "fix"); cur advances. |
| `be post ?..`                      | Commit on cur, then FF-advance parent branch to cur's new tip.  `POSTNOFF` if cur isn't a descendant of `?..tip`. |
| `be post ?feat`                    | Commit on cur, then FF-advance `?feat` to cur's new tip. |
| `be post ssh://origin`             | Commit on cur, then FF-push cur's new tip to origin's counterpart over the wire. |
| `be post //origin`                 | Same as above using the configured transport scheme; cached form alone (no transport) is refused since push needs the wire. |

Each POST appends one entry to cur's `REFS` for the new commit.
Patch-id dedup (`GRAFPatchId`) acts as a safety net to skip a
foster/parent absorption whose diff is already reachable from
cur — distinct from header assembly, which always runs.

##  PUT — write a ref

PUT is the **ref-writer**: it writes one row to `.dogs/REFS` (or
remote refs, for `//host`), and may stage blobs into keeper for
the next POST.  PUT **never creates commits** — that's POST's
job.  The URI components combine orthogonally:

  - **`?branch`** — the ref to write.  Default: cur.
  - **`./path`** — path whose dirty bytes are hashed into keeper
    as a blob and recorded in a `put` row in `.sniff`.  The blob
    is now staged for the next POST.
  - **`//remote`** — push our local ref-value to the remote's
    counterpart.  FF-checked at the wire.
  - **`#sha`** — explicit sha to write into the ref.  Without
    `#sha`, the default is `cur.tip` (label move).

Bare `be put` (no URI) stages every tracked-and-dirty file —
each gets a blob hashed into keeper and a `put` row stamped
with the command's ts.

| Form | Effect |
|---|---|
| `be put`                | Stage every tracked-and-dirty file (one `put` row per path).  Refuses with `PUTNONE` if no tracked file is dirty. |
| `be put file.c`         | Stage one file.  Refuses with `PUTNONE` if missing or already clean.  Re-stamps the file. |
| `be put src/`           | Stage a subtree: every dirty-tracked file plus every untracked (non-ignored) file under it. |
| `be put ?./fix`         | `mkdir`-the-branch: `?./fix` ⇒ cur.tip (label-only fork; no synth commit, no wt change). |
| `be put ?../sib`        | Sibling branch label at the parent's tip. |
| `be put ?feat/new`      | Absolute leaf `feat/new` under existing `feat`. |
| `be put ?br#abc1234`    | Reset `?br` to sha `abc1234`.  Non-FF rewrite is allowed (PUT is unconstrained on the local namespace). |
| `be put //origin`       | FF-push cur to origin's counterpart trunk.  Refused on remote-side concurrent change. |
| `be put //origin?br`    | FF-push our `?br` to origin's `?br`. |
| `be put ssh://host/path`| Register as a remote alias (name from host, or `--as=name`).  No `?ref` ⇒ alias-register only. |

PUT writes to `<wt>/.sniff` (for `./path` rows) and
`.dogs/REFS` (for `?branch` and `?branch#sha`); blobs land in
keeper.  No commit objects are written by PUT.

A `put` on a clean baseline-stamped file is refused —
re-stamping it under a `put` row would shift its provenance
from baseline to put for no semantic gain.

##  DELETE — remove

DELETE removes things — files, branches, aliases, remote refs.
In-tree paths are unlinked **immediately** (after a dirty-safety
check); a ref URI drops the branch dir.

The dirty check refuses (`DELDIRTY`) if the file's mtime is out
of the stamp-set **and** its content differs from the baseline
sha (cheap mtime check, content-hash only on drift).
Already-absent paths are an OK no-op.

| Form | Effect |
|---|---|
| `be delete`                         | Stage every tracked file that's missing on disk.  Mirror of bare PUT.  One `delete` row per absent file. |
| `be delete file.c`                  | Unlink the file (refused as `DELDIRTY` if user-edited); append `delete file.c` row. |
| `be delete src/`                    | Atomic pre-flight: scan all descendants; refuse if any is dirty.  On pass, unlink all + append one `delete src/` row. |
| `be delete ?feat/fix1`              | Drop a branch dir.  Leaf-only by default; refused with `DELDESC` if descendants exist or any wt's `.sniff` records this branch as base.  Reclaims unreachable shards. |
| `be delete -r ?feat`                | Drop the branch and every descendant, depth-first (leaves first).  Still refused if any wt has it as base. |
| `be delete //origin?feat`           | Push a delete (`<old> 000…0 refs/heads/feat`) via `keeper receive-pack`. |
| `be delete //origin`                | Drop the remote alias entry from `<store>/ALIAS`.  No network. |

##  PATCH — absorb commits into wt

PATCH absorbs commits from another branch into cur's wt and
records the absorbed sha(s) in `.sniff` for the next POST to
consume.  PATCH itself does not commit; the cycle is
**patch → test → post**, run once per merge / cherry-pick /
squash, or looped per commit for rebase.  This makes every
recorded commit a tested commit — no chain of unverified work
ever lands.

###  Four URI shapes

| User input        | Op           | Applies                          | POST records as                |
|-------------------|--------------|----------------------------------|--------------------------------|
| `?<br>`           | squash       | full `fork..br.tip` as one wt-merge | one `foster` header (br.tip) |
| `#<hash>`         | cherry-pick  | the one named commit             | `picked: <hash>` trailer       |
| `?<br>#<msg>`     | merge        | full `fork..br.tip` as one wt-merge | `parent` header (br.tip)     |
| `?<br>#`          | rebase one   | the next not-yet-replayed commit on `?br` | `foster` header (that commit) |

Shape classification is the URI form alone: presence of `?`,
presence and emptiness of `#`.  All four shapes accept the usual
URI extras — `//host` to fetch first, `./path` to scope the
absorption to one path, and so on — combined orthogonally.

###  Ancestor-skip walk

Squash and merge replay only commits not already reachable from
cur via parent ∪ foster.  `picked` trailers are dedup-only and
do **not** participate in reachability.  Rebase-one (`?br#`)
picks the next commit on `?br` not yet absorbed by cur, by
walking br's first-parent chain and stopping at the first sha
already reachable.

###  Path-scoped PATCH

When the URI carries a non-empty path slot (e.g.
`be patch file.c?feat`, `be patch src/?trunk#`), the absorbed
bytes land in the wt for those paths only.  The resulting row
carries the path but **no `&<theirs>` slot**: POST emits no
foster / parent / picked header for it, and the row contributes
zero "applied commits" to POST's message resolution.  Rationale:
a partial absorption is not a faithful record of any DAG commit,
so neither reachability nor msg reuse is sound.  Use a full
(no-path) shape if you want POST to record provenance.

###  Reporting

Every PATCH prints a ULOG-style report — one line per applied
commit and per touched file, in `<verb>\t<status>\t<path-or-uri>`
form — matching bare `be`'s output shape.  This keeps the
patch-test-post loop auditable: you can see what changed before
deciding to POST.

Per-file status is one of:

| Status     | Meaning |
|------------|---------|
| `applied`  | file was clean (at baseline or stamped) and has been overlaid with *theirs* bytes — no merge needed. |
| `merged`   | file had non-baseline bytes (user edits or prior PATCH output) AND theirs touched it; WEAVE 3-way merge integrated both sides cleanly. |
| `dirty`    | file had non-baseline bytes; theirs did **not** touch this path; the dirty bytes are preserved untouched. |
| `conflict` | file had non-baseline bytes AND theirs touched it AND WEAVE could not auto-resolve; conflict markers are now in the file. |

Conflicts are **loud**: every `conflict` row is also written to
stderr, and PATCH exits non-zero so an unattended `patch && post`
chain stops before recording a half-merged commit.  The wt is
left with the markers in place for the user to resolve.

###  Weave merge into dirty wt

PATCH does **not** refuse on dirty files.  It runs a WEAVE
3-way merge with the absorbed commit on the *theirs* side and
the wt's current bytes (including user edits AND any prior
PATCH's output) on the *ours* side.  Previous PATCH applications
look exactly like user edits: the merge composes them with the
new absorption.  PATCH-on-PATCH on overlapping files works by
construction.

Conflicts that cannot be auto-resolved are marked **token-level**
with 4-character delimiters (`<<<<` / `>>>>`), not the line-level
7-char markers git uses.  Existing diff/merge UIs and
`git mergetool` won't recognize them; hand-edit, or use a
`diff:?` projection to enumerate.

###  Common forms

| Form | Effect |
|---|---|
| `be patch ?..`                      | Squash parent's stack into wt.  Foster on next POST. |
| `be patch ?./fix`                   | Squash child branch `fix` into wt. |
| `be patch ?feat/fix#`               | Rebase one commit from `feat/fix` onto cur. |
| `be patch ?trunk '#sync from trunk'`| Merge trunk into cur with explicit msg. |
| `be patch '#abc1234'`               | Cherry-pick `abc1234`.  Picked trailer on next POST. |
| `be patch ssh://origin?main`        | Fetch + squash remote branch.  ≈ `git pull --squash --no-commit`. |
| `be patch file.c?feat`              | Apply one file's version from `?feat` into the wt (no foster row). |
| `be patch spot:#'Old'->'New'.c`     | Delegated to spot: in-place structural rewrite across `.c` files. |

Multiple PATCHes compose: each appends a `patch` row, all of
which the next POST consumes.  Combinations like rebase-one +
cherry-pick + merge are valid — POST emits the corresponding mix
of foster / parent headers and picked trailers in row order.

##  Worktree management

A **store** is the `.dogs/` directory holding packs, indexes,
REFS, and aliases.  A **worktree (wt)** is a checked-out tree on
disk; per-wt state — base branch, base tip, pending PATCH
parents — lives in `<wt>/.sniff` (see `sniff/AT.md`).  A
secondary wt shares the primary's store via a `.dogs` symlink.

One branch can only have one active worktree; that is tracked
in the branch reflog.

The guiding rule: **a machine only needs one store per upstream
repo**.  Every extra wt is just another dir with a `.dogs`
symlink back.

###  Eager branching: the canonical workflow

Branches are `mkdir`-cheap.  The idiomatic workflow is to
*fork preventively*: any time you're about to do something
speculative, mint a sub-branch first, then experiment freely.
Stash is a code smell — if you wanted to stash, you should have
been on a sub-branch already.

```sh
# on cur with clean wt; about to try something risky
be put ?./feature/exp1            # mkdir
be get ?./feature/exp1            # cd

# go wild — multiple commits, some discarded, doesn't matter
vim ...
be post '#trial 1'
vim ...
be post '#trial 2'

# need to chase a different idea?  fork again, deeper
be put ?./feature/exp1/deeper
be get ?./feature/exp1/deeper
... more wild work ...

# come back to wherever you were originally
be get ?other-branch
```

When the experiment pans out, bring it home as a single squash
on the parent:

```sh
# on the parent branch
be patch ?./feature/exp1/deeper   # weaves the entire deep chain into wt
be post '#feature: exp1 + deeper'  # one single-parent commit
```

The nested branch chain itself encodes the experimentation
history; PATCH absorbs it as one squash, no merge commit, no
recorded provenance.  The `exp` branches keep existing — they're
free recovery points.  If the experiment was a dead end,
`be delete -r ?./feature/exp1` drops the lot.

###  Example 1 — same tree, flip between two named refs

```sh
mkdir proj && cd proj

# clone + checkout v1.2.3 into this tree
be get ssh://server/proj?v1.2.3

# fetch v1.2.4 from the same origin
be get ssh://origin?v1.2.4

# flip this tree to v1.2.4
be get ?v1.2.4

# …inspect…
be get ?v1.2.3
```

###  Example 2 — sibling worktrees on different branches

```sh
# primary store + wt
mkdir proj && cd proj
be get ssh://server/proj?v1.2.3
be get ssh://origin?v1.2.4         # populate v1.2.4 in the shared store

# spawn sibling wts
cd ..
mkdir v1.2.3 && (cd v1.2.3 && be get file:../proj?v1.2.3)
mkdir v1.2.4 && (cd v1.2.4 && be get file:../proj?v1.2.4)
```

Now `proj/`, `v1.2.3/`, and `v1.2.4/` each have a `.dogs`
symlink to the primary store and their own `.sniff` recording
the branch they sit on.

###  Example 3 — feature branch workflow

```sh
# on trunk wt
cd proj
be put ?./feat              # mkdir feat at trunk's tip
be get ?./feat              # cd into feat
echo patch > new.c
be post '#feat stub'        # commit on feat (=cur)
be put ssh://origin?./feat  # FF-push feat to origin

# back on trunk
be get ?..
be patch ?./feat            # weave feat's delta into trunk's wt
be post '#sync feat'        # single-parent commit on trunk
```

###  Example 4 — close a worktree

```sh
cd ..
rm -rf proj-feat
```

Closing a wt is just removing its dir.  Branch dirs (packs,
REFS) stay put in the primary store.  Use `be delete ?feat` from
another wt to actually drop the branch.

##  Common-task cheat sheet

| git | be |
|---|---|
| `git clone URL`                        | `be get ssh://URL` |
| `git fetch`                            | `be head ssh://origin?*` |
| `git pull --ff-only`                   | `be patch //origin?` + `be post` (ff if linear, else refuses) |
| `git pull`                             | `be patch //origin?#` (rebase-one) loop, or `be patch //origin? '#merge'` for a merge commit |
| `git pull --rebase`                    | `be patch //origin?#` + `be post`, looped per commit |
| `git checkout -b feat`                 | `be put ?./feat && be get ?./feat` (PUT mkdir, GET cd) |
| `git checkout feat`                    | `be get ?feat` |
| `git worktree add ../feat feat`        | `cd ../feat && be get file:../proj?feat` |
| `git add file && git commit -m`        | `be put ./file && be post '#msg'` |
| `git commit -am "…"`                   | `be put . && be post 'msg with space'` |
| `git rm file && commit`                | `be delete ./file && be post '#msg'` |
| `git branch -d feat`                   | `be delete ?feat` |
| `git merge trunk`                      | `be patch ?trunk '#sync trunk' && be post` (parent header on cur) |
| `git cherry-pick <sha>`                | `be patch '#<sha>' && be post` (picked trailer; msg reused) |
| `git stash`                            | use a sub-branch — see §"Eager branching" |
| `git push`                             | `be put ssh://origin` |
| `git push -d origin feat`              | `be delete //origin?feat` |
| `git rev-parse HEAD`                   | `be sha1:?` |
| `git cat-file -p <sha>:file.c`         | `be blob:file.c?<sha>` |
| `git log -n 20 feat`                   | `be log:?feat#20` |
| `git branch -a`                        | `be refs:?**` |
| `git ls-remote origin main`            | `be sha1:ssh://origin?main` (fresh) or `be sha1://origin?main` (cached) |
| `git status`                           | `be` (bare) |

##  Design invariants

 1. **Verb × URI shape is unambiguous.**  A ref-only URI targets
    the branch dir (create/drop/switch).  A path+ref URI targets
    a file in that branch.  `//host` is cached unless paired
    with a transport scheme.  The projector scheme only reshapes
    the output.
 2. **First-parent linearity; multi-parent at POST.**  Walking
    first-parents from any commit reaches its fork point in a
    straight line.  Additional `parent` headers (merge) and
    `foster` headers (squash, rebase-one) come from in-scope
    `patch` rows at POST time; cherry-pick contributes a
    `picked` trailer with no DAG edge.  PATCH records the
    absorbed sha; provenance is no longer erased.
 3. **POST is the only commit-maker; PUT is the only ref-writer.**
    POST advances cur, reading `patch` rows since the pd
    boundary to assemble headers.  A populated `?branch` /
    `//remote` slot additionally **FF-advances** that ref to
    cur's new tip after the commit (refused with `POSTNOFF` if
    cur isn't a descendant).  PUT writes one (ref, sha) row to
    `.dogs/REFS`, optionally staging blobs into keeper for the
    next POST; PUT never creates commits.  GET is repo-read-only
    and refuses on dirty overlap.  Empty POSTs (`POSTNONE`) and
    message-less POSTs that can't auto-resolve (`POSTNOMSG`) are
    refused.  POST never rewrites cur's history; rebase is
    `patch ?br#` + `post`, looped.
 4. **Cheap branches; mkdir/cd separation.**  Branches are
    one-row reflog entries with empty pack logs.  `be put ?./A`
    creates the branch (mkdir); `be get ?./A` enters it (cd).
    The two are deliberately separate.  GET refuses on missing
    refs.
 5. **Eager branching replaces stash.**  The model encourages
    forking preventively; speculative work happens on a
    sub-branch, never on cur.  If you need to stash, you should
    have already been on a sub-branch.
 6. **One store per machine, many worktrees.**  Per-wt state
    lives in `<wt>/.sniff` (base branch, base tip, pending PATCH
    parents).  Secondary wts symlink `.dogs` back to the
    primary.
 7. **Detached mode is explicit** (`?<sha>` with no branch);
    `post`/`patch` refuse on detached wts.
 8. **Cached vs transport for remotes.**  `//host` reads only
    the locally-cached remote-tracking refs; `scheme://host`
    opens a wire.  HEAD with a transport scheme is the canonical
    way to refresh the cache.  POST/PATCH/GET on `//host` use
    the cache without network; on `ssh://host` they fetch first.
    PUT `//host` is the one cached-form exception that opens a
    wire — PUT-to-remote is by definition a write.
 9. **Remote operations are fast-forward only.**  Divergence is
    resolved client-side with PATCH + POST, never by the peer.
10. **Projector schemes are read-only.**  They never mutate —
    safe to compose with any verb.
11. **Git-peer interop: byte-faithful, topology-flat.**  Branch
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
    receive-pack.
  - **Bulk fetch (`?*`)** — ordering rule:
    parents-before-children, per the delta-dependency DAG; the
    client walks the ancestor chain and runs N upload-pack
    sessions.
  - **Projector + mutating verb** — `be post sha1:?feat` etc.
    is not a thing; projectors are their own verbs (read-only).
  - **Conflict marker normalisation.**  Token-level 4-char
    delimiters need a stable wire format so downstream tools
    (bro, graf-resolve, future `git mergetool` adapter) can
    parse them uniformly.
  - **`picked` trailer wire format.**  Cherry-pick records the
    picked sha in the commit message as a trailer; exact key
    name (`picked:` / `cherry-picked-from:` / other) and parser
    contract still TBD.  Multiple picked trailers from one POST
    accumulate in row order.
  - **Path-scoped PATCH provenance.**  A path-scoped PATCH
    intentionally records no header (partial absorption isn't a
    faithful DAG commit); if we ever want a "partial picked"
    trailer that names `<sha>:<path>` for forensics, that's a
    future extension.
  - **Squashing / repacking.**  The current GC path is "delete
    branch" (drops shards reachable only from that branch dir).
    A real squash (consolidate a branch's REFS into a single
    commit without dropping the branch) is TODO.
  - **Trunk for git peers.**  First contact reads the remote's
    `HEAD`; if absent, prefer `main` then `master`.
  - **Bare `be head` output shape.**  Exact format of the
    "ahead/behind cur vs parent + dirty list" summary still TBD.
  - **HEAD is a new verb.**  Not yet wired in `BE_CLI_VERBS` (see
    `beagle/BE.cli.c`); spec lands first, code follows.
