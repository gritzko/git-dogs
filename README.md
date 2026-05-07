#   Beagle

**Beagle** is a revision control system suitable for modern
workflows.  The data format and the syncing protocol are 100%
git to stay compatible with the existing mass of git repos. The
rest is reworked. 

 1. The system is made syntax-aware, diffing and merging is finer 
    grained and draws heavily from CRDT ideas. No false conflicts. 
 2. Content is indexed for efficient search. May grep fast, use
    regexes, search for code snippets/templates (syntax aware).
 3. CLI UX is reworked; *beagle* uses HTTP-like command language
    of verbs and URIs (get, post, put, delete etc). Not a zoo of
    CLI flags, but *uniform* language/syntax for everything.
 4. The branching model is tree-like (e.g. `feature/fix`), very
    patch stack friendly (e.g. to rebase the stack as one),
 5. The UI is reworked as well. 

Beagle focuses on making a comfortable git client for local
multi-branch multi-worktree development.  While Beagle's command
language can express any git operation, the model steers the
user towards tree-structured rebase-centric branching model.

The project dogfoods from day 1.

## Quick start

Build (requires libsodium, libcurl, lz4, zlib and cmake; ninja recommended):

    mkdir build && cd build
    CC=clang CXX=clang++ cmake -GNinja -DCMAKE_BUILD_TYPE=Release ..
    ninja
    ls bin/

## Using `be`

Beagle's dispatcher command is `be`. It only uses standard URI arguments
`scheme:host/path?version#message` and the verbs from the HTTP dictionary
that cover all possible data maneuvers. 

  * read-only commands
     - `GET` fetches/checks out a particular version/branch/project,
     - `HEAD` is `GET` dry-run, lists the changes to the version/branch,
  * read-write commands
     - `POST` advances the current branch (commit, fast-forward, rebase),
        this is worktree-to-repo write,
     - `PATCH` applies changes from another branch to the working tree,
        this is repo-to-worktree write,
  * reflog commands
     - `PUT` sets branch tip, adds a file, etc,
     - `DELETE` deletes a branch, a file, etc.

Beagle branches are tree-ordered, e.g. `feature/fix` for regular or
`feature/phase1/phase2` for stack-of-diffs workflows.

### GET: checkout / fetch / view / search

    be get ssh://host/repo.git       # clone (fetch + checkout + index)
    be get ?v1.2                     # checkout the "v1.2" ref locally
    be path/to/file.c                # open the file in the pager (bro)
    be grep:path/to/file.c#TODO      # grep inside one file
    be spot:#FuncName                # structural search across repo

### POST: commit / fast-forward / rebase

    ...                              # above: be get, etc
    vim file.c                       # go wild
    be post "wonderful changes"      # commit
    be head //host                   # see if remote changed
    be post //host                   # rebase to remote's tip

### PUT/DELETE: reflog edits (stage, add/remove branch)

    ...
    be put src/foo.c src/bar.c       # stage two files
    be put                           # stage everything dirty
    be delete src/obsolete.c         # stage removal of one path
    be delete                        # stage every tracked file rm'd on disk
    be post "new files"              # commit
    be put //host                    # fast forward remote to the head

### Projections

Apart from verbs, Beagle has *projections*: read-only and
presentation-only *verbless* use, e.g. `be diff:?other_branch`
or `be log:file.c` or `be grep:TODO`. These typically can be
used with URIs of any shapes, e.g. `be diff://host/file.c?remote_branch`.

## The dogs

<img src="dog/dogs.png" width="50%" align="right"/>
The repo is structured into *dogs*. Each dog has its purview, the
data and functions it is responsible for. Dogs coordinate to carry
out complex tasks.

  * **Bro**: interactive syntax-highlighted pager/viewer. 
  * **Spot**: structural code search, grep, regex, and replace 
    across a repo. Maintains a trigram index for instant lookups.
  * **Graf**: does token-level diffing, 3-way merges, history
    navigation. Maintains a history index. 
  * **Sniff**: serves the worktree, detects changes.
  * **Keeper**: keeps the data per se (git blobs, trees, commits).

New dogs may join, old dogs may learn new tricks.
If it works, it gets used. If it's used, it evolves.

##  FAQ

*Is this git based?*
This is git-compatible. git does not provide meaningful API for
external tools, unfortunately. Also, git's internal format 
junglified over 20 years of evolution. Meanwhile, git's internal
object model is simple and sound.

*Is this VC funded?*
Nope. The project is ran on old hardware discarded by a university. 
Heavy things (eg massive fuzzing), all run on a 32 core discounted
Hetzner server. Coding is mostly done by Claude Max, in 2..5 parallel
sessions.

##  Credits

Trigram indexing idea from [Russ Cox][c]. Dogenizers started with
[tree-sitter][t], later rewritten as [ragel][r] scanners for speed.
The Merkle scheme is by Linus Torvalds.

[c]: https://swtch.com/~rsc/regexp/regexp4.html
[r]: https://www.colm.net/open-source/ragel/
[t]: https://tree-sitter.github.io/tree-sitter/
