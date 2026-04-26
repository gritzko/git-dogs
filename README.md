# git dogs

**git dogs** is an experiment in refactoring git to make it suitable
for modern workflows. The data model and the syncing protocol are
left as-is to stay compatible with the existing mass of git repos.
The rest is reworked. The system is made syntax-aware, diffing and
merging is finer grained and draws heavily from CRDT ideas. Content
is indexed for efficient search.

The project dogfoods from day 1.

## The dogs

<img src="dog/dogs.png" width="50%" align=right/>
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

## Quick start

Build (requires libsodium, lz4, zlib and cmake, also ninja is recommended):

    mkdir build && cd build
    CC=clang CXX=clang++ cmake -GNinja -DCMAKE_BUILD_TYPE=Release ..
    ninja

## Using `be`

`be` is the dispatcher that ties the dogs together. Every verb is a
pipeline — `be get` fans out to keeper, sniff, spot and graf in turn;
`be post` walks the worktree into a commit and advances refs. See
[beagle/GURI.md](beagle/GURI.md) for the URI grammar.

### Get — checkout / fetch / view / search

    be get ssh://host/repo.git       # clone (fetch + checkout + index)
    be get ?v1.2                     # checkout the "v1.2" ref locally
    be get path/to/file.c            # open the file in the pager (bro)
    be get path/to/file.c#TODO       # grep (spot) inside one file
    be get .#FuncName                # structural search across repo

### Put / delete — stage into a new base tree (no commit)

    be put src/foo.c src/bar.c       # stage two files
    be put                           # stage everything dirty
    be delete src/obsolete.c         # stage removal of one path
    be delete                        # stage every tracked file rm'd on disk

Each `put` / `delete` grows or shrinks the staged base tree in
keeper's object store. HEAD does not move.

### Post — commit the base tree

    be post fix the parser           # commit; trailing words = message
    be post //origin release          # commit and push to the remote

`be post` wraps the current base tree into a commit with parent =
HEAD, advances HEAD, and updates refs. With a remote authority in the
URI the keeper push step is included; without, it's purely local.

### Diff — token-level diff across refs or against the worktree

    be diff path/to/file.c?v1..v2    # one file, ref-to-ref
    be diff path/to/file.c?v1        # one file, ref vs worktree
    be diff ?v1..v2                  # whole tree, ref-to-ref
    be diff ?v1                      # whole tree, ref vs worktree

The URI shape picks the mode: a `?from..to` query diffs two refs, a
bare `?ref` diffs that ref against the current worktree. Add a path
for a single file, leave it off for the whole tree. Output is the
same token-level unified hunk format `graf diff` emits on disk.

### A full workflow

    mkdir my-repo && cd my-repo
    echo 'int main(){return 0;}' > hello.c
    be post initial commit           # first commit, auto-stages hello.c

    echo 'printf("hi\n");' >> hello.c
    be put ./hello.c                 # stage the edit
    be post greet                    # commit

    be get ?$(cat .dogs/sniff/HEAD)  # round-trip: recheck out HEAD

## Other dogs (direct invocation)

    bro file.c                       # syntax-highlighted pager
    graf --diff old.c new.c          # token-level diff
    graf --install                   # register as git diff/merge driver

See each dog's `INDEX.md` (e.g. [sniff/INDEX.md](sniff/INDEX.md),
[keeper/INDEX.md](keeper/INDEX.md)) for the full API surface.

##  FAQ

*Is this git based?*
This is git-compatible.

*Is this VC funded?*
Nope. The project is ran on old hardware discarded by a university. 
Heavy things (eg massive fuzzing), all run on a 32 core discounted
Hetzner server. Coding is mostly done by Claude Max, in 2..5 parallel
sessions.

##  Credits

Trigram indexing idea from [Russ Cox][c]. Tokenizers started with
[tree-sitter][t], later rewritten as [ragel][r] scanners for speed.
The Merkle scheme is by Linus Torvalds AFAIK.

[c]: https://swtch.com/~rsc/regexp/regexp4.html
[r]: https://www.colm.net/open-source/ragel/
[t]: https://tree-sitter.github.io/tree-sitter/
