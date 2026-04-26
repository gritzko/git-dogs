# beagle — git dogs dispatcher

`be` is the command that ties the dogs together.  No verb = view.
A verb = an action with a direction.

## View (no verb — read-only, never mutates)

    be abc/MSET.h                     bro: syntax-highlighted cat
    be abc/MSET.h#42                  bro: view file, jump to line 42
    be abc/MSET.h#L10-L30             bro: view file, line range
    be abc/                           list directory
    be .                              status (all dogs report)

## Search (no verb, #fragment)

    be #TODO.c                        spot: grep "TODO" in .c files
    be #'ok64 o = OK'.c              spot: structural search in .c
    be #/u8s.*Feed/.h                spot: regex search in .h
    be #BROHunkNext                   spot: grep all files
    be abc/MSET.h#MSETOpen            spot: grep one file for "MSETOpen"

## Get (repo → worktree)

    be get ?feat                      checkout branch feat
    be get ?refs/tags/v1.0            checkout tag
    be get abc/MSET.h?main            checkout file from branch main
    be get //origin?main              fetch + checkout
    be get //origin                   fetch + refresh checkout

## Post (worktree → repo)

    be post abc/MSET.h                stage file
    be post .                         stage subtree + commit (dry-run sans msg)
    be post . fix MSET                stage subtree + commit with message
    be post ?refs/heads/feat          commit to branch
    be post MSET.h?feat               commit file to branch

## Put (repo → repo)

    be put //origin                   push to origin
    be put //origin?main              push branch main
    be put //backup                   push to backup remote

## Diff

    be diff abc/MSET.h                graf: diff working tree vs HEAD
    be diff ?HEAD~3                   graf: diff vs 3 commits back
    be diff ?main..feat               graf: diff between branches
    be diff //origin?main..HEAD       graf: diff local vs remote

## Patch (worktree → worktree)

    be patch #'OldFunc(x)'->'NewFunc(x)'.c    spot: rename across .c
    be patch #'malloc(sizeof(a)*B)'->'malloc(B*sizeof(a))'.c

## Delete

    be delete abc/tmp.md              stage file deletion
    be delete ?refs/heads/feat        delete branch
    be delete ?refs/tags/v1.0         delete tag

## URI grammar

    [//authority] [path] [?ref] [#search[.ext]]

- `//authority` — remote host or alias (`//origin`, `//github.com/user/repo.git`)
- `path` — repo-relative file or directory
- `?ref` — branch, tag, SHA, range (`?main`, `?HEAD~3`, `?main..feat`)
- `#search` — line, grep, spot, regex; trailing `.ext` filters by type

Short refs resolved by trying refs/heads → refs/tags → SHA.
See `beagle/GURI.md` for the full spec.

## Dogs

`be` dispatches to the dogs based on verb + URI pattern:

| dog | role |
|-----|------|
| **bro** | view files, page search results |
| **spot** | search, grep, replace, trigram index |
| **graf** | token-level diff, merge, git driver |
| **sniff** | worktree management (checkout, status) |

Bare `be` (no args) runs `--update` then `--status` on each dog
listed in `.dogs/DOGS` (default: spot, graf, sniff).
