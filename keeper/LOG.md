# keeper pack log

Pack logs are numbered append-only files holding concatenated
*packs*.  They are the sole storage for object bytes; nothing is
ever mutated in place.  The pack format is based on git packfiles.

Logs are sharded **by branch directory**; each branch dir holds its
own sequence of log files plus its own indexes, reflog and (if the
branch is checked out) a worktree back-pointer:

    <store>/                    trunk (heads/main|master|trunk → "")
        00001.keeper
        00003.keeper
        00001.idx
        refs                    dog/ULOG reflog (see REF.md)
        WT
        feature/
            00002.keeper
            00004.keeper
            00001.idx
            refs

File numbering (`NNNNN`) is **store-wide and sequential** — pack
logs in different branch dirs never share a number.  The physical
file sits in whichever branch dir the pack was written to.

## Append-only pack logs

One log file holds **many packs** appended back-to-back.  Small
packs (e.g. a single local commit) MUST be appended to that dir's
current tail log file — never open a new file just to store one
pack.  A new log file is only started when the current one crosses
a size threshold.  A file has the git packfile header but no
trailing checksum.

Pack boundaries inside a log file are discoverable only via the
index (see pack bookmarks below).  The raw bytes carry no
self-synchronising markers (git's limitation, kept for backward
compatibility).

## Intra-pack object order

Within a single pack, objects MUST appear in type order:

    1. commits   (type 1)
    2. trees     (type 2)
    3. blobs     (type 3)
    4. tags      (type 4)

Git relies on this ordering implicitly (`git repack` produces
type-grouped packs for delta-base locality); keeper makes it an
**explicit invariant** — writers should enforce it, readers may
rely on it.

**Current status (2026-04-22):** enforcement in `KEEPPackFeed` is
**live** for canonical packs.  `keep_pack.strict_order` opts in;
`KEEPPackOpen` sets it automatically.  Sniff staging packs
(see `sniff/STAGE.md`) leave it off — they accumulate tree/blob in
DFS order and are repacked canonically on `be post` (commit first,
then trees via staging walk, then blobs).  A handful of legacy
tests that hand-roll non-canonical packs clear the flag explicitly.

Consequences:

  * A pack's first object is always a commit (or empty / tag-only
    in degenerate cases).  Sync and graf can cheaply identify
    commits by scanning pack prefixes.
  * Trees never reference commits; blobs never reference trees or
    commits; delta bases therefore point earlier in the same pack
    or into an earlier pack.  This rules out forward references
    within a pack.
  * Incoming git packfiles already satisfy the ordering when
    produced by stock git; `KEEPImport` must verify and reject
    packs that violate it rather than silently reorder.

## Stripped git pack framing

Packs are stored with the git packfile header (12 B: `PACK` magic
+ version + object count) and trailer (20 B SHA-1) **stripped**,
except in the beginning of the file. What lands in the log is only
the concatenation of object records (varint header + zlib body,
plus deltas).

This means the stored bytes are not directly a valid git packfile,
but can cheaply be made one. Dog-to-dog sync (see WIRE.md) reframes
on the fly via PSTR (PACK header + concatenated stripped bodies +
fresh SHA-1 trailer).

Object count for reconstruction is read straight from the pack
bookmark's val (`obj_count32 | byte_len32` — see "Pack bookmarks"
below), so per-pack reconstruction (e.g. for the wire encoder in
`WIRE.md` Phase 2) is O(1) — no varint scan, no inflation.  The
git-compat trailing SHA-1 is recomputed on the fly over the
freshly framed bytes when an outgoing pack is sent on the wire.
Per-object 60-bit hashlets in the LSM are untouched.

## Delta-dependency DAG

OFS_DELTA is **pack-local**: the base sits earlier in the same
pack at a known offset.  A pack file can therefore be copied
verbatim between stores (dog-to-dog sync, branch-dir moves)
without rewriting deltas.

REF_DELTA resolves by hash lookup.  Keeper constrains the lookup
to the **dir chain from the pack's home dir up to the store root**:
a REF_DELTA's base MUST live in the same branch dir or in an
ancestor.  Writers that would otherwise delta against an object in
a sibling or descendant dir must materialize the base (emit it raw
into the target dir's pack) instead.

The invariant turns the branch tree into a dependency DAG: leaf
dirs can be dropped wholesale, interior dirs only after descendants
have materialized every cross-dir reference into the ancestor
chain.  See "Drop-a-dir" below.

## Pack bookmarks

Every pack appended to the log gets one wh128 index entry:

    key = file_id20 | offset40 | type4(PACK)
    val = obj_count32 | byte_len32

`obj_count` is the number of git objects the pack contains;
`byte_len` is the pack's stripped on-disk length, i.e. the number
of bytes of object records that follow the bookmark's `offset` in
`file_id`.  Together they let the wire encoder
(`keeper/PSTR.c`, see `WIRE.md` Phase 2) emit a valid git packfile
in O(1) per pack: sum the counts, write a fresh PACK header,
sendfile each `[offset, offset+byte_len)` range, append a fresh
SHA-1 trailer.  No varint scan, no inflation.

`offset40` is the byte position where the pack's first object
starts within the log file; bookmarks sort by (file_id, offset)
naturally.

The bookmark deliberately does **not** carry a per-pack hashlet.
The retired TLV-based dog↔dog SYNC needed one for dedup
negotiation; the new wire protocol (`WIRE.md`) negotiates over git
sha1s via pkt-line want/have, so the per-pack hash is no longer
useful.  Per-object hashlets in the LSM remain unchanged; the
git-compat trailing SHA-1 is recomputed on the fly when an
outgoing pack is framed for the wire.

Pack byte length is recorded explicitly in the bookmark val (no
need to look at the next bookmark or the file's current length —
both are still consistent with the stored `byte_len`).  No
sentinel is stored in the index itself.

Pack bookmarks share the LSM with object entries; the type tag in
the key's low 4 bits keeps them from colliding (objects use
1..4 for commit/tree/blob/tag; pack bookmarks use a reserved
value outside that range — TBD, propose 15).

## Drop-a-dir (replaces GC / repack)

Keeper never rewrites packs.  Consolidation and cleanup happen at
the granularity of a **branch dir**:

  - **Squash / rebase a leaf branch**: delete the dir (pack logs,
    indexes, REFS, WT).  The DAG invariant guarantees no surviving
    REF_DELTA pointed into it from a sibling/descendant; ancestor
    resolution is unaffected because writers never delta upward-
    against-downward.
  - **Drop an interior dir**: precondition — every descendant's
    cross-dir REF_DELTAs into this dir must be materialized into
    the descendant (or into an ancestor that survives).  If not,
    the operation is refused; there is no automatic rewrite.
  - **Uncommitted staging or a live WT**: refused.  `be stash` or
    close the worktree first.

Readers holding mmaps of dropped files continue to work until they
close; new lookups route around the missing dir.

Peer watermarks pointing at dropped `file_id`s become stale — the
affected peers fall back to full sync on next contact via the standard
have/want negotiation (`WIRE.md`).  This is acceptable: drops are
user-initiated and watermarks rebuild cheaply.

## Implications for sync

See `keeper/WIRE.md` for the active wire protocol (git pkt-line,
upload-pack / receive-pack compatible).  Sync scopes to a branch
dir: a fetch ships a contiguous byte prefix of the dir's log
(plus its ancestor dirs' logs up to the relevant watermark) as
one freshly-framed git packfile.  Per-pack `(obj_count, byte_len)`
in the bookmark is exactly what the encoder needs to sum object
counts for the new PACK header and to sendfile each segment in
one syscall.  The TLV-based predecessor (`SYNC.md`) and its
per-pack hashlet were removed once `WIRE.md` Phase 10 landed.

## Current code vs. this spec

As of 2026-04-28, Step 2 multi-branch open/create/drop is live:
`keeper_shard` is gone — the singleton `keeper` carries flat
keeper-level `Bkv32 packs` (seqno → fd) and `Bkv32 puppies` (seqno →
fd) directly, plus `u8cs leaf_branch` and one `int lock_fd` on the
leaf.  `KEEPOpenBranch(h, "feat/fix", rw)` walks trunk → feat →
feat/fix, registering every `.keeper` and `.keeper.idx` file along
the way; missing prefix dirs return `KEEPNONE`.
`KEEPCreateBranch(h, branch)` mkdirs a leaf under an existing parent
(`KEEPDUP` on collision, `KEEPNONE` on missing parent).
`KEEPBranchDrop(k, branch)` evicts + unlinks every file in the leaf
dir and rmdirs it; refuses trunk (`KEEPTRUNK`), the active leaf, or
a branch with subdirs (both `KEEPDIRTY`).  Writes (`KEEPPackOpen`,
`KEEPPackClose`, `KEEPIngestFile`, `KEEPSync`) all land in the leaf
branch dir; `KEEPCompact` writes its merged run into the leaf dir
too.  The REF_DELTA visibility check is now structural: every entry
in `k->packs` is by construction visible to a delta encoded into the
leaf, since the open walk only loads packs from trunk → … → leaf.
