#!/bin/sh
#  be-delete-alias.sh — `be delete //<host>` (no `?ref`) tombstones
#  every cached row that carries that host's authority.  No network.
#
#  The verbcheck `[refs]` snapshot only captures local `?<branch>`
#  rows (verbcheck.sh:81 — `^  \?` filter), so peer-observed rows
#  (`ssh://host/...?br`) wouldn't show up there.  We assert directly
#  on `keeper refs` output instead.

. "$(dirname "$0")/verbcheck.sh"
. "$(dirname "$0")/setup-primitives.sh"

vc_step "setup: trunk + injected //fakehost?heads/main row"
vc_fresh_wt
sp_seed_trunk

#  Inject one peer-observed row.  ULOG enforces strictly-increasing
#  ts within a file; appending a non-base64 char to the tail's ts
#  produces a >tail value (URILexer/ULOG accept it as a longer ron60).
ts=$(awk 'END { print $1 }' .dogs/refs)
fakesha="abc123abc123abc123abc123abc123abc123abc1"
printf '%sz\tget\tssh://fakehost/repo?heads/main#?%s\n' \
    "$ts" "$fakesha" >> .dogs/refs

#  Sanity: the injected row must show up in `keeper refs` before we
#  delete (otherwise the post-delete check would pass for the wrong
#  reason — REFSResolve's tombstone filter masking a bad inject).
keeper refs 2>/dev/null | grep -q fakehost \
    || vc_fail "setup: injected //fakehost row not visible in keeper refs"

vc_step "be delete //fakehost — drop alias"
vc_run del "$BE" delete "//fakehost"

vc_assert_exit 0
grep -qF "dropped alias //fakehost" "$TMP/stdout.del" \
    || vc_fail "stdout: missing 'dropped alias //fakehost'"

#  Post-state: the host row must no longer surface (REFSResolve
#  collapses the appended zero-sha row to "absent").
if keeper refs 2>/dev/null | grep -q fakehost; then
    echo "----- keeper refs after delete -----" >&2
    keeper refs 2>&1 >&2 || true
    vc_fail "after: //fakehost row still surfaced by keeper refs"
fi

#  Local trunk row stays — host filter is exact-match.
keeper refs 2>/dev/null | grep -qE '^[[:space:]]+\?[[:space:]]' \
    || vc_fail "after: local trunk row missing from keeper refs"

echo "=== be-delete-alias: OK ==="
