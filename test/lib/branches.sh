# test/lib/branches.sh — sourced at the top of every test/branches/*/run.sh.
#
# Layers on top of case.sh: same scratch-dir setup, exit trap, match/
# match_re/must/mustnt — plus the small awk helpers that the original
# workflow-branches.sh inlined (head_hex, cur_branch, ref_tip), the
# fail/note/skip log shorthand, and a $KEEPER path.

. "$(dirname "$0")/../../lib/case.sh"

#  Scratch dir that lives OUTSIDE the wt — for stderr captures and
#  sibling worktrees.  Anything dropped inside SCRATCH becomes part of
#  the worktree and trips sniff's dirty-check on the next `be get`.
ETMP="$TMP/$$/etmp/$VERB-$NAME"
mkdir -p "$ETMP"
export ETMP

KEEPER=${KEEPER:-${BIN:+$BIN/keeper}}
KEEPER=${KEEPER:-$(command -v keeper || true)}
[ -n "$KEEPER" ] && [ -x "$KEEPER" ] || {
    echo "branches.sh: cannot locate \`keeper\` (set BIN=... or KEEPER=...)" >&2
    exit 2
}
export KEEPER

#  Suppress LeakSanitizer in dev builds so a stray asan leak doesn't
#  fail an otherwise-correct test.
export ASAN_OPTIONS="${ASAN_OPTIONS:-}:detect_leaks=0"

fail() { echo "FAIL ($NAME): $*" >&2; exit 1; }
note() { echo "  - $*"; }
skip() { echo "  - SKIP: $*"; }

#  Latest sniff baseline row's URI sha (post|get|patch).
head_hex() {
    awk -F'\t' '$2=="post"||$2=="get"||$2=="patch" { last=$3 }
                END {
                    h = last; sub(/^[^#]*#/, "", h)
                    if (length(h) == 40 && h ~ /^[0-9a-f]+$/) print h
                }' .sniff
}

#  Branch portion (between leading `?` and `#`) of the latest row.
cur_branch() {
    awk -F'\t' '$2=="post"||$2=="get"||$2=="patch" { last=$3 }
                END {
                    q = last; sub(/#.*/, "", q); sub(/^\?/, "", q)
                    print q
                }' .sniff
}

#  Tip recorded for KEY in `keeper refs` output.  Empty if KEY absent.
ref_tip() {
    "$KEEPER" refs 2>/dev/null | awk -v k="$1" '
        { sub(/^[[:space:]]+/, "")
          tab = index($0, "\t"); if (tab == 0) next
          kf = substr($0, 1, tab - 1); if (kf != k) next
          n = split($0, toks, /[[:space:]]+/)
          v = toks[n]; sub(/^\?/, "", v); print v; exit
        }'
}
