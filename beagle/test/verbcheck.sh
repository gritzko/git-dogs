#!/bin/sh
#  verbcheck.sh — uniform integration-test harness for `be` verb tests.
#
#  Sourced from `be-<verb>-<case>.sh` files alongside this one.  See
#  `be-get-dirty-cross.sh` for the canonical example.
#
#  Five observables are captured per snapshot:
#    [sniff]    rows of <wt>/.sniff (verb + URI; trailing pad ignored)
#    [refs]     `keeper refs` (already tombstone-filtered)
#    [wt]       per-file inventory: path, size, sha1, mtime
#    [baseline] derived from .sniff: branch + tip + patch-parent count
#    [outcome]  exit code + first non-empty stderr line of last command
#
#  A test calls `vc_snapshot before`, runs commands via `vc_run NAME …`,
#  then either `vc_snapshot after` and one of the assertion helpers,
#  or directly asserts on the run's outcome.
#
#  Assertion helpers:
#    vc_assert_exit        N
#    vc_assert_stderr      NAME pattern    (substring grep -F)
#    vc_assert_unchanged   SECTION         (no diff in [SECTION])
#    vc_assert_appended    SECTION pattern (one new last line matching)
#    vc_assert_baseline    branch tip      (post-state baseline check)
#    vc_diff               (debug: dumps before/after diff to stderr)

#  Strict mode in callers; harness functions clear $? on capture.
set -eu

# ----- environment ---------------------------------------------------

BIN=${BIN:-$(dirname "$(command -v be)")}
BIN=$(cd "$BIN" && pwd)
BE="$BIN/be"
KEEPER="$BIN/keeper"
export PATH="$BIN:$PATH"
export ASAN_OPTIONS="${ASAN_OPTIONS:-}:detect_leaks=0"

TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-vctest}
TMP=$TMP/$TEST_ID
mkdir -p "$TMP"
trap 'rm -rf "$TMP"; rmdir "${TMP%/*}" 2>/dev/null || true' EXIT INT TERM

vc_fail() { echo "FAIL ($TEST_ID): $*" >&2; exit 1; }
vc_note() { echo "  - $*"; }
vc_step() { echo "=== $* ==="; }

# ----- snapshot ------------------------------------------------------
#
#  Caller's cwd must be the wt root.  Output goes to $TMP/snap.<name>.

vc_snapshot() {
    name=$1
    out="$TMP/snap.$name"
    {
        printf '[sniff]\n'
        if [ -f .sniff ]; then
            #  trim-strip pad: keep only rows with a verb in column 2.
            awk -F'\t' 'NF >= 2 && $2 != "" { print $2 "\t" $3 }' .sniff
        fi

        printf '[refs]\n'
        if [ -d .dogs ]; then
            #  `keeper refs` filters tombstones via REFSEach.  Pull
            #  just the `?<key> → <hex>` lines, sort for determinism.
            keeper refs 2>/dev/null | awk '
                /^  \?/ {
                    sub(/^  /, "")
                    sub(/[\t ]+→[\t ]+/, "\t")
                    print
                }' | LC_ALL=C sort
        fi

        printf '[wt]\n'
        if [ -d . ]; then
            #  Find tracked-or-not files; exclude .dogs/, .sniff,
            #  .sniff.pid (daemon scratch).  Sort for determinism.
            #  Mtime is intentionally omitted — POST restamps files,
            #  so mtime always changes; content shape (size + sha1)
            #  is the user-facing observable.  Stamp-set membership
            #  is checked via the dirty-overlap contract elsewhere.
            find . -type f \
                -not -path './.dogs' -not -path './.dogs/*' \
                -not -name '.sniff' -not -name '.sniff.pid' \
                2>/dev/null | LC_ALL=C sort | while IFS= read -r f; do
                sz=$(wc -c < "$f" | tr -d ' ')
                sha=$(sha1sum "$f" 2>/dev/null | awk '{print $1}')
                printf '%s\t%s\t%s\n' "$f" "$sz" "$sha"
            done
        fi

        printf '[baseline]\n'
        if [ -f .sniff ]; then
            awk -F'\t' '$2=="get"||$2=="post"||$2=="patch" { last=$3 }
                        END {
                            if (last == "") exit
                            br = last; sub(/#.*/, "", br); sub(/^\?/, "", br)
                            tp = last; sub(/^[^#]*#/, "", tp)
                            #  Count `&` in the query portion → patch parents.
                            q = last; sub(/#.*/, "", q)
                            n = gsub(/&/, "", q)
                            print "branch=" br
                            print "tip=" tp
                            print "patch_parents=" n
                        }' .sniff
        fi

        printf '[outcome]\n'
        if [ -n "${vc_last_name:-}" ]; then
            printf 'exit=%s\n' "${vc_last_exit:-0}"
            #  First non-empty stderr line, sanitised — we want a
            #  single intent line in the snapshot, not pages of trace.
            err=$(awk '$0 != "" { print; exit }' \
                    "$TMP/stderr.$vc_last_name" 2>/dev/null || true)
            printf 'stderr=%s\n' "$err"
        fi
    } > "$out"
}

# ----- run -----------------------------------------------------------
#
#  Captures stdout / stderr per name and the exit code.

vc_last_name=""
vc_last_exit=0

vc_run() {
    name=$1; shift
    vc_last_name=$name
    set +e
    "$@" >"$TMP/stdout.$name" 2>"$TMP/stderr.$name"
    vc_last_exit=$?
    set -e
}

# ----- assertions ----------------------------------------------------

#  vc_assert_exit 0       — must exit OK.
#  vc_assert_exit nonzero — any non-zero exit (any verb-refusal).
#  vc_assert_exit N       — exact code (rare; `be` wraps inner errs
#                           into BEDOGEXIT so codes aren't stable).
vc_assert_exit() {
    want=$1
    got=${vc_last_exit:-0}
    case "$want" in
        nonzero)
            if [ "$got" = "0" ]; then
                echo "----- stdout ($vc_last_name) -----" >&2
                cat "$TMP/stdout.$vc_last_name" >&2 || true
                echo "----- stderr ($vc_last_name) -----" >&2
                cat "$TMP/stderr.$vc_last_name" >&2 || true
                vc_fail "exit: want non-zero got 0"
            fi
            ;;
        *)
            if [ "$got" != "$want" ]; then
                echo "----- stderr ($vc_last_name) -----" >&2
                cat "$TMP/stderr.$vc_last_name" >&2 || true
                vc_fail "exit: want $want got $got"
            fi
            ;;
    esac
}

vc_assert_stderr() {
    name=$1; pat=$2
    grep -qF "$pat" "$TMP/stderr.$name" \
        || vc_fail "stderr [$name]: missing '$pat'; got:
$(sed 's/^/    /' "$TMP/stderr.$name")"
}

#  Extract a section's body (between [SECTION] and the next [) from a
#  snapshot.  Trims off the section headers themselves.  Use literal
#  string compare instead of regex — `awk -v` strips backslashes
#  from values, which breaks `\[…\]$` anchors silently.
vc_section() {
    snap=$1; section=$2
    awk -v want="[$section]" '
        $0 == want { f=1; next }
        /^\[/      { f=0 }
        f          { print }
    ' "$TMP/snap.$snap"
}

#  Most assertions accept optional snapshot-name overrides as the
#  trailing args.  Default pair is `before` / `after`; multi-stage
#  tests can pass e.g. `vc_assert_appended sniff "..." after_patch
#  after_post` to compare the patch and post snapshots.

vc_assert_unchanged() {
    section=$1
    a_snap=${2:-before}
    b_snap=${3:-after}
    a=$(vc_section "$a_snap" "$section")
    b=$(vc_section "$b_snap" "$section")
    if [ "$a" != "$b" ]; then
        echo "----- [$section] $a_snap -----" >&2
        printf '%s\n' "$a" >&2
        echo "----- [$section] $b_snap -----" >&2
        printf '%s\n' "$b" >&2
        vc_fail "[$section] $a_snap → $b_snap changed (expected unchanged)"
    fi
}

#  Exactly one extra line at the end of SECTION, matching the (grep -E)
#  pattern.  All earlier lines must equal the before snapshot.
vc_assert_appended() {
    section=$1; pat=$2
    a_snap=${3:-before}
    b_snap=${4:-after}
    a=$(vc_section "$a_snap" "$section")
    b=$(vc_section "$b_snap" "$section")
    na=$(printf '%s\n' "$a" | awk 'NF>0' | wc -l | tr -d ' ')
    nb=$(printf '%s\n' "$b" | awk 'NF>0' | wc -l | tr -d ' ')
    if [ "$nb" != "$((na + 1))" ]; then
        echo "----- [$section] $a_snap -----" >&2
        printf '%s\n' "$a" >&2
        echo "----- [$section] $b_snap -----" >&2
        printf '%s\n' "$b" >&2
        vc_fail "[$section] $a_snap → $b_snap: expected +1 row, got delta $((nb - na))"
    fi
    last=$(printf '%s\n' "$b" | awk 'NF>0' | tail -1)
    printf '%s\n' "$last" | grep -qE "$pat" \
        || vc_fail "[$section] last row '$last' does not match /$pat/"
}

#  One row in SECTION matched PATTERN before; that row is gone in
#  after.  Used for tombstone-style deletions where the section's
#  visible row count drops by one.
vc_assert_removed() {
    section=$1; pat=$2
    a_snap=${3:-before}
    b_snap=${4:-after}
    a=$(vc_section "$a_snap" "$section" | grep -E "$pat" || true)
    b=$(vc_section "$b_snap" "$section" | grep -E "$pat" || true)
    if [ -z "$a" ]; then
        vc_fail "[$section] no row matched '$pat' in $a_snap — wrong setup"
    fi
    if [ -n "$b" ]; then
        vc_fail "[$section] row '$b' still present in $b_snap (expected removed)"
    fi
}

vc_assert_baseline() {
    want_branch=$1; want_tip=$2
    snap=${3:-after}
    b=$(vc_section "$snap" baseline)
    got_branch=$(printf '%s\n' "$b" | awk -F= '$1=="branch"{print $2}')
    got_tip=$(printf '%s\n' "$b" | awk -F= '$1=="tip"{print $2}')
    [ "$got_branch" = "$want_branch" ] \
        || vc_fail "baseline branch ($snap): want '$want_branch' got '$got_branch'"
    if [ -n "$want_tip" ] && [ "$got_tip" != "$want_tip" ]; then
        vc_fail "baseline tip ($snap): want '$want_tip' got '$got_tip'"
    fi
}

vc_diff() {
    diff -u "$TMP/snap.before" "$TMP/snap.after" >&2 || true
}

# ----- per-test bootstrap -------------------------------------------

#  Make a fresh wt dir under $TMP and cd into it.  Caller usually
#  follows up with one of the setup-primitives.sh helpers.
vc_fresh_wt() {
    name=${1:-wt}
    wt="$TMP/$name"
    mkdir -p "$wt"
    cd "$wt"
}
