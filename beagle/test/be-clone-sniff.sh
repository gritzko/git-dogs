#!/bin/sh
#  be-clone-sniff.sh — verify `.sniff` after `be get ssh://...` clone.
#
#  After a clone the secondary `.sniff` must hold both:
#    row 0: `repo file:<wt>/.dogs/`
#    row 1: `get   ?<branch>#<sha>`
#
#  The `repo` row is bootstrapped by SNIFFOpen; the `get` row is
#  appended by sniff/GET.c at the end of the checkout.  Regression
#  observed in field reports: only the `repo` row survives on disk
#  even though `sniff: checkout done` printed; the SSH clone path
#  trips it but the local-dir-clone path does not.
#
#  Skips cleanly when sshd-to-localhost is not configured (CI envs
#  without ssh keys).
#
set -eu

BIN=${BIN:-$(dirname "$(command -v be)")}
BIN=$(cd "$BIN" && pwd)
BE="$BIN/be"

TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-be-clone-sniff}
TMP=$TMP/$TEST_ID
mkdir -p "$TMP"
trap 'rm -rf "$TMP"; rmdir "${TMP%/*}" 2>/dev/null || true' EXIT INT TERM

fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "  - $*"; }
skip() { echo "SKIP: $*" >&2; exit 0; }

#  Skip cleanly when localhost ssh isn't reachable in batch mode
#  (no key, no sshd, etc.) — the clone path needs a working ssh.
if ! ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
        -o ConnectTimeout=5 localhost true 2>/dev/null; then
    skip "ssh localhost not reachable in batch mode"
fi

# --- 1. seed a tiny git repo at the ssh-resolvable path ------------
#
#  ssh transport on git strips the leading slash, so the URL path
#  resolves relative to the ssh login's cwd ($HOME).  Place the seed
#  repo under $TMP (which lives under $HOME/tmp by default) and pass
#  the leading-slash form `/path-relative-to-home` in the URI.
echo "=== 1. seed git repo over ssh-reachable path ==="
SRC="$TMP/src"; mkdir -p "$SRC"; cd "$SRC"
git init --quiet -b main
git config user.email t@t
git config user.name  t
echo hello > README
git add README
git commit --quiet -m seed
SEED=$(git rev-parse HEAD)
[ ${#SEED} -eq 40 ] || fail "seed sha not 40 hex"

#  Build the ssh URL relative to $HOME (git strips the leading slash
#  on the remote so `/dir-under-home` resolves correctly via $HOME).
case "$SRC" in
    "$HOME"/*) REL="${SRC#$HOME}" ;;
    *) skip "TMP=$TMP not under \$HOME — adjust TMP to use ssh path" ;;
esac
URI="ssh://localhost${REL}"
note "seed sha=$SEED, ssh URI=$URI"

# --- 2. clone via be get ssh:// ------------------------------------
echo "=== 2. be get ssh://... in fresh wt ==="
WT="$TMP/wt"; mkdir -p "$WT"; cd "$WT"
"$BE" get "$URI" >/dev/null 2>&1 || fail "wt: be get failed"

[ -f .sniff ] || fail "wt: .sniff missing"

# --- 3. .sniff must carry both rows --------------------------------
echo "=== 3. .sniff has repo + get rows ==="
NREPO=$(awk -F'\t' '$2=="repo"' .sniff | wc -l)
NGET=$(awk -F'\t' '$2=="get"'  .sniff | wc -l)

[ "$NREPO" -eq 1 ] || fail ".sniff: expected 1 repo row, got $NREPO"
[ "$NGET"  -eq 1 ] || {
    echo "--- .sniff hex dump ---" >&2
    xxd .sniff >&2
    echo "-----------------------" >&2
    echo "--- .dogs/refs ---" >&2
    cat .dogs/refs 2>/dev/null >&2
    echo "------------------" >&2
    fail ".sniff: expected 1 get row after clone, got $NGET"
}

GROW=$(awk -F'\t' '$2=="get"{print $3}' .sniff)
case "$GROW" in
    *"#$SEED") note "get row OK: $GROW" ;;
    *)        fail "get row sha mismatch: row=$GROW, expected #$SEED" ;;
esac

echo "=== be-clone-sniff: OK ==="
