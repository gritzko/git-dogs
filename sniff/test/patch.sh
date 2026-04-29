#!/bin/sh
#  patch.sh — `sniff patch` end-to-end on toy two-branch repos.
#
#  Drives:
#    1. Disjoint-edit merge — feat-a prepends, feat-b appends.  Both
#       additions must survive in the worktree file, exit 0.
#    2. Conflict merge — same-line edit on both sides — JOIN emits
#       `<<<<<<<` markers, exit non-zero.
#    3. Target-side add — theirs adds a new file, ours unchanged.
#       File appears in wt, exit 0.
#
#  Each scenario builds its own bare git source, keeper-fetches both
#  branches via ssh localhost (same transport as
#  beagle/test/blobs-from-git.sh), `sniff get`s master into a fresh
#  wt, then `sniff patch <target>` merges.
#
#  Run: BIN=build-debug/bin sh sniff/test/patch.sh

set -eu

BIN=${DOG_BIN_DIR:-$(dirname "$(command -v be)")}
export PATH="$BIN:$PATH"
export DOG_REMOTE_PATH="$BIN"
export ASAN_OPTIONS="${ASAN_OPTIONS:-}:detect_leaks=0"

HOST=${HOST:-localhost}

#  Per-run scratch dir: $TMP/<test-id>/.  Base TMP and TEST_ID come
#  from ctest (see sniff/test/CMakeLists.txt); standalone runs fall
#  back to $HOME/tmp/run-<timestamp> and the script's basename.
TMP=${TMP:-$HOME/tmp/run-$(date +%Y%m%d-%H%M%S)}
TEST_ID=${TEST_ID:-SNIFFpatch}
TMP=$TMP/$TEST_ID
trap 'rm -rf "$TMP"; rmdir "${TMP%/*}" 2>/dev/null || true' EXIT
mkdir -p "$TMP"

fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "  - $*"; }

# --- Scenario 1: disjoint edits --------------------------------------

scenario1() {
    echo "=== 1. disjoint-edit merge ==="
    SRC=$TMP/s1/src
    CLI=$TMP/s1/client
    mkdir -p "$SRC" "$CLI/.dogs"
    git init --quiet --bare "$SRC"

    W=$(mktemp -d)
    git -c init.defaultBranch=master init --quiet "$W"
    git -C "$W" config user.email t@t
    git -C "$W" config user.name  t
    git -C "$W" remote add origin "$SRC"

    cat >"$W/f.c" <<'EOF'
int f(int x) {
    return x + 1;
}
EOF
    git -C "$W" add f.c
    git -C "$W" commit --quiet -m "base"
    git -C "$W" push --quiet origin master

    git -C "$W" checkout --quiet -b feat-a master
    cat >"$W/f.c" <<'EOF'
int foo(int a) {
    return a - 7;
}
int f(int x) {
    return x + 1;
}
EOF
    git -C "$W" commit --quiet -am "feat-a prepend"
    git -C "$W" push --quiet origin feat-a
    rm -rf "$W"

    SRC_REL=${SRC#$HOME/}
    cd "$CLI"
    keeper get "//$HOST/$SRC_REL?refs/heads/master" >/dev/null
    keeper get "//$HOST/$SRC_REL?refs/heads/feat-a" >/dev/null

    sniff get "?heads/master" >/dev/null 2>&1 \
        || fail "sniff get master failed"
    grep -qF 'return x + 1' f.c || fail "wt missing base line"

    sniff patch "?heads/feat-a" 2>&1 | sed 's/^/  | /'
    grep -qF 'int foo(' f.c || fail "patch lost feat-a prepend"
    grep -qF 'return x + 1' f.c || fail "patch dropped base function"
    ! grep -qF '<<<<' f.c \
        || fail "unexpected conflict markers (disjoint edits)"

    note "f.c carries both feat-a's foo() and master's f()"
}

# --- Scenario 2: same-line conflict -----------------------------------

scenario2() {
    echo "=== 2. conflict merge ==="
    SRC=$TMP/s2/src
    CLI=$TMP/s2/client
    mkdir -p "$SRC" "$CLI/.dogs"
    git init --quiet --bare "$SRC"

    W=$(mktemp -d)
    git -c init.defaultBranch=master init --quiet "$W"
    git -C "$W" config user.email t@t
    git -C "$W" config user.name  t
    git -C "$W" remote add origin "$SRC"

    cat >"$W/g.c" <<'EOF'
int g(int y) {
    return y + 0;
}
EOF
    git -C "$W" add g.c
    git -C "$W" commit --quiet -m "base"
    git -C "$W" push --quiet origin master

    git -C "$W" checkout --quiet -b feat-x master
    cat >"$W/g.c" <<'EOF'
int g(int y) {
    return y + 42;
}
EOF
    git -C "$W" commit --quiet -am "feat-x 42"
    git -C "$W" push --quiet origin feat-x

    git -C "$W" checkout --quiet master
    cat >"$W/g.c" <<'EOF'
int g(int y) {
    return y - 100;
}
EOF
    git -C "$W" commit --quiet -am "master -100"
    git -C "$W" push --quiet origin master
    rm -rf "$W"

    SRC_REL=${SRC#$HOME/}
    cd "$CLI"
    keeper get "//$HOST/$SRC_REL?refs/heads/master" >/dev/null
    keeper get "//$HOST/$SRC_REL?refs/heads/feat-x" >/dev/null

    sniff get "?heads/master" >/dev/null 2>&1 \
        || fail "sniff get master failed"

    set +e
    sniff patch "?heads/feat-x" >"$TMP/s2.out" 2>&1
    PATCH_RC=$?
    set -e
    sed 's/^/  | /' "$TMP/s2.out"
    [ "$PATCH_RC" != "0" ] || fail "conflict merge should exit non-zero"

    grep -qF '<<<<' g.c \
        || fail "expected conflict markers in g.c"
    note "g.c carries conflict markers, exit=$PATCH_RC"
}

# --- Scenario 3: target adds a new file -------------------------------

scenario3() {
    echo "=== 3. target-side add ==="
    SRC=$TMP/s3/src
    CLI=$TMP/s3/client
    mkdir -p "$SRC" "$CLI/.dogs"
    git init --quiet --bare "$SRC"

    W=$(mktemp -d)
    git -c init.defaultBranch=master init --quiet "$W"
    git -C "$W" config user.email t@t
    git -C "$W" config user.name  t
    git -C "$W" remote add origin "$SRC"

    cat >"$W/a.c" <<'EOF'
int a(void) { return 1; }
EOF
    git -C "$W" add a.c
    git -C "$W" commit --quiet -m "base"
    git -C "$W" push --quiet origin master

    git -C "$W" checkout --quiet -b feat-add master
    cat >"$W/b.c" <<'EOF'
int b(void) { return 2; }
EOF
    git -C "$W" add b.c
    git -C "$W" commit --quiet -am "add b.c"
    git -C "$W" push --quiet origin feat-add
    rm -rf "$W"

    SRC_REL=${SRC#$HOME/}
    cd "$CLI"
    keeper get "//$HOST/$SRC_REL?refs/heads/master" >/dev/null
    keeper get "//$HOST/$SRC_REL?refs/heads/feat-add" >/dev/null

    sniff get "?heads/master" >/dev/null 2>&1 \
        || fail "sniff get master failed"
    [ ! -f b.c ] || fail "b.c should be absent before patch"

    sniff patch "?heads/feat-add" 2>&1 | sed 's/^/  | /'
    [ -f b.c ] || fail "patch did not add b.c"
    grep -qF 'int b(void)' b.c || fail "b.c content missing"

    note "b.c appeared with target's bytes"
}

scenario1
scenario2
scenario3

echo
echo "=== sniff patch toys: OK ==="
