#!/bin/sh
#  setup-primitives.sh — common world-builders for verbcheck-driven
#  tests.  Each function expects to be called from inside a fresh wt
#  dir (use `vc_fresh_wt` from verbcheck.sh first), and leaves the wt
#  in a documented state.
#
#  These are toy-repo helpers — small, deterministic, controllable.
#  They are *not* meant to seed realistic histories.  Bigger tests
#  compose these.
#
#  Convention: each function exports the shas it produced as
#  uppercase shell vars (T1, T2, FEAT_TIP, …) so the test can refer
#  to them after the call.

# ----- helpers used internally ---------------------------------------

#  Latest sha recorded in .sniff (most recent get/post/patch row).
sp_head_hex() {
    awk -F'\t' '$2=="post"||$2=="get"||$2=="patch" { last=$3 }
                END {
                    h = last; sub(/^[^#]*#/, "", h)
                    if (length(h) == 40 && h ~ /^[0-9a-f]+$/) print h
                }' .sniff
}

#  Tip of a labelled branch via `keeper refs`.
sp_ref_tip() {
    keeper refs 2>/dev/null | awk -v k="$1" '
        { sub(/^[[:space:]]+/, "")
          tab = index($0, "\t")
          if (tab == 0) next
          kf = substr($0, 1, tab - 1)
          if (kf != k) next
          n = split($0, toks, /[[:space:]]+/)
          v = toks[n]; sub(/^\?/, "", v); print v; exit
        }'
}

# ----- world-builders ------------------------------------------------

#  Empty wt with a single `x.txt` committed on trunk.  Exports:
#    T1 — the commit sha.
sp_seed_trunk() {
    echo "x v1" > x.txt
    "$BE" post v1 >/dev/null
    T1=$(sp_head_hex)
    [ -n "$T1" ] || { echo "sp_seed_trunk: no T1" >&2; exit 1; }
}

#  After sp_seed_trunk: append a second post on trunk (modify x.txt).
#  Exports:
#    T2 — second commit sha (T2 != T1; T1 is T2's parent).
sp_seed_two_tips() {
    sp_seed_trunk
    usleep 10000
    echo "x v2" > x.txt
    "$BE" post v2 >/dev/null
    T2=$(sp_head_hex)
    [ -n "$T2" ] && [ "$T2" != "$T1" ] \
        || { echo "sp_seed_two_tips: no T2 (got '$T2')" >&2; exit 1; }
}

#  After sp_seed_trunk: label `?feat` at T1.  Exports:
#    FEAT_TIP — sha that ?feat points at (= T1).
sp_label_feat() {
    "$BE" post "?feat" >/dev/null
    FEAT_TIP=$(sp_ref_tip "?feat")
    [ "$FEAT_TIP" = "$T1" ] \
        || { echo "sp_label_feat: ?feat at '$FEAT_TIP' != T1=$T1" >&2; exit 1; }
}

#  After sp_label_feat: switch wt onto ?feat.  No exports.
sp_switch_feat() {
    "$BE" get "?feat" >/dev/null
}

#  Make a tracked file's mtime fall outside the stamp-set so the wt
#  appears dirty.  Pass a path; defaults to x.txt.
sp_make_dirty() {
    p=${1:-x.txt}
    usleep 10000
    echo "$(date +%N) dirty" >> "$p"
}

#  Write a present-but-unrelated tip into REFS for KEY.  Used by
#  non-ff tests — GRAFLca returns 0 for unknown shas, so the ff
#  guard fires.
sp_poison_refs() {
    key=$1                                    # e.g. "?" or "?feat"
    fake="deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    ts=$(awk 'END { print $1 }' .dogs/refs)
    printf '%sz\tpost\t%s#%s\n' "$ts" "$key" "$fake" >> .dogs/refs
}

#  Drop tracked files from disk (simulating a wiped wt).  Useful for
#  GET-restores-files scenarios.
sp_wipe_wt() {
    find . -type f \
        -not -path './.dogs' -not -path './.dogs/*' \
        -not -name '.sniff' -not -name '.sniff.pid' \
        -delete 2>/dev/null || true
}
