//
// JOIN01 - Property tests for token-level 3-way merge.
//
// Same core logic as JOINFUZZ.c, with fixed test cases.
// Fuzz crash repros go into the cases table below.
//
// JOINMerge is deprecated (see JOIN.h) — these tests exist solely to
// characterise the historic merge behaviour during the WEAVE
// migration.  The local pragma below silences the deprecation
// warning so the test file keeps building under -Werror; new code
// must call `GRAFMerge3Bytes` / `GRAFMergeWtFileTunable` instead.
//

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include "JOIN.h"

#include "abc/FILE.h"
#include "abc/PRO.h"
#include "abc/TEST.h"

// --- Helpers (shared with fuzzer) ---

static ok64 join_check_eq(u8csc a, u8csc b, char const *msg) {
    sane(1);
    if ($len(a) != $len(b)) {
        fprintf(stderr, "JOIN01: %s length %lu != %lu\n", msg, $len(a),
                $len(b));
        fail(TESTFAIL);
    }
    if ($len(a) > 0 && memcmp(a[0], b[0], $len(a)) != 0) {
        fprintf(stderr, "JOIN01: %s content mismatch\n", msg);
        fail(TESTFAIL);
    }
    done;
}

static b8 join_hash_in(u64 h, u64bp hashes) {
    u64 n = u64bDataLen(hashes);
    for (u64 i = 0; i < n; i++) {
        if (JOIN_HASH(hashes[1][i]) == h) return 1;
    }
    return 0;
}

// Check: every token in side that is NOT in base appears in merged
static ok64 join_check_insertions(u64bp side, u64bp base_h, u64bp merged,
                                   char const *msg) {
    sane(1);
    u64 n = u64bDataLen(side);
    for (u64 i = 0; i < n; i++) {
        u64 h = JOIN_HASH(side[1][i]);
        if (!join_hash_in(h, base_h) && !join_hash_in(h, merged)) {
            fprintf(stderr, "JOIN01: %s - hash %016lx at [%lu] missing\n", msg,
                    h, i);
            fail(TESTFAIL);
        }
    }
    done;
}

// Check: tokens deleted by BOTH sides are absent from merged
static ok64 join_check_both_deleted(u64bp base_h, u64bp ours_h, u64bp theirs_h,
                                     u64bp merged, char const *msg) {
    sane(1);
    u64 n = u64bDataLen(base_h);
    for (u64 i = 0; i < n; i++) {
        u64 h = JOIN_HASH(base_h[1][i]);
        if (!join_hash_in(h, ours_h) && !join_hash_in(h, theirs_h) &&
            join_hash_in(h, merged)) {
            fprintf(stderr, "JOIN01: %s - hash %016lx at [%lu] still in merge\n",
                    msg, h, i);
            fail(TESTFAIL);
        }
    }
    done;
}

// Run a single merge and check properties
static ok64 join_test(u8csc base_data, u8csc ours_data, u8csc theirs_data,
                       u8csc ext) {
    sane(1);
    u8csc c_ext = {(u8cp)"c", (u8cp)"c" + 1};
    if ($empty(ext)) {
        ext = c_ext;
    }

    JOINfile base_f = {}, ours_f = {}, theirs_f = {};
    call(JOINTokenize, &base_f, base_data, ext);
    call(JOINTokenize, &ours_f, ours_data, ext);
    call(JOINTokenize, &theirs_f, theirs_data, ext);

    u8 *merged[4] = {};
    call(u8bAlloc, merged, $len(ours_data) + $len(theirs_data) + 4096);
    call(JOINMerge, merged, &base_f, &ours_f, &theirs_f);
    u8csc mdata = {merged[1], merged[2]};

    // Re-tokenize merged
    JOINfile merged_f = {};
    if (!$empty(mdata)) {
        call(JOINTokenize, &merged_f, mdata, ext);
    }

    // Re-tokenize inputs (merge modifies hash bits)
    JOINFree(&base_f);
    JOINFree(&ours_f);
    JOINFree(&theirs_f);
    base_f = (JOINfile){};
    ours_f = (JOINfile){};
    theirs_f = (JOINfile){};
    call(JOINTokenize, &base_f, base_data, ext);
    call(JOINTokenize, &ours_f, ours_data, ext);
    call(JOINTokenize, &theirs_f, theirs_data, ext);

    // Insertions from each side present in merged
    call(join_check_insertions, ours_f.hashes, base_f.hashes,
         merged_f.hashes, "ours insertions missing");
    call(join_check_insertions, theirs_f.hashes, base_f.hashes,
         merged_f.hashes, "theirs insertions missing");
    // Tokens both sides deleted are gone
    call(join_check_both_deleted, base_f.hashes, ours_f.hashes,
         theirs_f.hashes, merged_f.hashes, "both-deleted still in merge");

    JOINFree(&base_f);
    JOINFree(&ours_f);
    JOINFree(&theirs_f);
    JOINFree(&merged_f);
    u8bFree(merged);
    done;
}

// Property: merge(B, X, B) == X
static ok64 join_test_one_side(u8csc base_data, u8csc changed, u8csc ext) {
    sane(1);
    u8csc c_ext = {(u8cp)"c", (u8cp)"c" + 1};
    if ($empty(ext)) ext = c_ext;

    JOINfile base_f = {}, changed_f = {}, base2_f = {};
    call(JOINTokenize, &base_f, base_data, ext);
    call(JOINTokenize, &changed_f, changed, ext);
    call(JOINTokenize, &base2_f, base_data, ext);

    u8 *merged[4] = {};
    call(u8bAlloc, merged, $len(base_data) + $len(changed) + 4096);

    // merge(B, changed, B)
    call(JOINMerge, merged, &base_f, &changed_f, &base2_f);
    u8csc mdata = {merged[1], merged[2]};
    call(join_check_eq, mdata, changed, "merge(B,X,B) != X");

    JOINFree(&base_f);
    JOINFree(&changed_f);
    JOINFree(&base2_f);
    u8bFree(merged);
    done;
}

// Property: merge(B, B, X) == X
static ok64 join_test_one_side_t(u8csc base_data, u8csc changed, u8csc ext) {
    sane(1);
    u8csc c_ext = {(u8cp)"c", (u8cp)"c" + 1};
    if ($empty(ext)) ext = c_ext;

    JOINfile base_f = {}, base2_f = {}, changed_f = {};
    call(JOINTokenize, &base_f, base_data, ext);
    call(JOINTokenize, &base2_f, base_data, ext);
    call(JOINTokenize, &changed_f, changed, ext);

    u8 *merged[4] = {};
    call(u8bAlloc, merged, $len(base_data) + $len(changed) + 4096);

    call(JOINMerge, merged, &base_f, &base2_f, &changed_f);
    u8csc mdata = {merged[1], merged[2]};
    call(join_check_eq, mdata, changed, "merge(B,B,X) != X");

    JOINFree(&base_f);
    JOINFree(&base2_f);
    JOINFree(&changed_f);
    u8bFree(merged);
    done;
}

// Property: merge(B, B, B) == B
static ok64 join_test_identity(u8csc base_data, u8csc ext) {
    sane(1);
    u8csc c_ext = {(u8cp)"c", (u8cp)"c" + 1};
    if ($empty(ext)) ext = c_ext;

    JOINfile b1 = {}, b2 = {}, b3 = {};
    call(JOINTokenize, &b1, base_data, ext);
    call(JOINTokenize, &b2, base_data, ext);
    call(JOINTokenize, &b3, base_data, ext);

    u8 *merged[4] = {};
    call(u8bAlloc, merged, $len(base_data) * 3 + 4096);

    call(JOINMerge, merged, &b1, &b2, &b3);
    u8csc mdata = {merged[1], merged[2]};
    call(join_check_eq, mdata, base_data, "merge(B,B,B) != B");

    JOINFree(&b1);
    JOINFree(&b2);
    JOINFree(&b3);
    u8bFree(merged);
    done;
}

// --- Test cases ---

typedef struct {
    char const *name;
    char const *base;
    char const *ours;
    char const *theirs;
    char const *expected;  // NULL = don't check exact output
} JOINCase;

static JOINCase cases[] = {
    {"identical", "int x = 1;", "int x = 1;", "int x = 1;", "int x = 1;"},
    {"ours_only", "int x = 1;", "int x = 2;", "int x = 1;", "int x = 2;"},
    {"theirs_only", "int x = 1;", "int x = 1;", "int x = 2;", "int x = 2;"},
    {"both_diff_tokens",
     "int x = 1;\nint y = 2;\n",
     "int x = 10;\nint y = 2;\n",
     "int x = 1;\nint y = 20;\n",
     "int x = 10;\nint y = 20;\n"},
    {"ours_add",
     "int x = 1;\n",
     "int x = 1;\nint y = 2;\n",
     "int x = 1;\n",
     "int x = 1;\nint y = 2;\n"},
    {"theirs_delete",
     "int x = 1;\nint y = 2;\n",
     "int x = 1;\nint y = 2;\n",
     "int x = 1;\n",
     "int x = 1;\n"},
    {"both_same_change",
     "int x = 1;",
     "int x = 42;",
     "int x = 42;",
     "int x = 42;"},
    // --- Fuzz crash repros go here ---
    {NULL, NULL, NULL, NULL, NULL},
};

ok64 JOINtest() {
    sane(1);
    u8csc ext = {(u8cp)"c", (u8cp)"c" + 1};

    for (JOINCase *c = cases; c->name != NULL; c++) {
        fprintf(stderr, "  %s...", c->name);

        u8csc base_d = {(u8cp)c->base, (u8cp)c->base + strlen(c->base)};
        u8csc ours_d = {(u8cp)c->ours, (u8cp)c->ours + strlen(c->ours)};
        u8csc theirs_d = {(u8cp)c->theirs, (u8cp)c->theirs + strlen(c->theirs)};

        // Identity
        call(join_test_identity, base_d, ext);

        // One-side properties
        call(join_test_one_side, base_d, ours_d, ext);
        call(join_test_one_side_t, base_d, theirs_d, ext);

        // Full merge with subset checks
        call(join_test, base_d, ours_d, theirs_d, ext);

        // Exact output check
        if (c->expected) {
            JOINfile bf = {}, of = {}, tf = {};
            call(JOINTokenize, &bf, base_d, ext);
            call(JOINTokenize, &of, ours_d, ext);
            call(JOINTokenize, &tf, theirs_d, ext);
            u8 *m[4] = {};
            call(u8bAlloc, m, $len(ours_d) + $len(theirs_d) + 4096);
            call(JOINMerge, m, &bf, &of, &tf);
            u8csc md = {m[1], m[2]};
            u8csc exp = {(u8cp)c->expected,
                         (u8cp)c->expected + strlen(c->expected)};
            call(join_check_eq, md, exp, "exact output");
            u8bFree(m);
            JOINFree(&bf);
            JOINFree(&of);
            JOINFree(&tf);
        }

        fprintf(stderr, " ok\n");
    }

    done;
}

TEST(JOINtest);

#pragma GCC diagnostic pop
#pragma clang diagnostic pop
