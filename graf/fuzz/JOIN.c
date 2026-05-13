//
// JOIN fuzz test - token-level 3-way merge.
//
// Input format: [base bytes] \0 [edit ops]
// Edit ops: for each base token, 2 bytes: ours_op, theirs_op
//   op & 0x3: 0=keep, 1=delete, 2=replace (next N bytes)
//   op >> 2:  replacement length (for op==2)
//
// JOINMerge is deprecated — see JOIN.h.  This fuzzer is retained
// alongside the JOIN01 property tests purely to characterise the
// historic merge behaviour during the WEAVE migration.
//

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include "JOIN.h"

#include "abc/PRO.h"
#include "abc/TEST.h"

#define JOIN_FUZZ_MAX 4096

static ok64 join_apply_edits(u8bp out, JOINfile *base, u8csc ops,
                             u8csc repl) {
    sane(out != NULL && base != NULL);
    u64 ntoks = u32bDataLen(base->toks);
    u8cp rp = repl[0];
    for (u64 i = 0; i < ntoks; i++) {
        u8 op = (i < (u64)$len(ops)) ? ops[0][i] : 0;
        u8 action = op & 0x3;
        u32 off = tok32Offset(base->toks[1][i]);
        u32 end = (i + 1 < ntoks)
                      ? tok32Offset(base->toks[1][i + 1])
                      : (u32)$len(base->data);
        u32 tlen = end - off;
        switch (action) {
        case 0:
        case 3: {
            a_rest(u8c, r, base->data, off);
            a_head(u8c, tok, r, tlen);
            call(u8bFeed, out, tok);
            break;
        }
        case 1:
            break;
        case 2: {
            u32 rlen = (op >> 2);
            if (rlen == 0) rlen = 1;
            if (rp + rlen > repl[1]) rlen = (u32)(repl[1] - rp);
            if (rlen > 0) {
                u8csc rslice = {rp, rp + rlen};
                call(u8bFeed, out, rslice);
                rp += rlen;
            }
            break;
        }
        }
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

static b8 join_insertions_present(u64bp side, u64bp base_h, u64bp merged) {
    u64 sn = u64bDataLen(side);
    for (u64 i = 0; i < sn; i++) {
        u64 h = JOIN_HASH(side[1][i]);
        if (!join_hash_in(h, base_h) && !join_hash_in(h, merged)) return 0;
    }
    return 1;
}

static b8 join_both_deleted_gone(u64bp base_h, u64bp ours_h, u64bp theirs_h,
                                 u64bp merged) {
    u64 bn = u64bDataLen(base_h);
    for (u64 i = 0; i < bn; i++) {
        u64 h = JOIN_HASH(base_h[1][i]);
        if (!join_hash_in(h, ours_h) && !join_hash_in(h, theirs_h) &&
            join_hash_in(h, merged))
            return 0;
    }
    return 1;
}

// Check merge(B, X, B2) == X  (X is ours or theirs, B2 is base copy)
static ok64 join_check_one_side(u8csc base_data, u8csc changed, u8csc ext,
                                 b8 ours_side) {
    sane(1);
    JOINfile bf = {}, cf = {}, b2f = {};
    u8 *m[4] = {};
    b8 ok = 1;
    try(JOINTokenize, &bf, base_data, ext);
    then try(JOINTokenize, &cf, changed, ext);
    then try(JOINTokenize, &b2f, base_data, ext);
    then try(u8bAlloc, m, $len(base_data) + $len(changed) + 4096);
    then {
        if (ours_side) {
            try(JOINMerge, m, &bf, &cf, &b2f);
        } else {
            try(JOINMerge, m, &bf, &b2f, &cf);
        }
        then {
            u8csc md = {m[1], m[2]};
            ok = ($len(md) == $len(changed) &&
                  memcmp(md[0], changed[0], $len(changed)) == 0);
        }
    }
    u8bFree(m);
    JOINFree(&bf);
    JOINFree(&cf);
    JOINFree(&b2f);
    if (__ != OK) done;  // tokenize/merge failed, not a property violation
    if (!ok) fail(FAILSANITY);
    done;
}

FUZZ(u8, JOINfuzz) {
    sane(1);
    if ($len(input) > JOIN_FUZZ_MAX || $len(input) < 4) done;

    // Split on \0
    u8cp sep = NULL;
    $for(u8c, p, input) {
        if (*p == 0) { sep = p; break; }
    }
    if (sep == NULL) done;

    a_head(u8c, base_data, input, sep - input[0]);
    a_rest(u8c, rest, input, sep - input[0] + 1);
    if ($empty(base_data) || $len(base_data) < 2) done;

    u8csc c_ext = {(u8cp)"c", (u8cp)"c" + 1};
    JOINfile base_f = {};
    try(JOINTokenize, &base_f, base_data, c_ext);
    nedo { JOINFree(&base_f); done; }
    u64 ntoks = u32bDataLen(base_f.toks);
    if (ntoks == 0) { JOINFree(&base_f); done; }

    if ((u64)$len(rest) < ntoks * 2) { JOINFree(&base_f); done; }
    a_head(u8c, ours_ops, rest, ntoks);
    a_rest(u8c, rest2, rest, ntoks);
    a_head(u8c, theirs_ops, rest2, ntoks);
    a_rest(u8c, repl_bytes, rest2, ntoks);

    // Build edited files
    u8 *ours_buf[4] = {}, *theirs_buf[4] = {};
    ok64 result = OK;
    try(u8bAlloc, ours_buf, $len(base_data) + $len(repl_bytes) + 256);
    then try(u8bAlloc, theirs_buf, $len(base_data) + $len(repl_bytes) + 256);
    then try(join_apply_edits, ours_buf, &base_f, ours_ops, repl_bytes);
    then try(join_apply_edits, theirs_buf, &base_f, theirs_ops, repl_bytes);
    nedo {
        JOINFree(&base_f);
        u8bFree(ours_buf);
        u8bFree(theirs_buf);
        done;
    }
    u8csc ours_data = {ours_buf[1], ours_buf[2]};
    u8csc theirs_data = {theirs_buf[1], theirs_buf[2]};

    // Property 1: merge(B,B,B) == B
    {
        JOINfile b1 = {}, b2 = {}, b3 = {};
        try(JOINTokenize, &b1, base_data, c_ext);
        then try(JOINTokenize, &b2, base_data, c_ext);
        then try(JOINTokenize, &b3, base_data, c_ext);
        then {
            u8 *m[4] = {};
            try(u8bAlloc, m, $len(base_data) * 3 + 4096);
            then try(JOINMerge, m, &b1, &b2, &b3);
            then {
                u8csc md = {m[1], m[2]};
                if ($len(md) != $len(base_data) ||
                    memcmp(md[0], base_data[0], $len(base_data)) != 0)
                    result = FAILSANITY;
            }
            u8bFree(m);
        }
        JOINFree(&b1);
        JOINFree(&b2);
        JOINFree(&b3);
    }

    // Property 2: merge(B,O,B) == O
    if (result == OK && !$empty(ours_data))
        try(join_check_one_side, base_data, ours_data, c_ext, 1);
    nedo result = __;

    // Property 3: merge(B,B,T) == T
    if (result == OK && !$empty(theirs_data))
        try(join_check_one_side, base_data, theirs_data, c_ext, 0);
    nedo result = __;

    // Property 8: non-overlapping edits → merge == combined
    // If ours_ops and theirs_ops never both edit the same token,
    // build the combined result and verify merge matches exactly.
    if (result == OK) {
        b8 non_overlapping = 1;
        for (u64 i = 0; i < ntoks; i++) {
            u8 oact = ours_ops[0][i] & 0x3;
            u8 tact = theirs_ops[0][i] & 0x3;
            if (oact != 0 && oact != 3 && tact != 0 && tact != 3) {
                non_overlapping = 0;
                break;
            }
        }
        if (non_overlapping) {
            // Build combined: for each token, apply whichever side edited it
            u8 *comb_buf[4] = {};
            try(u8bAlloc, comb_buf,
                $len(base_data) + $len(repl_bytes) + 256);
            then {
                // Combined ops: pick ours if ours edited, else theirs
                u8 comb_ops_arr[512];
                for (u64 i = 0; i < ntoks && i < 512; i++) {
                    u8 oact = ours_ops[0][i] & 0x3;
                    comb_ops_arr[i] =
                        (oact != 0 && oact != 3) ? ours_ops[0][i]
                                                  : theirs_ops[0][i];
                }
                u8csc comb_ops = {comb_ops_arr,
                                  comb_ops_arr + (ntoks < 512 ? ntoks : 512)};
                try(join_apply_edits, comb_buf, &base_f, comb_ops, repl_bytes);
                then {
                    u8csc comb_data = {comb_buf[1], comb_buf[2]};
                    // Now merge and compare
                    JOINfile bf = {}, of = {}, tf = {};
                    try(JOINTokenize, &bf, base_data, c_ext);
                    then try(JOINTokenize, &of, ours_data, c_ext);
                    then try(JOINTokenize, &tf, theirs_data, c_ext);
                    then {
                        u8 *m[4] = {};
                        try(u8bAlloc, m,
                            $len(ours_data) + $len(theirs_data) + 4096);
                        then try(JOINMerge, m, &bf, &of, &tf);
                        then {
                            u8csc md = {m[1], m[2]};
                            if ($len(md) != $len(comb_data) ||
                                ($len(md) > 0 &&
                                 memcmp(md[0], comb_data[0], $len(md)) != 0))
                                result = FAILSANITY;
                        }
                        u8bFree(m);
                    }
                    JOINFree(&bf);
                    JOINFree(&of);
                    JOINFree(&tf);
                }
            }
            u8bFree(comb_buf);
        }
    }

    // Full 3-way merge + property checks
    if (result == OK) {
        JOINfile bf = {}, of = {}, tf = {};
        try(JOINTokenize, &bf, base_data, c_ext);
        then try(JOINTokenize, &of, ours_data, c_ext);
        then try(JOINTokenize, &tf, theirs_data, c_ext);
        then {
            u8 *m[4] = {};
            try(u8bAlloc, m, $len(ours_data) + $len(theirs_data) + 4096);
            then try(JOINMerge, m, &bf, &of, &tf);
            then {
                u8csc md = {m[1], m[2]};

                // Property 7: identical edits → merge == ours
                if ($len(ours_data) == $len(theirs_data) &&
                    memcmp(ours_data[0], theirs_data[0], $len(ours_data)) == 0) {
                    if ($len(md) != $len(ours_data) ||
                        memcmp(md[0], ours_data[0], $len(ours_data)) != 0)
                        result = FAILSANITY;
                }

                // Properties 4-6: hash checks
                if (result == OK && !$empty(md)) {
                    JOINfile mf = {};
                    try(JOINTokenize, &mf, md, c_ext);
                    then {
                        // Re-tokenize inputs for clean hashes
                        JOINFree(&bf); JOINFree(&of); JOINFree(&tf);
                        bf = (JOINfile){}; of = (JOINfile){}; tf = (JOINfile){};
                        try(JOINTokenize, &bf, base_data, c_ext);
                        then try(JOINTokenize, &of, ours_data, c_ext);
                        then try(JOINTokenize, &tf, theirs_data, c_ext);
                        then {
                            if (!join_insertions_present(of.hashes, bf.hashes,
                                                         mf.hashes))
                                result = FAILSANITY;
                            if (result == OK &&
                                !join_insertions_present(tf.hashes, bf.hashes,
                                                         mf.hashes))
                                result = FAILSANITY;
                            if (result == OK &&
                                !join_both_deleted_gone(bf.hashes, of.hashes,
                                                        tf.hashes, mf.hashes))
                                result = FAILSANITY;
                        }
                    }
                    JOINFree(&mf);
                }
            }
            u8bFree(m);
        }
        JOINFree(&bf);
        JOINFree(&of);
        JOINFree(&tf);
    }

    // Cleanup (always reached)
    JOINFree(&base_f);
    u8bFree(ours_buf);
    u8bFree(theirs_buf);

    if (result != OK) fail(result);
    done;
}
