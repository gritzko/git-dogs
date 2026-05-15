//  DELT: git delta instruction applier
//
#include "DELT.h"

#include "abc/PRO.h"

// Decode a size varint (7-bit continuation, used for base/result sizes)
static ok64 DELTDrainSize(u8cs from, u64 *out) {
    sane(out);
    u64 val = 0;
    u32 shift = 0;
    for (;;) {
        u8 c = 0;
        call(u8sDrain8, from, &c);
        test(shift < 64, DELTBADFMT);
        val |= (u64)(c & 0x7f) << shift;
        if (!(c & 0x80)) break;
        shift += 7;
    }
    *out = val;
    done;
}

ok64 DELTApply(u8cs delta, u8cs base, u8g out) {
    sane(u8csOK(delta) && u8csOK(base) && u8gOK(out));

    // header: base size, result size
    u64 base_sz = 0, result_sz = 0;
    call(DELTDrainSize, delta, &base_sz);
    call(DELTDrainSize, delta, &result_sz);

    test((u64)u8gRestLen(out) >= result_sz, NOROOM);
    u64 written = 0;

    while (!u8csEmpty(delta)) {
        u8 cmd = 0;
        call(u8sDrain8, delta, &cmd);

        if (cmd & 0x80) {
            // copy from base
            u64 off = 0, sz = 0;
            u8 b = 0;
            if (cmd & 0x01) { call(u8sDrain8, delta, &b); off |= (u64)b; }
            if (cmd & 0x02) { call(u8sDrain8, delta, &b); off |= (u64)b << 8; }
            if (cmd & 0x04) { call(u8sDrain8, delta, &b); off |= (u64)b << 16; }
            if (cmd & 0x08) { call(u8sDrain8, delta, &b); off |= (u64)b << 24; }
            if (cmd & 0x10) { call(u8sDrain8, delta, &b); sz |= (u64)b; }
            if (cmd & 0x20) { call(u8sDrain8, delta, &b); sz |= (u64)b << 8; }
            if (cmd & 0x40) { call(u8sDrain8, delta, &b); sz |= (u64)b << 16; }
            if (sz == 0) sz = 0x10000;

            test(off <= (u64)$size(base), DELTBADFMT);
            test(sz <= (u64)$size(base) - off, DELTBADFMT);
            test(sz <= result_sz - written, DELTBADFMT);

            a_rest(u8c, src, base, off);
            a_head(u8c, src_h, src, sz);
            call(u8gFeed, out, src_h);
            written += sz;
        } else if (cmd > 0) {
            // insert literal
            u64 n = cmd;
            test(n <= (u64)$size(delta), DELTBADFMT);
            test(n <= result_sz - written, DELTBADFMT);
            a_head(u8c, lit, delta, n);
            call(u8gFeed, out, lit);
            u8csUsed(delta, n);
            written += n;
        } else {
            return DELTBADFMT;  // cmd=0 is reserved
        }
    }

    test(written == result_sz, DELTBADFMT);
    done;
}

// --- Delta encoder ---

// Feed size varint into buffer
static void delt_feed_size(u8bp buf, u64 size) {
    for (;;) {
        u8 c = (u8)(size & 0x7f);
        size >>= 7;
        if (size > 0) c |= 0x80;
        u8bFeed1(buf, c);
        if (size == 0) break;
    }
}

// Feed a copy instruction: copy from base[off..off+sz)
static void delt_feed_copy(u8bp buf, u64 off, u64 sz) {
    u8 cmd = 0x80;
    a_pad(u8, tmp, 8);
    if (off & 0xff)       { cmd |= 0x01; u8bFeed1(tmp, (u8)(off)); }
    if (off & 0xff00)     { cmd |= 0x02; u8bFeed1(tmp, (u8)(off >> 8)); }
    if (off & 0xff0000)   { cmd |= 0x04; u8bFeed1(tmp, (u8)(off >> 16)); }
    if (off & 0xff000000) { cmd |= 0x08; u8bFeed1(tmp, (u8)(off >> 24)); }
    if (sz != 0x10000) {
        if (sz & 0xff)       { cmd |= 0x10; u8bFeed1(tmp, (u8)(sz)); }
        if (sz & 0xff00)     { cmd |= 0x20; u8bFeed1(tmp, (u8)(sz >> 8)); }
        if (sz & 0xff0000)   { cmd |= 0x40; u8bFeed1(tmp, (u8)(sz >> 16)); }
    }
    u8bFeed1(buf, cmd);
    a_dup(u8c, td, u8bData(tmp));
    u8bFeed(buf, td);
}

// Feed an insert instruction: literal bytes from target
static void delt_feed_insert(u8bp buf, u8csc data) {
    a_dup(u8c, rest, data);
    while (!u8csEmpty(rest)) {
        u64 rlen = u8csLen(rest);
        u8 chunk = (u8)(rlen > 127 ? 127 : rlen);
        u8bFeed1(buf, chunk);
        u8cs part = {rest[0], rest[0] + chunk};
        u8bFeed(buf, part);
        u8csUsed(rest, chunk);
    }
}

// Simple hash for 4-byte window
#define DELT_WINSZ 4
#define DELT_HTBITS 16
#define DELT_HTSZ (1u << DELT_HTBITS)

static u32 delt_hash4(u8cp p) {
    u32 h = (u32)p[0] | ((u32)p[1] << 8) |
            ((u32)p[2] << 16) | ((u32)p[3] << 24);
    return (h * 2654435761u) >> (32 - DELT_HTBITS);
}

ok64 DELTEncode(u8csc base, u8csc target, u8bp out) {
    sane(u8csOK(base) && u8csOK(target) && out != NULL);

    u64 base_sz = u8csLen(base);
    u64 target_sz = u8csLen(target);

    // Header: base size, result size
    delt_feed_size(out, base_sz);
    delt_feed_size(out, target_sz);

    if (base_sz < DELT_WINSZ || target_sz < DELT_WINSZ) {
        // Too small for matching, just insert everything
        delt_feed_insert(out, target);
        // Check if delta is smaller than raw
        if (u8bDataLen(out) >= target_sz) return DELTFAIL;
        done;
    }

    // Build hash table: hash(4 bytes) → offset in base.  Index EVERY
    // byte offset so small blobs (short repeats) still find matches;
    // we only keep one occurrence per bucket, but forward + backward
    // extension over the hit covers most realistic duplication.
    Bu32 ht_b = {};
    if (u32bAllocate(ht_b, DELT_HTSZ) != OK) fail(DELTFAIL);
    u32 *ht = u32bDataHead(ht_b);
    // 0 = empty, store offset+1
    for (u64 i = 0; i + DELT_WINSZ <= base_sz; i++) {
        u32 h = delt_hash4(base[0] + i);
        ht[h] = (u32)i + 1;
    }

    // Scan target, find matches
    u8cp tp = target[0];
    u8cp tend = target[1];
    u8cp insert_start = tp;  // pending insert region

    while (tp + DELT_WINSZ <= tend) {
        u32 h = delt_hash4(tp);
        u32 boff_1 = ht[h];

        if (boff_1 == 0) {
            tp++;
            continue;
        }

        u32 boff = boff_1 - 1;
        // Verify match at boff
        if (memcmp(base[0] + boff, tp, DELT_WINSZ) != 0) {
            tp++;
            continue;
        }

        // Extend match forward
        u8cp bp = base[0] + boff + DELT_WINSZ;
        u8cp mp = tp + DELT_WINSZ;
        while (mp < tend && bp < base[1] && *mp == *bp) {
            mp++;
            bp++;
        }

        // Extend match backward, but not past insert_start — any bytes
        // before that have already been flushed as literals, so copying
        // them would double-emit.
        u8cp bs = base[0] + boff;
        u8cp ms = tp;
        while (ms > insert_start && bs > base[0] && *(ms - 1) == *(bs - 1)) {
            ms--;
            bs--;
        }

        u64 match_len = (u64)(mp - ms);
        u64 match_boff = (u64)boff - (u64)(tp - ms);

        // Flush pending inserts preceding the (possibly back-extended)
        // match start.
        if (ms > insert_start) {
            u8cs ins = {insert_start, ms};
            delt_feed_insert(out, ins);
        }

        // git copy size is 3 bytes max (0x10000 default if all zero);
        // split huge matches into 0xffffff-byte chunks.
        while (match_len > 0) {
            u64 chunk = match_len > 0xffffffULL ? 0xffffffULL : match_len;
            delt_feed_copy(out, match_boff, chunk);
            match_boff += chunk;
            match_len  -= chunk;
        }
        tp = mp;
        insert_start = tp;
    }

    // Flush remaining inserts (anything after the last copy).
    if (insert_start < tend) {
        u8cs ins = {insert_start, tend};
        delt_feed_insert(out, ins);
    }

    u32bFree(ht_b);

    // If delta is not smaller, signal caller to use raw
    if (u8bDataLen(out) >= target_sz) return DELTFAIL;

    done;
}
