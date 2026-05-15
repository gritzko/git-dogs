//  PKT: git pkt-line framing
//
#include "PKT.h"

#include "abc/HEX.h"
#include "abc/PRO.h"

// Decode 4 hex chars to a u16 length using abc/HEX reverse table
static ok64 PKTDecLen(u8cs from, u16 *out) {
    if ($size(from) < 4) return NODATA;
    u16 val = 0;
    for (int i = 0; i < 4; i++) {
        u8 d = BASE16rev[from[0][i]];
        if (d == 0xff) return PKTBADFMT;
        val = (val << 4) | d;
    }
    *out = val;
    return OK;
}

ok64 PKTu8sDrain(u8cs from, u8csp line) {
    sane(u8csOK(from) && line);
    if ($size(from) < 4) return NODATA;

    u16 len = 0;
    ok64 rl = PKTDecLen(from, &len);
    if (rl != OK) return rl;

    // special packets
    if (len <= 2) {
        u8csUsed(from, 4);
        if (len == 1) return PKTDELIM;
        return PKTFLUSH;  // 0 = flush, 2 = response-end
    }

    if (len < 4) return PKTBADFMT;
    u16 payload_len = len - 4;

    if ($size(from) < (u64)len) return NODATA;

    a_head(u8c, frame, from, len);
    u8csUsed(from, len);
    a_rest(u8c, payload, frame, 4);
    u8csMv(line, payload);

    done;
}

ok64 PKTu8sFeed(u8s into, u8csc payload) {
    sane(u8csOK(payload));
    u64 plen = $size(payload);
    if (plen > PKT_MAX) return PKTBADFMT;
    u16 total = (u16)(plen + 4);

    if ($size(into) < total) return NOROOM;

    // write 4-hex length + payload
    u8 lhex[4] = {
        $at(BASE16, (total >> 12) & 0xf),
        $at(BASE16, (total >> 8) & 0xf),
        $at(BASE16, (total >> 4) & 0xf),
        $at(BASE16, total & 0xf),
    };
    u8cs lhexs = {lhex, lhex + 4};
    u8sFeed(into, lhexs);
    u8sFeed(into, payload);

    done;
}

ok64 PKTu8sFeedFlush(u8s into) {
    sane(u8sOK(into));
    if ($size(into) < 4) return NOROOM;
    a_cstr(flush, "0000");
    u8sFeed(into, flush);
    done;
}
