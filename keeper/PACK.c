//  PACK: git packfile parser
//
#include "PACK.h"

#include "GIT.h"
#include "ZINF.h"
#include "abc/PRO.h"

static a_cstr(PACK_MAGIC, "PACK");

ok64 PACKu8sFeedHdr(u8s into, u32 count) {
    sane(u8sOK(into));
    call(u8sFeed, into, PACK_MAGIC);
    u32 ver_be = flip32(2);
    u32 cnt_be = flip32(count);
    call(u8sFeed32, into, &ver_be);
    call(u8sFeed32, into, &cnt_be);
    done;
}

ok64 PACKDrainHdr(u8cs from, pack_hdr *hdr) {
    sane(u8csOK(from) && hdr);
    if ($size(from) < 12) return NODATA;

    if (memcmp(from[0], PACK_MAGIC[0], 4) != 0)
        return PACKBADFMT;
    u8csUsed(from, 4);

    // version + count: big-endian u32
    u32 v = 0, c = 0;
    u8sDrain32(from, &v);
    u8sDrain32(from, &c);
    hdr->version = flip32(v);
    hdr->count = flip32(c);

    done;
}

// Decode git varint: type in bits 6..4 of first byte, size in
// bit 3..0 of first byte then 7-bit continuation.
static ok64 PACKDrainVarint(u8cs from, u8 *type, u64 *size) {
    sane(type && size);
    u8 c = 0;
    call(u8sDrain8, from, &c);

    *type = (c >> 4) & 0x7;
    *size = c & 0x0f;
    u32 shift = 4;

    while (c & 0x80) {
        test(shift < 64, PACKBADFMT);
        call(u8sDrain8, from, &c);
        *size |= (u64)(c & 0x7f) << shift;
        shift += 7;
    }

    done;
}

// Decode OFS_DELTA negative offset varint
static ok64 PACKDrainOfs(u8cs from, u64 *ofs) {
    sane(ofs);
    u8 c = 0;
    call(u8sDrain8, from, &c);
    *ofs = c & 0x7f;

    while (c & 0x80) {
        test(*ofs < (UINT64_MAX >> 7), PACKBADFMT);
        call(u8sDrain8, from, &c);
        *ofs = ((*ofs + 1) << 7) | (c & 0x7f);
    }

    done;
}

ok64 PACKDrainObjHdr(u8cs from, pack_obj *obj) {
    sane(u8csOK(from) && obj);
    memset(obj, 0, sizeof(*obj));

    ok64 rv = PACKDrainVarint(from, &obj->type, &obj->size);
    if (rv != OK) return rv;

    if (obj->type == PACK_OBJ_OFS_DELTA) {
        ok64 ro = PACKDrainOfs(from, &obj->ofs_delta);
        if (ro != OK) return ro;
    } else if (obj->type == PACK_OBJ_REF_DELTA) {
        if ($size(from) < GIT_SHA1_LEN) return PACKBADFMT;
        a_head(u8c, ref, from, GIT_SHA1_LEN);
        u8csUsed(from, GIT_SHA1_LEN);
        u8csMv(obj->ref_delta, ref);
    }

    done;
}

ok64 PACKInflate(u8cs from, u8s into, u64 size) {
    sane(u8csOK(from) && u8sOK(into));
    if ((u64)u8sLen(into) < size) return NOROOM;

    a_dup(u8, trimmed, into);
    u8sShed(trimmed, u8sLen(trimmed) - size);
    ok64 o = ZINFInflate(trimmed, from);
    if (o != OK) return PACKBADOBJ;
    u8sJoin(into, trimmed);

    done;
}
