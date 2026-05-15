//  ZINF: zlib inflate/deflate wrapper
//  zlib.h before abc to avoid voidp/voidpc typedef clash.
//
#include <limits.h>
#include <zlib.h>

#include "ZINF.h"
#include "abc/BUF.h"

ok64 ZINFInflate(u8p *into, u8cp *zipped) {
    u64 srclen = zipped[1] - zipped[0];
    u64 dstlen = into[1] - into[0];
    if (srclen > UINT_MAX || dstlen > UINT_MAX)
        return ZINFTOOBIG;

    z_stream zs = {0};
    zs.next_in = (Bytef *)zipped[0];
    zs.avail_in = (uInt)srclen;
    zs.next_out = (Bytef *)into[0];
    zs.avail_out = (uInt)dstlen;

    int r = inflateInit(&zs);
    if (r != Z_OK) return ZINFINIT;

    uInt cap = zs.avail_out;
    for (;;) {
        r = inflate(&zs, Z_NO_FLUSH);
        if (r == Z_STREAM_END) break;
        if (r != Z_OK) { inflateEnd(&zs); return ZINFFAIL; }
        if (zs.avail_out == 0) {
            zs.next_out = (Bytef *)into[0];
            zs.avail_out = cap;
        }
    }

    u8csUsed(zipped, zs.total_in);
    u8sFed(into, zs.total_out);

    inflateEnd(&zs);
    return OK;
}

ok64 ZINFDeflate(u8p *into, u8cp *plain) {
    u64 srclen = plain[1] - plain[0];
    u64 dstlen = into[1] - into[0];
    if (srclen > UINT_MAX || dstlen > UINT_MAX)
        return ZINFTOOBIG;

    z_stream zs = {0};
    zs.next_in = (Bytef *)plain[0];
    zs.avail_in = (uInt)srclen;
    zs.next_out = (Bytef *)into[0];
    zs.avail_out = (uInt)dstlen;

    int r = deflateInit(&zs, Z_DEFAULT_COMPRESSION);
    if (r != Z_OK) return ZINFINIT;

    r = deflate(&zs, Z_FINISH);
    if (r != Z_STREAM_END) {
        deflateEnd(&zs);
        return ZINFFAIL;
    }

    u8csUsed(plain, zs.total_in);
    u8sFed(into, zs.total_out);

    deflateEnd(&zs);
    return OK;
}
