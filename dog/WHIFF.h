#ifndef DOG_WHIFF_H
#define DOG_WHIFF_H

//  WHIFF: 64-bit tagged word with offset[40] | id[20] | type[4].
//
//  Hashlet in the MS 40 bits so entries sort by hashlet first.
//  When id=0, the hashlet effectively spans 60 bits (id bits
//  become additional hashlet bits).
//
//  Hashlets are big-endian: first SHA byte in the top bits.
//  Construct via flip64(memcpy 8 SHA bytes) >> shift.
//
//  Canonical layout used across dogs:
//    keeper: hashlet=sha_prefix, id=file_number, type=pack_format
//    graf:   hashlet=sha_prefix, id=generation,  type=entry_kind
//    sniff:  off=mtime,          id=path_index,  type=flags

#include "abc/INT.h"
#include "abc/HEX.h"

typedef u64 wh64;

fun int wh64cmp(wh64 const *a, wh64 const *b) {
    return *a < *b ? -1 : (*a == *b ? 0 : 1);
}

//  Bx instantiation for the wh64 value type — gives us `wh64b`,
//  `wh64s`, `wh64sFeed1`, etc.  Distinct from `u64*` even though
//  wh64 is a u64 alias, so call sites can declare intent.
#define X(M, name) M##wh64##name
#include "abc/Bx.h"
#undef X

#define WHIFF_TYPE_BITS   4
#define WHIFF_TYPE_MASK   0xfULL
#define WHIFF_ID_SHIFT    WHIFF_TYPE_BITS       // bits 4-23
#define WHIFF_ID_BITS     20
#define WHIFF_ID_MASK     ((1ULL << WHIFF_ID_BITS) - 1)
#define WHIFF_OFF_SHIFT   (WHIFF_TYPE_BITS + WHIFF_ID_BITS)  // bits 24-63
#define WHIFF_OFF_BITS    40
#define WHIFF_OFF_MASK    ((1ULL << WHIFF_OFF_BITS) - 1)

fun wh64 wh64Pack(u8 type, u32 id, u64 off) {
    return ((u64)type & WHIFF_TYPE_MASK) |
           (((u64)id & WHIFF_ID_MASK) << WHIFF_ID_SHIFT) |
           ((off & WHIFF_OFF_MASK) << WHIFF_OFF_SHIFT);
}

fun u8  wh64Type(wh64 v) { return (u8)(v & WHIFF_TYPE_MASK); }
fun u32 wh64Id(wh64 v)   { return (u32)((v >> WHIFF_ID_SHIFT) & WHIFF_ID_MASK); }
fun u64 wh64Off(wh64 v)  { return (v >> WHIFF_OFF_SHIFT) & WHIFF_OFF_MASK; }

// --- wh128: (key, val) pair, equality on both fields ---

typedef struct {
    wh64 key;
    wh64 val;
} wh128;

fun u64  wh128hash(wh128 const *v) { return mix64(v->key ^ v->val); }

fun int wh128cmp(wh128 const *a, wh128 const *b) {
    if (a->key != b->key) return a->key < b->key ? -1 : 1;
    if (a->val != b->val) return a->val < b->val ? -1 : 1;
    return 0;
}

fun b8 wh128Z(wh128 const *a, wh128 const *b) {
    if (a->key != b->key) return a->key < b->key;
    return a->val < b->val;
}

#define X(M, name) M##wh128##name
#include "abc/Bx.h"
#undef X

//  Bx instantiation for wh128cs slots (the slice-of-wh128 type
//  itself).  Gives us `wh128csb` (4-pointer buffer of wh128cs) and
//  `wh128cssFeed1` (push one wh128cs slot through a wh128css head),
//  paralleling BUF.h's u8csb / u8cssFeed1.  ABC_X_$ flag is set
//  because wh128cs is array-typed.
typedef wh128cs const *wh128cscp;

fun int wh128cscmp(wh128cs const *a, wh128cs const *b) { return $cmp(*a, *b); }

#define X(M, name) M##wh128cs##name
#define ABC_X_$
#include "abc/Bx.h"
#undef ABC_X_$
#undef X

// --- SHA-1 hashlet helpers ---
//
// Two widths:
//   40-bit (10 hex chars): for vals where id field is used separately
//   60-bit (15 hex chars): for keys where id=0 (hashlet spans both fields)
//
// Both are big-endian: first SHA byte in the most significant bits.
// Input: sha1 const * (typed, 20 bytes).

#include "dog/SHA1.h"

// 40-bit hashlet: first 5 bytes of SHA (10 hex chars)
#define WHIFF_HASHLET40_BITS  40
#define WHIFF_HASHLET40_MASK  WHIFF_OFF_MASK

fun u64 WHIFFHashlet40(sha1 const *s) {
    u64 h = 0;
    memcpy(&h, s->data, 8);
    return (flip64(h) >> 24) & WHIFF_HASHLET40_MASK;
}

// 60-bit hashlet: first 7.5 bytes of SHA (15 hex chars)
#define WHIFF_HASHLET60_BITS  60
#define WHIFF_HASHLET60_MASK  ((1ULL << 60) - 1)

fun u64 WHIFFHashlet60(sha1 const *s) {
    u64 h = 0;
    memcpy(&h, s->data, 8);
    return (flip64(h) >> 4) & WHIFF_HASHLET60_MASK;
}

// --- Hashlet to hex ---

fun ok64 WHIFFHexFeed40(u8s out, u64 hashlet) {
    for (int i = 0; i < 10 && !$empty(out); i++) {
        u8 nib = (u8)((hashlet >> (36 - i * 4)) & 0xf);
        **out = "0123456789abcdef"[nib];
        ++*out;
    }
    return OK;
}

fun ok64 WHIFFHexFeed60(u8s out, u64 hashlet) {
    for (int i = 0; i < 15 && !$empty(out); i++) {
        u8 nib = (u8)((hashlet >> (56 - i * 4)) & 0xf);
        **out = "0123456789abcdef"[nib];
        ++*out;
    }
    return OK;
}

// --- SHA-1 hex representation (40 ASCII hex chars) ---

typedef struct {
    u8 data[40];
} sha1hex;

typedef sha1hex const *sha1hexcp;

fun void sha1hexFromSha1(sha1hex *out, sha1 const *s) {
    u8s hs = {out->data, out->data + 40};
    u8cs bs = {s->data, s->data + 20};
    HEXu8sFeedSome(hs, bs);
}

fun ok64 sha1FromSha1hex(sha1 *out, sha1hex const *h) {
    u8s sb = {out->data, out->data + 20};
    u8cs hx = {h->data, h->data + 40};
    return HEXu8sDrainSome(sb, hx);
}

fun b8 sha1hexeq(sha1hexcp a, sha1hexcp b) {
    return memcmp(a->data, b->data, 40) == 0;
}

fun void sha1hexSlice(u8csp out, sha1hexcp s) {
    out[0] = s->data;
    out[1] = s->data + 40;
}

// --- Hex to hashlet ---

fun u64 WHIFFHexHashlet40(u8csc hex) {
    size_t nchars = u8csLen(hex);
    if (nchars > 10) nchars = 10;
    u64 h = 0;
    $for(u8c, p, hex) {
        if ((size_t)(p - hex[0]) >= nchars) break;
        u8 nib = BASE16rev[*p];
        if (nib == 0xff) break;
        h = (h << 4) | nib;
    }
    h <<= (10 - nchars) * 4;
    return h;
}

fun u64 WHIFFHexHashlet60(u8csc hex) {
    size_t nchars = u8csLen(hex);
    if (nchars > 15) nchars = 15;
    u64 h = 0;
    $for(u8c, p, hex) {
        if ((size_t)(p - hex[0]) >= nchars) break;
        u8 nib = BASE16rev[*p];
        if (nib == 0xff) break;
        h = (h << 4) | nib;
    }
    h <<= (15 - nchars) * 4;
    return h;
}

#endif
