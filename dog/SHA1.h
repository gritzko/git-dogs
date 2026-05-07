#ifndef DOG_SHA1_H
#define DOG_SHA1_H

//  SHA1: git SHA-1 type + hashing via sha1dc.
//  Follows abc/SHA.h pattern: struct, Sum, Open/Feed/Close.

#include "abc/INT.h"
#include "sha1dc/sha1.h"

typedef struct {
    u8 data[20];
} sha1;

fun b8 sha1empty(sha1 const *s) {
    u64c *w = (u64c *)s->data;
    u32c *t = (u32c *)(s->data + 16);
    return (w[0] | w[1] | *t) == 0;
}

fun int sha1cmp(sha1 const *a, sha1 const *b) {
    return memcmp(a->data, b->data, 20);
}

fun b8 sha1eq(sha1 const *a, sha1 const *b) {
    return memcmp(a->data, b->data, 20) == 0;
}

fun b8 sha1Z(sha1 const *a, sha1 const *b) {
    return memcmp(a->data, b->data, 20) < 0;
}

// --- Hashing ---

typedef SHA1_CTX SHA1state;

fun void SHA1Sum(sha1 *hash, u8csc from) {
    SHA1_CTX ctx;
    SHA1DCInit(&ctx);
    SHA1DCSetSafeHash(&ctx, 0);
    SHA1DCUpdate(&ctx, (char const *)from[0], (size_t)u8csLen(from));
    SHA1DCFinal(hash->data, &ctx);
}

fun void SHA1Open(SHA1state *state) {
    SHA1DCInit(state);
    SHA1DCSetSafeHash(state, 0);
}

fun void SHA1Feed(SHA1state *state, u8csc data) {
    SHA1DCUpdate(state, (char const *)data[0], (size_t)u8csLen(data));
}

fun void SHA1Close(SHA1state *state, sha1 *hash) {
    SHA1DCFinal(hash->data, state);
}

// --- Slice of sha1 as u8csc (for hashlet etc) ---

fun void sha1slice(u8csp out, sha1 const *s) {
    out[0] = s->data;
    out[1] = s->data + 20;
}

// Copy 20 raw bytes from a slice into a sha1.  Returns BADRANGE
// when the slice is not exactly 20 bytes; otherwise OK.
fun ok64 sha1FromBin(sha1 *out, u8cs bin) {
    if (u8csLen(bin) != 20) return BADRANGE;
    u8s dst = {out->data, out->data + 20};
    u8sCopy(dst, bin);
    return OK;
}

// --- ABC type system ---

#define X(M, n) M##sha1##n
#include "abc/Bx.h"
#include "abc/HEXx.h"
#undef X

#endif
