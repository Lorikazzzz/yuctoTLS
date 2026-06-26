#include "headers/includes.h"
#include "headers/crypto.h"
#include "headers/chacha20.h"
/* mlkem768_keygen and mlkem768_decaps are implemented in mlkem768.c */

#define F25519_SIZE 32

/* ── Utilities ───────────────────────────────────────────────────── */
void store32_le(uint8_t *p, uint32_t v) { p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24; }
uint32_t load32_le(const uint8_t *p) { return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24; }

/* ── SHA-256 ─────────────────────────────────────────────────────── */
#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define Ch(x, y, z)  ((x & y) ^ (~x & z))
#define Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define Sigma0(x) (ROR(x, 2) ^ ROR(x, 13) ^ ROR(x, 22))
#define Sigma1(x) (ROR(x, 6) ^ ROR(x, 11) ^ ROR(x, 25))
#define sigma0(x) (ROR(x, 7) ^ ROR(x, 18) ^ ((x) >> 3))
#define sigma1(x) (ROR(x, 17) ^ ROR(x, 19) ^ ((x) >> 10))
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
static void transform_soft(sha256_ctx_t *ctx) {
    uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64]; int i;
    for (i = 0; i < 16; i++) m[i] = (ctx->buffer[i * 4] << 24) | (ctx->buffer[i * 4 + 1] << 16) | (ctx->buffer[i * 4 + 2] << 8) | (ctx->buffer[i * 4 + 3]);
    for (; i < 64; i++) m[i] = sigma1(m[i - 2]) + m[i - 7] + sigma0(m[i - 15]) + m[i - 16];
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    for (i = 0; i < 64; i++) {
        t1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + m[i]; t2 = Sigma0(a) + Maj(a, b, c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
__attribute__((unused)) static int g_shani = -1;
__attribute__((unused)) static int shani_available(void) {
    int v = g_shani;
    if (v < 0) { v = __builtin_cpu_supports("sha") ? 1 : 0; g_shani = v; }
    return v;
}
/* Intel SHA-NI single-block SHA-256 compression. */
__attribute__((unused, target("sha,sse4.1,ssse3")))
static void transform_shani(sha256_ctx_t *ctx) {
    const __m128i BSWAP = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);
    __m128i state0, state1, msg, tmp, m0, m1, m2, m3, abef_save, cdgh_save;

    /* state: TMP=[a b e f], state1=[c d g h] from ctx->state[0..7] */
    tmp    = _mm_loadu_si128((const __m128i*)&ctx->state[0]); /* a b c d */
    state1 = _mm_loadu_si128((const __m128i*)&ctx->state[4]); /* e f g h */
    tmp    = _mm_shuffle_epi32(tmp, 0xB1);          /* b a d c */
    state1 = _mm_shuffle_epi32(state1, 0x1B);       /* h g f e */
    state0 = _mm_alignr_epi8(tmp, state1, 8);       /* a b e f */
    state1 = _mm_blend_epi16(state1, tmp, 0xF0);    /* c d g h */

    abef_save = state0; cdgh_save = state1;

    m0 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(ctx->buffer+0)),  BSWAP);
    m1 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(ctx->buffer+16)), BSWAP);
    m2 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(ctx->buffer+32)), BSWAP);
    m3 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(ctx->buffer+48)), BSWAP);

    #define RNDS2(M, K0, K1) \
        msg = _mm_add_epi32(M, _mm_set_epi64x(K1, K0)); \
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg); \
        msg = _mm_shuffle_epi32(msg, 0x0E); \
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg)
    #define SCHED(A,B,C,D) \
        A = _mm_sha256msg1_epu32(A, B); \
        tmp = _mm_alignr_epi8(D, C, 4); \
        A = _mm_add_epi32(A, tmp); \
        A = _mm_sha256msg2_epu32(A, D)

    RNDS2(m0, 0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL);
    RNDS2(m1, 0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL);
    RNDS2(m2, 0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL);
    RNDS2(m3, 0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL);
    SCHED(m0,m1,m2,m3); RNDS2(m0, 0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL);
    SCHED(m1,m2,m3,m0); RNDS2(m1, 0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL);
    SCHED(m2,m3,m0,m1); RNDS2(m2, 0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL);
    SCHED(m3,m0,m1,m2); RNDS2(m3, 0x1429296706CA6351ULL, 0xD5A79147C6E00BF3ULL);
    SCHED(m0,m1,m2,m3); RNDS2(m0, 0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL);
    SCHED(m1,m2,m3,m0); RNDS2(m1, 0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL);
    SCHED(m2,m3,m0,m1); RNDS2(m2, 0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL);
    SCHED(m3,m0,m1,m2); RNDS2(m3, 0x106AA070F40E3585ULL, 0xD6990624D192E819ULL);
    SCHED(m0,m1,m2,m3); RNDS2(m0, 0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL);
    SCHED(m1,m2,m3,m0); RNDS2(m1, 0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL);
    SCHED(m2,m3,m0,m1); RNDS2(m2, 0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL);
    SCHED(m3,m0,m1,m2); RNDS2(m3, 0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL);

    #undef RNDS2
    #undef SCHED

    state0 = _mm_add_epi32(state0, abef_save);
    state1 = _mm_add_epi32(state1, cdgh_save);

    tmp    = _mm_shuffle_epi32(state0, 0x1B);        /* f e b a */
    state1 = _mm_shuffle_epi32(state1, 0xB1);        /* d c h g */
    state0 = _mm_blend_epi16(tmp, state1, 0xF0);     /* a b c d */
    state1 = _mm_alignr_epi8(state1, tmp, 8);        /* e f g h */
    _mm_storeu_si128((__m128i*)&ctx->state[0], state0);
    _mm_storeu_si128((__m128i*)&ctx->state[4], state1);
}
#endif

static void transform(sha256_ctx_t *ctx) {
    /* NOTE: transform_shani (SHA-NI) is implemented but DISABLED — its
       round/schedule interleave is not yet bit-exact. SHA-256 is only on the
       handshake/HKDF path (small data), so the software path is used. Re-enable
       transform_shani only after it passes the SHA-256 KAT vectors.          */
    transform_soft(ctx);
}
void sha256_init(sha256_ctx_t *ctx) {
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85; ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c; ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->bitlen = 0;
}
void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len) {
    size_t buf_used = (size_t)((ctx->bitlen / 8) % 64);
    ctx->bitlen += (uint64_t)len * 8;
    while (len > 0) {
        size_t space = 64 - buf_used;
        size_t to_copy = len < space ? len : space;
        memcpy(ctx->buffer + buf_used, data, to_copy);
        data += to_copy; len -= to_copy; buf_used += to_copy;
        if (buf_used == 64) { transform(ctx); buf_used = 0; }
    }
}
void sha256_final(sha256_ctx_t *ctx, uint8_t *hash) {
    uint64_t bitlen = ctx->bitlen; uint8_t pad = 0x80; sha256_update(ctx, &pad, 1);
    while ((ctx->bitlen % 512) != 448) { pad = 0x00; sha256_update(ctx, &pad, 1); }
    for (int i = 7; i >= 0; i--) { uint8_t b = (uint8_t)(bitlen >> (i * 8)); sha256_update(ctx, &b, 1); }
    for (int i = 0; i < 8; i++) {
        hash[i * 4] = (ctx->state[i] >> 24) & 0xff; hash[i * 4 + 1] = (ctx->state[i] >> 16) & 0xff;
        hash[i * 4 + 2] = (ctx->state[i] >> 8) & 0xff; hash[i * 4 + 3] = (ctx->state[i] & 0xff);
    }
}
void hmac_sha256_init(hmac_sha256_ctx_t *ctx, const uint8_t *key, size_t key_len) {
    uint8_t k[64] = {0}, i_key_pad[64], o_key_pad[64];
    if (key_len > 64) { sha256_init(&ctx->inner); sha256_update(&ctx->inner, key, key_len); sha256_final(&ctx->inner, k); }
    else memcpy(k, key, key_len);
    for (int i = 0; i < 64; i++) { i_key_pad[i] = k[i] ^ 0x36; o_key_pad[i] = k[i] ^ 0x5c; }
    sha256_init(&ctx->inner); sha256_update(&ctx->inner, i_key_pad, 64);
    sha256_init(&ctx->outer); sha256_update(&ctx->outer, o_key_pad, 64);
    ctx->initialized = 1;
}
void hmac_sha256_update(hmac_sha256_ctx_t *ctx, const uint8_t *data, size_t len) { if (ctx->initialized) sha256_update(&ctx->inner, data, len); }
void hmac_sha256_final(hmac_sha256_ctx_t *ctx, uint8_t *hash) {
    uint8_t inner_hash[32]; if (!ctx->initialized) return;
    sha256_final(&ctx->inner, inner_hash); sha256_update(&ctx->outer, inner_hash, 32); sha256_final(&ctx->outer, hash);
    ctx->initialized = 0;
}
void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *mac) {
    hmac_sha256_ctx_t ctx; hmac_sha256_init(&ctx, key, key_len); hmac_sha256_update(&ctx, data, data_len); hmac_sha256_final(&ctx, mac);
}

/* ── Poly1305 — incremental block API (no allocation, zero-copy AEAD) ─────*/
typedef struct {
    uint32_t r[5], s[4], h[5];
    const uint8_t *key;          /* for the final +key[16..31] add */
} poly1305_state;

static void poly1305_setup(poly1305_state *st, const uint8_t *key) {
    st->r[0] = load32_le(key)      & 0x3ffffff;
    st->r[1] = (load32_le(key+3)  >> 2) & 0x3ffff03;
    st->r[2] = (load32_le(key+6)  >> 4) & 0x3ffc0ff;
    st->r[3] = (load32_le(key+9)  >> 6) & 0x3f03fff;
    st->r[4] = (load32_le(key+12) >> 8) & 0x00fffff;
    st->s[0] = st->r[1]*5; st->s[1] = st->r[2]*5; st->s[2] = st->r[3]*5; st->s[3] = st->r[4]*5;
    st->h[0]=st->h[1]=st->h[2]=st->h[3]=st->h[4]=0;
    st->key = key;
}

/* process one full 16-byte block (2^128 high bit set) */
static void poly1305_block16(poly1305_state *st, const uint8_t *block) {
    uint32_t *h = st->h, *r = st->r, *s = st->s, c[5]; uint64_t d[5];
    h[0] += load32_le(block)      & 0x3ffffff;
    h[1] += (load32_le(block+3)  >> 2) & 0x3ffffff;
    h[2] += (load32_le(block+6)  >> 4) & 0x3ffffff;
    h[3] += (load32_le(block+9)  >> 6) & 0x3ffffff;
    h[4] += (load32_le(block+12) >> 8) | (1 << 24);
    d[0] = (uint64_t)h[0]*r[0] + (uint64_t)h[1]*s[3] + (uint64_t)h[2]*s[2] + (uint64_t)h[3]*s[1] + (uint64_t)h[4]*s[0];
    d[1] = (uint64_t)h[0]*r[1] + (uint64_t)h[1]*r[0] + (uint64_t)h[2]*s[3] + (uint64_t)h[3]*s[2] + (uint64_t)h[4]*s[1];
    d[2] = (uint64_t)h[0]*r[2] + (uint64_t)h[1]*r[1] + (uint64_t)h[2]*r[0] + (uint64_t)h[3]*s[3] + (uint64_t)h[4]*s[2];
    d[3] = (uint64_t)h[0]*r[3] + (uint64_t)h[1]*r[2] + (uint64_t)h[2]*r[1] + (uint64_t)h[3]*r[0] + (uint64_t)h[4]*s[3];
    d[4] = (uint64_t)h[0]*r[4] + (uint64_t)h[1]*r[3] + (uint64_t)h[2]*r[2] + (uint64_t)h[3]*r[1] + (uint64_t)h[4]*r[0];
    h[0] = (uint32_t)d[0] & 0x3ffffff; c[1] = (uint32_t)(d[0] >> 26);
    d[1] += c[1]; h[1] = (uint32_t)d[1] & 0x3ffffff; c[2] = (uint32_t)(d[1] >> 26);
    d[2] += c[2]; h[2] = (uint32_t)d[2] & 0x3ffffff; c[3] = (uint32_t)(d[2] >> 26);
    d[3] += c[3]; h[3] = (uint32_t)d[3] & 0x3ffffff; c[4] = (uint32_t)(d[3] >> 26);
    d[4] += c[4]; h[4] = (uint32_t)d[4] & 0x3ffffff; c[0] = (uint32_t)(d[4] >> 26);
    h[0] += c[0]*5; c[1] = h[0] >> 26; h[0] &= 0x3ffffff; h[1] += c[1];
}

static void poly1305_done(poly1305_state *st, uint8_t *mac) {
    uint32_t *h = st->h, c[5], g[5]; const uint8_t *key = st->key;
    c[1] = h[1] >> 26; h[1] &= 0x3ffffff; h[2] += c[1]; c[2] = h[2] >> 26; h[2] &= 0x3ffffff; h[3] += c[2];
    c[3] = h[3] >> 26; h[3] &= 0x3ffffff; h[4] += c[3]; c[4] = h[4] >> 26; h[4] &= 0x3ffffff; h[0] += c[4]*5;
    c[0] = h[0] >> 26; h[0] &= 0x3ffffff; h[1] += c[0];
    g[0] = h[0]+5; c[1] = g[0] >> 26; g[0] &= 0x3ffffff; g[1] = h[1]+c[1]; c[2] = g[1] >> 26; g[1] &= 0x3ffffff;
    g[2] = h[2]+c[2]; c[3] = g[2] >> 26; g[2] &= 0x3ffffff; g[3] = h[3]+c[3]; c[4] = g[3] >> 26; g[3] &= 0x3ffffff;
    g[4] = h[4]+c[4]-(1 << 26);
    uint32_t mask = (g[4] >> 31)-1;
    h[0]=(h[0]&~mask)|(g[0]&mask); h[1]=(h[1]&~mask)|(g[1]&mask);
    h[2]=(h[2]&~mask)|(g[2]&mask); h[3]=(h[3]&~mask)|(g[3]&mask); h[4]=(h[4]&~mask)|(g[4]&mask);
    h[0]=h[0]|(h[1]<<26); h[1]=(h[1]>>6)|(h[2]<<20);
    h[2]=(h[2]>>12)|(h[3]<<14); h[3]=(h[3]>>18)|(h[4]<<8);
    uint64_t f0=(uint64_t)h[0]+load32_le(key+16); uint64_t f1=(uint64_t)h[1]+load32_le(key+20)+(f0>>32);
    uint64_t f2=(uint64_t)h[2]+load32_le(key+24)+(f1>>32); uint64_t f3=(uint64_t)h[3]+load32_le(key+28)+(f2>>32);
    store32_le(mac+0,(uint32_t)f0); store32_le(mac+4,(uint32_t)f1);
    store32_le(mac+8,(uint32_t)f2); store32_le(mac+12,(uint32_t)f3);
}

/* RFC 8439 AEAD tag: MAC over aad‖pad16‖ct‖pad16‖le64(aadlen)‖le64(ctlen),
   reading aad/ct in place — no allocation, no full-data copy. */
static void poly1305_aead_tag(uint8_t *tag, const uint8_t *poly_key,
                              const uint8_t *aad, size_t ad_len,
                              const uint8_t *ct, size_t ct_len) {
    poly1305_state st; poly1305_setup(&st, poly_key);
    size_t i;
    for (i = 0; i + 16 <= ad_len; i += 16) poly1305_block16(&st, aad + i);
    if (i < ad_len) { uint8_t b[16] = {0}; memcpy(b, aad + i, ad_len - i); poly1305_block16(&st, b); }
    for (i = 0; i + 16 <= ct_len; i += 16) poly1305_block16(&st, ct + i);
    if (i < ct_len) { uint8_t b[16] = {0}; memcpy(b, ct + i, ct_len - i); poly1305_block16(&st, b); }
    uint8_t lb[16];
    store32_le(lb+0,(uint32_t)ad_len); store32_le(lb+4,0);
    store32_le(lb+8,(uint32_t)ct_len); store32_le(lb+12,0);
    poly1305_block16(&st, lb);
    poly1305_done(&st, tag);
}

void chacha20_poly1305_encrypt(const uint8_t *key, const uint8_t *nonce, const uint8_t *ad, size_t ad_len, const uint8_t *in, size_t len, uint8_t *out, uint8_t *tag) {
    uint8_t poly_key[32] = {0};
    chacha20_xor((uint8_t*)key, 0, (uint8_t*)nonce, (char*)poly_key, (char*)poly_key, 32);
    chacha20_xor((uint8_t*)key, 1, (uint8_t*)nonce, (char*)in, (char*)out, (int)len);
    poly1305_aead_tag(tag, poly_key, ad, ad_len, out, len);  /* zero-copy MAC */
}

int chacha20_poly1305_decrypt(const uint8_t *key, const uint8_t *nonce, const uint8_t *ad, size_t ad_len, const uint8_t *in, size_t len, uint8_t *out, const uint8_t *tag) {
    uint8_t poly_key[32] = {0}, calc_tag[16];
    chacha20_xor((uint8_t*)key, 0, (uint8_t*)nonce, (char*)poly_key, (char*)poly_key, 32);
    poly1305_aead_tag(calc_tag, poly_key, ad, ad_len, in, len);  /* zero-copy MAC */

    int diff = 0;
    for (int i = 0; i < 16; i++) diff |= calc_tag[i] ^ tag[i];
    if (diff != 0) return -1;
    
    chacha20_xor((uint8_t*)key, 1, (uint8_t*)nonce, (char*)in, (char*)out, (int)len);
    return (int)len;
}
void hkdf_sha256_extract(const uint8_t *salt, size_t slen, const uint8_t *ikm, size_t ilen, uint8_t *prk) {
    uint8_t zs[32] = {0};
    hmac_sha256(salt ? salt : zs, salt ? slen : 32, ikm ? ikm : zs, ikm ? ilen : 32, prk);
}
void hkdf_sha256_expand(const uint8_t *prk, const uint8_t *info, size_t ilen, uint8_t *okm, size_t olen) {
    uint8_t t[32], c = 1; size_t off = 0; hmac_sha256_ctx_t ctx;
    while (off < olen) {
        hmac_sha256_init(&ctx, prk, 32); if (c > 1) hmac_sha256_update(&ctx, t, 32);
        hmac_sha256_update(&ctx, info, ilen); hmac_sha256_update(&ctx, &c, 1); hmac_sha256_final(&ctx, t);
        size_t n = (olen - off > 32) ? 32 : (olen - off); memcpy(okm + off, t, n); off += n; c++;
    }
}

/* ── X25519 (Standard 51-bit limbs) ────────────────────────── */
typedef int64_t fe[5];


static void fe_frombytes(fe h, const uint8_t *s) {
    uint64_t x0 = load32_le(s);
    uint64_t x1 = load32_le(s + 4);
    uint64_t x2 = load32_le(s + 8);
    uint64_t x3 = load32_le(s + 12);
    uint64_t x4 = load32_le(s + 16);
    uint64_t x5 = load32_le(s + 20);
    uint64_t x6 = load32_le(s + 24);
    uint64_t x7 = load32_le(s + 28);
    h[0] = (x0 | (x1 << 32)) & 0x7ffffffffffffLL;
    h[1] = ((x1 >> 19) | (x2 << 13) | (x3 << 45)) & 0x7ffffffffffffLL;
    h[2] = ((x3 >> 6) | (x4 << 26)) & 0x7ffffffffffffLL;
    h[3] = ((x4 >> 25) | (x5 << 7) | (x6 << 39)) & 0x7ffffffffffffLL;
    h[4] = ((x6 >> 12) | (x7 << 20)) & 0x7ffffffffffffLL;
}

static void fe_tobytes(uint8_t *s, const fe h) {
    fe f; memcpy(f, h, sizeof(fe));
    for(int j=0; j<5; j++) {
        int64_t q = (f[4] >> 51); f[4] &= 0x7ffffffffffffLL; f[0] += q * 19;
        for(int i=0; i<4; i++) { q = (f[i] >> 51); f[i] &= 0x7ffffffffffffLL; f[i+1] += q; }
    }
    fe m; m[0]=f[0]+19; for(int i=0; i<4; i++) { m[i+1]=f[i+1]+(m[i]>>51); m[i]&=0x7ffffffffffffLL; }
    if ((m[4] >> 51) > 0) { m[4]&=0x7ffffffffffffLL; memcpy(f, m, sizeof(fe)); }
    uint64_t x0=f[0], x1=f[1], x2=f[2], x3=f[3], x4=f[4];
    s[0]=x0; s[1]=x0>>8; s[2]=x0>>16; s[3]=x0>>24; s[4]=x0>>32; s[5]=x0>>40; s[6]=(x0>>48)|(x1<<3);
    s[7]=x1>>5; s[8]=x1>>13; s[9]=x1>>21; s[10]=x1>>29; s[11]=x1>>37; s[12]=(x1>>45)|(x2<<6);
    s[13]=x2>>2; s[14]=x2>>10; s[15]=x2>>18; s[16]=x2>>26; s[17]=x2>>34; s[18]=x2>>42; s[19]=(x2>>50)|(x3<<1);
    s[20]=x3>>7; s[21]=x3>>15; s[22]=x3>>23; s[23]=x3>>31; s[24]=x3>>39; s[25]=(x3>>47)|(x4<<4);
    s[26]=x4>>4; s[27]=x4>>12; s[28]=x4>>20; s[29]=x4>>28; s[30]=x4>>36; s[31]=x4>>44;
}

static void fe_add(fe h, const fe f, const fe g) { for(int i=0; i<5; i++) h[i] = f[i] + g[i]; }
static void fe_sub(fe h, const fe f, const fe g) { for(int i=0; i<5; i++) h[i] = f[i] - g[i]; }

typedef struct { uint64_t lo; int64_t hi; } i128;

static inline i128 i128_from_i64(int64_t x) {
    i128 r = { (uint64_t)x, x >> 63 };
    return r;
}

static inline i128 i128_mul(int64_t a, int64_t b) {
    int neg = (a < 0) ^ (b < 0);
    uint64_t ua = a < 0 ? (uint64_t)(-a) : (uint64_t)a;
    uint64_t ub = b < 0 ? (uint64_t)(-b) : (uint64_t)b;

    /* Split into 32-bit halves so every multiply is 32×32→64 (native on ARMv7) */
    uint32_t a0=(uint32_t)ua,        a1=(uint32_t)(ua>>32);
    uint32_t b0=(uint32_t)ub,        b1=(uint32_t)(ub>>32);
    uint64_t p00=(uint64_t)a0*b0,   p01=(uint64_t)a0*b1;
    uint64_t p10=(uint64_t)a1*b0,   p11=(uint64_t)a1*b1;

    uint64_t mid = (p00>>32) + (uint32_t)p01 + (uint32_t)p10;
    uint64_t lo  = ((uint64_t)(uint32_t)p00) | (mid<<32);
    uint64_t hi  = p11 + (p01>>32) + (p10>>32) + (mid>>32);

    if (neg) { lo = ~lo+1; hi = ~hi + (lo==0 ? 1u : 0u); }
    i128 r = { lo, (int64_t)hi };
    return r;
}

static inline i128 i128_add(i128 a, i128 b) {
    i128 r;
    r.lo = a.lo + b.lo;
    r.hi = a.hi + b.hi + (r.lo < a.lo ? 1 : 0);   /* propagate carry */
    return r;
}

static inline i128 i128_shr51(i128 a) {             /* arithmetic >>51  */
    i128 r;
    r.lo = (a.lo>>51) | ((uint64_t)a.hi<<13);
    r.hi = a.hi>>51;
    return r;
}

static inline int64_t i128_mask51(i128 a) {
    return (int64_t)(a.lo & 0x7ffffffffffffULL);
}

static void fe_mul(fe h, const fe f, const fe g) {
    int64_t f0=f[0],f1=f[1],f2=f[2],f3=f[3],f4=f[4];
    int64_t g0=g[0],g1=g[1],g2=g[2],g3=g[3],g4=g[4];
    int64_t g1_19=g1*19, g2_19=g2*19, g3_19=g3*19, g4_19=g4*19;

#define MUL(a,b)   i128_mul((a),(b))
#define ADD(a,b)   i128_add((a),(b))

    i128 r0=ADD(ADD(ADD(ADD(MUL(f0,g0),    MUL(f1,g4_19)),
                             MUL(f2,g3_19)),MUL(f3,g2_19)),MUL(f4,g1_19));
    i128 r1=ADD(ADD(ADD(ADD(MUL(f0,g1),    MUL(f1,g0)),
                             MUL(f2,g4_19)),MUL(f3,g3_19)),MUL(f4,g2_19));
    i128 r2=ADD(ADD(ADD(ADD(MUL(f0,g2),    MUL(f1,g1)),
                             MUL(f2,g0)),   MUL(f3,g4_19)),MUL(f4,g3_19));
    i128 r3=ADD(ADD(ADD(ADD(MUL(f0,g3),    MUL(f1,g2)),
                             MUL(f2,g1)),   MUL(f3,g0)),   MUL(f4,g4_19));
    i128 r4=ADD(ADD(ADD(ADD(MUL(f0,g4),    MUL(f1,g3)),
                             MUL(f2,g2)),   MUL(f3,g1)),   MUL(f4,g0));
#undef MUL
#undef ADD

    i128 c;
    c=i128_shr51(r0); h[0]=i128_mask51(r0); r1=i128_add(r1,c);
    c=i128_shr51(r1); h[1]=i128_mask51(r1); r2=i128_add(r2,c);
    c=i128_shr51(r2); h[2]=i128_mask51(r2); r3=i128_add(r3,c);
    c=i128_shr51(r3); h[3]=i128_mask51(r3); r4=i128_add(r4,c);
    c=i128_shr51(r4); h[4]=i128_mask51(r4);

    /* After the carry chain c fits in int64_t (≤ 2^54), so no i128 needed */
    int64_t h0x = h[0] + (int64_t)c.lo * 19;
    h[0] = h0x & 0x7ffffffffffffLL;
    h[1] += h0x >> 51;
}

static void fe_sq(fe h, const fe f) { fe_mul(h, f, f); }

static void fe_inv(fe out, const fe z) {
    fe z2, z9, z11, z2_5_0, z2_10_0, z2_20_0, z2_50_0, z2_100_0, t;

    fe_sq(z2, z);
    fe_sq(t, z2);
    fe_sq(t, t);
    fe_mul(z9, t, z);
    fe_mul(z11, z9, z2);
    fe_sq(t, z11);
    fe_mul(z2_5_0, t, z9);

    fe_sq(t, z2_5_0);
    for (int i = 1; i < 5; i++) fe_sq(t, t);
    fe_mul(z2_10_0, t, z2_5_0);

    fe_sq(t, z2_10_0);
    for (int i = 1; i < 10; i++) fe_sq(t, t);
    fe_mul(z2_20_0, t, z2_10_0);

    fe_sq(t, z2_20_0);
    for (int i = 1; i < 20; i++) fe_sq(t, t);
    fe_mul(t, t, z2_20_0);

    fe_sq(t, t);
    for (int i = 1; i < 10; i++) fe_sq(t, t);
    fe_mul(z2_50_0, t, z2_10_0);

    fe_sq(t, z2_50_0);
    for (int i = 1; i < 50; i++) fe_sq(t, t);
    fe_mul(z2_100_0, t, z2_50_0);

    fe_sq(t, z2_100_0);
    for (int i = 1; i < 100; i++) fe_sq(t, t);
    fe_mul(t, t, z2_100_0);

    fe_sq(t, t);
    for (int i = 1; i < 50; i++) fe_sq(t, t);
    fe_mul(t, t, z2_50_0);

    fe_sq(t, t);
    fe_sq(t, t);
    fe_sq(t, t);
    fe_sq(t, t);
    fe_sq(t, t);
    fe_mul(out, t, z11);
}

static void fe_cswap(fe f, fe g, uint8_t b) {
    int64_t mask = -(int64_t)b;
    for(int i=0; i<5; i++) { int64_t x = mask & (f[i] ^ g[i]); f[i] ^= x; g[i] ^= x; }
}

void x25519(uint8_t *result, const uint8_t *n_in, const uint8_t *p_in) {
    uint8_t n[32]; memcpy(n, n_in, 32); n[0] &= 248; n[31] &= 127; n[31] |= 64;
    fe x2 = {1,0,0,0,0}, z2 = {0,0,0,0,0}, x3, z3 = {1,0,0,0,0};
    fe_frombytes(x3, p_in);
    uint8_t prev_bit = 0;
    fe p; fe_frombytes(p, p_in);
    for (int i = 254; i >= 0; i--) {
        uint8_t bit = (n[i >> 3] >> (i & 7)) & 1;
        fe_cswap(x2, x3, bit ^ prev_bit); fe_cswap(z2, z3, bit ^ prev_bit);
        fe a, b, aa, bb, da, cb, e, tmp;
        fe_add(a, x2, z2); fe_sub(b, x3, z3); fe_mul(da, a, b);
        fe_sub(a, x2, z2); fe_add(b, x3, z3); fe_mul(cb, a, b);
        fe_add(a, da, cb); fe_sq(x3, a);
        fe_sub(b, da, cb); fe_sq(a, b); fe_mul(z3, a, p);
        fe_add(a, x2, z2); fe_sq(aa, a);
        fe_sub(b, x2, z2); fe_sq(bb, b);
        fe_mul(x2, aa, bb);
        fe_sub(e, aa, bb);
        fe a24 = {121665, 0, 0, 0, 0};
        fe_mul(tmp, e, a24); fe_add(a, aa, tmp); fe_mul(z2, e, a);
        prev_bit = bit;
    }
    fe_cswap(x2, x3, prev_bit); fe_cswap(z2, z3, prev_bit);
    fe z_inv; fe_inv(z_inv, z2); fe_mul(x2, x2, z_inv); fe_tobytes(result, x2);
}

void x25519_base(uint8_t *out, const uint8_t *scalar) {
    uint8_t basepoint[32] = {9};
    x25519(out, scalar, basepoint);
}

/* ── SHA-384 / SHA-512 ───────────────────────────────────────────── */
#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define Ch64(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define Maj64(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sigma0_64(x) (ROR64(x, 28) ^ ROR64(x, 34) ^ ROR64(x, 39))
#define Sigma1_64(x) (ROR64(x, 14) ^ ROR64(x, 18) ^ ROR64(x, 41))
#define sigma0_64(x) (ROR64(x, 1) ^ ROR64(x, 8) ^ ((x) >> 7))
#define sigma1_64(x) (ROR64(x, 19) ^ ROR64(x, 61) ^ ((x) >> 6))

static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static void sha384_transform(sha384_ctx_t *ctx) {
    uint64_t a, b, c, d, e, f, g, h, t1, t2, m[80];
    int i;
    for (i = 0; i < 16; i++) {
        m[i] = ((uint64_t)ctx->buffer[i * 8] << 56) |
               ((uint64_t)ctx->buffer[i * 8 + 1] << 48) |
               ((uint64_t)ctx->buffer[i * 8 + 2] << 40) |
               ((uint64_t)ctx->buffer[i * 8 + 3] << 32) |
               ((uint64_t)ctx->buffer[i * 8 + 4] << 24) |
               ((uint64_t)ctx->buffer[i * 8 + 5] << 16) |
               ((uint64_t)ctx->buffer[i * 8 + 6] << 8) |
               ((uint64_t)ctx->buffer[i * 8 + 7]);
    }
    for (; i < 80; i++) {
        m[i] = sigma1_64(m[i - 2]) + m[i - 7] + sigma0_64(m[i - 15]) + m[i - 16];
    }
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    for (i = 0; i < 80; i++) {
        t1 = h + Sigma1_64(e) + Ch64(e, f, g) + K512[i] + m[i];
        t2 = Sigma0_64(a) + Maj64(a, b, c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

void sha384_init(sha384_ctx_t *ctx) {
    ctx->state[0] = 0xcbbb9d5dc1059ed8ULL;
    ctx->state[1] = 0x629a292a367cd507ULL;
    ctx->state[2] = 0x9159015a3070dd17ULL;
    ctx->state[3] = 0x152fecd8f70e5939ULL;
    ctx->state[4] = 0x67332667ffc00b31ULL;
    ctx->state[5] = 0x8eb44a8768581511ULL;
    ctx->state[6] = 0xdb0c2e0d64f98fa7ULL;
    ctx->state[7] = 0x47b5481dbefa4fa4ULL;
    ctx->bitlen = 0;
}

void sha384_update(sha384_ctx_t *ctx, const uint8_t *data, size_t len) {
    size_t buf_used = (size_t)((ctx->bitlen / 8) % 128);
    ctx->bitlen += (uint64_t)len * 8;
    while (len > 0) {
        size_t space = 128 - buf_used;
        size_t to_copy = len < space ? len : space;
        memcpy(ctx->buffer + buf_used, data, to_copy);
        data += to_copy; len -= to_copy; buf_used += to_copy;
        if (buf_used == 128) { sha384_transform(ctx); buf_used = 0; }
    }
}

void sha384_final(sha384_ctx_t *ctx, uint8_t *hash) {
    uint64_t bitlen = ctx->bitlen;
    uint8_t pad = 0x80;
    sha384_update(ctx, &pad, 1);
    while ((ctx->bitlen % 1024) != 896) {
        pad = 0x00;
        sha384_update(ctx, &pad, 1);
    }
    for (int i = 0; i < 8; i++) {
        uint8_t zero = 0x00;
        sha384_update(ctx, &zero, 1);
    }
    for (int i = 7; i >= 0; i--) {
        uint8_t b = (uint8_t)(bitlen >> (i * 8));
        sha384_update(ctx, &b, 1);
    }
    for (int i = 0; i < 6; i++) {
        hash[i * 8]     = (ctx->state[i] >> 56) & 0xff;
        hash[i * 8 + 1] = (ctx->state[i] >> 48) & 0xff;
        hash[i * 8 + 2] = (ctx->state[i] >> 40) & 0xff;
        hash[i * 8 + 3] = (ctx->state[i] >> 32) & 0xff;
        hash[i * 8 + 4] = (ctx->state[i] >> 24) & 0xff;
        hash[i * 8 + 5] = (ctx->state[i] >> 16) & 0xff;
        hash[i * 8 + 6] = (ctx->state[i] >> 8) & 0xff;
        hash[i * 8 + 7] = (ctx->state[i] & 0xff);
    }
}

void hmac_sha384_init(hmac_sha384_ctx_t *ctx, const uint8_t *key, size_t key_len) {
    uint8_t k[128] = {0};
    uint8_t i_key_pad[128], o_key_pad[128];
    if (key_len > 128) {
        sha384_ctx_t tmp;
        sha384_init(&tmp);
        sha384_update(&tmp, key, key_len);
        sha384_final(&tmp, k);
    } else {
        memcpy(k, key, key_len);
    }
    for (int i = 0; i < 128; i++) {
        i_key_pad[i] = k[i] ^ 0x36;
        o_key_pad[i] = k[i] ^ 0x5c;
    }
    sha384_init(&ctx->inner);
    sha384_update(&ctx->inner, i_key_pad, 128);
    sha384_init(&ctx->outer);
    sha384_update(&ctx->outer, o_key_pad, 128);
    ctx->initialized = 1;
}

void hmac_sha384_update(hmac_sha384_ctx_t *ctx, const uint8_t *data, size_t len) {
    sha384_update(&ctx->inner, data, len);
}

void hmac_sha384_final(hmac_sha384_ctx_t *ctx, uint8_t *hash) {
    uint8_t inner_hash[48];
    sha384_final(&ctx->inner, inner_hash);
    sha384_update(&ctx->outer, inner_hash, 48);
    sha384_final(&ctx->outer, hash);
}

void hmac_sha384(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *mac) {
    hmac_sha384_ctx_t ctx;
    hmac_sha384_init(&ctx, key, key_len);
    hmac_sha384_update(&ctx, data, data_len);
    hmac_sha384_final(&ctx, mac);
}

void hkdf_sha384_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, uint8_t *prk) {
    uint8_t zs[48] = {0};
    hmac_sha384(salt ? salt : zs, salt ? salt_len : 48, ikm ? ikm : zs, ikm ? ikm_len : 48, prk);
}

void hkdf_sha384_expand(const uint8_t *prk, const uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len) {
    uint8_t T[48] = {0};
    size_t n = (okm_len + 47) / 48;
    uint8_t c = 1;
    size_t left = okm_len;
    for (size_t i = 0; i < n; i++) {
        hmac_sha384_ctx_t ctx;
        hmac_sha384_init(&ctx, prk, 48);
        if (i > 0) {
            hmac_sha384_update(&ctx, T, 48);
        }
        hmac_sha384_update(&ctx, info, info_len);
        hmac_sha384_update(&ctx, &c, 1);
        hmac_sha384_final(&ctx, T);
        size_t take = (left < 48) ? left : 48;
        memcpy(okm + (i * 48), T, take);
        left -= take;
        c++;
    }
}

void tls12_prf(const uint8_t *secret, size_t secret_len, const char *label, const uint8_t *seed, size_t seed_len, uint8_t *out, size_t out_len) {
    size_t label_len = strlen(label);
    size_t total_seed_len = label_len + seed_len;
    uint8_t total_seed[128];
    if (total_seed_len > 128) return;
    memcpy(total_seed, label, label_len);
    memcpy(total_seed + label_len, seed, seed_len);

    uint8_t A[32];
    hmac_sha256(secret, secret_len, total_seed, total_seed_len, A);

    size_t out_off = 0;
    while (out_off < out_len) {
        hmac_sha256_ctx_t ctx;
        hmac_sha256_init(&ctx, secret, secret_len);
        hmac_sha256_update(&ctx, A, 32);
        hmac_sha256_update(&ctx, total_seed, total_seed_len);
        
        uint8_t tmp[32];
        hmac_sha256_final(&ctx, tmp);

        size_t chunk_len = out_len - out_off;
        if (chunk_len > 32) chunk_len = 32;
        memcpy(out + out_off, tmp, chunk_len);
        out_off += chunk_len;

        hmac_sha256(secret, secret_len, A, 32, A);
    }
}

