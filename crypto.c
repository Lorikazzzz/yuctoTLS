#include "headers/includes.h"
#include "headers/crypto.h"
#include "headers/chacha20.h"

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
static void transform(sha256_ctx_t *ctx) {
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
void sha256_init(sha256_ctx_t *ctx) {
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85; ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c; ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->bitlen = 0;
}
void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) { ctx->buffer[(ctx->bitlen / 8) % 64] = data[i]; ctx->bitlen += 8; if (ctx->bitlen % 512 == 0) transform(ctx); }
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

static void poly1305_mac(uint8_t *mac, const uint8_t *msg, size_t msg_len, const uint8_t *key) {
    uint32_t r[5], h[5] = {0}, c[5], g[5]; uint64_t d[5];
    r[0] = load32_le(key) & 0x3ffffff; r[1] = (load32_le(key + 3) >> 2) & 0x3ffff03;
    r[2] = (load32_le(key + 6) >> 4) & 0x3ffc0ff; r[3] = (load32_le(key + 9) >> 6) & 0x3f03fff;
    r[4] = (load32_le(key + 12) >> 8) & 0x00fffff;
    uint32_t s1 = r[1] * 5, s2 = r[2] * 5, s3 = r[3] * 5, s4 = r[4] * 5;
    size_t off = 0;
    while (off < msg_len) {
        size_t len = msg_len - off; if (len > 16) len = 16;
        uint8_t block[16] = {0}; memcpy(block, msg + off, len); if (len < 16) block[len] = 1;
        h[0] += load32_le(block) & 0x3ffffff; h[1] += (load32_le(block + 3) >> 2) & 0x3ffffff;
        h[2] += (load32_le(block + 6) >> 4) & 0x3ffffff; h[3] += (load32_le(block + 9) >> 6) & 0x3ffffff;
        h[4] += (load32_le(block + 12) >> 8) | (len == 16 ? (1 << 24) : 0);
        d[0] = (uint64_t)h[0]*r[0] + (uint64_t)h[1]*s4 + (uint64_t)h[2]*s3 + (uint64_t)h[3]*s2 + (uint64_t)h[4]*s1;
        d[1] = (uint64_t)h[0]*r[1] + (uint64_t)h[1]*r[0] + (uint64_t)h[2]*s4 + (uint64_t)h[3]*s3 + (uint64_t)h[4]*s2;
        d[2] = (uint64_t)h[0]*r[2] + (uint64_t)h[1]*r[1] + (uint64_t)h[2]*r[0] + (uint64_t)h[3]*s4 + (uint64_t)h[4]*s3;
        d[3] = (uint64_t)h[0]*r[3] + (uint64_t)h[1]*r[2] + (uint64_t)h[2]*r[1] + (uint64_t)h[3]*r[0] + (uint64_t)h[4]*s4;
        d[4] = (uint64_t)h[0]*r[4] + (uint64_t)h[1]*r[3] + (uint64_t)h[2]*r[2] + (uint64_t)h[3]*r[1] + (uint64_t)h[4]*r[0];
        h[0] = (uint32_t)d[0] & 0x3ffffff; c[1] = (uint32_t)(d[0] >> 26);
        d[1] += c[1]; h[1] = (uint32_t)d[1] & 0x3ffffff; c[2] = (uint32_t)(d[1] >> 26);
        d[2] += c[2]; h[2] = (uint32_t)d[2] & 0x3ffffff; c[3] = (uint32_t)(d[2] >> 26);
        d[3] += c[3]; h[3] = (uint32_t)d[3] & 0x3ffffff; c[4] = (uint32_t)(d[3] >> 26);
        d[4] += c[4]; h[4] = (uint32_t)d[4] & 0x3ffffff; c[0] = (uint32_t)(d[4] >> 26);
        h[0] += c[0] * 5; c[1] = h[0] >> 26; h[0] &= 0x3ffffff; h[1] += c[1];
        off += 16;
    }
    c[1] = h[1] >> 26; h[1] &= 0x3ffffff; h[2] += c[1]; c[2] = h[2] >> 26; h[2] &= 0x3ffffff; h[3] += c[2];
    c[3] = h[3] >> 26; h[3] &= 0x3ffffff; h[4] += c[3]; c[4] = h[4] >> 26; h[4] &= 0x3ffffff; h[0] += c[4] * 5;
    c[0] = h[0] >> 26; h[0] &= 0x3ffffff; h[1] += c[0];
    g[0] = h[0] + 5; c[1] = g[0] >> 26; g[0] &= 0x3ffffff; g[1] = h[1] + c[1]; c[2] = g[1] >> 26; g[1] &= 0x3ffffff;
    g[2] = h[2] + c[2]; c[3] = g[2] >> 26; g[2] &= 0x3ffffff; g[3] = h[3] + c[3]; c[4] = g[3] >> 26; g[3] &= 0x3ffffff;
    g[4] = h[4] + c[4] - (1 << 26);
    uint32_t mask = (g[4] >> 31) - 1;
    h[0] = (h[0] & ~mask) | (g[0] & mask); h[1] = (h[1] & ~mask) | (g[1] & mask);
    h[2] = (h[2] & ~mask) | (g[2] & mask); h[3] = (h[3] & ~mask) | (g[3] & mask);
    h[4] = (h[4] & ~mask) | (g[4] & mask);
    h[0] = h[0] | (h[1] << 26); h[1] = (h[1] >> 6) | (h[2] << 20);
    h[2] = (h[2] >> 12) | (h[3] << 14); h[3] = (h[3] >> 18) | (h[4] << 8);
    uint64_t f0 = (uint64_t)h[0] + load32_le(key + 16); uint64_t f1 = (uint64_t)h[1] + load32_le(key + 20) + (f0 >> 32);
    uint64_t f2 = (uint64_t)h[2] + load32_le(key + 24) + (f1 >> 32); uint64_t f3 = (uint64_t)h[3] + load32_le(key + 28) + (f2 >> 32);
    store32_le(mac + 0, (uint32_t)f0); store32_le(mac + 4, (uint32_t)f1);
    store32_le(mac + 8, (uint32_t)f2); store32_le(mac + 12, (uint32_t)f3);
}

void chacha20_poly1305_encrypt(const uint8_t *key, const uint8_t *nonce, const uint8_t *ad, size_t ad_len, const uint8_t *in, size_t len, uint8_t *out, uint8_t *tag) {
    uint8_t poly_key[32] = {0};
    chacha20_xor((uint8_t*)key, 0, (uint8_t*)nonce, (char*)poly_key, (char*)poly_key, 32);
    chacha20_xor((uint8_t*)key, 1, (uint8_t*)nonce, (char*)in, (char*)out, (int)len);
    
    size_t alloc_len = ((ad_len + 15) & ~15) + ((len + 15) & ~15) + 16;
    uint8_t *poly_msg = malloc(alloc_len);
    if (!poly_msg) return;
    size_t off = 0;
    if (ad && ad_len > 0) { memcpy(poly_msg + off, ad, ad_len); off += ad_len; while (off % 16 != 0) poly_msg[off++] = 0; }
    memcpy(poly_msg + off, out, len); off += len; while (off % 16 != 0) poly_msg[off++] = 0;
    store32_le(poly_msg + off, (uint32_t)ad_len); store32_le(poly_msg + off + 4, 0); off += 8;
    store32_le(poly_msg + off, (uint32_t)len); store32_le(poly_msg + off + 4, 0); off += 8;
    poly1305_mac(tag, poly_msg, off, poly_key);
    free(poly_msg);
}

int chacha20_poly1305_decrypt(const uint8_t *key, const uint8_t *nonce, const uint8_t *ad, size_t ad_len, const uint8_t *in, size_t len, uint8_t *out, const uint8_t *tag) {
    uint8_t poly_key[32] = {0}, calc_tag[16];
    chacha20_xor((uint8_t*)key, 0, (uint8_t*)nonce, (char*)poly_key, (char*)poly_key, 32);
    
    size_t alloc_len = ((ad_len + 15) & ~15) + ((len + 15) & ~15) + 16;
    uint8_t *poly_msg = malloc(alloc_len);
    if (!poly_msg) return -1;
    size_t off = 0;
    if (ad && ad_len > 0) { memcpy(poly_msg + off, ad, ad_len); off += ad_len; while (off % 16 != 0) poly_msg[off++] = 0; }
    memcpy(poly_msg + off, in, len); off += len; while (off % 16 != 0) poly_msg[off++] = 0;
    store32_le(poly_msg + off, (uint32_t)ad_len); store32_le(poly_msg + off + 4, 0); off += 8;
    store32_le(poly_msg + off, (uint32_t)len); store32_le(poly_msg + off + 4, 0); off += 8;
    poly1305_mac(calc_tag, poly_msg, off, poly_key);
    free(poly_msg);
    
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
    for (size_t i = 0; i < len; i++) {
        ctx->buffer[(ctx->bitlen / 8) % 128] = data[i];
        ctx->bitlen += 8;
        if (ctx->bitlen % 1024 == 0) {
            sha384_transform(ctx);
        }
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

/* ── Keccak-f[1600] and SHA-3 / SHAKE (FIPS 202) ────────────────── */
#define ROL64(a, offset) (((a) << (offset)) | ((a) >> (64 - (offset))))

static const uint64_t keccakf_round_constants[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008201ULL, 0x0000000080008008ULL,
    0x000000008000800aULL, 0x800000000000008bULL, 0x800000000000808bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL, 0x8000000000008002ULL,
    0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000800aULL,
    0x8000000080008081ULL, 0x0000000080008080ULL, 0x8000000080000001ULL
};

static void keccakf1600_compact(uint64_t s[25]) {
    const int r_offsets[24] = {
        1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
        27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
    };
    const int r_indices[24] = {
        10, 7,  11, 17, 18, 3,  5,  16, 8,  21, 24, 4,
        15, 23, 19, 13, 12, 2,  20, 14, 22, 9,  6,  1
    };
    for (int round = 0; round < 24; round++) {
        // Theta
        uint64_t C[5], D[5];
        for (int i = 0; i < 5; i++) C[i] = s[i] ^ s[i+5] ^ s[i+10] ^ s[i+15] ^ s[i+20];
        for (int i = 0; i < 5; i++) D[i] = C[(i+4)%5] ^ ROL64(C[(i+1)%5], 1);
        for (int i = 0; i < 25; i++) s[i] ^= D[i%5];
        // Rho & Pi
        uint64_t tmp = s[1];
        for (int i = 0; i < 24; i++) {
            int idx = r_indices[i];
            uint64_t next_tmp = s[idx];
            s[idx] = ROL64(tmp, r_offsets[i]);
            tmp = next_tmp;
        }
        // Chi
        for (int j = 0; j < 25; j += 5) {
            uint64_t T[5];
            for (int i = 0; i < 5; i++) T[i] = s[j+i];
            for (int i = 0; i < 5; i++) s[j+i] = T[i] ^ (~T[(i+1)%5] & T[(i+2)%5]);
        }
        // Iota
        s[0] ^= keccakf_round_constants[round];
    }
}

typedef struct {
    uint64_t s[25];
    int pos;
    int rate;
} shake_ctx_t;

static void shake_init(shake_ctx_t *ctx, int rate) {
    memset(ctx->s, 0, sizeof(ctx->s));
    ctx->pos = 0;
    ctx->rate = rate;
}

static void shake_update(shake_ctx_t *ctx, const uint8_t *in, size_t len) {
    for (size_t i = 0; i < len; i++) {
        int byte_idx = ctx->pos % ctx->rate;
        ctx->s[byte_idx / 8] ^= ((uint64_t)in[i]) << ((byte_idx % 8) * 8);
        ctx->pos++;
        if (ctx->pos % ctx->rate == 0) {
            keccakf1600_compact(ctx->s);
        }
    }
}

static void shake_padding(shake_ctx_t *ctx, uint8_t pad_byte) {
    int byte_idx = ctx->pos % ctx->rate;
    ctx->s[byte_idx / 8] ^= ((uint64_t)pad_byte) << ((byte_idx % 8) * 8);
    int last_idx = ctx->rate - 1;
    ctx->s[last_idx / 8] ^= 0x80ULL << ((last_idx % 8) * 8);
    keccakf1600_compact(ctx->s);
    ctx->pos = 0;
}

static void shake_out(shake_ctx_t *ctx, uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        int byte_idx = ctx->pos % ctx->rate;
        out[i] = (ctx->s[byte_idx / 8] >> ((byte_idx % 8) * 8)) & 0xFF;
        ctx->pos++;
        if (ctx->pos % ctx->rate == 0) {
            keccakf1600_compact(ctx->s);
        }
    }
}

void shake128(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen) {
    shake_ctx_t ctx;
    shake_init(&ctx, 168);
    shake_update(&ctx, in, inlen);
    shake_padding(&ctx, 0x1F);
    shake_out(&ctx, out, outlen);
}

void shake256(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen) {
    shake_ctx_t ctx;
    shake_init(&ctx, 136);
    shake_update(&ctx, in, inlen);
    shake_padding(&ctx, 0x1F);
    shake_out(&ctx, out, outlen);
}

void sha3_256(const uint8_t *in, size_t inlen, uint8_t *out) {
    shake_ctx_t ctx;
    shake_init(&ctx, 136);
    shake_update(&ctx, in, inlen);
    shake_padding(&ctx, 0x06);
    shake_out(&ctx, out, 32);
}

void sha3_512(const uint8_t *in, size_t inlen, uint8_t *out) {
    shake_ctx_t ctx;
    shake_init(&ctx, 72);
    shake_update(&ctx, in, inlen);
    shake_padding(&ctx, 0x06);
    shake_out(&ctx, out, 64);
}

/* ── FIPS 203 ML-KEM-768 Lattice Cryptography ────────────────────── */
#define KYBER_Q 3329
#define MONT 2285
#define QINV -3327

static int16_t montgomery_reduce(int32_t a) {
    int32_t t = (int16_t)a * QINV;
    t = (a - t * KYBER_Q) >> 16;
    return t;
}

static int16_t barrett_reduce(int16_t a) {
    int32_t t = ((int32_t)a * 20159) >> 26;
    t *= KYBER_Q;
    return a - t;
}

static const int16_t zetas[128] = {
    -1044, -758, -359, -1517, 1493, 1422, 287, 202,
    -171, 622, 1577, 724, 1375, -676, 1014, -700,
    -165, -244, 287, -429, 635, 148, -260, 224,
    1465, 1522, 451, -1026, -632, -505, -362, 1261,
    -147, 1357, 1205, -985, -29, 1478, 961, 810,
    1396, -26, -554, 886, -728, 1152, 1201, -1212,
    1443, -1149, 1010, -1066, 1177, 1381, 1033, -292,
    344, 110, 1148, -1202, -1539, -1479, 1007, -438,
    322, -169, 1403, 149, 1174, -1434, -1071, -1379,
    -959, 1015, -127, -41, 1001, -1283, 1222, -1067,
    -767, -270, 780, -969, -1082, -1106, 1171, 1445,
    -864, -209, -1305, 564, 1023, 761, 313, 1516,
    -126, 305, -2, -1441, -567, 1529, 30, -1364,
    -200, 1113, 915, -1386, 101, -1188, 1475, -814,
    -379, -510, 1285, -579, 837, -13, 1421, 617,
    -1191, -1102, 144, 76, 1530, 360, -980, 705
};

static const int16_t zetas_inv[128] = {
    -705, 980, -360, -1530, -76, -144, 1102, 1191,
    -617, -1421, 13, -837, 579, -1285, 510, 379,
    814, -1475, 1188, -101, 1386, -915, -1113, 200,
    1364, -30, -1529, 567, 1441, 2, -305, 126,
    -1516, -313, -761, -1023, -564, 1305, 209, 864,
    -1445, -1171, 1106, 1082, 969, -780, 270, 767,
    1067, -1222, 1283, -1001, 41, 127, -1015, 959,
    1379, 1071, 1434, -1174, -149, -1403, 169, -322,
    438, -1007, 1479, 1539, 1202, -1148, -110, -344,
    292, -1033, -1381, -1177, 1066, -1010, 1149, -1443,
    1212, -1201, -1152, 728, -886, 554, 26, -1396,
    -810, -961, -1478, 29, 985, -1205, -1357, 147,
    -1261, 362, 505, 632, 1026, -451, -1522, -1465,
    -224, 260, -148, -635, 429, -287, 244, 165,
    700, -1014, 676, -1375, -724, -1577, -622, 171,
    -202, -287, -1422, -1493, 1517, 359, 758, 1044
};

static void ntt(int16_t r[256]) {
    int k = 1;
    for (int len = 128; len >= 2; len >>= 1) {
        for (int start = 0; start < 256; start += 2 * len) {
            int16_t zeta = zetas[k++];
            for (int j = start; j < start + len; j++) {
                int16_t t = montgomery_reduce((int32_t)r[j + len] * zeta);
                r[j + len] = r[j] - t;
                r[j] = r[j] + t;
            }
        }
    }
}

static void invntt(int16_t r[256]) {
    int k = 0;
    for (int len = 2; len <= 128; len <<= 1) {
        for (int start = 0; start < 256; start += 2 * len) {
            int16_t zeta = zetas_inv[k++];
            for (int j = start; j < start + len; j++) {
                int16_t t = r[j];
                r[j] = barrett_reduce(t + r[j + len]);
                r[j + len] = montgomery_reduce((int32_t)(t - r[j + len]) * zeta);
            }
        }
    }
    int16_t f = 256;
    for (int j = 0; j < 256; j++) {
        r[j] = montgomery_reduce((int32_t)r[j] * f);
    }
}

static void poly_basemul(int16_t r[256], const int16_t a[256], const int16_t b[256]) {
    for (int i = 0; i < 64; i++) {
        int16_t zeta = zetas[64 + i];
        
        // Pair 1: coeffs 4*i and 4*i+1 with twiddle factor zeta
        int32_t t0 = (int32_t)a[4*i+1] * b[4*i+1];
        int16_t r0 = montgomery_reduce(t0);
        r0 = montgomery_reduce((int32_t)r0 * zeta);
        r0 += montgomery_reduce((int32_t)a[4*i] * b[4*i]);
        
        int32_t t1 = (int32_t)a[4*i] * b[4*i+1];
        t1 += (int32_t)a[4*i+1] * b[4*i];
        int16_t r1 = montgomery_reduce(t1);
        
        r[4*i] = r0;
        r[4*i+1] = r1;
        
        // Pair 2: coeffs 4*i+2 and 4*i+3 with twiddle factor -zeta
        int32_t t2 = (int32_t)a[4*i+3] * b[4*i+3];
        int16_t r2 = montgomery_reduce(t2);
        r2 = montgomery_reduce((int32_t)r2 * (-zeta));
        r2 += montgomery_reduce((int32_t)a[4*i+2] * b[4*i+2]);
        
        int32_t t3 = (int32_t)a[4*i+2] * b[4*i+3];
        t3 += (int32_t)a[4*i+3] * b[4*i+2];
        int16_t r3 = montgomery_reduce(t3);
        
        r[4*i+2] = r2;
        r[4*i+3] = r3;
    }
}

static void poly_tobytes(uint8_t *r, const int16_t *a) {
    for (int i = 0; i < 128; i++) {
        uint16_t t0 = barrett_reduce(a[2*i]);
        t0 = t0 + ((t0 >> 15) & KYBER_Q);
        uint16_t t1 = barrett_reduce(a[2*i+1]);
        t1 = t1 + ((t1 >> 15) & KYBER_Q);
        r[3*i] = t0 & 0xFF;
        r[3*i+1] = (t0 >> 8) | ((t1 & 0x0F) << 4);
        r[3*i+2] = (t1 >> 4);
    }
}

static void poly_frombytes(int16_t *r, const uint8_t *a) {
    for (int i = 0; i < 128; i++) {
        r[2*i] = a[3*i] | ((uint16_t)(a[3*i+1] & 0x0F) << 8);
        r[2*i+1] = (a[3*i+1] >> 4) | ((uint16_t)a[3*i+2] << 4);
    }
}

static void poly_compress10(uint8_t *r, const int16_t *a) {
    uint16_t t[4];
    for (int i = 0; i < 64; i++) {
        for (int j = 0; j < 4; j++) {
            int32_t val = barrett_reduce(a[4*i+j]);
            val = val + ((val >> 15) & KYBER_Q);
            t[j] = ((((uint32_t)val << 10) + KYBER_Q/2) / KYBER_Q) & 0x3FF;
        }
        r[5*i] = t[0] & 0xFF;
        r[5*i+1] = (t[0] >> 8) | ((t[1] & 0x3F) << 2);
        r[5*i+2] = (t[1] >> 6) | ((t[2] & 0x0F) << 4);
        r[5*i+3] = (t[2] >> 4) | ((t[3] & 0x03) << 6);
        r[5*i+4] = (t[3] >> 2);
    }
}

static void poly_decompress10(int16_t *r, const uint8_t *a) {
    uint16_t t[4];
    for (int i = 0; i < 64; i++) {
        t[0] = a[5*i] | ((uint16_t)(a[5*i+1] & 0x03) << 8);
        t[1] = (a[5*i+1] >> 2) | ((uint16_t)(a[5*i+2] & 0x0F) << 6);
        t[2] = (a[5*i+2] >> 4) | ((uint16_t)(a[5*i+3] & 0x3F) << 4);
        t[3] = (a[5*i+3] >> 6) | ((uint16_t)a[5*i+4] << 2);
        for (int j = 0; j < 4; j++) {
            r[4*i+j] = ((uint32_t)t[j] * KYBER_Q + 512) >> 10;
        }
    }
}

static void poly_compress4(uint8_t *r, const int16_t *a) {
    for (int i = 0; i < 128; i++) {
        int32_t val0 = barrett_reduce(a[2*i]);
        val0 = val0 + ((val0 >> 15) & KYBER_Q);
        uint8_t t0 = ((((uint32_t)val0 << 4) + KYBER_Q/2) / KYBER_Q) & 0x0F;
        
        int32_t val1 = barrett_reduce(a[2*i+1]);
        val1 = val1 + ((val1 >> 15) & KYBER_Q);
        uint8_t t1 = ((((uint32_t)val1 << 4) + KYBER_Q/2) / KYBER_Q) & 0x0F;
        
        r[i] = t0 | (t1 << 4);
    }
}

static void poly_decompress4(int16_t *r, const uint8_t *a) {
    for (int i = 0; i < 128; i++) {
        uint8_t t0 = a[i] & 0x0F;
        uint8_t t1 = a[i] >> 4;
        r[2*i] = ((uint32_t)t0 * KYBER_Q + 8) >> 4;
        r[2*i+1] = ((uint32_t)t1 * KYBER_Q + 8) >> 4;
    }
}

typedef struct {
    int16_t coeffs[256];
} poly_t;

typedef struct {
    poly_t vec[3];
} polyvec_t;

static void polyvec_ntt(polyvec_t *r) {
    for (int i = 0; i < 3; i++) ntt(r->vec[i].coeffs);
}

static void polyvec_invntt(polyvec_t *r) {
    for (int i = 0; i < 3; i++) invntt(r->vec[i].coeffs);
}

static void poly_pointwise_acc_montgomery(poly_t *r, const polyvec_t *a, const polyvec_t *b) {
    poly_t t;
    poly_basemul(r->coeffs, a->vec[0].coeffs, b->vec[0].coeffs);
    for (int i = 1; i < 3; i++) {
        poly_basemul(t.coeffs, a->vec[i].coeffs, b->vec[i].coeffs);
        for (int j = 0; j < 256; j++) {
            r->coeffs[j] = barrett_reduce(r->coeffs[j] + t.coeffs[j]);
        }
    }
}

static void cbd2(poly_t *r, const uint8_t *buf) {
    for (int i = 0; i < 128; i++) {
        uint8_t t = buf[i];
        int a0 = (t >> 0) & 1;
        int a1 = (t >> 1) & 1;
        int b0 = (t >> 2) & 1;
        int b1 = (t >> 3) & 1;
        r->coeffs[2*i] = (a0 + a1) - (b0 + b1);
        
        int a2 = (t >> 4) & 1;
        int a3 = (t >> 5) & 1;
        int b2 = (t >> 6) & 1;
        int b3 = (t >> 7) & 1;
        r->coeffs[2*i+1] = (a2 + a3) - (b2 + b3);
    }
}

static void gen_matrix_element(poly_t *r, const uint8_t seed[32], uint8_t i, uint8_t j) {
    uint8_t extseed[34];
    memcpy(extseed, seed, 32);
    extseed[32] = j;
    extseed[33] = i;
    
    shake_ctx_t ctx;
    shake_init(&ctx, 168);
    shake_update(&ctx, extseed, 34);
    shake_padding(&ctx, 0x1F);
    
    int ctr = 0;
    while (ctr < 256) {
        uint8_t buf[3];
        shake_out(&ctx, buf, 3);
        uint16_t d1 = buf[0] | ((uint16_t)(buf[1] & 0x0F) << 8);
        uint16_t d2 = (buf[1] >> 4) | ((uint16_t)buf[2] << 4);
        if (d1 < KYBER_Q) r->coeffs[ctr++] = d1;
        if (ctr < 256 && d2 < KYBER_Q) r->coeffs[ctr++] = d2;
    }
}

void mlkem768_keygen(uint8_t pk[1184], uint8_t sk[2400], const uint8_t coins[32]) {
    uint8_t hashed[64];
    sha3_512(coins, 32, hashed);
    const uint8_t *rho = hashed;
    const uint8_t *sigma = hashed + 32;
    
    polyvec_t A[3];
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 3; j++) {
            gen_matrix_element(&A[i].vec[j], rho, i, j);
        }
    }
    
    polyvec_t s, e;
    uint8_t prf_input[33];
    memcpy(prf_input, sigma, 32);
    
    for (int i = 0; i < 3; i++) {
        prf_input[32] = i;
        uint8_t out[128];
        shake256(prf_input, 33, out, 128);
        cbd2(&s.vec[i], out);
    }
    for (int i = 0; i < 3; i++) {
        prf_input[32] = i + 3;
        uint8_t out[128];
        shake256(prf_input, 33, out, 128);
        cbd2(&e.vec[i], out);
    }
    
    polyvec_ntt(&s);
    polyvec_ntt(&e);
    
    polyvec_t t;
    for (int i = 0; i < 3; i++) {
        poly_pointwise_acc_montgomery(&t.vec[i], &A[i], &s);
        for (int j = 0; j < 256; j++) {
            t.vec[i].coeffs[j] = barrett_reduce(t.vec[i].coeffs[j] + e.vec[i].coeffs[j]);
        }
    }
    
    for (int i = 0; i < 3; i++) {
        poly_tobytes(pk + 384 * i, t.vec[i].coeffs);
    }
    memcpy(pk + 1152, rho, 32);
    
    for (int i = 0; i < 3; i++) {
        poly_tobytes(sk + 384 * i, s.vec[i].coeffs);
    }
    memcpy(sk + 1152, pk, 1184);
    sha3_256(pk, 1184, sk + 2336);
    memset(sk + 2368, 0, 32);
}

int mlkem768_decaps(uint8_t ss[32], const uint8_t ct[1088], const uint8_t sk[2400]) {
    const uint8_t *pk = sk + 1152;
    const uint8_t *hpk = sk + 2336;
    const uint8_t *z = sk + 2368;
    
    polyvec_t u;
    poly_t v;
    for (int i = 0; i < 3; i++) {
        poly_decompress10(u.vec[i].coeffs, ct + 320 * i);
    }
    poly_decompress4(v.coeffs, ct + 960);
    
    polyvec_t s;
    for (int i = 0; i < 3; i++) {
        poly_frombytes(s.vec[i].coeffs, sk + 384 * i);
    }
    
    polyvec_ntt(&u);
    poly_t tmp;
    poly_pointwise_acc_montgomery(&tmp, &s, &u);
    invntt(tmp.coeffs);
    
    poly_t m;
    for (int j = 0; j < 256; j++) {
        int16_t diff = v.coeffs[j] - tmp.coeffs[j];
        m.coeffs[j] = barrett_reduce(diff);
    }
    
    uint8_t mp[32] = {0};
    for (int i = 0; i < 32; i++) {
        for (int j = 0; j < 8; j++) {
            int16_t val = barrett_reduce(m.coeffs[8*i+j]);
            val = val + ((val >> 15) & KYBER_Q);
            uint8_t bit = ((((uint32_t)val << 1) + KYBER_Q/2) / KYBER_Q) & 1;
            mp[i] |= bit << j;
        }
    }
    
    uint8_t g_input[64];
    memcpy(g_input, mp, 32);
    memcpy(g_input + 32, hpk, 32);
    
    uint8_t hashed[64];
    sha3_512(g_input, 64, hashed);
    const uint8_t *rho_prime = hashed;
    const uint8_t *sigma_prime = hashed + 32;
    
    polyvec_t A[3];
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 3; j++) {
            gen_matrix_element(&A[i].vec[j], rho_prime, i, j);
        }
    }
    
    polyvec_t s_prime;
    uint8_t prf_input[33];
    memcpy(prf_input, sigma_prime, 32);
    
    for (int i = 0; i < 3; i++) {
        prf_input[32] = i;
        uint8_t out[128];
        shake256(prf_input, 33, out, 128);
        cbd2(&s_prime.vec[i], out);
    }
    
    polyvec_t e_prime_prime;
    poly_t e_prime_prime_prime;
    for (int i = 0; i < 3; i++) {
        prf_input[32] = i + 6;
        uint8_t out[128];
        shake256(prf_input, 33, out, 128);
        cbd2(&e_prime_prime.vec[i], out);
    }
    {
        prf_input[32] = 9;
        uint8_t out[128];
        shake256(prf_input, 33, out, 128);
        cbd2(&e_prime_prime_prime, out);
    }
    
    polyvec_ntt(&s_prime);
    polyvec_ntt(&e_prime_prime);
    
    polyvec_t t_prime;
    for (int i = 0; i < 3; i++) {
        poly_pointwise_acc_montgomery(&t_prime.vec[i], &A[i], &s_prime);
        for (int j = 0; j < 256; j++) {
            t_prime.vec[i].coeffs[j] = barrett_reduce(t_prime.vec[i].coeffs[j] + e_prime_prime.vec[i].coeffs[j]);
        }
    }
    
    polyvec_t pk_vec;
    for (int i = 0; i < 3; i++) {
        poly_frombytes(pk_vec.vec[i].coeffs, pk + 384 * i);
    }
    polyvec_ntt(&pk_vec);
    poly_t v_prime;
    poly_pointwise_acc_montgomery(&v_prime, &pk_vec, &s_prime);
    invntt(v_prime.coeffs);
    for (int j = 0; j < 256; j++) {
        v_prime.coeffs[j] = barrett_reduce(v_prime.coeffs[j] + e_prime_prime_prime.coeffs[j]);
    }
    for (int i = 0; i < 32; i++) {
        for (int j = 0; j < 8; j++) {
            uint16_t m_bit = (mp[i] >> j) & 1;
            v_prime.coeffs[8*i+j] = barrett_reduce(v_prime.coeffs[8*i+j] + m_bit * (KYBER_Q / 2));
        }
    }
    
    uint8_t ct_prime[1088];
    for (int i = 0; i < 3; i++) {
        poly_compress10(ct_prime + 320 * i, t_prime.vec[i].coeffs);
    }
    poly_compress4(ct_prime + 960, v_prime.coeffs);
    
    int diff = 0;
    for (int i = 0; i < 1088; i++) {
        diff |= ct[i] ^ ct_prime[i];
    }
    
    uint8_t kdf_input[64];
    if (diff == 0) {
        memcpy(kdf_input, mp, 32);
        memcpy(kdf_input + 32, hpk, 32);
        shake256(kdf_input, 64, ss, 32);
    } else {
        shake_ctx_t kdf_ctx;
        shake_init(&kdf_ctx, 136);
        shake_update(&kdf_ctx, z, 32);
        shake_update(&kdf_ctx, ct, 1088);
        shake_padding(&kdf_ctx, 0x1F);
        shake_out(&kdf_ctx, ss, 32);
    }
    return 0;
}
