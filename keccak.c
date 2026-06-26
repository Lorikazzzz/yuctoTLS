/*
 * keccak.c — Compact Keccak-f[1600] sponge + the subset of the FIPS 202
 * (fips202.h) API that PQClean's ML-KEM-768 reference implementation calls.
 *
 * Compiled from mlkem768.c with every symbol below renamed to a pqc_*
 * prefix (see the #defines there), so nothing here is visible outside
 * the ML-KEM translation unit.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "fips202.h"

/* ── Keccak-f[1600] round constants (FIPS 202, Appendix B) ──────────────── */
static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

#define ROL64(x,n) (((x)<<(n))|((x)>>(64-(n))))

static void keccakf1600(uint64_t s[25]) {
    static const int rho[24] = {
         1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
        27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
    };
    static const int pi_[24] = {
        10,  7, 11, 17, 18, 3,  5, 16,  8, 21, 24,  4,
        15, 23, 19, 13, 12, 2, 20, 14, 22,  9,  6,  1
    };
    for (int r = 0; r < 24; r++) {
        uint64_t C[5], D[5];
        for (int i = 0; i < 5; i++)
            C[i] = s[i]^s[i+5]^s[i+10]^s[i+15]^s[i+20];
        for (int i = 0; i < 5; i++)
            D[i] = C[(i+4)%5] ^ ROL64(C[(i+1)%5], 1);
        for (int i = 0; i < 25; i++) s[i] ^= D[i%5];

        uint64_t t = s[1];
        for (int i = 0; i < 24; i++) {
            int j = pi_[i];
            uint64_t u = s[j];
            s[j] = ROL64(t, rho[i]);
            t = u;
        }
        for (int i = 0; i < 25; i += 5) {
            uint64_t b[5];
            for (int j = 0; j < 5; j++) b[j] = s[i+j];
            for (int j = 0; j < 5; j++) s[i+j] = b[j] ^ (~b[(j+1)%5] & b[(j+2)%5]);
        }
        s[0] ^= RC[r];
    }
}

/* ── Sponge state — shared keccak_state type from fips202.h ─────────────── */
typedef keccak_state kstate;

static void ks_init(kstate *k, unsigned rate) {
    memset(k->ctx, 0, sizeof(k->ctx)); k->pos = 0; k->rate = rate;
}
static void ks_absorb(kstate *k, const uint8_t *in, size_t len) {
    for (size_t i = 0; i < len; i++) {
        ((uint8_t *)k->ctx)[k->pos] ^= in[i];
        if (++k->pos == k->rate) { keccakf1600(k->ctx); k->pos = 0; }
    }
}
static void ks_finalize(kstate *k, uint8_t pad) {
    ((uint8_t *)k->ctx)[k->pos] ^= pad;
    ((uint8_t *)k->ctx)[k->rate - 1] ^= 0x80;
    keccakf1600(k->ctx);
    k->pos = 0;
}
static void ks_squeeze(kstate *k, uint8_t *out, size_t outlen) {
    for (size_t i = 0; i < outlen; i++) {
        if (k->pos == k->rate) { keccakf1600(k->ctx); k->pos = 0; }
        out[i] = ((uint8_t *)k->ctx)[k->pos++];
    }
}
static void ks_squeezeblocks(uint8_t *out, size_t nblocks, kstate *k) {
    for (size_t b = 0; b < nblocks; b++) {
        memcpy(out + b * k->rate, k->ctx, k->rate);
        keccakf1600(k->ctx);
    }
}

/* ── One-shot SHA3/SHAKE (PQClean argument order: out, in, inlen) ───────── */
void sha3_256(uint8_t *out, const uint8_t *in, size_t inlen) {
    kstate k; ks_init(&k, 136); ks_absorb(&k, in, inlen); ks_finalize(&k, 0x06); ks_squeeze(&k, out, 32);
}
void sha3_512(uint8_t *out, const uint8_t *in, size_t inlen) {
    kstate k; ks_init(&k, 72);  ks_absorb(&k, in, inlen); ks_finalize(&k, 0x06); ks_squeeze(&k, out, 64);
}
void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
    kstate k; ks_init(&k, 136); ks_absorb(&k, in, inlen); ks_finalize(&k, 0x1f); ks_squeeze(&k, out, outlen);
}

/* ── shake128 one-shot context (used by Kyber's matrix-generation XOF) ──── */
void shake128_absorb(shake128ctx *ctx, const uint8_t *in, size_t inlen) {
    ks_init(ctx, 168); ks_absorb(ctx, in, inlen);
    ((uint8_t *)ctx->ctx)[ctx->pos] ^= 0x1f;
    ((uint8_t *)ctx->ctx)[ctx->rate - 1] ^= 0x80;
    keccakf1600(ctx->ctx); ctx->pos = 0;
}
void shake128_squeezeblocks(uint8_t *out, size_t nblocks, shake128ctx *ctx) {
    ks_squeezeblocks(out, nblocks, ctx);
}
void shake128_ctx_release(shake128ctx *ctx) { (void)ctx; }
void shake128_ctx_clone(shake128ctx *dst, const shake128ctx *src) { *dst = *src; }

/* ── shake256 incremental context (used by Kyber's PRF/KDF) ─────────────── */
void shake256_inc_init(shake256incctx *ctx)    { ks_init(ctx, 136); }
void shake256_inc_absorb(shake256incctx *ctx, const uint8_t *in, size_t inlen) {
    ks_absorb(ctx, in, inlen);
}
void shake256_inc_finalize(shake256incctx *ctx) { ks_finalize(ctx, 0x1f); }
void shake256_inc_squeeze(uint8_t *out, size_t outlen, shake256incctx *ctx) {
    ks_squeeze(ctx, out, outlen);
}
void shake256_inc_ctx_clone(shake256incctx *dst, const shake256incctx *src) { *dst = *src; }
void shake256_inc_ctx_release(shake256incctx *ctx) { (void)ctx; }
