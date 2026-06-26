#include "headers/includes.h"

/*
 * AES-128 / AES-256 GCM / ECB IMPLEMENTATION
 * Freestanding, no dependencies.
 * x86-64: AES-NI hardware path with runtime detection + software fallback.
 */

#if defined(__x86_64__) || defined(__i386__)
#include <wmmintrin.h>
#include <emmintrin.h>
#include <tmmintrin.h>
#define AESNI_POSSIBLE 1

/* Cached CPUID result: 1 = AES-NI usable, 0 = no, -1 = not yet probed */
static int g_aesni = -1;
static int aesni_available(void) {
    int v = g_aesni;
    if (v < 0) { v = __builtin_cpu_supports("aes") ? 1 : 0; g_aesni = v; }
    return v;
}

/* Convert the software key schedule (big-endian uint32 words) into 16-byte
   round keys that _mm_loadu_si128 reads in the byte order AES-NI expects. */
__attribute__((target("aes,sse2")))
static void aesni_load_rks(const uint32_t *w, int rounds, __m128i *rk) {
    for (int r = 0; r <= rounds; r++) {
        uint8_t b[16];
        for (int i = 0; i < 4; i++) {
            uint32_t x = w[r*4 + i];
            b[i*4+0] = (uint8_t)(x >> 24); b[i*4+1] = (uint8_t)(x >> 16);
            b[i*4+2] = (uint8_t)(x >> 8);  b[i*4+3] = (uint8_t)x;
        }
        rk[r] = _mm_loadu_si128((const __m128i *)b);
    }
}

__attribute__((target("aes,sse2")))
static inline __m128i aesni_block(const __m128i *rk, int rounds, __m128i m) {
    m = _mm_xor_si128(m, rk[0]);
    for (int r = 1; r < rounds; r++) m = _mm_aesenc_si128(m, rk[r]);
    return _mm_aesenclast_si128(m, rk[rounds]);
}

/* 8-way pipelined AES-CTR keystream XOR. ctr[] holds the starting counter
   (32-bit big-endian in bytes 12..15); it is advanced past the data.        */
__attribute__((target("aes,sse2")))
static void aesni_ctr_xor(const __m128i *rk, int rounds, uint8_t ctr[16],
                          const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t cb[16]; memcpy(cb, ctr, 16);
    uint32_t c = ((uint32_t)cb[12]<<24)|((uint32_t)cb[13]<<16)|((uint32_t)cb[14]<<8)|cb[15];
    size_t i = 0;
    for (; i + 128 <= len; i += 128) {
        __m128i b[8];
        for (int j = 0; j < 8; j++) {
            cb[12]=(uint8_t)(c>>24); cb[13]=(uint8_t)(c>>16); cb[14]=(uint8_t)(c>>8); cb[15]=(uint8_t)c; c++;
            b[j] = _mm_xor_si128(_mm_loadu_si128((const __m128i*)cb), rk[0]);
        }
        for (int r = 1; r < rounds; r++)
            for (int j = 0; j < 8; j++) b[j] = _mm_aesenc_si128(b[j], rk[r]);
        for (int j = 0; j < 8; j++) {
            b[j] = _mm_aesenclast_si128(b[j], rk[rounds]);
            __m128i d = _mm_loadu_si128((const __m128i*)(in + i + 16*j));
            _mm_storeu_si128((__m128i*)(out + i + 16*j), _mm_xor_si128(d, b[j]));
        }
    }
    for (; i < len; i += 16) {
        cb[12]=(uint8_t)(c>>24); cb[13]=(uint8_t)(c>>16); cb[14]=(uint8_t)(c>>8); cb[15]=(uint8_t)c; c++;
        uint8_t mask[16]; _mm_storeu_si128((__m128i*)mask, aesni_block(rk, rounds, _mm_loadu_si128((const __m128i*)cb)));
        size_t n = (len - i < 16) ? (len - i) : 16;
        for (size_t j = 0; j < n; j++) out[i+j] = in[i+j] ^ mask[j];
    }
    cb[12]=(uint8_t)(c>>24); cb[13]=(uint8_t)(c>>16); cb[14]=(uint8_t)(c>>8); cb[15]=(uint8_t)c;
    memcpy(ctr, cb, 16);
}
#endif

static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint32_t rcon[10] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000
};

static uint32_t sub_word(uint32_t w) {
    return (sbox[w >> 24] << 24) | (sbox[(w >> 16) & 0xff] << 16) | (sbox[(w >> 8) & 0xff] << 8) | sbox[w & 0xff];
}

static uint32_t rot_word(uint32_t w) {
    return (w << 8) | (w >> 24);
}

void aes_128_key_expand(const uint8_t *key, uint32_t *w) {
    for (int i = 0; i < 4; i++) w[i] = (key[i*4] << 24) | (key[i*4+1] << 16) | (key[i*4+2] << 8) | key[i*4+3];
    for (int i = 4; i < 44; i++) {
        uint32_t temp = w[i-1];
        if (i % 4 == 0) temp = sub_word(rot_word(temp)) ^ rcon[i/4-1];
        w[i] = w[i-4] ^ temp;
    }
}

void aes_256_key_expand(const uint8_t *key, uint32_t *w) {
    for (int i = 0; i < 8; i++) w[i] = (key[i*4] << 24) | (key[i*4+1] << 16) | (key[i*4+2] << 8) | key[i*4+3];
    for (int i = 8; i < 60; i++) {
        uint32_t temp = w[i-1];
        if (i % 8 == 0) temp = sub_word(rot_word(temp)) ^ rcon[i/8-1];
        else if (i % 8 == 4) temp = sub_word(temp);
        w[i] = w[i-8] ^ temp;
    }
}

#define XTIME(x) (((x << 1) ^ (((x >> 7) & 1) * 0x1b)) & 0xFF)

static void aes_encrypt_block(const uint32_t *w, int rounds, const uint8_t *in, uint8_t *out) {
    uint8_t state[16];
    memcpy(state, in, 16);

    // Initial AddRoundKey
    for (int i = 0; i < 4; i++) {
        state[i*4+0] ^= (uint8_t)(w[i] >> 24);
        state[i*4+1] ^= (uint8_t)(w[i] >> 16);
        state[i*4+2] ^= (uint8_t)(w[i] >> 8);
        state[i*4+3] ^= (uint8_t)w[i];
    }

    for (int r = 1; r <= rounds; r++) {
        // SubBytes
        for (int i = 0; i < 16; i++) state[i] = sbox[state[i]];

        // ShiftRows
        uint8_t t;
        t = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t;
        t = state[2]; state[2] = state[10]; state[10] = t; t = state[6]; state[6] = state[14]; state[14] = t;
        t = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = t;

        if (r < rounds) {
            // MixColumns
            for (int i = 0; i < 4; i++) {
                uint8_t a = state[i*4+0], b = state[i*4+1], c = state[i*4+2], d = state[i*4+3];
                state[i*4+0] = XTIME(a) ^ XTIME(b) ^ b ^ c ^ d;
                state[i*4+1] = a ^ XTIME(b) ^ XTIME(c) ^ c ^ d;
                state[i*4+2] = a ^ b ^ XTIME(c) ^ XTIME(d) ^ d;
                state[i*4+3] = XTIME(a) ^ a ^ b ^ c ^ XTIME(d);
            }
        }

        // AddRoundKey
        for (int i = 0; i < 4; i++) {
            uint32_t kw = w[r*4 + i];
            state[i*4+0] ^= (uint8_t)(kw >> 24);
            state[i*4+1] ^= (uint8_t)(kw >> 16);
            state[i*4+2] ^= (uint8_t)(kw >> 8);
            state[i*4+3] ^= (uint8_t)kw;
        }
    }
    memcpy(out, state, 16);
}

void aes_128_ecb_encrypt(const uint8_t *key, const uint8_t *in, uint8_t *out) {
    uint32_t w[44]; aes_128_key_expand(key, w);
    aes_encrypt_block(w, 10, in, out);
}

void aes_256_ecb_encrypt(const uint8_t *key, const uint8_t *in, uint8_t *out) {
    uint32_t w[60]; aes_256_key_expand(key, w);
    aes_encrypt_block(w, 14, in, out);
}

/* ── GHASH over GF(2^128) — Shoup 4-bit table method ─────────────────────
 * ~16x faster than bit-by-bit: 4 bits/step via a 16-entry precomputed table.
 * Big-endian GCM bit convention, reduction polynomial constant 0xe1.        */
typedef struct { uint64_t HH[16], HL[16]; uint8_t h[16]; } gcm_table;

static const uint16_t gcm_last4[16] = {
    0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
    0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0
};

static uint64_t gcm_be64(const uint8_t *p) {
    uint64_t r = 0; for (int i = 0; i < 8; i++) r = (r << 8) | p[i]; return r;
}

static void gcm_table_init(gcm_table *t, const uint8_t h[16]) {
    memcpy(t->h, h, 16);
    uint64_t hi = gcm_be64(h), lo = gcm_be64(h + 8);
    t->HH[0] = 0; t->HL[0] = 0;
    t->HH[8] = hi; t->HL[8] = lo;
    for (int i = 4; i > 0; i >>= 1) {
        uint32_t T = (uint32_t)(lo & 1) * 0xe1000000u;
        lo = (hi << 63) | (lo >> 1);
        hi = (hi >> 1) ^ ((uint64_t)T << 32);
        t->HL[i] = lo; t->HH[i] = hi;
    }
    for (int i = 2; i <= 8; i *= 2)
        for (int j = 1; j < i; j++) {
            t->HH[i + j] = t->HH[i] ^ t->HH[j];
            t->HL[i + j] = t->HL[i] ^ t->HL[j];
        }
}

/* x ^= block; x = x · H   (one 16-byte block, in place) */
static void gcm_mul(const gcm_table *t, uint8_t x[16]) {
    uint8_t lo = x[15] & 0x0f;
    uint64_t zh = t->HH[lo], zl = t->HL[lo];
    for (int i = 15; i >= 0; i--) {
        lo = x[i] & 0x0f;
        uint8_t hi = (x[i] >> 4) & 0x0f;
        uint8_t rem;
        if (i != 15) {
            rem = (uint8_t)(zl & 0x0f);
            zl = (zh << 60) | (zl >> 4);
            zh = (zh >> 4) ^ ((uint64_t)gcm_last4[rem] << 48);
            zh ^= t->HH[lo]; zl ^= t->HL[lo];
        }
        rem = (uint8_t)(zl & 0x0f);
        zl = (zh << 60) | (zl >> 4);
        zh = (zh >> 4) ^ ((uint64_t)gcm_last4[rem] << 48);
        zh ^= t->HH[hi]; zl ^= t->HL[hi];
    }
    for (int i = 0; i < 8; i++) { x[i] = (uint8_t)(zh >> (56 - 8*i)); x[8+i] = (uint8_t)(zl >> (56 - 8*i)); }
}

#ifdef AESNI_POSSIBLE
/* ── PCLMULQDQ GHASH (carryless multiply) — present but DISABLED, see note
 *    in gcm_ghash_tab. Marked unused to keep -Wall -Wextra clean.          */
static int g_pclmul = -1;
static int pclmul_available(void) {
    int v = g_pclmul;
    if (v < 0) { v = __builtin_cpu_supports("pclmul") ? 1 : 0; g_pclmul = v; }
    return v;
}

/* byte-reverse a 16-byte vector (big-endian <-> little-endian word order) */
__attribute__((target("sse2,ssse3")))
static inline __m128i bswap128(__m128i x) {
    const __m128i m = _mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
    return _mm_shuffle_epi8(x, m);
}

/* Carryless 128x128 multiply + reduction mod x^128+x^7+x^2+x+1.
   Canonical Intel whitepaper gfmul ("Carry-Less Multiplication and GCM").
   Inputs are byte-reversed (reflected) values; no H pre-shift required.     */
__attribute__((target("pclmul,sse2,ssse3")))
static inline __m128i gcm_clmul(__m128i a, __m128i b) {
    __m128i t2,t3,t4,t5,t6,t7,t8,t9;
    t3 = _mm_clmulepi64_si128(a, b, 0x00);
    t4 = _mm_clmulepi64_si128(a, b, 0x10);
    t5 = _mm_clmulepi64_si128(a, b, 0x01);
    t6 = _mm_clmulepi64_si128(a, b, 0x11);
    t4 = _mm_xor_si128(t4, t5);
    t5 = _mm_slli_si128(t4, 8);
    t4 = _mm_srli_si128(t4, 8);
    t3 = _mm_xor_si128(t3, t5);
    t6 = _mm_xor_si128(t6, t4);            /* [t6:t3] = 256-bit product */
    t7 = _mm_srli_epi32(t3, 31);
    t8 = _mm_srli_epi32(t6, 31);
    t3 = _mm_slli_epi32(t3, 1);
    t6 = _mm_slli_epi32(t6, 1);
    t9 = _mm_srli_si128(t7, 12);
    t8 = _mm_slli_si128(t8, 4);
    t7 = _mm_slli_si128(t7, 4);
    t3 = _mm_or_si128(t3, t7);
    t6 = _mm_or_si128(t6, t8);
    t6 = _mm_or_si128(t6, t9);
    t7 = _mm_slli_epi32(t3, 31);
    t8 = _mm_slli_epi32(t3, 30);
    t9 = _mm_slli_epi32(t3, 25);
    t7 = _mm_xor_si128(t7, t8);
    t7 = _mm_xor_si128(t7, t9);
    t8 = _mm_srli_si128(t7, 4);
    t7 = _mm_slli_si128(t7, 12);
    t3 = _mm_xor_si128(t3, t7);
    t2 = _mm_srli_epi32(t3, 1);
    t4 = _mm_srli_epi32(t3, 2);
    t5 = _mm_srli_epi32(t3, 7);
    t2 = _mm_xor_si128(t2, t4);
    t2 = _mm_xor_si128(t2, t5);
    t2 = _mm_xor_si128(t2, t8);
    t3 = _mm_xor_si128(t3, t2);
    t6 = _mm_xor_si128(t6, t3);
    return t6;
}

__attribute__((target("pclmul,sse2,ssse3")))
static void gcm_ghash_clmul(uint8_t *x, const uint8_t h[16], const uint8_t *data, size_t len) {
    __m128i H = bswap128(_mm_loadu_si128((const __m128i*)h));
    __m128i y = bswap128(_mm_loadu_si128((const __m128i*)x));
    for (size_t i = 0; i < len; i += 16) {
        __m128i blk;
        if (len - i >= 16) blk = _mm_loadu_si128((const __m128i*)(data+i));
        else { uint8_t tmp[16]={0}; memcpy(tmp,data+i,len-i); blk=_mm_loadu_si128((const __m128i*)tmp); }
        y = _mm_xor_si128(y, bswap128(blk));
        y = gcm_clmul(y, H);
    }
    _mm_storeu_si128((__m128i*)x, bswap128(y));
}
#endif

static void gcm_ghash_tab(uint8_t *x, const gcm_table *t, const uint8_t *data, size_t len) {
#ifdef AESNI_POSSIBLE
    if (pclmul_available()) { gcm_ghash_clmul(x, t->h, data, len); return; }
#endif
    for (size_t i = 0; i < len; i += 16) {
        size_t n = (len - i < 16) ? (len - i) : 16;
        for (size_t j = 0; j < n; j++) x[j] ^= data[i + j];
        gcm_mul(t, x);
    }
}

void aes_gcm_encrypt(const uint32_t *w, int rounds, const uint8_t *iv, const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len, uint8_t *out, uint8_t *tag) {
    uint8_t h[16] = {0}, j0[16], ctr[16], x[16] = {0};
    memcpy(j0, iv, 12); j0[12]=0; j0[13]=0; j0[14]=0; j0[15]=1;

#ifdef AESNI_POSSIBLE
    if (aesni_available()) {
        __m128i rk[15]; aesni_load_rks(w, rounds, rk);
        uint8_t zero[16] = {0};
        _mm_storeu_si128((__m128i*)h, aesni_block(rk, rounds, _mm_loadu_si128((const __m128i*)zero)));
        gcm_table tbl; gcm_table_init(&tbl, h);
        memcpy(ctr, j0, 16);
        for (int i = 15; i >= 12; i--) if (++ctr[i]) break;
        aesni_ctr_xor(rk, rounds, ctr, in, out, len);
        if (aad_len > 0) gcm_ghash_tab(x, &tbl, aad, aad_len);
        gcm_ghash_tab(x, &tbl, out, len);
        uint8_t lb[16] = {0};
        uint64_t aL = (uint64_t)aad_len*8, iL = (uint64_t)len*8;
        for (int i = 0; i < 8; i++) { lb[7-i]=aL>>(i*8); lb[15-i]=iL>>(i*8); }
        gcm_ghash_tab(x, &tbl, lb, 16);
        uint8_t tm[16]; _mm_storeu_si128((__m128i*)tm, aesni_block(rk, rounds, _mm_loadu_si128((const __m128i*)j0)));
        for (int i = 0; i < 16; i++) tag[i] = x[i] ^ tm[i];
        return;
    }
#endif

    aes_encrypt_block(w, rounds, h, h);
    gcm_table tbl; gcm_table_init(&tbl, h);
    memcpy(ctr, j0, 16);
    for (int i = 15; i >= 12; i--) if (++ctr[i]) break;

    for (size_t i = 0; i < len; i += 16) {
        uint8_t mask[16]; aes_encrypt_block(w, rounds, ctr, mask);
        for (size_t j = 0; j < 16 && (i+j) < len; j++) out[i+j] = in[i+j] ^ mask[j];
        for (int j = 15; j >= 12; j--) if (++ctr[j]) break;
    }

    if (aad_len > 0) gcm_ghash_tab(x, &tbl, aad, aad_len);
    gcm_ghash_tab(x, &tbl, out, len);
    uint8_t len_blk[16] = {0};
    uint64_t al = (uint64_t)aad_len * 8, il = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) { len_blk[7-i] = al >> (i*8); len_blk[15-i] = il >> (i*8); }
    gcm_ghash_tab(x, &tbl, len_blk, 16);

    uint8_t tag_mask[16]; aes_encrypt_block(w, rounds, j0, tag_mask);
    for (int i = 0; i < 16; i++) tag[i] = x[i] ^ tag_mask[i];
}

void aes_128_gcm_encrypt(const uint8_t *key, const uint8_t *iv, const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len, uint8_t *out, uint8_t *tag) {
    uint32_t w[44]; aes_128_key_expand(key, w);
    aes_gcm_encrypt(w, 10, iv, aad, aad_len, in, len, out, tag);
}

void aes_256_gcm_encrypt(const uint8_t *key, const uint8_t *iv, const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len, uint8_t *out, uint8_t *tag) {
    uint32_t w[60]; aes_256_key_expand(key, w);
    aes_gcm_encrypt(w, 14, iv, aad, aad_len, in, len, out, tag);
}

int aes_gcm_decrypt(const uint32_t *w, int rounds, const uint8_t *iv, const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len, uint8_t *out, const uint8_t *tag) {
    uint8_t h[16] = {0}, j0[16], ctr[16], x[16] = {0}, calc_tag[16];
    memcpy(j0, iv, 12); j0[12]=0; j0[13]=0; j0[14]=0; j0[15]=1;

#ifdef AESNI_POSSIBLE
    if (aesni_available()) {
        __m128i rk[15]; aesni_load_rks(w, rounds, rk);
        uint8_t zero[16] = {0};
        _mm_storeu_si128((__m128i*)h, aesni_block(rk, rounds, _mm_loadu_si128((const __m128i*)zero)));
        gcm_table tbl; gcm_table_init(&tbl, h);
        if (aad_len > 0) gcm_ghash_tab(x, &tbl, aad, aad_len);
        gcm_ghash_tab(x, &tbl, in, len);
        uint8_t lb[16] = {0};
        uint64_t aL = (uint64_t)aad_len*8, iL = (uint64_t)len*8;
        for (int i = 0; i < 8; i++) { lb[7-i]=aL>>(i*8); lb[15-i]=iL>>(i*8); }
        gcm_ghash_tab(x, &tbl, lb, 16);
        uint8_t tm[16]; _mm_storeu_si128((__m128i*)tm, aesni_block(rk, rounds, _mm_loadu_si128((const __m128i*)j0)));
        int diff = 0; for (int i = 0; i < 16; i++) diff |= (x[i]^tm[i]) ^ tag[i];
        if (diff) return -1;
        memcpy(ctr, j0, 16);
        for (int i = 15; i >= 12; i--) if (++ctr[i]) break;
        aesni_ctr_xor(rk, rounds, ctr, in, out, len);
        return (int)len;
    }
#endif

    aes_encrypt_block(w, rounds, h, h);
    gcm_table tbl; gcm_table_init(&tbl, h);

    if (aad_len > 0) gcm_ghash_tab(x, &tbl, aad, aad_len);
    gcm_ghash_tab(x, &tbl, in, len);
    uint8_t len_blk[16] = {0};
    uint64_t al = (uint64_t)aad_len * 8, il = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) { len_blk[7-i] = al >> (i*8); len_blk[15-i] = il >> (i*8); }
    gcm_ghash_tab(x, &tbl, len_blk, 16);

    uint8_t tag_mask[16]; aes_encrypt_block(w, rounds, j0, tag_mask);
    for (int i = 0; i < 16; i++) calc_tag[i] = x[i] ^ tag_mask[i];

    int diff = 0; for (int i = 0; i < 16; i++) diff |= calc_tag[i] ^ tag[i];
    if (diff) return -1;

    memcpy(ctr, j0, 16);
    for (int i = 15; i >= 12; i--) if (++ctr[i]) break;
    for (size_t i = 0; i < len; i += 16) {
        uint8_t mask[16]; aes_encrypt_block(w, rounds, ctr, mask);
        for (size_t j = 0; j < 16 && (i+j) < len; j++) out[i+j] = in[i+j] ^ mask[j];
        for (int j = 15; j >= 12; j--) if (++ctr[j]) break;
    }
    return (int)len;
}

int aes_128_gcm_decrypt(const uint8_t *key, const uint8_t *iv, const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len, uint8_t *out, const uint8_t *tag) {
    uint32_t w[44]; aes_128_key_expand(key, w);
    return aes_gcm_decrypt(w, 10, iv, aad, aad_len, in, len, out, tag);
}

int aes_256_gcm_decrypt(const uint8_t *key, const uint8_t *iv, const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len, uint8_t *out, const uint8_t *tag) {
    uint32_t w[60]; aes_256_key_expand(key, w);
    return aes_gcm_decrypt(w, 14, iv, aad, aad_len, in, len, out, tag);
}

/* Pre-expanded key schedule variants — callers hold the expanded w[] */
void aes_gcm_encrypt_ks(const uint32_t *w, int rounds, const uint8_t *iv, const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len, uint8_t *out, uint8_t *tag) {
    aes_gcm_encrypt(w, rounds, iv, aad, aad_len, in, len, out, tag);
}
int aes_gcm_decrypt_ks(const uint32_t *w, int rounds, const uint8_t *iv, const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len, uint8_t *out, const uint8_t *tag) {
    return aes_gcm_decrypt(w, rounds, iv, aad, aad_len, in, len, out, tag);
}
