#include "headers/chacha20.h"
#include "headers/includes.h"

#if defined(__x86_64__) || defined(__i386__)
#include <emmintrin.h>
#define CHACHA_SSE2 1

#define ROL32V(x,n) _mm_or_si128(_mm_slli_epi32(x,(n)), _mm_srli_epi32(x,32-(n)))
#define QR(v,a,b,c,d) \
    v[a]=_mm_add_epi32(v[a],v[b]); v[d]=_mm_xor_si128(v[d],v[a]); v[d]=ROL32V(v[d],16); \
    v[c]=_mm_add_epi32(v[c],v[d]); v[b]=_mm_xor_si128(v[b],v[c]); v[b]=ROL32V(v[b],12); \
    v[a]=_mm_add_epi32(v[a],v[b]); v[d]=_mm_xor_si128(v[d],v[a]); v[d]=ROL32V(v[d],8);  \
    v[c]=_mm_add_epi32(v[c],v[d]); v[b]=_mm_xor_si128(v[b],v[c]); v[b]=ROL32V(v[b],7);

/* Produce 4 ChaCha20 keystream blocks (256 bytes) for counters c..c+3. */
__attribute__((target("sse2")))
static void chacha20_4block(const uint32_t s[16], uint8_t out[256]) {
    __m128i v[16], o[16];
    for (int i = 0; i < 16; i++) v[i] = _mm_set1_epi32((int)s[i]);
    v[12] = _mm_add_epi32(v[12], _mm_set_epi32(3, 2, 1, 0));   /* counters c..c+3 */
    for (int i = 0; i < 16; i++) o[i] = v[i];
    for (int r = 0; r < 10; r++) {
        QR(v,0,4,8,12); QR(v,1,5,9,13); QR(v,2,6,10,14); QR(v,3,7,11,15);
        QR(v,0,5,10,15); QR(v,1,6,11,12); QR(v,2,7,8,13); QR(v,3,4,9,14);
    }
    for (int i = 0; i < 16; i++) v[i] = _mm_add_epi32(v[i], o[i]);
    uint32_t t[16][4];
    for (int i = 0; i < 16; i++) _mm_storeu_si128((__m128i*)t[i], v[i]);
    for (int b = 0; b < 4; b++)
        for (int i = 0; i < 16; i++) {
            uint32_t w = t[i][b];   /* lane b of word i = block b's word i */
            out[b*64+i*4+0]=(uint8_t)w;      out[b*64+i*4+1]=(uint8_t)(w>>8);
            out[b*64+i*4+2]=(uint8_t)(w>>16);out[b*64+i*4+3]=(uint8_t)(w>>24);
        }
}
#undef QR
#undef ROL32V
#endif

static inline void u32t8le(uint32_t v, uint8_t *p) {
    p[0] = v & 0xff;
    p[1] = (v >> 8) & 0xff;
    p[2] = (v >> 16) & 0xff;
    p[3] = (v >> 24) & 0xff;
}

static inline uint32_t u8t32le(uint8_t *p) {
    uint32_t value = p[3];

    value = (value << 8) | p[2];
    value = (value << 8) | p[1];
    value = (value << 8) | p[0];

    return value;
}

static inline uint32_t rotl32(uint32_t x, int n) {
    // http://blog.regehr.org/archives/1063
    return x << n | (x >> (-n & 31));
}

// https://tools.ietf.org/html/rfc7539#section-2.1
static void chacha20_quarterround(uint32_t *x, int a, int b, int c, int d) {
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 16);
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 12);
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a],  8);
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c],  7);
}

static void chacha20_serialize(uint32_t *in, uint8_t *output) {
    int i;
    for (i = 0; i < 16; i++) {
        u32t8le(in[i], output + (i << 2));
    }
}

static void chacha20_block(uint32_t *in, uint8_t *out, int num_rounds) {
    int i;
    uint32_t x[16];

    memcpy(x, in, sizeof(uint32_t) * 16);

    for (i = num_rounds; i > 0; i -= 2) {
        chacha20_quarterround(x, 0, 4,  8, 12);
        chacha20_quarterround(x, 1, 5,  9, 13);
        chacha20_quarterround(x, 2, 6, 10, 14);
        chacha20_quarterround(x, 3, 7, 11, 15);
        chacha20_quarterround(x, 0, 5, 10, 15);
        chacha20_quarterround(x, 1, 6, 11, 12);
        chacha20_quarterround(x, 2, 7,  8, 13);
        chacha20_quarterround(x, 3, 4,  9, 14);
    }

    for (i = 0; i < 16; i++) {
        x[i] += in[i];
    }

    chacha20_serialize(x, out);
}

// https://tools.ietf.org/html/rfc7539#section-2.3
static void chacha20_init_state(uint32_t *s, uint8_t *key, uint32_t counter, uint8_t *nonce) {
    int i;

    // refer: https://dxr.mozilla.org/mozilla-beta/source/security/nss/lib/freebl/chacha20.c
    // convert magic number to string: "expand 32-byte k"
    s[0] = 0x61707865;
    s[1] = 0x3320646e;
    s[2] = 0x79622d32;
    s[3] = 0x6b206574;

    for (i = 0; i < 8; i++) {
        s[4 + i] = u8t32le(key + i * 4);
    }

    s[12] = counter;

    for (i = 0; i < 3; i++) {
        s[13 + i] = u8t32le(nonce + i * 4);
    }
}

void chacha20_xor(uint8_t *key, uint32_t counter, uint8_t *nonce, char *in, char *out, int inlen) {
    int i, j;

    uint32_t s[16];
    uint8_t block[64];

    chacha20_init_state(s, key, counter, nonce);

    i = 0;
#ifdef CHACHA_SSE2
    /* 4-way SIMD: 256 bytes per iteration */
    uint8_t ks[256];
    for (; i + 256 <= inlen; i += 256) {
        chacha20_4block(s, ks);
        s[12] += 4;
        for (int k = 0; k < 256; k++) out[i + k] = in[i + k] ^ ks[k];
    }
#endif
    for (; i < inlen; i += 64) {
        chacha20_block(s, block, 20);
        s[12]++;
        for (j = i; j < i + 64; j++) {
            if (j >= inlen) break;
            out[j] = in[j] ^ block[j - i];
        }
    }
}