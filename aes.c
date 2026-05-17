#include "headers/includes.h"

/* 
 * AES-128 / AES-256 GCM / ECB IMPLEMENTATION
 * Freestanding, no dependencies.
 */

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

static void gcm_ghash(uint8_t *x, const uint8_t *h, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i += 16) {
        for (size_t j = 0; j < 16 && (i+j) < len; j++) x[j] ^= data[i+j];
        
        uint8_t z[16] = {0};
        uint8_t v[16]; memcpy(v, h, 16);
        
        for (int j = 0; j < 128; j++) {
            if ((x[j >> 3] >> (7 - (j & 7))) & 1) {
                for (int k = 0; k < 16; k++) z[k] ^= v[k];
            }
            
            uint8_t carry = v[15] & 1;
            for (int k = 15; k > 0; k--) {
                v[k] = (v[k] >> 1) | (v[k-1] << 7);
            }
            v[0] >>= 1;
            if (carry) v[0] ^= 0xe1;
        }
        memcpy(x, z, 16);
    }
}

void aes_gcm_encrypt(const uint32_t *w, int rounds, const uint8_t *iv, const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len, uint8_t *out, uint8_t *tag) {
    uint8_t h[16] = {0}, j0[16], ctr[16], x[16] = {0};
    aes_encrypt_block(w, rounds, h, h);
    memcpy(j0, iv, 12); j0[12]=0; j0[13]=0; j0[14]=0; j0[15]=1;
    memcpy(ctr, j0, 16);
    for (int i = 15; i >= 12; i--) if (++ctr[i]) break;

    for (size_t i = 0; i < len; i += 16) {
        uint8_t mask[16]; aes_encrypt_block(w, rounds, ctr, mask);
        for (size_t j = 0; j < 16 && (i+j) < len; j++) out[i+j] = in[i+j] ^ mask[j];
        for (int j = 15; j >= 12; j--) if (++ctr[j]) break;
    }

    if (aad_len > 0) gcm_ghash(x, h, aad, aad_len);
    gcm_ghash(x, h, out, len);
    uint8_t len_blk[16] = {0};
    uint64_t al = (uint64_t)aad_len * 8, il = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) { len_blk[7-i] = al >> (i*8); len_blk[15-i] = il >> (i*8); }
    gcm_ghash(x, h, len_blk, 16);
    
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
    aes_encrypt_block(w, rounds, h, h);
    memcpy(j0, iv, 12); j0[12]=0; j0[13]=0; j0[14]=0; j0[15]=1;
    
    if (aad_len > 0) gcm_ghash(x, h, aad, aad_len);
    gcm_ghash(x, h, in, len);
    uint8_t len_blk[16] = {0};
    uint64_t al = (uint64_t)aad_len * 8, il = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) { len_blk[7-i] = al >> (i*8); len_blk[15-i] = il >> (i*8); }
    gcm_ghash(x, h, len_blk, 16);
    
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
