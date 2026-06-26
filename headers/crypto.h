#pragma once

#include "includes.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t buffer[64];
} sha256_ctx_t;

typedef struct {
    sha256_ctx_t inner;
    sha256_ctx_t outer;
    int initialized;
} hmac_sha256_ctx_t;

uint32_t crypto_md5_hash(uint8_t *data, uint32_t len);
void crypto_md5_hash_bin(uint8_t *data, uint32_t len, uint8_t *out);

void sha256_init(sha256_ctx_t *ctx);
void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len);
void sha256_final(sha256_ctx_t *ctx, uint8_t *hash);

void hmac_sha256_init(hmac_sha256_ctx_t *ctx, const uint8_t *key, size_t key_len);
void hmac_sha256_update(hmac_sha256_ctx_t *ctx, const uint8_t *data, size_t len);
void hmac_sha256_final(hmac_sha256_ctx_t *ctx, uint8_t *hash);
void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *mac);

/* HKDF-SHA256 */
void hkdf_sha256_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, uint8_t *prk);
void hkdf_sha256_expand(const uint8_t *prk, const uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len);
void tls12_prf(const uint8_t *secret, size_t secret_len, const char *label, const uint8_t *seed, size_t seed_len, uint8_t *out, size_t out_len);

/* SHA-384 structures and functions */
typedef struct {
    uint64_t state[8];
    uint64_t bitlen;
    uint8_t buffer[128];
} sha384_ctx_t;

typedef struct {
    sha384_ctx_t inner;
    sha384_ctx_t outer;
    int initialized;
} hmac_sha384_ctx_t;

void sha384_init(sha384_ctx_t *ctx);
void sha384_update(sha384_ctx_t *ctx, const uint8_t *data, size_t len);
void sha384_final(sha384_ctx_t *ctx, uint8_t *hash);

void hmac_sha384_init(hmac_sha384_ctx_t *ctx, const uint8_t *key, size_t key_len);
void hmac_sha384_update(hmac_sha384_ctx_t *ctx, const uint8_t *data, size_t len);
void hmac_sha384_final(hmac_sha384_ctx_t *ctx, uint8_t *hash);
void hmac_sha384(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *mac);

/* HKDF-SHA384 */
void hkdf_sha384_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, uint8_t *prk);
void hkdf_sha384_expand(const uint8_t *prk, const uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len);

/* X25519 */
void x25519(uint8_t *out, const uint8_t *scalar, const uint8_t *point);
void x25519_base(uint8_t *out, const uint8_t *scalar);

/* ChaCha20-Poly1305 */
void chacha20_poly1305_encrypt(const uint8_t *key, const uint8_t *nonce, const uint8_t *ad, size_t ad_len, const uint8_t *in, size_t in_len, uint8_t *out, uint8_t *tag);
int chacha20_poly1305_decrypt(const uint8_t *key, const uint8_t *nonce, const uint8_t *ad, size_t ad_len, const uint8_t *in, size_t in_len, uint8_t *out, const uint8_t *tag);

/* AES-128 */
void aes_128_ecb_encrypt(const uint8_t *key, const uint8_t *in, uint8_t *out);
void aes_128_gcm_encrypt(const uint8_t *key, const uint8_t *iv, const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len, uint8_t *out, uint8_t *tag);
int aes_128_gcm_decrypt(const uint8_t *key, const uint8_t *iv, const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len, uint8_t *out, const uint8_t *tag);

/* Key expansion (for pre-expanding schedules into nanotls_conn) */
void aes_128_key_expand(const uint8_t *key, uint32_t *w);
void aes_256_key_expand(const uint8_t *key, uint32_t *w);

/* Pre-expanded key schedule variants */
void aes_gcm_encrypt_ks(const uint32_t *w, int rounds, const uint8_t *iv, const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len, uint8_t *out, uint8_t *tag);
int  aes_gcm_decrypt_ks(const uint32_t *w, int rounds, const uint8_t *iv, const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len, uint8_t *out, const uint8_t *tag);

/* AES-256 */
void aes_256_ecb_encrypt(const uint8_t *key, const uint8_t *in, uint8_t *out);
void aes_256_gcm_encrypt(const uint8_t *key, const uint8_t *iv, const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len, uint8_t *out, uint8_t *tag);
int aes_256_gcm_decrypt(const uint8_t *key, const uint8_t *iv, const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len, uint8_t *out, const uint8_t *tag);

/* SHA-3 / ML-KEM-768 */
void mlkem768_keygen(uint8_t pk[1184], uint8_t sk[2400], const uint8_t coins[32]);
int mlkem768_decaps(uint8_t ss[32], const uint8_t ct[1088], const uint8_t sk[2400]);

#ifdef __cplusplus
}
#endif
