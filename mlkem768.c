/*
 * mlkem768.c — Standalone ML-KEM-768 (FIPS 203), single translation unit
 *
 * This file is a self-contained amalgamation of the PQClean ML-KEM-768
 * clean reference implementation (https://github.com/PQClean/PQClean,
 * MIT license). All PQClean source files are #include'd here so the
 * entire implementation compiles as one .c file. The pqclean_mlkem/
 * directory contains the vendored source; no network access is needed
 * at build time. No symbols from this file leak into the global namespace
 * — every fips202/SHA3 name is prefixed pqc_ via the #defines below.
 *
 * The only two externally-visible symbols are:
 *   void mlkem768_keygen(pk[1184], sk[2400], coins[32])
 *   int  mlkem768_decaps(ss[32],   ct[1088], sk[2400])
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Forward-declare our PRNG (defined in prng.c) */
int bot_prng_generate_block(unsigned char *output, unsigned int sz);

/* ── Rename fips202 externals so they never collide with anything ────────── */
#define shake128_absorb            pqc_shake128_absorb
#define shake128_squeezeblocks     pqc_shake128_squeezeblocks
#define shake128_ctx_release       pqc_shake128_ctx_release
#define shake128_ctx_clone         pqc_shake128_ctx_clone
#define shake128_inc_init          pqc_shake128_inc_init
#define shake128_inc_absorb        pqc_shake128_inc_absorb
#define shake128_inc_finalize      pqc_shake128_inc_finalize
#define shake128_inc_squeeze       pqc_shake128_inc_squeeze
#define shake128_inc_ctx_clone     pqc_shake128_inc_ctx_clone
#define shake128_inc_ctx_release   pqc_shake128_inc_ctx_release
#define shake128                   pqc_shake128
#define shake256_absorb            pqc_shake256_absorb
#define shake256_squeezeblocks     pqc_shake256_squeezeblocks
#define shake256_ctx_release       pqc_shake256_ctx_release
#define shake256_ctx_clone         pqc_shake256_ctx_clone
#define shake256_inc_init          pqc_shake256_inc_init
#define shake256_inc_absorb        pqc_shake256_inc_absorb
#define shake256_inc_finalize      pqc_shake256_inc_finalize
#define shake256_inc_squeeze       pqc_shake256_inc_squeeze
#define shake256_inc_ctx_clone     pqc_shake256_inc_ctx_clone
#define shake256_inc_ctx_release   pqc_shake256_inc_ctx_release
#define shake256                   pqc_shake256
#define sha3_256                   pqc_sha3_256
#define sha3_256_inc_init          pqc_sha3_256_inc_init
#define sha3_256_inc_absorb        pqc_sha3_256_inc_absorb
#define sha3_256_inc_finalize      pqc_sha3_256_inc_finalize
#define sha3_256_inc_ctx_clone     pqc_sha3_256_inc_ctx_clone
#define sha3_256_inc_ctx_release   pqc_sha3_256_inc_ctx_release
#define sha3_384                   pqc_sha3_384
#define sha3_384_inc_init          pqc_sha3_384_inc_init
#define sha3_384_inc_absorb        pqc_sha3_384_inc_absorb
#define sha3_384_inc_finalize      pqc_sha3_384_inc_finalize
#define sha3_384_inc_ctx_clone     pqc_sha3_384_inc_ctx_clone
#define sha3_384_inc_ctx_release   pqc_sha3_384_inc_ctx_release
#define sha3_512                   pqc_sha3_512
#define sha3_512_inc_init          pqc_sha3_512_inc_init
#define sha3_512_inc_absorb        pqc_sha3_512_inc_absorb
#define sha3_512_inc_finalize      pqc_sha3_512_inc_finalize
#define sha3_512_inc_ctx_clone     pqc_sha3_512_inc_ctx_clone
#define sha3_512_inc_ctx_release   pqc_sha3_512_inc_ctx_release

/* Rename the PQClean KEM API; only our two wrappers are exported */
#define PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand  pqc_mlkem768_keypair_derand
#define PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair         pqc_mlkem768_keypair
#define PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand      pqc_mlkem768_enc_derand
#define PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc             pqc_mlkem768_enc
#define PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec             pqc_mlkem768_dec

/* ── Inline all PQClean source files ─────────────────────────────────────── */
#include "keccak.c"
#include "pqclean_mlkem/reduce.c"
#include "pqclean_mlkem/ntt.c"
#include "pqclean_mlkem/cbd.c"
#include "pqclean_mlkem/poly.c"
#include "pqclean_mlkem/polyvec.c"
#include "pqclean_mlkem/verify.c"
#include "pqclean_mlkem/symmetric-shake.c"
#include "pqclean_mlkem/indcpa.c"
#include "pqclean_mlkem/kem.c"

/* ── Public API wrappers ─────────────────────────────────────────────────── */

void mlkem768_keygen(uint8_t pk[1184], uint8_t sk[2400], const uint8_t coins[32]) {
    /* keypair_derand takes 64 bytes: d (32) || z (32).
       We receive d=coins; generate z independently.    */
    uint8_t full_coins[64];
    memcpy(full_coins, coins, 32);
    bot_prng_generate_block(full_coins + 32, 32);
    pqc_mlkem768_keypair_derand(pk, sk, full_coins);
}

int mlkem768_decaps(uint8_t ss[32], const uint8_t ct[1088], const uint8_t sk[2400]) {
    return pqc_mlkem768_dec(ss, ct, sk);
}
