/*
 * Copyright (c) 2026 Andrey Kuvshinov
 *
 * Dual-licensed under Apache-2.0 OR MIT.
 * See LICENSE-APACHE and LICENSE-MIT for details.
 */

#ifndef AREION_PQ_H
#define AREION_PQ_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if !defined(AREION_API)
#if defined(_WIN32) || defined(__CYGWIN__)
#define AREION_API
#elif (defined(__GNUC__) && __GNUC__ >= 4) || defined(__clang__)
#define AREION_API __attribute__((visibility("hidden")))
#else
#define AREION_API
#endif
#endif

#if defined(__has_include)
#if __has_include("areion.h")
#include "areion.h"
#else
#include "../areion-c/areion.h"
#endif
#else
#include "../areion-c/areion.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__clang__) && !defined(__cplusplus) && (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"
#endif

#if !defined(AREION_PQ_API)
#if defined(_WIN32) || defined(__CYGWIN__)
#if defined(AREION_PQ_SHARED_EXPORTS)
#define AREION_PQ_API __declspec(dllexport)
#else
#define AREION_PQ_API
#endif
#elif (defined(__GNUC__) && __GNUC__ >= 4) || defined(__clang__)
#define AREION_PQ_API __attribute__((visibility("default")))
#else
#define AREION_PQ_API
#endif
#endif

/* =========================================================================
 * 1. Version & Size Constants
 * ========================================================================= */

#define AREION_PQ_VERSION                       "0.2.0"
#define AREION_PQ_VERSION_STRING                "0.2.0"
#define AREION_PQ_VERSION_MAJOR                 0
#define AREION_PQ_VERSION_MINOR                 2
#define AREION_PQ_VERSION_PATCH                 0

/* Finite-field & witness sizes */
#define AREION_PQ_BLOCK_SIZE                    16
#define AREION_PQ_STATE256_SIZE                 32
#define AREION_PQ_STATE512_SIZE                 64
#define AREION_PQ_WITNESS256_SIZE               288
#define AREION_PQ_WITNESS_EM2_256_SIZE          576
#define AREION_PQ_WITNESSEM2_256_SIZE           576

/* Track 1: FAEST-Areion (VOLE-in-the-Head zero-knowledge signatures) */
#define AREION_PQ_FAEST128_SEED_SIZE            32
#define AREION_PQ_FAEST128_PUBLIC_KEY_SIZE      48
#define AREION_PQ_FAEST128_PK_SIZE              48
#define AREION_PQ_FAEST128_SECRET_KEY_SIZE      64
#define AREION_PQ_FAEST128_SK_SIZE              64
#define AREION_PQ_FAEST128S_SIG_SIZE            6448
#define AREION_PQ_FAEST128F_SIG_SIZE            7456

#define AREION_PQ_FAEST256_SEED_SIZE            64
#define AREION_PQ_FAEST256_PUBLIC_KEY_SIZE      64
#define AREION_PQ_FAEST256_PK_SIZE              64
#define AREION_PQ_FAEST256_SECRET_KEY_SIZE      96
#define AREION_PQ_FAEST256_SK_SIZE              96
#define AREION_PQ_FAEST256S_SIG_SIZE            18208
#define AREION_PQ_FAEST256F_SIG_SIZE            20512

#define AREION_PQ_FAEST_EM2_256_SEED_SIZE       64
#define AREION_PQ_FAESTEM2256_SEED_SIZE         64
#define AREION_PQ_FAEST_EM2_256_PUBLIC_KEY_SIZE 64
#define AREION_PQ_FAESTEM2256_PUBLIC_KEY_SIZE   64
#define AREION_PQ_FAEST_EM2_256_PK_SIZE         64
#define AREION_PQ_FAEST_EM2_256_SECRET_KEY_SIZE 96
#define AREION_PQ_FAESTEM2256_SECRET_KEY_SIZE   96
#define AREION_PQ_FAEST_EM2_256_SK_SIZE         96
#define AREION_PQ_FAEST_EM2_256S_SIG_SIZE       25696
#define AREION_PQ_FAESTEM2256S_SIG_SIZE         25696
#define AREION_PQ_FAEST_EM2_256F_SIG_SIZE       30368
#define AREION_PQ_FAESTEM2256F_SIG_SIZE         30368

/* Track 2: SLH-DSA-Areion (NIST FIPS 205 stateless hash-based signatures) */
#define AREION_PQ_SLHDSA128_SEED_SIZE           48
#define AREION_PQ_SLHDSA128_PUBLIC_KEY_SIZE     32
#define AREION_PQ_SLHDSA128_PK_SIZE             32
#define AREION_PQ_SLHDSA128_SECRET_KEY_SIZE     64
#define AREION_PQ_SLHDSA128_SK_SIZE             64
#define AREION_PQ_SLHDSA128F_SIG_SIZE           17088
#define AREION_PQ_SLHDSA128S_SIG_SIZE           7856

#define AREION_PQ_SLHDSA256_SEED_SIZE           96
#define AREION_PQ_SLHDSA256_PUBLIC_KEY_SIZE     64
#define AREION_PQ_SLHDSA256_PK_SIZE             64
#define AREION_PQ_SLHDSA256_SECRET_KEY_SIZE     128
#define AREION_PQ_SLHDSA256_SK_SIZE             128
#define AREION_PQ_SLHDSA256F_SIG_SIZE           49856
#define AREION_PQ_SLHDSA256S_SIG_SIZE           29792
#define AREION_PQ_SLHDSA_TEM256F_SIG_SIZE       49856

/* Track 3: Areion-HPKE & Areion-TEM2-SIV Wide-Block AEAD */
#define AREION_PQ_TEM2_SIV_KEY_SIZE             128
#define AREION_PQ_TEM2SIV_KEY_SIZE              128
#define AREION_PQ_TEM2_SIV_NONCE_SIZE           32
#define AREION_PQ_TEM2SIV_NONCE_SIZE            32
#define AREION_PQ_TEM2_SIV_TAG_SIZE             32
#define AREION_PQ_TEM2SIV_TAG_SIZE              32
#define AREION_PQ_HPKE_SHARED_SIZE              32
#define AREION_PQ_HPKE_KEY_SEED_SIZE            64

/* =========================================================================
 * 2. CPU Dispatch, Tier Control, SelfTest & Zeroize
 * ========================================================================= */

typedef enum {
    AREION_PQ_TIER_AUTO     = 0,
    AREION_PQ_TIER_PUREC    = 1,
    AREION_PQ_TIER_AESNI    = 2,
    AREION_PQ_TIER_VEX      = 3,
    AREION_PQ_TIER_VAESAVX2 = 4,
    AREION_PQ_TIER_AVX512   = 5,
    AREION_PQ_TIER_ARM64    = 6
} areion_pq_tier_t;

/* Returns the name of the active dispatch tier ("avx512", "vaesavx2",
 * "vex", "aesni", "arm64", or "purec"). */
AREION_PQ_API const char *areion_pq_tier(void);

/* Returns the active dispatch tier enum value. */
AREION_PQ_API areion_pq_tier_t areion_pq_tier_code(void);

/* Populates out[0..count-1] with the names of all tiers supported on the
 * current CPU (up to max_out entries) and returns the total number of
 * supported tiers. Safe to call with out == NULL to query the count. */
AREION_PQ_API size_t areion_pq_available_tiers(const char **out, size_t max_out);

/* Overrides the active dispatch tier by name ("auto", "purec", "purego",
 * "aesni", "vex", "vaesavx2", "avx512", "arm64") and synchronizes the
 * underlying areion-c tier. Returns 0 on success, -1 if unsupported. */
AREION_PQ_API int areion_pq_set_tier(const char *name);

/* Overrides the active dispatch tier by enum code and synchronizes the
 * underlying areion-c tier. Returns 0 on success, -1 if unsupported. */
AREION_PQ_API int areion_pq_set_tier_code(areion_pq_tier_t id);

/* Returns true if the specified tier is supported on the current CPU. */
AREION_PQ_API bool areion_pq_tier_supported(areion_pq_tier_t tier);

/* Enables (enable = true) or disables (enable = false, forcing "purec")
 * hardware acceleration. */
AREION_PQ_API void areion_pq_use_hardware_acceleration(bool enable);

/* Runs deterministic Known-Answer Tests (KATs) across all post-quantum
 * primitives on the active dispatch tier and zeroizes all temporary buffers
 * before returning. Returns 0 on success, -1 on failure. */
AREION_PQ_API int areion_pq_selftest(void);

/* Scrubs len bytes at ptr with zeros in a manner resistant to dead-store
 * elimination (DSE). Safe to call with ptr == NULL or len == 0. */
AREION_PQ_API void areion_pq_zeroize(void *ptr, size_t len);

/* =========================================================================
 * 3. Finite Field & Witness Primitives
 * ========================================================================= */

AREION_PQ_API uint8_t areion_pq_gf256_mul(uint8_t a, uint8_t b);
AREION_PQ_API uint8_t areion_pq_gf256_sq(uint8_t a);
AREION_PQ_API uint8_t areion_pq_gf256_inv(uint8_t a);
AREION_PQ_API uint8_t areion_pq_gf256_affine(uint8_t a);
AREION_PQ_API uint8_t areion_pq_gf256_affine_inv(uint8_t s);

AREION_PQ_API void areion_pq_gf128_mul(uint8_t out[16], const uint8_t a[16], const uint8_t b[16]);
AREION_PQ_API void areion_pq_gf128_polymac(
    uint8_t out[16], const uint8_t *a, const uint8_t *b, size_t count, const uint8_t chi[16]);
AREION_PQ_API void areion_pq_gf256_field_mul(uint8_t out[32], const uint8_t a[32], const uint8_t b[32]);

AREION_PQ_API void areion_pq_mul_ortho256(uint8_t out[32], const uint8_t t[32], const uint8_t k[32]);
AREION_PQ_API void areion_pq_ortho_sigma256(uint8_t out[32], const uint8_t k[32]);

AREION_PQ_API void areion_pq_extract_witness256(
    uint8_t c[32], uint8_t w[288], const uint8_t m[32], const uint8_t k1[32], const uint8_t k2[32]);
AREION_PQ_API void areion_pq_extract_witness256_p2(
    uint8_t c[32], uint8_t w[288], const uint8_t m[32], const uint8_t k1[32], const uint8_t k2[32]);
/* Returns 1 if valid, 0 if invalid. */
AREION_PQ_API int areion_pq_verify_witness256(
    const uint8_t m[32], const uint8_t c[32], const uint8_t k1[32], const uint8_t k2[32], const uint8_t w[288]);
/* Returns 1 if valid, 0 if invalid. */
AREION_PQ_API int areion_pq_verify_witness256_p2(
    const uint8_t m[32], const uint8_t c[32], const uint8_t k1[32], const uint8_t k2[32], const uint8_t w[288]);

AREION_PQ_API void areion_pq_extract_witness_em2_256(
    uint8_t c[32], uint8_t w[576], const uint8_t m[32], const uint8_t k1[32], const uint8_t k2[32]);
/* Returns 1 if valid, 0 if invalid. */
AREION_PQ_API int areion_pq_verify_witness_em2_256(
    const uint8_t m[32], const uint8_t c[32], const uint8_t k1[32], const uint8_t k2[32], const uint8_t w[576]);

/* =========================================================================
 * 4. Track 1: FAEST-Areion (VOLE-in-the-Head Signatures)
 * ========================================================================= */

AREION_PQ_API void areion_pq_faest_keygen128s(uint8_t pk[48], uint8_t sk[64], const uint8_t seed[32]);
AREION_PQ_API void areion_pq_faest_sign128s(
    uint8_t sig[6448], const uint8_t sk[64], const uint8_t *msg, size_t msg_len, const uint8_t opt_rand[16]);
/* Returns 1 if valid, 0 if invalid. */
AREION_PQ_API int areion_pq_faest_verify128s(
    const uint8_t pk[48], const uint8_t *msg, size_t msg_len, const uint8_t sig[6448]);

AREION_PQ_API void areion_pq_faest_keygen128f(uint8_t pk[48], uint8_t sk[64], const uint8_t seed[32]);
AREION_PQ_API void areion_pq_faest_sign128f(
    uint8_t sig[7456], const uint8_t sk[64], const uint8_t *msg, size_t msg_len, const uint8_t opt_rand[16]);
/* Returns 1 if valid, 0 if invalid. */
AREION_PQ_API int areion_pq_faest_verify128f(
    const uint8_t pk[48], const uint8_t *msg, size_t msg_len, const uint8_t sig[7456]);

AREION_PQ_API void areion_pq_faest_keygen256s(uint8_t pk[64], uint8_t sk[96], const uint8_t seed[64]);
AREION_PQ_API void areion_pq_faest_sign256s(
    uint8_t sig[18208], const uint8_t sk[96], const uint8_t *msg, size_t msg_len, const uint8_t opt_rand[32]);
/* Returns 1 if valid, 0 if invalid. */
AREION_PQ_API int areion_pq_faest_verify256s(
    const uint8_t pk[64], const uint8_t *msg, size_t msg_len, const uint8_t sig[18208]);

AREION_PQ_API void areion_pq_faest_keygen256f(uint8_t pk[64], uint8_t sk[96], const uint8_t seed[64]);
AREION_PQ_API void areion_pq_faest_sign256f(
    uint8_t sig[20512], const uint8_t sk[96], const uint8_t *msg, size_t msg_len, const uint8_t opt_rand[32]);
/* Returns 1 if valid, 0 if invalid. */
AREION_PQ_API int areion_pq_faest_verify256f(
    const uint8_t pk[64], const uint8_t *msg, size_t msg_len, const uint8_t sig[20512]);

AREION_PQ_API void areion_pq_faest_em2_keygen256s(uint8_t pk[64], uint8_t sk[96], const uint8_t seed[64]);
AREION_PQ_API void areion_pq_faest_em2_sign256s(
    uint8_t sig[25696], const uint8_t sk[96], const uint8_t *msg, size_t msg_len, const uint8_t opt_rand[32]);
/* Returns 1 if valid, 0 if invalid. */
AREION_PQ_API int areion_pq_faest_em2_verify256s(
    const uint8_t pk[64], const uint8_t *msg, size_t msg_len, const uint8_t sig[25696]);

AREION_PQ_API void areion_pq_faest_em2_keygen256f(uint8_t pk[64], uint8_t sk[96], const uint8_t seed[64]);
AREION_PQ_API void areion_pq_faest_em2_sign256f(
    uint8_t sig[30368], const uint8_t sk[96], const uint8_t *msg, size_t msg_len, const uint8_t opt_rand[32]);
/* Returns 1 if valid, 0 if invalid. */
AREION_PQ_API int areion_pq_faest_em2_verify256f(
    const uint8_t pk[64], const uint8_t *msg, size_t msg_len, const uint8_t sig[30368]);

#define areion_pq_faest_keygen_em2_256s areion_pq_faest_em2_keygen256s
#define areion_pq_faest_sign_em2_256s   areion_pq_faest_em2_sign256s
#define areion_pq_faest_verify_em2_256s areion_pq_faest_em2_verify256s
#define areion_pq_faest_keygen_em2_256f areion_pq_faest_em2_keygen256f
#define areion_pq_faest_sign_em2_256f   areion_pq_faest_em2_sign256f
#define areion_pq_faest_verify_em2_256f areion_pq_faest_em2_verify256f

/* =========================================================================
 * 5. Track 2: SLH-DSA-Areion (NIST FIPS 205) Tweakable Hashes & Signatures
 * ========================================================================= */

AREION_PQ_API void areion_pq_slh_expand_seed128(
    uint8_t k_pub[64], uint8_t k_sk[64], const uint8_t pk_seed[16], const uint8_t sk_seed[16]);
AREION_PQ_API void areion_pq_slh_expand_seed256(
    uint8_t k_pub[64], uint8_t k_sk[64], const uint8_t pk_seed[32], const uint8_t sk_seed[32]);
AREION_PQ_API void areion_pq_slh_compact_adrs(uint8_t out[16], const uint8_t adrs[32]);

AREION_PQ_API void areion_pq_slh_prf128(uint8_t out[16], const uint8_t k_sk[64], const uint8_t adrs[32]);
AREION_PQ_API void areion_pq_slh_prf256(uint8_t out[32], const uint8_t k_sk[64], const uint8_t adrs[32]);
AREION_PQ_API void areion_pq_slh_prf256x4(uint8_t out[4][32], const uint8_t k_sk[64], const uint8_t adrs[4][32]);

AREION_PQ_API void areion_pq_slh_f128(
    uint8_t out[16], const uint8_t pk_seed[16], const uint8_t k_pub[64], const uint8_t adrs[32], const uint8_t m1[16]);
AREION_PQ_API void areion_pq_slh_f256(
    uint8_t out[32], const uint8_t k_pub[64], const uint8_t adrs[32], const uint8_t m1[32]);
AREION_PQ_API void areion_pq_slh_f_tem256(
    uint8_t out[32], const uint8_t k_pub[64], const uint8_t adrs[32], const uint8_t m1[32]);

AREION_PQ_API void areion_pq_slh_h128(
    uint8_t out[16], const uint8_t pk_seed[16], const uint8_t k_pub[64], const uint8_t adrs[32],
    const uint8_t m1[16], const uint8_t m2[16]);
AREION_PQ_API void areion_pq_slh_h256(
    uint8_t out[32], const uint8_t k_pub[64], const uint8_t adrs[32],
    const uint8_t m1[32], const uint8_t m2[32]);

AREION_PQ_API void areion_pq_slh_tl128(
    uint8_t out[16], const uint8_t k_pub[64], const uint8_t adrs[32], const uint8_t *blocks, size_t num_blocks);
AREION_PQ_API void areion_pq_slh_tl256(
    uint8_t out[32], const uint8_t k_pub[64], const uint8_t adrs[32], const uint8_t *blocks, size_t num_blocks);

AREION_PQ_API void areion_pq_slhdsa_keygen128f(uint8_t pk[32], uint8_t sk[64], const uint8_t seed[48]);
AREION_PQ_API void areion_pq_slhdsa_sign128f(
    uint8_t sig[17088], const uint8_t sk[64], const uint8_t *msg, size_t msg_len, const uint8_t opt_rand[16]);
/* Returns 1 if valid, 0 if invalid. */
AREION_PQ_API int areion_pq_slhdsa_verify128f(
    const uint8_t pk[32], const uint8_t *msg, size_t msg_len, const uint8_t sig[17088]);

AREION_PQ_API void areion_pq_slhdsa_keygen128s(uint8_t pk[32], uint8_t sk[64], const uint8_t seed[48]);
AREION_PQ_API void areion_pq_slhdsa_sign128s(
    uint8_t sig[7856], const uint8_t sk[64], const uint8_t *msg, size_t msg_len, const uint8_t opt_rand[16]);
/* Returns 1 if valid, 0 if invalid. */
AREION_PQ_API int areion_pq_slhdsa_verify128s(
    const uint8_t pk[32], const uint8_t *msg, size_t msg_len, const uint8_t sig[7856]);

AREION_PQ_API void areion_pq_slhdsa_keygen256f(uint8_t pk[64], uint8_t sk[128], const uint8_t seed[96]);
AREION_PQ_API void areion_pq_slhdsa_sign256f(
    uint8_t sig[49856], const uint8_t sk[128], const uint8_t *msg, size_t msg_len, const uint8_t opt_rand[32]);
/* Returns 1 if valid, 0 if invalid. */
AREION_PQ_API int areion_pq_slhdsa_verify256f(
    const uint8_t pk[64], const uint8_t *msg, size_t msg_len, const uint8_t sig[49856]);

AREION_PQ_API void areion_pq_slhdsa_keygen256s(uint8_t pk[64], uint8_t sk[128], const uint8_t seed[96]);
AREION_PQ_API void areion_pq_slhdsa_sign256s(
    uint8_t sig[29792], const uint8_t sk[128], const uint8_t *msg, size_t msg_len, const uint8_t opt_rand[32]);
/* Returns 1 if valid, 0 if invalid. */
AREION_PQ_API int areion_pq_slhdsa_verify256s(
    const uint8_t pk[64], const uint8_t *msg, size_t msg_len, const uint8_t sig[29792]);

AREION_PQ_API void areion_pq_slhdsa_tem_keygen256f(uint8_t pk[64], uint8_t sk[128], const uint8_t seed[96]);
AREION_PQ_API void areion_pq_slhdsa_tem_sign256f(
    uint8_t sig[49856], const uint8_t sk[128], const uint8_t *msg, size_t msg_len, const uint8_t opt_rand[32]);
/* Returns 1 if valid, 0 if invalid. */
AREION_PQ_API int areion_pq_slhdsa_tem_verify256f(
    const uint8_t pk[64], const uint8_t *msg, size_t msg_len, const uint8_t sig[49856]);

/* =========================================================================
 * 6. Track 3: Areion-HPKE, AreionKDF & Areion-TEM2-SIV Wide-Block AEAD
 * ========================================================================= */

AREION_PQ_API void areion_pq_kdf_expand(
    uint8_t *dst, size_t dst_len,
    const uint8_t *secret, size_t secret_len,
    const uint8_t *context, size_t context_len);

AREION_PQ_API void areion_pq_tem2_siv_encrypt(
    uint8_t *ciphertext, uint8_t tag[32],
    const uint8_t key[128], const uint8_t nonce[32],
    const uint8_t *ad, size_t ad_len,
    const uint8_t *plaintext, size_t pt_len);

/* Returns 1 if tag is valid, 0 if authentication fails (and wipes plaintext). */
AREION_PQ_API int areion_pq_tem2_siv_decrypt(
    uint8_t *plaintext,
    const uint8_t key[128], const uint8_t nonce[32],
    const uint8_t *ad, size_t ad_len,
    const uint8_t *ciphertext, size_t ct_len,
    const uint8_t tag[32]);

AREION_PQ_API void areion_pq_hpke_derive_keys(
    uint8_t dem_key[128], uint8_t base_nonce[32],
    const uint8_t shared_secret[32],
    const uint8_t *info, size_t info_len);

AREION_PQ_API void areion_pq_hpke_seal_det(
    uint8_t *ciphertext, uint8_t tag[32],
    const uint8_t shared_secret[32],
    const uint8_t *info, size_t info_len,
    uint64_t seq,
    const uint8_t *ad, size_t ad_len,
    const uint8_t *plaintext, size_t pt_len);

/* Returns 1 if tag is valid, 0 if authentication fails (and wipes plaintext). */
AREION_PQ_API int areion_pq_hpke_open_det(
    uint8_t *plaintext,
    const uint8_t shared_secret[32],
    const uint8_t *info, size_t info_len,
    uint64_t seq,
    const uint8_t *ad, size_t ad_len,
    const uint8_t *ciphertext, size_t ct_len,
    const uint8_t tag[32]);

#if !defined(__cplusplus) && !defined(S_SPLINT_S) && (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L)
#define areion_pq_slh_prf256x4(out, k_sk, adrs) \
    (areion_pq_slh_prf256x4)((out), (k_sk), AREION_CONST_U8_32(adrs))
#endif

#if defined(__clang__) && !defined(__cplusplus) && (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L)
#pragma clang diagnostic pop
#endif

#ifdef __cplusplus
}
#endif

#endif /* AREION_PQ_H */
