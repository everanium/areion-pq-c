/*
 * Copyright (c) 2026 Andrey Kuvshinov
 *
 * Dual-licensed under Apache-2.0 OR MIT.
 * See LICENSE-APACHE and LICENSE-MIT for details.
 */

#include "areion_pq.h"
#include "areion_pq_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* =========================================================================
 * SUPERCOP (eBACS) & PQClean C99 Wrapper Includes (Macro-Aliased for Testing)
 * ========================================================================= */

#define crypto_sign_seed_keypair supercop_faest128s_seed_keypair
#define crypto_sign_keypair      supercop_faest128s_keypair
#define crypto_sign_signature    supercop_faest128s_signature
#define crypto_sign_verify       supercop_faest128s_verify
#define crypto_sign              supercop_faest128s_sign
#define crypto_sign_open         supercop_faest128s_open
#include "supercop/crypto_sign/faest_areion128s/ref/sign.c" /* NOLINT(bugprone-suspicious-include) */
#undef crypto_sign_seed_keypair
#undef crypto_sign_keypair
#undef crypto_sign_signature
#undef crypto_sign_verify
#undef crypto_sign
#undef crypto_sign_open
#undef CRYPTO_SECRETKEYBYTES
#undef CRYPTO_PUBLICKEYBYTES
#undef CRYPTO_BYTES
#undef CRYPTO_SEEDBYTES
#undef CRYPTO_VERSION

#define crypto_sign_seed_keypair supercop_faest128f_seed_keypair
#define crypto_sign_keypair      supercop_faest128f_keypair
#define crypto_sign_signature    supercop_faest128f_signature
#define crypto_sign_verify       supercop_faest128f_verify
#define crypto_sign              supercop_faest128f_sign
#define crypto_sign_open         supercop_faest128f_open
#include "supercop/crypto_sign/faest_areion128f/ref/sign.c" /* NOLINT(bugprone-suspicious-include) */
#undef crypto_sign_seed_keypair
#undef crypto_sign_keypair
#undef crypto_sign_signature
#undef crypto_sign_verify
#undef crypto_sign
#undef crypto_sign_open
#undef CRYPTO_SECRETKEYBYTES
#undef CRYPTO_PUBLICKEYBYTES
#undef CRYPTO_BYTES
#undef CRYPTO_SEEDBYTES
#undef CRYPTO_VERSION

#define crypto_sign_seed_keypair supercop_faest256s_seed_keypair
#define crypto_sign_keypair      supercop_faest256s_keypair
#define crypto_sign_signature    supercop_faest256s_signature
#define crypto_sign_verify       supercop_faest256s_verify
#define crypto_sign              supercop_faest256s_sign
#define crypto_sign_open         supercop_faest256s_open
#include "supercop/crypto_sign/faest_areion256s/ref/sign.c" /* NOLINT(bugprone-suspicious-include) */
#undef crypto_sign_seed_keypair
#undef crypto_sign_keypair
#undef crypto_sign_signature
#undef crypto_sign_verify
#undef crypto_sign
#undef crypto_sign_open
#undef CRYPTO_SECRETKEYBYTES
#undef CRYPTO_PUBLICKEYBYTES
#undef CRYPTO_BYTES
#undef CRYPTO_SEEDBYTES
#undef CRYPTO_VERSION

#define crypto_sign_seed_keypair supercop_faest256f_seed_keypair
#define crypto_sign_keypair      supercop_faest256f_keypair
#define crypto_sign_signature    supercop_faest256f_signature
#define crypto_sign_verify       supercop_faest256f_verify
#define crypto_sign              supercop_faest256f_sign
#define crypto_sign_open         supercop_faest256f_open
#include "supercop/crypto_sign/faest_areion256f/ref/sign.c" /* NOLINT(bugprone-suspicious-include) */
#undef crypto_sign_seed_keypair
#undef crypto_sign_keypair
#undef crypto_sign_signature
#undef crypto_sign_verify
#undef crypto_sign
#undef crypto_sign_open
#undef CRYPTO_SECRETKEYBYTES
#undef CRYPTO_PUBLICKEYBYTES
#undef CRYPTO_BYTES
#undef CRYPTO_SEEDBYTES
#undef CRYPTO_VERSION

#define crypto_sign_seed_keypair supercop_faest_em2_256s_seed_keypair
#define crypto_sign_keypair      supercop_faest_em2_256s_keypair
#define crypto_sign_signature    supercop_faest_em2_256s_signature
#define crypto_sign_verify       supercop_faest_em2_256s_verify
#define crypto_sign              supercop_faest_em2_256s_sign
#define crypto_sign_open         supercop_faest_em2_256s_open
#include "supercop/crypto_sign/faest_areion_em2_256s/ref/sign.c" /* NOLINT(bugprone-suspicious-include) */
#undef crypto_sign_seed_keypair
#undef crypto_sign_keypair
#undef crypto_sign_signature
#undef crypto_sign_verify
#undef crypto_sign
#undef crypto_sign_open
#undef CRYPTO_SECRETKEYBYTES
#undef CRYPTO_PUBLICKEYBYTES
#undef CRYPTO_BYTES
#undef CRYPTO_SEEDBYTES
#undef CRYPTO_VERSION

#define crypto_sign_seed_keypair supercop_faest_em2_256f_seed_keypair
#define crypto_sign_keypair      supercop_faest_em2_256f_keypair
#define crypto_sign_signature    supercop_faest_em2_256f_signature
#define crypto_sign_verify       supercop_faest_em2_256f_verify
#define crypto_sign              supercop_faest_em2_256f_sign
#define crypto_sign_open         supercop_faest_em2_256f_open
#include "supercop/crypto_sign/faest_areion_em2_256f/ref/sign.c" /* NOLINT(bugprone-suspicious-include) */
#undef crypto_sign_seed_keypair
#undef crypto_sign_keypair
#undef crypto_sign_signature
#undef crypto_sign_verify
#undef crypto_sign
#undef crypto_sign_open
#undef CRYPTO_SECRETKEYBYTES
#undef CRYPTO_PUBLICKEYBYTES
#undef CRYPTO_BYTES
#undef CRYPTO_SEEDBYTES
#undef CRYPTO_VERSION

#define crypto_sign_seed_keypair supercop_slhdsa128f_seed_keypair
#define crypto_sign_keypair      supercop_slhdsa128f_keypair
#define crypto_sign_signature    supercop_slhdsa128f_signature
#define crypto_sign_verify       supercop_slhdsa128f_verify
#define crypto_sign              supercop_slhdsa128f_sign
#define crypto_sign_open         supercop_slhdsa128f_open
#include "supercop/crypto_sign/slh_dsa_areion128f/ref/sign.c" /* NOLINT(bugprone-suspicious-include) */
#undef crypto_sign_seed_keypair
#undef crypto_sign_keypair
#undef crypto_sign_signature
#undef crypto_sign_verify
#undef crypto_sign
#undef crypto_sign_open
#undef CRYPTO_SECRETKEYBYTES
#undef CRYPTO_PUBLICKEYBYTES
#undef CRYPTO_BYTES
#undef CRYPTO_SEEDBYTES
#undef CRYPTO_VERSION

#define crypto_sign_seed_keypair supercop_slhdsa128s_seed_keypair
#define crypto_sign_keypair      supercop_slhdsa128s_keypair
#define crypto_sign_signature    supercop_slhdsa128s_signature
#define crypto_sign_verify       supercop_slhdsa128s_verify
#define crypto_sign              supercop_slhdsa128s_sign
#define crypto_sign_open         supercop_slhdsa128s_open
#include "supercop/crypto_sign/slh_dsa_areion128s/ref/sign.c" /* NOLINT(bugprone-suspicious-include) */
#undef crypto_sign_seed_keypair
#undef crypto_sign_keypair
#undef crypto_sign_signature
#undef crypto_sign_verify
#undef crypto_sign
#undef crypto_sign_open
#undef CRYPTO_SECRETKEYBYTES
#undef CRYPTO_PUBLICKEYBYTES
#undef CRYPTO_BYTES
#undef CRYPTO_SEEDBYTES
#undef CRYPTO_VERSION

#define crypto_sign_seed_keypair supercop_slhdsa256f_seed_keypair
#define crypto_sign_keypair      supercop_slhdsa256f_keypair
#define crypto_sign_signature    supercop_slhdsa256f_signature
#define crypto_sign_verify       supercop_slhdsa256f_verify
#define crypto_sign              supercop_slhdsa256f_sign
#define crypto_sign_open         supercop_slhdsa256f_open
#include "supercop/crypto_sign/slh_dsa_areion256f/ref/sign.c" /* NOLINT(bugprone-suspicious-include) */
#undef crypto_sign_seed_keypair
#undef crypto_sign_keypair
#undef crypto_sign_signature
#undef crypto_sign_verify
#undef crypto_sign
#undef crypto_sign_open
#undef CRYPTO_SECRETKEYBYTES
#undef CRYPTO_PUBLICKEYBYTES
#undef CRYPTO_BYTES
#undef CRYPTO_SEEDBYTES
#undef CRYPTO_VERSION

#define crypto_sign_seed_keypair supercop_slhdsa256s_seed_keypair
#define crypto_sign_keypair      supercop_slhdsa256s_keypair
#define crypto_sign_signature    supercop_slhdsa256s_signature
#define crypto_sign_verify       supercop_slhdsa256s_verify
#define crypto_sign              supercop_slhdsa256s_sign
#define crypto_sign_open         supercop_slhdsa256s_open
#include "supercop/crypto_sign/slh_dsa_areion256s/ref/sign.c" /* NOLINT(bugprone-suspicious-include) */
#undef crypto_sign_seed_keypair
#undef crypto_sign_keypair
#undef crypto_sign_signature
#undef crypto_sign_verify
#undef crypto_sign
#undef crypto_sign_open
#undef CRYPTO_SECRETKEYBYTES
#undef CRYPTO_PUBLICKEYBYTES
#undef CRYPTO_BYTES
#undef CRYPTO_SEEDBYTES
#undef CRYPTO_VERSION

#define crypto_aead_encrypt supercop_tem2_siv512_encrypt
#define crypto_aead_decrypt supercop_tem2_siv512_decrypt
#include "supercop/crypto_aead/areion_tem2_siv512/ref/encrypt.c" /* NOLINT(bugprone-suspicious-include) */
#undef crypto_aead_encrypt
#undef crypto_aead_decrypt
#undef CRYPTO_KEYBYTES
#undef CRYPTO_NSECBYTES
#undef CRYPTO_NPUBBYTES
#undef CRYPTO_ABYTES
#undef CRYPTO_NOOVERLAP
#undef CRYPTO_VERSION

#include "pqclean/crypto_sign/faest-areion-128f/clean/sign.c" /* NOLINT(bugprone-suspicious-include) */
#include "pqclean/crypto_sign/faest-areion-256f/clean/sign.c" /* NOLINT(bugprone-suspicious-include) */
#include "pqclean/crypto_sign/slh-dsa-areion-128f/clean/sign.c" /* NOLINT(bugprone-suspicious-include) */
#include "pqclean/crypto_sign/slh-dsa-areion-256f/clean/sign.c" /* NOLINT(bugprone-suspicious-include) */

#if defined(_REENTRANT) || defined(AREION_PQ_TEST_PTHREAD)
#define AREION_PQ_HAS_PTHREAD_TEST 1
#include <pthread.h>
#else
#define AREION_PQ_HAS_PTHREAD_TEST 0
#endif

static int g_failures = 0;
static int g_full_mode = 0;
static volatile uint8_t g_bench_sink = 0;

static void check_true(const char *label, int cond) {
    if (!cond) {
        (void)fprintf(stderr, "FAIL [%s]: condition was false\n", label);
        g_failures++;
    }
}

static void check_bytes_eq(const char *label, const uint8_t *got, const uint8_t *want, size_t len) {
    if (memcmp(got, want, len) != 0) {
        size_t i;
        size_t show = (len < 64U) ? len : 64U;
        (void)fprintf(stderr, "FAIL [%s]:\n  got : ", label);
        for (i = 0U; i < show; i++) {
            (void)fprintf(stderr, "%02x", got[i]);
        }
        (void)fprintf(stderr, "\n  want: ");
        for (i = 0U; i < show; i++) {
            (void)fprintf(stderr, "%02x", want[i]);
        }
        (void)fprintf(stderr, "\n");
        g_failures++;
    }
}

static void fill_pattern(uint8_t *buf, size_t len, uint8_t seed) {
    size_t i;
    for (i = 0U; i < len; i++) {
        buf[i] = (uint8_t)((i * 37U + (size_t)seed * 13U + 0x5aU) & 0xFFU);
    }
}

/* =========================================================================
 * 1. Finite Field & Witness Algebraic Property Tests
 * ========================================================================= */

static void test_finite_fields_and_witnesses(void) {
    uint32_t a, b, c;
    uint8_t zero16[16], one16[16], x16[16], y16[16], z16[16];
    uint8_t t1_16[16], t2_16[16], t3_16[16];
    uint8_t poly_a[4][16], poly_b[4][16], chi16[16], mac_got[16], mac_want[16];
    uint8_t f256_a[32], f256_b[32], f256_c[32], f256_ab[32], f256_ba[32], f256_lhs[32], f256_rhs[32];
    uint8_t ortho_t[32], ortho_a[32], ortho_b[32], ortho_ab[32], ortho_ta[32], ortho_tb[32], ortho_tab[32];
    uint8_t m32[32], k1_32[32], k2_32[32], c32[32], c_ref[32], k64[64];
    uint8_t w288[288], w576[576];
    size_t i;

    /* 1a. Exhaustive GF(2^8) field & QuickSilver S-box gate checks */
    for (a = 0U; a < 256U; a++) {
        uint8_t ua = (uint8_t)a;
        uint8_t sq = areion_pq_gf256_sq(ua);
        uint8_t mul_aa = areion_pq_gf256_mul(ua, ua);
        uint8_t inv = areion_pq_gf256_inv(ua);
        uint8_t sbox = areion_pq_gf256_affine(inv);
        uint8_t y = areion_pq_gf256_affine_inv(sbox);
        uint8_t c1 = (uint8_t)(areion_pq_gf256_mul(sq, y) ^ ua);
        uint8_t c2 = (uint8_t)(areion_pq_gf256_mul(areion_pq_gf256_sq(y), ua) ^ y);

        check_true("GF256Sq == GF256Mul(a,a)", sq == mul_aa);
        check_true("GF256Mul(a,0) == 0", areion_pq_gf256_mul(ua, 0U) == 0U);
        check_true("GF256Mul(a,1) == a", areion_pq_gf256_mul(ua, 1U) == ua);
        if (ua == 0U) {
            check_true("GF256Inv(0) == 0", inv == 0U);
        } else {
            check_true("GF256Mul(a, GF256Inv(a)) == 1", areion_pq_gf256_mul(ua, inv) == 1U);
        }
        check_true("GF256Affine(GF256Inv(a)) == AES_SBOX[a]", sbox == areion_pq_aes_sbox[a]);
        check_true("GF256AffineInv(GF256Affine(a)) == a", areion_pq_gf256_affine_inv(areion_pq_gf256_affine(ua)) == ua);
        check_true("GF256Affine(GF256AffineInv(a)) == a", areion_pq_gf256_affine(areion_pq_gf256_affine_inv(ua)) == ua);
        check_true("QuickSilver C1 == 0 && C2 == 0", c1 == 0U && c2 == 0U);

        /* Soundness: any wrong S-box output s' != sbox must violate C1 or C2 */
        for (b = 0U; b < 256U; b++) {
            uint8_t sb = (uint8_t)b;
            uint8_t yb = areion_pq_gf256_affine_inv(sb);
            uint8_t bad_c1 = (uint8_t)(areion_pq_gf256_mul(sq, yb) ^ ua);
            uint8_t bad_c2 = (uint8_t)(areion_pq_gf256_mul(areion_pq_gf256_sq(yb), ua) ^ yb);
            if (sb != sbox) {
                check_true("QuickSilver S-box gate soundness", (bad_c1 | bad_c2) != 0U);
            }
            check_true("GF256Mul commutativity", areion_pq_gf256_mul(ua, sb) == areion_pq_gf256_mul(sb, ua));
            check_true("GF256Sq linearity", areion_pq_gf256_sq((uint8_t)(ua ^ sb)) == (uint8_t)(sq ^ areion_pq_gf256_sq(sb)));
        }
    }

    for (a = 1U; a < 256U; a += 17U) {
        for (b = 2U; b < 256U; b += 29U) {
            for (c = 3U; c < 256U; c += 37U) {
                uint8_t ua = (uint8_t)a, ub = (uint8_t)b, uc = (uint8_t)c;
                uint8_t lhs_assoc = areion_pq_gf256_mul(areion_pq_gf256_mul(ua, ub), uc);
                uint8_t rhs_assoc = areion_pq_gf256_mul(ua, areion_pq_gf256_mul(ub, uc));
                uint8_t lhs_dist = areion_pq_gf256_mul(ua, (uint8_t)(ub ^ uc));
                uint8_t rhs_dist = (uint8_t)(areion_pq_gf256_mul(ua, ub) ^ areion_pq_gf256_mul(ua, uc));
                check_true("GF256Mul associativity", lhs_assoc == rhs_assoc);
                check_true("GF256Mul distributivity", lhs_dist == rhs_dist);
            }
        }
    }

    /* 1b. GF(2^128) field axioms & GF128PolyMAC */
    memset(zero16, 0, 16U);
    memset(one16, 0, 16U);
    one16[0] = 1U;
    fill_pattern(x16, 16U, 0x11U);
    fill_pattern(y16, 16U, 0x22U);
    fill_pattern(z16, 16U, 0x33U);

    areion_pq_gf128_mul(t1_16, x16, zero16);
    check_bytes_eq("GF128Mul(x, 0) == 0", t1_16, zero16, 16U);
    areion_pq_gf128_mul(t1_16, x16, one16);
    check_bytes_eq("GF128Mul(x, 1) == x", t1_16, x16, 16U);

    areion_pq_gf128_mul(t1_16, x16, y16);
    areion_pq_gf128_mul(t2_16, y16, x16);
    check_bytes_eq("GF128Mul commutativity", t1_16, t2_16, 16U);
    areion_pq_gf128_mul_core(t3_16, x16, y16);
    check_bytes_eq("GF128Mul == GF128MulCore", t1_16, t3_16, 16U);

    areion_pq_gf128_mul(t2_16, t1_16, z16);
    areion_pq_gf128_mul(t3_16, y16, z16);
    areion_pq_gf128_mul(t1_16, x16, t3_16);
    check_bytes_eq("GF128Mul associativity", t2_16, t1_16, 16U);

    for (i = 0U; i < 16U; i++) {
        t3_16[i] = (uint8_t)(y16[i] ^ z16[i]);
    }
    areion_pq_gf128_mul(t1_16, x16, t3_16);
    areion_pq_gf128_mul(t2_16, x16, y16);
    areion_pq_gf128_mul(t3_16, x16, z16);
    for (i = 0U; i < 16U; i++) {
        t2_16[i] ^= t3_16[i];
    }
    check_bytes_eq("GF128Mul distributivity", t1_16, t2_16, 16U);

    /* GF128PolyMAC verification */
    for (i = 0U; i < 4U; i++) {
        fill_pattern(poly_a[i], 16U, (uint8_t)(0x40U + i));
        fill_pattern(poly_b[i], 16U, (uint8_t)(0x50U + i));
    }
    fill_pattern(chi16, 16U, 0x60U);
    areion_pq_gf128_polymac(mac_got, &poly_a[0][0], &poly_b[0][0], 4U, chi16);
    memset(mac_want, 0, 16U);
    for (i = 0U; i < 4U; i++) {
        size_t j;
        areion_pq_gf128_mul(mac_want, mac_want, chi16);
        areion_pq_gf128_mul(t1_16, poly_a[i], poly_b[i]);
        for (j = 0U; j < 16U; j++) {
            mac_want[j] ^= t1_16[j];
        }
    }
    check_bytes_eq("GF128PolyMAC Horner equivalence", mac_got, mac_want, 16U);

    /* 1c. GF(2^256) extension field & Orthomorphisms */
    fill_pattern(f256_a, 32U, 0x61U);
    fill_pattern(f256_b, 32U, 0x62U);
    fill_pattern(f256_c, 32U, 0x63U);
    areion_pq_gf256_field_mul(f256_ab, f256_a, f256_b);
    areion_pq_gf256_field_mul(f256_ba, f256_b, f256_a);
    check_bytes_eq("GF256FieldMul commutativity", f256_ab, f256_ba, 32U);
    for (i = 0U; i < 32U; i++) {
        f256_ba[i] = (uint8_t)(f256_b[i] ^ f256_c[i]);
    }
    areion_pq_gf256_field_mul(f256_lhs, f256_a, f256_ba);
    areion_pq_gf256_field_mul(f256_rhs, f256_a, f256_c);
    for (i = 0U; i < 32U; i++) {
        f256_rhs[i] ^= f256_ab[i];
    }
    check_bytes_eq("GF256FieldMul distributivity", f256_lhs, f256_rhs, 32U);

    fill_pattern(ortho_t, 32U, 0x64U);
    ortho_t[0] |= 0x02U;
    ortho_t[16] |= 0x02U;
    fill_pattern(ortho_a, 32U, 0x65U);
    fill_pattern(ortho_b, 32U, 0x66U);
    for (i = 0U; i < 32U; i++) {
        ortho_ab[i] = (uint8_t)(ortho_a[i] ^ ortho_b[i]);
    }
    areion_pq_mul_ortho256(ortho_ta, ortho_t, ortho_a);
    areion_pq_mul_ortho256(ortho_tb, ortho_t, ortho_b);
    areion_pq_mul_ortho256(ortho_tab, ortho_t, ortho_ab);
    for (i = 0U; i < 32U; i++) {
        ortho_ta[i] ^= ortho_tb[i];
    }
    check_bytes_eq("MulOrtho256 GF(2)-linearity", ortho_tab, ortho_ta, 32U);

    areion_pq_ortho_sigma256(ortho_ta, ortho_a);
    areion_pq_ortho_sigma256(ortho_tb, ortho_b);
    areion_pq_ortho_sigma256(ortho_tab, ortho_ab);
    for (i = 0U; i < 32U; i++) {
        ortho_ta[i] ^= ortho_tb[i];
    }
    check_bytes_eq("OrthoSigma256 GF(2)-linearity", ortho_tab, ortho_ta, 32U);

    /* 1d. 288-S-box (P1 & P2) and 576-S-box (EM2) Witness Completeness & Soundness */
    fill_pattern(m32, 32U, 0x70U);
    fill_pattern(k1_32, 32U, 0x71U);
    fill_pattern(k2_32, 32U, 0x72U);
    memcpy(&k64[0], k1_32, 32U);
    memcpy(&k64[32], k2_32, 32U);

    areion_em_encrypt256(c_ref, k64, m32);
    areion_pq_extract_witness256(c32, w288, m32, k1_32, k2_32);
    check_bytes_eq("ExtractWitness256 C == EMEncrypt256", c32, c_ref, 32U);
    check_true("VerifyWitness256 valid", areion_pq_verify_witness256(m32, c32, k1_32, k2_32, w288) == 1);

    for (i = 0U; i < 288U; i += 9U) {
        w288[i] ^= 0x01U;
        check_true("VerifyWitness256 rejects tampered w", areion_pq_verify_witness256(m32, c32, k1_32, k2_32, w288) == 0);
        w288[i] ^= 0x01U;
    }
    c32[15] ^= 0x80U;
    check_true("VerifyWitness256 rejects tampered c", areion_pq_verify_witness256(m32, c32, k1_32, k2_32, w288) == 0);
    c32[15] ^= 0x80U;

    areion_pq_extract_witness256_p2(c32, w288, m32, k1_32, k2_32);
    check_true("VerifyWitness256P2 valid", areion_pq_verify_witness256_p2(m32, c32, k1_32, k2_32, w288) == 1);
    w288[143] ^= 0x04U;
    check_true("VerifyWitness256P2 rejects tampered w", areion_pq_verify_witness256_p2(m32, c32, k1_32, k2_32, w288) == 0);

    areion_em2_encrypt256(c_ref, k64, m32);
    areion_pq_extract_witness_em2_256(c32, w576, m32, k1_32, k2_32);
    check_bytes_eq("ExtractWitnessEM2_256 C == EM2Encrypt256", c32, c_ref, 32U);
    check_true("VerifyWitnessEM2_256 valid", areion_pq_verify_witness_em2_256(m32, c32, k1_32, k2_32, w576) == 1);
    for (i = 0U; i < 576U; i += 19U) {
        w576[i] ^= 0x02U;
        check_true("VerifyWitnessEM2_256 rejects tampered w", areion_pq_verify_witness_em2_256(m32, c32, k1_32, k2_32, w576) == 0);
        w576[i] ^= 0x02U;
    }
}

/* =========================================================================
 * 2. Track 2: SLH-DSA Tweakable Hash & Domain Separation Tests
 * ========================================================================= */

static void test_slh_tweakable_hashes(void) {
    uint8_t pk16[16], sk16[16], pk32[32], sk32[32];
    uint8_t kpub128[64], ksk128[64], kpub256[64], ksk256[64];
    uint8_t adrs_a[32], cadrs_a[16];
    uint8_t adrs4[4][32], prf4[4][32], prf1[32];
    size_t i;

    fill_pattern(pk16, 16U, 0x80U);
    fill_pattern(sk16, 16U, 0x81U);
    fill_pattern(pk32, 32U, 0x82U);
    fill_pattern(sk32, 32U, 0x83U);
    areion_pq_slh_expand_seed128(kpub128, ksk128, pk16, sk16);
    areion_pq_slh_expand_seed256(kpub256, ksk256, pk32, sk32);

    memset(adrs_a, 0, 32U);
    adrs_a[3] = 2U;  /* layer */
    adrs_a[15] = 7U; /* tree */
    adrs_a[19] = 3U; /* type */
    adrs_a[23] = 5U; /* keypair */
    adrs_a[27] = 1U; /* chain */
    adrs_a[31] = 9U; /* hash */
    areion_pq_slh_compact_adrs(cadrs_a, adrs_a);

    /* Any change to active ADRS fields must change compact ADRS and hash outputs */
    {
        static const size_t active_Indices[6] = { 3U, 15U, 19U, 23U, 27U, 31U };
        uint8_t adrs_b[32], cadrs_b[16];
        uint8_t m1[32], m2[32], out_a[32], out_b[32];
        fill_pattern(m1, 32U, 0x84U);
        fill_pattern(m2, 32U, 0x85U);
        for (i = 0U; i < 6U; i++) {
            size_t idx = active_Indices[i];
            memcpy(adrs_b, adrs_a, 32U);
            adrs_b[idx] ^= 1U;
            areion_pq_slh_compact_adrs(cadrs_b, adrs_b);
            check_true("SLHCompactADRS domain separation", memcmp(cadrs_a, cadrs_b, 16U) != 0);

            areion_pq_slh_f128(out_a, pk16, kpub128, adrs_a, m1);
            areion_pq_slh_f128(out_b, pk16, kpub128, adrs_b, m1);
            check_true("SLHF128 tweak separation", memcmp(out_a, out_b, 16U) != 0);

            areion_pq_slh_f256(out_a, kpub256, adrs_a, m1);
            areion_pq_slh_f256(out_b, kpub256, adrs_b, m1);
            check_true("SLHF256 tweak separation", memcmp(out_a, out_b, 32U) != 0);

            areion_pq_slh_f_tem256(out_a, kpub256, adrs_a, m1);
            areion_pq_slh_f_tem256(out_b, kpub256, adrs_b, m1);
            check_true("SLHFTEM256 tweak separation", memcmp(out_a, out_b, 32U) != 0);

            areion_pq_slh_h128(out_a, pk16, kpub128, adrs_a, m1, m2);
            areion_pq_slh_h128(out_b, pk16, kpub128, adrs_b, m1, m2);
            check_true("SLHH128 tweak separation", memcmp(out_a, out_b, 16U) != 0);

            areion_pq_slh_h256(out_a, kpub256, adrs_a, m1, m2);
            areion_pq_slh_h256(out_b, kpub256, adrs_b, m1, m2);
            check_true("SLHH256 tweak separation", memcmp(out_a, out_b, 32U) != 0);
        }
    }

    for (i = 0U; i < 4U; i++) {
        fill_pattern(adrs4[i], 32U, (uint8_t)(0x88U + i));
    }
    areion_pq_slh_prf256x4(prf4, ksk256, adrs4);
    for (i = 0U; i < 4U; i++) {
        areion_pq_slh_prf256(prf1, ksk256, adrs4[i]);
        check_bytes_eq("SLHPRF256x4 == SLHPRF256", prf4[i], prf1, 32U);
    }
}

/* =========================================================================
 * 3. Track 3: AreionKDF, TEM2-SIV & HPKE Roundtrip + Negative Tamper Tests
 * ========================================================================= */

static void test_kdf_siv_and_hpke(void) {
    static const size_t test_lens[7] = { 0U, 1U, 31U, 63U, 64U, 128U, 333U };
    uint8_t key[128], nonce[32], ad[192], pt[384], ct[384], dec[384], tag[32];
    uint8_t shared[32], info[32], dem_key[128], base_nonce[32];
    size_t idx, i;

    fill_pattern(key, sizeof(key), 0x90U);
    fill_pattern(nonce, sizeof(nonce), 0x91U);
    fill_pattern(ad, sizeof(ad), 0x92U);
    fill_pattern(pt, sizeof(pt), 0x93U);

    for (idx = 0U; idx < 7U; idx++) {
        size_t len = test_lens[idx];
        size_t ad_len = (idx * 29U) % sizeof(ad);

        areion_pq_tem2_siv_encrypt(ct, tag, key, nonce, ad, ad_len, pt, len);
        memset(dec, 0xAA, sizeof(dec));
        check_true("TEM2SIVDecrypt valid",
                   areion_pq_tem2_siv_decrypt(dec, key, nonce, ad, ad_len, ct, len, tag) == 1);
        if (len > 0U) {
            check_bytes_eq("TEM2SIVDecrypt plaintext match", dec, pt, len);

            /* In-place encryption and decryption */
            memcpy(dec, pt, len);
            areion_pq_tem2_siv_encrypt(dec, tag, key, nonce, ad, ad_len, dec, len);
            check_bytes_eq("TEM2SIVEncrypt in-place", dec, ct, len);
            check_true("TEM2SIVDecrypt in-place",
                       areion_pq_tem2_siv_decrypt(dec, key, nonce, ad, ad_len, dec, len, tag) == 1);
            check_bytes_eq("TEM2SIVDecrypt in-place pt match", dec, pt, len);
        }

        /* Negative tamper tests: tag, ciphertext, ad, nonce, key */
        tag[idx % 32U] ^= 0x01U;
        memset(dec, 0x55, sizeof(dec));
        check_true("TEM2SIVDecrypt rejects tampered tag",
                   areion_pq_tem2_siv_decrypt(dec, key, nonce, ad, ad_len, ct, len, tag) == 0);
        for (i = 0U; i < len; i++) {
            if (dec[i] != 0U) {
                (void)fprintf(stderr, "FAIL: TEM2SIVDecrypt did not zeroize output on tag failure\n");
                g_failures++;
                break;
            }
        }
        tag[idx % 32U] ^= 0x01U;

        if (len > 0U) {
            ct[len / 2U] ^= 0x80U;
            memset(dec, 0x55, sizeof(dec));
            check_true("TEM2SIVDecrypt rejects tampered ciphertext",
                       areion_pq_tem2_siv_decrypt(dec, key, nonce, ad, ad_len, ct, len, tag) == 0);
            for (i = 0U; i < len; i++) {
                if (dec[i] != 0U) {
                    (void)fprintf(stderr, "FAIL: TEM2SIVDecrypt did not zeroize output on ct tamper\n");
                    g_failures++;
                    break;
                }
            }
            ct[len / 2U] ^= 0x80U;
        }

        if (ad_len > 0U) {
            ad[0] ^= 0x01U;
            check_true("TEM2SIVDecrypt rejects tampered AD",
                       areion_pq_tem2_siv_decrypt(dec, key, nonce, ad, ad_len, ct, len, tag) == 0);
            ad[0] ^= 0x01U;
        }
    }

    /* HPKE deterministic seal/open + tamper tests */
    fill_pattern(shared, sizeof(shared), 0x94U);
    fill_pattern(info, sizeof(info), 0x95U);
    areion_pq_hpke_derive_keys(dem_key, base_nonce, shared, info, sizeof(info));
    areion_pq_hpke_seal_det(ct, tag, shared, info, sizeof(info), 42ULL, ad, 37U, pt, 145U);
    memset(dec, 0x77, sizeof(dec));
    check_true("HPKEOpenDet valid",
               areion_pq_hpke_open_det(dec, shared, info, sizeof(info), 42ULL, ad, 37U, ct, 145U, tag) == 1);
    check_bytes_eq("HPKEOpenDet plaintext match", dec, pt, 145U);

    /* Wrong sequence number must fail authentication and zeroize dec */
    memset(dec, 0x77, sizeof(dec));
    check_true("HPKEOpenDet rejects wrong seq",
               areion_pq_hpke_open_det(dec, shared, info, sizeof(info), 43ULL, ad, 37U, ct, 145U, tag) == 0);
    for (i = 0U; i < 145U; i++) {
        if (dec[i] != 0U) {
            (void)fprintf(stderr, "FAIL: HPKEOpenDet did not zeroize output on failure\n");
            g_failures++;
            break;
        }
    }
}

/* =========================================================================
 * 4. FAEST-Areion & SLH-DSA-Areion Sign/Verify + Negative Tamper + Wrappers
 * ========================================================================= */

static void test_signatures_and_wrappers(int run_slow_s_variants) {
    uint8_t seed32[32], seed48[48], seed64[64], seed96[96];
    uint8_t opt16[16], opt32[32], msg[29];
    uint8_t pk48[48], sk64[64], pk64[64], sk96[96], pk32[32], sk128[128];
    static uint8_t sig_buf[50000];
    static uint8_t sm_buf[50100];
    static uint8_t open_buf[50100];
    unsigned long long smlen = 0ULL, mlen_out = 0ULL;
    size_t pq_siglen = 0U, pq_smlen = 0U, pq_mlen = 0U;

    fill_pattern(seed32, sizeof(seed32), 0xA0U);
    fill_pattern(seed48, sizeof(seed48), 0xA1U);
    fill_pattern(seed64, sizeof(seed64), 0xA2U);
    fill_pattern(seed96, sizeof(seed96), 0xA3U);
    fill_pattern(opt16, sizeof(opt16), 0xA4U);
    fill_pattern(opt32, sizeof(opt32), 0xA5U);
    fill_pattern(msg, sizeof(msg), 0xA6U);

    /* 4a. FAEST-128f + SUPERCOP + PQClean + Tamper checks */
    areion_pq_faest_keygen128f(pk48, sk64, seed32);
    areion_pq_faest_sign128f(sig_buf, sk64, msg, sizeof(msg), opt16);
    check_true("FAEST-128f verify valid", areion_pq_faest_verify128f(pk48, msg, sizeof(msg), sig_buf) == 1);
    msg[0] ^= 0x01U;
    check_true("FAEST-128f rejects tampered msg", areion_pq_faest_verify128f(pk48, msg, sizeof(msg), sig_buf) == 0);
    msg[0] ^= 0x01U;
    pk48[20] ^= 0x01U;
    check_true("FAEST-128f rejects tampered pk", areion_pq_faest_verify128f(pk48, msg, sizeof(msg), sig_buf) == 0);
    pk48[20] ^= 0x01U;
    sig_buf[0] ^= 0x01U;
    check_true("FAEST-128f rejects tampered salt", areion_pq_faest_verify128f(pk48, msg, sizeof(msg), sig_buf) == 0);
    sig_buf[0] ^= 0x01U;
    sig_buf[200] ^= 0x01U;
    check_true("FAEST-128f rejects tampered witness", areion_pq_faest_verify128f(pk48, msg, sizeof(msg), sig_buf) == 0);
    sig_buf[200] ^= 0x01U;
    sig_buf[AREION_PQ_FAEST128F_SIG_SIZE - 1] ^= 0x01U;
    check_true("FAEST-128f rejects tampered com_delta", areion_pq_faest_verify128f(pk48, msg, sizeof(msg), sig_buf) == 0);
    sig_buf[AREION_PQ_FAEST128F_SIG_SIZE - 1] ^= 0x01U;

    g_failures += supercop_faest128f_keypair(pk48, sk64);
    g_failures += supercop_faest128f_sign(sm_buf, &smlen, msg, sizeof(msg), sk64);
    check_true("SUPERCOP faest128f open", supercop_faest128f_open(open_buf, &mlen_out, sm_buf, smlen, pk48) == 0);
    check_true("SUPERCOP faest128f mlen", mlen_out == sizeof(msg));
    check_bytes_eq("SUPERCOP faest128f msg", open_buf, msg, sizeof(msg));

    g_failures += PQCLEAN_FAESTAREION128F_CLEAN_crypto_sign_keypair(pk48, sk64);
    g_failures += PQCLEAN_FAESTAREION128F_CLEAN_crypto_sign_signature(sig_buf, &pq_siglen, msg, sizeof(msg), sk64);
    check_true("PQClean faest-128f verify",
               PQCLEAN_FAESTAREION128F_CLEAN_crypto_sign_verify(sig_buf, pq_siglen, msg, sizeof(msg), pk48) == 0);
    g_failures += PQCLEAN_FAESTAREION128F_CLEAN_crypto_sign(sm_buf, &pq_smlen, msg, sizeof(msg), sk64);
    check_true("PQClean faest-128f open",
               PQCLEAN_FAESTAREION128F_CLEAN_crypto_sign_open(open_buf, &pq_mlen, sm_buf, pq_smlen, pk48) == 0);

    /* 4b. FAEST-256f + PQClean + Tamper checks */
    areion_pq_faest_keygen256f(pk64, sk96, seed64);
    areion_pq_faest_sign256f(sig_buf, sk96, msg, sizeof(msg), opt32);
    check_true("FAEST-256f verify valid", areion_pq_faest_verify256f(pk64, msg, sizeof(msg), sig_buf) == 1);
    sig_buf[500] ^= 0x04U;
    check_true("FAEST-256f rejects tampered sig", areion_pq_faest_verify256f(pk64, msg, sizeof(msg), sig_buf) == 0);
    sig_buf[500] ^= 0x04U;
    check_true("PQClean faest-256f verify",
               PQCLEAN_FAESTAREION256F_CLEAN_crypto_sign_verify(
                   sig_buf, AREION_PQ_FAEST256F_SIG_SIZE, msg, sizeof(msg), pk64) == 0);

    /* 4c. FAEST-EM2-256f + Tamper checks */
    areion_pq_faest_em2_keygen256f(pk64, sk96, seed64);
    areion_pq_faest_em2_sign256f(sig_buf, sk96, msg, sizeof(msg), opt32);
    check_true("FAEST-EM2-256f verify valid", areion_pq_faest_em2_verify256f(pk64, msg, sizeof(msg), sig_buf) == 1);
    sig_buf[400] ^= 0x02U;
    check_true("FAEST-EM2-256f rejects tampered sig", areion_pq_faest_em2_verify256f(pk64, msg, sizeof(msg), sig_buf) == 0);
    sig_buf[400] ^= 0x02U;

    /* 4d. SLH-DSA-128f + SUPERCOP + PQClean + Tamper checks */
    areion_pq_slhdsa_keygen128f(pk32, sk64, seed48);
    areion_pq_slhdsa_sign128f(sig_buf, sk64, msg, sizeof(msg), opt16);
    check_true("SLH-DSA-128f verify valid", areion_pq_slhdsa_verify128f(pk32, msg, sizeof(msg), sig_buf) == 1);
    sig_buf[100] ^= 0x01U;
    check_true("SLH-DSA-128f rejects tampered FORS", areion_pq_slhdsa_verify128f(pk32, msg, sizeof(msg), sig_buf) == 0);
    sig_buf[100] ^= 0x01U;
    sig_buf[AREION_PQ_SLHDSA128F_SIG_SIZE - 10] ^= 0x01U;
    check_true("SLH-DSA-128f rejects tampered HT", areion_pq_slhdsa_verify128f(pk32, msg, sizeof(msg), sig_buf) == 0);
    sig_buf[AREION_PQ_SLHDSA128F_SIG_SIZE - 10] ^= 0x01U;
    check_true("PQClean slh-dsa-128f verify",
               PQCLEAN_SLHDSAAREION128F_CLEAN_crypto_sign_verify(
                   sig_buf, AREION_PQ_SLHDSA128F_SIG_SIZE, msg, sizeof(msg), pk32) == 0);

    /* 4e. SLH-DSA-256f & SLH-DSA-TEM-256f + PQClean + Tamper checks */
    areion_pq_slhdsa_keygen256f(pk64, sk128, seed96);
    areion_pq_slhdsa_sign256f(sig_buf, sk128, msg, sizeof(msg), opt32);
    check_true("SLH-DSA-256f verify valid", areion_pq_slhdsa_verify256f(pk64, msg, sizeof(msg), sig_buf) == 1);
    sig_buf[1024] ^= 0x08U;
    check_true("SLH-DSA-256f rejects tampered sig", areion_pq_slhdsa_verify256f(pk64, msg, sizeof(msg), sig_buf) == 0);
    sig_buf[1024] ^= 0x08U;
    check_true("PQClean slh-dsa-256f verify",
               PQCLEAN_SLHDSAAREION256F_CLEAN_crypto_sign_verify(
                   sig_buf, AREION_PQ_SLHDSA256F_SIG_SIZE, msg, sizeof(msg), pk64) == 0);

    areion_pq_slhdsa_tem_keygen256f(pk64, sk128, seed96);
    areion_pq_slhdsa_tem_sign256f(sig_buf, sk128, msg, sizeof(msg), opt32);
    check_true("SLH-DSA-TEM-256f verify valid", areion_pq_slhdsa_tem_verify256f(pk64, msg, sizeof(msg), sig_buf) == 1);
    sig_buf[2048] ^= 0x10U;
    check_true("SLH-DSA-TEM-256f rejects tampered sig", areion_pq_slhdsa_tem_verify256f(pk64, msg, sizeof(msg), sig_buf) == 0);
    sig_buf[2048] ^= 0x10U;

    /* 4f. SUPERCOP AEAD wrapper check */
    {
        uint8_t aead_k[128], aead_npub[32], aead_ad[24], aead_ct[64], aead_dec[64];
        unsigned long long clen = 0ULL, dlen = 0ULL;
        fill_pattern(aead_k, sizeof(aead_k), 0xB0U);
        fill_pattern(aead_npub, sizeof(aead_npub), 0xB1U);
        fill_pattern(aead_ad, sizeof(aead_ad), 0xB2U);
        g_failures += supercop_tem2_siv512_encrypt(
            aead_ct, &clen, msg, sizeof(msg), aead_ad, sizeof(aead_ad), NULL, aead_npub, aead_k);
        check_true("SUPERCOP AEAD decrypt",
                   supercop_tem2_siv512_decrypt(aead_dec, &dlen, NULL, aead_ct, clen, aead_ad, sizeof(aead_ad), aead_npub, aead_k) == 0);
        check_bytes_eq("SUPERCOP AEAD msg", aead_dec, msg, sizeof(msg));
        aead_ct[0] ^= 0x01U;
        check_true("SUPERCOP AEAD tamper reject",
                   supercop_tem2_siv512_decrypt(aead_dec, &dlen, NULL, aead_ct, clen, aead_ad, sizeof(aead_ad), aead_npub, aead_k) == -1);
    }

    if (run_slow_s_variants) {
        /* FAEST-128s, FAEST-256s, FAEST-EM2-256s, SLH-DSA-128s, SLH-DSA-256s */
        g_failures += supercop_faest128s_seed_keypair(pk48, sk64, seed32);
        areion_pq_faest_sign128s(sig_buf, sk64, msg, sizeof(msg), opt16);
        check_true("FAEST-128s verify valid", areion_pq_faest_verify128s(pk48, msg, sizeof(msg), sig_buf) == 1);
        sig_buf[128] ^= 0x01U;
        check_true("FAEST-128s rejects tampered sig", areion_pq_faest_verify128s(pk48, msg, sizeof(msg), sig_buf) == 0);

        g_failures += supercop_faest256s_seed_keypair(pk64, sk96, seed64);
        areion_pq_faest_sign256s(sig_buf, sk96, msg, sizeof(msg), opt32);
        check_true("FAEST-256s verify valid", areion_pq_faest_verify256s(pk64, msg, sizeof(msg), sig_buf) == 1);
        sig_buf[128] ^= 0x01U;
        check_true("FAEST-256s rejects tampered sig", areion_pq_faest_verify256s(pk64, msg, sizeof(msg), sig_buf) == 0);

        g_failures += supercop_faest_em2_256s_seed_keypair(pk64, sk96, seed64);
        areion_pq_faest_em2_sign256s(sig_buf, sk96, msg, sizeof(msg), opt32);
        check_true("FAEST-EM2-256s verify valid", areion_pq_faest_em2_verify256s(pk64, msg, sizeof(msg), sig_buf) == 1);
        sig_buf[128] ^= 0x01U;
        check_true("FAEST-EM2-256s rejects tampered sig", areion_pq_faest_em2_verify256s(pk64, msg, sizeof(msg), sig_buf) == 0);

        g_failures += supercop_slhdsa128s_seed_keypair(pk32, sk64, seed48);
        areion_pq_slhdsa_sign128s(sig_buf, sk64, msg, sizeof(msg), opt16);
        check_true("SLH-DSA-128s verify valid", areion_pq_slhdsa_verify128s(pk32, msg, sizeof(msg), sig_buf) == 1);
        sig_buf[128] ^= 0x01U;
        check_true("SLH-DSA-128s rejects tampered sig", areion_pq_slhdsa_verify128s(pk32, msg, sizeof(msg), sig_buf) == 0);

        g_failures += supercop_slhdsa256s_seed_keypair(pk64, sk128, seed96);
        areion_pq_slhdsa_sign256s(sig_buf, sk128, msg, sizeof(msg), opt32);
        check_true("SLH-DSA-256s verify valid", areion_pq_slhdsa_verify256s(pk64, msg, sizeof(msg), sig_buf) == 1);
        sig_buf[128] ^= 0x01U;
        check_true("SLH-DSA-256s rejects tampered sig", areion_pq_slhdsa_verify256s(pk64, msg, sizeof(msg), sig_buf) == 0);
    } else {
        /* Fast keygen + negative verify check on s-variants */
        volatile unsigned long long short_len = 16ULL;
        g_failures += supercop_faest128s_keypair(pk48, sk64);
        g_failures += supercop_faest256s_keypair(pk64, sk96);
        g_failures += supercop_faest_em2_256s_keypair(pk64, sk96);
        check_true("SUPERCOP slhdsa128s reject short sig",
                   supercop_slhdsa128s_verify(sig_buf, short_len, msg, sizeof(msg), pk32) == -1);
        check_true("SUPERCOP slhdsa256s reject short sig",
                   supercop_slhdsa256s_verify(sig_buf, short_len, msg, sizeof(msg), pk64) == -1);
        g_failures += supercop_faest_em2_256f_keypair(pk64, sk96);
        g_failures += supercop_slhdsa128f_keypair(pk32, sk64);
        g_failures += supercop_slhdsa256f_keypair(pk64, sk128);
        g_failures += PQCLEAN_FAESTAREION256F_CLEAN_crypto_sign_keypair(pk64, sk96);
        g_failures += PQCLEAN_SLHDSAAREION128F_CLEAN_crypto_sign_keypair(pk32, sk64);
        g_failures += PQCLEAN_SLHDSAAREION256F_CLEAN_crypto_sign_keypair(pk64, sk128);
    }
}

/* =========================================================================
 * 5. Cross-Tier & Cross-Language KAT Dumper + Pairwise Tier Matrix
 * ========================================================================= */

#define AREION_PQ_MAX_KAT_ENTRIES 96U

typedef struct {
    char name[40];
    uint8_t digest[64];
} pq_kat_entry_t;

typedef struct {
    const char *tier_name;
    areion_pq_tier_t tier_code;
    pq_kat_entry_t entries[AREION_PQ_MAX_KAT_ENTRIES];
    size_t count;
} pq_tier_kat_set_t;

static pq_tier_kat_set_t g_tier_kats[6];
static pq_tier_kat_set_t *g_kat_capture = NULL;

static void record_kat(const char *name, const uint8_t *buf, size_t len) {
    if (g_kat_capture != NULL) {
        if (g_kat_capture->count < AREION_PQ_MAX_KAT_ENTRIES) {
            pq_kat_entry_t *e = &g_kat_capture->entries[g_kat_capture->count++];
            size_t nlen = strlen(name);
            if (nlen >= sizeof(e->name)) {
                nlen = sizeof(e->name) - 1U;
            }
            memcpy(e->name, name, nlen);
            e->name[nlen] = '\0';
            areion_pq_kdf_expand(e->digest, 64U, buf, len, (const uint8_t *)name, nlen);
        }
    } else {
        size_t i;
        printf("%s=", name);
        for (i = 0U; i < len; i++) {
            printf("%02x", buf[i]);
        }
        printf("\n");
    }
}

static void record_kat_bool(const char *name, int ok) {
    uint8_t b = (ok != 0) ? 1U : 0U;
    record_kat(name, &b, 1U);
}

static int dump_kat_for_tier(const char *tier_arg, int include_s_variants) {
    static uint8_t sig_buf[50000];
    uint8_t gf256_tbl[256 * 5];
    uint8_t a16[16], b16[16], chi16[16], out16[16];
    uint8_t poly_a[4][16], poly_b[4][16];
    uint8_t a32[32], b32[32], k32[32], out32[32];
    uint8_t m32[32], k1_32[32], k2_32[32], c256[32], w256[288], wem2[576];
    uint8_t seed32[32], opt32[32], seed64[64], opt16[16], msg33[33];
    uint8_t pk48[48], sk64[64], pk64[64], sk96[96];
    uint8_t pk_seed16[16], sk_seed16[16], m1_16[16], m2_16[16];
    uint8_t pk_seed32[32], sk_seed32[32], adrs32[32], m1_32[32], m2_32[32];
    uint8_t kpub128[64], ksk128[64], kpub256[64], ksk256[64];
    uint8_t adrs4[4][32], prf4[4][32];
    uint8_t blks16[5][16], blks32[5][32];
    uint8_t slh_seed48[48], slh_seed96[96], slh_pk32[32], slh_sk64[64], slh_pk64[64], slh_sk128[128];
    uint8_t kdf_sec[48], kdf_ctx[29], kdf_out[300];
    uint8_t siv_key[128], siv_nonce[32], siv_ad[300], siv_pt[333], siv_ct[333], siv_dec[333], siv_tag[32];
    uint8_t hpke_shared[32], hpke_info[25], hpke_ad[37], hpke_pt[145], hpke_ct[145], hpke_dec[145];
    uint8_t dem_key[128], base_nonce[32];
    size_t i;

    if (tier_arg != NULL) {
        if (areion_pq_set_tier(tier_arg) != 0) {
            return 2;
        }
    }

    /* 1. Finite field & witness primitives */
    for (i = 0U; i < 256U; i++) {
        uint8_t a = (uint8_t)i;
        uint8_t b = (uint8_t)((i * 17U + 3U) & 0xFFU);
        gf256_tbl[i * 5U + 0U] = areion_pq_gf256_mul(a, b);
        gf256_tbl[i * 5U + 1U] = areion_pq_gf256_sq(a);
        gf256_tbl[i * 5U + 2U] = areion_pq_gf256_inv(a);
        gf256_tbl[i * 5U + 3U] = areion_pq_gf256_affine(a);
        gf256_tbl[i * 5U + 4U] = areion_pq_gf256_affine_inv(a);
    }
    record_kat("GF256Table", gf256_tbl, sizeof(gf256_tbl));

    fill_pattern(a16, 16U, 0x01U);
    fill_pattern(b16, 16U, 0x02U);
    areion_pq_gf128_mul(out16, a16, b16);
    record_kat("GF128Mul", out16, 16U);

    for (i = 0U; i < 4U; i++) {
        fill_pattern(poly_a[i], 16U, (uint8_t)(0x03U + i));
        fill_pattern(poly_b[i], 16U, (uint8_t)(0x07U + i));
    }
    fill_pattern(chi16, 16U, 0x0BU);
    areion_pq_gf128_polymac(out16, &poly_a[0][0], &poly_b[0][0], 4U, chi16);
    record_kat("GF128PolyMAC", out16, 16U);

    fill_pattern(a32, 32U, 0x0CU);
    fill_pattern(b32, 32U, 0x0DU);
    areion_pq_gf256_field_mul(out32, a32, b32);
    record_kat("GF256FieldMul", out32, 32U);

    fill_pattern(a32, 32U, 0x0EU);
    fill_pattern(b32, 32U, 0x0FU);
    areion_pq_mul_ortho256(out32, a32, b32);
    record_kat("MulOrtho256", out32, 32U);

    fill_pattern(k32, 32U, 0x10U);
    areion_pq_ortho_sigma256(out32, k32);
    record_kat("OrthoSigma256", out32, 32U);

    fill_pattern(m32, 32U, 0x11U);
    fill_pattern(k1_32, 32U, 0x12U);
    fill_pattern(k2_32, 32U, 0x13U);
    areion_pq_extract_witness256(c256, w256, m32, k1_32, k2_32);
    record_kat("ExtractWitness256_C", c256, 32U);
    record_kat("ExtractWitness256_W", w256, 288U);
    record_kat_bool("VerifyWitness256", areion_pq_verify_witness256(m32, c256, k1_32, k2_32, w256));

    fill_pattern(m32, 32U, 0x14U);
    fill_pattern(k1_32, 32U, 0x15U);
    fill_pattern(k2_32, 32U, 0x16U);
    areion_pq_extract_witness256_p2(c256, w256, m32, k1_32, k2_32);
    record_kat("ExtractWitness256P2_C", c256, 32U);
    record_kat("ExtractWitness256P2_W", w256, 288U);
    record_kat_bool("VerifyWitness256P2", areion_pq_verify_witness256_p2(m32, c256, k1_32, k2_32, w256));

    fill_pattern(m32, 32U, 0x17U);
    fill_pattern(k1_32, 32U, 0x18U);
    fill_pattern(k2_32, 32U, 0x19U);
    areion_pq_extract_witness_em2_256(c256, wem2, m32, k1_32, k2_32);
    record_kat("ExtractWitnessEM2_256_C", c256, 32U);
    record_kat("ExtractWitnessEM2_256_W", wem2, 576U);
    record_kat_bool("VerifyWitnessEM2_256", areion_pq_verify_witness_em2_256(m32, c256, k1_32, k2_32, wem2));

    /* 2. Track 1: FAEST-Areion */
    if (include_s_variants) {
        fill_pattern(seed32, 32U, 0x20U);
        fill_pattern(msg33, 33U, 0x21U);
        fill_pattern(opt16, 16U, 0x22U);
        areion_pq_faest_keygen128s(pk48, sk64, seed32);
        areion_pq_faest_sign128s(sig_buf, sk64, msg33, 33U, opt16);
        record_kat("FAEST128s_PK", pk48, 48U);
        record_kat("FAEST128s_SK", sk64, 64U);
        record_kat("FAEST128s_Sig", sig_buf, AREION_PQ_FAEST128S_SIG_SIZE);
        record_kat_bool("FAEST128s_Verify", areion_pq_faest_verify128s(pk48, msg33, 33U, sig_buf));
    }

    fill_pattern(seed32, 32U, 0x23U);
    fill_pattern(msg33, 33U, 0x24U);
    fill_pattern(opt16, 16U, 0x25U);
    areion_pq_faest_keygen128f(pk48, sk64, seed32);
    areion_pq_faest_sign128f(sig_buf, sk64, msg33, 33U, opt16);
    record_kat("FAEST128f_PK", pk48, 48U);
    record_kat("FAEST128f_SK", sk64, 64U);
    record_kat("FAEST128f_Sig", sig_buf, AREION_PQ_FAEST128F_SIG_SIZE);
    record_kat_bool("FAEST128f_Verify", areion_pq_faest_verify128f(pk48, msg33, 33U, sig_buf));

    if (include_s_variants) {
        fill_pattern(seed64, 64U, 0x26U);
        fill_pattern(msg33, 33U, 0x27U);
        fill_pattern(opt32, 32U, 0x28U);
        areion_pq_faest_keygen256s(pk64, sk96, seed64);
        areion_pq_faest_sign256s(sig_buf, sk96, msg33, 33U, opt32);
        record_kat("FAEST256s_PK", pk64, 64U);
        record_kat("FAEST256s_SK", sk96, 96U);
        record_kat("FAEST256s_Sig", sig_buf, AREION_PQ_FAEST256S_SIG_SIZE);
        record_kat_bool("FAEST256s_Verify", areion_pq_faest_verify256s(pk64, msg33, 33U, sig_buf));
    }

    fill_pattern(seed64, 64U, 0x29U);
    fill_pattern(msg33, 33U, 0x2AU);
    fill_pattern(opt32, 32U, 0x2BU);
    areion_pq_faest_keygen256f(pk64, sk96, seed64);
    areion_pq_faest_sign256f(sig_buf, sk96, msg33, 33U, opt32);
    record_kat("FAEST256f_PK", pk64, 64U);
    record_kat("FAEST256f_SK", sk96, 96U);
    record_kat("FAEST256f_Sig", sig_buf, AREION_PQ_FAEST256F_SIG_SIZE);
    record_kat_bool("FAEST256f_Verify", areion_pq_faest_verify256f(pk64, msg33, 33U, sig_buf));

    if (include_s_variants) {
        fill_pattern(seed64, 64U, 0x2CU);
        fill_pattern(msg33, 33U, 0x2DU);
        fill_pattern(opt32, 32U, 0x2EU);
        areion_pq_faest_em2_keygen256s(pk64, sk96, seed64);
        areion_pq_faest_em2_sign256s(sig_buf, sk96, msg33, 33U, opt32);
        record_kat("FAESTEM2_256s_PK", pk64, 64U);
        record_kat("FAESTEM2_256s_SK", sk96, 96U);
        record_kat("FAESTEM2_256s_Sig", sig_buf, AREION_PQ_FAEST_EM2_256S_SIG_SIZE);
        record_kat_bool("FAESTEM2_256s_Verify", areion_pq_faest_em2_verify256s(pk64, msg33, 33U, sig_buf));
    }

    fill_pattern(seed64, 64U, 0x2FU);
    fill_pattern(msg33, 33U, 0x30U);
    fill_pattern(opt32, 32U, 0x31U);
    areion_pq_faest_em2_keygen256f(pk64, sk96, seed64);
    areion_pq_faest_em2_sign256f(sig_buf, sk96, msg33, 33U, opt32);
    record_kat("FAESTEM2_256f_PK", pk64, 64U);
    record_kat("FAESTEM2_256f_SK", sk96, 96U);
    record_kat("FAESTEM2_256f_Sig", sig_buf, AREION_PQ_FAEST_EM2_256F_SIG_SIZE);
    record_kat_bool("FAESTEM2_256f_Verify", areion_pq_faest_em2_verify256f(pk64, msg33, 33U, sig_buf));

    /* 3. Track 2: SLH-DSA-Areion */
    fill_pattern(pk_seed16, 16U, 0x40U);
    fill_pattern(sk_seed16, 16U, 0x41U);
    areion_pq_slh_expand_seed128(kpub128, ksk128, pk_seed16, sk_seed16);
    record_kat("SLHExpandSeed128_KPub", kpub128, 64U);
    record_kat("SLHExpandSeed128_KSK", ksk128, 64U);

    fill_pattern(pk_seed32, 32U, 0x42U);
    fill_pattern(sk_seed32, 32U, 0x43U);
    areion_pq_slh_expand_seed256(kpub256, ksk256, pk_seed32, sk_seed32);
    record_kat("SLHExpandSeed256_KPub", kpub256, 64U);
    record_kat("SLHExpandSeed256_KSK", ksk256, 64U);

    fill_pattern(adrs32, 32U, 0x44U);
    areion_pq_slh_compact_adrs(out16, adrs32);
    record_kat("SLHCompactADRS", out16, 16U);

    areion_pq_slh_prf128(out16, ksk128, adrs32);
    record_kat("SLHPRF128", out16, 16U);
    areion_pq_slh_prf256(out32, ksk256, adrs32);
    record_kat("SLHPRF256", out32, 32U);

    for (i = 0U; i < 4U; i++) {
        fill_pattern(adrs4[i], 32U, (uint8_t)(0x45U + i));
    }
    areion_pq_slh_prf256x4(prf4, ksk256, adrs4);
    record_kat("SLHPRF256x4", &prf4[0][0], 128U);

    fill_pattern(m1_16, 16U, 0x49U);
    fill_pattern(m1_32, 32U, 0x4AU);
    fill_pattern(m2_16, 16U, 0x4BU);
    fill_pattern(m2_32, 32U, 0x4CU);
    areion_pq_slh_f128(out16, pk_seed16, kpub128, adrs32, m1_16);
    record_kat("SLHF128", out16, 16U);
    areion_pq_slh_f256(out32, kpub256, adrs32, m1_32);
    record_kat("SLHF256", out32, 32U);
    areion_pq_slh_f_tem256(out32, kpub256, adrs32, m1_32);
    record_kat("SLHFTEM256", out32, 32U);
    areion_pq_slh_h128(out16, pk_seed16, kpub128, adrs32, m1_16, m2_16);
    record_kat("SLHH128", out16, 16U);
    areion_pq_slh_h256(out32, kpub256, adrs32, m1_32, m2_32);
    record_kat("SLHH256", out32, 32U);

    for (i = 0U; i < 5U; i++) {
        fill_pattern(blks16[i], 16U, (uint8_t)(0x50U + i));
        fill_pattern(blks32[i], 32U, (uint8_t)(0x55U + i));
    }
    areion_pq_slh_tl128(out16, kpub128, adrs32, &blks16[0][0], 5U);
    record_kat("SLHTl128", out16, 16U);
    areion_pq_slh_tl256(out32, kpub256, adrs32, &blks32[0][0], 5U);
    record_kat("SLHTl256", out32, 32U);

    fill_pattern(slh_seed48, 48U, 0x60U);
    fill_pattern(msg33, 33U, 0x61U);
    fill_pattern(opt16, 16U, 0x62U);
    areion_pq_slhdsa_keygen128f(slh_pk32, slh_sk64, slh_seed48);
    areion_pq_slhdsa_sign128f(sig_buf, slh_sk64, msg33, 33U, opt16);
    record_kat("SLHDSA128f_PK", slh_pk32, 32U);
    record_kat("SLHDSA128f_SK", slh_sk64, 64U);
    record_kat("SLHDSA128f_Sig", sig_buf, AREION_PQ_SLHDSA128F_SIG_SIZE);
    record_kat_bool("SLHDSA128f_Verify", areion_pq_slhdsa_verify128f(slh_pk32, msg33, 33U, sig_buf));

    fill_pattern(slh_seed96, 96U, 0x63U);
    fill_pattern(msg33, 33U, 0x64U);
    fill_pattern(opt32, 32U, 0x65U);
    areion_pq_slhdsa_keygen256f(slh_pk64, slh_sk128, slh_seed96);
    areion_pq_slhdsa_sign256f(sig_buf, slh_sk128, msg33, 33U, opt32);
    record_kat("SLHDSA256f_PK", slh_pk64, 64U);
    record_kat("SLHDSA256f_SK", slh_sk128, 128U);
    record_kat("SLHDSA256f_Sig", sig_buf, AREION_PQ_SLHDSA256F_SIG_SIZE);
    record_kat_bool("SLHDSA256f_Verify", areion_pq_slhdsa_verify256f(slh_pk64, msg33, 33U, sig_buf));

    fill_pattern(slh_seed96, 96U, 0x66U);
    fill_pattern(msg33, 33U, 0x67U);
    fill_pattern(opt32, 32U, 0x68U);
    areion_pq_slhdsa_tem_keygen256f(slh_pk64, slh_sk128, slh_seed96);
    areion_pq_slhdsa_tem_sign256f(sig_buf, slh_sk128, msg33, 33U, opt32);
    record_kat("SLHDSATEM256f_PK", slh_pk64, 64U);
    record_kat("SLHDSATEM256f_SK", slh_sk128, 128U);
    record_kat("SLHDSATEM256f_Sig", sig_buf, AREION_PQ_SLHDSA_TEM256F_SIG_SIZE);
    record_kat_bool("SLHDSATEM256f_Verify", areion_pq_slhdsa_tem_verify256f(slh_pk64, msg33, 33U, sig_buf));

    if (g_full_mode != 0) {
        fill_pattern(slh_seed48, 48U, 0x69U);
        fill_pattern(msg33, 33U, 0x6AU);
        fill_pattern(opt16, 16U, 0x6BU);
        areion_pq_slhdsa_keygen128s(slh_pk32, slh_sk64, slh_seed48);
        areion_pq_slhdsa_sign128s(sig_buf, slh_sk64, msg33, 33U, opt16);
        record_kat("SLHDSA128s_PK", slh_pk32, 32U);
        record_kat("SLHDSA128s_SK", slh_sk64, 64U);
        record_kat("SLHDSA128s_Sig", sig_buf, AREION_PQ_SLHDSA128S_SIG_SIZE);
        record_kat_bool("SLHDSA128s_Verify", areion_pq_slhdsa_verify128s(slh_pk32, msg33, 33U, sig_buf));

        fill_pattern(slh_seed96, 96U, 0x6CU);
        fill_pattern(msg33, 33U, 0x6DU);
        fill_pattern(opt32, 32U, 0x6EU);
        areion_pq_slhdsa_keygen256s(slh_pk64, slh_sk128, slh_seed96);
        areion_pq_slhdsa_sign256s(sig_buf, slh_sk128, msg33, 33U, opt32);
        record_kat("SLHDSA256s_PK", slh_pk64, 64U);
        record_kat("SLHDSA256s_SK", slh_sk128, 128U);
        record_kat("SLHDSA256s_Sig", sig_buf, AREION_PQ_SLHDSA256S_SIG_SIZE);
        record_kat_bool("SLHDSA256s_Verify", areion_pq_slhdsa_verify256s(slh_pk64, msg33, 33U, sig_buf));
    }

    /* 4. Track 3: Areion-HPKE, KDF & TEM2-SIV */
    fill_pattern(kdf_sec, sizeof(kdf_sec), 0x70U);
    fill_pattern(kdf_ctx, sizeof(kdf_ctx), 0x71U);
    areion_pq_kdf_expand(kdf_out, sizeof(kdf_out), kdf_sec, sizeof(kdf_sec), kdf_ctx, sizeof(kdf_ctx));
    record_kat("KDFExpand", kdf_out, sizeof(kdf_out));

    fill_pattern(siv_key, sizeof(siv_key), 0x72U);
    fill_pattern(siv_nonce, sizeof(siv_nonce), 0x73U);
    fill_pattern(siv_ad, sizeof(siv_ad), 0x74U);
    fill_pattern(siv_pt, sizeof(siv_pt), 0x75U);
    areion_pq_tem2_siv_encrypt(NULL, siv_tag, siv_key, siv_nonce, NULL, 0U, NULL, 0U);
    record_kat("TEM2SIV_Empty_Tag", siv_tag, 32U);
    areion_pq_tem2_siv_encrypt(siv_ct, siv_tag, siv_key, siv_nonce, siv_ad, sizeof(siv_ad), siv_pt, sizeof(siv_pt));
    record_kat("TEM2SIV_Full_CT", siv_ct, sizeof(siv_ct));
    record_kat("TEM2SIV_Full_Tag", siv_tag, 32U);
    record_kat_bool("TEM2SIV_Full_OK",
                    areion_pq_tem2_siv_decrypt(siv_dec, siv_key, siv_nonce, siv_ad, sizeof(siv_ad), siv_ct, sizeof(siv_ct), siv_tag));

    fill_pattern(hpke_shared, sizeof(hpke_shared), 0x76U);
    fill_pattern(hpke_info, sizeof(hpke_info), 0x77U);
    fill_pattern(hpke_ad, sizeof(hpke_ad), 0x78U);
    fill_pattern(hpke_pt, sizeof(hpke_pt), 0x79U);
    areion_pq_hpke_derive_keys(dem_key, base_nonce, hpke_shared, hpke_info, sizeof(hpke_info));
    record_kat("HPKEDeriveKeys_Key", dem_key, 128U);
    record_kat("HPKEDeriveKeys_Nonce", base_nonce, 32U);
    areion_pq_hpke_seal_det(hpke_ct, siv_tag, hpke_shared, hpke_info, sizeof(hpke_info),
                            0x0102030405060708ULL, hpke_ad, sizeof(hpke_ad), hpke_pt, sizeof(hpke_pt));
    record_kat("HPKESealDet_CT", hpke_ct, sizeof(hpke_ct));
    record_kat("HPKESealDet_Tag", siv_tag, 32U);
    record_kat_bool("HPKEOpenDet_OK",
                    areion_pq_hpke_open_det(hpke_dec, hpke_shared, hpke_info, sizeof(hpke_info),
                                            0x0102030405060708ULL, hpke_ad, sizeof(hpke_ad), hpke_ct, sizeof(hpke_ct), siv_tag));

    if (g_kat_capture == NULL) {
        printf("_meta_tier=%s\n", areion_pq_tier());
        printf("_meta_tier_code=%d\n", (int)areion_pq_tier_code());
    }
    return 0;
}

static void test_all_tiers_pairwise_matrix(void) {
    static const areion_pq_tier_t all_tiers[] = {
        AREION_PQ_TIER_PUREC,
        AREION_PQ_TIER_AESNI,
        AREION_PQ_TIER_VEX,
        AREION_PQ_TIER_VAESAVX2,
        AREION_PQ_TIER_AVX512,
        AREION_PQ_TIER_ARM64
    };
    static const char *const all_tier_names[] = {
        "purec", "aesni", "vex", "vaesavx2", "avx512", "arm64"
    };
    size_t num_supported = 0U;
    size_t t, a, b, k;

    for (t = 0U; t < sizeof(all_tiers) / sizeof(all_tiers[0]); t++) {
        areion_pq_tier_t tier = all_tiers[t];
        if (!areion_pq_tier_supported(tier)) {
            continue;
        }
        if (areion_pq_set_tier_code(tier) != 0) {
            (void)fprintf(stderr, "FAIL: areion_pq_set_tier_code(%d) failed\n", (int)tier);
            g_failures++;
            continue;
        }
        if (strcmp(areion_pq_tier(), all_tier_names[t]) != 0 || areion_pq_tier_code() != tier) {
            (void)fprintf(stderr, "FAIL: tier introspection mismatch for %s\n", all_tier_names[t]);
            g_failures++;
        }

        memset(&g_tier_kats[num_supported], 0, sizeof(g_tier_kats[0]));
        g_tier_kats[num_supported].tier_name = all_tier_names[t];
        g_tier_kats[num_supported].tier_code = tier;
        g_kat_capture = &g_tier_kats[num_supported];
        (void)dump_kat_for_tier(NULL, g_full_mode);
        g_kat_capture = NULL;
        num_supported++;
    }

    printf("Testing pairwise tier_A x tier_B KAT matrix (%u tiers, %u entries) ... ",
           (unsigned)num_supported, (unsigned)(num_supported > 0U ? g_tier_kats[0].count : 0U));
    (void)fflush(stdout);

    for (a = 0U; a < num_supported; a++) {
        for (b = 0U; b < num_supported; b++) {
            if (g_tier_kats[a].count != g_tier_kats[b].count) {
                (void)fprintf(stderr, "FAIL: tier KAT count mismatch [%s=%u vs %s=%u]\n",
                        g_tier_kats[a].tier_name, (unsigned)g_tier_kats[a].count,
                        g_tier_kats[b].tier_name, (unsigned)g_tier_kats[b].count);
                g_failures++;
                continue;
            }
            for (k = 0U; k < g_tier_kats[a].count; k++) {
                const pq_kat_entry_t *ea = &g_tier_kats[a].entries[k];
                const pq_kat_entry_t *eb = &g_tier_kats[b].entries[k];
                if (strcmp(ea->name, eb->name) != 0 || memcmp(ea->digest, eb->digest, 64U) != 0) {
                    (void)fprintf(stderr, "FAIL: pairwise tier matrix mismatch [%s <-> %s] on %s\n",
                            g_tier_kats[a].tier_name, g_tier_kats[b].tier_name, ea->name);
                    g_failures++;
                }
            }
        }
    }
    printf("OK\n");
}

/* =========================================================================
 * 6. Multi-Threaded Concurrency Stress Test (pthread)
 * ========================================================================= */

#if AREION_PQ_HAS_PTHREAD_TEST
typedef struct {
    uint8_t m[32];
    uint8_t k1[32];
    uint8_t k2[32];
    uint8_t exp_c[32];
    uint8_t exp_w[288];
    uint8_t siv_key[128];
    uint8_t siv_nonce[32];
    uint8_t siv_pt[64];
    uint8_t exp_ct[64];
    uint8_t exp_tag[32];
    int thread_errors;
} pq_mt_worker_ctx_t;

static void *pq_mt_worker_fn(void *arg) {
    pq_mt_worker_ctx_t *ctx = (pq_mt_worker_ctx_t *)arg;
    uint8_t c[32], w[288], ct[64], dec[64], tag[32];
    size_t iter;

    for (iter = 0U; iter < 64U; iter++) {
        const char *tname = areion_pq_tier();
        if (tname == NULL || tname[0] == '\0' || !areion_pq_tier_supported(areion_pq_tier_code())) {
            ctx->thread_errors++;
            break;
        }
        areion_pq_extract_witness256(c, w, ctx->m, ctx->k1, ctx->k2);
        if (memcmp(c, ctx->exp_c, 32U) != 0 || memcmp(w, ctx->exp_w, 288U) != 0) {
            ctx->thread_errors++;
            break;
        }
        if (areion_pq_verify_witness256(ctx->m, c, ctx->k1, ctx->k2, w) != 1) {
            ctx->thread_errors++;
            break;
        }
        areion_pq_tem2_siv_encrypt(ct, tag, ctx->siv_key, ctx->siv_nonce, ctx->m, 32U, ctx->siv_pt, 64U);
        if (memcmp(ct, ctx->exp_ct, 64U) != 0 || memcmp(tag, ctx->exp_tag, 32U) != 0) {
            ctx->thread_errors++;
            break;
        }
        if (areion_pq_tem2_siv_decrypt(dec, ctx->siv_key, ctx->siv_nonce, ctx->m, 32U, ct, 64U, tag) != 1 ||
            memcmp(dec, ctx->siv_pt, 64U) != 0) {
            ctx->thread_errors++;
            break;
        }
    }
    return NULL;
}

static void test_multithreaded_dispatch(void) {
    pthread_t threads[8];
    pq_mt_worker_ctx_t ctxs[8];
    size_t i;

    (void)areion_pq_set_tier_code(AREION_PQ_TIER_AUTO);
    for (i = 0U; i < 8U; i++) {
        memset(&ctxs[i], 0, sizeof(ctxs[i]));
        fill_pattern(ctxs[i].m, 32U, (uint8_t)(0x10U + i));
        fill_pattern(ctxs[i].k1, 32U, (uint8_t)(0x20U + i));
        fill_pattern(ctxs[i].k2, 32U, (uint8_t)(0x30U + i));
        areion_pq_extract_witness256(ctxs[i].exp_c, ctxs[i].exp_w, ctxs[i].m, ctxs[i].k1, ctxs[i].k2);
        fill_pattern(ctxs[i].siv_key, 128U, (uint8_t)(0x40U + i));
        fill_pattern(ctxs[i].siv_nonce, 32U, (uint8_t)(0x50U + i));
        fill_pattern(ctxs[i].siv_pt, 64U, (uint8_t)(0x60U + i));
        areion_pq_tem2_siv_encrypt(ctxs[i].exp_ct, ctxs[i].exp_tag,
                                   ctxs[i].siv_key, ctxs[i].siv_nonce, ctxs[i].m, 32U, ctxs[i].siv_pt, 64U);
    }

    printf("Testing 8-thread concurrent dispatch (%s) ... ", areion_pq_tier());
    (void)fflush(stdout);
    for (i = 0U; i < 8U; i++) {
        if (pthread_create(&threads[i], NULL, pq_mt_worker_fn, &ctxs[i]) != 0) {
            (void)fprintf(stderr, "FAIL: pthread_create failed on thread %u\n", (unsigned)i);
            g_failures++;
            return;
        }
    }
    for (i = 0U; i < 8U; i++) {
        (void)pthread_join(threads[i], NULL);
        if (ctxs[i].thread_errors != 0) {
            (void)fprintf(stderr, "FAIL: thread %u reported %d error(s)\n", (unsigned)i, ctxs[i].thread_errors);
            g_failures++;
        }
    }
    printf("OK\n");
}
#endif

/* =========================================================================
 * 7. Industrial Hardening: Unaligned, Win64 ABI, Timecop & dudect
 * ========================================================================= */

#if defined(_WIN64) && (defined(__x86_64__) || defined(_M_X64)) && (defined(__GNUC__) || defined(__clang__))
typedef void (*win64_cb_fn_t)(void *ctx);

typedef struct {
    win64_cb_fn_t fn;
    void *ctx;
    const uint8_t (*xmm_want)[16];
    const uint64_t *gpr_want;
    uint64_t *gpr_got;
    uint8_t (*xmm_got)[16];
} win64_check_args_t;

static AREION_PQ_NOINLINE void win64_invoke_check(const char *label, win64_cb_fn_t fn, void *ctx) {
    AREION_PQ_ALIGN64 uint8_t xmm_want[10][16];
    AREION_PQ_ALIGN64 uint8_t xmm_got[10][16];
    const uint64_t gpr_want[2] = { 0xCAFEBABE11223344ULL, 0xDEADBEEF55667788ULL };
    uint64_t gpr_got[2];
    win64_check_args_t args;
    size_t r, b;

    gpr_got[0] = 0ULL;
    gpr_got[1] = 0ULL;
    for (r = 0U; r < 10U; r++) {
        for (b = 0U; b < 16U; b++) {
            xmm_want[r][b] = (uint8_t)(0xA0U + r * 17U + b * 3U);
            xmm_got[r][b] = 0U;
        }
    }

    args.fn = fn;
    args.ctx = ctx;
    args.xmm_want = (const uint8_t (*)[16])xmm_want;
    args.gpr_want = gpr_want;
    args.gpr_got = gpr_got;
    args.xmm_got = xmm_got;

    __asm__ __volatile__(
        "movq 16(%%rbx), %%rax\n\t"
        "movdqu 0(%%rax), %%xmm6\n\t"
        "movdqu 16(%%rax), %%xmm7\n\t"
        "movdqu 32(%%rax), %%xmm8\n\t"
        "movdqu 48(%%rax), %%xmm9\n\t"
        "movdqu 64(%%rax), %%xmm10\n\t"
        "movdqu 80(%%rax), %%xmm11\n\t"
        "movdqu 96(%%rax), %%xmm12\n\t"
        "movdqu 112(%%rax), %%xmm13\n\t"
        "movdqu 128(%%rax), %%xmm14\n\t"
        "movdqu 144(%%rax), %%xmm15\n\t"
        "movq 24(%%rbx), %%rax\n\t"
        "movq 0(%%rax), %%rsi\n\t"
        "movq 8(%%rax), %%rdi\n\t"
        "subq $32, %%rsp\n\t"
        "movq 8(%%rbx), %%rcx\n\t"
        "call *0(%%rbx)\n\t"
        "addq $32, %%rsp\n\t"
        "movq 32(%%rbx), %%rax\n\t"
        "movq %%rsi, 0(%%rax)\n\t"
        "movq %%rdi, 8(%%rax)\n\t"
        "movq 40(%%rbx), %%rax\n\t"
        "movdqu %%xmm6, 0(%%rax)\n\t"
        "movdqu %%xmm7, 16(%%rax)\n\t"
        "movdqu %%xmm8, 32(%%rax)\n\t"
        "movdqu %%xmm9, 48(%%rax)\n\t"
        "movdqu %%xmm10, 64(%%rax)\n\t"
        "movdqu %%xmm11, 80(%%rax)\n\t"
        "movdqu %%xmm12, 96(%%rax)\n\t"
        "movdqu %%xmm13, 112(%%rax)\n\t"
        "movdqu %%xmm14, 128(%%rax)\n\t"
        "movdqu %%xmm15, 144(%%rax)\n\t"
        :
        : "b"(&args)
        : "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11",
          "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5",
          "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
          "cc", "memory"
    );

    if (gpr_got[0] != gpr_want[0] || gpr_got[1] != gpr_want[1]) {
        (void)fprintf(stderr, "FAIL [%s/_WIN64]: %s clobbered RSI/RDI\n", areion_pq_tier(), label);
        g_failures++;
    }
    if (memcmp(xmm_got, xmm_want, sizeof(xmm_want)) != 0) {
        (void)fprintf(stderr, "FAIL [%s/_WIN64]: %s clobbered XMM6..XMM15\n", areion_pq_tier(), label);
        g_failures++;
    }
}

static void win64_cb_all(void *ctx) {
    uint8_t m[32] = {0}, k1[32] = {0}, k2[32] = {0}, c[32] = {0}, w[288] = {0};
    uint8_t a16[64], b16[64], chi16[16], out16[16], want16[16];
    (void)ctx;
    fill_pattern(a16, sizeof(a16), 0x11U);
    fill_pattern(b16, sizeof(b16), 0x22U);
    fill_pattern(chi16, sizeof(chi16), 0x33U);
    areion_pq_extract_witness256(c, w, m, k1, k2);
    areion_pq_gf128_mul(out16, a16, b16);
    areion_pq_gf128_mul_core(want16, a16, b16);
    check_bytes_eq("win64_cb_all GF128Mul(a, b) == GF128MulCore(a, b)", out16, want16, 16U);
    areion_pq_gf128_polymac(out16, a16, b16, 4U, chi16);
    memset(want16, 0, sizeof(want16));
    areion_pq_gf128_polymac_purec(want16, a16, b16, 4U, chi16);
    check_bytes_eq("win64_cb_all GF128PolyMAC == GF128PolyMACPureC", out16, want16, 16U);
    areion_pq_dispatch_vole_xor_row(w, w + 16, 256U);
}
#endif

static void test_win64_callee_saved_abi(void) {
#if defined(_WIN64) && (defined(__x86_64__) || defined(_M_X64)) && (defined(__GNUC__) || defined(__clang__))
    win64_invoke_check("all_pq_kernels_win64_abi", win64_cb_all, NULL);
#endif
}

static void test_unaligned_and_overlap(void) {
    static const size_t offsets[4] = { 1U, 2U, 3U, 7U };
    uint8_t raw_a[512], raw_b[512], raw_c[512], raw_d[512];
    uint8_t ref_c[32], ref_w[288], ref_16[16], ref_vole[352];
    uint8_t m[32], k1[32], k2[32], poly_a[64], poly_b[64], chi[16];
    size_t idx;

    fill_pattern(m, 32U, 0xC0U);
    fill_pattern(k1, 32U, 0xC1U);
    fill_pattern(k2, 32U, 0xC2U);
    fill_pattern(poly_a, 64U, 0xC3U);
    fill_pattern(poly_b, 64U, 0xC4U);
    fill_pattern(chi, 16U, 0xC5U);

    areion_pq_extract_witness256(ref_c, ref_w, m, k1, k2);
    areion_pq_gf128_polymac(ref_16, poly_a, poly_b, 4U, chi);

    for (idx = 0U; idx < 4U; idx++) {
        size_t off = offsets[idx];
        uint8_t *pa = raw_a + off;
        uint8_t *pb = raw_b + off;
        uint8_t *pc = raw_c + off;
        uint8_t *pd = raw_d + off;

        memcpy(pa, m, 32U);
        memcpy(pb, k1, 32U);
        memcpy(pc, k2, 32U);
        areion_pq_extract_witness256(pa, pd, pa, pb, pc);
        check_bytes_eq("unaligned overlap ExtractWitness256 C", pa, ref_c, 32U);
        check_bytes_eq("unaligned ExtractWitness256 W", pd, ref_w, 288U);
        check_true("unaligned VerifyWitness256", areion_pq_verify_witness256(m, pa, pb, pc, pd) == 1);

        memcpy(pa, poly_a, 64U);
        memcpy(pb, poly_b, 64U);
        memcpy(pc, chi, 16U);
        areion_pq_gf128_polymac(pd, pa, pb, 4U, pc);
        check_bytes_eq("unaligned GF128PolyMAC", pd, ref_16, 16U);

        fill_pattern(ref_vole, 352U, 0xC6U);
        fill_pattern(pa, 352U, 0xC6U);
        fill_pattern(pb, 352U, 0xC7U);
        areion_pq_vole_xor_row_purec(ref_vole, pb, 352U);
        areion_pq_dispatch_vole_xor_row(pa, pb, 352U);
        check_bytes_eq("unaligned dispatch_vole_xor_row", pa, ref_vole, 352U);
    }
}

static void vg_make_mem_undefined(const void *p, size_t n) {
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__)) && \
    !__has_feature(memory_sanitizer) && !__has_feature(address_sanitizer) && \
    !__has_feature(thread_sanitizer) && !defined(__SANITIZE_ADDRESS__) && !defined(__SANITIZE_THREAD__)
    volatile unsigned long args[6];
    unsigned long vg_res = 0UL;
    args[0] = 0x4d430001UL; /* VG_USERREQ__MAKE_MEM_UNDEFINED */
    args[1] = (unsigned long)(uintptr_t)p;
    args[2] = (unsigned long)n;
    args[3] = 0UL;
    args[4] = 0UL;
    args[5] = 0UL;
    __asm__ __volatile__(
        "rolq $3,  %%rdi ; rolq $13, %%rdi\n\t"
        "rolq $61, %%rdi ; rolq $51, %%rdi\n\t"
        "xchgq %%rbx, %%rbx"
        : "=d"(vg_res)
        : "a"(&args[0]), "0"(0UL)
        : "cc", "memory"
    );
    (void)vg_res;
#else
    (void)p;
    (void)n;
#endif
}

static void vg_make_mem_defined(const void *p, size_t n) {
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__)) && \
    !__has_feature(memory_sanitizer) && !__has_feature(address_sanitizer) && \
    !__has_feature(thread_sanitizer) && !defined(__SANITIZE_ADDRESS__) && !defined(__SANITIZE_THREAD__)
    volatile unsigned long args[6];
    unsigned long vg_res = 0UL;
    args[0] = 0x4d430002UL; /* VG_USERREQ__MAKE_MEM_DEFINED */
    args[1] = (unsigned long)(uintptr_t)p;
    args[2] = (unsigned long)n;
    args[3] = 0UL;
    args[4] = 0UL;
    args[5] = 0UL;
    __asm__ __volatile__(
        "rolq $3,  %%rdi ; rolq $13, %%rdi\n\t"
        "rolq $61, %%rdi ; rolq $51, %%rdi\n\t"
        "xchgq %%rbx, %%rbx"
        : "=d"(vg_res)
        : "a"(&args[0]), "0"(0UL)
        : "cc", "memory"
    );
    (void)vg_res;
#else
    (void)p;
    (void)n;
#endif
}

static void test_timecop_constant_time(void) {
    uint8_t m[32] = {0}, k1[32] = {0}, k2[32] = {0}, c[32] = {0}, w[288] = {0}, w_em2[576] = {0};
    uint8_t a16[64] = {0}, b16[64] = {0}, chi16[16] = {0}, out16[16] = {0};
    uint8_t siv_key[128] = {0}, siv_nonce[32] = {0}, siv_ad[64] = {0}, siv_pt[64] = {0}, siv_ct[64] = {0}, siv_tag[32] = {0};

    vg_make_mem_undefined(m, sizeof(m));
    vg_make_mem_undefined(k1, sizeof(k1));
    vg_make_mem_undefined(k2, sizeof(k2));
    vg_make_mem_undefined(a16, sizeof(a16));
    vg_make_mem_undefined(b16, sizeof(b16));
    vg_make_mem_undefined(chi16, sizeof(chi16));
    vg_make_mem_undefined(siv_key, sizeof(siv_key));
    vg_make_mem_undefined(siv_nonce, sizeof(siv_nonce));
    vg_make_mem_undefined(siv_ad, sizeof(siv_ad));
    vg_make_mem_undefined(siv_pt, sizeof(siv_pt));

    areion_pq_gf128_mul(out16, a16, b16);
    areion_pq_gf128_polymac(out16, a16, b16, 4U, chi16);
    areion_pq_extract_witness256(c, w, m, k1, k2);
    (void)areion_pq_verify_witness256(m, c, k1, k2, w);
    areion_pq_extract_witness_em2_256(c, w_em2, m, k1, k2);
    (void)areion_pq_verify_witness_em2_256(m, c, k1, k2, w_em2);
    areion_pq_tem2_siv_encrypt(siv_ct, siv_tag, siv_key, siv_nonce, siv_ad, 64U, siv_pt, 64U);

    vg_make_mem_defined(m, sizeof(m));
    vg_make_mem_defined(k1, sizeof(k1));
    vg_make_mem_defined(k2, sizeof(k2));
    vg_make_mem_defined(c, sizeof(c));
    vg_make_mem_defined(w, sizeof(w));
    vg_make_mem_defined(w_em2, sizeof(w_em2));
    vg_make_mem_defined(a16, sizeof(a16));
    vg_make_mem_defined(b16, sizeof(b16));
    vg_make_mem_defined(chi16, sizeof(chi16));
    vg_make_mem_defined(out16, sizeof(out16));
    vg_make_mem_defined(siv_key, sizeof(siv_key));
    vg_make_mem_defined(siv_nonce, sizeof(siv_nonce));
    vg_make_mem_defined(siv_ad, sizeof(siv_ad));
    vg_make_mem_defined(siv_pt, sizeof(siv_pt));
    vg_make_mem_defined(siv_ct, sizeof(siv_ct));
    vg_make_mem_defined(siv_tag, sizeof(siv_tag));
}

static uint64_t dudect_ticks(void) {
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
    uint32_t lo = 0U, hi = 0U;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32U) | (uint64_t)lo;
#elif defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__))
    uint64_t v = 0U;
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(v));
    return v;
#else
    return (uint64_t)clock();
#endif
}

static double dudect_sqrt(double x) {
    double g;
    int i;
    if (x <= 0.0) {
        return 0.0;
    }
    g = x;
    for (i = 0; i < 30; i++) {
        g = 0.5 * (g + x / g);
    }
    return g;
}

typedef struct {
    double mean[2];
    double m2[2];
    double n[2];
} dudect_ctx_t;

static void dudect_push(dudect_ctx_t *ctx, size_t cls, double val) {
    double delta;
    ctx->n[cls] += 1.0;
    delta = val - ctx->mean[cls];
    ctx->mean[cls] += delta / ctx->n[cls];
    ctx->m2[cls] += delta * (val - ctx->mean[cls]);
}

static double dudect_t_stat(const dudect_ctx_t *ctx) {
    double var0, var1, denom, diff;
    if (ctx->n[0] < 2.0 || ctx->n[1] < 2.0) {
        return 0.0;
    }
    var0 = ctx->m2[0] / (ctx->n[0] - 1.0);
    var1 = ctx->m2[1] / (ctx->n[1] - 1.0);
    denom = dudect_sqrt(var0 / ctx->n[0] + var1 / ctx->n[1]);
    if (denom <= 0.0) {
        return 0.0;
    }
    diff = ctx->mean[0] - ctx->mean[1];
    return (diff < 0.0) ? -diff / denom : diff / denom;
}

static void test_dudect_timing(int extended) {
    dudect_ctx_t st_wit = {{0.0, 0.0}, {0.0, 0.0}, {0.0, 0.0}};
    dudect_ctx_t st_gf128 = {{0.0, 0.0}, {0.0, 0.0}, {0.0, 0.0}};
    dudect_ctx_t st_siv = {{0.0, 0.0}, {0.0, 0.0}, {0.0, 0.0}};
    uint8_t m[32], k1[32], k2[32], c[32], w[288];
    uint8_t a16[64], b16[64], chi16[16], out16[16];
    uint8_t siv_key[128], siv_nonce[32], siv_pt[64], siv_ct[64], siv_tag[32];
    size_t samples = extended ? 10000U : 128U;
    uint32_t prng = 0x9E3779B9U;
    size_t s, i;

    memset(siv_key, 0x33, sizeof(siv_key));
    memset(siv_nonce, 0x55, sizeof(siv_nonce));
    memset(chi16, 0x77, sizeof(chi16));

    for (s = 0U; s < samples; s++) {
        size_t cls = (size_t)(prng & 1U);
        uint64_t t0, t1;
        prng ^= prng << 13U;
        prng ^= prng >> 17U;
        prng ^= prng << 5U;

        if (cls == 0U) {
            memset(m, 0, sizeof(m));
            memset(k1, 0, sizeof(k1));
            memset(k2, 0, sizeof(k2));
            memset(a16, 0, sizeof(a16));
            memset(b16, 0, sizeof(b16));
            memset(siv_pt, 0, sizeof(siv_pt));
        } else {
            for (i = 0U; i < 32U; i++) {
                prng = prng * 1664525U + 1013904223U;
                m[i] = (uint8_t)(prng >> 24U);
                k1[i] = (uint8_t)(prng >> 16U);
                k2[i] = (uint8_t)(prng >> 8U);
            }
            for (i = 0U; i < 64U; i++) {
                prng = prng * 1664525U + 1013904223U;
                a16[i] = (uint8_t)(prng >> 24U);
                b16[i] = (uint8_t)(prng >> 16U);
                siv_pt[i] = (uint8_t)(prng >> 8U);
            }
        }

        t0 = dudect_ticks();
        for (i = 0U; i < 4U; i++) {
            areion_pq_extract_witness256(c, w, m, k1, k2);
        }
        t1 = dudect_ticks();
        dudect_push(&st_wit, cls, (double)(t1 - t0));

        t0 = dudect_ticks();
        for (i = 0U; i < 8U; i++) {
            areion_pq_gf128_polymac(out16, a16, b16, 4U, chi16);
        }
        t1 = dudect_ticks();
        dudect_push(&st_gf128, cls, (double)(t1 - t0));

        t0 = dudect_ticks();
        for (i = 0U; i < 2U; i++) {
            areion_pq_tem2_siv_encrypt(siv_ct, siv_tag, siv_key, siv_nonce, NULL, 0U, siv_pt, 64U);
        }
        t1 = dudect_ticks();
        dudect_push(&st_siv, cls, (double)(t1 - t0));

        g_bench_sink = (uint8_t)((uint32_t)g_bench_sink ^ (uint32_t)c[0] ^ (uint32_t)out16[0] ^ (uint32_t)siv_ct[0]);
    }

    if (extended) {
        printf("dudect Welch t-test [%s, N=%u]:\n", areion_pq_tier(), (unsigned)samples);
        printf("  ExtractWitness256 : |t| = %.2f\n", dudect_t_stat(&st_wit));
        printf("  GF128PolyMAC      : |t| = %.2f\n", dudect_t_stat(&st_gf128));
        printf("  TEM2SIVEncrypt    : |t| = %.2f\n", dudect_t_stat(&st_siv));
    }
    areion_pq_zeroize(k1, sizeof(k1));
    areion_pq_zeroize(k2, sizeof(k2));
    areion_pq_zeroize(w, sizeof(w));
    areion_pq_zeroize(siv_key, sizeof(siv_key));
}

/* =========================================================================
 * 8. Benchmark Suite (--bench)
 * ========================================================================= */

#define AREION_PQ_BENCH_OP(label, bytes_per_op, min_iters, call_expr) \
    do { \
        size_t iters_ = (min_iters); \
        double secs_ = 0.0; \
        for (;;) { \
            size_t i_; \
            clock_t t0_ = clock(); \
            for (i_ = 0U; i_ < iters_; i_++) { \
                call_expr; \
            } \
            clock_t t1_ = clock(); \
            secs_ = (double)(t1_ - t0_) / (double)CLOCKS_PER_SEC; \
            if (secs_ >= 0.05 || iters_ >= (1U << 26U)) { \
                break; \
            } \
            if (secs_ < 0.005) { \
                iters_ *= 8U; \
            } else { \
                iters_ *= 2U; \
            } \
        } \
        if (secs_ > 0.0) { \
            double ns_per_op_ = (secs_ * 1e9) / (double)iters_; \
            double mb_per_s_ = ((double)iters_ * (double)(bytes_per_op) / 1e6) / secs_; \
            printf("  %-28s : %8.1f MB/s (%10.2f ns/op)\n", (label), mb_per_s_, ns_per_op_); \
        } \
    } while (0)

static void run_benchmarks(void) {
    static uint8_t sig_buf[50000];
    uint8_t m32[32] = {0}, k1[32] = {0}, k2[32] = {0}, c32[32] = {0};
    uint8_t w288[288] = {0}, w576[576] = {0};
    uint8_t poly_a[16][16] = {{0}}, poly_b[16][16] = {{0}}, chi16[16] = {1U};
    uint8_t seed32[32] = {0}, seed48[48] = {0}, seed64[64] = {0}, seed96[96] = {0};
    uint8_t opt16[16] = {0}, opt32[32] = {0};
    const uint8_t msg32[32] = {0};
    uint8_t pk48[48], sk64[64], pk64[64], sk96[96], pk32[32], sk128[128];
    uint8_t siv_key[128] = {0}, siv_nonce[32] = {0};
    const uint8_t siv_ad[64] = {0};
    uint8_t siv_pt[4096] = {0}, siv_ct[4096] = {0}, siv_tag[32] = {0};
    uint8_t kdf_out[1024] = {0};

    printf("Benchmarking active tier: %s\n", areion_pq_tier());

    AREION_PQ_BENCH_OP("GF128Mul", 16U, 65536U, areion_pq_gf128_mul(c32, m32, k1));
    AREION_PQ_BENCH_OP("GF128PolyMAC_16", 256U, 16384U,
                       areion_pq_gf128_polymac(c32, &poly_a[0][0], &poly_b[0][0], 16U, chi16));
    AREION_PQ_BENCH_OP("ExtractWitness256", 288U, 16384U,
                       areion_pq_extract_witness256(c32, w288, m32, k1, k2));
    AREION_PQ_BENCH_OP("VerifyWitness256", 288U, 16384U,
                       g_bench_sink ^= (uint8_t)areion_pq_verify_witness256(m32, c32, k1, k2, w288));
    AREION_PQ_BENCH_OP("ExtractWitnessEM2_256", 576U, 8192U,
                       areion_pq_extract_witness_em2_256(c32, w576, m32, k1, k2));
    AREION_PQ_BENCH_OP("VerifyWitnessEM2_256", 576U, 8192U,
                       g_bench_sink ^= (uint8_t)areion_pq_verify_witness_em2_256(m32, c32, k1, k2, w576));

    areion_pq_faest_keygen128f(pk48, sk64, seed32);
    AREION_PQ_BENCH_OP("FAEST_128f_Sign", AREION_PQ_FAEST128F_SIG_SIZE, 4U,
                       areion_pq_faest_sign128f(sig_buf, sk64, msg32, 32U, opt16));
    AREION_PQ_BENCH_OP("FAEST_128f_Verify", AREION_PQ_FAEST128F_SIG_SIZE, 4U,
                       g_bench_sink ^= (uint8_t)areion_pq_faest_verify128f(pk48, msg32, 32U, sig_buf));

    areion_pq_faest_keygen256f(pk64, sk96, seed64);
    AREION_PQ_BENCH_OP("FAEST_256f_Sign", AREION_PQ_FAEST256F_SIG_SIZE, 2U,
                       areion_pq_faest_sign256f(sig_buf, sk96, msg32, 32U, opt32));
    AREION_PQ_BENCH_OP("FAEST_256f_Verify", AREION_PQ_FAEST256F_SIG_SIZE, 2U,
                       g_bench_sink ^= (uint8_t)areion_pq_faest_verify256f(pk64, msg32, 32U, sig_buf));

    areion_pq_faest_em2_keygen256f(pk64, sk96, seed64);
    AREION_PQ_BENCH_OP("FAEST_EM2_256f_Sign", AREION_PQ_FAEST_EM2_256F_SIG_SIZE, 2U,
                       areion_pq_faest_em2_sign256f(sig_buf, sk96, msg32, 32U, opt32));
    AREION_PQ_BENCH_OP("FAEST_EM2_256f_Verify", AREION_PQ_FAEST_EM2_256F_SIG_SIZE, 2U,
                       g_bench_sink ^= (uint8_t)areion_pq_faest_em2_verify256f(pk64, msg32, 32U, sig_buf));

    areion_pq_slhdsa_keygen128f(pk32, sk64, seed48);
    AREION_PQ_BENCH_OP("SLH_DSA_128f_Sign", AREION_PQ_SLHDSA128F_SIG_SIZE, 4U,
                       areion_pq_slhdsa_sign128f(sig_buf, sk64, msg32, 32U, opt16));
    AREION_PQ_BENCH_OP("SLH_DSA_128f_Verify", AREION_PQ_SLHDSA128F_SIG_SIZE, 16U,
                       g_bench_sink ^= (uint8_t)areion_pq_slhdsa_verify128f(pk32, msg32, 32U, sig_buf));

    areion_pq_slhdsa_keygen256f(pk64, sk128, seed96);
    AREION_PQ_BENCH_OP("SLH_DSA_256f_Sign", AREION_PQ_SLHDSA256F_SIG_SIZE, 2U,
                       areion_pq_slhdsa_sign256f(sig_buf, sk128, msg32, 32U, opt32));
    AREION_PQ_BENCH_OP("SLH_DSA_256f_Verify", AREION_PQ_SLHDSA256F_SIG_SIZE, 8U,
                       g_bench_sink ^= (uint8_t)areion_pq_slhdsa_verify256f(pk64, msg32, 32U, sig_buf));

    areion_pq_slhdsa_tem_keygen256f(pk64, sk128, seed96);
    AREION_PQ_BENCH_OP("SLH_DSA_TEM256f_Sign", AREION_PQ_SLHDSA_TEM256F_SIG_SIZE, 2U,
                       areion_pq_slhdsa_tem_sign256f(sig_buf, sk128, msg32, 32U, opt32));
    AREION_PQ_BENCH_OP("SLH_DSA_TEM256f_Verify", AREION_PQ_SLHDSA_TEM256F_SIG_SIZE, 8U,
                       g_bench_sink ^= (uint8_t)areion_pq_slhdsa_tem_verify256f(pk64, msg32, 32U, sig_buf));

    AREION_PQ_BENCH_OP("AreionKDF_1KB", 1024U, 2048U,
                       areion_pq_kdf_expand(kdf_out, 1024U, m32, 32U, k1, 32U));
    AREION_PQ_BENCH_OP("TEM2_SIV_Encrypt_4KB", 4096U, 1024U,
                       areion_pq_tem2_siv_encrypt(siv_ct, siv_tag, siv_key, siv_nonce, siv_ad, 64U, siv_pt, 4096U));
    AREION_PQ_BENCH_OP("TEM2_SIV_Decrypt_4KB", 4096U, 1024U,
                       g_bench_sink ^= (uint8_t)areion_pq_tem2_siv_decrypt(
                           siv_pt, siv_key, siv_nonce, siv_ad, 64U, siv_ct, 4096U, siv_tag));

    g_bench_sink ^= kdf_out[0];
}

int main(int argc, char **argv) {
    static const areion_pq_tier_t all_tiers[] = {
        AREION_PQ_TIER_PUREC,
        AREION_PQ_TIER_AESNI,
        AREION_PQ_TIER_VEX,
        AREION_PQ_TIER_VAESAVX2,
        AREION_PQ_TIER_AVX512,
        AREION_PQ_TIER_ARM64
    };
    const char *avail[8];
    size_t num_avail, t;
    int i;

    (void)setvbuf(stdout, NULL, _IONBF, 0);

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--full") == 0) {
            g_full_mode = 1;
        }
    }

    if (argc >= 2 && strcmp(argv[1], "--dump-kat") == 0) {
        const char *tier_arg = (argc >= 3 && strncmp(argv[2], "--", 2) != 0) ? argv[2] : NULL;
        return dump_kat_for_tier(tier_arg, 1);
    }
    if (argc >= 2 && strcmp(argv[1], "--bench") == 0) {
        if (argc >= 3) {
            const char *tname = argv[2];
            if (strncmp(tname, "--tier=", 7) == 0) {
                tname += 7;
            }
            if (strncmp(tname, "--", 2) != 0) {
                if (areion_pq_set_tier(tname) != 0) {
                    return 2;
                }
            }
        }
        run_benchmarks();
        return 0;
    }
    if (argc >= 2 && strncmp(argv[1], "--tier=", 7) == 0) {
        if (areion_pq_set_tier(argv[1] + 7) != 0) {
            return 2;
        }
        run_benchmarks();
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "--dudect") == 0) {
        test_dudect_timing(1);
        return 0;
    }

    /* Verify tier name overrides and introspection */
    num_avail = areion_pq_available_tiers(avail, 8U);
    check_true("areion_pq_available_tiers >= 1", num_avail >= 1U);
    check_true("areion_pq_set_tier(purec)", areion_pq_set_tier("purec") == 0 && strcmp(areion_pq_tier(), "purec") == 0);
    check_true("areion_pq_set_tier(purego)", areion_pq_set_tier("purego") == 0 && strcmp(areion_pq_tier(), "purec") == 0);
    check_true("areion_pq_set_tier(SCALAR)", areion_pq_set_tier("  SCALAR ") == 0 && strcmp(areion_pq_tier(), "purec") == 0);
    check_true("areion_pq_set_tier(invalid)", areion_pq_set_tier("nonexistent_tier") == -1);
    check_true("areion_pq_set_tier(NULL)", areion_pq_set_tier(NULL) == -1);
    areion_pq_use_hardware_acceleration(false);
    check_true("areion_pq_use_hardware_acceleration(false)", areion_pq_tier_code() == AREION_PQ_TIER_PUREC);
    areion_pq_use_hardware_acceleration(true);
    (void)areion_pq_set_tier("auto");

    printf("Active hardware tier: %s\n", areion_pq_tier());

#if AREION_PQ_HAS_PTHREAD_TEST
    test_multithreaded_dispatch();
#endif

    for (t = 0U; t < sizeof(all_tiers) / sizeof(all_tiers[0]); t++) {
        areion_pq_tier_t tier = all_tiers[t];
        int run_slow = (g_full_mode != 0) ? 1 : 0;
        if (!areion_pq_tier_supported(tier)) {
            continue;
        }
        (void)areion_pq_set_tier_code(tier);
        printf("Testing tier: %s ... ", areion_pq_tier());
        (void)fflush(stdout);
        check_true("areion_pq_selftest", areion_pq_selftest() == 0);
        test_finite_fields_and_witnesses();
        test_slh_tweakable_hashes();
        test_kdf_siv_and_hpke();
        test_signatures_and_wrappers(run_slow);
        test_win64_callee_saved_abi();
        test_unaligned_and_overlap();
        test_timecop_constant_time();
        test_dudect_timing(0);
        printf("OK\n");
    }

    test_all_tiers_pairwise_matrix();

    (void)areion_pq_set_tier_code(AREION_PQ_TIER_AUTO);
    if (g_failures != 0) {
        (void)fprintf(stderr, "FAILED: %d check(s) failed.\n", g_failures);
        return 1;
    }
    printf("ALL TESTS PASSED.\n");
    return 0;
}
