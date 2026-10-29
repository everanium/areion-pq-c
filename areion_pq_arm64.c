/*
 * Copyright (c) 2026 Andrey Kuvshinov
 *
 * Dual-licensed under Apache-2.0 OR MIT.
 * See LICENSE-APACHE and LICENSE-MIT for details.
 */

#include "areion_pq_internal.h"

#if (defined(__aarch64__) || defined(_M_ARM64)) && !defined(AREION_PQ_FORCE_PORTABLE) && !defined(AREION_FORCE_PORTABLE)

int areion_pq_has_hw_extract_witness256(void) {
    return (areion_pq_active_tier() == AREION_PQ_TIER_ARM64) ? 1 : 0;
}

void areion_pq_dispatch_extract_witness256(
    uint8_t c[32], uint8_t w[288],
    const uint8_t m[32], const uint8_t k1[32], const uint8_t k2[32],
    const uint8_t rc[10][16]) {
    if (areion_pq_active_tier() == AREION_PQ_TIER_ARM64) {
        areion_pq_extract_witness256_arm64(c, w, m, k1, k2, rc);
        AREION_PQ_MSAN_UNPOISON(c, 32U);
        AREION_PQ_MSAN_UNPOISON(w, 288U);
        return;
    }
    areion_pq_extract_witness256_purec(c, w, m, k1, k2, rc);
}

void areion_pq_dispatch_gf128_mul(
    uint8_t out[16], const uint8_t a[16], const uint8_t b[16]) {
    if (areion_pq_active_tier() == AREION_PQ_TIER_ARM64 && areion_pq_has_pmull()) {
        areion_pq_gf128_mul_pmull(out, a, b);
        AREION_PQ_MSAN_UNPOISON(out, 16U);
        return;
    }
    areion_pq_gf128_mul_purec(out, a, b);
}

void areion_pq_dispatch_gf128_mul_nowipe(
    uint8_t out[16], const uint8_t a[16], const uint8_t b[16]) {
    if (areion_pq_active_tier() == AREION_PQ_TIER_ARM64 && areion_pq_has_pmull()) {
        areion_pq_gf128_mul_pmull(out, a, b);
        AREION_PQ_MSAN_UNPOISON(out, 16U);
        return;
    }
    areion_pq_gf128_mul_core(out, a, b);
}

void areion_pq_dispatch_gf128_polymac(
    uint8_t acc[16], const uint8_t *a, const uint8_t *b, size_t count, const uint8_t chi[16]) {
    if (count == 0U) {
        return;
    }
    if (areion_pq_active_tier() == AREION_PQ_TIER_ARM64 && areion_pq_has_pmull()) {
        areion_pq_gf128_polymac_pmull(acc, a, b, count, chi);
        AREION_PQ_MSAN_UNPOISON(acc, 16U);
        return;
    }
    areion_pq_gf128_polymac_purec(acc, a, b, count, chi);
}

void areion_pq_dispatch_vole_xor_row(
    uint8_t *dst, const uint8_t *src, size_t len) {
    if (len == 0U) {
        return;
    }
    if (areion_pq_active_tier() == AREION_PQ_TIER_ARM64) {
        areion_pq_vole_xor_row_neon(dst, src, len);
        AREION_PQ_MSAN_UNPOISON(dst, len);
        return;
    }
    areion_pq_vole_xor_row_purec(dst, src, len);
}

void areion_pq_dispatch_vole_xor_row_nowipe(
    uint8_t *dst, const uint8_t *src, size_t len) {
    if (len == 0U) {
        return;
    }
    if (areion_pq_active_tier() == AREION_PQ_TIER_ARM64) {
        areion_pq_vole_xor_row_neon(dst, src, len);
        AREION_PQ_MSAN_UNPOISON(dst, len);
        return;
    }
    areion_pq_vole_xor_row_core(dst, src, len);
}

void areion_pq_wots_chain256x4_arm64(
    uint8_t out[4][32], const uint8_t in[4][32], const uint8_t adrs[4][32],
    const uint8_t kpub1[32], const uint8_t kpub2[32],
    uint32_t start_step, uint32_t steps) {
    areion_pq_wots_chain256x4_purec(out, in, adrs, kpub1, kpub2, start_step, steps);
}

void areion_pq_dispatch_wots_chain256x4(
    uint8_t out[4][32], const uint8_t in[4][32], const uint8_t adrs[4][32],
    const uint8_t kpub1[32], const uint8_t kpub2[32],
    uint32_t start_step, uint32_t steps) {
    areion_pq_wots_chain256x4_purec(out, in, adrs, kpub1, kpub2, start_step, steps);
}

#else
typedef int areion_pq_arm64_unused_t;
#endif
