/*
 * Copyright (c) 2026 Andrey Kuvshinov
 *
 * Dual-licensed under Apache-2.0 OR MIT.
 * See LICENSE-APACHE and LICENSE-MIT for details.
 */

#include "areion_pq_internal.h"

#if defined(AREION_PQ_FORCE_PORTABLE) || defined(AREION_FORCE_PORTABLE) || \
    (!defined(__x86_64__) && !defined(_M_X64) && !defined(__aarch64__) && !defined(_M_ARM64))

void areion_pq_dispatch_extract_witness256(
    uint8_t c[32], uint8_t w[288],
    const uint8_t m[32], const uint8_t k1[32], const uint8_t k2[32],
    const uint8_t rc[10][16]) {
    areion_pq_extract_witness256_purec(c, w, m, k1, k2, rc);
}

void areion_pq_dispatch_gf128_mul(
    uint8_t out[16], const uint8_t a[16], const uint8_t b[16]) {
    areion_pq_gf128_mul_purec(out, a, b);
}

void areion_pq_dispatch_gf128_mul_nowipe(
    uint8_t out[16], const uint8_t a[16], const uint8_t b[16]) {
    areion_pq_gf128_mul_core(out, a, b);
}

void areion_pq_dispatch_gf128_polymac(
    uint8_t acc[16], const uint8_t *a, const uint8_t *b, size_t count, const uint8_t chi[16]) {
    areion_pq_gf128_polymac_purec(acc, a, b, count, chi);
}

void areion_pq_dispatch_vole_xor_row(
    uint8_t *dst, const uint8_t *src, size_t len) {
    areion_pq_vole_xor_row_purec(dst, src, len);
}

void areion_pq_dispatch_vole_xor_row_nowipe(
    uint8_t *dst, const uint8_t *src, size_t len) {
    areion_pq_vole_xor_row_core(dst, src, len);
}

#else
typedef int areion_pq_other_unused_t;
#endif
