/*
 * Copyright (c) 2026 Andrey Kuvshinov
 *
 * Dual-licensed under Apache-2.0 OR MIT.
 * See LICENSE-APACHE and LICENSE-MIT for details.
 */

#include "areion_pq_internal.h"

#undef areion_soem256x4
#undef areion_soem512x4
#undef areion_em_encrypt256x4
#undef areion_em_decrypt256x4
#undef areion_em_encrypt512x4
#undef areion_em_decrypt512x4
#undef areion_em2_encrypt256x4
#undef areion_em2_decrypt256x4
#undef areion_em2_encrypt512x4
#undef areion_em2_decrypt512x4
#undef areion_tem_encrypt256x4
#undef areion_tem_decrypt256x4
#undef areion_tem_encrypt512x4
#undef areion_tem_decrypt512x4
#undef areion_tem2_encrypt256x4
#undef areion_tem2_decrypt256x4
#undef areion_tem2_encrypt512x4
#undef areion_tem2_decrypt512x4
#undef areion_aes128_encrypt_block
#undef areion_aes128_encrypt4_blocks
#undef areion_pq_slh_prf256x4

/* =========================================================================
 * 1. Software Stack Frame Zeroization & Small Block Helpers
 * ========================================================================= */

static AREION_PQ_NOINLINE AREION_PQ_NO_STACK_PROTECTOR void areion_pq_wipe_software_stack(void) {
    volatile uint64_t frame[768];
    size_t i;
#if defined(__GNUC__) || defined(__clang__)
    const void *fp = __builtin_frame_address(0);
#endif
    for (i = 0U; i < 768U; i++) {
        frame[i] = 0ULL;
    }
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(frame), "r"(fp) : "memory");
#else
    areion_pq_compiler_barrier();
#endif
}

static inline void pq_xor16(uint8_t dst[16], const uint8_t a[16], const uint8_t b[16]) {
    size_t i;
    for (i = 0U; i < 16U; i++) {
        dst[i] = (uint8_t)(a[i] ^ b[i]);
    }
}

static inline void pq_xor32(uint8_t dst[32], const uint8_t a[32], const uint8_t b[32]) {
    size_t i;
    for (i = 0U; i < 32U; i++) {
        dst[i] = (uint8_t)(a[i] ^ b[i]);
    }
}

static inline void pq_xor64(uint8_t dst[64], const uint8_t a[64], const uint8_t b[64]) {
    size_t i;
    for (i = 0U; i < 64U; i++) {
        dst[i] = (uint8_t)(a[i] ^ b[i]);
    }
}

static inline void pq_pad32(uint8_t out[32], const uint8_t *in, size_t n) {
    if (n == 16U) {
        memcpy(&out[0], in, 16U);
        memcpy(&out[16], in, 16U);
    } else {
        memcpy(&out[0], in, 32U);
    }
}

/* =========================================================================
 * 2. 64-Bit Bitsliced AES Primitives (1-to-1 with areion_pq_purego.go)
 * ========================================================================= */

#define PQ_BS_BYTE0_MASK 0x0101010101010101ULL

static inline uint64_t pq_bs_rotl64(uint64_t x, unsigned int n) {
    return (x << (n & 63U)) | (x >> ((64U - n) & 63U));
}

static inline uint16_t pq_bs_rotl16_4(uint16_t x) {
    return (uint16_t)(((uint32_t)x << 4U) | ((uint32_t)x >> 12U));
}

static inline uint16_t pq_bs_rotr16_4(uint16_t x) {
    return (uint16_t)(((uint32_t)x >> 4U) | ((uint32_t)x << 12U));
}

static inline uint16_t pq_bs_rot16_8(uint16_t x) {
    return (uint16_t)(((uint32_t)x << 8U) | ((uint32_t)x >> 8U));
}

static inline uint64_t pq_bs_prep_word(uint64_t u) {
    uint64_t t = ((u >> 24U) ^ u) & 0x00000000ff00ff00ULL;
    u ^= t ^ (t << 24U);
    t = ((u >> 16U) ^ u) & 0x00000000ffff0000ULL;
    u ^= t ^ (t << 16U);
    return u;
}

static inline uint64_t pq_bs_unprep_word(uint64_t u) {
    uint64_t t = ((u >> 16U) ^ u) & 0x00000000ffff0000ULL;
    u ^= t ^ (t << 16U);
    t = ((u >> 24U) ^ u) & 0x00000000ff00ff00ULL;
    u ^= t ^ (t << 24U);
    return u;
}

static inline void pq_bs_prep_block(uint64_t lo, uint64_t hi, uint64_t *u0, uint64_t *u1) {
    uint64_t a0 = (lo & 0x00000000ffffffffULL) | (hi << 32U);
    uint64_t a1 = (lo >> 32U) | (hi & 0xffffffff00000000ULL);
    *u0 = pq_bs_prep_word(a0);
    *u1 = pq_bs_prep_word(a1);
}

static inline void pq_bs_unprep_block(uint64_t u0, uint64_t u1, uint64_t *lo, uint64_t *hi) {
    u0 = pq_bs_unprep_word(u0);
    u1 = pq_bs_unprep_word(u1);
    *lo = (u0 & 0x00000000ffffffffULL) | (u1 << 32U);
    *hi = (u0 >> 32U) | (u1 & 0xffffffff00000000ULL);
}

static inline void pq_bs_pack1(uint64_t q[8], const uint8_t b0[16]) {
    uint64_t lo = areion_pq_load_le64(&b0[0]);
    uint64_t hi = areion_pq_load_le64(&b0[8]);
    uint64_t u0, u1;
    pq_bs_prep_block(lo, hi, &u0, &u1);
    q[0] = (u0 & PQ_BS_BYTE0_MASK) | ((u1 & PQ_BS_BYTE0_MASK) << 4U);
    q[1] = ((u0 >> 1U) & PQ_BS_BYTE0_MASK) | (((u1 >> 1U) & PQ_BS_BYTE0_MASK) << 4U);
    q[2] = ((u0 >> 2U) & PQ_BS_BYTE0_MASK) | (((u1 >> 2U) & PQ_BS_BYTE0_MASK) << 4U);
    q[3] = ((u0 >> 3U) & PQ_BS_BYTE0_MASK) | (((u1 >> 3U) & PQ_BS_BYTE0_MASK) << 4U);
    q[4] = ((u0 >> 4U) & PQ_BS_BYTE0_MASK) | (((u1 >> 4U) & PQ_BS_BYTE0_MASK) << 4U);
    q[5] = ((u0 >> 5U) & PQ_BS_BYTE0_MASK) | (((u1 >> 5U) & PQ_BS_BYTE0_MASK) << 4U);
    q[6] = ((u0 >> 6U) & PQ_BS_BYTE0_MASK) | (((u1 >> 6U) & PQ_BS_BYTE0_MASK) << 4U);
    q[7] = ((u0 >> 7U) & PQ_BS_BYTE0_MASK) | (((u1 >> 7U) & PQ_BS_BYTE0_MASK) << 4U);
}

static inline void pq_bs_unpack1(const uint64_t q[8], uint8_t b0[16]) {
    uint64_t u0 = (q[0] & PQ_BS_BYTE0_MASK) |
                  ((q[1] & PQ_BS_BYTE0_MASK) << 1U) |
                  ((q[2] & PQ_BS_BYTE0_MASK) << 2U) |
                  ((q[3] & PQ_BS_BYTE0_MASK) << 3U) |
                  ((q[4] & PQ_BS_BYTE0_MASK) << 4U) |
                  ((q[5] & PQ_BS_BYTE0_MASK) << 5U) |
                  ((q[6] & PQ_BS_BYTE0_MASK) << 6U) |
                  ((q[7] & PQ_BS_BYTE0_MASK) << 7U);
    uint64_t u1 = ((q[0] >> 4U) & PQ_BS_BYTE0_MASK) |
                  (((q[1] >> 4U) & PQ_BS_BYTE0_MASK) << 1U) |
                  (((q[2] >> 4U) & PQ_BS_BYTE0_MASK) << 2U) |
                  (((q[3] >> 4U) & PQ_BS_BYTE0_MASK) << 3U) |
                  (((q[4] >> 4U) & PQ_BS_BYTE0_MASK) << 4U) |
                  (((q[5] >> 4U) & PQ_BS_BYTE0_MASK) << 5U) |
                  (((q[6] >> 4U) & PQ_BS_BYTE0_MASK) << 6U) |
                  (((q[7] >> 4U) & PQ_BS_BYTE0_MASK) << 7U);
    uint64_t lo, hi;
    pq_bs_unprep_block(u0, u1, &lo, &hi);
    areion_pq_store_le64(&b0[0], lo);
    areion_pq_store_le64(&b0[8], hi);
}

static void pq_bs_sub_bytes(uint64_t q[8]) {
    uint64_t u0 = q[7], u1 = q[6], u2 = q[5], u3 = q[4];
    uint64_t u4 = q[3], u5 = q[2], u6 = q[1], u7 = q[0];

    uint64_t y14 = u3 ^ u5;
    uint64_t y13 = u0 ^ u6;
    uint64_t y9 = u0 ^ u3;
    uint64_t y8 = u0 ^ u5;
    uint64_t t0 = u1 ^ u2;
    uint64_t y1 = t0 ^ u7;
    uint64_t y4 = y1 ^ u3;
    uint64_t y12 = y13 ^ y14;
    uint64_t y2 = y1 ^ u0;
    uint64_t y5 = y1 ^ u6;
    uint64_t y3 = y5 ^ y8;
    uint64_t t1 = u4 ^ y12;
    uint64_t y15 = t1 ^ u5;
    uint64_t y20 = t1 ^ u1;
    uint64_t y6 = y15 ^ u7;
    uint64_t y10 = y15 ^ t0;
    uint64_t y11 = y20 ^ y9;
    uint64_t y7 = u7 ^ y11;
    uint64_t y17 = y10 ^ y11;
    uint64_t y19 = y10 ^ y8;
    uint64_t y16 = t0 ^ y11;
    uint64_t y21 = y13 ^ y16;
    uint64_t y18 = u0 ^ y16;

    uint64_t t2 = y12 & y15;
    uint64_t t3 = y3 & y6;
    uint64_t t4 = t3 ^ t2;
    uint64_t t5 = y4 & u7;
    uint64_t t6 = t5 ^ t2;
    uint64_t t7 = y13 & y16;
    uint64_t t8 = y5 & y1;
    uint64_t t9 = t8 ^ t7;
    uint64_t t10 = y2 & y7;
    uint64_t t11 = t10 ^ t7;
    uint64_t t12 = y9 & y11;
    uint64_t t13 = y14 & y17;
    uint64_t t14 = t13 ^ t12;
    uint64_t t15 = y8 & y10;
    uint64_t t16 = t15 ^ t12;
    uint64_t t17 = t4 ^ t14;
    uint64_t t18 = t6 ^ t16;
    uint64_t t19 = t9 ^ t14;
    uint64_t t20 = t11 ^ t16;
    uint64_t t21 = t17 ^ y20;
    uint64_t t22 = t18 ^ y19;
    uint64_t t23 = t19 ^ y21;
    uint64_t t24 = t20 ^ y18;

    uint64_t t25 = t21 ^ t22;
    uint64_t t26 = t21 & t23;
    uint64_t t27 = t24 ^ t26;
    uint64_t t28 = t25 & t27;
    uint64_t t29 = t28 ^ t22;
    uint64_t t30 = t23 ^ t24;
    uint64_t t31 = t22 ^ t26;
    uint64_t t32 = t31 & t30;
    uint64_t t33 = t32 ^ t24;
    uint64_t t34 = t23 ^ t33;
    uint64_t t35 = t27 ^ t33;
    uint64_t t36 = t24 & t35;
    uint64_t t37 = t36 ^ t34;
    uint64_t t38 = t27 ^ t36;
    uint64_t t39 = t29 & t38;
    uint64_t t40 = t25 ^ t39;
    uint64_t t41 = t40 ^ t37;
    uint64_t t42 = t29 ^ t33;
    uint64_t t43 = t29 ^ t40;
    uint64_t t44 = t33 ^ t37;
    uint64_t t45 = t42 ^ t41;

    uint64_t z0 = t44 & y15;
    uint64_t z1 = t37 & y6;
    uint64_t z2 = t33 & u7;
    uint64_t z3 = t43 & y16;
    uint64_t z4 = t40 & y1;
    uint64_t z5 = t29 & y7;
    uint64_t z6 = t42 & y11;
    uint64_t z7 = t45 & y17;
    uint64_t z8 = t41 & y10;
    uint64_t z9 = t44 & y12;
    uint64_t z10 = t37 & y3;
    uint64_t z11 = t33 & y4;
    uint64_t z12 = t43 & y13;
    uint64_t z13 = t40 & y5;
    uint64_t z14 = t29 & y2;
    uint64_t z15 = t42 & y9;
    uint64_t z16 = t45 & y14;
    uint64_t z17 = t41 & y8;

    uint64_t t46 = z15 ^ z16;
    uint64_t t47 = z10 ^ z11;
    uint64_t t48 = z5 ^ z13;
    uint64_t t49 = z9 ^ z10;
    uint64_t t50 = z2 ^ z12;
    uint64_t t51 = z2 ^ z5;
    uint64_t t52 = z7 ^ z8;
    uint64_t t53 = z0 ^ z3;
    uint64_t t54 = z6 ^ z7;
    uint64_t t55 = z16 ^ z17;
    uint64_t t56 = z12 ^ t48;
    uint64_t t57 = t50 ^ t53;
    uint64_t t58 = z4 ^ t46;
    uint64_t t59 = z3 ^ t54;
    uint64_t t60 = t46 ^ t57;
    uint64_t t61 = z14 ^ t57;
    uint64_t t62 = t52 ^ t58;
    uint64_t t63 = t49 ^ t58;
    uint64_t t64 = z4 ^ t59;
    uint64_t t65 = t61 ^ t62;
    uint64_t t66 = z1 ^ t63;
    uint64_t s0 = t59 ^ t63;
    uint64_t s6 = ~(t56 ^ t62);
    uint64_t s7 = ~(t48 ^ t60);
    uint64_t t67 = t64 ^ t65;
    uint64_t s3 = t53 ^ t66;
    uint64_t s4 = t51 ^ t66;
    uint64_t s5 = t47 ^ t65;
    uint64_t s1 = ~(t64 ^ s3);
    uint64_t s2 = ~(t55 ^ t67);

    q[7] = s0;
    q[6] = s1;
    q[5] = s2;
    q[4] = s3;
    q[3] = s4;
    q[2] = s5;
    q[1] = s6;
    q[0] = s7;
}

static inline void pq_bs_shift_rows(uint64_t q[8]) {
    size_t k;
    for (k = 0U; k < 8U; k++) {
        uint64_t x = q[k];
        q[k] = (uint64_t)(uint16_t)x |
               ((uint64_t)pq_bs_rotr16_4((uint16_t)(x >> 16U)) << 16U) |
               ((uint64_t)pq_bs_rot16_8((uint16_t)(x >> 32U)) << 32U) |
               ((uint64_t)pq_bs_rotl16_4((uint16_t)(x >> 48U)) << 48U);
    }
}

static inline void pq_bs_inv_shift_rows(uint64_t q[8]) {
    size_t k;
    for (k = 0U; k < 8U; k++) {
        uint64_t x = q[k];
        q[k] = (uint64_t)(uint16_t)x |
               ((uint64_t)pq_bs_rotl16_4((uint16_t)(x >> 16U)) << 16U) |
               ((uint64_t)pq_bs_rot16_8((uint16_t)(x >> 32U)) << 32U) |
               ((uint64_t)pq_bs_rotr16_4((uint16_t)(x >> 48U)) << 48U);
    }
}

static void pq_bs_mix_columns(uint64_t q[8]) {
    uint64_t a[8], b[8];
    uint64_t a7;
    size_t k;
    for (k = 0U; k < 8U; k++) {
        uint64_t r1 = pq_bs_rotl64(q[k], 48U);
        uint64_t ak = q[k] ^ r1;
        a[k] = ak;
        b[k] = r1 ^ pq_bs_rotl64(ak, 32U);
    }
    a7 = a[7];
    q[0] = a7 ^ b[0];
    q[1] = a[0] ^ a7 ^ b[1];
    q[2] = a[1] ^ b[2];
    q[3] = a[2] ^ a7 ^ b[3];
    q[4] = a[3] ^ a7 ^ b[4];
    q[5] = a[4] ^ b[5];
    q[6] = a[5] ^ b[6];
    q[7] = a[6] ^ b[7];
}

static void pq_bs_inv_mix_columns(uint64_t q[8]) {
    uint64_t d[8], u[8], f[8];
    uint64_t d6, d7, d67, f7;
    size_t k;
    for (k = 0U; k < 8U; k++) {
        d[k] = q[k] ^ pq_bs_rotl64(q[k], 32U);
    }
    d6 = d[6];
    d7 = d[7];
    d67 = d6 ^ d7;
    u[0] = d6;
    u[1] = d67;
    u[2] = d[0] ^ d7;
    u[3] = d[1] ^ d6;
    u[4] = d[2] ^ d67;
    u[5] = d[3] ^ d7;
    u[6] = d[4];
    u[7] = d[5];

    for (k = 0U; k < 8U; k++) {
        f[k] = u[k] ^ pq_bs_rotl64(u[k], 48U);
    }
    pq_bs_mix_columns(q);
    f7 = f[7];
    q[0] ^= u[0] ^ f7;
    q[1] ^= u[1] ^ f[0] ^ f7;
    q[2] ^= u[2] ^ f[1];
    q[3] ^= u[3] ^ f[2] ^ f7;
    q[4] ^= u[4] ^ f[3] ^ f7;
    q[5] ^= u[5] ^ f[4];
    q[6] ^= u[6] ^ f[5];
    q[7] ^= u[7] ^ f[6];
}

static void pq_soft_inv_shift_rows(uint8_t out[16], const uint8_t in[16]) {
    uint64_t q[8];
    pq_bs_pack1(q, in);
    pq_bs_inv_shift_rows(q);
    pq_bs_unpack1(q, out);
}

static void pq_soft_mix_columns(uint8_t out[16], const uint8_t in[16]) {
    uint64_t q[8];
    pq_bs_pack1(q, in);
    pq_bs_mix_columns(q);
    pq_bs_unpack1(q, out);
}

static void pq_soft_inv_mix_columns(uint8_t out[16], const uint8_t in[16]) {
    uint64_t q[8];
    pq_bs_pack1(q, in);
    pq_bs_inv_mix_columns(q);
    pq_bs_unpack1(q, out);
}

/* =========================================================================
 * 3. Low-Level Pure-C Software Dispatch Kernels
 * ========================================================================= */

static AREION_PQ_NOINLINE void pq_extract_witness256_purec_body(
    uint8_t c[32], uint8_t w[288],
    const uint8_t m[32], const uint8_t k1[32], const uint8_t k2[32],
    const uint8_t rc[10][16]) {
    uint8_t x0[16], x1[16], a_next[16], u[16], b_next[16];
    uint64_t q[8], q_rc[8];
    size_t r, k;

    pq_xor16(x0, &m[0], &k1[0]);
    pq_xor16(x1, &m[16], &k1[16]);

    for (r = 0U; r < 10U; r++) {
        if ((r & 1U) == 0U) {
            pq_bs_pack1(q, x0);
        } else {
            pq_bs_pack1(q, x1);
        }
        pq_bs_sub_bytes(q);
        pq_bs_shift_rows(q);
        pq_bs_unpack1(q, a_next);

        pq_bs_mix_columns(q);
        pq_bs_pack1(q_rc, rc[r]);
        for (k = 0U; k < 8U; k++) {
            q[k] ^= q_rc[k];
        }
        pq_bs_sub_bytes(q);
        pq_bs_shift_rows(q);
        pq_bs_mix_columns(q);
        pq_bs_unpack1(q, u);

        if ((r & 1U) == 0U) {
            pq_xor16(b_next, x1, u);
            memcpy(x0, a_next, 16U);
            memcpy(x1, b_next, 16U);
        } else {
            pq_xor16(b_next, x0, u);
            memcpy(x1, a_next, 16U);
            memcpy(x0, b_next, 16U);
        }

        if (r < 9U) {
            memcpy(&w[32U * r], a_next, 16U);
            memcpy(&w[32U * r + 16U], b_next, 16U);
        }
    }

    pq_xor16(&c[0], x0, &k2[0]);
    pq_xor16(&c[16], x1, &k2[16]);
}

void areion_pq_extract_witness256_purec(
    uint8_t c[32], uint8_t w[288],
    const uint8_t m[32], const uint8_t k1[32], const uint8_t k2[32],
    const uint8_t rc[10][16]) {
    pq_extract_witness256_purec_body(c, w, m, k1, k2, rc);
    areion_pq_wipe_software_stack();
    areion_pq_clobber_scratch_gprs();
}

static void pq_clmul64(uint64_t x, uint64_t y, uint64_t *lo_out, uint64_t *hi_out) {
    uint64_t lo = 0ULL;
    uint64_t hi = 0ULL;
    unsigned int i;
    for (i = 0U; i < 64U; i++) {
        uint64_t mask = 0ULL - ((y >> i) & 1ULL);
        lo ^= (x << i) & mask;
        if (i > 0U) {
            hi ^= (x >> (64U - i)) & mask;
        }
    }
    *lo_out = lo;
    *hi_out = hi;
}

AREION_PQ_NOINLINE void areion_pq_gf128_mul_core(uint8_t out[16], const uint8_t a[16], const uint8_t b[16]) {
    uint64_t a0 = areion_pq_load_le64(&a[0]);
    uint64_t a1 = areion_pq_load_le64(&a[8]);
    uint64_t b0 = areion_pq_load_le64(&b[0]);
    uint64_t b1 = areion_pq_load_le64(&b[8]);
    uint64_t l0, l1, h0, h1, m0, m1;
    uint64_t c0, c1, t1, t1_hi, r0, r1;

    pq_clmul64(a0, b0, &l0, &l1);
    pq_clmul64(a1, b1, &h0, &h1);
    pq_clmul64(a0 ^ a1, b0 ^ b1, &m0, &m1);
    m0 ^= l0 ^ h0;
    m1 ^= l1 ^ h1;

    c0 = l0;
    c1 = l1 ^ m0;
    h0 ^= m1;

    /* Reduce c_high = (h0, h1) modulo x^128 + x^7 + x^2 + x + 1 (0x87). */
    t1 = (h1 << 7U) ^ (h1 << 2U) ^ (h1 << 1U) ^ h1;
    t1_hi = (h1 >> 57U) ^ (h1 >> 62U) ^ (h1 >> 63U);
    h0 ^= t1_hi;
    r1 = c1 ^ t1 ^ (h0 >> 57U) ^ (h0 >> 62U) ^ (h0 >> 63U);
    r0 = c0 ^ (h0 << 7U) ^ (h0 << 2U) ^ (h0 << 1U) ^ h0;

    areion_pq_store_le64(&out[0], r0);
    areion_pq_store_le64(&out[8], r1);
}

void areion_pq_gf128_mul_purec(uint8_t out[16], const uint8_t a[16], const uint8_t b[16]) {
    areion_pq_gf128_mul_core(out, a, b);
    areion_pq_wipe_software_stack();
    areion_pq_clobber_scratch_gprs();
}

static AREION_PQ_NOINLINE void pq_gf128_polymac_purec_body(
    uint8_t acc[16], const uint8_t *a, const uint8_t *b, size_t count, const uint8_t chi[16]) {
    uint8_t ai[16], bi[16], prod[16], cur[16];
    size_t i;

    memcpy(cur, acc, 16U);
    for (i = 0U; i < count; i++) {
        memcpy(ai, &a[16U * i], 16U);
        memcpy(bi, &b[16U * i], 16U);
        areion_pq_gf128_mul_core(prod, ai, bi);
        areion_pq_gf128_mul_core(cur, cur, chi);
        pq_xor16(cur, cur, prod);
    }
    memcpy(acc, cur, 16U);
}

void areion_pq_gf128_polymac_purec(
    uint8_t acc[16], const uint8_t *a, const uint8_t *b, size_t count, const uint8_t chi[16]) {
    pq_gf128_polymac_purec_body(acc, a, b, count, chi);
    areion_pq_wipe_software_stack();
    areion_pq_clobber_scratch_gprs();
}

AREION_PQ_NOINLINE void areion_pq_vole_xor_row_core(uint8_t *dst, const uint8_t *src, size_t len) {
    size_t i = 0U;
    for (; i + 8U <= len; i += 8U) {
        uint64_t v = areion_pq_load_le64(&dst[i]) ^ areion_pq_load_le64(&src[i]);
        areion_pq_store_le64(&dst[i], v);
    }
    for (; i < len; i++) {
        dst[i] ^= src[i];
    }
}

void areion_pq_vole_xor_row_purec(uint8_t *dst, const uint8_t *src, size_t len) {
    areion_pq_vole_xor_row_core(dst, src, len);
    areion_pq_wipe_software_stack();
    areion_pq_clobber_scratch_gprs();
}

static AREION_PQ_NOINLINE void pq_wots_chain256x4_purec_body(
    uint8_t out[4][32], const uint8_t in[4][32], const uint8_t adrs[4][32],
    const uint8_t kpub1[32], const uint8_t kpub2[32],
    uint32_t start_step, uint32_t steps) {
    uint8_t cur[4][32];
    uint8_t b512[4][64];
    uint8_t p512[4][64];
    uint32_t kp1_be28;
    uint32_t s, lane;

    memcpy(cur, in, sizeof(cur));
    if (steps == 0U) {
        memcpy(out, cur, sizeof(cur));
        return;
    }
    kp1_be28 = areion_pq_load_be32(&kpub1[28]);
    for (lane = 0U; lane < 4U; lane++) {
        pq_xor32(&b512[lane][0], adrs[lane], kpub1);
    }

    for (s = 0U; s < steps; s++) {
        uint32_t step_masked = (start_step + s) ^ kp1_be28;
        for (lane = 0U; lane < 4U; lane++) {
            areion_pq_store_be32(&b512[lane][28], step_masked);
            pq_xor32(&b512[lane][32], cur[lane], kpub2);
        }
        memcpy(p512, b512, sizeof(p512));
        areion_permute512x4(p512[0], p512[1], p512[2], p512[3]);
        for (lane = 0U; lane < 4U; lane++) {
            uint64_t w0 = areion_pq_load_le64(&p512[lane][8]) ^ areion_pq_load_le64(&b512[lane][8]);
            uint64_t w1 = areion_pq_load_le64(&p512[lane][24]) ^ areion_pq_load_le64(&b512[lane][24]);
            uint64_t w2 = areion_pq_load_le64(&p512[lane][32]) ^ areion_pq_load_le64(&b512[lane][32]);
            uint64_t w3 = areion_pq_load_le64(&p512[lane][48]) ^ areion_pq_load_le64(&b512[lane][48]);
            areion_pq_store_le64(&cur[lane][0], w0);
            areion_pq_store_le64(&cur[lane][8], w1);
            areion_pq_store_le64(&cur[lane][16], w2);
            areion_pq_store_le64(&cur[lane][24], w3);
        }
    }

    memcpy(out, cur, sizeof(cur));
}

void areion_pq_wots_chain256x4_purec(
    uint8_t out[4][32], const uint8_t in[4][32], const uint8_t adrs[4][32],
    const uint8_t kpub1[32], const uint8_t kpub2[32],
    uint32_t start_step, uint32_t steps) {
    pq_wots_chain256x4_purec_body(out, in, adrs, kpub1, kpub2, start_step, steps);
    areion_pq_wipe_software_stack();
    areion_pq_clobber_scratch_gprs();
}

/* =========================================================================
 * 4. Public Finite Field & Witness Primitives (§3.2)
 * ========================================================================= */

uint8_t areion_pq_gf256_mul(uint8_t a, uint8_t b) {
    uint32_t p = 0U;
    uint32_t x = (uint32_t)a;
    uint32_t y = (uint32_t)b;
    unsigned int i;
    for (i = 0U; i < 8U; i++) {
        uint32_t mask = (0U - (y & 1U)) & 0xFFU;
        uint32_t hi = (0U - ((x >> 7U) & 1U)) & 0x1BU;
        p ^= x & mask;
        x = ((x << 1U) & 0xFFU) ^ hi;
        y >>= 1U;
    }
    return (uint8_t)p;
}

uint8_t areion_pq_gf256_sq(uint8_t a) {
    return areion_pq_gf256_mul(a, a);
}

uint8_t areion_pq_gf256_inv(uint8_t a) {
    uint8_t a2 = areion_pq_gf256_sq(a);
    uint8_t a3 = areion_pq_gf256_mul(a2, a);
    uint8_t a6 = areion_pq_gf256_sq(a3);
    uint8_t a12 = areion_pq_gf256_sq(a6);
    uint8_t a14 = areion_pq_gf256_mul(a12, a2);
    uint8_t a15 = areion_pq_gf256_mul(a14, a);
    uint8_t a30 = areion_pq_gf256_sq(a15);
    uint8_t a60 = areion_pq_gf256_sq(a30);
    uint8_t a120 = areion_pq_gf256_sq(a60);
    uint8_t a240 = areion_pq_gf256_sq(a120);
    return areion_pq_gf256_mul(a240, a14);
}

static inline uint8_t pq_rotl8(uint8_t x, unsigned int k) {
    return (uint8_t)((((uint32_t)x << k) | ((uint32_t)x >> (8U - k))) & 0xFFU);
}

uint8_t areion_pq_gf256_affine(uint8_t a) {
    return (uint8_t)((uint32_t)a ^ (uint32_t)pq_rotl8(a, 1U) ^ (uint32_t)pq_rotl8(a, 2U) ^ (uint32_t)pq_rotl8(a, 3U) ^ (uint32_t)pq_rotl8(a, 4U) ^ 0x63U);
}

uint8_t areion_pq_gf256_affine_inv(uint8_t s) {
    uint8_t u = (uint8_t)(s ^ 0x63U);
    return (uint8_t)((uint32_t)pq_rotl8(u, 1U) ^ (uint32_t)pq_rotl8(u, 3U) ^ (uint32_t)pq_rotl8(u, 6U));
}

void areion_pq_gf128_mul(uint8_t out[16], const uint8_t a[16], const uint8_t b[16]) {
    areion_pq_dispatch_gf128_mul(out, a, b);
}

void areion_pq_gf128_polymac(
    uint8_t out[16], const uint8_t *a, const uint8_t *b, size_t count, const uint8_t chi[16]) {
    uint8_t acc[16];
    memset(acc, 0, sizeof(acc));
    if (count > 0U && a != NULL && b != NULL) {
        areion_pq_dispatch_gf128_polymac(acc, a, b, count, chi);
    }
    memcpy(out, acc, 16U);
    areion_pq_secure_wipe(acc, sizeof(acc));
}

static AREION_PQ_NOINLINE void pq_gf256_field_mul_body(
    uint8_t out[32], const uint8_t a[32], const uint8_t b[32]) {
    uint8_t a0[16], a1[16], b0[16], b1[16];
    uint8_t a01[16], b01[16], p0[16], p1[16], pm[16], alpha[16], p1_alpha[16];

    memcpy(a0, &a[0], 16U);
    memcpy(a1, &a[16], 16U);
    memcpy(b0, &b[0], 16U);
    memcpy(b1, &b[16], 16U);
    pq_xor16(a01, a0, a1);
    pq_xor16(b01, b0, b1);

    areion_pq_dispatch_gf128_mul_nowipe(p0, a0, b0);
    areion_pq_dispatch_gf128_mul_nowipe(p1, a1, b1);
    areion_pq_dispatch_gf128_mul_nowipe(pm, a01, b01);

    memset(alpha, 0, sizeof(alpha));
    alpha[0] = 0x87U;
    areion_pq_dispatch_gf128_mul_nowipe(p1_alpha, p1, alpha);

    pq_xor16(&out[0], p0, p1_alpha);
    pq_xor16(&out[16], pm, p0);
}

void areion_pq_gf256_field_mul(uint8_t out[32], const uint8_t a[32], const uint8_t b[32]) {
    pq_gf256_field_mul_body(out, a, b);
    areion_pq_wipe_software_stack();
    areion_pq_clobber_scratch_gprs();
}

static AREION_PQ_NOINLINE void pq_mul_ortho256_body(
    uint8_t out[32], const uint8_t t[32], const uint8_t k[32]) {
    uint8_t r0[16], r1[16];
    areion_pq_dispatch_gf128_mul_nowipe(r0, &t[0], &k[0]);
    areion_pq_dispatch_gf128_mul_nowipe(r1, &t[16], &k[16]);
    memcpy(&out[0], r0, 16U);
    memcpy(&out[16], r1, 16U);
}

void areion_pq_mul_ortho256(uint8_t out[32], const uint8_t t[32], const uint8_t k[32]) {
    pq_mul_ortho256_body(out, t, k);
    areion_pq_wipe_software_stack();
    areion_pq_clobber_scratch_gprs();
}

static AREION_PQ_NOINLINE void pq_ortho_sigma256_body(uint8_t out[32], const uint8_t k[32]) {
    uint8_t k0[16], k1[16];
    memcpy(k0, &k[0], 16U);
    memcpy(k1, &k[16], 16U);
    memcpy(&out[0], k1, 16U);
    pq_xor16(&out[16], k0, k1);
}

void areion_pq_ortho_sigma256(uint8_t out[32], const uint8_t k[32]) {
    pq_ortho_sigma256_body(out, k);
    areion_pq_wipe_software_stack();
    areion_pq_clobber_scratch_gprs();
}

void areion_pq_extract_witness256(
    uint8_t c[32], uint8_t w[288], const uint8_t m[32], const uint8_t k1[32], const uint8_t k2[32]) {
    areion_pq_dispatch_extract_witness256(c, w, m, k1, k2, areion_pq_rc_p1);
}

void areion_pq_extract_witness256_p2(
    uint8_t c[32], uint8_t w[288], const uint8_t m[32], const uint8_t k1[32], const uint8_t k2[32]) {
    areion_pq_dispatch_extract_witness256(c, w, m, k1, k2, areion_pq_rc_p2);
}

static AREION_PQ_NOINLINE int pq_verify_witness256_purec_body(
    const uint8_t m[32], const uint8_t c[32],
    const uint8_t k1[32], const uint8_t k2[32],
    const uint8_t w[288], const uint8_t rc[10][16]) {
    uint8_t x0[16], x1[16], a[16], b[16], a_next[16], b_next[16];
    uint8_t t[16], x_l1[16], s_l1[16], x_l2[16], s_l2[16], tmp_mc[16], tmp_imc[16];
    uint32_t diff = 0U;
    size_t r, j;

    pq_xor16(x0, &m[0], &k1[0]);
    pq_xor16(x1, &m[16], &k1[16]);

    for (r = 0U; r < 10U; r++) {
        if ((r & 1U) == 0U) {
            memcpy(a, x0, 16U);
            memcpy(b, x1, 16U);
        } else {
            memcpy(a, x1, 16U);
            memcpy(b, x0, 16U);
        }
        if (r < 9U) {
            memcpy(a_next, &w[32U * r], 16U);
            memcpy(b_next, &w[32U * r + 16U], 16U);
        } else {
            pq_xor16(a_next, &c[16], &k2[16]);
            pq_xor16(b_next, &c[0], &k2[0]);
        }

        memcpy(x_l1, a, 16U);
        pq_soft_inv_shift_rows(s_l1, a_next);
        for (j = 0U; j < 16U; j++) {
            uint8_t xj = x_l1[j];
            uint8_t sj = s_l1[j];
            uint8_t uj = areion_pq_gf256_sq(xj);
            uint8_t yj = areion_pq_gf256_affine_inv(sj);
            uint8_t wj = areion_pq_gf256_sq(yj);
            diff |= ((uint32_t)areion_pq_gf256_mul(uj, yj) ^ (uint32_t)xj) | ((uint32_t)areion_pq_gf256_mul(wj, xj) ^ (uint32_t)yj);
        }

        pq_soft_mix_columns(tmp_mc, a_next);
        pq_xor16(x_l2, tmp_mc, rc[r]);
        pq_xor16(t, b, b_next);
        pq_soft_inv_mix_columns(tmp_imc, t);
        pq_soft_inv_shift_rows(s_l2, tmp_imc);
        for (j = 0U; j < 16U; j++) {
            uint8_t xj = x_l2[j];
            uint8_t sj = s_l2[j];
            uint8_t uj = areion_pq_gf256_sq(xj);
            uint8_t yj = areion_pq_gf256_affine_inv(sj);
            uint8_t wj = areion_pq_gf256_sq(yj);
            diff |= ((uint32_t)areion_pq_gf256_mul(uj, yj) ^ (uint32_t)xj) | ((uint32_t)areion_pq_gf256_mul(wj, xj) ^ (uint32_t)yj);
        }

        if ((r & 1U) == 0U) {
            memcpy(x0, a_next, 16U);
            memcpy(x1, b_next, 16U);
        } else {
            memcpy(x1, a_next, 16U);
            memcpy(x0, b_next, 16U);
        }
    }

    return (int)(1U & ((diff - 1U) >> 31U));
}

static int pq_verify_witness256_internal(
    const uint8_t m[32], const uint8_t c[32],
    const uint8_t k1[32], const uint8_t k2[32],
    const uint8_t w[288], const uint8_t rc[10][16]) {
    int ok;
    if (areion_pq_has_hw_extract_witness256()) {
        uint8_t c_exp[32];
        uint8_t w_exp[288];
        areion_pq_dispatch_extract_witness256(c_exp, w_exp, m, k1, k2, rc);
        ok = (int)((uint32_t)areion_pq_ct_eq(c, c_exp, 32U) &
                   (uint32_t)areion_pq_ct_eq(w, w_exp, 288U));
        areion_pq_secure_wipe(c_exp, sizeof(c_exp));
        areion_pq_secure_wipe(w_exp, sizeof(w_exp));
        areion_pq_clobber_scratch_gprs();
        return ok;
    }
    ok = pq_verify_witness256_purec_body(m, c, k1, k2, w, rc);
    areion_pq_wipe_software_stack();
    areion_pq_clobber_scratch_gprs();
    return ok;
}

int areion_pq_verify_witness256(
    const uint8_t m[32], const uint8_t c[32], const uint8_t k1[32], const uint8_t k2[32], const uint8_t w[288]) {
    return pq_verify_witness256_internal(m, c, k1, k2, w, areion_pq_rc_p1);
}

int areion_pq_verify_witness256_p2(
    const uint8_t m[32], const uint8_t c[32], const uint8_t k1[32], const uint8_t k2[32], const uint8_t w[288]) {
    return pq_verify_witness256_internal(m, c, k1, k2, w, areion_pq_rc_p2);
}

static AREION_PQ_NOINLINE void pq_extract_witness_em2_256_body(
    uint8_t c[32], uint8_t w[576], const uint8_t m[32], const uint8_t k1[32], const uint8_t k2[32]) {
    uint8_t zero32[32];
    uint8_t u_p1[32], k12[32];

    memset(zero32, 0, sizeof(zero32));
    pq_xor32(k12, k1, k2);
    areion_pq_dispatch_extract_witness256(u_p1, &w[0], m, k1, zero32, areion_pq_rc_p1);
    areion_pq_dispatch_extract_witness256(c, &w[288], u_p1, k2, k12, areion_pq_rc_p2);

    areion_pq_secure_wipe(u_p1, sizeof(u_p1));
    areion_pq_secure_wipe(k12, sizeof(k12));
}

void areion_pq_extract_witness_em2_256(
    uint8_t c[32], uint8_t w[576], const uint8_t m[32], const uint8_t k1[32], const uint8_t k2[32]) {
    pq_extract_witness_em2_256_body(c, w, m, k1, k2);
    if (!areion_pq_has_hw_extract_witness256()) {
        areion_pq_wipe_software_stack();
    }
    areion_pq_clobber_scratch_gprs();
}

static AREION_PQ_NOINLINE int pq_verify_witness_em2_256_purec_body(
    const uint8_t m[32], const uint8_t c[32], const uint8_t k1[32], const uint8_t k2[32], const uint8_t w[576]) {
    uint8_t zero32[32];
    uint8_t x0[16], x1[16], a_next9[16], u9[16], b_next9[16], u_p1[32], k12[32];
    uint64_t q[8], q_rc[8];
    size_t k;
    int ok1, ok2;

    memset(zero32, 0, sizeof(zero32));
    /* Recompute Round 9 output of P1 from round 8 witness w[256..287]. */
    memcpy(x0, &w[256], 16U);
    memcpy(x1, &w[272], 16U);
    pq_bs_pack1(q, x1);
    pq_bs_sub_bytes(q);
    pq_bs_shift_rows(q);
    pq_bs_unpack1(q, a_next9);

    pq_bs_mix_columns(q);
    pq_bs_pack1(q_rc, areion_pq_rc_p1[9]);
    for (k = 0U; k < 8U; k++) {
        q[k] ^= q_rc[k];
    }
    pq_bs_sub_bytes(q);
    pq_bs_shift_rows(q);
    pq_bs_mix_columns(q);
    pq_bs_unpack1(q, u9);
    pq_xor16(b_next9, x0, u9);

    memcpy(&u_p1[0], b_next9, 16U);
    memcpy(&u_p1[16], a_next9, 16U);
    pq_xor32(k12, k1, k2);

    ok1 = pq_verify_witness256_purec_body(m, u_p1, k1, zero32, &w[0], areion_pq_rc_p1);
    ok2 = pq_verify_witness256_purec_body(u_p1, c, k2, k12, &w[288], areion_pq_rc_p2);

    return (ok1 != 0 && ok2 != 0) ? 1 : 0;
}

int areion_pq_verify_witness_em2_256(
    const uint8_t m[32], const uint8_t c[32], const uint8_t k1[32], const uint8_t k2[32], const uint8_t w[576]) {
    int ok;
    if (areion_pq_has_hw_extract_witness256()) {
        uint8_t zero32[32];
        uint8_t u_p1[32], c_exp[32], k12[32];
        uint8_t w1_exp[288], w2_exp[288];

        memset(zero32, 0, sizeof(zero32));
        pq_xor32(k12, k1, k2);
        areion_pq_dispatch_extract_witness256(u_p1, w1_exp, m, k1, zero32, areion_pq_rc_p1);
        areion_pq_dispatch_extract_witness256(c_exp, w2_exp, u_p1, k2, k12, areion_pq_rc_p2);

        ok = (int)((uint32_t)areion_pq_ct_eq(c, c_exp, 32U) &
                   (uint32_t)areion_pq_ct_eq(&w[0], w1_exp, 288U) &
                   (uint32_t)areion_pq_ct_eq(&w[288], w2_exp, 288U));

        areion_pq_secure_wipe(u_p1, sizeof(u_p1));
        areion_pq_secure_wipe(c_exp, sizeof(c_exp));
        areion_pq_secure_wipe(k12, sizeof(k12));
        areion_pq_secure_wipe(w1_exp, sizeof(w1_exp));
        areion_pq_secure_wipe(w2_exp, sizeof(w2_exp));
        areion_pq_clobber_scratch_gprs();
        return ok;
    }
    ok = pq_verify_witness_em2_256_purec_body(m, c, k1, k2, w);
    areion_pq_wipe_software_stack();
    areion_pq_clobber_scratch_gprs();
    return ok;
}


/* =========================================================================
 * 5. Track 3: Areion-HPKE, KDF & TEM2-SIV Wide-Block AEAD (§3.5 & §8)
 * ========================================================================= */

#undef areion_pq_slh_prf256x4

static AREION_PQ_NOINLINE void pq_kdf_expand_body(
    uint8_t *dst, size_t dst_len,
    const uint8_t *secret, size_t secret_len,
    const uint8_t *context, size_t context_len) {
    uint8_t dom[32];
    uint8_t v[32], v2[32];
    uint8_t b512[64];
    uint8_t k0[32], k1[32], k2[32], k3[32];
    uint8_t k_soem[128];
    uint8_t keys4[4][128];
    uint8_t base_in[64];
    uint8_t in4[4][64], out4[4][64];
    uint8_t in64[64], out64[64];
    size_t off;
    uint64_t blk_idx;
    unsigned int lane;

    if (dst_len == 0U || dst == NULL) {
        return;
    }

    memset(dom, 0, sizeof(dom));
    areion_pq_store_le64(&dom[0], (uint64_t)secret_len);
    areion_pq_store_le64(&dom[8], (uint64_t)context_len);
    areion_pq_store_le64(&dom[16], UINT64_C(0x415245494F4E4B44));

    areion_dm256(v, dom);

    for (off = 0U; off < secret_len; off += 32U) {
        size_t rem = secret_len - off;
        if (rem > 32U) {
            rem = 32U;
        }
        memset(b512, 0, sizeof(b512));
        memcpy(&b512[0], v, 32U);
        if (secret != NULL && rem > 0U) {
            memcpy(&b512[32], &secret[off], rem);
        }
        areion_dm512(v, b512);
    }

    v[0] ^= 0x01U;
    areion_dm256(v, v);

    for (off = 0U; off < context_len; off += 32U) {
        size_t rem = context_len - off;
        if (rem > 32U) {
            rem = 32U;
        }
        memset(b512, 0, sizeof(b512));
        memcpy(&b512[0], v, 32U);
        if (context != NULL && rem > 0U) {
            memcpy(&b512[32], &context[off], rem);
        }
        areion_dm512(v, b512);
    }

    areion_dm256(k0, v);
    memcpy(k1, v, 32U);
    areion_permute256_p2(k1);
    pq_xor32(k1, k1, v);

    memcpy(v2, v, 32U);
    v2[0] ^= 0x02U;
    areion_dm256(k2, v2);
    memcpy(k3, v2, 32U);
    areion_permute256_p2(k3);
    pq_xor32(k3, k3, v2);

    memcpy(&k_soem[0], k0, 32U);
    memcpy(&k_soem[32], k1, 32U);
    memcpy(&k_soem[64], k2, 32U);
    memcpy(&k_soem[96], k3, 32U);

    for (lane = 0U; lane < 4U; lane++) {
        memcpy(keys4[lane], k_soem, 128U);
    }

    memcpy(&base_in[0], v, 32U);
    memcpy(&base_in[32], v2, 32U);

    blk_idx = 0U;
    off = 0U;
    while (off + 256U <= dst_len) {
        for (lane = 0U; lane < 4U; lane++) {
            uint64_t idx = blk_idx + (uint64_t)lane;
            uint64_t w0, w1;
            memcpy(in4[lane], base_in, 64U);
            w0 = areion_pq_load_le64(&in4[lane][0]) ^ idx;
            w1 = areion_pq_load_le64(&in4[lane][32]) ^ (idx ^ UINT64_C(0x5555555555555555));
            areion_pq_store_le64(&in4[lane][0], w0);
            areion_pq_store_le64(&in4[lane][32], w1);
        }
        areion_soem512x4(out4, (const uint8_t (*)[128])keys4, (const uint8_t (*)[64])in4);
        for (lane = 0U; lane < 4U; lane++) {
            memcpy(&dst[off + 64U * (size_t)lane], out4[lane], 64U);
        }
        blk_idx += 4U;
        off += 256U;
    }

    while (off < dst_len) {
        uint64_t w0, w1;
        size_t rem = dst_len - off;
        if (rem > 64U) {
            rem = 64U;
        }
        memcpy(in64, base_in, 64U);
        w0 = areion_pq_load_le64(&in64[0]) ^ blk_idx;
        w1 = areion_pq_load_le64(&in64[32]) ^ (blk_idx ^ UINT64_C(0x5555555555555555));
        areion_pq_store_le64(&in64[0], w0);
        areion_pq_store_le64(&in64[32], w1);
        areion_soem512(out64, k_soem, in64);
        memcpy(&dst[off], out64, rem);
        blk_idx++;
        off += rem;
    }

    areion_pq_secure_wipe(dom, sizeof(dom));
    areion_pq_secure_wipe(v, sizeof(v));
    areion_pq_secure_wipe(v2, sizeof(v2));
    areion_pq_secure_wipe(b512, sizeof(b512));
    areion_pq_secure_wipe(k0, sizeof(k0));
    areion_pq_secure_wipe(k1, sizeof(k1));
    areion_pq_secure_wipe(k2, sizeof(k2));
    areion_pq_secure_wipe(k3, sizeof(k3));
    areion_pq_secure_wipe(k_soem, sizeof(k_soem));
    areion_pq_secure_wipe(keys4, sizeof(keys4));
    areion_pq_secure_wipe(base_in, sizeof(base_in));
    areion_pq_secure_wipe(in4, sizeof(in4));
    areion_pq_secure_wipe(out4, sizeof(out4));
    areion_pq_secure_wipe(in64, sizeof(in64));
    areion_pq_secure_wipe(out64, sizeof(out64));
}

void areion_pq_kdf_expand(
    uint8_t *dst, size_t dst_len,
    const uint8_t *secret, size_t secret_len,
    const uint8_t *context, size_t context_len) {
    pq_kdf_expand_body(dst, dst_len, secret, secret_len, context, context_len);
    areion_pq_wipe_software_stack();
    areion_pq_clobber_scratch_gprs();
}

static void pq_tem2_siv_absorb_stream(
    uint8_t acc[64], const uint8_t key[128],
    const uint8_t *data, size_t data_len, uint64_t dom) {
    uint8_t keys4[4][128];
    uint8_t in4[4][64], mac4[4][64];
    uint8_t in_blk[64], mac_blk[64];
    uint64_t idx = 0U;
    size_t off = 0U;
    unsigned int lane;

    for (lane = 0U; lane < 4U; lane++) {
        memcpy(keys4[lane], key, 128U);
    }

    while (off + 256U <= data_len) {
        for (lane = 0U; lane < 4U; lane++) {
            uint64_t w0, w1;
            memcpy(in4[lane], &data[off + 64U * (size_t)lane], 64U);
            w0 = areion_pq_load_le64(&in4[lane][0]) ^ (idx + (uint64_t)lane);
            w1 = areion_pq_load_le64(&in4[lane][8]) ^ dom;
            areion_pq_store_le64(&in4[lane][0], w0);
            areion_pq_store_le64(&in4[lane][8], w1);
        }
        areion_soem512x4(mac4, (const uint8_t (*)[128])keys4, (const uint8_t (*)[64])in4);
        for (lane = 0U; lane < 4U; lane++) {
            pq_xor64(acc, acc, mac4[lane]);
        }
        idx += 4U;
        off += 256U;
    }

    while (off < data_len) {
        uint64_t w0, w1;
        size_t rem = data_len - off;
        if (rem > 64U) {
            rem = 64U;
        }
        memset(in_blk, 0, sizeof(in_blk));
        if (data != NULL && rem > 0U) {
            memcpy(in_blk, &data[off], rem);
        }
        w0 = areion_pq_load_le64(&in_blk[0]) ^ idx;
        w1 = areion_pq_load_le64(&in_blk[8]) ^ dom;
        areion_pq_store_le64(&in_blk[0], w0);
        areion_pq_store_le64(&in_blk[8], w1);
        areion_soem512(mac_blk, key, in_blk);
        pq_xor64(acc, acc, mac_blk);
        idx++;
        off += rem;
    }

    areion_pq_secure_wipe(keys4, sizeof(keys4));
    areion_pq_secure_wipe(in4, sizeof(in4));
    areion_pq_secure_wipe(mac4, sizeof(mac4));
    areion_pq_secure_wipe(in_blk, sizeof(in_blk));
    areion_pq_secure_wipe(mac_blk, sizeof(mac_blk));
}

static void pq_tem2_siv_compute_tag(
    uint8_t tag[32], const uint8_t key[128], const uint8_t nonce[32],
    const uint8_t *ad, size_t ad_len,
    const uint8_t *plaintext, size_t plaintext_len) {
    uint8_t acc[64];

    memset(acc, 0, sizeof(acc));
    memcpy(&acc[0], nonce, 32U);
    areion_pq_store_le64(&acc[32], (uint64_t)ad_len);
    areion_pq_store_le64(&acc[40], (uint64_t)plaintext_len);
    areion_pq_store_le64(&acc[48], UINT64_C(0x54454D3253495630));
    areion_soem512(acc, key, acc);

    pq_tem2_siv_absorb_stream(acc, key, ad, ad_len, UINT64_C(0x4144000000000001));
    pq_tem2_siv_absorb_stream(acc, key, plaintext, plaintext_len, UINT64_C(0x5054000000000002));
    areion_dm512(tag, acc);

    areion_pq_secure_wipe(acc, sizeof(acc));
}

static AREION_PQ_NOINLINE void pq_tem2_siv_encrypt_body(
    uint8_t *ciphertext, uint8_t tag[32],
    const uint8_t key[128], const uint8_t nonce[32],
    const uint8_t *ad, size_t ad_len,
    const uint8_t *plaintext, size_t pt_len) {
    uint8_t k_enc[128];
    uint8_t keys4[4][128];
    uint8_t tweaks4[4][64], msgs4[4][64], ct4[4][64];
    uint8_t tweak[64], msg[64], ct[64];
    uint8_t t_tail[64], stream[64];
    uint64_t blk_idx;
    size_t off;
    unsigned int lane;

    pq_tem2_siv_compute_tag(tag, key, nonce, ad, ad_len, plaintext, pt_len);
    if (pt_len == 0U) {
        return;
    }

    memcpy(k_enc, key, 128U);
    k_enc[0] ^= 0x5AU;
    for (lane = 0U; lane < 4U; lane++) {
        memcpy(keys4[lane], k_enc, 128U);
        memcpy(&tweaks4[lane][0], tag, 32U);
        memcpy(&tweaks4[lane][32], &nonce[0], 16U);
        areion_pq_store_le64(&tweaks4[lane][56], UINT64_C(0x54454D3253495601));
    }

    blk_idx = 0U;
    off = 0U;
    while (off + 256U <= pt_len) {
        for (lane = 0U; lane < 4U; lane++) {
            areion_pq_store_le64(&tweaks4[lane][48], blk_idx + (uint64_t)lane);
            memcpy(msgs4[lane], &plaintext[off + 64U * (size_t)lane], 64U);
        }
        areion_tem2_encrypt512x4(
            ct4, (const uint8_t (*)[128])keys4,
            (const uint8_t (*)[64])tweaks4, (const uint8_t (*)[64])msgs4);
        for (lane = 0U; lane < 4U; lane++) {
            memcpy(&ciphertext[off + 64U * (size_t)lane], ct4[lane], 64U);
        }
        blk_idx += 4U;
        off += 256U;
    }

    while (off + 64U <= pt_len) {
        memcpy(&tweak[0], tag, 32U);
        memcpy(&tweak[32], &nonce[0], 16U);
        areion_pq_store_le64(&tweak[48], blk_idx);
        areion_pq_store_le64(&tweak[56], UINT64_C(0x54454D3253495601));
        memcpy(msg, &plaintext[off], 64U);
        areion_tem2_encrypt512(ct, k_enc, tweak, msg);
        memcpy(&ciphertext[off], ct, 64U);
        blk_idx++;
        off += 64U;
    }

    if (off < pt_len) {
        size_t rem = pt_len - off;
        size_t i;
        memcpy(&t_tail[0], tag, 32U);
        memcpy(&t_tail[32], &nonce[16], 16U);
        areion_pq_store_le64(&t_tail[48], blk_idx);
        areion_pq_store_le64(&t_tail[56], UINT64_C(0x54454D3253495602));
        areion_soem512(stream, k_enc, t_tail);
        for (i = 0U; i < rem; i++) {
            ciphertext[off + i] = (uint8_t)(plaintext[off + i] ^ stream[i]);
        }
    }

    areion_pq_secure_wipe(k_enc, sizeof(k_enc));
    areion_pq_secure_wipe(keys4, sizeof(keys4));
    areion_pq_secure_wipe(tweaks4, sizeof(tweaks4));
    areion_pq_secure_wipe(msgs4, sizeof(msgs4));
    areion_pq_secure_wipe(ct4, sizeof(ct4));
    areion_pq_secure_wipe(tweak, sizeof(tweak));
    areion_pq_secure_wipe(msg, sizeof(msg));
    areion_pq_secure_wipe(ct, sizeof(ct));
    areion_pq_secure_wipe(t_tail, sizeof(t_tail));
    areion_pq_secure_wipe(stream, sizeof(stream));
}

void areion_pq_tem2_siv_encrypt(
    uint8_t *ciphertext, uint8_t tag[32],
    const uint8_t key[128], const uint8_t nonce[32],
    const uint8_t *ad, size_t ad_len,
    const uint8_t *plaintext, size_t pt_len) {
    pq_tem2_siv_encrypt_body(ciphertext, tag, key, nonce, ad, ad_len, plaintext, pt_len);
    areion_pq_wipe_software_stack();
    areion_pq_clobber_scratch_gprs();
}

static AREION_PQ_NOINLINE int pq_tem2_siv_decrypt_body(
    uint8_t *plaintext,
    const uint8_t key[128], const uint8_t nonce[32],
    const uint8_t *ad, size_t ad_len,
    const uint8_t *ciphertext, size_t ct_len,
    const uint8_t tag[32]) {
    uint8_t k_enc[128];
    uint8_t keys4[4][128];
    uint8_t tweaks4[4][64], cts4[4][64], pt4[4][64];
    uint8_t tweak[64], ct[64], pt[64];
    uint8_t t_tail[64], stream[64];
    uint8_t expected_tag[32];
    uint64_t blk_idx;
    size_t off;
    unsigned int lane;
    int ok;

    memcpy(k_enc, key, 128U);
    k_enc[0] ^= 0x5AU;
    for (lane = 0U; lane < 4U; lane++) {
        memcpy(keys4[lane], k_enc, 128U);
        memcpy(&tweaks4[lane][0], tag, 32U);
        memcpy(&tweaks4[lane][32], &nonce[0], 16U);
        areion_pq_store_le64(&tweaks4[lane][56], UINT64_C(0x54454D3253495601));
    }

    blk_idx = 0U;
    off = 0U;
    while (off + 256U <= ct_len) {
        for (lane = 0U; lane < 4U; lane++) {
            areion_pq_store_le64(&tweaks4[lane][48], blk_idx + (uint64_t)lane);
            memcpy(cts4[lane], &ciphertext[off + 64U * (size_t)lane], 64U);
        }
        areion_tem2_decrypt512x4(
            pt4, (const uint8_t (*)[128])keys4,
            (const uint8_t (*)[64])tweaks4, (const uint8_t (*)[64])cts4);
        for (lane = 0U; lane < 4U; lane++) {
            memcpy(&plaintext[off + 64U * (size_t)lane], pt4[lane], 64U);
        }
        blk_idx += 4U;
        off += 256U;
    }

    while (off + 64U <= ct_len) {
        memcpy(&tweak[0], tag, 32U);
        memcpy(&tweak[32], &nonce[0], 16U);
        areion_pq_store_le64(&tweak[48], blk_idx);
        areion_pq_store_le64(&tweak[56], UINT64_C(0x54454D3253495601));
        memcpy(ct, &ciphertext[off], 64U);
        areion_tem2_decrypt512(pt, k_enc, tweak, ct);
        memcpy(&plaintext[off], pt, 64U);
        blk_idx++;
        off += 64U;
    }

    if (off < ct_len) {
        size_t rem = ct_len - off;
        size_t i;
        memcpy(&t_tail[0], tag, 32U);
        memcpy(&t_tail[32], &nonce[16], 16U);
        areion_pq_store_le64(&t_tail[48], blk_idx);
        areion_pq_store_le64(&t_tail[56], UINT64_C(0x54454D3253495602));
        areion_soem512(stream, k_enc, t_tail);
        for (i = 0U; i < rem; i++) {
            plaintext[off + i] = (uint8_t)(ciphertext[off + i] ^ stream[i]);
        }
    }

    pq_tem2_siv_compute_tag(expected_tag, key, nonce, ad, ad_len, plaintext, ct_len);
    ok = areion_pq_ct_eq(expected_tag, tag, 32U);
    if (!ok && plaintext != NULL && ct_len > 0U) {
        areion_pq_zeroize(plaintext, ct_len);
    }

    areion_pq_secure_wipe(k_enc, sizeof(k_enc));
    areion_pq_secure_wipe(keys4, sizeof(keys4));
    areion_pq_secure_wipe(tweaks4, sizeof(tweaks4));
    areion_pq_secure_wipe(cts4, sizeof(cts4));
    areion_pq_secure_wipe(pt4, sizeof(pt4));
    areion_pq_secure_wipe(tweak, sizeof(tweak));
    areion_pq_secure_wipe(ct, sizeof(ct));
    areion_pq_secure_wipe(pt, sizeof(pt));
    areion_pq_secure_wipe(t_tail, sizeof(t_tail));
    areion_pq_secure_wipe(stream, sizeof(stream));
    areion_pq_secure_wipe(expected_tag, sizeof(expected_tag));

    return ok;
}

int areion_pq_tem2_siv_decrypt(
    uint8_t *plaintext,
    const uint8_t key[128], const uint8_t nonce[32],
    const uint8_t *ad, size_t ad_len,
    const uint8_t *ciphertext, size_t ct_len,
    const uint8_t tag[32]) {
    int ok = pq_tem2_siv_decrypt_body(plaintext, key, nonce, ad, ad_len, ciphertext, ct_len, tag);
    areion_pq_wipe_software_stack();
    areion_pq_clobber_scratch_gprs();
    return ok;
}

static AREION_PQ_NOINLINE void pq_hpke_derive_keys_body(
    uint8_t dem_key[128], uint8_t base_nonce[32],
    const uint8_t shared_secret[32],
    const uint8_t *info, size_t info_len) {
    uint8_t buf[160];
    pq_kdf_expand_body(buf, sizeof(buf), shared_secret, 32U, info, info_len);
    memcpy(dem_key, &buf[0], 128U);
    memcpy(base_nonce, &buf[128], 32U);
}

void areion_pq_hpke_derive_keys(
    uint8_t dem_key[128], uint8_t base_nonce[32],
    const uint8_t shared_secret[32],
    const uint8_t *info, size_t info_len) {
    pq_hpke_derive_keys_body(dem_key, base_nonce, shared_secret, info, info_len);
    areion_pq_wipe_software_stack();
    areion_pq_clobber_scratch_gprs();
}

static AREION_PQ_NOINLINE void pq_hpke_seal_det_body(
    uint8_t *ciphertext, uint8_t tag[32],
    const uint8_t shared_secret[32],
    const uint8_t *info, size_t info_len,
    uint64_t seq,
    const uint8_t *ad, size_t ad_len,
    const uint8_t *plaintext, size_t pt_len) {
    uint8_t dem_key[128], nonce[32];
    uint64_t w0;

    pq_hpke_derive_keys_body(dem_key, nonce, shared_secret, info, info_len);
    w0 = areion_pq_load_le64(&nonce[0]) ^ seq;
    areion_pq_store_le64(&nonce[0], w0);
    pq_tem2_siv_encrypt_body(ciphertext, tag, dem_key, nonce, ad, ad_len, plaintext, pt_len);
}

void areion_pq_hpke_seal_det(
    uint8_t *ciphertext, uint8_t tag[32],
    const uint8_t shared_secret[32],
    const uint8_t *info, size_t info_len,
    uint64_t seq,
    const uint8_t *ad, size_t ad_len,
    const uint8_t *plaintext, size_t pt_len) {
    pq_hpke_seal_det_body(ciphertext, tag, shared_secret, info, info_len, seq, ad, ad_len, plaintext, pt_len);
    areion_pq_wipe_software_stack();
    areion_pq_clobber_scratch_gprs();
}

static AREION_PQ_NOINLINE int pq_hpke_open_det_body(
    uint8_t *plaintext,
    const uint8_t shared_secret[32],
    const uint8_t *info, size_t info_len,
    uint64_t seq,
    const uint8_t *ad, size_t ad_len,
    const uint8_t *ciphertext, size_t ct_len,
    const uint8_t tag[32]) {
    uint8_t dem_key[128], nonce[32];
    uint64_t w0;
    int ok;

    pq_hpke_derive_keys_body(dem_key, nonce, shared_secret, info, info_len);
    w0 = areion_pq_load_le64(&nonce[0]) ^ seq;
    areion_pq_store_le64(&nonce[0], w0);
    ok = pq_tem2_siv_decrypt_body(plaintext, dem_key, nonce, ad, ad_len, ciphertext, ct_len, tag);
    return ok;
}

int areion_pq_hpke_open_det(
    uint8_t *plaintext,
    const uint8_t shared_secret[32],
    const uint8_t *info, size_t info_len,
    uint64_t seq,
    const uint8_t *ad, size_t ad_len,
    const uint8_t *ciphertext, size_t ct_len,
    const uint8_t tag[32]) {
    int ok = pq_hpke_open_det_body(plaintext, shared_secret, info, info_len, seq, ad, ad_len, ciphertext, ct_len, tag);
    areion_pq_wipe_software_stack();
    areion_pq_clobber_scratch_gprs();
    return ok;
}

/* =========================================================================
 * 6. Track 2: SLH-DSA-Areion (§3.4 & §7)
 * ========================================================================= */

#define PQ_SLH_ADRS_WOTS_HASH  0U
#define PQ_SLH_ADRS_WOTS_PK    1U
#define PQ_SLH_ADRS_TREE       2U
#define PQ_SLH_ADRS_FORS_TREE  3U
#define PQ_SLH_ADRS_FORS_ROOTS 4U
#define PQ_SLH_ADRS_WOTS_PRF   5U
#define PQ_SLH_ADRS_FORS_PRF   6U

static inline void pq_slh_set_layer_address(uint8_t adrs[32], uint32_t layer) {
    areion_pq_store_be32(&adrs[0], layer);
}

static inline void pq_slh_set_tree_address(uint8_t adrs[32], uint64_t tree) {
    memset(&adrs[4], 0, 4U);
    areion_pq_store_be64(&adrs[8], tree);
}

static inline void pq_slh_set_type_and_clear(uint8_t adrs[32], uint32_t typ) {
    areion_pq_store_be32(&adrs[16], typ);
    memset(&adrs[20], 0, 12U);
}

static inline void pq_slh_set_key_pair_address(uint8_t adrs[32], uint32_t kp) {
    areion_pq_store_be32(&adrs[20], kp);
}

static inline uint32_t pq_slh_get_key_pair_address(const uint8_t adrs[32]) {
    return areion_pq_load_be32(&adrs[20]);
}

static inline void pq_slh_set_chain_address(uint8_t adrs[32], uint32_t chain) {
    areion_pq_store_be32(&adrs[24], chain);
}

static inline void pq_slh_set_tree_height(uint8_t adrs[32], uint32_t h) {
    areion_pq_store_be32(&adrs[24], h);
}

static inline void pq_slh_set_hash_address(uint8_t adrs[32], uint32_t hash) {
    areion_pq_store_be32(&adrs[28], hash);
}

static inline void pq_slh_set_tree_index(uint8_t adrs[32], uint32_t idx) {
    areion_pq_store_be32(&adrs[28], idx);
}

static AREION_PQ_NOINLINE void pq_slh_expand_seed256_body(
    uint8_t k_pub[64], uint8_t k_sk[64],
    const uint8_t pk_seed[32], const uint8_t sk_seed[32]) {
    uint8_t p[32], k_pub1[32], k_pub2[32];

    memset(p, 0, sizeof(p));
    if (pk_seed != NULL) {
        memcpy(p, pk_seed, 32U);
    }
    areion_dm256(k_pub1, p);
    memcpy(k_pub2, p, 32U);
    areion_permute256_p2(k_pub2);
    pq_xor32(k_pub2, k_pub2, p);

    if (k_pub != NULL) {
        memcpy(&k_pub[0], k_pub1, 32U);
        memcpy(&k_pub[32], k_pub2, 32U);
    }

    if (k_sk != NULL) {
        if (sk_seed != NULL) {
            uint8_t s[32], ksk1[32], ksk2[32];
            memcpy(s, sk_seed, 32U);
            pq_xor32(ksk1, s, k_pub1);
            areion_permute256(ksk1);
            pq_xor32(ksk1, ksk1, s);

            pq_xor32(ksk2, s, k_pub2);
            areion_permute256_p2(ksk2);
            pq_xor32(ksk2, ksk2, s);

            memcpy(&k_sk[0], ksk1, 32U);
            memcpy(&k_sk[32], ksk2, 32U);
        } else {
            memset(k_sk, 0, 64U);
        }
    }
}

void areion_pq_slh_expand_seed256(
    uint8_t k_pub[64], uint8_t k_sk[64],
    const uint8_t pk_seed[32], const uint8_t sk_seed[32]) {
    pq_slh_expand_seed256_body(k_pub, k_sk, pk_seed, sk_seed);
    areion_pq_wipe_software_stack();
    areion_pq_clobber_scratch_gprs();
}

static AREION_PQ_NOINLINE void pq_slh_expand_seed128_body(
    uint8_t k_pub[64], uint8_t k_sk[64],
    const uint8_t pk_seed[16], const uint8_t sk_seed[16]) {
    uint8_t p32[32], s32[32];
    memset(p32, 0, sizeof(p32));
    memset(s32, 0, sizeof(s32));
    if (pk_seed != NULL) {
        pq_pad32(p32, pk_seed, 16U);
    }
    if (sk_seed != NULL) {
        pq_pad32(s32, sk_seed, 16U);
    }
    pq_slh_expand_seed256_body(k_pub, k_sk, p32, (sk_seed != NULL) ? s32 : NULL);
}

void areion_pq_slh_expand_seed128(
    uint8_t k_pub[64], uint8_t k_sk[64],
    const uint8_t pk_seed[16], const uint8_t sk_seed[16]) {
    pq_slh_expand_seed128_body(k_pub, k_sk, pk_seed, sk_seed);
    areion_pq_wipe_software_stack();
    areion_pq_clobber_scratch_gprs();
}

void areion_pq_slh_compact_adrs(uint8_t out[16], const uint8_t adrs[32]) {
    out[0] = adrs[3];
    memcpy(&out[1], &adrs[8], 8U);
    out[9] = adrs[19];
    memcpy(&out[10], &adrs[22], 2U);
    out[12] = adrs[27];
    memcpy(&out[13], &adrs[29], 3U);
}

static inline void pq_slh_prf128_core(uint8_t out[16], const uint8_t k_sk[64], const uint8_t adrs[32]) {
    uint8_t y[32];
    areion_soem256(y, k_sk, adrs);
    memcpy(out, y, 16U);
}

void areion_pq_slh_prf128(uint8_t out[16], const uint8_t k_sk[64], const uint8_t adrs[32]) {
    uint8_t y[32];
    areion_soem256(y, k_sk, adrs);
    memcpy(out, y, 16U);
    areion_pq_secure_wipe(y, sizeof(y));
}

static inline void pq_slh_prf256_core(uint8_t out[32], const uint8_t k_sk[64], const uint8_t adrs[32]) {
    areion_soem256(out, k_sk, adrs);
}

void areion_pq_slh_prf256(uint8_t out[32], const uint8_t k_sk[64], const uint8_t adrs[32]) {
    pq_slh_prf256_core(out, k_sk, adrs);
}

static inline void pq_slh_prf256x4_core(
    uint8_t out[4][32], const uint8_t k_sk[64], const uint8_t adrs[4][32]) {
    uint8_t keys4[4][64];
    unsigned int lane;
    for (lane = 0U; lane < 4U; lane++) {
        memcpy(keys4[lane], k_sk, 64U);
    }
    areion_soem256x4(out, (const uint8_t (*)[64])keys4, adrs);
}

void areion_pq_slh_prf256x4(
    uint8_t out[4][32], const uint8_t k_sk[64], const uint8_t adrs[4][32]) {
    uint8_t keys4[4][64];
    unsigned int lane;
    for (lane = 0U; lane < 4U; lane++) {
        memcpy(keys4[lane], k_sk, 64U);
    }
    areion_soem256x4(out, (const uint8_t (*)[64])keys4, adrs);
    areion_pq_secure_wipe(keys4, sizeof(keys4));
}

static inline void pq_slh_f128_core(
    uint8_t out[16], const uint8_t pk_seed[16], const uint8_t k_pub[64],
    const uint8_t adrs[32], const uint8_t m1[16]) {
    uint8_t b[64], d[32];
    memcpy(&b[0], pk_seed, 16U);
    memcpy(&b[16], adrs, 32U);
    memcpy(&b[48], m1, 16U);
    pq_xor64(b, b, k_pub);
    areion_dm512(d, b);
    memcpy(out, d, 16U);
}

void areion_pq_slh_f128(
    uint8_t out[16], const uint8_t pk_seed[16], const uint8_t k_pub[64],
    const uint8_t adrs[32], const uint8_t m1[16]) {
    uint8_t b[64], d[32];
    memcpy(&b[0], pk_seed, 16U);
    memcpy(&b[16], adrs, 32U);
    memcpy(&b[48], m1, 16U);
    pq_xor64(b, b, k_pub);
    areion_dm512(d, b);
    memcpy(out, d, 16U);
    areion_pq_secure_wipe(b, sizeof(b));
    areion_pq_secure_wipe(d, sizeof(d));
}

static inline void pq_slh_f256_core(
    uint8_t out[32], const uint8_t k_pub[64], const uint8_t adrs[32], const uint8_t m1[32]) {
    uint8_t b[64];
    pq_xor32(&b[0], adrs, &k_pub[0]);
    pq_xor32(&b[32], m1, &k_pub[32]);
    areion_dm512(out, b);
}

void areion_pq_slh_f256(
    uint8_t out[32], const uint8_t k_pub[64], const uint8_t adrs[32], const uint8_t m1[32]) {
    uint8_t b[64];
    pq_xor32(&b[0], adrs, &k_pub[0]);
    pq_xor32(&b[32], m1, &k_pub[32]);
    areion_dm512(out, b);
    areion_pq_secure_wipe(b, sizeof(b));
}

static inline void pq_slh_f_tem256_core(
    uint8_t out[32], const uint8_t k_pub[64], const uint8_t adrs[32], const uint8_t m1[32]) {
    uint8_t enc[32];
    areion_tem_encrypt256(enc, k_pub, m1, adrs);
    pq_xor32(out, enc, m1);
}

void areion_pq_slh_f_tem256(
    uint8_t out[32], const uint8_t k_pub[64], const uint8_t adrs[32], const uint8_t m1[32]) {
    uint8_t enc[32];
    areion_tem_encrypt256(enc, k_pub, m1, adrs);
    pq_xor32(out, enc, m1);
    areion_pq_secure_wipe(enc, sizeof(enc));
}

static inline void pq_slh_h128_core(
    uint8_t out[16], const uint8_t pk_seed[16], const uint8_t k_pub[64],
    const uint8_t adrs[32], const uint8_t m1[16], const uint8_t m2[16]) {
    uint8_t c[16], b[64], d[32];
    areion_pq_slh_compact_adrs(c, adrs);
    memcpy(&b[0], pk_seed, 16U);
    memcpy(&b[16], c, 16U);
    memcpy(&b[32], m1, 16U);
    memcpy(&b[48], m2, 16U);
    pq_xor64(b, b, k_pub);
    areion_dm512(d, b);
    memcpy(out, d, 16U);
}

void areion_pq_slh_h128(
    uint8_t out[16], const uint8_t pk_seed[16], const uint8_t k_pub[64],
    const uint8_t adrs[32], const uint8_t m1[16], const uint8_t m2[16]) {
    uint8_t c[16], b[64], d[32];
    areion_pq_slh_compact_adrs(c, adrs);
    memcpy(&b[0], pk_seed, 16U);
    memcpy(&b[16], c, 16U);
    memcpy(&b[32], m1, 16U);
    memcpy(&b[48], m2, 16U);
    pq_xor64(b, b, k_pub);
    areion_dm512(d, b);
    memcpy(out, d, 16U);
    areion_pq_secure_wipe(b, sizeof(b));
    areion_pq_secure_wipe(d, sizeof(d));
}

static inline void pq_slh_h256_core(
    uint8_t out[32], const uint8_t k_pub[64], const uint8_t adrs[32],
    const uint8_t m1[32], const uint8_t m2[32]) {
    uint8_t b1[64], b2[64], v1[32];
    pq_xor32(&b1[0], adrs, &k_pub[0]);
    pq_xor32(&b1[32], m1, &k_pub[32]);
    areion_dm512(v1, b1);

    pq_xor32(&b2[0], v1, &k_pub[0]);
    pq_xor32(&b2[32], m2, adrs);
    pq_xor32(&b2[32], &b2[32], &k_pub[32]);
    b2[0] ^= 0x02U;
    areion_dm512(out, b2);
}

void areion_pq_slh_h256(
    uint8_t out[32], const uint8_t k_pub[64], const uint8_t adrs[32],
    const uint8_t m1[32], const uint8_t m2[32]) {
    uint8_t b1[64], b2[64], v1[32];
    pq_xor32(&b1[0], adrs, &k_pub[0]);
    pq_xor32(&b1[32], m1, &k_pub[32]);
    areion_dm512(v1, b1);

    pq_xor32(&b2[0], v1, &k_pub[0]);
    pq_xor32(&b2[32], m2, adrs);
    pq_xor32(&b2[32], &b2[32], &k_pub[32]);
    b2[0] ^= 0x02U;
    areion_dm512(out, b2);

    areion_pq_secure_wipe(b1, sizeof(b1));
    areion_pq_secure_wipe(b2, sizeof(b2));
    areion_pq_secure_wipe(v1, sizeof(v1));
}

void areion_pq_slh_tl128(
    uint8_t out[16], const uint8_t k_pub[64], const uint8_t adrs[32],
    const uint8_t *blocks, size_t num_blocks) {
    uint8_t b[64], m0[32], mi[32], v[32];
    size_t idx;

    memset(m0, 0, sizeof(m0));
    if (num_blocks > 0U && blocks != NULL) {
        memcpy(m0, &blocks[0], 16U);
    }
    pq_xor32(&b[0], adrs, &k_pub[0]);
    pq_xor32(&b[32], m0, &k_pub[32]);
    areion_dm512(v, b);

    for (idx = 1U; idx < num_blocks && blocks != NULL; idx++) {
        uint64_t w_dom;
        memset(mi, 0, sizeof(mi));
        memcpy(mi, &blocks[16U * idx], 16U);
        pq_xor32(&b[0], v, &k_pub[0]);
        pq_xor32(&b[32], mi, adrs);
        pq_xor32(&b[32], &b[32], &k_pub[32]);
        w_dom = areion_pq_load_le64(&b[0]) ^ (uint64_t)(idx + 1U);
        areion_pq_store_le64(&b[0], w_dom);
        areion_dm512(v, b);
    }
    memcpy(out, v, 16U);

    areion_pq_secure_wipe(b, sizeof(b));
    areion_pq_secure_wipe(m0, sizeof(m0));
    areion_pq_secure_wipe(mi, sizeof(mi));
    areion_pq_secure_wipe(v, sizeof(v));
}

void areion_pq_slh_tl256(
    uint8_t out[32], const uint8_t k_pub[64], const uint8_t adrs[32],
    const uint8_t *blocks, size_t num_blocks) {
    uint8_t b[64], m0[32], mi[32], v[32];
    size_t idx;

    memset(m0, 0, sizeof(m0));
    if (num_blocks > 0U && blocks != NULL) {
        memcpy(m0, &blocks[0], 32U);
    }
    pq_xor32(&b[0], adrs, &k_pub[0]);
    pq_xor32(&b[32], m0, &k_pub[32]);
    areion_dm512(v, b);

    for (idx = 1U; idx < num_blocks && blocks != NULL; idx++) {
        uint64_t w_dom;
        memcpy(mi, &blocks[32U * idx], 32U);
        pq_xor32(&b[0], v, &k_pub[0]);
        pq_xor32(&b[32], mi, adrs);
        pq_xor32(&b[32], &b[32], &k_pub[32]);
        w_dom = areion_pq_load_le64(&b[0]) ^ (uint64_t)(idx + 1U);
        areion_pq_store_le64(&b[0], w_dom);
        areion_dm512(v, b);
    }
    memcpy(out, v, 32U);

    areion_pq_secure_wipe(b, sizeof(b));
    areion_pq_secure_wipe(m0, sizeof(m0));
    areion_pq_secure_wipe(mi, sizeof(mi));
    areion_pq_secure_wipe(v, sizeof(v));
}

typedef struct {
    uint32_t n;
    uint32_t h;
    uint32_t d;
    uint32_t hp;
    uint32_t a;
    uint32_t k;
    uint32_t wots_l;
    uint32_t m_bytes;
    int use_tem;
} pq_slh_params_t;

static const pq_slh_params_t pq_slh_params_128f    = { 16U, 66U, 22U, 3U,  6U, 33U, 35U, 34U, 0 };
static const pq_slh_params_t pq_slh_params_128s    = { 16U, 63U,  7U, 9U, 12U, 14U, 35U, 30U, 0 };
static const pq_slh_params_t pq_slh_params_256f    = { 32U, 68U, 17U, 4U,  9U, 35U, 67U, 49U, 0 };
static const pq_slh_params_t pq_slh_params_256s    = { 32U, 64U,  8U, 8U, 14U, 22U, 67U, 47U, 0 };
static const pq_slh_params_t pq_slh_params_tem256f = { 32U, 68U, 17U, 4U,  9U, 35U, 67U, 49U, 1 };

static void pq_slh_prf_msg(
    const pq_slh_params_t *p, const uint8_t *sk_prf, const uint8_t *opt_rand,
    const uint8_t *msg, size_t msg_len, uint8_t *out) {
    uint8_t p_prf[32], o_rand[32], xee[32], v[32], b512[64], bj[32];
    uint8_t k_prf[64], dm_p[32], res[32];
    size_t num_blocks = (msg_len / 32U) + 1U;
    size_t blk;

    if (p->n == 16U) {
        pq_pad32(p_prf, sk_prf, 16U);
        pq_pad32(o_rand, opt_rand, 16U);
    } else {
        memcpy(p_prf, sk_prf, 32U);
        memcpy(o_rand, opt_rand, 32U);
    }
    pq_xor32(xee, p_prf, o_rand);
    areion_dm256(v, xee);

    for (blk = 0U; blk < num_blocks; blk++) {
        size_t off = blk * 32U;
        memset(bj, 0, sizeof(bj));
        if (off + 32U <= msg_len) {
            memcpy(bj, &msg[off], 32U);
        } else {
            size_t rem = msg_len - off;
            if (rem > 0U && msg != NULL) {
                memcpy(bj, &msg[off], rem);
            }
            bj[rem] = 0x80U;
        }
        pq_xor32(&b512[0], v, p_prf);
        pq_xor32(&b512[32], bj, o_rand);
        areion_dm512(v, b512);
    }

    areion_dm256(dm_p, p_prf);
    memcpy(&k_prf[0], p_prf, 32U);
    memcpy(&k_prf[32], dm_p, 32U);
    areion_soem256(res, k_prf, v);
    memcpy(out, res, (size_t)p->n);

    areion_pq_secure_wipe(p_prf, sizeof(p_prf));
    areion_pq_secure_wipe(o_rand, sizeof(o_rand));
    areion_pq_secure_wipe(xee, sizeof(xee));
    areion_pq_secure_wipe(v, sizeof(v));
    areion_pq_secure_wipe(b512, sizeof(b512));
    areion_pq_secure_wipe(bj, sizeof(bj));
    areion_pq_secure_wipe(k_prf, sizeof(k_prf));
    areion_pq_secure_wipe(dm_p, sizeof(dm_p));
    areion_pq_secure_wipe(res, sizeof(res));
}

static void pq_slh_h_msg(
    const pq_slh_params_t *p, const uint8_t *r, const uint8_t *pk_seed, const uint8_t *pk_root,
    const uint8_t k_pub[64], const uint8_t *msg, size_t msg_len, uint8_t *out) {
    uint8_t r32[32], s32[32], root32[32], b512[64], v[32], v_ctr[32], bj[32];
    uint8_t in64[64], k128[128], out64[64];
    size_t num_blocks = (msg_len / 32U) + 1U;
    size_t blk;

    if (p->n == 16U) {
        pq_pad32(r32, r, 16U);
        pq_pad32(s32, pk_seed, 16U);
        pq_pad32(root32, pk_root, 16U);
    } else {
        memcpy(r32, r, 32U);
        memcpy(s32, pk_seed, 32U);
        memcpy(root32, pk_root, 32U);
    }

    memcpy(&b512[0], r32, 32U);
    memcpy(&b512[32], s32, 32U);
    areion_dm512(v, b512);

    memcpy(&b512[0], v, 32U);
    memcpy(&b512[32], root32, 32U);
    areion_dm512(v, b512);

    for (blk = 0U; blk < num_blocks; blk++) {
        size_t off = blk * 32U;
        memset(bj, 0, sizeof(bj));
        if (off + 32U <= msg_len) {
            memcpy(bj, &msg[off], 32U);
        } else {
            size_t rem = msg_len - off;
            if (rem > 0U && msg != NULL) {
                memcpy(bj, &msg[off], rem);
            }
            bj[rem] = 0x80U;
        }
        pq_xor32(&b512[0], v, &k_pub[0]);
        pq_xor32(&b512[32], bj, &k_pub[32]);
        areion_dm512(v, b512);
    }

    memcpy(v_ctr, v, 32U);
    v_ctr[0] ^= 0x01U;
    memcpy(&in64[0], v, 32U);
    memcpy(&in64[32], v_ctr, 32U);
    memcpy(&k128[0], k_pub, 64U);
    memcpy(&k128[64], k_pub, 64U);
    areion_soem512(out64, k128, in64);
    memcpy(out, out64, (size_t)p->m_bytes);

    areion_pq_secure_wipe(b512, sizeof(b512));
    areion_pq_secure_wipe(v, sizeof(v));
    areion_pq_secure_wipe(v_ctr, sizeof(v_ctr));
    areion_pq_secure_wipe(bj, sizeof(bj));
    areion_pq_secure_wipe(in64, sizeof(in64));
    areion_pq_secure_wipe(out64, sizeof(out64));
}

static void pq_slh_base2b(const uint8_t *in, uint32_t b, uint32_t *out, uint32_t out_len) {
    size_t in_idx = 0U;
    uint32_t bits_acc = 0U;
    uint32_t total = 0U;
    uint32_t mask = (1U << b) - 1U;
    uint32_t i;

    for (i = 0U; i < out_len; i++) {
        while (bits_acc < b) {
            total = (total << 8U) | (uint32_t)in[in_idx];
            in_idx++;
            bits_acc += 8U;
        }
        bits_acc -= b;
        out[i] = (total >> bits_acc) & mask;
    }
}

static void pq_slh_wots_msg_nibbles(const pq_slh_params_t *p, const uint8_t *m, uint32_t *out) {
    uint32_t csum = 0U;
    uint32_t i;
    for (i = 0U; i < p->n; i++) {
        uint32_t hi = (uint32_t)(m[i] >> 4U);
        uint32_t lo = (uint32_t)(m[i] & 0x0FU);
        out[2U * (size_t)i] = hi;
        out[2U * (size_t)i + 1U] = lo;
        csum += (15U - hi) + (15U - lo);
    }
    out[2U * (size_t)p->n + 0U] = (csum >> 8U) & 0x0FU;
    out[2U * (size_t)p->n + 1U] = (csum >> 4U) & 0x0FU;
    out[2U * (size_t)p->n + 2U] = csum & 0x0FU;
}

static void pq_slh_wots_chain_single(
    const pq_slh_params_t *p, uint8_t out[32], const uint8_t x[32],
    uint32_t start, uint32_t steps,
    const uint8_t pk_seed[16], const uint8_t k_pub[64], const uint8_t adrs[32]) {
    uint8_t cur[32], adrs_local[32];
    uint32_t s;

    memcpy(cur, x, 32U);
    memcpy(adrs_local, adrs, 32U);
    for (s = start; s < start + steps; s++) {
        pq_slh_set_hash_address(adrs_local, s);
        if (p->n == 16U) {
            pq_slh_f128_core(cur, pk_seed, k_pub, adrs_local, cur);
        } else if (p->use_tem) {
            pq_slh_f_tem256_core(cur, k_pub, adrs_local, cur);
        } else {
            pq_slh_f256_core(cur, k_pub, adrs_local, cur);
        }
    }
    memcpy(out, cur, 32U);
}

static void pq_slh_wots_pk_gen(
    const pq_slh_params_t *p, uint8_t out[32],
    const uint8_t pk_seed[16], const uint8_t k_pub[64], const uint8_t k_sk[64],
    const uint8_t adrs[32]) {
    uint8_t tmp256[67 * 32];
    uint8_t tmp128[35 * 16];
    uint8_t sk_adrs[32], chain_adrs[32], wotspk_adrs[32];
    uint32_t i;

    memset(tmp256, 0, sizeof(tmp256));
    memset(tmp128, 0, sizeof(tmp128));
    memcpy(sk_adrs, adrs, 32U);
    pq_slh_set_type_and_clear(sk_adrs, PQ_SLH_ADRS_WOTS_PRF);
    pq_slh_set_key_pair_address(sk_adrs, pq_slh_get_key_pair_address(adrs));
    memcpy(chain_adrs, adrs, 32U);

    if (p->n == 32U && !p->use_tem) {
        uint8_t adrs4[4][32], ch_adrs4[4][32], sk4[4][32], out4[4][32];
        uint8_t sk[32];
        uint32_t lane;
        i = 0U;
        for (; i + 4U <= p->wots_l; i += 4U) {
            for (lane = 0U; lane < 4U; lane++) {
                memcpy(adrs4[lane], sk_adrs, 32U);
                pq_slh_set_chain_address(adrs4[lane], i + lane);
                memcpy(ch_adrs4[lane], chain_adrs, 32U);
                pq_slh_set_chain_address(ch_adrs4[lane], i + lane);
            }
            pq_slh_prf256x4_core(
                sk4, k_sk, (const uint8_t (*)[32])adrs4);
            pq_wots_chain256x4_purec_body(
                out4, (const uint8_t (*)[32])sk4, (const uint8_t (*)[32])ch_adrs4,
                &k_pub[0], &k_pub[32], 0U, 15U);
            for (lane = 0U; lane < 4U; lane++) {
                memcpy(&tmp256[32U * (size_t)(i + lane)], out4[lane], 32U);
            }
        }
        for (; i < p->wots_l; i++) {
            pq_slh_set_chain_address(sk_adrs, i);
            pq_slh_prf256_core(sk, k_sk, sk_adrs);
            pq_slh_set_chain_address(chain_adrs, i);
            pq_slh_wots_chain_single(p, &tmp256[32U * (size_t)i], sk, 0U, 15U, pk_seed, k_pub, chain_adrs);
        }
        areion_pq_secure_wipe(sk, sizeof(sk));
        areion_pq_secure_wipe(sk4, sizeof(sk4));
    } else {
        uint8_t sk[32], end_node[32];
        memset(sk, 0, sizeof(sk));
        for (i = 0U; i < p->wots_l; i++) {
            pq_slh_set_chain_address(sk_adrs, i);
            if (p->n == 16U) {
                pq_slh_prf128_core(sk, k_sk, sk_adrs);
            } else {
                pq_slh_prf256_core(sk, k_sk, sk_adrs);
            }
            pq_slh_set_chain_address(chain_adrs, i);
            pq_slh_wots_chain_single(p, end_node, sk, 0U, 15U, pk_seed, k_pub, chain_adrs);
            if (p->n == 16U) {
                memcpy(&tmp128[16U * (size_t)i], end_node, 16U);
            } else {
                memcpy(&tmp256[32U * (size_t)i], end_node, 32U);
            }
        }
        areion_pq_secure_wipe(sk, sizeof(sk));
    }

    memcpy(wotspk_adrs, adrs, 32U);
    pq_slh_set_type_and_clear(wotspk_adrs, PQ_SLH_ADRS_WOTS_PK);
    pq_slh_set_key_pair_address(wotspk_adrs, pq_slh_get_key_pair_address(adrs));
    memset(out, 0, 32U);
    if (p->n == 16U) {
        areion_pq_slh_tl128(out, k_pub, wotspk_adrs, tmp128, (size_t)p->wots_l);
    } else {
        areion_pq_slh_tl256(out, k_pub, wotspk_adrs, tmp256, (size_t)p->wots_l);
    }

    areion_pq_secure_wipe(tmp256, sizeof(tmp256));
    areion_pq_secure_wipe(tmp128, sizeof(tmp128));
}

static void pq_slh_wots_sign(
    const pq_slh_params_t *p, const uint8_t *m,
    const uint8_t pk_seed[16], const uint8_t k_pub[64], const uint8_t k_sk[64],
    const uint8_t adrs[32], uint8_t *sig_out) {
    uint32_t msg_nibbles[67];
    uint8_t sk_adrs[32], chain_adrs[32], sk[32], node[32];
    uint32_t i;

    pq_slh_wots_msg_nibbles(p, m, msg_nibbles);
    memcpy(sk_adrs, adrs, 32U);
    pq_slh_set_type_and_clear(sk_adrs, PQ_SLH_ADRS_WOTS_PRF);
    pq_slh_set_key_pair_address(sk_adrs, pq_slh_get_key_pair_address(adrs));
    memcpy(chain_adrs, adrs, 32U);
    memset(sk, 0, sizeof(sk));

    for (i = 0U; i < p->wots_l; i++) {
        pq_slh_set_chain_address(sk_adrs, i);
        if (p->n == 16U) {
            pq_slh_prf128_core(sk, k_sk, sk_adrs);
        } else {
            pq_slh_prf256_core(sk, k_sk, sk_adrs);
        }
        pq_slh_set_chain_address(chain_adrs, i);
        pq_slh_wots_chain_single(p, node, sk, 0U, msg_nibbles[i], pk_seed, k_pub, chain_adrs);
        memcpy(&sig_out[(size_t)i * (size_t)p->n], node, (size_t)p->n);
    }

    areion_pq_secure_wipe(sk, sizeof(sk));
    areion_pq_secure_wipe(node, sizeof(node));
    areion_pq_secure_wipe(msg_nibbles, sizeof(msg_nibbles));
}

static void pq_slh_wots_pk_from_sig(
    const pq_slh_params_t *p, uint8_t out[32], const uint8_t *sig, const uint8_t *m,
    const uint8_t pk_seed[16], const uint8_t k_pub[64], const uint8_t adrs[32]) {
    uint32_t msg_nibbles[67];
    uint8_t tmp256[67 * 32];
    uint8_t tmp128[35 * 16];
    uint8_t chain_adrs[32], wotspk_adrs[32], sig_node[32], end_node[32];
    uint32_t i;

    pq_slh_wots_msg_nibbles(p, m, msg_nibbles);
    memcpy(chain_adrs, adrs, 32U);

    for (i = 0U; i < p->wots_l; i++) {
        uint32_t step = msg_nibbles[i];
        memset(sig_node, 0, sizeof(sig_node));
        memcpy(sig_node, &sig[(size_t)i * (size_t)p->n], (size_t)p->n);
        pq_slh_set_chain_address(chain_adrs, i);
        pq_slh_wots_chain_single(p, end_node, sig_node, step, 15U - step, pk_seed, k_pub, chain_adrs);
        if (p->n == 16U) {
            memcpy(&tmp128[16U * (size_t)i], end_node, 16U);
        } else {
            memcpy(&tmp256[32U * (size_t)i], end_node, 32U);
        }
    }

    memcpy(wotspk_adrs, adrs, 32U);
    pq_slh_set_type_and_clear(wotspk_adrs, PQ_SLH_ADRS_WOTS_PK);
    pq_slh_set_key_pair_address(wotspk_adrs, pq_slh_get_key_pair_address(adrs));
    memset(out, 0, 32U);
    if (p->n == 16U) {
        areion_pq_slh_tl128(out, k_pub, wotspk_adrs, tmp128, (size_t)p->wots_l);
    } else {
        areion_pq_slh_tl256(out, k_pub, wotspk_adrs, tmp256, (size_t)p->wots_l);
    }
}

static void pq_slh_tree_hash(
    const pq_slh_params_t *p, uint8_t out[32],
    const uint8_t left[32], const uint8_t right[32],
    const uint8_t pk_seed[16], const uint8_t k_pub[64], const uint8_t adrs[32]) {
    if (p->n == 16U) {
        pq_slh_h128_core(out, pk_seed, k_pub, adrs, left, right);
        memset(&out[16], 0, 16U);
    } else {
        pq_slh_h256_core(out, k_pub, adrs, left, right);
    }
}

static void pq_slh_xmss_node(
    const pq_slh_params_t *p, uint8_t out[32],
    uint32_t idx, uint32_t z,
    const uint8_t pk_seed[16], const uint8_t k_pub[64], const uint8_t k_sk[64],
    const uint8_t adrs[32]) {
    uint8_t stack_node[12][32];
    uint32_t stack_h[12];
    uint8_t leaf_adrs[32], tree_adrs[32], node[32];
    uint32_t num_leaves = 1U << z;
    uint32_t base_leaf = idx * num_leaves;
    uint32_t top = 0U;
    uint32_t l;

    memcpy(tree_adrs, adrs, 32U);
    pq_slh_set_type_and_clear(tree_adrs, PQ_SLH_ADRS_TREE);

    for (l = 0U; l < num_leaves; l++) {
        uint32_t h = 0U;
        uint32_t j = l;
        memcpy(leaf_adrs, adrs, 32U);
        pq_slh_set_type_and_clear(leaf_adrs, PQ_SLH_ADRS_WOTS_HASH);
        pq_slh_set_key_pair_address(leaf_adrs, base_leaf + l);
        pq_slh_wots_pk_gen(p, node, pk_seed, k_pub, k_sk, leaf_adrs);

        while (top > 0U && stack_h[top - 1U] == h) {
            top--;
            h++;
            j >>= 1U;
            pq_slh_set_tree_height(tree_adrs, h);
            pq_slh_set_tree_index(tree_adrs, (idx << (z - h)) + j);
            pq_slh_tree_hash(p, node, stack_node[top], node, pk_seed, k_pub, tree_adrs);
        }
        memcpy(stack_node[top], node, 32U);
        stack_h[top] = h;
        top++;
    }
    memcpy(out, stack_node[0], 32U);
    areion_pq_secure_wipe(stack_node, sizeof(stack_node));
    areion_pq_secure_wipe(node, sizeof(node));
}

static void pq_slh_xmss_sign(
    const pq_slh_params_t *p, uint8_t root_out[32],
    const uint8_t m[32], uint32_t idx,
    const uint8_t pk_seed[16], const uint8_t k_pub[64], const uint8_t k_sk[64],
    const uint8_t adrs[32], uint8_t *sig_out) {
    uint8_t stack_node[12][32];
    uint32_t stack_h[12];
    uint8_t leaf_adrs[32], tree_adrs[32], wots_adrs[32], node[32];
    uint32_t num_leaves = 1U << p->hp;
    size_t wots_sig_bytes = (size_t)p->wots_l * (size_t)p->n;
    uint32_t top = 0U;
    uint32_t l;

    memcpy(wots_adrs, adrs, 32U);
    pq_slh_set_type_and_clear(wots_adrs, PQ_SLH_ADRS_WOTS_HASH);
    pq_slh_set_key_pair_address(wots_adrs, idx);
    pq_slh_wots_sign(p, m, pk_seed, k_pub, k_sk, wots_adrs, sig_out);

    memcpy(tree_adrs, adrs, 32U);
    pq_slh_set_type_and_clear(tree_adrs, PQ_SLH_ADRS_TREE);

    for (l = 0U; l < num_leaves; l++) {
        uint32_t h = 0U;
        uint32_t j = l;
        memcpy(leaf_adrs, adrs, 32U);
        pq_slh_set_type_and_clear(leaf_adrs, PQ_SLH_ADRS_WOTS_HASH);
        pq_slh_set_key_pair_address(leaf_adrs, l);
        pq_slh_wots_pk_gen(p, node, pk_seed, k_pub, k_sk, leaf_adrs);

        if (j == (idx ^ 1U)) {
            memcpy(&sig_out[wots_sig_bytes], node, (size_t)p->n);
        }
        while (top > 0U && stack_h[top - 1U] == h) {
            top--;
            h++;
            j >>= 1U;
            pq_slh_set_tree_height(tree_adrs, h);
            pq_slh_set_tree_index(tree_adrs, j);
            pq_slh_tree_hash(p, node, stack_node[top], node, pk_seed, k_pub, tree_adrs);
            if (h < p->hp && j == ((idx >> h) ^ 1U)) {
                memcpy(&sig_out[wots_sig_bytes + (size_t)h * (size_t)p->n], node, (size_t)p->n);
            }
        }
        memcpy(stack_node[top], node, 32U);
        stack_h[top] = h;
        top++;
    }
    memcpy(root_out, stack_node[0], 32U);
    areion_pq_secure_wipe(stack_node, sizeof(stack_node));
    areion_pq_secure_wipe(node, sizeof(node));
}

static void pq_slh_xmss_pk_from_sig(
    const pq_slh_params_t *p, uint8_t out[32],
    uint32_t idx, const uint8_t *sig, const uint8_t m[32],
    const uint8_t pk_seed[16], const uint8_t k_pub[64], const uint8_t adrs[32]) {
    uint8_t wots_adrs[32], tree_adrs[32], node[32], auth_k[32];
    size_t wots_sig_bytes = (size_t)p->wots_l * (size_t)p->n;
    uint32_t k;

    memcpy(wots_adrs, adrs, 32U);
    pq_slh_set_type_and_clear(wots_adrs, PQ_SLH_ADRS_WOTS_HASH);
    pq_slh_set_key_pair_address(wots_adrs, idx);
    pq_slh_wots_pk_from_sig(p, node, sig, m, pk_seed, k_pub, wots_adrs);

    memcpy(tree_adrs, adrs, 32U);
    pq_slh_set_type_and_clear(tree_adrs, PQ_SLH_ADRS_TREE);

    for (k = 0U; k < p->hp; k++) {
        memset(auth_k, 0, sizeof(auth_k));
        memcpy(auth_k, &sig[wots_sig_bytes + (size_t)k * (size_t)p->n], (size_t)p->n);
        pq_slh_set_tree_height(tree_adrs, k + 1U);
        pq_slh_set_tree_index(tree_adrs, idx >> (k + 1U));
        if (((idx >> k) & 1U) == 0U) {
            pq_slh_tree_hash(p, node, node, auth_k, pk_seed, k_pub, tree_adrs);
        } else {
            pq_slh_tree_hash(p, node, auth_k, node, pk_seed, k_pub, tree_adrs);
        }
    }
    memcpy(out, node, 32U);
}

static void pq_slh_fors_sign(
    const pq_slh_params_t *p, uint8_t root_out[32],
    const uint8_t *md, const uint8_t pk_seed[16],
    const uint8_t k_pub[64], const uint8_t k_sk[64],
    const uint8_t adrs[32], uint8_t *sig_out) {
    uint32_t indices[35];
    uint8_t roots256[35 * 32];
    uint8_t roots128[35 * 16];
    uint8_t stack_node[16][32];
    uint32_t stack_h[16];
    uint8_t sk_adrs[32], tree_adrs[32], forspk_adrs[32], sk[32], node[32];
    uint32_t num_leaves = 1U << p->a;
    uint32_t i, l;

    pq_slh_base2b(md, p->a, indices, p->k);

    for (i = 0U; i < p->k; i++) {
        uint32_t tree_offset = i << p->a;
        uint32_t idx = indices[i];
        size_t sig_tree_off = (size_t)i * (size_t)(p->a + 1U) * (size_t)p->n;
        size_t auth_off = sig_tree_off + (size_t)p->n;
        uint32_t top = 0U;

        memcpy(sk_adrs, adrs, 32U);
        pq_slh_set_type_and_clear(sk_adrs, PQ_SLH_ADRS_FORS_PRF);
        pq_slh_set_key_pair_address(sk_adrs, pq_slh_get_key_pair_address(adrs));
        pq_slh_set_tree_height(sk_adrs, 0U);

        memcpy(tree_adrs, adrs, 32U);
        pq_slh_set_type_and_clear(tree_adrs, PQ_SLH_ADRS_FORS_TREE);
        pq_slh_set_key_pair_address(tree_adrs, pq_slh_get_key_pair_address(adrs));

        memset(sk, 0, sizeof(sk));
        for (l = 0U; l < num_leaves; l++) {
            uint32_t h = 0U;
            uint32_t j = l;
            memset(node, 0, sizeof(node));
            pq_slh_set_tree_index(sk_adrs, tree_offset + l);
            if (p->n == 16U) {
                pq_slh_prf128_core(sk, k_sk, sk_adrs);
                if (l == idx) {
                    memcpy(&sig_out[sig_tree_off], sk, 16U);
                }
            } else {
                pq_slh_prf256_core(sk, k_sk, sk_adrs);
                if (l == idx) {
                    memcpy(&sig_out[sig_tree_off], sk, 32U);
                }
            }
            pq_slh_set_tree_height(tree_adrs, 0U);
            pq_slh_set_tree_index(tree_adrs, tree_offset + l);
            if (p->n == 16U) {
                pq_slh_f128_core(node, pk_seed, k_pub, tree_adrs, sk);
            } else if (p->use_tem) {
                pq_slh_f_tem256_core(node, k_pub, tree_adrs, sk);
            } else {
                pq_slh_f256_core(node, k_pub, tree_adrs, sk);
            }

            if (j == (idx ^ 1U)) {
                memcpy(&sig_out[auth_off], node, (size_t)p->n);
            }
            while (top > 0U && stack_h[top - 1U] == h) {
                top--;
                h++;
                j >>= 1U;
                pq_slh_set_tree_height(tree_adrs, h);
                pq_slh_set_tree_index(tree_adrs, (i << (p->a - h)) + j);
                pq_slh_tree_hash(p, node, stack_node[top], node, pk_seed, k_pub, tree_adrs);
                if (h < p->a && j == ((idx >> h) ^ 1U)) {
                    memcpy(&sig_out[auth_off + (size_t)h * (size_t)p->n], node, (size_t)p->n);
                }
            }
            memcpy(stack_node[top], node, 32U);
            stack_h[top] = h;
            top++;
        }
        if (p->n == 16U) {
            memcpy(&roots128[16U * (size_t)i], stack_node[0], 16U);
        } else {
            memcpy(&roots256[32U * (size_t)i], stack_node[0], 32U);
        }
    }

    memcpy(forspk_adrs, adrs, 32U);
    pq_slh_set_type_and_clear(forspk_adrs, PQ_SLH_ADRS_FORS_ROOTS);
    pq_slh_set_key_pair_address(forspk_adrs, pq_slh_get_key_pair_address(adrs));
    memset(root_out, 0, 32U);
    if (p->n == 16U) {
        areion_pq_slh_tl128(root_out, k_pub, forspk_adrs, roots128, (size_t)p->k);
    } else {
        areion_pq_slh_tl256(root_out, k_pub, forspk_adrs, roots256, (size_t)p->k);
    }

    areion_pq_secure_wipe(stack_node, sizeof(stack_node));
    areion_pq_secure_wipe(sk, sizeof(sk));
    areion_pq_secure_wipe(node, sizeof(node));
    areion_pq_secure_wipe(roots256, sizeof(roots256));
    areion_pq_secure_wipe(roots128, sizeof(roots128));
}

static void pq_slh_fors_pk_from_sig(
    const pq_slh_params_t *p, uint8_t out[32],
    const uint8_t *sig, const uint8_t *md,
    const uint8_t pk_seed[16], const uint8_t k_pub[64], const uint8_t adrs[32]) {
    uint32_t indices[35];
    uint8_t roots256[35 * 32];
    uint8_t roots128[35 * 16];
    uint8_t tree_adrs[32], forspk_adrs[32], sk[32], node[32], auth_h[32];
    uint32_t i, h;

    pq_slh_base2b(md, p->a, indices, p->k);
    memcpy(tree_adrs, adrs, 32U);
    pq_slh_set_type_and_clear(tree_adrs, PQ_SLH_ADRS_FORS_TREE);
    pq_slh_set_key_pair_address(tree_adrs, pq_slh_get_key_pair_address(adrs));

    for (i = 0U; i < p->k; i++) {
        uint32_t tree_offset = i << p->a;
        uint32_t idx = indices[i];
        size_t sig_tree_off = (size_t)i * (size_t)(p->a + 1U) * (size_t)p->n;
        size_t auth_off = sig_tree_off + (size_t)p->n;

        memset(sk, 0, sizeof(sk));
        memset(node, 0, sizeof(node));
        memcpy(sk, &sig[sig_tree_off], (size_t)p->n);
        pq_slh_set_tree_height(tree_adrs, 0U);
        pq_slh_set_tree_index(tree_adrs, tree_offset + idx);
        if (p->n == 16U) {
            pq_slh_f128_core(node, pk_seed, k_pub, tree_adrs, sk);
        } else if (p->use_tem) {
            pq_slh_f_tem256_core(node, k_pub, tree_adrs, sk);
        } else {
            pq_slh_f256_core(node, k_pub, tree_adrs, sk);
        }

        for (h = 0U; h < p->a; h++) {
            memset(auth_h, 0, sizeof(auth_h));
            memcpy(auth_h, &sig[auth_off + (size_t)h * (size_t)p->n], (size_t)p->n);
            pq_slh_set_tree_height(tree_adrs, h + 1U);
            pq_slh_set_tree_index(tree_adrs, (tree_offset + idx) >> (h + 1U));
            if (((idx >> h) & 1U) == 0U) {
                pq_slh_tree_hash(p, node, node, auth_h, pk_seed, k_pub, tree_adrs);
            } else {
                pq_slh_tree_hash(p, node, auth_h, node, pk_seed, k_pub, tree_adrs);
            }
        }
        if (p->n == 16U) {
            memcpy(&roots128[16U * (size_t)i], node, 16U);
        } else {
            memcpy(&roots256[32U * (size_t)i], node, 32U);
        }
    }

    memcpy(forspk_adrs, adrs, 32U);
    pq_slh_set_type_and_clear(forspk_adrs, PQ_SLH_ADRS_FORS_ROOTS);
    pq_slh_set_key_pair_address(forspk_adrs, pq_slh_get_key_pair_address(adrs));
    memset(out, 0, 32U);
    if (p->n == 16U) {
        areion_pq_slh_tl128(out, k_pub, forspk_adrs, roots128, (size_t)p->k);
    } else {
        areion_pq_slh_tl256(out, k_pub, forspk_adrs, roots256, (size_t)p->k);
    }
}

static void pq_slh_split_digest(
    const pq_slh_params_t *p, const uint8_t *digest,
    const uint8_t **md_out, uint64_t *idx_tree_out, uint32_t *idx_leaf_out) {
    uint32_t md_len = (p->k * p->a + 7U) / 8U;
    uint32_t tree_bytes = (p->h - p->hp + 7U) / 8U;
    uint32_t leaf_bytes = (p->hp + 7U) / 8U;
    uint32_t tree_bits = p->h - p->hp;
    uint64_t idx_tree = 0U;
    uint32_t idx_leaf = 0U;
    uint32_t i;

    *md_out = digest;
    for (i = 0U; i < tree_bytes; i++) {
        idx_tree = (idx_tree << 8U) | (uint64_t)digest[md_len + i];
    }
    if (tree_bits < 64U) {
        idx_tree &= (UINT64_C(1) << tree_bits) - 1U;
    }
    for (i = 0U; i < leaf_bytes; i++) {
        idx_leaf = (idx_leaf << 8U) | (uint32_t)digest[md_len + tree_bytes + i];
    }
    idx_leaf &= (1U << p->hp) - 1U;
    *idx_tree_out = idx_tree;
    *idx_leaf_out = idx_leaf;
}

static AREION_PQ_NOINLINE void pq_slh_keygen_core_body(
    const pq_slh_params_t *p, const uint8_t *seed, uint8_t *pk, uint8_t *sk) {
    const uint8_t *sk_seed = &seed[0];
    const uint8_t *sk_prf = &seed[p->n];
    const uint8_t *pk_seed = &seed[2U * (size_t)p->n];
    uint8_t pk_seed16[16];
    uint8_t k_pub[64], k_sk[64], adrs[32], root[32];

    memset(pk_seed16, 0, sizeof(pk_seed16));
    if (p->n == 16U) {
        memcpy(pk_seed16, pk_seed, 16U);
        pq_slh_expand_seed128_body(k_pub, k_sk, pk_seed, sk_seed);
    } else {
        pq_slh_expand_seed256_body(k_pub, k_sk, pk_seed, sk_seed);
    }

    memset(adrs, 0, sizeof(adrs));
    pq_slh_set_layer_address(adrs, p->d - 1U);
    pq_slh_xmss_node(p, root, 0U, p->hp, pk_seed16, k_pub, k_sk, adrs);

    memcpy(&pk[0], pk_seed, (size_t)p->n);
    memcpy(&pk[p->n], root, (size_t)p->n);

    memcpy(&sk[0], sk_seed, (size_t)p->n);
    memcpy(&sk[p->n], sk_prf, (size_t)p->n);
    memcpy(&sk[2U * (size_t)p->n], pk_seed, (size_t)p->n);
    memcpy(&sk[3U * (size_t)p->n], root, (size_t)p->n);

    areion_pq_secure_wipe(pk_seed16, sizeof(pk_seed16));
    areion_pq_secure_wipe(k_pub, sizeof(k_pub));
    areion_pq_secure_wipe(k_sk, sizeof(k_sk));
    areion_pq_secure_wipe(adrs, sizeof(adrs));
    areion_pq_secure_wipe(root, sizeof(root));
}

static void pq_slh_keygen_core(
    const pq_slh_params_t *p, const uint8_t *seed, uint8_t *pk, uint8_t *sk) {
    pq_slh_keygen_core_body(p, seed, pk, sk);
    areion_pq_wipe_software_stack();
    areion_pq_clobber_scratch_gprs();
}

static AREION_PQ_NOINLINE void pq_slh_sign_core_body(
    const pq_slh_params_t *p, uint8_t *sig_out, const uint8_t *sk,
    const uint8_t *msg, size_t msg_len, const uint8_t *opt_rand) {
    const uint8_t *sk_seed = &sk[0];
    const uint8_t *sk_prf = &sk[p->n];
    const uint8_t *pk_seed = &sk[2U * (size_t)p->n];
    const uint8_t *pk_root = &sk[3U * (size_t)p->n];
    uint8_t pk_seed16[16], opt_local[32];
    uint8_t k_pub[64], k_sk[64], digest[64], adrs[32], root[32];
    const uint8_t *md;
    uint64_t idx_tree;
    uint32_t idx_leaf, layer;
    size_t fors_bytes, xmss_bytes, ht_off;

    memset(pk_seed16, 0, sizeof(pk_seed16));
    if (p->n == 16U) {
        memcpy(pk_seed16, pk_seed, 16U);
        pq_slh_expand_seed128_body(k_pub, k_sk, pk_seed, sk_seed);
    } else {
        pq_slh_expand_seed256_body(k_pub, k_sk, pk_seed, sk_seed);
    }

    memset(opt_local, 0, sizeof(opt_local));
    if (opt_rand != NULL) {
        memcpy(opt_local, opt_rand, (size_t)p->n);
    } else {
        memcpy(opt_local, pk_seed, (size_t)p->n);
    }

    pq_slh_prf_msg(p, sk_prf, opt_local, msg, msg_len, &sig_out[0]);
    pq_slh_h_msg(p, &sig_out[0], pk_seed, pk_root, k_pub, msg, msg_len, digest);
    pq_slh_split_digest(p, digest, &md, &idx_tree, &idx_leaf);

    memset(adrs, 0, sizeof(adrs));
    pq_slh_set_tree_address(adrs, idx_tree);
    pq_slh_set_type_and_clear(adrs, PQ_SLH_ADRS_FORS_TREE);
    pq_slh_set_key_pair_address(adrs, idx_leaf);

    fors_bytes = (size_t)p->k * (size_t)(p->a + 1U) * (size_t)p->n;
    pq_slh_fors_sign(p, root, md, pk_seed16, k_pub, k_sk, adrs, &sig_out[p->n]);

    xmss_bytes = (size_t)(p->wots_l + p->hp) * (size_t)p->n;
    ht_off = (size_t)p->n + fors_bytes;
    for (layer = 0U; layer < p->d; layer++) {
        pq_slh_set_layer_address(adrs, layer);
        pq_slh_set_tree_address(adrs, idx_tree);
        pq_slh_xmss_sign(
            p, root, root, idx_leaf, pk_seed16, k_pub, k_sk, adrs,
            &sig_out[ht_off + (size_t)layer * xmss_bytes]);
        idx_leaf = (uint32_t)(idx_tree & ((UINT64_C(1) << p->hp) - 1U));
        idx_tree >>= p->hp;
    }

    areion_pq_secure_wipe(pk_seed16, sizeof(pk_seed16));
    areion_pq_secure_wipe(k_pub, sizeof(k_pub));
    areion_pq_secure_wipe(k_sk, sizeof(k_sk));
    areion_pq_secure_wipe(digest, sizeof(digest));
    areion_pq_secure_wipe(adrs, sizeof(adrs));
    areion_pq_secure_wipe(root, sizeof(root));
    areion_pq_secure_wipe(opt_local, sizeof(opt_local));
}

static void pq_slh_sign_core(
    const pq_slh_params_t *p, uint8_t *sig_out, const uint8_t *sk,
    const uint8_t *msg, size_t msg_len, const uint8_t *opt_rand) {
    pq_slh_sign_core_body(p, sig_out, sk, msg, msg_len, opt_rand);
    areion_pq_wipe_software_stack();
    areion_pq_clobber_scratch_gprs();
}

static int pq_slh_verify_core(
    const pq_slh_params_t *p, const uint8_t *pk,
    const uint8_t *msg, size_t msg_len, const uint8_t *sig) {
    const uint8_t *pk_seed = &pk[0];
    const uint8_t *pk_root = &pk[p->n];
    uint8_t pk_seed16[16];
    uint8_t k_pub[64], digest[64], adrs[32], node[32];
    const uint8_t *md;
    uint64_t idx_tree;
    uint32_t idx_leaf, layer;
    size_t fors_bytes, xmss_bytes, ht_off;

    memset(pk_seed16, 0, sizeof(pk_seed16));
    if (p->n == 16U) {
        memcpy(pk_seed16, pk_seed, 16U);
        pq_slh_expand_seed128_body(k_pub, NULL, pk_seed, NULL);
    } else {
        pq_slh_expand_seed256_body(k_pub, NULL, pk_seed, NULL);
    }

    pq_slh_h_msg(p, &sig[0], pk_seed, pk_root, k_pub, msg, msg_len, digest);
    pq_slh_split_digest(p, digest, &md, &idx_tree, &idx_leaf);

    memset(adrs, 0, sizeof(adrs));
    pq_slh_set_tree_address(adrs, idx_tree);
    pq_slh_set_type_and_clear(adrs, PQ_SLH_ADRS_FORS_TREE);
    pq_slh_set_key_pair_address(adrs, idx_leaf);

    fors_bytes = (size_t)p->k * (size_t)(p->a + 1U) * (size_t)p->n;
    pq_slh_fors_pk_from_sig(p, node, &sig[p->n], md, pk_seed16, k_pub, adrs);

    xmss_bytes = (size_t)(p->wots_l + p->hp) * (size_t)p->n;
    ht_off = (size_t)p->n + fors_bytes;
    for (layer = 0U; layer < p->d; layer++) {
        pq_slh_set_layer_address(adrs, layer);
        pq_slh_set_tree_address(adrs, idx_tree);
        pq_slh_xmss_pk_from_sig(
            p, node, idx_leaf, &sig[ht_off + (size_t)layer * xmss_bytes],
            node, pk_seed16, k_pub, adrs);
        idx_leaf = (uint32_t)(idx_tree & ((UINT64_C(1) << p->hp) - 1U));
        idx_tree >>= p->hp;
    }

    return areion_pq_ct_eq(node, pk_root, (size_t)p->n);
}

void areion_pq_slhdsa_keygen128f(
    uint8_t pk[AREION_PQ_SLHDSA128_PK_SIZE],
    uint8_t sk[AREION_PQ_SLHDSA128_SK_SIZE],
    const uint8_t seed[AREION_PQ_SLHDSA128_SEED_SIZE]) {
    pq_slh_keygen_core(&pq_slh_params_128f, seed, pk, sk);
}

void areion_pq_slhdsa_sign128f(
    uint8_t sig[AREION_PQ_SLHDSA128F_SIG_SIZE],
    const uint8_t sk[AREION_PQ_SLHDSA128_SK_SIZE],
    const uint8_t *msg, size_t msg_len,
    const uint8_t opt_rand[16]) {
    pq_slh_sign_core(&pq_slh_params_128f, sig, sk, msg, msg_len, opt_rand);
}

int areion_pq_slhdsa_verify128f(
    const uint8_t pk[AREION_PQ_SLHDSA128_PK_SIZE],
    const uint8_t *msg, size_t msg_len,
    const uint8_t sig[AREION_PQ_SLHDSA128F_SIG_SIZE]) {
    return pq_slh_verify_core(&pq_slh_params_128f, pk, msg, msg_len, sig);
}

void areion_pq_slhdsa_keygen128s(
    uint8_t pk[AREION_PQ_SLHDSA128_PK_SIZE],
    uint8_t sk[AREION_PQ_SLHDSA128_SK_SIZE],
    const uint8_t seed[AREION_PQ_SLHDSA128_SEED_SIZE]) {
    pq_slh_keygen_core(&pq_slh_params_128s, seed, pk, sk);
}

void areion_pq_slhdsa_sign128s(
    uint8_t sig[AREION_PQ_SLHDSA128S_SIG_SIZE],
    const uint8_t sk[AREION_PQ_SLHDSA128_SK_SIZE],
    const uint8_t *msg, size_t msg_len,
    const uint8_t opt_rand[16]) {
    pq_slh_sign_core(&pq_slh_params_128s, sig, sk, msg, msg_len, opt_rand);
}

int areion_pq_slhdsa_verify128s(
    const uint8_t pk[AREION_PQ_SLHDSA128_PK_SIZE],
    const uint8_t *msg, size_t msg_len,
    const uint8_t sig[AREION_PQ_SLHDSA128S_SIG_SIZE]) {
    return pq_slh_verify_core(&pq_slh_params_128s, pk, msg, msg_len, sig);
}

void areion_pq_slhdsa_keygen256f(
    uint8_t pk[AREION_PQ_SLHDSA256_PK_SIZE],
    uint8_t sk[AREION_PQ_SLHDSA256_SK_SIZE],
    const uint8_t seed[AREION_PQ_SLHDSA256_SEED_SIZE]) {
    pq_slh_keygen_core(&pq_slh_params_256f, seed, pk, sk);
}

void areion_pq_slhdsa_sign256f(
    uint8_t sig[AREION_PQ_SLHDSA256F_SIG_SIZE],
    const uint8_t sk[AREION_PQ_SLHDSA256_SK_SIZE],
    const uint8_t *msg, size_t msg_len,
    const uint8_t opt_rand[32]) {
    pq_slh_sign_core(&pq_slh_params_256f, sig, sk, msg, msg_len, opt_rand);
}

int areion_pq_slhdsa_verify256f(
    const uint8_t pk[AREION_PQ_SLHDSA256_PK_SIZE],
    const uint8_t *msg, size_t msg_len,
    const uint8_t sig[AREION_PQ_SLHDSA256F_SIG_SIZE]) {
    return pq_slh_verify_core(&pq_slh_params_256f, pk, msg, msg_len, sig);
}

void areion_pq_slhdsa_keygen256s(
    uint8_t pk[AREION_PQ_SLHDSA256_PK_SIZE],
    uint8_t sk[AREION_PQ_SLHDSA256_SK_SIZE],
    const uint8_t seed[AREION_PQ_SLHDSA256_SEED_SIZE]) {
    pq_slh_keygen_core(&pq_slh_params_256s, seed, pk, sk);
}

void areion_pq_slhdsa_sign256s(
    uint8_t sig[AREION_PQ_SLHDSA256S_SIG_SIZE],
    const uint8_t sk[AREION_PQ_SLHDSA256_SK_SIZE],
    const uint8_t *msg, size_t msg_len,
    const uint8_t opt_rand[32]) {
    pq_slh_sign_core(&pq_slh_params_256s, sig, sk, msg, msg_len, opt_rand);
}

int areion_pq_slhdsa_verify256s(
    const uint8_t pk[AREION_PQ_SLHDSA256_PK_SIZE],
    const uint8_t *msg, size_t msg_len,
    const uint8_t sig[AREION_PQ_SLHDSA256S_SIG_SIZE]) {
    return pq_slh_verify_core(&pq_slh_params_256s, pk, msg, msg_len, sig);
}

void areion_pq_slhdsa_tem_keygen256f(
    uint8_t pk[AREION_PQ_SLHDSA256_PK_SIZE],
    uint8_t sk[AREION_PQ_SLHDSA256_SK_SIZE],
    const uint8_t seed[AREION_PQ_SLHDSA256_SEED_SIZE]) {
    pq_slh_keygen_core(&pq_slh_params_tem256f, seed, pk, sk);
}

void areion_pq_slhdsa_tem_sign256f(
    uint8_t sig[AREION_PQ_SLHDSA_TEM256F_SIG_SIZE],
    const uint8_t sk[AREION_PQ_SLHDSA256_SK_SIZE],
    const uint8_t *msg, size_t msg_len,
    const uint8_t opt_rand[32]) {
    pq_slh_sign_core(&pq_slh_params_tem256f, sig, sk, msg, msg_len, opt_rand);
}

int areion_pq_slhdsa_tem_verify256f(
    const uint8_t pk[AREION_PQ_SLHDSA256_PK_SIZE],
    const uint8_t *msg, size_t msg_len,
    const uint8_t sig[AREION_PQ_SLHDSA_TEM256F_SIG_SIZE]) {
    return pq_slh_verify_core(&pq_slh_params_tem256f, pk, msg, msg_len, sig);
}


/* =========================================================================
 * 7. Track 1: FAEST-Areion (VOLE-in-the-Head Zero-Knowledge Signatures, §3.3 & §6)
 * ========================================================================= */

typedef struct {
    const uint8_t *ptr;
    size_t len;
} pq_iov_t;

static void pq_kdf_expand_iov(
    const pq_iov_t *iov, size_t iov_cnt,
    const uint8_t *context, size_t context_len,
    uint8_t *dst, size_t dst_len) {
    uint8_t dom[32], v[32], v2[32], b512[64], chunk[32];
    uint8_t k0[32], k1[32], k2[32], k3[32], k_soem[128];
    uint8_t keys4[4][128];
    uint8_t base_in[64], in4[4][64], out4[4][64], in64[64], out64[64];
    size_t total_secret_len = 0U;
    size_t chunk_fill = 0U;
    size_t idx_seg, off;
    uint64_t blk_idx;
    unsigned int lane;

    if (dst_len == 0U || dst == NULL) {
        return;
    }

    for (idx_seg = 0U; idx_seg < iov_cnt; idx_seg++) {
        total_secret_len += iov[idx_seg].len;
    }

    memset(dom, 0, sizeof(dom));
    areion_pq_store_le64(&dom[0], (uint64_t)total_secret_len);
    areion_pq_store_le64(&dom[8], (uint64_t)context_len);
    areion_pq_store_le64(&dom[16], UINT64_C(0x415245494F4E4B44));
    areion_dm256(v, dom);

    memset(chunk, 0, sizeof(chunk));
    for (idx_seg = 0U; idx_seg < iov_cnt; idx_seg++) {
        const uint8_t *p = iov[idx_seg].ptr;
        size_t rem = iov[idx_seg].len;
        while (rem > 0U) {
            size_t take = 32U - chunk_fill;
            if (take > rem) {
                take = rem;
            }
            if (p != NULL) {
                memcpy(&chunk[chunk_fill], p, take);
                p += take;
            } else {
                memset(&chunk[chunk_fill], 0, take);
            }
            chunk_fill += take;
            rem -= take;
            if (chunk_fill == 32U) {
                memcpy(&b512[0], v, 32U);
                memcpy(&b512[32], chunk, 32U);
                areion_dm512(v, b512);
                memset(chunk, 0, sizeof(chunk));
                chunk_fill = 0U;
            }
        }
    }
    if (chunk_fill > 0U) {
        memcpy(&b512[0], v, 32U);
        memcpy(&b512[32], chunk, 32U);
        areion_dm512(v, b512);
    }

    v[0] ^= 0x01U;
    areion_dm256(v, v);

    for (off = 0U; off < context_len; off += 32U) {
        size_t rem = context_len - off;
        if (rem > 32U) {
            rem = 32U;
        }
        memset(b512, 0, sizeof(b512));
        memcpy(&b512[0], v, 32U);
        if (context != NULL && rem > 0U) {
            memcpy(&b512[32], &context[off], rem);
        }
        areion_dm512(v, b512);
    }

    areion_dm256(k0, v);
    memcpy(k1, v, 32U);
    areion_permute256_p2(k1);
    pq_xor32(k1, k1, v);

    memcpy(v2, v, 32U);
    v2[0] ^= 0x02U;
    areion_dm256(k2, v2);
    memcpy(k3, v2, 32U);
    areion_permute256_p2(k3);
    pq_xor32(k3, k3, v2);

    memcpy(&k_soem[0], k0, 32U);
    memcpy(&k_soem[32], k1, 32U);
    memcpy(&k_soem[64], k2, 32U);
    memcpy(&k_soem[96], k3, 32U);

    for (lane = 0U; lane < 4U; lane++) {
        memcpy(keys4[lane], k_soem, 128U);
    }

    memcpy(&base_in[0], v, 32U);
    memcpy(&base_in[32], v2, 32U);

    blk_idx = 0U;
    off = 0U;
    while (off + 256U <= dst_len) {
        for (lane = 0U; lane < 4U; lane++) {
            uint64_t idx = blk_idx + (uint64_t)lane;
            uint64_t w0, w1;
            memcpy(in4[lane], base_in, 64U);
            w0 = areion_pq_load_le64(&in4[lane][0]) ^ idx;
            w1 = areion_pq_load_le64(&in4[lane][32]) ^ (idx ^ UINT64_C(0x5555555555555555));
            areion_pq_store_le64(&in4[lane][0], w0);
            areion_pq_store_le64(&in4[lane][32], w1);
        }
        areion_soem512x4(out4, (const uint8_t (*)[128])keys4, (const uint8_t (*)[64])in4);
        for (lane = 0U; lane < 4U; lane++) {
            memcpy(&dst[off + 64U * (size_t)lane], out4[lane], 64U);
        }
        blk_idx += 4U;
        off += 256U;
    }

    while (off < dst_len) {
        uint64_t w0, w1;
        size_t rem = dst_len - off;
        if (rem > 64U) {
            rem = 64U;
        }
        memcpy(in64, base_in, 64U);
        w0 = areion_pq_load_le64(&in64[0]) ^ blk_idx;
        w1 = areion_pq_load_le64(&in64[32]) ^ (blk_idx ^ UINT64_C(0x5555555555555555));
        areion_pq_store_le64(&in64[0], w0);
        areion_pq_store_le64(&in64[32], w1);
        areion_soem512(out64, k_soem, in64);
        memcpy(&dst[off], out64, rem);
        blk_idx++;
        off += rem;
    }

    areion_pq_secure_wipe(dom, sizeof(dom));
    areion_pq_secure_wipe(v, sizeof(v));
    areion_pq_secure_wipe(v2, sizeof(v2));
    areion_pq_secure_wipe(b512, sizeof(b512));
    areion_pq_secure_wipe(chunk, sizeof(chunk));
    areion_pq_secure_wipe(k0, sizeof(k0));
    areion_pq_secure_wipe(k1, sizeof(k1));
    areion_pq_secure_wipe(k2, sizeof(k2));
    areion_pq_secure_wipe(k3, sizeof(k3));
    areion_pq_secure_wipe(k_soem, sizeof(k_soem));
    areion_pq_secure_wipe(keys4, sizeof(keys4));
    areion_pq_secure_wipe(base_in, sizeof(base_in));
    areion_pq_secure_wipe(in4, sizeof(in4));
    areion_pq_secure_wipe(out4, sizeof(out4));
    areion_pq_secure_wipe(in64, sizeof(in64));
    areion_pq_secure_wipe(out64, sizeof(out64));
}

typedef struct {
    uint32_t lambda;
    uint32_t k_bytes;
    uint32_t l_bytes;
    uint32_t l_ext;
    uint32_t tau;
    uint32_t depths[32];
    int is_em2;
    size_t sig_size;
} pq_faest_params_t;

static const pq_faest_params_t pq_faest_params_128s = {
    16U, 16U, 304U, 320U, 13U,
    { 10U, 10U, 10U, 10U, 10U, 10U, 10U, 10U, 10U, 10U, 10U, 10U, 8U,
      0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U },
    0, AREION_PQ_FAEST128S_SIG_SIZE
};

static const pq_faest_params_t pq_faest_params_128f = {
    16U, 16U, 304U, 320U, 16U,
    { 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U,
      0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U },
    0, AREION_PQ_FAEST128F_SIG_SIZE
};

static const pq_faest_params_t pq_faest_params_256s = {
    32U, 32U, 320U, 352U, 26U,
    { 10U, 10U, 10U, 10U, 10U, 10U, 10U, 10U, 10U, 10U, 10U, 10U,
      10U, 10U, 10U, 10U, 10U, 10U, 10U, 10U, 10U, 10U, 10U, 10U,
      8U, 8U, 0U, 0U, 0U, 0U, 0U, 0U },
    0, AREION_PQ_FAEST256S_SIG_SIZE
};

static const pq_faest_params_t pq_faest_params_256f = {
    32U, 32U, 320U, 352U, 32U,
    { 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U,
      8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U },
    0, AREION_PQ_FAEST256F_SIG_SIZE
};

static const pq_faest_params_t pq_faest_params_em2_256s = {
    32U, 32U, 608U, 640U, 26U,
    { 10U, 10U, 10U, 10U, 10U, 10U, 10U, 10U, 10U, 10U, 10U, 10U,
      10U, 10U, 10U, 10U, 10U, 10U, 10U, 10U, 10U, 10U, 10U, 10U,
      8U, 8U, 0U, 0U, 0U, 0U, 0U, 0U },
    1, AREION_PQ_FAEST_EM2_256S_SIG_SIZE
};

static const pq_faest_params_t pq_faest_params_em2_256f = {
    32U, 32U, 608U, 640U, 32U,
    { 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U,
      8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U },
    1, AREION_PQ_FAEST_EM2_256F_SIG_SIZE
};

static void pq_faest_derive_tm(uint8_t t[32], uint8_t m[32], const uint8_t p_seed[32]) {
    uint8_t k128[128], z64[64], tm[64];
    memset(z64, 0, sizeof(z64));
    memcpy(&k128[0], p_seed, 32U);
    memcpy(&k128[32], p_seed, 32U);
    memcpy(&k128[64], p_seed, 32U);
    memcpy(&k128[96], p_seed, 32U);
    areion_soem512(tm, k128, z64);
    memcpy(t, &tm[0], 32U);
    memcpy(m, &tm[32], 32U);
    t[0] |= 0x02U;
    t[16] |= 0x02U;
    areion_pq_secure_wipe(k128, sizeof(k128));
    areion_pq_secure_wipe(tm, sizeof(tm));
}

static AREION_PQ_NOINLINE void pq_faest_keygen128_core_body(
    uint8_t pk[48], uint8_t sk[64], const uint8_t seed[32]) {
    uint8_t k32[32], p_seed[32], t[32], m[32], k2[32], state[32], c[32];

    pq_pad32(k32, &seed[0], 16U);
    pq_pad32(p_seed, &seed[16], 16U);
    pq_faest_derive_tm(t, m, p_seed);
    pq_mul_ortho256_body(k2, t, k32);
    pq_xor32(state, m, k32);
    areion_permute256(state);
    pq_xor32(c, state, k2);

    memcpy(&pk[0], &seed[16], 16U);
    memcpy(&pk[16], c, 32U);

    memcpy(&sk[0], &seed[0], 16U);
    memcpy(&sk[16], &seed[16], 16U);
    memcpy(&sk[32], c, 32U);

    areion_pq_secure_wipe(k32, sizeof(k32));
    areion_pq_secure_wipe(p_seed, sizeof(p_seed));
    areion_pq_secure_wipe(t, sizeof(t));
    areion_pq_secure_wipe(m, sizeof(m));
    areion_pq_secure_wipe(k2, sizeof(k2));
    areion_pq_secure_wipe(state, sizeof(state));
    areion_pq_secure_wipe(c, sizeof(c));
}

static void pq_faest_keygen128_core(uint8_t pk[48], uint8_t sk[64], const uint8_t seed[32]) {
    pq_faest_keygen128_core_body(pk, sk, seed);
    areion_pq_wipe_software_stack();
    areion_pq_clobber_scratch_gprs();
}

static AREION_PQ_NOINLINE void pq_faest_keygen256_core_body(
    uint8_t pk[64], uint8_t sk[96], const uint8_t seed[64], int is_em2) {
    uint8_t k32[32], p_seed[32], t[32], m[32], k2[32], k64[64], state[32], c[32];

    memcpy(k32, &seed[0], 32U);
    memcpy(p_seed, &seed[32], 32U);
    pq_faest_derive_tm(t, m, p_seed);

    if (is_em2) {
        pq_ortho_sigma256_body(k2, k32);
        memcpy(&k64[0], k32, 32U);
        memcpy(&k64[32], k2, 32U);
        areion_em2_encrypt256(c, k64, m);
    } else {
        pq_mul_ortho256_body(k2, t, k32);
        pq_xor32(state, m, k32);
        areion_permute256(state);
        pq_xor32(c, state, k2);
    }

    memcpy(&pk[0], p_seed, 32U);
    memcpy(&pk[32], c, 32U);

    memcpy(&sk[0], k32, 32U);
    memcpy(&sk[32], p_seed, 32U);
    memcpy(&sk[64], c, 32U);

    areion_pq_secure_wipe(k32, sizeof(k32));
    areion_pq_secure_wipe(p_seed, sizeof(p_seed));
    areion_pq_secure_wipe(t, sizeof(t));
    areion_pq_secure_wipe(m, sizeof(m));
    areion_pq_secure_wipe(k2, sizeof(k2));
    areion_pq_secure_wipe(k64, sizeof(k64));
    areion_pq_secure_wipe(state, sizeof(state));
    areion_pq_secure_wipe(c, sizeof(c));
}

static void pq_faest_keygen256_core(
    uint8_t pk[64], uint8_t sk[96], const uint8_t seed[64], int is_em2) {
    pq_faest_keygen256_core_body(pk, sk, seed, is_em2);
    areion_pq_wipe_software_stack();
    areion_pq_clobber_scratch_gprs();
}

static void pq_faest_expand_node(
    uint32_t lambda, const uint8_t salt[32],
    uint32_t t, uint32_t lvl, uint32_t idx,
    const uint8_t *s, uint8_t *c0, uint8_t *c1) {
    uint8_t b_node[64], h0[32];

    if (lambda == 16U) {
        pq_pad32(&b_node[0], s, 16U);
    } else {
        memcpy(&b_node[0], s, 32U);
    }
    pq_xor32(&b_node[0], &b_node[0], salt);
    areion_pq_store_le64(&b_node[32], (uint64_t)t);
    areion_pq_store_le64(&b_node[40], (uint64_t)lvl);
    areion_pq_store_le64(&b_node[48], (uint64_t)idx);
    areion_pq_store_le64(&b_node[56], UINT64_C(0x47474D4E4F444501));

    if (lambda == 16U) {
        areion_dm512(h0, b_node);
        memcpy(c0, &h0[0], 16U);
        memcpy(c1, &h0[16], 16U);
    } else {
        uint8_t h1[32];
        areion_dm512(h0, b_node);
        b_node[56] ^= 0x01U;
        areion_dm512(h1, b_node);
        memcpy(c0, h0, 32U);
        memcpy(c1, h1, 32U);
    }
}

static void pq_faest_expand_leaf(
    uint32_t lambda, uint32_t l_ext, const uint8_t salt[32],
    uint32_t t, uint32_t j, const uint8_t *s_leaf,
    uint8_t *row_out, uint8_t *com_out) {
    uint8_t k_leaf[64];
    uint8_t keys4[4][64];
    uint8_t buf[24 * 32];
    uint8_t in4[4][32], out4[4][32], in32[32], out32[32];
    uint32_t total_bytes = (com_out != NULL) ? (l_ext + lambda) : l_ext;
    uint32_t num_blks = (total_bytes + 31U) / 32U;
    uint32_t blk = 0U;
    uint32_t lane;

    if (lambda == 16U) {
        pq_pad32(&k_leaf[0], s_leaf, 16U);
    } else {
        memcpy(&k_leaf[0], s_leaf, 32U);
    }
    memcpy(&k_leaf[32], salt, 32U);

    if (row_out == NULL) {
        blk = l_ext / 32U;
        for (; blk < num_blks; blk++) {
            areion_pq_store_le64(&in32[0], (uint64_t)t);
            areion_pq_store_le64(&in32[8], (uint64_t)j);
            areion_pq_store_le64(&in32[16], (uint64_t)blk);
            areion_pq_store_le64(&in32[24], UINT64_C(0x564F4C454C454146));
            areion_soem256(out32, k_leaf, in32);
            memcpy(&buf[32U * (size_t)blk], out32, 32U);
        }
    } else {
        for (lane = 0U; lane < 4U; lane++) {
            memcpy(keys4[lane], k_leaf, 64U);
        }
        for (; blk < num_blks; blk += 4U) {
            for (lane = 0U; lane < 4U; lane++) {
                areion_pq_store_le64(&in4[lane][0], (uint64_t)t);
                areion_pq_store_le64(&in4[lane][8], (uint64_t)j);
                areion_pq_store_le64(&in4[lane][16], (uint64_t)blk + (uint64_t)lane);
                areion_pq_store_le64(&in4[lane][24], UINT64_C(0x564F4C454C454146));
            }
            areion_soem256x4(out4, (const uint8_t (*)[64])keys4, (const uint8_t (*)[32])in4);
            for (lane = 0U; lane < 4U; lane++) {
                memcpy(&buf[32U * (size_t)(blk + lane)], out4[lane], 32U);
            }
        }
        memcpy(row_out, &buf[0], (size_t)l_ext);
    }
    if (com_out != NULL) {
        memcpy(com_out, &buf[l_ext], (size_t)lambda);
    }
}

typedef struct {
    uint8_t val;
    uint8_t tag[8][16];
} pq_qs_byte_wire_t;

static void pq_qs_xor_byte_wire(
    pq_qs_byte_wire_t *out, const pq_qs_byte_wire_t *a, const pq_qs_byte_wire_t *b) {
    unsigned int k;
    out->val = (uint8_t)(a->val ^ b->val);
    for (k = 0U; k < 8U; k++) {
        pq_xor16(out->tag[k], a->tag[k], b->tag[k]);
    }
}

static inline void pq_xor16_masked(uint8_t dst[16], const uint8_t src[16], uint8_t bit) {
    uint64_t mask = 0ULL - ((uint64_t)bit & 1ULL);
    uint64_t lo = areion_pq_load_le64(&dst[0]) ^ (areion_pq_load_le64(&src[0]) & mask);
    uint64_t hi = areion_pq_load_le64(&dst[8]) ^ (areion_pq_load_le64(&src[8]) & mask);
    areion_pq_store_le64(&dst[0], lo);
    areion_pq_store_le64(&dst[8], hi);
}

static void pq_qs_add_const_byte(
    pq_qs_byte_wire_t *out, const pq_qs_byte_wire_t *w,
    uint8_t c, int is_verifier, const uint8_t delta[16]) {
    *out = *w;
    if (!is_verifier) {
        out->val ^= c;
    } else {
        unsigned int k;
        for (k = 0U; k < 8U; k++) {
            pq_xor16_masked(out->tag[k], delta, (uint8_t)(((uint32_t)c >> k) & 1U));
        }
    }
}

static void pq_qs_xtime_byte_wire(pq_qs_byte_wire_t *out, const pq_qs_byte_wire_t *w) {
    pq_qs_byte_wire_t r;
    r.val = areion_pq_gf256_mul(w->val, 0x02U);
    memcpy(r.tag[0], w->tag[7], 16U);
    pq_xor16(r.tag[1], w->tag[0], w->tag[7]);
    memcpy(r.tag[2], w->tag[1], 16U);
    pq_xor16(r.tag[3], w->tag[2], w->tag[7]);
    pq_xor16(r.tag[4], w->tag[3], w->tag[7]);
    memcpy(r.tag[5], w->tag[4], 16U);
    memcpy(r.tag[6], w->tag[5], 16U);
    memcpy(r.tag[7], w->tag[6], 16U);
    *out = r;
}

static const unsigned int pq_qs_inv_shift_rows_idx[16] = {
    0U, 13U, 10U, 7U, 4U, 1U, 14U, 11U, 8U, 5U, 2U, 15U, 12U, 9U, 6U, 3U
};

static void pq_qs_inv_shift_rows_block(
    pq_qs_byte_wire_t out[16], const pq_qs_byte_wire_t in[16]) {
    pq_qs_byte_wire_t tmp[16];
    unsigned int i;
    for (i = 0U; i < 16U; i++) {
        tmp[i] = in[pq_qs_inv_shift_rows_idx[i]];
    }
    memcpy(out, tmp, sizeof(tmp));
}

static void pq_qs_mix_columns_block(
    pq_qs_byte_wire_t out[16], const pq_qs_byte_wire_t in[16]) {
    unsigned int col;
    for (col = 0U; col < 4U; col++) {
        pq_qs_byte_wire_t s0 = in[4U * col + 0U];
        pq_qs_byte_wire_t s1 = in[4U * col + 1U];
        pq_qs_byte_wire_t s2 = in[4U * col + 2U];
        pq_qs_byte_wire_t s3 = in[4U * col + 3U];
        pq_qs_byte_wire_t t01, t23, t, s12, s30, xt01, xt12, xt23, xt30, u0, u1, u2, u3;

        pq_qs_xor_byte_wire(&t01, &s0, &s1);
        pq_qs_xor_byte_wire(&t23, &s2, &s3);
        pq_qs_xor_byte_wire(&t, &t01, &t23);

        pq_qs_xor_byte_wire(&s12, &s1, &s2);
        pq_qs_xor_byte_wire(&s30, &s3, &s0);

        pq_qs_xtime_byte_wire(&xt01, &t01);
        pq_qs_xtime_byte_wire(&xt12, &s12);
        pq_qs_xtime_byte_wire(&xt23, &t23);
        pq_qs_xtime_byte_wire(&xt30, &s30);

        pq_qs_xor_byte_wire(&u0, &s0, &t);
        pq_qs_xor_byte_wire(&u1, &s1, &t);
        pq_qs_xor_byte_wire(&u2, &s2, &t);
        pq_qs_xor_byte_wire(&u3, &s3, &t);

        pq_qs_xor_byte_wire(&out[4U * col + 0U], &u0, &xt01);
        pq_qs_xor_byte_wire(&out[4U * col + 1U], &u1, &xt12);
        pq_qs_xor_byte_wire(&out[4U * col + 2U], &u2, &xt23);
        pq_qs_xor_byte_wire(&out[4U * col + 3U], &u3, &xt30);
    }
}

static void pq_qs_inv_mix_columns_block(
    pq_qs_byte_wire_t out[16], const pq_qs_byte_wire_t in[16]) {
    pq_qs_byte_wire_t pre[16];
    unsigned int col;
    for (col = 0U; col < 4U; col++) {
        pq_qs_byte_wire_t s0 = in[4U * col + 0U];
        pq_qs_byte_wire_t s1 = in[4U * col + 1U];
        pq_qs_byte_wire_t s2 = in[4U * col + 2U];
        pq_qs_byte_wire_t s3 = in[4U * col + 3U];
        pq_qs_byte_wire_t s02, s13, u1, u, v1, v;

        pq_qs_xor_byte_wire(&s02, &s0, &s2);
        pq_qs_xor_byte_wire(&s13, &s1, &s3);
        pq_qs_xtime_byte_wire(&u1, &s02);
        pq_qs_xtime_byte_wire(&u, &u1);
        pq_qs_xtime_byte_wire(&v1, &s13);
        pq_qs_xtime_byte_wire(&v, &v1);

        pq_qs_xor_byte_wire(&pre[4U * col + 0U], &s0, &u);
        pq_qs_xor_byte_wire(&pre[4U * col + 1U], &s1, &v);
        pq_qs_xor_byte_wire(&pre[4U * col + 2U], &s2, &u);
        pq_qs_xor_byte_wire(&pre[4U * col + 3U], &s3, &v);
    }
    pq_qs_mix_columns_block(out, pre);
}

static void pq_qs_sq_gf256_wire(pq_qs_byte_wire_t *u, const pq_qs_byte_wire_t *x) {
    uint8_t t46[16], t67[16], t467[16];
    u->val = areion_pq_gf256_sq(x->val);
    pq_xor16(t46, x->tag[4], x->tag[6]);
    pq_xor16(t67, x->tag[6], x->tag[7]);
    pq_xor16(t467, t46, x->tag[7]);

    pq_xor16(u->tag[0], x->tag[0], t46);
    memcpy(u->tag[1], t467, 16U);
    pq_xor16(u->tag[2], x->tag[1], x->tag[5]);
    pq_xor16(u->tag[3], t467, x->tag[5]);
    pq_xor16(u->tag[4], x->tag[2], x->tag[4]);
    pq_xor16(u->tag[4], u->tag[4], x->tag[7]);
    pq_xor16(u->tag[5], x->tag[5], x->tag[6]);
    pq_xor16(u->tag[6], x->tag[3], x->tag[5]);
    memcpy(u->tag[7], t67, 16U);
}

static void pq_qs_affine_inv_wire(
    pq_qs_byte_wire_t *y, const pq_qs_byte_wire_t *s,
    int is_verifier, const uint8_t delta[16]) {
    pq_qs_byte_wire_t sp;
    unsigned int b;

    pq_qs_add_const_byte(&sp, s, 0x63U, is_verifier, delta);
    y->val = areion_pq_gf256_affine_inv(s->val);
    for (b = 0U; b < 8U; b++) {
        uint8_t t[16];
        pq_xor16(t, sp.tag[(b + 2U) & 7U], sp.tag[(b + 5U) & 7U]);
        pq_xor16(y->tag[b], t, sp.tag[(b + 7U) & 7U]);
    }
}

static void pq_qs_reduce_gf256_tags(uint8_t p[8][16], const uint8_t d[15][16]) {
    static const uint8_t mod_mask[7] = { 0x1BU, 0x36U, 0x6CU, 0xD8U, 0xABU, 0x4DU, 0x9AU };
    unsigned int i, k, b;
    for (i = 0U; i < 8U; i++) {
        memcpy(p[i], d[i], 16U);
    }
    for (k = 0U; k < 7U; k++) {
        uint8_t m = mod_mask[k];
        for (b = 0U; b < 8U; b++) {
            if ((((uint32_t)m >> b) & 1U) != 0U) {
                pq_xor16(p[b], p[b], d[8U + k]);
            }
        }
    }
}

/* 3-level Karatsuba over GF(2^128)[z] reducing 64 GF(2^128) muls per constraint to 27. */
static void pq_qs_mul2(uint8_t d[3][16], const uint8_t a[2][16], const uint8_t b[2][16]) {
    uint8_t a01[16], b01[16], m[16];
    areion_pq_dispatch_gf128_mul_nowipe(d[0], a[0], b[0]);
    areion_pq_dispatch_gf128_mul_nowipe(d[2], a[1], b[1]);
    pq_xor16(a01, a[0], a[1]);
    pq_xor16(b01, b[0], b[1]);
    areion_pq_dispatch_gf128_mul_nowipe(m, a01, b01);
    pq_xor16(d[1], m, d[0]);
    pq_xor16(d[1], d[1], d[2]);
}

static void pq_qs_mul4(uint8_t d[7][16], const uint8_t a[4][16], const uint8_t b[4][16]) {
    uint8_t p0[3][16], p1[3][16], pm[3][16];
    uint8_t a_sum[2][16], b_sum[2][16];
    unsigned int i;

    pq_qs_mul2(p0, &a[0], &b[0]);
    pq_qs_mul2(p1, &a[2], &b[2]);
    for (i = 0U; i < 2U; i++) {
        pq_xor16(a_sum[i], a[i], a[2U + i]);
        pq_xor16(b_sum[i], b[i], b[2U + i]);
    }
    pq_qs_mul2(pm, (const uint8_t (*)[16])a_sum, (const uint8_t (*)[16])b_sum);

    memset(d, 0, (size_t)7U * 16U);
    for (i = 0U; i < 3U; i++) {
        pq_xor16(pm[i], pm[i], p0[i]);
        pq_xor16(pm[i], pm[i], p1[i]);
        pq_xor16(d[i], d[i], p0[i]);
        pq_xor16(d[i + 2U], d[i + 2U], pm[i]);
        pq_xor16(d[i + 4U], d[i + 4U], p1[i]);
    }
}

static void pq_qs_mul8(uint8_t d[15][16], const uint8_t a[8][16], const uint8_t b[8][16]) {
    uint8_t p0[7][16], p1[7][16], pm[7][16];
    uint8_t a_sum[4][16], b_sum[4][16];
    unsigned int i;

    pq_qs_mul4(p0, &a[0], &b[0]);
    pq_qs_mul4(p1, &a[4], &b[4]);
    for (i = 0U; i < 4U; i++) {
        pq_xor16(a_sum[i], a[i], a[4U + i]);
        pq_xor16(b_sum[i], b[i], b[4U + i]);
    }
    pq_qs_mul4(pm, (const uint8_t (*)[16])a_sum, (const uint8_t (*)[16])b_sum);

    memset(d, 0, (size_t)15U * 16U);
    for (i = 0U; i < 7U; i++) {
        pq_xor16(pm[i], pm[i], p0[i]);
        pq_xor16(pm[i], pm[i], p1[i]);
        pq_xor16(d[i], d[i], p0[i]);
        pq_xor16(d[i + 4U], d[i + 4U], pm[i]);
        pq_xor16(d[i + 8U], d[i + 8U], p1[i]);
    }
}

static void pq_qs_eval_bilinear_constraint(
    const pq_qs_byte_wire_t *a, const pq_qs_byte_wire_t *b, const pq_qs_byte_wire_t *c,
    int is_verifier, const uint8_t delta[16], const uint8_t chi[16],
    uint8_t a1_acc[16], uint8_t a0_or_bv_acc[16]) {
    uint8_t d0[15][16], p0[8][16];
    unsigned int m;

    pq_qs_mul8(d0, a->tag, b->tag);
    pq_qs_reduce_gf256_tags(p0, (const uint8_t (*)[16])d0);

    if (!is_verifier) {
        uint8_t d1[15][16], p1[8][16];
        unsigned int i, j;
        memset(d1, 0, sizeof(d1));
        for (i = 0U; i < 8U; i++) {
            uint8_t ai_val = (uint8_t)(((uint32_t)a->val >> i) & 1U);
            for (j = 0U; j < 8U; j++) {
                uint8_t bj_val = (uint8_t)(((uint32_t)b->val >> j) & 1U);
                pq_xor16_masked(d1[i + j], b->tag[j], ai_val);
                pq_xor16_masked(d1[i + j], a->tag[i], bj_val);
            }
        }
        pq_qs_reduce_gf256_tags(p1, (const uint8_t (*)[16])d1);
        for (m = 0U; m < 8U; m++) {
            pq_xor16(p1[m], p1[m], c->tag[m]);
            areion_pq_dispatch_gf128_mul_nowipe(a1_acc, a1_acc, chi);
            pq_xor16(a1_acc, a1_acc, p1[m]);

            areion_pq_dispatch_gf128_mul_nowipe(a0_or_bv_acc, a0_or_bv_acc, chi);
            pq_xor16(a0_or_bv_acc, a0_or_bv_acc, p0[m]);
        }
    } else {
        uint8_t c_delta[16];
        for (m = 0U; m < 8U; m++) {
            areion_pq_dispatch_gf128_mul_nowipe(c_delta, c->tag[m], delta);
            pq_xor16(p0[m], p0[m], c_delta);
            areion_pq_dispatch_gf128_mul_nowipe(a0_or_bv_acc, a0_or_bv_acc, chi);
            pq_xor16(a0_or_bv_acc, a0_or_bv_acc, p0[m]);
        }
    }
}

static void pq_qs_eval_sbox_gate(
    const pq_qs_byte_wire_t *x, const pq_qs_byte_wire_t *s,
    int is_verifier, const uint8_t delta[16], const uint8_t chi[16],
    uint8_t a1_acc[16], uint8_t a0_or_bv_acc[16]) {
    pq_qs_byte_wire_t u, y, w;
    pq_qs_sq_gf256_wire(&u, x);
    pq_qs_affine_inv_wire(&y, s, is_verifier, delta);
    pq_qs_sq_gf256_wire(&w, &y);
    pq_qs_eval_bilinear_constraint(&u, &y, x, is_verifier, delta, chi, a1_acc, a0_or_bv_acc);
    pq_qs_eval_bilinear_constraint(&w, x, &y, is_verifier, delta, chi, a1_acc, a0_or_bv_acc);
}

static void pq_qs_mul_ortho128_wires(
    pq_qs_byte_wire_t out[16], const uint8_t t_half[16], const pq_qs_byte_wire_t k_wires[16]) {
    uint8_t p_cur[16];
    unsigned int b, j;

    memset(out, 0, 16U * sizeof(pq_qs_byte_wire_t));
    memcpy(p_cur, t_half, 16U);

    for (b = 0U; b < 128U; b++) {
        unsigned int byte_idx = b >> 3U;
        unsigned int bit_idx = b & 7U;
        uint8_t w_val = (uint8_t)(((uint32_t)k_wires[byte_idx].val >> bit_idx) & 1U);
        const uint8_t *w_tag = k_wires[byte_idx].tag[bit_idx];
        uint64_t lo, hi, msb;

        for (j = 0U; j < 128U; j++) {
            unsigned int jb = j >> 3U;
            unsigned int jbit = j & 7U;
            if ((((uint32_t)p_cur[jb] >> jbit) & 1U) != 0U) {
                out[jb].val ^= (uint8_t)((uint32_t)w_val << jbit);
                pq_xor16(out[jb].tag[jbit], out[jb].tag[jbit], w_tag);
            }
        }

        lo = areion_pq_load_le64(&p_cur[0]);
        hi = areion_pq_load_le64(&p_cur[8]);
        msb = hi >> 63U;
        hi = (hi << 1U) | (lo >> 63U);
        lo = (lo << 1U) ^ (UINT64_C(0x87) & (0U - msb));
        areion_pq_store_le64(&p_cur[0], lo);
        areion_pq_store_le64(&p_cur[8], hi);
    }
}

static void pq_qs_wire_from_witness_byte(
    pq_qs_byte_wire_t *w, uint32_t byte_offset,
    const uint8_t *w_full, const uint8_t bit_tags[][16], int is_verifier) {
    unsigned int b;
    w->val = (!is_verifier && w_full != NULL) ? w_full[byte_offset] : 0U;
    for (b = 0U; b < 8U; b++) {
        memcpy(w->tag[b], bit_tags[8U * byte_offset + b], 16U);
    }
}

static void pq_faest_eval_quicksilver_lane(
    const pq_faest_params_t *p,
    const uint8_t m_pub[32], const uint8_t t_pub[32], const uint8_t c_pub[32],
    const uint8_t *w_full, const uint8_t bit_tags[][16],
    int is_verifier, const uint8_t delta_lane[16], const uint8_t chi[16],
    uint8_t a1_acc[16], uint8_t a0_or_bv_acc[16]) {
    pq_qs_byte_wire_t k1_wires[32], k2_wires[32];
    pq_qs_byte_wire_t x0[16], x1[16];
    uint32_t i, r, j, p1_rounds;

    memset(a1_acc, 0, 16U);
    memset(a0_or_bv_acc, 0, 16U);

    if (p->k_bytes == 16U) {
        for (i = 0U; i < 16U; i++) {
            pq_qs_wire_from_witness_byte(&k1_wires[i], i, w_full, bit_tags, is_verifier);
            k1_wires[16U + i] = k1_wires[i];
        }
    } else {
        for (i = 0U; i < 32U; i++) {
            pq_qs_wire_from_witness_byte(&k1_wires[i], i, w_full, bit_tags, is_verifier);
        }
    }

    if (!p->is_em2) {
        pq_qs_mul_ortho128_wires(&k2_wires[0], &t_pub[0], &k1_wires[0]);
        pq_qs_mul_ortho128_wires(&k2_wires[16], &t_pub[16], &k1_wires[16]);
    } else {
        for (i = 0U; i < 16U; i++) {
            k2_wires[i] = k1_wires[16U + i];
            pq_qs_xor_byte_wire(&k2_wires[16U + i], &k1_wires[i], &k1_wires[16U + i]);
        }
    }

    for (i = 0U; i < 16U; i++) {
        pq_qs_add_const_byte(&x0[i], &k1_wires[i], m_pub[i], is_verifier, delta_lane);
        pq_qs_add_const_byte(&x1[i], &k1_wires[16U + i], m_pub[16U + i], is_verifier, delta_lane);
    }

    p1_rounds = p->is_em2 ? 9U : 10U;
    for (r = 0U; r < p1_rounds; r++) {
        pq_qs_byte_wire_t a[16], b[16], a_next[16], b_next[16];
        pq_qs_byte_wire_t s1[16], mc[16], x2[16], t[16], imc[16], s2[16];

        if ((r & 1U) == 0U) {
            memcpy(a, x0, sizeof(a));
            memcpy(b, x1, sizeof(b));
        } else {
            memcpy(a, x1, sizeof(a));
            memcpy(b, x0, sizeof(b));
        }
        if (r < 9U) {
            uint32_t base = p->k_bytes + 32U * r;
            for (i = 0U; i < 16U; i++) {
                pq_qs_wire_from_witness_byte(&a_next[i], base + i, w_full, bit_tags, is_verifier);
                pq_qs_wire_from_witness_byte(&b_next[i], base + 16U + i, w_full, bit_tags, is_verifier);
            }
        } else {
            for (i = 0U; i < 16U; i++) {
                pq_qs_add_const_byte(&a_next[i], &k2_wires[16U + i], c_pub[16U + i], is_verifier, delta_lane);
                pq_qs_add_const_byte(&b_next[i], &k2_wires[i], c_pub[i], is_verifier, delta_lane);
            }
        }

        pq_qs_inv_shift_rows_block(s1, a_next);
        for (j = 0U; j < 16U; j++) {
            pq_qs_eval_sbox_gate(&a[j], &s1[j], is_verifier, delta_lane, chi, a1_acc, a0_or_bv_acc);
        }

        pq_qs_mix_columns_block(mc, a_next);
        for (j = 0U; j < 16U; j++) {
            pq_qs_add_const_byte(&x2[j], &mc[j], areion_pq_rc_p1[r][j], is_verifier, delta_lane);
            pq_qs_xor_byte_wire(&t[j], &b[j], &b_next[j]);
        }
        pq_qs_inv_mix_columns_block(imc, t);
        pq_qs_inv_shift_rows_block(s2, imc);
        for (j = 0U; j < 16U; j++) {
            pq_qs_eval_sbox_gate(&x2[j], &s2[j], is_verifier, delta_lane, chi, a1_acc, a0_or_bv_acc);
        }

        if ((r & 1U) == 0U) {
            memcpy(x0, a_next, sizeof(x0));
            memcpy(x1, b_next, sizeof(x1));
        } else {
            memcpy(x1, a_next, sizeof(x1));
            memcpy(x0, b_next, sizeof(x0));
        }
    }

    if (p->is_em2) {
        uint32_t base_p2 = p->k_bytes + 288U;
        for (i = 0U; i < 16U; i++) {
            pq_qs_wire_from_witness_byte(&x0[i], base_p2 + i, w_full, bit_tags, is_verifier);
            pq_qs_wire_from_witness_byte(&x1[i], base_p2 + 16U + i, w_full, bit_tags, is_verifier);
        }
        for (r = 1U; r < 10U; r++) {
            pq_qs_byte_wire_t a[16], b[16], a_next[16], b_next[16];
            pq_qs_byte_wire_t s1[16], mc[16], x2[16], t[16], imc[16], s2[16];

            if ((r & 1U) == 0U) {
                memcpy(a, x0, sizeof(a));
                memcpy(b, x1, sizeof(b));
            } else {
                memcpy(a, x1, sizeof(a));
                memcpy(b, x0, sizeof(b));
            }
            if (r < 9U) {
                uint32_t base = base_p2 + 32U * r;
                for (i = 0U; i < 16U; i++) {
                    pq_qs_wire_from_witness_byte(&a_next[i], base + i, w_full, bit_tags, is_verifier);
                    pq_qs_wire_from_witness_byte(&b_next[i], base + 16U + i, w_full, bit_tags, is_verifier);
                }
            } else {
                for (i = 0U; i < 16U; i++) {
                    pq_qs_byte_wire_t k12_hi, k12_lo;
                    pq_qs_xor_byte_wire(&k12_hi, &k1_wires[16U + i], &k2_wires[16U + i]);
                    pq_qs_xor_byte_wire(&k12_lo, &k1_wires[i], &k2_wires[i]);
                    pq_qs_add_const_byte(&a_next[i], &k12_hi, c_pub[16U + i], is_verifier, delta_lane);
                    pq_qs_add_const_byte(&b_next[i], &k12_lo, c_pub[i], is_verifier, delta_lane);
                }
            }

            pq_qs_inv_shift_rows_block(s1, a_next);
            for (j = 0U; j < 16U; j++) {
                pq_qs_eval_sbox_gate(&a[j], &s1[j], is_verifier, delta_lane, chi, a1_acc, a0_or_bv_acc);
            }

            pq_qs_mix_columns_block(mc, a_next);
            for (j = 0U; j < 16U; j++) {
                pq_qs_add_const_byte(&x2[j], &mc[j], areion_pq_rc_p2[r][j], is_verifier, delta_lane);
                pq_qs_xor_byte_wire(&t[j], &b[j], &b_next[j]);
            }
            pq_qs_inv_mix_columns_block(imc, t);
            pq_qs_inv_shift_rows_block(s2, imc);
            for (j = 0U; j < 16U; j++) {
                pq_qs_eval_sbox_gate(&x2[j], &s2[j], is_verifier, delta_lane, chi, a1_acc, a0_or_bv_acc);
            }

            if ((r & 1U) == 0U) {
                memcpy(x0, a_next, sizeof(x0));
                memcpy(x1, b_next, sizeof(x1));
            } else {
                memcpy(x1, a_next, sizeof(x1));
                memcpy(x0, b_next, sizeof(x0));
            }
        }
    }

    areion_pq_secure_wipe(k1_wires, sizeof(k1_wires));
    areion_pq_secure_wipe(k2_wires, sizeof(k2_wires));
    areion_pq_secure_wipe(x0, sizeof(x0));
    areion_pq_secure_wipe(x1, sizeof(x1));
}

static void pq_faest_fold_mask128(
    uint8_t mask[16], const uint8_t bit_tags[][16], uint32_t start_bit) {
    uint8_t basis[16], prod[16];
    uint32_t m;

    memset(mask, 0, 16U);
    for (m = 0U; m < 128U; m++) {
        memset(basis, 0, sizeof(basis));
        basis[m >> 3U] = (uint8_t)(1U << (m & 7U));
        areion_pq_dispatch_gf128_mul_nowipe(prod, bit_tags[start_bit + m], basis);
        pq_xor16(mask, mask, prod);
    }
}

static AREION_PQ_NOINLINE void pq_faest_sign_core_body(
    const pq_faest_params_t *p, uint8_t *sig_out,
    const uint8_t *sk, size_t sk_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *opt_rand) {
    uint8_t k32[32], p_seed[32], c_pub[32], pk_bytes[64], t_pub[32], m_pub[32];
    uint8_t w_full[608], k2[32], c_unused[32];
    uint8_t opt_local[32];
    uint8_t root_buf[32 + 32 * 32], salt[32];
    uint8_t u0[640], c_trees[32][640], q_rows[256][640], h_trees[32][32];
    uint8_t cur_nodes[1024 * 32], next_nodes[1024 * 32], com_concat[1024 * 32];
    uint8_t row_j[640], ut[640], d_ext[640], chi[16];
    uint8_t bit_tags[8 * 640][16];
    uint8_t zero_delta[16], qs_u[32], w_poly[32], delta_in[80], delta[32];
    pq_iov_t seed_iov[3], fs_iov[6];
    size_t pk_len, off, com_off, end_off;
    uint32_t bit_off, t, lvl, idx, j, b, num_lanes, lane, k, i;

    if (p->k_bytes == 16U) {
        pq_pad32(k32, &sk[0], 16U);
        pq_pad32(p_seed, &sk[16], 16U);
        memcpy(c_pub, &sk[32], 32U);
        memcpy(&pk_bytes[0], &sk[16], 16U);
        memcpy(&pk_bytes[16], &sk[32], 32U);
        pk_len = 48U;
    } else {
        memcpy(k32, &sk[0], 32U);
        memcpy(p_seed, &sk[32], 32U);
        memcpy(c_pub, &sk[64], 32U);
        memcpy(&pk_bytes[0], &sk[32], 32U);
        memcpy(&pk_bytes[32], &sk[64], 32U);
        pk_len = 64U;
    }

    pq_faest_derive_tm(t_pub, m_pub, p_seed);
    memset(w_full, 0, sizeof(w_full));
    memcpy(&w_full[0], &sk[0], (size_t)p->k_bytes);
    if (!p->is_em2) {
        pq_mul_ortho256_body(k2, t_pub, k32);
        areion_pq_extract_witness256(c_unused, &w_full[p->k_bytes], m_pub, k32, k2);
    } else {
        pq_ortho_sigma256_body(k2, k32);
        areion_pq_extract_witness_em2_256(c_unused, &w_full[p->k_bytes], m_pub, k32, k2);
    }

    memset(opt_local, 0, sizeof(opt_local));
    if (opt_rand != NULL) {
        memcpy(opt_local, opt_rand, (size_t)p->lambda);
    }
    seed_iov[0].ptr = sk;
    seed_iov[0].len = sk_len;
    seed_iov[1].ptr = opt_local;
    seed_iov[1].len = (size_t)p->lambda;
    seed_iov[2].ptr = msg;
    seed_iov[2].len = msg_len;
    pq_kdf_expand_iov(
        seed_iov, 3U,
        (const uint8_t *)"FAEST-AREION-ROOT", 17U,
        root_buf, 32U + (size_t)p->tau * (size_t)p->lambda);

    memcpy(salt, &root_buf[0], 32U);
    memcpy(&sig_out[0], salt, 32U);

    memset(u0, 0, sizeof(u0));
    memset(c_trees, 0, sizeof(c_trees));
    memset(q_rows, 0, sizeof(q_rows));
    memset(h_trees, 0, sizeof(h_trees));

    bit_off = 0U;
    for (t = 0U; t < p->tau; t++) {
        uint32_t dt = p->depths[t];
        uint32_t nt = 1U << dt;

        memcpy(cur_nodes, &root_buf[32U + t * p->lambda], (size_t)p->lambda);
        for (lvl = 0U; lvl < dt; lvl++) {
            uint32_t num_nodes = 1U << lvl;
            for (idx = 0U; idx < num_nodes; idx++) {
                pq_faest_expand_node(
                    p->lambda, salt, t, lvl, idx,
                    &cur_nodes[(size_t)idx * (size_t)p->lambda],
                    &next_nodes[(size_t)(2U * idx) * (size_t)p->lambda],
                    &next_nodes[(size_t)(2U * idx + 1U) * (size_t)p->lambda]);
            }
            memcpy(cur_nodes, next_nodes, (size_t)(2U * num_nodes) * (size_t)p->lambda);
        }

        memset(ut, 0, sizeof(ut));
        for (j = 0U; j < nt; j++) {
            pq_faest_expand_leaf(
                p->lambda, p->l_ext, salt, t, j,
                &cur_nodes[(size_t)j * (size_t)p->lambda],
                row_j, &com_concat[(size_t)j * (size_t)p->lambda]);
            areion_pq_dispatch_vole_xor_row_nowipe(ut, row_j, (size_t)p->l_ext);
            for (b = 0U; b < dt; b++) {
                if (((j >> b) & 1U) != 0U) {
                    areion_pq_dispatch_vole_xor_row_nowipe(q_rows[bit_off + b], row_j, (size_t)p->l_ext);
                }
            }
        }

        if (t < p->tau - 1U) {
            pq_kdf_expand_body(
                h_trees[t], 32U,
                com_concat, (size_t)nt * (size_t)p->lambda,
                salt, 32U);
        }
        if (t == 0U) {
            memcpy(u0, ut, (size_t)p->l_ext);
        } else {
            for (i = 0U; i < p->l_ext; i++) {
                c_trees[t][i] = (uint8_t)(u0[i] ^ ut[i]);
            }
        }
        bit_off += dt;
    }

    memset(d_ext, 0, sizeof(d_ext));
    for (i = 0U; i < p->l_bytes; i++) {
        d_ext[i] = (uint8_t)(w_full[i] ^ u0[i]);
    }

    /* Pack c_1 .. c_{tau-1} into sig_out[32 + l_ext : 32 + tau * l_ext] first so we can stream it into chi. */
    off = 32U + (size_t)p->l_ext;
    for (t = 1U; t < p->tau; t++) {
        memcpy(&sig_out[off], c_trees[t], (size_t)p->l_ext);
        off += (size_t)p->l_ext;
    }

    fs_iov[0].ptr = pk_bytes;
    fs_iov[0].len = pk_len;
    fs_iov[1].ptr = msg;
    fs_iov[1].len = msg_len;
    fs_iov[2].ptr = salt;
    fs_iov[2].len = 32U;
    fs_iov[3].ptr = &h_trees[0][0];
    fs_iov[3].len = (size_t)(p->tau - 1U) * 32U;
    fs_iov[4].ptr = d_ext;
    fs_iov[4].len = (size_t)p->l_bytes;
    fs_iov[5].ptr = &sig_out[32U + (size_t)p->l_ext];
    fs_iov[5].len = (size_t)(p->tau - 1U) * (size_t)p->l_ext;
    pq_kdf_expand_iov(
        fs_iov, 6U,
        (const uint8_t *)"FAEST-FS-CHI", 12U,
        chi, 16U);
    chi[0] |= 0x01U;

    num_lanes = p->lambda / 16U;
    memset(zero_delta, 0, sizeof(zero_delta));
    memset(qs_u, 0, sizeof(qs_u));
    memset(w_poly, 0, sizeof(w_poly));

    for (lane = 0U; lane < num_lanes; lane++) {
        uint8_t a1_acc[16], a0_acc[16], q_mask[16];
        memset(bit_tags, 0, (size_t)(8U * p->l_ext) * 16U);
        for (k = 0U; k < 128U; k++) {
            const uint8_t *row = q_rows[128U * lane + k];
            uint32_t k_byte = k >> 3U;
            uint32_t k_bit = k & 7U;
            for (i = 0U; i < p->l_ext; i++) {
                uint32_t rb = (uint32_t)row[i];
                uint32_t base = i << 3U;
                bit_tags[base + 0U][k_byte] |= (uint8_t)((rb & 1U) << k_bit);
                bit_tags[base + 1U][k_byte] |= (uint8_t)(((rb >> 1U) & 1U) << k_bit);
                bit_tags[base + 2U][k_byte] |= (uint8_t)(((rb >> 2U) & 1U) << k_bit);
                bit_tags[base + 3U][k_byte] |= (uint8_t)(((rb >> 3U) & 1U) << k_bit);
                bit_tags[base + 4U][k_byte] |= (uint8_t)(((rb >> 4U) & 1U) << k_bit);
                bit_tags[base + 5U][k_byte] |= (uint8_t)(((rb >> 5U) & 1U) << k_bit);
                bit_tags[base + 6U][k_byte] |= (uint8_t)(((rb >> 6U) & 1U) << k_bit);
                bit_tags[base + 7U][k_byte] |= (uint8_t)(((rb >> 7U) & 1U) << k_bit);
            }
        }
        pq_faest_eval_quicksilver_lane(
            p, m_pub, t_pub, c_pub, w_full,
            (const uint8_t (*)[16])bit_tags, 0, zero_delta, chi, a1_acc, a0_acc);
        pq_faest_fold_mask128(q_mask, (const uint8_t (*)[16])bit_tags, 8U * p->l_bytes + 128U * lane);
        for (i = 0U; i < 16U; i++) {
            uint8_t u_mask_byte = u0[p->l_bytes + 16U * lane + i];
            qs_u[16U * lane + i] = (uint8_t)(a1_acc[i] ^ u_mask_byte);
            d_ext[p->l_bytes + 16U * lane + i] = qs_u[16U * lane + i];
            w_poly[16U * lane + i] = (uint8_t)(a0_acc[i] ^ q_mask[i]);
        }
        areion_pq_secure_wipe(a1_acc, sizeof(a1_acc));
        areion_pq_secure_wipe(a0_acc, sizeof(a0_acc));
        areion_pq_secure_wipe(q_mask, sizeof(q_mask));
    }

    memcpy(&sig_out[32], d_ext, (size_t)p->l_ext);

    memcpy(&delta_in[0], chi, 16U);
    memcpy(&delta_in[16], qs_u, (size_t)p->lambda);
    memcpy(&delta_in[16U + p->lambda], w_poly, (size_t)p->lambda);
    pq_kdf_expand_body(
        delta, (size_t)p->lambda,
        delta_in, 16U + 2U * (size_t)p->lambda,
        salt, 32U);

    com_off = off + (size_t)(8U * p->lambda) * (size_t)p->lambda;
    bit_off = 0U;
    {
        uint8_t path_node[32], c0[32], c1[32];
        for (t = 0U; t < p->tau; t++) {
            uint32_t dt = p->depths[t];
            uint32_t delta_t = 0U;

            for (b = 0U; b < dt; b++) {
                uint32_t g_bit = bit_off + b;
                if ((((uint32_t)delta[g_bit >> 3U] >> (g_bit & 7U)) & 1U) != 0U) {
                    delta_t |= 1U << b;
                }
            }

            memcpy(path_node, &root_buf[32U + t * p->lambda], (size_t)p->lambda);
            for (lvl = 0U; lvl < dt; lvl++) {
                uint32_t parent_idx = delta_t >> (dt - lvl);
                uint32_t bit = (delta_t >> (dt - 1U - lvl)) & 1U;
                pq_faest_expand_node(p->lambda, salt, t, lvl, parent_idx, path_node, c0, c1);
                if (bit == 0U) {
                    memcpy(&sig_out[off], c1, (size_t)p->lambda);
                    memcpy(path_node, c0, (size_t)p->lambda);
                } else {
                    memcpy(&sig_out[off], c0, (size_t)p->lambda);
                    memcpy(path_node, c1, (size_t)p->lambda);
                }
                off += (size_t)p->lambda;
            }

            if (t < p->tau - 1U) {
                pq_faest_expand_leaf(
                    p->lambda, p->l_ext, salt, t, delta_t, path_node,
                    NULL, &sig_out[com_off + (size_t)t * (size_t)p->lambda]);
            } else {
                memcpy(&sig_out[com_off + (size_t)t * (size_t)p->lambda], delta, (size_t)p->lambda);
            }
            bit_off += dt;
        }
        areion_pq_secure_wipe(path_node, sizeof(path_node));
        areion_pq_secure_wipe(c0, sizeof(c0));
        areion_pq_secure_wipe(c1, sizeof(c1));
    }

    end_off = com_off + (size_t)p->tau * (size_t)p->lambda;
    if (end_off < p->sig_size) {
        pq_kdf_expand_body(
            &sig_out[end_off], p->sig_size - end_off,
            delta, (size_t)p->lambda,
            salt, 32U);
    }

    areion_pq_secure_wipe(k32, sizeof(k32));
    areion_pq_secure_wipe(p_seed, sizeof(p_seed));
    areion_pq_secure_wipe(c_pub, sizeof(c_pub));
    areion_pq_secure_wipe(pk_bytes, sizeof(pk_bytes));
    areion_pq_secure_wipe(t_pub, sizeof(t_pub));
    areion_pq_secure_wipe(m_pub, sizeof(m_pub));
    areion_pq_secure_wipe(k2, sizeof(k2));
    areion_pq_secure_wipe(c_unused, sizeof(c_unused));
    areion_pq_secure_wipe(w_full, sizeof(w_full));
    areion_pq_secure_wipe(opt_local, sizeof(opt_local));
    areion_pq_secure_wipe(root_buf, sizeof(root_buf));
    areion_pq_secure_wipe(salt, sizeof(salt));
    areion_pq_secure_wipe(u0, sizeof(u0));
    areion_pq_secure_wipe(c_trees, sizeof(c_trees));
    areion_pq_secure_wipe(q_rows, sizeof(q_rows));
    areion_pq_secure_wipe(h_trees, sizeof(h_trees));
    areion_pq_secure_wipe(cur_nodes, sizeof(cur_nodes));
    areion_pq_secure_wipe(next_nodes, sizeof(next_nodes));
    areion_pq_secure_wipe(com_concat, sizeof(com_concat));
    areion_pq_secure_wipe(row_j, sizeof(row_j));
    areion_pq_secure_wipe(ut, sizeof(ut));
    areion_pq_secure_wipe(d_ext, sizeof(d_ext));
    areion_pq_secure_wipe(chi, sizeof(chi));
    areion_pq_secure_wipe(bit_tags, sizeof(bit_tags));
    areion_pq_secure_wipe(qs_u, sizeof(qs_u));
    areion_pq_secure_wipe(w_poly, sizeof(w_poly));
    areion_pq_secure_wipe(delta_in, sizeof(delta_in));
    areion_pq_secure_wipe(delta, sizeof(delta));
    areion_pq_secure_wipe(seed_iov, sizeof(seed_iov));
    areion_pq_secure_wipe(fs_iov, sizeof(fs_iov));
}

static void pq_faest_sign_core(
    const pq_faest_params_t *p, uint8_t *sig_out,
    const uint8_t *sk, size_t sk_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *opt_rand) {
    pq_faest_sign_core_body(p, sig_out, sk, sk_len, msg, msg_len, opt_rand);
    areion_pq_wipe_software_stack();
    areion_pq_clobber_scratch_gprs();
}

static AREION_PQ_NOINLINE int pq_faest_verify_core_body(
    const pq_faest_params_t *p,
    const uint8_t *pk, size_t pk_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *sig) {
    uint8_t p_seed[32], c_pub[32], t_pub[32], m_pub[32], salt[32];
    const uint8_t *d_ext, *d_witness, *qs_u, *delta_sig;
    size_t c_off, sib_off, com_off, cur_sib_off, end_off;
    uint8_t v_rows[256][640], h_trees[32][32];
    uint8_t cur_nodes[1024 * 32], next_nodes[1024 * 32], com_concat[1024 * 32], row_j[640];
    uint8_t chi[16], w_verif[32], delta_in[80], delta_prime[32];
    uint8_t bit_tags[8 * 640][16];
    pq_iov_t fs_iov[6];
    uint32_t bit_off, t, lvl, idx, j, b, num_lanes, lane, k, i;
    int ok;

    if (p->k_bytes == 16U) {
        pq_pad32(p_seed, &pk[0], 16U);
        memcpy(c_pub, &pk[16], 32U);
    } else {
        memcpy(p_seed, &pk[0], 32U);
        memcpy(c_pub, &pk[32], 32U);
    }
    pq_faest_derive_tm(t_pub, m_pub, p_seed);

    memcpy(salt, &sig[0], 32U);
    d_ext = &sig[32];
    d_witness = &d_ext[0];
    qs_u = &d_ext[p->l_bytes];

    c_off = 32U + (size_t)p->l_ext;
    sib_off = c_off + (size_t)(p->tau - 1U) * (size_t)p->l_ext;
    com_off = sib_off + (size_t)(8U * p->lambda) * (size_t)p->lambda;
    delta_sig = &sig[com_off + (size_t)(p->tau - 1U) * (size_t)p->lambda];

    memset(v_rows, 0, sizeof(v_rows));
    memset(h_trees, 0, sizeof(h_trees));
    cur_sib_off = sib_off;
    bit_off = 0U;

    for (t = 0U; t < p->tau; t++) {
        uint32_t dt = p->depths[t];
        uint32_t nt = 1U << dt;
        uint32_t delta_t = 0U;

        for (b = 0U; b < dt; b++) {
            uint32_t g_bit = bit_off + b;
            if ((((uint32_t)delta_sig[g_bit >> 3U] >> (g_bit & 7U)) & 1U) != 0U) {
                delta_t |= 1U << b;
            }
        }

        for (lvl = 0U; lvl < dt; lvl++) {
            uint32_t num_nodes = 1U << lvl;
            uint32_t missing_parent = delta_t >> (dt - lvl);
            uint32_t prefix = delta_t >> (dt - 1U - lvl);
            uint32_t sib_idx = prefix ^ 1U;

            for (idx = 0U; idx < num_nodes; idx++) {
                if (idx == missing_parent) {
                    continue;
                }
                pq_faest_expand_node(
                    p->lambda, salt, t, lvl, idx,
                    &cur_nodes[(size_t)idx * (size_t)p->lambda],
                    &next_nodes[(size_t)(2U * idx) * (size_t)p->lambda],
                    &next_nodes[(size_t)(2U * idx + 1U) * (size_t)p->lambda]);
            }
            memcpy(
                &next_nodes[(size_t)sib_idx * (size_t)p->lambda],
                &sig[cur_sib_off], (size_t)p->lambda);
            cur_sib_off += (size_t)p->lambda;
            memcpy(cur_nodes, next_nodes, (size_t)(2U * num_nodes) * (size_t)p->lambda);
        }

        for (j = 0U; j < nt; j++) {
            uint32_t diff;
            if (j == delta_t) {
                if (t < p->tau - 1U) {
                    memcpy(
                        &com_concat[(size_t)j * (size_t)p->lambda],
                        &sig[com_off + (size_t)t * (size_t)p->lambda],
                        (size_t)p->lambda);
                }
                continue;
            }
            pq_faest_expand_leaf(
                p->lambda, p->l_ext, salt, t, j,
                &cur_nodes[(size_t)j * (size_t)p->lambda],
                row_j, &com_concat[(size_t)j * (size_t)p->lambda]);
            diff = j ^ delta_t;
            for (b = 0U; b < dt; b++) {
                if (((diff >> b) & 1U) != 0U) {
                    areion_pq_dispatch_vole_xor_row_nowipe(v_rows[bit_off + b], row_j, (size_t)p->l_ext);
                }
            }
        }

        for (b = 0U; b < dt; b++) {
            if (((delta_t >> b) & 1U) != 0U) {
                if (t > 0U) {
                    const uint8_t *ct = &sig[c_off + (size_t)(t - 1U) * (size_t)p->l_ext];
                    areion_pq_dispatch_vole_xor_row_nowipe(v_rows[bit_off + b], ct, (size_t)p->l_ext);
                }
                areion_pq_dispatch_vole_xor_row_nowipe(v_rows[bit_off + b], d_ext, (size_t)p->l_ext);
            }
        }

        if (t < p->tau - 1U) {
            pq_kdf_expand_body(
                h_trees[t], 32U,
                com_concat, (size_t)nt * (size_t)p->lambda,
                salt, 32U);
        }
        bit_off += dt;
    }

    fs_iov[0].ptr = pk;
    fs_iov[0].len = pk_len;
    fs_iov[1].ptr = msg;
    fs_iov[1].len = msg_len;
    fs_iov[2].ptr = salt;
    fs_iov[2].len = 32U;
    fs_iov[3].ptr = &h_trees[0][0];
    fs_iov[3].len = (size_t)(p->tau - 1U) * 32U;
    fs_iov[4].ptr = d_witness;
    fs_iov[4].len = (size_t)p->l_bytes;
    fs_iov[5].ptr = &sig[c_off];
    fs_iov[5].len = sib_off - c_off;
    pq_kdf_expand_iov(
        fs_iov, 6U,
        (const uint8_t *)"FAEST-FS-CHI", 12U,
        chi, 16U);
    chi[0] |= 0x01U;

    num_lanes = p->lambda / 16U;
    memset(w_verif, 0, sizeof(w_verif));

    for (lane = 0U; lane < num_lanes; lane++) {
        uint8_t delta_lane[16], a1_unused[16], bv_acc[16], v_mask[16];
        memset(bit_tags, 0, (size_t)(8U * p->l_ext) * 16U);
        for (k = 0U; k < 128U; k++) {
            const uint8_t *row = v_rows[128U * lane + k];
            uint32_t k_byte = k >> 3U;
            uint32_t k_bit = k & 7U;
            for (i = 0U; i < p->l_ext; i++) {
                uint32_t rb = (uint32_t)row[i];
                uint32_t base = i << 3U;
                bit_tags[base + 0U][k_byte] |= (uint8_t)((rb & 1U) << k_bit);
                bit_tags[base + 1U][k_byte] |= (uint8_t)(((rb >> 1U) & 1U) << k_bit);
                bit_tags[base + 2U][k_byte] |= (uint8_t)(((rb >> 2U) & 1U) << k_bit);
                bit_tags[base + 3U][k_byte] |= (uint8_t)(((rb >> 3U) & 1U) << k_bit);
                bit_tags[base + 4U][k_byte] |= (uint8_t)(((rb >> 4U) & 1U) << k_bit);
                bit_tags[base + 5U][k_byte] |= (uint8_t)(((rb >> 5U) & 1U) << k_bit);
                bit_tags[base + 6U][k_byte] |= (uint8_t)(((rb >> 6U) & 1U) << k_bit);
                bit_tags[base + 7U][k_byte] |= (uint8_t)(((rb >> 7U) & 1U) << k_bit);
            }
        }
        memcpy(delta_lane, &delta_sig[16U * (size_t)lane], 16U);
        pq_faest_eval_quicksilver_lane(
            p, m_pub, t_pub, c_pub, NULL,
            (const uint8_t (*)[16])bit_tags, 1, delta_lane, chi, a1_unused, bv_acc);
        pq_faest_fold_mask128(v_mask, (const uint8_t (*)[16])bit_tags, 8U * p->l_bytes + 128U * lane);
        for (i = 0U; i < 16U; i++) {
            w_verif[16U * lane + i] = (uint8_t)(bv_acc[i] ^ v_mask[i]);
        }
    }

    memcpy(&delta_in[0], chi, 16U);
    memcpy(&delta_in[16], qs_u, (size_t)p->lambda);
    memcpy(&delta_in[16U + p->lambda], w_verif, (size_t)p->lambda);
    pq_kdf_expand_body(
        delta_prime, (size_t)p->lambda,
        delta_in, 16U + 2U * (size_t)p->lambda,
        salt, 32U);

    ok = areion_pq_ct_eq(delta_sig, delta_prime, (size_t)p->lambda);
    end_off = com_off + (size_t)p->tau * (size_t)p->lambda;
    if (end_off < p->sig_size) {
        uint8_t expected_tail[640];
        size_t tail_len = p->sig_size - end_off;
        pq_kdf_expand_body(
            expected_tail, tail_len,
            delta_prime, (size_t)p->lambda,
            salt, 32U);
        if (areion_pq_ct_eq(&sig[end_off], expected_tail, tail_len) == 0) {
            ok = 0;
        }
    }

    return ok;
}

static int pq_faest_verify_core(
    const pq_faest_params_t *p,
    const uint8_t *pk, size_t pk_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *sig) {
    int ok = pq_faest_verify_core_body(p, pk, pk_len, msg, msg_len, sig);
    areion_pq_wipe_software_stack();
    areion_pq_clobber_scratch_gprs();
    return ok;
}

void areion_pq_faest_keygen128s(
    uint8_t pk[AREION_PQ_FAEST128_PK_SIZE],
    uint8_t sk[AREION_PQ_FAEST128_SK_SIZE],
    const uint8_t seed[AREION_PQ_FAEST128_SEED_SIZE]) {
    pq_faest_keygen128_core(pk, sk, seed);
}

void areion_pq_faest_sign128s(
    uint8_t sig[AREION_PQ_FAEST128S_SIG_SIZE],
    const uint8_t sk[AREION_PQ_FAEST128_SK_SIZE],
    const uint8_t *msg, size_t msg_len,
    const uint8_t opt_rand[16]) {
    pq_faest_sign_core(&pq_faest_params_128s, sig, sk, AREION_PQ_FAEST128_SK_SIZE, msg, msg_len, opt_rand);
}

int areion_pq_faest_verify128s(
    const uint8_t pk[AREION_PQ_FAEST128_PK_SIZE],
    const uint8_t *msg, size_t msg_len,
    const uint8_t sig[AREION_PQ_FAEST128S_SIG_SIZE]) {
    return pq_faest_verify_core(&pq_faest_params_128s, pk, AREION_PQ_FAEST128_PK_SIZE, msg, msg_len, sig);
}

void areion_pq_faest_keygen128f(
    uint8_t pk[AREION_PQ_FAEST128_PK_SIZE],
    uint8_t sk[AREION_PQ_FAEST128_SK_SIZE],
    const uint8_t seed[AREION_PQ_FAEST128_SEED_SIZE]) {
    pq_faest_keygen128_core(pk, sk, seed);
}

void areion_pq_faest_sign128f(
    uint8_t sig[AREION_PQ_FAEST128F_SIG_SIZE],
    const uint8_t sk[AREION_PQ_FAEST128_SK_SIZE],
    const uint8_t *msg, size_t msg_len,
    const uint8_t opt_rand[16]) {
    pq_faest_sign_core(&pq_faest_params_128f, sig, sk, AREION_PQ_FAEST128_SK_SIZE, msg, msg_len, opt_rand);
}

int areion_pq_faest_verify128f(
    const uint8_t pk[AREION_PQ_FAEST128_PK_SIZE],
    const uint8_t *msg, size_t msg_len,
    const uint8_t sig[AREION_PQ_FAEST128F_SIG_SIZE]) {
    return pq_faest_verify_core(&pq_faest_params_128f, pk, AREION_PQ_FAEST128_PK_SIZE, msg, msg_len, sig);
}

void areion_pq_faest_keygen256s(
    uint8_t pk[AREION_PQ_FAEST256_PK_SIZE],
    uint8_t sk[AREION_PQ_FAEST256_SK_SIZE],
    const uint8_t seed[AREION_PQ_FAEST256_SEED_SIZE]) {
    pq_faest_keygen256_core(pk, sk, seed, 0);
}

void areion_pq_faest_sign256s(
    uint8_t sig[AREION_PQ_FAEST256S_SIG_SIZE],
    const uint8_t sk[AREION_PQ_FAEST256_SK_SIZE],
    const uint8_t *msg, size_t msg_len,
    const uint8_t opt_rand[32]) {
    pq_faest_sign_core(&pq_faest_params_256s, sig, sk, AREION_PQ_FAEST256_SK_SIZE, msg, msg_len, opt_rand);
}

int areion_pq_faest_verify256s(
    const uint8_t pk[AREION_PQ_FAEST256_PK_SIZE],
    const uint8_t *msg, size_t msg_len,
    const uint8_t sig[AREION_PQ_FAEST256S_SIG_SIZE]) {
    return pq_faest_verify_core(&pq_faest_params_256s, pk, AREION_PQ_FAEST256_PK_SIZE, msg, msg_len, sig);
}

void areion_pq_faest_keygen256f(
    uint8_t pk[AREION_PQ_FAEST256_PK_SIZE],
    uint8_t sk[AREION_PQ_FAEST256_SK_SIZE],
    const uint8_t seed[AREION_PQ_FAEST256_SEED_SIZE]) {
    pq_faest_keygen256_core(pk, sk, seed, 0);
}

void areion_pq_faest_sign256f(
    uint8_t sig[AREION_PQ_FAEST256F_SIG_SIZE],
    const uint8_t sk[AREION_PQ_FAEST256_SK_SIZE],
    const uint8_t *msg, size_t msg_len,
    const uint8_t opt_rand[32]) {
    pq_faest_sign_core(&pq_faest_params_256f, sig, sk, AREION_PQ_FAEST256_SK_SIZE, msg, msg_len, opt_rand);
}

int areion_pq_faest_verify256f(
    const uint8_t pk[AREION_PQ_FAEST256_PK_SIZE],
    const uint8_t *msg, size_t msg_len,
    const uint8_t sig[AREION_PQ_FAEST256F_SIG_SIZE]) {
    return pq_faest_verify_core(&pq_faest_params_256f, pk, AREION_PQ_FAEST256_PK_SIZE, msg, msg_len, sig);
}

void areion_pq_faest_em2_keygen256s(
    uint8_t pk[AREION_PQ_FAEST_EM2_256_PK_SIZE],
    uint8_t sk[AREION_PQ_FAEST_EM2_256_SK_SIZE],
    const uint8_t seed[AREION_PQ_FAEST_EM2_256_SEED_SIZE]) {
    pq_faest_keygen256_core(pk, sk, seed, 1);
}

void areion_pq_faest_em2_sign256s(
    uint8_t sig[AREION_PQ_FAEST_EM2_256S_SIG_SIZE],
    const uint8_t sk[AREION_PQ_FAEST_EM2_256_SK_SIZE],
    const uint8_t *msg, size_t msg_len,
    const uint8_t opt_rand[32]) {
    pq_faest_sign_core(&pq_faest_params_em2_256s, sig, sk, AREION_PQ_FAEST_EM2_256_SK_SIZE, msg, msg_len, opt_rand);
}

int areion_pq_faest_em2_verify256s(
    const uint8_t pk[AREION_PQ_FAEST_EM2_256_PK_SIZE],
    const uint8_t *msg, size_t msg_len,
    const uint8_t sig[AREION_PQ_FAEST_EM2_256S_SIG_SIZE]) {
    return pq_faest_verify_core(&pq_faest_params_em2_256s, pk, AREION_PQ_FAEST_EM2_256_PK_SIZE, msg, msg_len, sig);
}

void areion_pq_faest_em2_keygen256f(
    uint8_t pk[AREION_PQ_FAEST_EM2_256_PK_SIZE],
    uint8_t sk[AREION_PQ_FAEST_EM2_256_SK_SIZE],
    const uint8_t seed[AREION_PQ_FAEST_EM2_256_SEED_SIZE]) {
    pq_faest_keygen256_core(pk, sk, seed, 1);
}

void areion_pq_faest_em2_sign256f(
    uint8_t sig[AREION_PQ_FAEST_EM2_256F_SIG_SIZE],
    const uint8_t sk[AREION_PQ_FAEST_EM2_256_SK_SIZE],
    const uint8_t *msg, size_t msg_len,
    const uint8_t opt_rand[32]) {
    pq_faest_sign_core(&pq_faest_params_em2_256f, sig, sk, AREION_PQ_FAEST_EM2_256_SK_SIZE, msg, msg_len, opt_rand);
}

int areion_pq_faest_em2_verify256f(
    const uint8_t pk[AREION_PQ_FAEST_EM2_256_PK_SIZE],
    const uint8_t *msg, size_t msg_len,
    const uint8_t sig[AREION_PQ_FAEST_EM2_256F_SIG_SIZE]) {
    return pq_faest_verify_core(&pq_faest_params_em2_256f, pk, AREION_PQ_FAEST_EM2_256_PK_SIZE, msg, msg_len, sig);
}
