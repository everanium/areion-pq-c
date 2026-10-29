/*
 * Copyright (c) 2026 Andrey Kuvshinov
 *
 * Dual-licensed under Apache-2.0 OR MIT.
 * See LICENSE-APACHE and LICENSE-MIT for details.
 */

#ifndef AREION_PQ_INTERNAL_H
#define AREION_PQ_INTERNAL_H

#include "areion_pq.h"
#include <string.h>

#ifndef __has_attribute
#define __has_attribute(x) 0
#endif

#ifndef __has_feature
#define __has_feature(x) 0
#endif

#if __has_feature(memory_sanitizer)
#include <sanitizer/msan_interface.h>
#define AREION_PQ_MSAN_UNPOISON(p, n) __msan_unpoison((p), (n))
#else
#define AREION_PQ_MSAN_UNPOISON(p, n) ((void)(p), (void)(n))
#endif

#if defined(_MSC_VER)
#include <intrin.h>
#ifndef InterlockedCompareExchange
#define InterlockedCompareExchange _InterlockedCompareExchange
#endif
#define AREION_PQ_ALIGN64 __declspec(align(64))
#define AREION_PQ_NOINLINE __declspec(noinline)
#define AREION_PQ_NO_STACK_PROTECTOR __declspec(safebuffers)
#define AREION_PQ_INTERNAL
#elif defined(__clang__)
#define AREION_PQ_ALIGN64 __attribute__((aligned(64)))
#if __has_attribute(noipa)
#define AREION_PQ_NOINLINE __attribute__((noinline, noipa))
#else
#define AREION_PQ_NOINLINE __attribute__((noinline))
#endif
#if __has_attribute(no_stack_protector)
#define AREION_PQ_NO_STACK_PROTECTOR __attribute__((no_stack_protector))
#else
#define AREION_PQ_NO_STACK_PROTECTOR
#endif
#if defined(__ELF__)
#define AREION_PQ_INTERNAL __attribute__((visibility("hidden")))
#else
#define AREION_PQ_INTERNAL
#endif
#elif defined(__GNUC__)
#define AREION_PQ_ALIGN64 __attribute__((aligned(64)))
#if __GNUC__ >= 8
#define AREION_PQ_NOINLINE __attribute__((noinline, noipa))
#define AREION_PQ_NO_STACK_PROTECTOR __attribute__((no_stack_protector))
#else
#define AREION_PQ_NOINLINE __attribute__((noinline, noclone))
#define AREION_PQ_NO_STACK_PROTECTOR
#endif
#if defined(__ELF__)
#define AREION_PQ_INTERNAL __attribute__((visibility("hidden")))
#else
#define AREION_PQ_INTERNAL
#endif
#else
#define AREION_PQ_ALIGN64
#define AREION_PQ_NOINLINE
#define AREION_PQ_NO_STACK_PROTECTOR
#define AREION_PQ_INTERNAL
#endif

/* Prevents interprocedural argument promotion of const pointer parameters. */
#if defined(__GNUC__) || defined(__clang__)
#define AREION_PQ_OPAQUE_PTR(p) __asm__ __volatile__("" : : "r"(p) : "memory")
#else
#define AREION_PQ_OPAQUE_PTR(p) ((void)(p))
#endif

/* Compiler memory barrier to prevent dead-store elimination and reordering. */
static inline void areion_pq_compiler_barrier(void) {
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : : "memory");
#elif defined(_MSC_VER)
    _ReadWriteBarrier();
#endif
}

/* DSE-resistant buffer zeroization. */
static inline void areion_pq_secure_wipe(void *ptr, size_t len) {
    if (ptr == NULL || len == 0U) {
        return;
    }
#if defined(__GNUC__) || defined(__clang__)
    memset(ptr, 0, len);
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
#else
    {
        volatile uint8_t *p = (volatile uint8_t *)ptr;
        size_t i;
        for (i = 0; i < len; i++) {
            p[i] = 0;
        }
    }
#if defined(_MSC_VER)
    _ReadWriteBarrier();
#endif
#endif
}

/* Constant-time byte array equality check (returns 1 if equal, 0 otherwise). */
static inline int areion_pq_ct_eq(const uint8_t *a, const uint8_t *b, size_t len) {
    uint32_t diff = 0U;
    size_t i;
    for (i = 0; i < len; i++) {
        diff |= (uint32_t)(a[i] ^ b[i]);
    }
    return (int)(1U & ((diff - 1U) >> 31U));
}

#ifndef AREION_PQ_IS_LITTLE_ENDIAN
#if (defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)) || \
    defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86) || \
    defined(__aarch64__) || defined(_M_ARM64) || defined(__ARMEL__) || defined(__riscv)
#define AREION_PQ_IS_LITTLE_ENDIAN 1
#else
#define AREION_PQ_IS_LITTLE_ENDIAN 0
#endif
#endif

static inline uint32_t areion_pq_load_le32(const uint8_t *p) {
#if AREION_PQ_IS_LITTLE_ENDIAN
    uint32_t v;
#if defined(__GNUC__) || defined(__clang__)
    __builtin_memcpy(&v, p, sizeof(v));
#else
    memcpy(&v, p, sizeof(v));
#endif
    return v;
#else
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] << 8U) |
           ((uint32_t)p[2] << 16U) |
           ((uint32_t)p[3] << 24U);
#endif
}

static inline void areion_pq_store_le32(uint8_t *p, uint32_t v) {
#if AREION_PQ_IS_LITTLE_ENDIAN
#if defined(__GNUC__) || defined(__clang__)
    __builtin_memcpy(p, &v, sizeof(v));
#else
    memcpy(p, &v, sizeof(v));
#endif
#else
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8U);
    p[2] = (uint8_t)(v >> 16U);
    p[3] = (uint8_t)(v >> 24U);
#endif
}

static inline uint64_t areion_pq_load_le64(const uint8_t *p) {
#if AREION_PQ_IS_LITTLE_ENDIAN
    uint64_t v;
#if defined(__GNUC__) || defined(__clang__)
    __builtin_memcpy(&v, p, sizeof(v));
#else
    memcpy(&v, p, sizeof(v));
#endif
    return v;
#else
    return ((uint64_t)p[0]) |
           ((uint64_t)p[1] << 8U) |
           ((uint64_t)p[2] << 16U) |
           ((uint64_t)p[3] << 24U) |
           ((uint64_t)p[4] << 32U) |
           ((uint64_t)p[5] << 40U) |
           ((uint64_t)p[6] << 48U) |
           ((uint64_t)p[7] << 56U);
#endif
}

static inline void areion_pq_store_le64(uint8_t *p, uint64_t v) {
#if AREION_PQ_IS_LITTLE_ENDIAN
#if defined(__GNUC__) || defined(__clang__)
    __builtin_memcpy(p, &v, sizeof(v));
#else
    memcpy(p, &v, sizeof(v));
#endif
#else
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8U);
    p[2] = (uint8_t)(v >> 16U);
    p[3] = (uint8_t)(v >> 24U);
    p[4] = (uint8_t)(v >> 32U);
    p[5] = (uint8_t)(v >> 40U);
    p[6] = (uint8_t)(v >> 48U);
    p[7] = (uint8_t)(v >> 56U);
#endif
}

static inline uint32_t areion_pq_load_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24U) |
           ((uint32_t)p[1] << 16U) |
           ((uint32_t)p[2] << 8U) |
           ((uint32_t)p[3]);
}

static inline void areion_pq_store_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24U);
    p[1] = (uint8_t)(v >> 16U);
    p[2] = (uint8_t)(v >> 8U);
    p[3] = (uint8_t)(v);
}

static inline uint64_t areion_pq_load_be64(const uint8_t *p) {
    return ((uint64_t)p[0] << 56U) |
           ((uint64_t)p[1] << 48U) |
           ((uint64_t)p[2] << 40U) |
           ((uint64_t)p[3] << 32U) |
           ((uint64_t)p[4] << 24U) |
           ((uint64_t)p[5] << 16U) |
           ((uint64_t)p[6] << 8U) |
           ((uint64_t)p[7]);
}

static inline void areion_pq_store_be64(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v >> 56U);
    p[1] = (uint8_t)(v >> 48U);
    p[2] = (uint8_t)(v >> 40U);
    p[3] = (uint8_t)(v >> 32U);
    p[4] = (uint8_t)(v >> 24U);
    p[5] = (uint8_t)(v >> 16U);
    p[6] = (uint8_t)(v >> 8U);
    p[7] = (uint8_t)(v);
}

/* =========================================================================
 * Internal Constants (constants.c)
 * ========================================================================= */

extern AREION_PQ_ALIGN64 const uint8_t areion_pq_rc_p1[15][16] AREION_PQ_INTERNAL;
extern AREION_PQ_ALIGN64 const uint8_t areion_pq_rc_p2[15][16] AREION_PQ_INTERNAL;
extern const uint8_t areion_pq_aes_sbox[256] AREION_PQ_INTERNAL;

/* =========================================================================
 * CPU Detection (cpu.c, cpu_amd64.c, cpu_arm64.c, cpu_other.c)
 * ========================================================================= */

AREION_PQ_INTERNAL areion_pq_tier_t areion_pq_detect_hardware_tier(void);
AREION_PQ_INTERNAL bool areion_pq_check_tier_supported(areion_pq_tier_t tier);
AREION_PQ_INTERNAL bool areion_pq_detect_pclmul(void);
AREION_PQ_INTERNAL bool areion_pq_detect_vpclmul(void);
AREION_PQ_INTERNAL bool areion_pq_detect_pmull(void);

#if defined(_MSC_VER)
extern volatile long areion_pq_g_active_tier;
extern volatile long areion_pq_g_has_pclmul;
extern volatile long areion_pq_g_has_vpclmul;
extern volatile long areion_pq_g_has_pmull;
#elif defined(__GNUC__) || defined(__clang__)
extern int areion_pq_g_active_tier AREION_PQ_INTERNAL;
extern int areion_pq_g_has_pclmul AREION_PQ_INTERNAL;
extern int areion_pq_g_has_vpclmul AREION_PQ_INTERNAL;
extern int areion_pq_g_has_pmull AREION_PQ_INTERNAL;
#else
extern volatile int areion_pq_g_active_tier;
extern volatile int areion_pq_g_has_pclmul;
extern volatile int areion_pq_g_has_vpclmul;
extern volatile int areion_pq_g_has_pmull;
#endif

static inline areion_pq_tier_t areion_pq_active_tier(void) {
#if defined(_MSC_VER)
    return (areion_pq_tier_t)InterlockedCompareExchange((volatile long *)&areion_pq_g_active_tier, 0, 0);
#elif defined(__GNUC__) || defined(__clang__)
    return (areion_pq_tier_t)__atomic_load_n(&areion_pq_g_active_tier, __ATOMIC_ACQUIRE);
#else
    return areion_pq_tier_code();
#endif
}

static inline bool areion_pq_has_pclmul(void) {
#if defined(_MSC_VER)
    return InterlockedCompareExchange((volatile long *)&areion_pq_g_has_pclmul, 0, 0) != 0;
#elif defined(__GNUC__) || defined(__clang__)
    return __atomic_load_n(&areion_pq_g_has_pclmul, __ATOMIC_ACQUIRE) != 0;
#else
    return areion_pq_detect_pclmul();
#endif
}

static inline bool areion_pq_has_vpclmul(void) {
#if defined(_MSC_VER)
    return InterlockedCompareExchange((volatile long *)&areion_pq_g_has_vpclmul, 0, 0) != 0;
#elif defined(__GNUC__) || defined(__clang__)
    return __atomic_load_n(&areion_pq_g_has_vpclmul, __ATOMIC_ACQUIRE) != 0;
#else
    return areion_pq_detect_vpclmul();
#endif
}

static inline bool areion_pq_has_pmull(void) {
#if defined(_MSC_VER)
    return InterlockedCompareExchange((volatile long *)&areion_pq_g_has_pmull, 0, 0) != 0;
#elif defined(__GNUC__) || defined(__clang__)
    return __atomic_load_n(&areion_pq_g_has_pmull, __ATOMIC_ACQUIRE) != 0;
#else
    return areion_pq_detect_pmull();
#endif
}

/* =========================================================================
 * Scratch Register & Zeroization Helpers
 * ========================================================================= */

#if !defined(AREION_PQ_FORCE_PORTABLE) && !defined(AREION_FORCE_PORTABLE) && \
    (defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__) || defined(_M_ARM64))
extern void areion_pq_clobber_scratch_gprs_asm(void) AREION_PQ_INTERNAL;
extern void areion_pq_dump_simd_regs(uint64_t *dst, int has_avx512) AREION_PQ_INTERNAL;
extern void areion_pq_dirty_simd_reg_for_test(uint64_t masked) AREION_PQ_INTERNAL;

static inline void areion_pq_clobber_scratch_gprs(void) {
#if (defined(__GNUC__) || defined(__clang__)) && (defined(__x86_64__) || defined(_M_X64))
    if (areion_pq_active_tier() == AREION_PQ_TIER_AVX512) {
        __asm__ __volatile__(
            "vpxord %%zmm16, %%zmm16, %%zmm16\n\t"
            "vpxord %%zmm17, %%zmm17, %%zmm17\n\t"
            "vpxord %%zmm18, %%zmm18, %%zmm18\n\t"
            "vpxord %%zmm19, %%zmm19, %%zmm19\n\t"
            "vpxord %%zmm20, %%zmm20, %%zmm20\n\t"
            "vpxord %%zmm21, %%zmm21, %%zmm21\n\t"
            "vpxord %%zmm22, %%zmm22, %%zmm22\n\t"
            "vpxord %%zmm23, %%zmm23, %%zmm23\n\t"
            "vpxord %%zmm24, %%zmm24, %%zmm24\n\t"
            "vpxord %%zmm25, %%zmm25, %%zmm25\n\t"
            "vpxord %%zmm26, %%zmm26, %%zmm26\n\t"
            "vpxord %%zmm27, %%zmm27, %%zmm27\n\t"
            "vpxord %%zmm28, %%zmm28, %%zmm28\n\t"
            "vpxord %%zmm29, %%zmm29, %%zmm29\n\t"
            "vpxord %%zmm30, %%zmm30, %%zmm30\n\t"
            "vpxord %%zmm31, %%zmm31, %%zmm31\n\t"
            "vzeroupper"
            : : : "memory");
    }
#endif
    areion_pq_clobber_scratch_gprs_asm();
}
#else
static inline void areion_pq_clobber_scratch_gprs(void) {
    areion_pq_compiler_barrier();
}
#endif

/* =========================================================================
 * Pure-C Software Entry Points (areion_pq_purec.c)
 * ========================================================================= */

AREION_PQ_INTERNAL void areion_pq_extract_witness256_purec(
    uint8_t c[32], uint8_t w[288],
    const uint8_t m[32], const uint8_t k1[32], const uint8_t k2[32],
    const uint8_t rc[10][16]);

AREION_PQ_INTERNAL void areion_pq_gf128_mul_core(
    uint8_t out[16], const uint8_t a[16], const uint8_t b[16]);

AREION_PQ_INTERNAL void areion_pq_gf128_mul_purec(
    uint8_t out[16], const uint8_t a[16], const uint8_t b[16]);

AREION_PQ_INTERNAL void areion_pq_gf128_polymac_purec(
    uint8_t acc[16], const uint8_t *a, const uint8_t *b, size_t count, const uint8_t chi[16]);

AREION_PQ_INTERNAL void areion_pq_vole_xor_row_core(
    uint8_t *dst, const uint8_t *src, size_t len);

AREION_PQ_INTERNAL void areion_pq_vole_xor_row_purec(
    uint8_t *dst, const uint8_t *src, size_t len);

AREION_PQ_INTERNAL void areion_pq_wots_chain256x4_purec(
    uint8_t out[4][32], const uint8_t in[4][32], const uint8_t adrs[4][32],
    const uint8_t kpub1[32], const uint8_t kpub2[32],
    uint32_t start_step, uint32_t steps);

/* =========================================================================
 * Dispatched Hardware/Software Hooks (areion_pq_{amd64,arm64,other}.c)
 * ========================================================================= */

AREION_PQ_INTERNAL int areion_pq_has_hw_extract_witness256(void);

AREION_PQ_INTERNAL void areion_pq_dispatch_extract_witness256(
    uint8_t c[32], uint8_t w[288],
    const uint8_t m[32], const uint8_t k1[32], const uint8_t k2[32],
    const uint8_t rc[10][16]);

AREION_PQ_INTERNAL void areion_pq_dispatch_gf128_mul(
    uint8_t out[16], const uint8_t a[16], const uint8_t b[16]);

AREION_PQ_INTERNAL void areion_pq_dispatch_gf128_mul_nowipe(
    uint8_t out[16], const uint8_t a[16], const uint8_t b[16]);

AREION_PQ_INTERNAL void areion_pq_dispatch_gf128_polymac(
    uint8_t acc[16], const uint8_t *a, const uint8_t *b, size_t count, const uint8_t chi[16]);

AREION_PQ_INTERNAL void areion_pq_dispatch_vole_xor_row(
    uint8_t *dst, const uint8_t *src, size_t len);

AREION_PQ_INTERNAL void areion_pq_dispatch_vole_xor_row_nowipe(
    uint8_t *dst, const uint8_t *src, size_t len);

AREION_PQ_INTERNAL void areion_pq_dispatch_wots_chain256x4(
    uint8_t out[4][32], const uint8_t in[4][32], const uint8_t adrs[4][32],
    const uint8_t kpub1[32], const uint8_t kpub2[32],
    uint32_t start_step, uint32_t steps);

/* =========================================================================
 * Architecture-Specific Assembly Kernels (areion_pq_{amd64,arm64}.S)
 * ========================================================================= */

#if (defined(__x86_64__) || defined(_M_X64)) && !defined(AREION_PQ_FORCE_PORTABLE) && !defined(AREION_FORCE_PORTABLE)
extern void areion_pq_extract_witness256_aesni(
    uint8_t c[32], uint8_t w[288],
    const uint8_t m[32], const uint8_t k1[32], const uint8_t k2[32],
    const uint8_t rc[10][16]) AREION_PQ_INTERNAL;
extern void areion_pq_extract_witness256_vex(
    uint8_t c[32], uint8_t w[288],
    const uint8_t m[32], const uint8_t k1[32], const uint8_t k2[32],
    const uint8_t rc[10][16]) AREION_PQ_INTERNAL;

extern void areion_pq_gf128_mul_pclmul(
    uint8_t out[16], const uint8_t a[16], const uint8_t b[16]) AREION_PQ_INTERNAL;
extern void areion_pq_gf128_mul_vpclmul(
    uint8_t out[16], const uint8_t a[16], const uint8_t b[16]) AREION_PQ_INTERNAL;

extern void areion_pq_gf128_polymac_pclmul(
    uint8_t acc[16], const uint8_t *a, const uint8_t *b, size_t count, const uint8_t chi[16]) AREION_PQ_INTERNAL;
extern void areion_pq_gf128_polymac_vpclmul(
    uint8_t acc[16], const uint8_t *a, const uint8_t *b, size_t count, const uint8_t chi[16]) AREION_PQ_INTERNAL;

extern void areion_pq_vole_xor_row_sse2(
    uint8_t *dst, const uint8_t *src, size_t len) AREION_PQ_INTERNAL;
extern void areion_pq_vole_xor_row_avx2(
    uint8_t *dst, const uint8_t *src, size_t len) AREION_PQ_INTERNAL;
extern void areion_pq_vole_xor_row_avx512(
    uint8_t *dst, const uint8_t *src, size_t len) AREION_PQ_INTERNAL;

AREION_PQ_INTERNAL void areion_pq_wots_chain256x4_aesni(
    uint8_t out[4][32], const uint8_t in[4][32], const uint8_t adrs[4][32],
    const uint8_t kpub1[32], const uint8_t kpub2[32],
    uint32_t start_step, uint32_t steps);
AREION_PQ_INTERNAL void areion_pq_wots_chain256x4_vex(
    uint8_t out[4][32], const uint8_t in[4][32], const uint8_t adrs[4][32],
    const uint8_t kpub1[32], const uint8_t kpub2[32],
    uint32_t start_step, uint32_t steps);
AREION_PQ_INTERNAL void areion_pq_wots_chain256x4_vaesavx2(
    uint8_t out[4][32], const uint8_t in[4][32], const uint8_t adrs[4][32],
    const uint8_t kpub1[32], const uint8_t kpub2[32],
    uint32_t start_step, uint32_t steps);
AREION_PQ_INTERNAL void areion_pq_wots_chain256x4_avx512(
    uint8_t out[4][32], const uint8_t in[4][32], const uint8_t adrs[4][32],
    const uint8_t kpub1[32], const uint8_t kpub2[32],
    uint32_t start_step, uint32_t steps);
#endif

#if (defined(__aarch64__) || defined(_M_ARM64)) && !defined(AREION_PQ_FORCE_PORTABLE) && !defined(AREION_FORCE_PORTABLE)
extern void areion_pq_extract_witness256_arm64(
    uint8_t c[32], uint8_t w[288],
    const uint8_t m[32], const uint8_t k1[32], const uint8_t k2[32],
    const uint8_t rc[10][16]) AREION_PQ_INTERNAL;

extern void areion_pq_gf128_mul_pmull(
    uint8_t out[16], const uint8_t a[16], const uint8_t b[16]) AREION_PQ_INTERNAL;

extern void areion_pq_gf128_polymac_pmull(
    uint8_t acc[16], const uint8_t *a, const uint8_t *b, size_t count, const uint8_t chi[16]) AREION_PQ_INTERNAL;

extern void areion_pq_vole_xor_row_neon(
    uint8_t *dst, const uint8_t *src, size_t len) AREION_PQ_INTERNAL;

AREION_PQ_INTERNAL void areion_pq_wots_chain256x4_arm64(
    uint8_t out[4][32], const uint8_t in[4][32], const uint8_t adrs[4][32],
    const uint8_t kpub1[32], const uint8_t kpub2[32],
    uint32_t start_step, uint32_t steps);
#endif

#endif /* AREION_PQ_INTERNAL_H */
