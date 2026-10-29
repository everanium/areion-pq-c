/*
 * Copyright (c) 2026 Andrey Kuvshinov
 *
 * Dual-licensed under Apache-2.0 OR MIT.
 * See LICENSE-APACHE and LICENSE-MIT for details.
 */

#include "areion_pq_internal.h"

#if (defined(__x86_64__) || defined(_M_X64)) && !defined(AREION_PQ_FORCE_PORTABLE) && !defined(AREION_FORCE_PORTABLE)

#if defined(_MSC_VER)
#include <intrin.h>
#endif

#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif

static void cpuid_count(uint32_t leaf, uint32_t subleaf,
                        uint32_t *eax, uint32_t *ebx,
                        uint32_t *ecx, uint32_t *edx) {
#if defined(_MSC_VER)
    int regs[4];
    __cpuidex(regs, (int)leaf, (int)subleaf);
    *eax = (uint32_t)regs[0];
    *ebx = (uint32_t)regs[1];
    *ecx = (uint32_t)regs[2];
    *edx = (uint32_t)regs[3];
#else
    *eax = 0U;
    *ebx = 0U;
    *ecx = 0U;
    *edx = 0U;
    __asm__ __volatile__(
        "cpuid"
        : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
        : "a"(leaf), "c"(subleaf));
#endif
}

static uint64_t xgetbv_xcr0(void) {
#if defined(_MSC_VER)
    return _xgetbv(0);
#else
    uint32_t eax, edx;
    __asm__ __volatile__(
        ".byte 0x0f, 0x01, 0xd0" /* xgetbv */
        : "=a"(eax), "=d"(edx)
        : "c"(0U));
    return ((uint64_t)edx << 32U) | (uint64_t)eax;
#endif
}

typedef struct {
    bool has_aesni;
    bool has_pclmul;
    bool has_vex;
    bool has_vpclmul;
    bool has_vaes_avx2;
    bool has_avx512;
} x86_pq_features_t;

static int g_x86_feat_mask = -1;

static uint32_t compute_x86_pq_feature_mask(void) {
    uint32_t mask = 0U;
    uint32_t max_leaf = 0U, eax = 0U, ebx = 0U, ecx = 0U, edx = 0U;

    cpuid_count(0U, 0U, &max_leaf, &ebx, &ecx, &edx);
    if (max_leaf < 1U) {
        return mask;
    }

    cpuid_count(1U, 0U, &eax, &ebx, &ecx, &edx);
    bool pclmul = (ecx & (1U << 1U)) != 0U;
    bool aesni = (ecx & (1U << 25U)) != 0U;
    bool osxsave = (ecx & (1U << 27U)) != 0U;
    bool avx = (ecx & (1U << 28U)) != 0U;

    if (aesni) {
        mask |= (1U << 0U);
    }
    if (pclmul) {
        mask |= (1U << 1U);
    }
    if (!osxsave || !avx) {
        return mask;
    }

    uint64_t xcr0 = xgetbv_xcr0();
    bool os_avx = (xcr0 & 0x06ULL) == 0x06ULL;
    if (!os_avx) {
        return mask;
    }
    if (pclmul) {
        mask |= (1U << 3U);
    }
    if (!aesni) {
        return mask;
    }
    mask |= (1U << 2U);

    if (max_leaf < 7U) {
        return mask;
    }

    cpuid_count(7U, 0U, &eax, &ebx, &ecx, &edx);
    bool avx2 = (ebx & (1U << 5U)) != 0U;
    bool vaes = (ecx & (1U << 9U)) != 0U;
    bool vpclmul256 = (ecx & (1U << 10U)) != 0U;
    if (avx2 && vaes) {
        mask |= (1U << 4U);
    }
    if (avx2 && vpclmul256) {
        mask |= (1U << 3U);
    }

    bool os_avx512 = (xcr0 & 0xE6ULL) == 0xE6ULL;
#if defined(__APPLE__)
    if (!os_avx512 && os_avx) {
        int avx512f = 0;
        size_t len = sizeof(avx512f);
        if (sysctlbyname("hw.optional.avx512f", &avx512f, &len, NULL, 0) == 0 && avx512f == 1) {
            os_avx512 = true;
        }
    }
#endif
    uint32_t avx512_mask = (1U << 16U) | (1U << 17U) | (1U << 30U) | (1U << 31U);
    bool avx512_isa = (ebx & avx512_mask) == avx512_mask;
    if (((mask & (1U << 4U)) != 0U) && os_avx512 && avx512_isa) {
        mask |= (1U << 5U);
    }

    return mask;
}

static x86_pq_features_t query_x86_pq_features(void) {
    int cached;
    uint32_t m;
    x86_pq_features_t feat;
#if defined(__GNUC__) || defined(__clang__)
    cached = __atomic_load_n(&g_x86_feat_mask, __ATOMIC_RELAXED);
#else
    cached = g_x86_feat_mask;
#endif
    if (cached < 0) {
        m = compute_x86_pq_feature_mask();
#if defined(__GNUC__) || defined(__clang__)
        __atomic_store_n(&g_x86_feat_mask, (int)m, __ATOMIC_RELAXED);
#else
        g_x86_feat_mask = (int)m;
#endif
    } else {
        m = (uint32_t)cached;
    }
    feat.has_aesni = (m & (1U << 0U)) != 0U;
    feat.has_pclmul = (m & (1U << 1U)) != 0U;
    feat.has_vex = (m & (1U << 2U)) != 0U;
    feat.has_vpclmul = (m & (1U << 3U)) != 0U;
    feat.has_vaes_avx2 = (m & (1U << 4U)) != 0U;
    feat.has_avx512 = (m & (1U << 5U)) != 0U;
    return feat;
}

areion_pq_tier_t areion_pq_detect_hardware_tier(void) {
    x86_pq_features_t feat = query_x86_pq_features();
    if (feat.has_avx512) {
        return AREION_PQ_TIER_AVX512;
    }
    if (feat.has_vaes_avx2) {
        return AREION_PQ_TIER_VAESAVX2;
    }
    if (feat.has_vex) {
        return AREION_PQ_TIER_VEX;
    }
    if (feat.has_aesni) {
        return AREION_PQ_TIER_AESNI;
    }
    return AREION_PQ_TIER_PUREC;
}

bool areion_pq_check_tier_supported(areion_pq_tier_t tier) {
    x86_pq_features_t feat = query_x86_pq_features();
    switch (tier) {
        case AREION_PQ_TIER_PUREC:
            return true;
        case AREION_PQ_TIER_AESNI:
            return feat.has_aesni;
        case AREION_PQ_TIER_VEX:
            return feat.has_vex;
        case AREION_PQ_TIER_VAESAVX2:
            return feat.has_vaes_avx2;
        case AREION_PQ_TIER_AVX512:
            return feat.has_avx512;
        case AREION_PQ_TIER_ARM64:
        case AREION_PQ_TIER_AUTO:
        default:
            return false;
    }
}

bool areion_pq_detect_pclmul(void) {
    return query_x86_pq_features().has_pclmul;
}

bool areion_pq_detect_vpclmul(void) {
    return query_x86_pq_features().has_vpclmul;
}

bool areion_pq_detect_pmull(void) {
    return false;
}

#else
typedef int areion_pq_cpu_amd64_unused_t;
#endif
