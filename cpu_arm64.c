/*
 * Copyright (c) 2026 Andrey Kuvshinov
 *
 * Dual-licensed under Apache-2.0 OR MIT.
 * See LICENSE-APACHE and LICENSE-MIT for details.
 */

#include "areion_pq_internal.h"

#if (defined(__aarch64__) || defined(_M_ARM64)) && !defined(AREION_PQ_FORCE_PORTABLE) && !defined(AREION_FORCE_PORTABLE)

#if defined(__linux__)
#include <sys/auxv.h>
#ifndef AT_HWCAP
#define AT_HWCAP 16
#endif
#ifndef HWCAP_AES
#define HWCAP_AES (1UL << 3U)
#endif
#ifndef HWCAP_PMULL
#define HWCAP_PMULL (1UL << 4U)
#endif
#elif defined(_WIN32)
#include <windows.h>
#ifndef PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE
#define PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE 30
#endif
#endif

static int g_arm64_feat_mask = -1;

static uint32_t get_arm64_feat_mask(void) {
    int cached;
    uint32_t m = 0U;
#if defined(__GNUC__) || defined(__clang__)
    cached = __atomic_load_n(&g_arm64_feat_mask, __ATOMIC_RELAXED);
#else
    cached = g_arm64_feat_mask;
#endif
    if (cached >= 0) {
        return (uint32_t)cached;
    }
#if defined(__linux__)
    {
        unsigned long hwcap = getauxval(AT_HWCAP);
        if ((hwcap & HWCAP_AES) != 0UL) {
            m |= (1U << 0U);
        }
        if ((hwcap & HWCAP_PMULL) != 0UL) {
            m |= (1U << 1U);
        }
    }
#elif defined(_WIN32)
    if (IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE) != 0) {
        m |= (1U << 0U) | (1U << 1U);
    }
#elif defined(__APPLE__) || defined(__ARM_FEATURE_CRYPTO)
    m |= (1U << 0U) | (1U << 1U);
#elif defined(__ARM_FEATURE_AES)
    m |= (1U << 0U);
#endif
#if defined(__GNUC__) || defined(__clang__)
    __atomic_store_n(&g_arm64_feat_mask, (int)m, __ATOMIC_RELAXED);
#else
    g_arm64_feat_mask = (int)m;
#endif
    return m;
}

static bool query_arm64_aes(void) {
    return (get_arm64_feat_mask() & (1U << 0U)) != 0U;
}

static bool query_arm64_pmull(void) {
    return (get_arm64_feat_mask() & (1U << 1U)) != 0U;
}

areion_pq_tier_t areion_pq_detect_hardware_tier(void) {
    if (query_arm64_aes()) {
        return AREION_PQ_TIER_ARM64;
    }
    return AREION_PQ_TIER_PUREC;
}

bool areion_pq_check_tier_supported(areion_pq_tier_t tier) {
    if (tier == AREION_PQ_TIER_PUREC) {
        return true;
    }
    if (tier == AREION_PQ_TIER_ARM64) {
        return query_arm64_aes();
    }
    return false;
}

bool areion_pq_detect_pclmul(void) {
    return false;
}

bool areion_pq_detect_vpclmul(void) {
    return false;
}

bool areion_pq_detect_pmull(void) {
    return query_arm64_pmull();
}

#else
typedef int areion_pq_cpu_arm64_unused_t;
#endif
