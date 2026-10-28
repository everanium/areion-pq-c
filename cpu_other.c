/*
 * Copyright (c) 2026 Andrey Kuvshinov
 *
 * Dual-licensed under Apache-2.0 OR MIT.
 * See LICENSE-APACHE and LICENSE-MIT for details.
 */

#include "areion_pq_internal.h"

#if defined(AREION_PQ_FORCE_PORTABLE) || defined(AREION_FORCE_PORTABLE) || \
    (!defined(__x86_64__) && !defined(_M_X64) && !defined(__aarch64__) && !defined(_M_ARM64))

areion_pq_tier_t areion_pq_detect_hardware_tier(void) {
    return AREION_PQ_TIER_PUREC;
}

bool areion_pq_check_tier_supported(areion_pq_tier_t tier) {
    return tier == AREION_PQ_TIER_PUREC;
}

bool areion_pq_has_pclmul(void) {
    return false;
}

bool areion_pq_has_vpclmul(void) {
    return false;
}

bool areion_pq_has_pmull(void) {
    return false;
}

#else
typedef int areion_pq_cpu_other_unused_t;
#endif
