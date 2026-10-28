/*
 * Copyright (c) 2026 Andrey Kuvshinov
 *
 * Dual-licensed under Apache-2.0 OR MIT.
 * See LICENSE-APACHE and LICENSE-MIT for details.
 */

#include "areion_pq_internal.h"
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

/* Internal state values:
 * -2 = uninitialized
 * >= 1 = active areion_pq_tier_t */
static int g_active_pq_tier = -2;
static int g_hw_pq_tier = -2;

static int atomic_load_int(const int *p) {
#if defined(__GNUC__) || defined(__clang__)
    return __atomic_load_n(p, __ATOMIC_ACQUIRE);
#elif defined(_WIN32)
    return (int)InterlockedCompareExchange((volatile LONG *)(uintptr_t)p, 0L, 0L);
#else
    return *(const volatile int *)p;
#endif
}

static void atomic_store_int(int *p, int v) {
#if defined(__GNUC__) || defined(__clang__)
    __atomic_store_n(p, v, __ATOMIC_RELEASE);
#elif defined(_WIN32)
    (void)InterlockedExchange((volatile LONG *)p, (LONG)v);
#else
    *(volatile int *)p = v;
#endif
}

static areion_tier_t pq_tier_to_base_tier(areion_pq_tier_t id) {
    switch (id) {
        case AREION_PQ_TIER_AUTO:
            return AREION_TIER_AUTO;
        case AREION_PQ_TIER_PUREC:
            return AREION_TIER_PUREC;
        case AREION_PQ_TIER_AESNI:
            return AREION_TIER_AESNI;
        case AREION_PQ_TIER_VEX:
            return AREION_TIER_VEX;
        case AREION_PQ_TIER_VAESAVX2:
            return AREION_TIER_VAESAVX2;
        case AREION_PQ_TIER_AVX512:
            return AREION_TIER_AVX512;
        case AREION_PQ_TIER_ARM64:
            return AREION_TIER_ARM64;
        default:
            return AREION_TIER_PUREC;
    }
}

static bool parse_pq_tier_name(const char *name, areion_pq_tier_t *out) {
    char buf[32];
    size_t pos = 0U, len = 0U;
    if (name == NULL) {
        return false;
    }
    while (name[pos] == ' ' || name[pos] == '\t' || name[pos] == '\r' || name[pos] == '\n') {
        pos++;
    }
    while (name[pos] != '\0' && name[pos] != ' ' && name[pos] != '\t' &&
           name[pos] != '\r' && name[pos] != '\n') {
        char c = name[pos++];
        if (len + 1U >= sizeof(buf)) {
            return false;
        }
        if (c >= 'A' && c <= 'Z') {
            c = (char)(c - 'A' + 'a');
        }
        buf[len++] = c;
    }
    while (name[pos] == ' ' || name[pos] == '\t' || name[pos] == '\r' || name[pos] == '\n') {
        pos++;
    }
    if (len == 0U || name[pos] != '\0') {
        return false;
    }
    buf[len] = '\0';

    if (strcmp(buf, "auto") == 0) {
        *out = AREION_PQ_TIER_AUTO;
        return true;
    }
    if (strcmp(buf, "purec") == 0 || strcmp(buf, "purego") == 0 ||
        strcmp(buf, "scalar") == 0 || strcmp(buf, "gpr") == 0) {
        *out = AREION_PQ_TIER_PUREC;
        return true;
    }
    if (strcmp(buf, "aesni") == 0) {
        *out = AREION_PQ_TIER_AESNI;
        return true;
    }
    if (strcmp(buf, "vex") == 0) {
        *out = AREION_PQ_TIER_VEX;
        return true;
    }
    if (strcmp(buf, "vaesavx2") == 0) {
        *out = AREION_PQ_TIER_VAESAVX2;
        return true;
    }
    if (strcmp(buf, "avx512") == 0) {
        *out = AREION_PQ_TIER_AVX512;
        return true;
    }
    if (strcmp(buf, "arm64") == 0 || strcmp(buf, "neon") == 0 ||
        strcmp(buf, "sve") == 0 || strcmp(buf, "sve2") == 0) {
        *out = AREION_PQ_TIER_ARM64;
        return true;
    }
    return false;
}

static const char *get_env_tier_str(void) {
    const char *env = getenv("AREION_PQ_FORCE_TIER");
    if (env != NULL && env[0] != '\0') {
        return env;
    }
    env = getenv("AREION_FORCE_TIER");
    if (env != NULL && env[0] != '\0') {
        return env;
    }
    env = getenv("AREION_TIER");
    if (env != NULL && env[0] != '\0') {
        return env;
    }
    return NULL;
}

static areion_pq_tier_t get_hw_pq_tier(void) {
    int hw = atomic_load_int(&g_hw_pq_tier);
    if (hw < 0) {
        hw = (int)areion_pq_detect_hardware_tier();
        atomic_store_int(&g_hw_pq_tier, hw);
    }
    return (areion_pq_tier_t)hw;
}

static areion_pq_tier_t init_active_pq_tier(void) {
    areion_pq_tier_t hw = get_hw_pq_tier();
    areion_pq_tier_t selected = hw;
    const char *env = get_env_tier_str();
    if (env != NULL) {
        areion_pq_tier_t req = AREION_PQ_TIER_AUTO;
        if (parse_pq_tier_name(env, &req) && req != AREION_PQ_TIER_AUTO &&
            areion_pq_check_tier_supported(req)) {
            selected = req;
        }
    }
    (void)areion_set_tier_override(pq_tier_to_base_tier(selected));
    atomic_store_int(&g_active_pq_tier, (int)selected);
    return selected;
}

areion_pq_tier_t areion_pq_tier_code(void) {
    int cur = atomic_load_int(&g_active_pq_tier);
    if (cur < 0) {
        return init_active_pq_tier();
    }
    return (areion_pq_tier_t)cur;
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((constructor))
static void areion_pq_cpu_early_init(void) {
    (void)areion_pq_tier_code();
}
#elif defined(_MSC_VER)
static void __cdecl areion_pq_cpu_early_init(void) {
    (void)areion_pq_tier_code();
}
#pragma section(".CRT$XCU", read)
__declspec(allocate(".CRT$XCU")) static void (__cdecl *p_areion_pq_cpu_early_init)(void) = areion_pq_cpu_early_init;
#endif

const char *areion_pq_tier(void) {
    switch (areion_pq_tier_code()) {
        case AREION_PQ_TIER_AVX512:
            return "avx512";
        case AREION_PQ_TIER_VAESAVX2:
            return "vaesavx2";
        case AREION_PQ_TIER_VEX:
            return "vex";
        case AREION_PQ_TIER_AESNI:
            return "aesni";
        case AREION_PQ_TIER_ARM64:
            return "arm64";
        case AREION_PQ_TIER_PUREC:
        case AREION_PQ_TIER_AUTO:
        default:
            return "purec";
    }
}

bool areion_pq_tier_supported(areion_pq_tier_t tier) {
    if (tier == AREION_PQ_TIER_AUTO || tier == AREION_PQ_TIER_PUREC) {
        return true;
    }
    return areion_pq_check_tier_supported(tier);
}

size_t areion_pq_available_tiers(const char **out, size_t max_out) {
    static const struct {
        areion_pq_tier_t id;
        const char *name;
    } candidates[] = {
        {AREION_PQ_TIER_PUREC, "purec"},
        {AREION_PQ_TIER_AESNI, "aesni"},
        {AREION_PQ_TIER_VEX, "vex"},
        {AREION_PQ_TIER_VAESAVX2, "vaesavx2"},
        {AREION_PQ_TIER_AVX512, "avx512"},
        {AREION_PQ_TIER_ARM64, "arm64"},
    };
    size_t count = 0U;
    size_t i;
    for (i = 0U; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        if (areion_pq_tier_supported(candidates[i].id)) {
            if (out != NULL && count < max_out) {
                out[count] = candidates[i].name;
            }
            count++;
        }
    }
    return count;
}

int areion_pq_set_tier_code(areion_pq_tier_t id) {
    (void)get_hw_pq_tier();
    if (id == AREION_PQ_TIER_AUTO) {
        areion_pq_tier_t selected = get_hw_pq_tier();
        const char *env = get_env_tier_str();
        if (env != NULL) {
            areion_pq_tier_t req = AREION_PQ_TIER_AUTO;
            if (parse_pq_tier_name(env, &req) && req != AREION_PQ_TIER_AUTO &&
                areion_pq_check_tier_supported(req)) {
                selected = req;
            }
        }
        (void)areion_set_tier_override(pq_tier_to_base_tier(selected));
        atomic_store_int(&g_active_pq_tier, (int)selected);
        return 0;
    }
    if (!areion_pq_tier_supported(id)) {
        return -1;
    }
    if (!areion_set_tier_override(pq_tier_to_base_tier(id))) {
        return -1;
    }
    atomic_store_int(&g_active_pq_tier, (int)id);
    return 0;
}

int areion_pq_set_tier(const char *name) {
    areion_pq_tier_t tier = AREION_PQ_TIER_AUTO;
    if (!parse_pq_tier_name(name, &tier)) {
        return -1;
    }
    return areion_pq_set_tier_code(tier);
}

void areion_pq_use_hardware_acceleration(bool enable) {
    if (enable) {
        (void)areion_pq_set_tier_code(AREION_PQ_TIER_AUTO);
    } else {
        (void)areion_pq_set_tier_code(AREION_PQ_TIER_PUREC);
    }
}

void areion_pq_zeroize(void *ptr, size_t len) {
    if (ptr == NULL || len == 0U) {
        return;
    }
#if defined(_WIN32)
    SecureZeroMemory(ptr, len);
#endif
    {
        volatile uint8_t *vp = (volatile uint8_t *)ptr;
        size_t i;
        for (i = 0U; i < len; i++) {
            vp[i] = 0U;
        }
    }
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
#elif defined(_MSC_VER)
    _ReadWriteBarrier();
#endif
    areion_pq_clobber_scratch_gprs();
}

static AREION_PQ_NOINLINE AREION_PQ_NO_STACK_PROTECTOR void areion_pq_wipe_selftest_stack(void) {
    volatile uint64_t frame[1664];
    size_t i;
#if defined(__GNUC__) || defined(__clang__)
    const void *fp = __builtin_frame_address(0);
#endif
    for (i = 0U; i < 1664U; i++) {
        frame[i] = 0ULL;
    }
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(frame), "r"(fp) : "memory");
#else
    areion_pq_compiler_barrier();
#endif
}

static AREION_PQ_NOINLINE uint32_t selftest_pq_primitives(void) {
    static const uint8_t ad_str[22] = "areion-pq-selftest-ad";
    static const uint8_t pt_str[35] = "areion-pq-selftest-plaintext-block";

    uint8_t one128[16], a128[16], b128[16], ab128[16], ba128[16];
    uint8_t m[32], k1[32], k2[32], c[32], c_em2[32];
    uint8_t w256[288], w_em2[576];
    uint8_t siv_key[128], siv_nonce[32], siv_tag[32];
    uint8_t ct_buf[35], dec_buf[35];
    uint32_t fail = 0U;
    size_t i;

    /* 1. GF(2^8) S-box inversion and affine identity check */
    for (i = 0U; i < 256U; i++) {
        uint8_t xb = (uint8_t)i;
        uint8_t inv = areion_pq_gf256_inv(xb);
        uint8_t s = areion_pq_gf256_affine(inv);
        uint8_t y = areion_pq_gf256_affine_inv(s);
        uint8_t c1 = (uint8_t)(areion_pq_gf256_mul(areion_pq_gf256_sq(xb), y) ^ xb);
        uint8_t c2 = (uint8_t)(areion_pq_gf256_mul(areion_pq_gf256_sq(y), xb) ^ y);
        fail |= (uint32_t)(s ^ areion_pq_aes_sbox[i]);
        fail |= (uint32_t)(y ^ inv);
        fail |= (uint32_t)(c1 | c2);
    }

    /* 2. GF(2^128) multiplication identity & commutativity check */
    memset(one128, 0, sizeof(one128));
    one128[0] = 1U;
    for (i = 0U; i < 16U; i++) {
        a128[i] = (uint8_t)(0x10U + i);
        b128[i] = (uint8_t)(0x20U + i);
    }
    areion_pq_gf128_mul(ab128, a128, one128);
    if (areion_pq_ct_eq(ab128, a128, 16U) != 1) {
        fail |= 1U;
    }
    areion_pq_gf128_mul(ab128, a128, b128);
    areion_pq_gf128_mul(ba128, b128, a128);
    if (areion_pq_ct_eq(ab128, ba128, 16U) != 1) {
        fail |= 1U;
    }

    /* 3. 288-S-box and 576-S-box witness extraction & verification check */
    for (i = 0U; i < 32U; i++) {
        m[i] = (uint8_t)(i + 1U);
        k1[i] = (uint8_t)(0x40U + i);
        k2[i] = (uint8_t)(0x80U + i);
    }
    areion_pq_extract_witness256(c, w256, m, k1, k2);
    if (areion_pq_verify_witness256(m, c, k1, k2, w256) != 1) {
        fail |= 1U;
    }
    areion_pq_extract_witness_em2_256(c_em2, w_em2, m, k1, k2);
    if (areion_pq_verify_witness_em2_256(m, c_em2, k1, k2, w_em2) != 1) {
        fail |= 1U;
    }

    /* 4. TEM2-SIV roundtrip check */
    for (i = 0U; i < 128U; i++) {
        siv_key[i] = (uint8_t)i;
    }
    for (i = 0U; i < 32U; i++) {
        siv_nonce[i] = (uint8_t)(0xa0U + i);
    }
    areion_pq_tem2_siv_encrypt(ct_buf, siv_tag, siv_key, siv_nonce, ad_str, sizeof(ad_str), pt_str, sizeof(pt_str));
    if (areion_pq_tem2_siv_decrypt(dec_buf, siv_key, siv_nonce, ad_str, sizeof(ad_str), ct_buf, sizeof(ct_buf), siv_tag) != 1) {
        fail |= 1U;
    }
    if (areion_pq_ct_eq(dec_buf, pt_str, sizeof(pt_str)) != 1) {
        fail |= 1U;
    }

    areion_pq_secure_wipe(one128, sizeof(one128));
    areion_pq_secure_wipe(a128, sizeof(a128));
    areion_pq_secure_wipe(b128, sizeof(b128));
    areion_pq_secure_wipe(ab128, sizeof(ab128));
    areion_pq_secure_wipe(ba128, sizeof(ba128));
    areion_pq_secure_wipe(m, sizeof(m));
    areion_pq_secure_wipe(k1, sizeof(k1));
    areion_pq_secure_wipe(k2, sizeof(k2));
    areion_pq_secure_wipe(c, sizeof(c));
    areion_pq_secure_wipe(c_em2, sizeof(c_em2));
    areion_pq_secure_wipe(w256, sizeof(w256));
    areion_pq_secure_wipe(w_em2, sizeof(w_em2));
    areion_pq_secure_wipe(siv_key, sizeof(siv_key));
    areion_pq_secure_wipe(siv_nonce, sizeof(siv_nonce));
    areion_pq_secure_wipe(siv_tag, sizeof(siv_tag));
    areion_pq_secure_wipe(ct_buf, sizeof(ct_buf));
    areion_pq_secure_wipe(dec_buf, sizeof(dec_buf));

    return fail;
}

int areion_pq_selftest(void) {
    uint32_t fail = 0U;
    if (areion_selftest() != 0) {
        fail |= 1U;
    }
    fail |= selftest_pq_primitives();
    areion_pq_wipe_selftest_stack();
    areion_pq_clobber_scratch_gprs();
    return (fail == 0U) ? 0 : -1;
}
