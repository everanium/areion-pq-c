/*
 * Copyright (c) 2026 Andrey Kuvshinov
 *
 * Dual-licensed under Apache-2.0 OR MIT.
 * See LICENSE-APACHE and LICENSE-MIT for details.
 *
 * Zeroization, stack-frame, SIMD/GPR register-hygiene, and Timecop verification
 * suite for areion-pq-c.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "areion_pq.h"
#include "areion_pq_internal.h"

#if defined(AREION_PQ_TIMECOP)
#include <valgrind/memcheck.h>
#define TIMECOP_POISON(ptr, len) VALGRIND_MAKE_MEM_UNDEFINED((ptr), (len))
#define TIMECOP_UNPOISON(ptr, len) VALGRIND_MAKE_MEM_DEFINED((ptr), (len))
#else
#define TIMECOP_POISON(ptr, len) ((void)(ptr), (void)(len))
#define TIMECOP_UNPOISON(ptr, len) ((void)(ptr), (void)(len))
#endif

#define AREION_PQ_RESIDUE_PAD_WORDS 256U
#define AREION_PQ_RESIDUE_WINDOW    (16UL * 1024UL)
#define AREION_PQ_STACK_WORDS       (AREION_PQ_RESIDUE_WINDOW / 8UL)
#define AREION_PQ_SIMD_WORDS        96U
#define AREION_PQ_TOTAL_WORDS       (AREION_PQ_STACK_WORDS + AREION_PQ_SIMD_WORDS)
#define AREION_PQ_RESIDUE_SENTINEL  0x5A5A5A5A5A5A5A5AULL
#define AREION_PQ_MAX_TARGETS       256U

#if defined(__SANITIZE_ADDRESS__) || __has_feature(address_sanitizer) || __has_feature(memory_sanitizer)
#define AREION_PQ_SANITIZER_NO_STACK_PROBE 1
#else
#define AREION_PQ_SANITIZER_NO_STACK_PROBE 0
#endif

static int g_zeroize_failures = 0;
static volatile uint64_t g_areion_pq_sink = 0;

#if !defined(AREION_PQ_FORCE_PORTABLE) && !defined(AREION_FORCE_PORTABLE) && \
    (defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__) || defined(_M_ARM64))
#define AREION_PQ_HAS_ASM_TEST_HELPERS 1
#else
#define AREION_PQ_HAS_ASM_TEST_HELPERS 0
static void areion_pq_dump_simd_regs(uint64_t *dst, int has_avx512) {
    (void)has_avx512;
    memset(dst, 0, AREION_PQ_SIMD_WORDS * sizeof(uint64_t));
}
#endif

typedef void (*areion_pq_probe_cb_t)(const void *ctx);

/* =========================================================================
 * 16 KiB Stack Sentinel Window & Register Residue Harness
 * ========================================================================= */

#if !AREION_PQ_SANITIZER_NO_STACK_PROBE
static AREION_PQ_NOINLINE uintptr_t seed_or_read_stack_window(
    int read_mode, uint64_t out[AREION_PQ_STACK_WORDS]) {
    volatile uint64_t window[AREION_PQ_STACK_WORDS];
    volatile uintptr_t addr = (uintptr_t)&window[0];
    size_t i;
    if (read_mode == 0) {
        for (i = 0; i < AREION_PQ_STACK_WORDS; i++) {
            window[i] = AREION_PQ_RESIDUE_SENTINEL;
        }
    } else {
#if (defined(__GNUC__) || defined(__clang__)) && defined(__x86_64__)
        {
            /* Tell Valgrind Memcheck that the stack window being inspected is defined. */
            volatile unsigned long vg_args[6];
            unsigned long vg_res = 0UL;
            vg_args[0] = 0x4d430002UL; /* VG_USERREQ__MAKE_MEM_DEFINED */
            vg_args[1] = (unsigned long)addr;
            vg_args[2] = (unsigned long)sizeof(window);
            vg_args[3] = 0UL;
            vg_args[4] = 0UL;
            vg_args[5] = 0UL;
            __asm__ __volatile__(
                "rolq $3,  %%rdi ; rolq $13, %%rdi\n\t"
                "rolq $61, %%rdi ; rolq $51, %%rdi\n\t"
                "xchgq %%rbx, %%rbx"
                : "=d"(vg_res)
                : "a"(&vg_args[0]), "0"(0UL)
                : "cc", "memory");
            (void)vg_res;
        }
#endif
        for (i = 0; i < AREION_PQ_STACK_WORDS; i++) {
            out[i] = window[i];
        }
    }
    areion_pq_compiler_barrier();
    return addr;
}
#endif

static AREION_PQ_NOINLINE uint64_t areion_pq_residue_deep(
    areion_pq_probe_cb_t fn, const void *ctx, size_t idx,
    uint64_t regs[AREION_PQ_SIMD_WORDS], int avx512) {
    volatile uint64_t pad[AREION_PQ_RESIDUE_PAD_WORDS];
    volatile size_t vidx = idx;
    pad[vidx % AREION_PQ_RESIDUE_PAD_WORDS] = 1ULL;
    pad[(vidx + 7U) % AREION_PQ_RESIDUE_PAD_WORDS] = 2ULL;
    pad[(vidx + 63U) % AREION_PQ_RESIDUE_PAD_WORDS] = 3ULL;
    pad[(vidx + 255U) % AREION_PQ_RESIDUE_PAD_WORDS] = 4ULL;
    areion_pq_dump_simd_regs(regs, avx512);
    AREION_PQ_MSAN_UNPOISON(regs, AREION_PQ_SIMD_WORDS * sizeof(uint64_t));
    areion_pq_clobber_scratch_gprs();
    fn(ctx);
    areion_pq_dump_simd_regs(regs, avx512);
    AREION_PQ_MSAN_UNPOISON(regs, AREION_PQ_SIMD_WORDS * sizeof(uint64_t));
    return pad[(vidx + 7U) % AREION_PQ_RESIDUE_PAD_WORDS] ^
           pad[(vidx + 255U) % AREION_PQ_RESIDUE_PAD_WORDS];
}

static AREION_PQ_NOINLINE size_t capture_areion_pq_frame_and_reg_residue(
    areion_pq_probe_cb_t fn, const void *ctx, uint64_t dst[AREION_PQ_TOTAL_WORDS]) {
    uint64_t simd[AREION_PQ_SIMD_WORDS];
    int avx512 = (areion_pq_tier_code() == AREION_PQ_TIER_AVX512) ? 1 : 0;
#if !AREION_PQ_SANITIZER_NO_STACK_PROBE
    uintptr_t a0, a1;
    size_t i, written = 0;
#endif

    memset(simd, 0, sizeof(simd));
#if !AREION_PQ_SANITIZER_NO_STACK_PROBE
    a0 = seed_or_read_stack_window(0, dst);
#endif
#if (defined(__GNUC__) || defined(__clang__)) && (defined(__x86_64__) || defined(_M_X64))
    __asm__ __volatile__(
        "xorl %%ebx, %%ebx\n\t"
        "xorl %%r12d, %%r12d\n\t"
        "xorl %%r13d, %%r13d\n\t"
        "xorl %%r14d, %%r14d\n\t"
        "xorl %%r15d, %%r15d\n\t"
#if defined(_WIN32) || defined(__CYGWIN__)
        "xorl %%esi, %%esi\n\t"
        "xorl %%edi, %%edi\n\t"
        "pxor %%xmm6, %%xmm6\n\t"
        "pxor %%xmm7, %%xmm7\n\t"
        "pxor %%xmm8, %%xmm8\n\t"
        "pxor %%xmm9, %%xmm9\n\t"
        "pxor %%xmm10, %%xmm10\n\t"
        "pxor %%xmm11, %%xmm11\n\t"
        "pxor %%xmm12, %%xmm12\n\t"
        "pxor %%xmm13, %%xmm13\n\t"
        "pxor %%xmm14, %%xmm14\n\t"
        "pxor %%xmm15, %%xmm15\n\t"
        : : : "rbx", "r12", "r13", "r14", "r15", "rsi", "rdi",
              "xmm6", "xmm7", "xmm8", "xmm9", "xmm10",
              "xmm11", "xmm12", "xmm13", "xmm14", "xmm15", "memory"
#else
        : : : "rbx", "r12", "r13", "r14", "r15", "memory"
#endif
    );
#elif (defined(__GNUC__) || defined(__clang__)) && (defined(__aarch64__) || defined(_M_ARM64))
    __asm__ __volatile__(
        "mov x19, xzr\n\t"
        "mov x20, xzr\n\t"
        "mov x21, xzr\n\t"
        "mov x22, xzr\n\t"
        "mov x23, xzr\n\t"
        "mov x24, xzr\n\t"
        "mov x25, xzr\n\t"
        "mov x26, xzr\n\t"
        "mov x27, xzr\n\t"
        "mov x28, xzr\n\t"
        "eor v8.16b, v8.16b, v8.16b\n\t"
        "eor v9.16b, v9.16b, v9.16b\n\t"
        "eor v10.16b, v10.16b, v10.16b\n\t"
        "eor v11.16b, v11.16b, v11.16b\n\t"
        "eor v12.16b, v12.16b, v12.16b\n\t"
        "eor v13.16b, v13.16b, v13.16b\n\t"
        "eor v14.16b, v14.16b, v14.16b\n\t"
        "eor v15.16b, v15.16b, v15.16b\n\t"
        : : : "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28",
              "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "memory"
    );
#endif
    g_areion_pq_sink = areion_pq_residue_deep(fn, ctx, 0U, simd, avx512);
#if !AREION_PQ_SANITIZER_NO_STACK_PROBE
    a1 = seed_or_read_stack_window(1, dst);

    if (a0 != a1) {
        (void)fprintf(stderr, "FAIL: stack window address mismatch (0x%llx != 0x%llx)\n",
                      (unsigned long long)a0, (unsigned long long)a1);
        g_zeroize_failures++;
    }

    memcpy(&dst[AREION_PQ_STACK_WORDS], simd, sizeof(simd));

    for (i = 0; i < AREION_PQ_STACK_WORDS; i++) {
        if (dst[i] != AREION_PQ_RESIDUE_SENTINEL) {
            written++;
        }
    }
    return written;
#else
    memset(dst, 0, AREION_PQ_STACK_WORDS * sizeof(uint64_t));
    memcpy(&dst[AREION_PQ_STACK_WORDS], simd, sizeof(simd));
    return 1U;
#endif
}

/* =========================================================================
 * Target Word Extraction & Window Scanners
 * ========================================================================= */

typedef struct {
    uint64_t words[AREION_PQ_MAX_TARGETS];
    size_t count;
} target_list_t;

static void targets_init(target_list_t *t) {
    t->count = 0;
}

static void targets_add_bytes(target_list_t *t, const uint8_t *buf, size_t len) {
    size_t i;
    for (i = 0; i + 8 <= len; i += 8) {
        uint64_t w_le = areion_pq_load_le64(&buf[i]);
        uint64_t w_native = 0;
        memcpy(&w_native, &buf[i], 8);
        if (w_le != 0ULL && w_le != AREION_PQ_RESIDUE_SENTINEL &&
            t->count < AREION_PQ_MAX_TARGETS) {
            t->words[t->count++] = w_le;
        }
        if (w_native != 0ULL && w_native != AREION_PQ_RESIDUE_SENTINEL &&
            w_native != w_le && t->count < AREION_PQ_MAX_TARGETS) {
            t->words[t->count++] = w_native;
        }
    }
}

static bool scan_for_areion_pq_words(
    const uint64_t window[AREION_PQ_TOTAL_WORDS], const target_list_t *targets,
    uint64_t *leaked_word, size_t *leaked_off) {
    size_t i, j;
    for (i = 0; i < AREION_PQ_TOTAL_WORDS; i++) {
        uint64_t w = window[i];
        if (w == 0ULL || (i < AREION_PQ_STACK_WORDS && w == AREION_PQ_RESIDUE_SENTINEL)) {
            continue;
        }
        for (j = 0; j < targets->count; j++) {
            uint64_t t = targets->words[j];
            if (t != 0ULL && w == t) {
                *leaked_word = t;
                *leaked_off = i * 8U;
                return true;
            }
        }
    }
    return false;
}

#if !AREION_PQ_SANITIZER_NO_STACK_PROBE
static bool scan_for_areion_pq_words_in_stack(
    const uint64_t window[AREION_PQ_TOTAL_WORDS], const target_list_t *targets,
    uint64_t *leaked_word, size_t *leaked_off) {
    size_t i, j;
    for (i = 0; i < AREION_PQ_STACK_WORDS; i++) {
        uint64_t w = window[i];
        if (w == 0ULL || w == AREION_PQ_RESIDUE_SENTINEL) {
            continue;
        }
        for (j = 0; j < targets->count; j++) {
            uint64_t t = targets->words[j];
            if (t != 0ULL && w == t) {
                *leaked_word = t;
                *leaked_off = i * 8U;
                return true;
            }
        }
    }
    return false;
}
#endif

#if AREION_PQ_HAS_ASM_TEST_HELPERS
static bool scan_for_areion_pq_words_in_regs(
    const uint64_t window[AREION_PQ_TOTAL_WORDS], const target_list_t *targets,
    uint64_t *leaked_word, size_t *leaked_off) {
    size_t i, j;
    for (i = AREION_PQ_STACK_WORDS; i < AREION_PQ_TOTAL_WORDS; i++) {
        uint64_t w = window[i];
        if (w == 0ULL) {
            continue;
        }
        for (j = 0; j < targets->count; j++) {
            uint64_t t = targets->words[j];
            if (t != 0ULL && w == t) {
                *leaked_word = t;
                *leaked_off = i * 8U;
                return true;
            }
        }
    }
    return false;
}
#endif

static void assert_no_leak(
    const char *tier_name, const char *op_name, size_t written,
    const uint64_t res[AREION_PQ_TOTAL_WORDS], const target_list_t *targets) {
    uint64_t word = 0;
    size_t off = 0;
    if (written == 0) {
        (void)fprintf(stderr, "FAIL [%s] %s: probe missed stack window\n", tier_name, op_name);
        g_zeroize_failures++;
        return;
    }
    if (scan_for_areion_pq_words(res, targets, &word, &off)) {
        const char *where = (off < AREION_PQ_RESIDUE_WINDOW) ? "stack" : "SIMD/GPR register";
        (void)fprintf(stderr, "FAIL [%s] %s leaked word 0x%016llx in %s at offset %u\n",
                      tier_name, op_name, (unsigned long long)word, where, (unsigned)off);
        g_zeroize_failures++;
    }
}

/* =========================================================================
 * 1. Direct areion_pq_zeroize() Functional Verification
 * ========================================================================= */

static void test_zeroize_primitive(void) {
    uint8_t buf[1056];
    static const size_t sizes[] = {0, 1, 7, 15, 16, 31, 32, 63, 64, 128, 256, 512, 1024};
    size_t s_idx;

    areion_pq_zeroize(NULL, 0);
    areion_pq_zeroize(NULL, 64);

    for (s_idx = 0; s_idx < sizeof(sizes) / sizeof(sizes[0]); s_idx++) {
        size_t n = sizes[s_idx];
        size_t off;
        for (off = 0; off < 16; off++) {
            size_t i;
            memset(buf, 0xCC, sizeof(buf));
            areion_pq_zeroize(buf + off, n);
            for (i = 0; i < off; i++) {
                if (buf[i] != 0xCCu) {
                    (void)fprintf(stderr, "FAIL: areion_pq_zeroize clobbered prefix at off=%zu\n", off);
                    g_zeroize_failures++;
                    return;
                }
            }
            for (i = 0; i < n; i++) {
                if (buf[off + i] != 0x00u) {
                    (void)fprintf(stderr, "FAIL: areion_pq_zeroize failed at n=%zu off=%zu idx=%zu\n",
                                  n, off, i);
                    g_zeroize_failures++;
                    return;
                }
            }
            for (i = off + n; i < sizeof(buf); i++) {
                if (buf[i] != 0xCCu) {
                    (void)fprintf(stderr, "FAIL: areion_pq_zeroize clobbered suffix at n=%zu off=%zu\n",
                                  n, off);
                    g_zeroize_failures++;
                    return;
                }
            }
        }
    }
    printf("areion_pq_zeroize primitive ... OK\n");
}

/* =========================================================================
 * 2. Negative Controls (Proving Stack & SIMD/GPR Leak Detection)
 * ========================================================================= */

#if !AREION_PQ_SANITIZER_NO_STACK_PROBE
typedef struct {
    uint64_t secret;
    size_t idx;
} neg_stack_ctx_t;

static AREION_PQ_NOINLINE void leaky_areion_pq_frame(uint64_t secret, size_t idx) {
    volatile uint64_t frame[64];
    size_t j;
    for (j = 0; j < 64; j++) {
        frame[j] = secret;
    }
    g_areion_pq_sink = frame[(idx + 1U) % 64U];
}

static void cb_neg_stack(const void *p) {
    const neg_stack_ctx_t *c = (const neg_stack_ctx_t *)p;
    leaky_areion_pq_frame(c->secret, c->idx);
}
#endif

#if AREION_PQ_HAS_ASM_TEST_HELPERS
static void cb_neg_regs(const void *p) {
    const uint64_t *masked = (const uint64_t *)p;
    areion_pq_dirty_simd_reg_for_test(*masked);
}
#endif

static void test_negative_controls(uint64_t res[AREION_PQ_TOTAL_WORDS]) {
    res[0] = 0;

#if !AREION_PQ_SANITIZER_NO_STACK_PROBE
    {
        const uint64_t stack_canary = 0xCAFEBABE13579BDFULL;
        neg_stack_ctx_t sctx;
        target_list_t targets;
        uint64_t leaked = 0;
        size_t off = 0;
        size_t written;

        sctx.secret = stack_canary;
        sctx.idx = 3U;
        written = capture_areion_pq_frame_and_reg_residue(cb_neg_stack, &sctx, res);
        targets_init(&targets);
        targets.words[targets.count++] = stack_canary;
        if (written == 0 || !scan_for_areion_pq_words_in_stack(res, &targets, &leaked, &off)) {
            (void)fprintf(stderr, "FAIL: NegativeControl_Stack did not detect intentional stack canary\n");
            g_zeroize_failures++;
        } else {
            printf("NegativeControl_Stack ... OK (caught 0x%016llx at stack offset %u)\n",
                   (unsigned long long)leaked, (unsigned)off);
        }
    }
#else
    printf("NegativeControl_Stack ... SKIPPED (sanitizer fake-stack/shadow active)\n");
#endif

#if AREION_PQ_HAS_ASM_TEST_HELPERS
    {
        const uint64_t mask = 0x5555555555555555ULL;
        const uint64_t reg_secret = 0xFEEDFACECAFEBEEFULL;
        uint64_t masked = reg_secret ^ mask;
        target_list_t targets;
        uint64_t leaked = 0;
        size_t off = 0;
        size_t written;

        written = capture_areion_pq_frame_and_reg_residue(cb_neg_regs, &masked, res);
        targets_init(&targets);
        targets.words[targets.count++] = reg_secret;
        if (written == 0 || !scan_for_areion_pq_words_in_regs(res, &targets, &leaked, &off)) {
            (void)fprintf(stderr, "FAIL: NegativeControl_SIMDAndGPR did not detect intentional SIMD/GPR canary\n");
            g_zeroize_failures++;
        } else {
            printf("NegativeControl_SIMDAndGPR ... OK (caught 0x%016llx at reg dump offset %u)\n",
                   (unsigned long long)leaked, (unsigned)(off - AREION_PQ_RESIDUE_WINDOW));
        }
    }
#endif
}

/* =========================================================================
 * 3. Direct $0-Frame Assembly Kernel Hygiene Verification
 * ========================================================================= */

#if AREION_PQ_HAS_ASM_TEST_HELPERS
typedef void (*kern_witness_fn)(
    uint8_t c[32], uint8_t w[288],
    const uint8_t m[32], const uint8_t k1[32], const uint8_t k2[32],
    const uint8_t rc[10][16]);

typedef struct {
    kern_witness_fn fn;
    uint8_t *c;
    uint8_t *w;
    const uint8_t *m;
    const uint8_t *k1;
    const uint8_t *k2;
} kern_witness_ctx_t;

static void cb_kern_witness(const void *p) {
    const kern_witness_ctx_t *ctx = (const kern_witness_ctx_t *)p;
    ctx->fn(ctx->c, ctx->w, ctx->m, ctx->k1, ctx->k2, areion_pq_rc_p1);
}

static void run_kern_witness(
    const char *tier_name, const char *name, kern_witness_fn fn,
    uint64_t res[AREION_PQ_TOTAL_WORDS]) {
    AREION_PQ_ALIGN64 uint8_t m[32], k1[32], k2[32], c[32], w[288];
    kern_witness_ctx_t ctx;
    target_list_t targets;
    size_t i, written;

    for (i = 0; i < 32; i++) {
        m[i]  = (uint8_t)(0x11U + i * 3U);
        k1[i] = (uint8_t)(0x37U + i * 5U);
        k2[i] = (uint8_t)(0x73U + i * 7U);
    }
    memset(c, 0, sizeof(c));
    memset(w, 0, sizeof(w));
    ctx.fn = fn;
    ctx.c = c;
    ctx.w = w;
    ctx.m = m;
    ctx.k1 = k1;
    ctx.k2 = k2;
    written = capture_areion_pq_frame_and_reg_residue(cb_kern_witness, &ctx, res);
    AREION_PQ_MSAN_UNPOISON(c, sizeof(c));
    AREION_PQ_MSAN_UNPOISON(w, sizeof(w));
    targets_init(&targets);
    targets_add_bytes(&targets, m, sizeof(m));
    targets_add_bytes(&targets, k1, sizeof(k1));
    targets_add_bytes(&targets, k2, sizeof(k2));
    targets_add_bytes(&targets, c, sizeof(c));
    targets_add_bytes(&targets, w, 128U);
    assert_no_leak(tier_name, name, written, res, &targets);
}

typedef void (*kern_gf128_mul_fn)(uint8_t out[16], const uint8_t a[16], const uint8_t b[16]);

typedef struct {
    kern_gf128_mul_fn fn;
    uint8_t *out;
    const uint8_t *a;
    const uint8_t *b;
} kern_gf128_mul_ctx_t;

static void cb_kern_gf128_mul(const void *p) {
    const kern_gf128_mul_ctx_t *ctx = (const kern_gf128_mul_ctx_t *)p;
    ctx->fn(ctx->out, ctx->a, ctx->b);
}

static void run_kern_gf128_mul(
    const char *tier_name, const char *name, kern_gf128_mul_fn fn,
    uint64_t res[AREION_PQ_TOTAL_WORDS]) {
    AREION_PQ_ALIGN64 uint8_t a[16], b[16], out[16];
    kern_gf128_mul_ctx_t ctx;
    target_list_t targets;
    size_t i, written;

    for (i = 0; i < 16; i++) {
        a[i] = (uint8_t)(0x23U + i * 9U);
        b[i] = (uint8_t)(0x49U + i * 11U);
    }
    memset(out, 0, sizeof(out));
    ctx.fn = fn;
    ctx.out = out;
    ctx.a = a;
    ctx.b = b;
    written = capture_areion_pq_frame_and_reg_residue(cb_kern_gf128_mul, &ctx, res);
    AREION_PQ_MSAN_UNPOISON(out, sizeof(out));
    targets_init(&targets);
    targets_add_bytes(&targets, a, sizeof(a));
    targets_add_bytes(&targets, b, sizeof(b));
    targets_add_bytes(&targets, out, sizeof(out));
    assert_no_leak(tier_name, name, written, res, &targets);
}

typedef void (*kern_polymac_fn)(
    uint8_t acc[16], const uint8_t *a, const uint8_t *b, size_t count, const uint8_t chi[16]);

typedef struct {
    kern_polymac_fn fn;
    uint8_t *acc;
    const uint8_t *a;
    const uint8_t *b;
    size_t count;
    const uint8_t *chi;
} kern_polymac_ctx_t;

static void cb_kern_polymac(const void *p) {
    const kern_polymac_ctx_t *ctx = (const kern_polymac_ctx_t *)p;
    ctx->fn(ctx->acc, ctx->a, ctx->b, ctx->count, ctx->chi);
}

static void run_kern_polymac(
    const char *tier_name, const char *name, kern_polymac_fn fn,
    uint64_t res[AREION_PQ_TOTAL_WORDS]) {
    AREION_PQ_ALIGN64 uint8_t a[64], b[64], chi[16], acc[16];
    kern_polymac_ctx_t ctx;
    target_list_t targets;
    size_t i, written;

    for (i = 0; i < 64; i++) {
        a[i] = (uint8_t)(0x17U + i * 5U);
        b[i] = (uint8_t)(0x89U + i * 7U);
    }
    for (i = 0; i < 16; i++) {
        chi[i] = (uint8_t)(0xC1U + i * 3U);
        acc[i] = 0U;
    }
    ctx.fn = fn;
    ctx.acc = acc;
    ctx.a = a;
    ctx.b = b;
    ctx.count = 4U;
    ctx.chi = chi;
    written = capture_areion_pq_frame_and_reg_residue(cb_kern_polymac, &ctx, res);
    AREION_PQ_MSAN_UNPOISON(acc, sizeof(acc));
    targets_init(&targets);
    targets_add_bytes(&targets, a, sizeof(a));
    targets_add_bytes(&targets, b, sizeof(b));
    targets_add_bytes(&targets, chi, sizeof(chi));
    targets_add_bytes(&targets, acc, sizeof(acc));
    assert_no_leak(tier_name, name, written, res, &targets);
}

typedef void (*kern_vole_fn)(uint8_t *dst, const uint8_t *src, size_t len);

typedef struct {
    kern_vole_fn fn;
    uint8_t *dst;
    const uint8_t *src;
    size_t len;
} kern_vole_ctx_t;

static void cb_kern_vole(const void *p) {
    const kern_vole_ctx_t *ctx = (const kern_vole_ctx_t *)p;
    ctx->fn(ctx->dst, ctx->src, ctx->len);
}

static void run_kern_vole(
    const char *tier_name, const char *name, kern_vole_fn fn,
    uint64_t res[AREION_PQ_TOTAL_WORDS]) {
    AREION_PQ_ALIGN64 uint8_t src[135], dst[135];
    kern_vole_ctx_t ctx;
    target_list_t targets;
    size_t i, written;

    for (i = 0; i < sizeof(src); i++) {
        src[i] = (uint8_t)(0x3BU + i * 13U);
        dst[i] = (uint8_t)(0x6DU + i * 17U);
    }
    ctx.fn = fn;
    ctx.dst = dst;
    ctx.src = src;
    ctx.len = sizeof(src);
    written = capture_areion_pq_frame_and_reg_residue(cb_kern_vole, &ctx, res);
    AREION_PQ_MSAN_UNPOISON(dst, sizeof(dst));
    targets_init(&targets);
    targets_add_bytes(&targets, src, 128U);
    targets_add_bytes(&targets, dst, 128U);
    assert_no_leak(tier_name, name, written, res, &targets);
}

static void test_direct_asm_kernels(uint64_t res[AREION_PQ_TOTAL_WORDS]) {
#if defined(__x86_64__) || defined(_M_X64)
    if (areion_pq_tier_supported(AREION_PQ_TIER_AESNI)) {
        run_kern_witness("aesni", "areion_pq_extract_witness256_aesni",
                         areion_pq_extract_witness256_aesni, res);
        run_kern_vole("aesni", "areion_pq_vole_xor_row_sse2",
                      areion_pq_vole_xor_row_sse2, res);
    }
    if (areion_pq_tier_supported(AREION_PQ_TIER_VEX)) {
        run_kern_witness("vex", "areion_pq_extract_witness256_vex",
                         areion_pq_extract_witness256_vex, res);
    }
    if (areion_pq_has_pclmul()) {
        run_kern_gf128_mul("aesni", "areion_pq_gf128_mul_pclmul",
                           areion_pq_gf128_mul_pclmul, res);
        run_kern_polymac("aesni", "areion_pq_gf128_polymac_pclmul",
                         areion_pq_gf128_polymac_pclmul, res);
    }
    if (areion_pq_has_vpclmul()) {
        run_kern_gf128_mul("vex", "areion_pq_gf128_mul_vpclmul",
                           areion_pq_gf128_mul_vpclmul, res);
        run_kern_polymac("vex", "areion_pq_gf128_polymac_vpclmul",
                         areion_pq_gf128_polymac_vpclmul, res);
    }
    if (areion_pq_tier_supported(AREION_PQ_TIER_VAESAVX2)) {
        run_kern_vole("vaesavx2", "areion_pq_vole_xor_row_avx2",
                      areion_pq_vole_xor_row_avx2, res);
    }
    if (areion_pq_tier_supported(AREION_PQ_TIER_AVX512)) {
        run_kern_vole("avx512", "areion_pq_vole_xor_row_avx512",
                      areion_pq_vole_xor_row_avx512, res);
    }
#elif defined(__aarch64__) || defined(_M_ARM64)
    if (areion_pq_tier_supported(AREION_PQ_TIER_ARM64)) {
        run_kern_witness("arm64", "areion_pq_extract_witness256_arm64",
                         areion_pq_extract_witness256_arm64, res);
        run_kern_vole("arm64", "areion_pq_vole_xor_row_neon",
                      areion_pq_vole_xor_row_neon, res);
    }
    if (areion_pq_has_pmull()) {
        run_kern_gf128_mul("arm64", "areion_pq_gf128_mul_pmull",
                           areion_pq_gf128_mul_pmull, res);
        run_kern_polymac("arm64", "areion_pq_gf128_polymac_pmull",
                         areion_pq_gf128_polymac_pmull, res);
    }
#endif
    printf("direct $0-frame assembly kernels ... OK\n");
}
#endif /* AREION_PQ_HAS_ASM_TEST_HELPERS */

/* =========================================================================
 * 4. Public API Secret-Residue Scans Across All Supported Tiers
 * ========================================================================= */

typedef struct {
    uint8_t secret[128];
} public_api_ctx_t;

static void cb_public_witness(const void *p) {
    const public_api_ctx_t *ctx = (const public_api_ctx_t *)p;
    uint8_t c[32];
    uint8_t w256[AREION_PQ_WITNESS256_SIZE];
    uint8_t wem[AREION_PQ_WITNESS_EM2_256_SIZE];
    int ok;

    areion_pq_extract_witness256(c, w256, ctx->secret, ctx->secret + 32, ctx->secret + 64);
    ok = areion_pq_verify_witness256(ctx->secret, c, ctx->secret + 32, ctx->secret + 64, w256);
    (void)ok;
    areion_pq_extract_witness256_p2(c, w256, ctx->secret, ctx->secret + 32, ctx->secret + 64);
    ok = areion_pq_verify_witness256_p2(ctx->secret, c, ctx->secret + 32, ctx->secret + 64, w256);
    (void)ok;
    areion_pq_extract_witness_em2_256(c, wem, ctx->secret, ctx->secret + 32, ctx->secret + 64);
    ok = areion_pq_verify_witness_em2_256(ctx->secret, c, ctx->secret + 32, ctx->secret + 64, wem);
    (void)ok;

    areion_pq_zeroize(c, sizeof(c));
    areion_pq_zeroize(w256, sizeof(w256));
    areion_pq_zeroize(wem, sizeof(wem));
}

static void cb_public_kdf_aead_hpke(const void *p) {
    const public_api_ctx_t *ctx = (const public_api_ctx_t *)p;
    static const uint8_t aad[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    static const uint8_t nonce[32] = {0};
    static const char context_str[] = "areion-pq-zeroize";
    static const char info_str[] = "hpke-info";
    uint8_t okm[128];
    uint8_t pt[96];
    uint8_t ct[96];
    uint8_t dec[96];
    uint8_t tag[32];
    int ok;

    memset(pt, 0x42, sizeof(pt));
    areion_pq_kdf_expand(okm, sizeof(okm), ctx->secret, 32,
                         (const uint8_t *)context_str, sizeof(context_str) - 1U);
    areion_pq_tem2_siv_encrypt(ct, tag, ctx->secret, nonce, aad, sizeof(aad), pt, sizeof(pt));
    ok = areion_pq_tem2_siv_decrypt(dec, ctx->secret, nonce, aad, sizeof(aad), ct, sizeof(ct), tag);
    (void)ok;

    areion_pq_hpke_seal_det(ct, tag, ctx->secret,
                            (const uint8_t *)info_str, sizeof(info_str) - 1U,
                            0ULL, aad, sizeof(aad), pt, sizeof(pt));
    ok = areion_pq_hpke_open_det(dec, ctx->secret,
                                 (const uint8_t *)info_str, sizeof(info_str) - 1U,
                                 0ULL, aad, sizeof(aad), ct, sizeof(ct), tag);
    (void)ok;

    areion_pq_zeroize(okm, sizeof(okm));
    areion_pq_zeroize(pt, sizeof(pt));
    areion_pq_zeroize(ct, sizeof(ct));
    areion_pq_zeroize(dec, sizeof(dec));
    areion_pq_zeroize(tag, sizeof(tag));
}

static void cb_public_keygen(const void *p) {
    const public_api_ctx_t *ctx = (const public_api_ctx_t *)p;
    uint8_t f_pk[AREION_PQ_FAEST128_PUBLIC_KEY_SIZE];
    uint8_t f_sk[AREION_PQ_FAEST128_SECRET_KEY_SIZE];
    uint8_t s_pk[AREION_PQ_SLHDSA128_PUBLIC_KEY_SIZE];
    uint8_t s_sk[AREION_PQ_SLHDSA128_SECRET_KEY_SIZE];

    areion_pq_faest_keygen128f(f_pk, f_sk, ctx->secret);
    areion_pq_slhdsa_keygen128f(s_pk, s_sk, ctx->secret);

    areion_pq_zeroize(f_pk, sizeof(f_pk));
    areion_pq_zeroize(f_sk, sizeof(f_sk));
    areion_pq_zeroize(s_pk, sizeof(s_pk));
    areion_pq_zeroize(s_sk, sizeof(s_sk));
}

static void test_public_api_across_tiers(uint64_t res[AREION_PQ_TOTAL_WORDS]) {
    static const char *const tiers[] = {
        "purec", "aesni", "vex", "vaesavx2", "avx512", "arm64"
    };
    public_api_ctx_t ctx;
    target_list_t targets;
    size_t i, t;

    for (i = 0; i < sizeof(ctx.secret); i++) {
        ctx.secret[i] = (uint8_t)(((i * 29U + 17U) & 0x7FU) | 0x80U);
    }
    targets_init(&targets);
    targets_add_bytes(&targets, ctx.secret, sizeof(ctx.secret));

    for (t = 0; t < sizeof(tiers) / sizeof(tiers[0]); t++) {
        size_t written;
        if (areion_pq_set_tier(tiers[t]) != 0) {
            continue;
        }

        written = capture_areion_pq_frame_and_reg_residue(cb_public_witness, &ctx, res);
        assert_no_leak(tiers[t], "public_witness_ops", written, res, &targets);

        written = capture_areion_pq_frame_and_reg_residue(cb_public_kdf_aead_hpke, &ctx, res);
        assert_no_leak(tiers[t], "public_kdf_aead_hpke_ops", written, res, &targets);

        written = capture_areion_pq_frame_and_reg_residue(cb_public_keygen, &ctx, res);
        assert_no_leak(tiers[t], "public_keygen_ops", written, res, &targets);
    }

    (void)areion_pq_set_tier("auto");
    areion_pq_zeroize(&ctx, sizeof(ctx));
    printf("public API secret-residue scan across all supported tiers ... OK\n");
}

/* =========================================================================
 * 5. Failed-Authentication Output Buffer Zeroization
 * ========================================================================= */

static void test_failed_decrypt_zeroization(void) {
    uint8_t key[AREION_PQ_TEM2_SIV_KEY_SIZE];
    uint8_t nonce[AREION_PQ_TEM2_SIV_NONCE_SIZE];
    uint8_t aad[16];
    uint8_t pt[100];
    uint8_t ct[100];
    uint8_t dec[100];
    uint8_t tag[AREION_PQ_TEM2_SIV_TAG_SIZE];
    static const uint8_t info[4] = {'i', 'n', 'f', 'o'};
    size_t i;

    for (i = 0; i < sizeof(key); i++) key[i] = (uint8_t)(i + 1u);
    for (i = 0; i < sizeof(nonce); i++) nonce[i] = (uint8_t)(i + 0x20u);
    for (i = 0; i < sizeof(aad); i++) aad[i] = (uint8_t)(i + 0x40u);
    for (i = 0; i < sizeof(pt); i++) pt[i] = (uint8_t)(i ^ 0x55u);

    areion_pq_tem2_siv_encrypt(ct, tag, key, nonce, aad, sizeof(aad), pt, sizeof(pt));
    tag[0] ^= 0x01u;
    memset(dec, 0xAA, sizeof(dec));
    if (areion_pq_tem2_siv_decrypt(dec, key, nonce, aad, sizeof(aad), ct, sizeof(ct), tag) != 0) {
        (void)fprintf(stderr, "FAIL: tem2_siv_decrypt succeeded with forged tag\n");
        g_zeroize_failures++;
        return;
    }
    for (i = 0; i < sizeof(dec); i++) {
        if (dec[i] != 0x00u) {
            (void)fprintf(stderr, "FAIL: tem2_siv_decrypt did not zeroize plaintext[%zu] on auth failure\n", i);
            g_zeroize_failures++;
            return;
        }
    }

    areion_pq_hpke_seal_det(ct, tag, key, info, sizeof(info), 7ULL, aad, sizeof(aad), pt, sizeof(pt));
    tag[31] ^= 0x80u;
    memset(dec, 0xBB, sizeof(dec));
    if (areion_pq_hpke_open_det(dec, key, info, sizeof(info), 7ULL, aad, sizeof(aad), ct, sizeof(ct), tag) != 0) {
        (void)fprintf(stderr, "FAIL: hpke_open_det succeeded with forged tag\n");
        g_zeroize_failures++;
        return;
    }
    for (i = 0; i < sizeof(dec); i++) {
        if (dec[i] != 0x00u) {
            (void)fprintf(stderr, "FAIL: hpke_open_det did not zeroize plaintext[%zu] on auth failure\n", i);
            g_zeroize_failures++;
            return;
        }
    }

    areion_pq_zeroize(key, sizeof(key));
    printf("failed-authentication output buffer zeroization ... OK\n");
}

/* =========================================================================
 * 6. Valgrind/Memcheck Timecop Constant-Time Taint Checks
 * ========================================================================= */

static void test_timecop_taint(void) {
    uint8_t secret[128];
    uint8_t c[32];
    uint8_t w[AREION_PQ_WITNESS256_SIZE];
    uint8_t nonce[32] = {0};
    uint8_t aad[16] = {1, 2, 3, 4};
    uint8_t pt[64] = {0};
    uint8_t ct[64];
    uint8_t dec[64];
    uint8_t tag[32];
    int ok;
    size_t i;

    for (i = 0; i < sizeof(secret); i++) {
        secret[i] = (uint8_t)(i * 7u + 3u);
    }

    TIMECOP_POISON(secret, sizeof(secret));
    TIMECOP_POISON(pt, sizeof(pt));

    areion_pq_extract_witness256(c, w, secret, secret + 32, secret + 64);
    TIMECOP_UNPOISON(c, sizeof(c));
    ok = areion_pq_verify_witness256(secret, c, secret + 32, secret + 64, w);
    TIMECOP_UNPOISON(&ok, sizeof(ok));
    if (ok != 1) {
        TIMECOP_UNPOISON(secret, sizeof(secret));
        TIMECOP_UNPOISON(pt, sizeof(pt));
        TIMECOP_UNPOISON(w, sizeof(w));
        (void)fprintf(stderr, "FAIL: timecop verify_witness256 failed\n");
        g_zeroize_failures++;
        return;
    }

    areion_pq_tem2_siv_encrypt(ct, tag, secret, nonce, aad, sizeof(aad), pt, sizeof(pt));
    ok = areion_pq_tem2_siv_decrypt(dec, secret, nonce, aad, sizeof(aad), ct, sizeof(ct), tag);
    TIMECOP_UNPOISON(&ok, sizeof(ok));
    TIMECOP_UNPOISON(secret, sizeof(secret));
    TIMECOP_UNPOISON(pt, sizeof(pt));
    TIMECOP_UNPOISON(ct, sizeof(ct));
    TIMECOP_UNPOISON(dec, sizeof(dec));
    TIMECOP_UNPOISON(tag, sizeof(tag));
    TIMECOP_UNPOISON(w, sizeof(w));

    if (ok != 1) {
        (void)fprintf(stderr, "FAIL: timecop tem2_siv_decrypt failed\n");
        g_zeroize_failures++;
        return;
    }

    areion_pq_zeroize(secret, sizeof(secret));
    areion_pq_zeroize(w, sizeof(w));
    printf("Timecop constant-time secret-taint verification ... OK\n");
}

int main(void) {
    uint64_t *res = (uint64_t *)calloc(AREION_PQ_TOTAL_WORDS, sizeof(uint64_t));
    if (res == NULL) {
        (void)fprintf(stderr, "FAIL: out of memory allocating residue buffer\n");
        return 1;
    }

    printf("=== areion-pq-c zeroize & register-hygiene suite (active tier: %s) ===\n",
           areion_pq_tier());

    test_zeroize_primitive();
    test_negative_controls(res);
#if AREION_PQ_HAS_ASM_TEST_HELPERS
    test_direct_asm_kernels(res);
#endif
    test_public_api_across_tiers(res);
    test_failed_decrypt_zeroization();
    test_timecop_taint();

    free(res);

    if (g_zeroize_failures != 0) {
        (void)fprintf(stderr, "FAIL: %d zeroize/hygiene check(s) failed\n", g_zeroize_failures);
        return 1;
    }

    printf("ALL AREION-PQ-C ZEROIZE TESTS PASSED.\n");
    return 0;
}
