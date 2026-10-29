/*
 * Copyright (c) 2026 Andrey Kuvshinov
 *
 * Dual-licensed under Apache-2.0 OR MIT.
 * See LICENSE-APACHE and LICENSE-MIT for details.
 */

#if defined(__x86_64__) || defined(_M_X64)
#include "asm_abi.h"

.text

AREION_FUNC_START(areion_pq_extract_witness256_aesni)
#if !defined(_WIN64)
    movq %rdi, %rax
    movq %rsi, %r10
    movq %r8, %r11
#else
    movq %rcx, %rax
    movq %rdx, %r10
    movq %r8, %rdx
    movq %r9, %rcx
    movq 40(%rsp), %r11
    movq 48(%rsp), %r9
#endif
    movdqu 0(%rdx), %xmm0
    movdqu 16(%rdx), %xmm1
    movdqu 0(%rcx), %xmm2
    movdqu 16(%rcx), %xmm3
    pxor %xmm2, %xmm0
    pxor %xmm3, %xmm1
    pxor %xmm4, %xmm4

    /* Round 0 (even: active xmm0, passive xmm1) */
    movdqu 0(%r9), %xmm2
    movdqa %xmm0, %xmm3
    aesenc %xmm2, %xmm3
    aesenc %xmm1, %xmm3
    aesenclast %xmm4, %xmm0
    movdqa %xmm3, %xmm1
    movdqu %xmm0, 0(%r10)
    movdqu %xmm1, 16(%r10)

    /* Round 1 (odd: active xmm1, passive xmm0) */
    movdqu 16(%r9), %xmm2
    movdqa %xmm1, %xmm3
    aesenc %xmm2, %xmm3
    aesenc %xmm0, %xmm3
    aesenclast %xmm4, %xmm1
    movdqa %xmm3, %xmm0
    movdqu %xmm1, 32(%r10)
    movdqu %xmm0, 48(%r10)

    /* Round 2 (even: active xmm0, passive xmm1) */
    movdqu 32(%r9), %xmm2
    movdqa %xmm0, %xmm3
    aesenc %xmm2, %xmm3
    aesenc %xmm1, %xmm3
    aesenclast %xmm4, %xmm0
    movdqa %xmm3, %xmm1
    movdqu %xmm0, 64(%r10)
    movdqu %xmm1, 80(%r10)

    /* Round 3 (odd: active xmm1, passive xmm0) */
    movdqu 48(%r9), %xmm2
    movdqa %xmm1, %xmm3
    aesenc %xmm2, %xmm3
    aesenc %xmm0, %xmm3
    aesenclast %xmm4, %xmm1
    movdqa %xmm3, %xmm0
    movdqu %xmm1, 96(%r10)
    movdqu %xmm0, 112(%r10)

    /* Round 4 (even: active xmm0, passive xmm1) */
    movdqu 64(%r9), %xmm2
    movdqa %xmm0, %xmm3
    aesenc %xmm2, %xmm3
    aesenc %xmm1, %xmm3
    aesenclast %xmm4, %xmm0
    movdqa %xmm3, %xmm1
    movdqu %xmm0, 128(%r10)
    movdqu %xmm1, 144(%r10)

    /* Round 5 (odd: active xmm1, passive xmm0) */
    movdqu 80(%r9), %xmm2
    movdqa %xmm1, %xmm3
    aesenc %xmm2, %xmm3
    aesenc %xmm0, %xmm3
    aesenclast %xmm4, %xmm1
    movdqa %xmm3, %xmm0
    movdqu %xmm1, 160(%r10)
    movdqu %xmm0, 176(%r10)

    /* Round 6 (even: active xmm0, passive xmm1) */
    movdqu 96(%r9), %xmm2
    movdqa %xmm0, %xmm3
    aesenc %xmm2, %xmm3
    aesenc %xmm1, %xmm3
    aesenclast %xmm4, %xmm0
    movdqa %xmm3, %xmm1
    movdqu %xmm0, 192(%r10)
    movdqu %xmm1, 208(%r10)

    /* Round 7 (odd: active xmm1, passive xmm0) */
    movdqu 112(%r9), %xmm2
    movdqa %xmm1, %xmm3
    aesenc %xmm2, %xmm3
    aesenc %xmm0, %xmm3
    aesenclast %xmm4, %xmm1
    movdqa %xmm3, %xmm0
    movdqu %xmm1, 224(%r10)
    movdqu %xmm0, 240(%r10)

    /* Round 8 (even: active xmm0, passive xmm1) */
    movdqu 128(%r9), %xmm2
    movdqa %xmm0, %xmm3
    aesenc %xmm2, %xmm3
    aesenc %xmm1, %xmm3
    aesenclast %xmm4, %xmm0
    movdqa %xmm3, %xmm1
    movdqu %xmm0, 256(%r10)
    movdqu %xmm1, 272(%r10)

    /* Round 9 (odd: active xmm1, passive xmm0) */
    movdqu 144(%r9), %xmm2
    movdqa %xmm1, %xmm3
    aesenc %xmm2, %xmm3
    aesenc %xmm0, %xmm3
    aesenclast %xmm4, %xmm1
    movdqa %xmm3, %xmm0

    /* Post-whitening with k2 */
    movdqu 0(%r11), %xmm2
    movdqu 16(%r11), %xmm3
    pxor %xmm2, %xmm0
    pxor %xmm3, %xmm1
    movdqu %xmm0, 0(%rax)
    movdqu %xmm1, 16(%rax)

    pxor %xmm0, %xmm0
    pxor %xmm1, %xmm1
    pxor %xmm2, %xmm2
    pxor %xmm3, %xmm3
    pxor %xmm4, %xmm4
#if !defined(_WIN64)
    xorq %rdi, %rdi
    xorq %rsi, %rsi
#endif
    xorq %rax, %rax
    xorq %rcx, %rcx
    xorq %rdx, %rdx
    xorq %r8, %r8
    xorq %r9, %r9
    xorq %r10, %r10
    xorq %r11, %r11
    ret
AREION_FUNC_END(areion_pq_extract_witness256_aesni)

AREION_FUNC_START(areion_pq_extract_witness256_vex)
#if !defined(_WIN64)
    movq %rdi, %rax
    movq %rsi, %r10
    movq %r8, %r11
#else
    movq %rcx, %rax
    movq %rdx, %r10
    movq %r8, %rdx
    movq %r9, %rcx
    movq 40(%rsp), %r11
    movq 48(%rsp), %r9
#endif
    vmovdqu 0(%rdx), %xmm0
    vmovdqu 16(%rdx), %xmm1
    vpxor 0(%rcx), %xmm0, %xmm0
    vpxor 16(%rcx), %xmm1, %xmm1
    vpxor %xmm4, %xmm4, %xmm4

    /* Round 0 (even: active xmm0, passive xmm1) */
    vaesenc 0(%r9), %xmm0, %xmm3
    vaesenclast %xmm4, %xmm0, %xmm0
    vaesenc %xmm1, %xmm3, %xmm1
    vmovdqu %xmm0, 0(%r10)
    vmovdqu %xmm1, 16(%r10)

    /* Round 1 (odd: active xmm1, passive xmm0) */
    vaesenc 16(%r9), %xmm1, %xmm3
    vaesenclast %xmm4, %xmm1, %xmm1
    vaesenc %xmm0, %xmm3, %xmm0
    vmovdqu %xmm1, 32(%r10)
    vmovdqu %xmm0, 48(%r10)

    /* Round 2 (even: active xmm0, passive xmm1) */
    vaesenc 32(%r9), %xmm0, %xmm3
    vaesenclast %xmm4, %xmm0, %xmm0
    vaesenc %xmm1, %xmm3, %xmm1
    vmovdqu %xmm0, 64(%r10)
    vmovdqu %xmm1, 80(%r10)

    /* Round 3 (odd: active xmm1, passive xmm0) */
    vaesenc 48(%r9), %xmm1, %xmm3
    vaesenclast %xmm4, %xmm1, %xmm1
    vaesenc %xmm0, %xmm3, %xmm0
    vmovdqu %xmm1, 96(%r10)
    vmovdqu %xmm0, 112(%r10)

    /* Round 4 (even: active xmm0, passive xmm1) */
    vaesenc 64(%r9), %xmm0, %xmm3
    vaesenclast %xmm4, %xmm0, %xmm0
    vaesenc %xmm1, %xmm3, %xmm1
    vmovdqu %xmm0, 128(%r10)
    vmovdqu %xmm1, 144(%r10)

    /* Round 5 (odd: active xmm1, passive xmm0) */
    vaesenc 80(%r9), %xmm1, %xmm3
    vaesenclast %xmm4, %xmm1, %xmm1
    vaesenc %xmm0, %xmm3, %xmm0
    vmovdqu %xmm1, 160(%r10)
    vmovdqu %xmm0, 176(%r10)

    /* Round 6 (even: active xmm0, passive xmm1) */
    vaesenc 96(%r9), %xmm0, %xmm3
    vaesenclast %xmm4, %xmm0, %xmm0
    vaesenc %xmm1, %xmm3, %xmm1
    vmovdqu %xmm0, 192(%r10)
    vmovdqu %xmm1, 208(%r10)

    /* Round 7 (odd: active xmm1, passive xmm0) */
    vaesenc 112(%r9), %xmm1, %xmm3
    vaesenclast %xmm4, %xmm1, %xmm1
    vaesenc %xmm0, %xmm3, %xmm0
    vmovdqu %xmm1, 224(%r10)
    vmovdqu %xmm0, 240(%r10)

    /* Round 8 (even: active xmm0, passive xmm1) */
    vaesenc 128(%r9), %xmm0, %xmm3
    vaesenclast %xmm4, %xmm0, %xmm0
    vaesenc %xmm1, %xmm3, %xmm1
    vmovdqu %xmm0, 256(%r10)
    vmovdqu %xmm1, 272(%r10)

    /* Round 9 (odd: active xmm1, passive xmm0) */
    vaesenc 144(%r9), %xmm1, %xmm3
    vaesenclast %xmm4, %xmm1, %xmm1
    vaesenc %xmm0, %xmm3, %xmm0

    /* Post-whitening with k2 */
    vpxor 0(%r11), %xmm0, %xmm0
    vpxor 16(%r11), %xmm1, %xmm1
    vmovdqu %xmm0, 0(%rax)
    vmovdqu %xmm1, 16(%rax)

    vpxor %xmm0, %xmm0, %xmm0
    vpxor %xmm1, %xmm1, %xmm1
    vpxor %xmm3, %xmm3, %xmm3
    vpxor %xmm4, %xmm4, %xmm4
#if !defined(_WIN64)
    xorq %rdi, %rdi
    xorq %rsi, %rsi
#endif
    xorq %rax, %rax
    xorq %rcx, %rcx
    xorq %rdx, %rdx
    xorq %r8, %r8
    xorq %r9, %r9
    xorq %r10, %r10
    xorq %r11, %r11
    ret
AREION_FUNC_END(areion_pq_extract_witness256_vex)

AREION_FUNC_START(areion_pq_gf128_mul_pclmul)
#if !defined(_WIN64)
    movq %rdi, %rax
    movq %rsi, %r8
    movq %rdx, %r9
#else
    movq %rcx, %rax
    movq %r8, %r9
    movq %rdx, %r8
#endif
    movdqu (%r8), %xmm0
    movdqu (%r9), %xmm1

    movdqa %xmm0, %xmm2
    pclmulqdq $0x00, %xmm1, %xmm2

    movdqa %xmm0, %xmm3
    pclmulqdq $0x11, %xmm1, %xmm3

    movdqa %xmm0, %xmm4
    psrldq $8, %xmm4
    pxor %xmm0, %xmm4
    movdqa %xmm1, %xmm5
    psrldq $8, %xmm5
    pxor %xmm1, %xmm5
    pclmulqdq $0x00, %xmm5, %xmm4
    pxor %xmm2, %xmm4
    pxor %xmm3, %xmm4

    movdqa %xmm4, %xmm5
    pslldq $8, %xmm5
    pxor %xmm5, %xmm2
    psrldq $8, %xmm4
    pxor %xmm4, %xmm3

    movq $0x87, %r10
    movq %r10, %xmm0
    punpcklqdq %xmm0, %xmm0

    movdqa %xmm3, %xmm4
    pclmulqdq $0x11, %xmm0, %xmm4
    movdqa %xmm4, %xmm5
    pslldq $8, %xmm5
    pxor %xmm5, %xmm2
    psrldq $8, %xmm4
    pxor %xmm4, %xmm3

    pclmulqdq $0x00, %xmm0, %xmm3
    pxor %xmm3, %xmm2

    movdqu %xmm2, (%rax)

    pxor %xmm0, %xmm0
    pxor %xmm1, %xmm1
    pxor %xmm2, %xmm2
    pxor %xmm3, %xmm3
    pxor %xmm4, %xmm4
    pxor %xmm5, %xmm5
#if !defined(_WIN64)
    xorq %rdi, %rdi
    xorq %rsi, %rsi
#else
    xorq %rcx, %rcx
#endif
    xorq %rax, %rax
    xorq %rdx, %rdx
    xorq %r8, %r8
    xorq %r9, %r9
    xorq %r10, %r10
    ret
AREION_FUNC_END(areion_pq_gf128_mul_pclmul)

AREION_FUNC_START(areion_pq_gf128_mul_vpclmul)
#if !defined(_WIN64)
    movq %rdi, %rax
    movq %rsi, %r8
    movq %rdx, %r9
#else
    movq %rcx, %rax
    movq %r8, %r9
    movq %rdx, %r8
#endif
    vmovdqu (%r8), %xmm0
    vmovdqu (%r9), %xmm1

    vpclmulqdq $0x00, %xmm1, %xmm0, %xmm2
    vpclmulqdq $0x11, %xmm1, %xmm0, %xmm3

    vpsrldq $8, %xmm0, %xmm4
    vpxor %xmm0, %xmm4, %xmm4
    vpsrldq $8, %xmm1, %xmm5
    vpxor %xmm1, %xmm5, %xmm5
    vpclmulqdq $0x00, %xmm5, %xmm4, %xmm4
    vpxor %xmm2, %xmm4, %xmm4
    vpxor %xmm3, %xmm4, %xmm4

    vpslldq $8, %xmm4, %xmm5
    vpxor %xmm5, %xmm2, %xmm2
    vpsrldq $8, %xmm4, %xmm4
    vpxor %xmm4, %xmm3, %xmm3

    movq $0x87, %r10
    vmovq %r10, %xmm0
    vpunpcklqdq %xmm0, %xmm0, %xmm0

    vpclmulqdq $0x11, %xmm0, %xmm3, %xmm4
    vpslldq $8, %xmm4, %xmm5
    vpxor %xmm5, %xmm2, %xmm2
    vpsrldq $8, %xmm4, %xmm4
    vpxor %xmm4, %xmm3, %xmm3

    vpclmulqdq $0x00, %xmm0, %xmm3, %xmm3
    vpxor %xmm3, %xmm2, %xmm2

    vmovdqu %xmm2, (%rax)

    vpxor %xmm0, %xmm0, %xmm0
    vpxor %xmm1, %xmm1, %xmm1
    vpxor %xmm2, %xmm2, %xmm2
    vpxor %xmm3, %xmm3, %xmm3
    vpxor %xmm4, %xmm4, %xmm4
    vpxor %xmm5, %xmm5, %xmm5
#if !defined(_WIN64)
    xorq %rdi, %rdi
    xorq %rsi, %rsi
#else
    xorq %rcx, %rcx
#endif
    xorq %rax, %rax
    xorq %rdx, %rdx
    xorq %r8, %r8
    xorq %r9, %r9
    xorq %r10, %r10
    ret
AREION_FUNC_END(areion_pq_gf128_mul_vpclmul)

AREION_FUNC_START(areion_pq_gf128_polymac_pclmul)
#if !defined(_WIN64)
    movq %rdi, %rax
    movq %r8, %r11
    movq %rsi, %r8
    movq %rdx, %r9
    movq %rcx, %r10
#else
    movq %rcx, %rax
    movq %r8, %rcx
    movq %rdx, %r8
    movq %r9, %r10
    movq %rcx, %r9
    movq 40(%rsp), %r11
#endif
    testq %r10, %r10
    jle .Lpolymac_pclmul_done

    movdqu (%rax), %xmm0
    movq $0x87, %rcx

.Lpolymac_pclmul_loop:
    /* 1. Multiply acc (xmm0) by chi -> unreduced (xmm2, xmm3) */
    movdqu (%r11), %xmm1
    movdqa %xmm0, %xmm2
    pclmulqdq $0x00, %xmm1, %xmm2
    movdqa %xmm0, %xmm3
    pclmulqdq $0x11, %xmm1, %xmm3
    movdqa %xmm0, %xmm4
    psrldq $8, %xmm4
    pxor %xmm0, %xmm4
    movdqa %xmm1, %xmm5
    psrldq $8, %xmm5
    pxor %xmm1, %xmm5
    pclmulqdq $0x00, %xmm5, %xmm4
    pxor %xmm2, %xmm4
    pxor %xmm3, %xmm4
    movdqa %xmm4, %xmm5
    pslldq $8, %xmm5
    pxor %xmm5, %xmm2
    psrldq $8, %xmm4
    pxor %xmm4, %xmm3

    /* 2. Multiply a_i by b_i and accumulate into (xmm2, xmm3) */
    movdqu (%r8), %xmm0
    movdqu (%r9), %xmm1
    movdqa %xmm0, %xmm4
    psrldq $8, %xmm4
    pxor %xmm0, %xmm4
    movdqa %xmm1, %xmm5
    psrldq $8, %xmm5
    pxor %xmm1, %xmm5
    pclmulqdq $0x00, %xmm5, %xmm4

    movdqa %xmm0, %xmm5
    pclmulqdq $0x00, %xmm1, %xmm5
    pxor %xmm5, %xmm4
    pxor %xmm5, %xmm2

    movdqa %xmm0, %xmm5
    pclmulqdq $0x11, %xmm1, %xmm5
    pxor %xmm5, %xmm4
    pxor %xmm5, %xmm3

    movdqa %xmm4, %xmm5
    pslldq $8, %xmm5
    pxor %xmm5, %xmm2
    psrldq $8, %xmm4
    pxor %xmm4, %xmm3

    /* 3. Reduce modulo x^128 + x^7 + x^2 + x + 1 */
    movq %rcx, %xmm0
    punpcklqdq %xmm0, %xmm0
    movdqa %xmm3, %xmm4
    pclmulqdq $0x11, %xmm0, %xmm4
    movdqa %xmm4, %xmm5
    pslldq $8, %xmm5
    pxor %xmm5, %xmm2
    psrldq $8, %xmm4
    pxor %xmm4, %xmm3

    pclmulqdq $0x00, %xmm0, %xmm3
    pxor %xmm3, %xmm2
    movdqa %xmm2, %xmm0

    addq $16, %r8
    addq $16, %r9
    decq %r10
    jnz .Lpolymac_pclmul_loop

    movdqu %xmm0, (%rax)

.Lpolymac_pclmul_done:
    pxor %xmm0, %xmm0
    pxor %xmm1, %xmm1
    pxor %xmm2, %xmm2
    pxor %xmm3, %xmm3
    pxor %xmm4, %xmm4
    pxor %xmm5, %xmm5
#if !defined(_WIN64)
    xorq %rdi, %rdi
    xorq %rsi, %rsi
#endif
    xorq %rax, %rax
    xorq %rcx, %rcx
    xorq %rdx, %rdx
    xorq %r8, %r8
    xorq %r9, %r9
    xorq %r10, %r10
    xorq %r11, %r11
    ret
AREION_FUNC_END(areion_pq_gf128_polymac_pclmul)

AREION_FUNC_START(areion_pq_gf128_polymac_vpclmul)
#if !defined(_WIN64)
    movq %rdi, %rax
    movq %r8, %r11
    movq %rsi, %r8
    movq %rdx, %r9
    movq %rcx, %r10
#else
    movq %rcx, %rax
    movq %r8, %rcx
    movq %rdx, %r8
    movq %r9, %r10
    movq %rcx, %r9
    movq 40(%rsp), %r11
#endif
    testq %r10, %r10
    jle .Lpolymac_vpclmul_done

    vmovdqu (%rax), %xmm0
    movq $0x87, %rcx

.Lpolymac_vpclmul_loop:
    /* 1. Multiply acc (xmm0) by chi -> unreduced (xmm2, xmm3) */
    vmovdqu (%r11), %xmm1
    vpclmulqdq $0x00, %xmm1, %xmm0, %xmm2
    vpclmulqdq $0x11, %xmm1, %xmm0, %xmm3
    vpsrldq $8, %xmm0, %xmm4
    vpxor %xmm0, %xmm4, %xmm4
    vpsrldq $8, %xmm1, %xmm5
    vpxor %xmm1, %xmm5, %xmm5
    vpclmulqdq $0x00, %xmm5, %xmm4, %xmm4
    vpxor %xmm2, %xmm4, %xmm4
    vpxor %xmm3, %xmm4, %xmm4
    vpslldq $8, %xmm4, %xmm5
    vpxor %xmm5, %xmm2, %xmm2
    vpsrldq $8, %xmm4, %xmm4
    vpxor %xmm4, %xmm3, %xmm3

    /* 2. Multiply a_i by b_i and accumulate into (xmm2, xmm3) */
    vmovdqu (%r8), %xmm0
    vmovdqu (%r9), %xmm1
    vpsrldq $8, %xmm0, %xmm4
    vpxor %xmm0, %xmm4, %xmm4
    vpsrldq $8, %xmm1, %xmm5
    vpxor %xmm1, %xmm5, %xmm5
    vpclmulqdq $0x00, %xmm5, %xmm4, %xmm4

    vpclmulqdq $0x00, %xmm1, %xmm0, %xmm5
    vpxor %xmm5, %xmm4, %xmm4
    vpxor %xmm5, %xmm2, %xmm2

    vpclmulqdq $0x11, %xmm1, %xmm0, %xmm5
    vpxor %xmm5, %xmm4, %xmm4
    vpxor %xmm5, %xmm3, %xmm3

    vpslldq $8, %xmm4, %xmm5
    vpxor %xmm5, %xmm2, %xmm2
    vpsrldq $8, %xmm4, %xmm4
    vpxor %xmm4, %xmm3, %xmm3

    /* 3. Reduce modulo x^128 + x^7 + x^2 + x + 1 */
    vmovq %rcx, %xmm0
    vpunpcklqdq %xmm0, %xmm0, %xmm0
    vpclmulqdq $0x11, %xmm0, %xmm3, %xmm4
    vpslldq $8, %xmm4, %xmm5
    vpxor %xmm5, %xmm2, %xmm2
    vpsrldq $8, %xmm4, %xmm4
    vpxor %xmm4, %xmm3, %xmm3

    vpclmulqdq $0x00, %xmm0, %xmm3, %xmm3
    vpxor %xmm3, %xmm2, %xmm0

    addq $16, %r8
    addq $16, %r9
    decq %r10
    jnz .Lpolymac_vpclmul_loop

    vmovdqu %xmm0, (%rax)

.Lpolymac_vpclmul_done:
    vpxor %xmm0, %xmm0, %xmm0
    vpxor %xmm1, %xmm1, %xmm1
    vpxor %xmm2, %xmm2, %xmm2
    vpxor %xmm3, %xmm3, %xmm3
    vpxor %xmm4, %xmm4, %xmm4
    vpxor %xmm5, %xmm5, %xmm5
#if !defined(_WIN64)
    xorq %rdi, %rdi
    xorq %rsi, %rsi
#endif
    xorq %rax, %rax
    xorq %rcx, %rcx
    xorq %rdx, %rdx
    xorq %r8, %r8
    xorq %r9, %r9
    xorq %r10, %r10
    xorq %r11, %r11
    ret
AREION_FUNC_END(areion_pq_gf128_polymac_vpclmul)

AREION_FUNC_START(areion_pq_vole_xor_row_sse2)
#if !defined(_WIN64)
    movq %rdi, %r9
    movq %rsi, %r8
    movq %rdx, %r10
#else
    movq %rcx, %r9
    movq %r8, %r10
    movq %rdx, %r8
#endif
.Lvole_sse2_loop16:
    cmpq $16, %r10
    jb .Lvole_sse2_tail
    movdqu (%r8), %xmm0
    movdqu (%r9), %xmm1
    pxor %xmm0, %xmm1
    movdqu %xmm1, (%r9)
    addq $16, %r8
    addq $16, %r9
    subq $16, %r10
    jmp .Lvole_sse2_loop16

.Lvole_sse2_tail:
    testq %r10, %r10
    jz .Lvole_sse2_done
.Lvole_sse2_byte_loop:
    movzbl (%r8), %eax
    xorb %al, (%r9)
    incq %r8
    incq %r9
    decq %r10
    jnz .Lvole_sse2_byte_loop

.Lvole_sse2_done:
    pxor %xmm0, %xmm0
    pxor %xmm1, %xmm1
#if !defined(_WIN64)
    xorq %rdi, %rdi
    xorq %rsi, %rsi
#else
    xorq %rcx, %rcx
#endif
    xorq %rax, %rax
    xorq %rdx, %rdx
    xorq %r8, %r8
    xorq %r9, %r9
    xorq %r10, %r10
    ret
AREION_FUNC_END(areion_pq_vole_xor_row_sse2)

AREION_FUNC_START(areion_pq_vole_xor_row_avx2)
#if !defined(_WIN64)
    movq %rdi, %r9
    movq %rsi, %r8
    movq %rdx, %r10
#else
    movq %rcx, %r9
    movq %r8, %r10
    movq %rdx, %r8
#endif
.Lvole_avx2_loop32:
    cmpq $32, %r10
    jb .Lvole_avx2_loop16
    vmovdqu (%r8), %ymm0
    vpxor (%r9), %ymm0, %ymm0
    vmovdqu %ymm0, (%r9)
    addq $32, %r8
    addq $32, %r9
    subq $32, %r10
    jmp .Lvole_avx2_loop32

.Lvole_avx2_loop16:
    cmpq $16, %r10
    jb .Lvole_avx2_tail
    vmovdqu (%r8), %xmm0
    vpxor (%r9), %xmm0, %xmm0
    vmovdqu %xmm0, (%r9)
    addq $16, %r8
    addq $16, %r9
    subq $16, %r10
    jmp .Lvole_avx2_loop16

.Lvole_avx2_tail:
    testq %r10, %r10
    jz .Lvole_avx2_done
.Lvole_avx2_byte_loop:
    movzbl (%r8), %eax
    xorb %al, (%r9)
    incq %r8
    incq %r9
    decq %r10
    jnz .Lvole_avx2_byte_loop

.Lvole_avx2_done:
    vpxor %xmm0, %xmm0, %xmm0
#if !defined(_WIN64)
    xorq %rdi, %rdi
    xorq %rsi, %rsi
#else
    xorq %rcx, %rcx
#endif
    xorq %rax, %rax
    xorq %rdx, %rdx
    xorq %r8, %r8
    xorq %r9, %r9
    xorq %r10, %r10
    vzeroupper
    ret
AREION_FUNC_END(areion_pq_vole_xor_row_avx2)

AREION_FUNC_START(areion_pq_vole_xor_row_avx512)
#if !defined(_WIN64)
    movq %rdi, %r9
    movq %rsi, %r8
    movq %rdx, %r10
#else
    movq %rcx, %r9
    movq %r8, %r10
    movq %rdx, %r8
#endif
.Lvole_avx512_loop64:
    cmpq $64, %r10
    jb .Lvole_avx512_loop16
    vmovdqu64 (%r8), %zmm0
    vpxorq (%r9), %zmm0, %zmm0
    vmovdqu64 %zmm0, (%r9)
    addq $64, %r8
    addq $64, %r9
    subq $64, %r10
    jmp .Lvole_avx512_loop64

.Lvole_avx512_loop16:
    cmpq $16, %r10
    jb .Lvole_avx512_tail
    vmovdqu (%r8), %xmm0
    vpxor (%r9), %xmm0, %xmm0
    vmovdqu %xmm0, (%r9)
    addq $16, %r8
    addq $16, %r9
    subq $16, %r10
    jmp .Lvole_avx512_loop16

.Lvole_avx512_tail:
    testq %r10, %r10
    jz .Lvole_avx512_done
.Lvole_avx512_byte_loop:
    movzbl (%r8), %eax
    xorb %al, (%r9)
    incq %r8
    incq %r9
    decq %r10
    jnz .Lvole_avx512_byte_loop

.Lvole_avx512_done:
    vpxord %xmm0, %xmm0, %xmm0
#if !defined(_WIN64)
    xorq %rdi, %rdi
    xorq %rsi, %rsi
#else
    xorq %rcx, %rcx
#endif
    xorq %rax, %rax
    xorq %rdx, %rdx
    xorq %r8, %r8
    xorq %r9, %r9
    xorq %r10, %r10
    vzeroupper
    ret
AREION_FUNC_END(areion_pq_vole_xor_row_avx512)

AREION_FUNC_START(areion_pq_dump_simd_regs)
#if !defined(_WIN64)
    movq %rax, 512(%rdi)
    movq %rcx, 520(%rdi)
    movq %rdx, 528(%rdi)
    movq $0, 536(%rdi)
    movq %r8, 544(%rdi)
    movq %r9, 552(%rdi)
    movq %r10, 560(%rdi)
    movq %r11, 568(%rdi)
    movq $0, 576(%rdi)
    movq $0, 584(%rdi)
    movq $0, 592(%rdi)
    movq %rdi, %rax
    movl %esi, %ecx
#else
    movq %rax, 512(%rcx)
    movq $0, 520(%rcx)
    movq $0, 528(%rcx)
    movq $0, 536(%rcx)
    movq %r8, 544(%rcx)
    movq %r9, 552(%rcx)
    movq %r10, 560(%rcx)
    movq %r11, 568(%rcx)
    movq $0, 576(%rcx)
    movq $0, 584(%rcx)
    movq $0, 592(%rcx)
    movq %rcx, %rax
    movl %edx, %ecx
#endif
    movdqu %xmm0, 0(%rax)
    movdqu %xmm1, 16(%rax)
    movdqu %xmm2, 32(%rax)
    movdqu %xmm3, 48(%rax)
    movdqu %xmm4, 64(%rax)
    movdqu %xmm5, 80(%rax)
    movdqu %xmm6, 96(%rax)
    movdqu %xmm7, 112(%rax)
    movdqu %xmm8, 128(%rax)
    movdqu %xmm9, 144(%rax)
    movdqu %xmm10, 160(%rax)
    movdqu %xmm11, 176(%rax)
    movdqu %xmm12, 192(%rax)
    movdqu %xmm13, 208(%rax)
    movdqu %xmm14, 224(%rax)
    movdqu %xmm15, 240(%rax)
    testl %ecx, %ecx
    jz .Lpq_dump_done
    vmovdqu64 %xmm16, 256(%rax)
    vmovdqu64 %xmm17, 272(%rax)
    vmovdqu64 %xmm18, 288(%rax)
    vmovdqu64 %xmm19, 304(%rax)
    vmovdqu64 %xmm20, 320(%rax)
    vmovdqu64 %xmm21, 336(%rax)
    vmovdqu64 %xmm22, 352(%rax)
    vmovdqu64 %xmm23, 368(%rax)
    vmovdqu64 %xmm24, 384(%rax)
    vmovdqu64 %xmm25, 400(%rax)
    vmovdqu64 %xmm26, 416(%rax)
    vmovdqu64 %xmm27, 432(%rax)
    vmovdqu64 %xmm28, 448(%rax)
    vmovdqu64 %xmm29, 464(%rax)
    vmovdqu64 %xmm30, 480(%rax)
    vmovdqu64 %xmm31, 496(%rax)
    vpxord %xmm16, %xmm16, %xmm16
    vpxord %xmm17, %xmm17, %xmm17
    vpxord %xmm18, %xmm18, %xmm18
    vpxord %xmm19, %xmm19, %xmm19
    vpxord %xmm20, %xmm20, %xmm20
    vpxord %xmm21, %xmm21, %xmm21
    vpxord %xmm22, %xmm22, %xmm22
    vpxord %xmm23, %xmm23, %xmm23
    vpxord %xmm24, %xmm24, %xmm24
    vpxord %xmm25, %xmm25, %xmm25
    vpxord %xmm26, %xmm26, %xmm26
    vpxord %xmm27, %xmm27, %xmm27
    vpxord %xmm28, %xmm28, %xmm28
    vpxord %xmm29, %xmm29, %xmm29
    vpxord %xmm30, %xmm30, %xmm30
    vpxord %xmm31, %xmm31, %xmm31
    vzeroupper
.Lpq_dump_done:
    pxor %xmm0, %xmm0
    pxor %xmm1, %xmm1
    pxor %xmm2, %xmm2
    pxor %xmm3, %xmm3
    pxor %xmm4, %xmm4
    pxor %xmm5, %xmm5
#if !defined(_WIN64)
    pxor %xmm6, %xmm6
    pxor %xmm7, %xmm7
    pxor %xmm8, %xmm8
    pxor %xmm9, %xmm9
    pxor %xmm10, %xmm10
    pxor %xmm11, %xmm11
    pxor %xmm12, %xmm12
    pxor %xmm13, %xmm13
    pxor %xmm14, %xmm14
    pxor %xmm15, %xmm15
    xorq %rsi, %rsi
    xorq %rdi, %rdi
#endif
    xorq %rax, %rax
    xorq %rcx, %rcx
    xorq %rdx, %rdx
    xorq %r8, %r8
    xorq %r9, %r9
    xorq %r10, %r10
    xorq %r11, %r11
    ret
AREION_FUNC_END(areion_pq_dump_simd_regs)

AREION_FUNC_START(areion_pq_clobber_scratch_gprs_asm)
    pxor %xmm0, %xmm0
    pxor %xmm1, %xmm1
    pxor %xmm2, %xmm2
    pxor %xmm3, %xmm3
    pxor %xmm4, %xmm4
    pxor %xmm5, %xmm5
#if !defined(_WIN64)
    pxor %xmm6, %xmm6
    pxor %xmm7, %xmm7
    pxor %xmm8, %xmm8
    pxor %xmm9, %xmm9
    pxor %xmm10, %xmm10
    pxor %xmm11, %xmm11
    pxor %xmm12, %xmm12
    pxor %xmm13, %xmm13
    pxor %xmm14, %xmm14
    pxor %xmm15, %xmm15
    xorq %rsi, %rsi
    xorq %rdi, %rdi
#endif
    xorq %rax, %rax
    xorq %rcx, %rcx
    xorq %rdx, %rdx
    xorq %r8, %r8
    xorq %r9, %r9
    xorq %r10, %r10
    xorq %r11, %r11
    ret
AREION_FUNC_END(areion_pq_clobber_scratch_gprs_asm)

AREION_FUNC_START(areion_pq_dirty_simd_reg_for_test)
#if !defined(_WIN64)
    movq %rdi, %r10
#else
    movq %rcx, %r10
#endif
    movabsq $0x5555555555555555, %rax
    xorq %rax, %r10
    movq %r10, %xmm2
    xorq %rax, %rax
    ret
AREION_FUNC_END(areion_pq_dirty_simd_reg_for_test)

#endif /* __x86_64__ || _M_X64 */

#if defined(__ELF__)
#if defined(__x86_64__)
.pushsection .note.gnu.property, "a"
.p2align 3
.long 4
.long 16
.long 5
.asciz "GNU"
.long 0xc0000002
.long 4
.long 3
.long 0
.popsection
#elif defined(__aarch64__)
.pushsection .note.gnu.property, "a"
.p2align 3
.long 4
.long 16
.long 5
.asciz "GNU"
.long 0xc0000000
.long 4
.long 3
.long 0
.popsection
#endif
.section .note.GNU-stack,"",%progbits
#endif
