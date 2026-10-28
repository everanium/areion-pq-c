/*
 * Copyright (c) 2026 Andrey Kuvshinov
 *
 * Dual-licensed under Apache-2.0 OR MIT.
 * See LICENSE-APACHE and LICENSE-MIT for details.
 */

#if defined(__aarch64__) || defined(_M_ARM64)
#include "asm_abi.h"

#if !defined(__APPLE__)
.arch armv8-a+crypto
#endif
.text

AREION_FUNC_START(areion_pq_extract_witness256_arm64)
    ld1 { v0.16b, v1.16b }, [x2]
    ld1 { v2.16b, v3.16b }, [x3]
    eor v0.16b, v0.16b, v2.16b
    eor v1.16b, v1.16b, v3.16b
    eor v16.16b, v16.16b, v16.16b

    /* Round 0 (even: active v0, passive v1) */
    ld1 { v2.16b }, [x5], #16
    aese v0.16b, v16.16b
    aesmc v3.16b, v0.16b
    aese v3.16b, v2.16b
    aesmc v3.16b, v3.16b
    eor v1.16b, v1.16b, v3.16b
    st1 { v0.16b, v1.16b }, [x1], #32

    /* Round 1 (odd: active v1, passive v0) */
    ld1 { v2.16b }, [x5], #16
    aese v1.16b, v16.16b
    aesmc v3.16b, v1.16b
    aese v3.16b, v2.16b
    aesmc v3.16b, v3.16b
    eor v0.16b, v0.16b, v3.16b
    st1 { v1.16b }, [x1], #16
    st1 { v0.16b }, [x1], #16

    /* Round 2 (even: active v0, passive v1) */
    ld1 { v2.16b }, [x5], #16
    aese v0.16b, v16.16b
    aesmc v3.16b, v0.16b
    aese v3.16b, v2.16b
    aesmc v3.16b, v3.16b
    eor v1.16b, v1.16b, v3.16b
    st1 { v0.16b, v1.16b }, [x1], #32

    /* Round 3 (odd: active v1, passive v0) */
    ld1 { v2.16b }, [x5], #16
    aese v1.16b, v16.16b
    aesmc v3.16b, v1.16b
    aese v3.16b, v2.16b
    aesmc v3.16b, v3.16b
    eor v0.16b, v0.16b, v3.16b
    st1 { v1.16b }, [x1], #16
    st1 { v0.16b }, [x1], #16

    /* Round 4 (even: active v0, passive v1) */
    ld1 { v2.16b }, [x5], #16
    aese v0.16b, v16.16b
    aesmc v3.16b, v0.16b
    aese v3.16b, v2.16b
    aesmc v3.16b, v3.16b
    eor v1.16b, v1.16b, v3.16b
    st1 { v0.16b, v1.16b }, [x1], #32

    /* Round 5 (odd: active v1, passive v0) */
    ld1 { v2.16b }, [x5], #16
    aese v1.16b, v16.16b
    aesmc v3.16b, v1.16b
    aese v3.16b, v2.16b
    aesmc v3.16b, v3.16b
    eor v0.16b, v0.16b, v3.16b
    st1 { v1.16b }, [x1], #16
    st1 { v0.16b }, [x1], #16

    /* Round 6 (even: active v0, passive v1) */
    ld1 { v2.16b }, [x5], #16
    aese v0.16b, v16.16b
    aesmc v3.16b, v0.16b
    aese v3.16b, v2.16b
    aesmc v3.16b, v3.16b
    eor v1.16b, v1.16b, v3.16b
    st1 { v0.16b, v1.16b }, [x1], #32

    /* Round 7 (odd: active v1, passive v0) */
    ld1 { v2.16b }, [x5], #16
    aese v1.16b, v16.16b
    aesmc v3.16b, v1.16b
    aese v3.16b, v2.16b
    aesmc v3.16b, v3.16b
    eor v0.16b, v0.16b, v3.16b
    st1 { v1.16b }, [x1], #16
    st1 { v0.16b }, [x1], #16

    /* Round 8 (even: active v0, passive v1) */
    ld1 { v2.16b }, [x5], #16
    aese v0.16b, v16.16b
    aesmc v3.16b, v0.16b
    aese v3.16b, v2.16b
    aesmc v3.16b, v3.16b
    eor v1.16b, v1.16b, v3.16b
    st1 { v0.16b, v1.16b }, [x1], #32

    /* Round 9 (odd: active v1, passive v0) */
    ld1 { v2.16b }, [x5]
    aese v1.16b, v16.16b
    aesmc v3.16b, v1.16b
    aese v3.16b, v2.16b
    aesmc v3.16b, v3.16b
    eor v0.16b, v0.16b, v3.16b

    /* Post-whitening with k2 */
    ld1 { v2.16b, v3.16b }, [x4]
    eor v0.16b, v0.16b, v2.16b
    eor v1.16b, v1.16b, v3.16b
    st1 { v0.16b, v1.16b }, [x0]

    eor v0.16b, v0.16b, v0.16b
    eor v1.16b, v1.16b, v1.16b
    eor v2.16b, v2.16b, v2.16b
    eor v3.16b, v3.16b, v3.16b
    eor v16.16b, v16.16b, v16.16b
    mov x0, xzr
    mov x1, xzr
    mov x2, xzr
    mov x3, xzr
    mov x4, xzr
    mov x5, xzr
    ret
AREION_FUNC_END(areion_pq_extract_witness256_arm64)

AREION_FUNC_START(areion_pq_gf128_mul_pmull)
    ld1 { v0.16b }, [x1]
    ld1 { v1.16b }, [x2]
    eor v16.16b, v16.16b, v16.16b

    mov x3, #0x87
    dup v6.2d, x3

    pmull v2.1q, v0.1d, v1.1d
    pmull2 v3.1q, v0.2d, v1.2d

    ext v4.16b, v0.16b, v16.16b, #8
    eor v4.16b, v4.16b, v0.16b
    ext v5.16b, v1.16b, v16.16b, #8
    eor v5.16b, v5.16b, v1.16b
    pmull v4.1q, v4.1d, v5.1d
    eor v4.16b, v4.16b, v2.16b
    eor v4.16b, v4.16b, v3.16b

    ext v5.16b, v16.16b, v4.16b, #8
    eor v2.16b, v2.16b, v5.16b
    ext v4.16b, v4.16b, v16.16b, #8
    eor v3.16b, v3.16b, v4.16b

    pmull2 v4.1q, v3.2d, v6.2d
    ext v5.16b, v16.16b, v4.16b, #8
    eor v2.16b, v2.16b, v5.16b
    ext v4.16b, v4.16b, v16.16b, #8
    eor v3.16b, v3.16b, v4.16b

    pmull v3.1q, v3.1d, v6.1d
    eor v2.16b, v2.16b, v3.16b

    st1 { v2.16b }, [x0]

    eor v0.16b, v0.16b, v0.16b
    eor v1.16b, v1.16b, v1.16b
    eor v2.16b, v2.16b, v2.16b
    eor v3.16b, v3.16b, v3.16b
    eor v4.16b, v4.16b, v4.16b
    eor v5.16b, v5.16b, v5.16b
    eor v6.16b, v6.16b, v6.16b
    eor v16.16b, v16.16b, v16.16b
    mov x0, xzr
    mov x1, xzr
    mov x2, xzr
    mov x3, xzr
    ret
AREION_FUNC_END(areion_pq_gf128_mul_pmull)

AREION_FUNC_START(areion_pq_gf128_polymac_pmull)
    cbz x3, .Lpolymac_pmull_done

    ld1 { v0.16b }, [x0]
    ld1 { v7.16b }, [x4]
    eor v16.16b, v16.16b, v16.16b
    ext v17.16b, v7.16b, v16.16b, #8
    eor v17.16b, v17.16b, v7.16b

    mov x5, #0x87
    dup v6.2d, x5

.Lpolymac_pmull_loop:
    /* 1. Multiply acc (v0) by chi (v7) */
    pmull v2.1q, v0.1d, v7.1d
    pmull2 v3.1q, v0.2d, v7.2d
    ext v4.16b, v0.16b, v16.16b, #8
    eor v4.16b, v4.16b, v0.16b
    pmull v4.1q, v4.1d, v17.1d
    eor v4.16b, v4.16b, v2.16b
    eor v4.16b, v4.16b, v3.16b
    ext v5.16b, v16.16b, v4.16b, #8
    eor v2.16b, v2.16b, v5.16b
    ext v4.16b, v4.16b, v16.16b, #8
    eor v3.16b, v3.16b, v4.16b

    /* 2. Multiply a_i (v1) by b_i (v18) */
    ld1 { v1.16b }, [x1], #16
    ld1 { v18.16b }, [x2], #16
    pmull v19.1q, v1.1d, v18.1d
    pmull2 v20.1q, v1.2d, v18.2d
    ext v4.16b, v1.16b, v16.16b, #8
    eor v4.16b, v4.16b, v1.16b
    ext v5.16b, v18.16b, v16.16b, #8
    eor v5.16b, v5.16b, v18.16b
    pmull v4.1q, v4.1d, v5.1d
    eor v4.16b, v4.16b, v19.16b
    eor v4.16b, v4.16b, v20.16b
    ext v5.16b, v16.16b, v4.16b, #8
    eor v19.16b, v19.16b, v5.16b
    ext v4.16b, v4.16b, v16.16b, #8
    eor v20.16b, v20.16b, v4.16b

    /* 3. Combine unreduced products and reduce */
    eor v2.16b, v2.16b, v19.16b
    eor v3.16b, v3.16b, v20.16b

    pmull2 v4.1q, v3.2d, v6.2d
    ext v5.16b, v16.16b, v4.16b, #8
    eor v2.16b, v2.16b, v5.16b
    ext v4.16b, v4.16b, v16.16b, #8
    eor v3.16b, v3.16b, v4.16b

    pmull v3.1q, v3.1d, v6.1d
    eor v0.16b, v2.16b, v3.16b

    subs x3, x3, #1
    b.ne .Lpolymac_pmull_loop

    st1 { v0.16b }, [x0]

.Lpolymac_pmull_done:
    eor v0.16b, v0.16b, v0.16b
    eor v1.16b, v1.16b, v1.16b
    eor v2.16b, v2.16b, v2.16b
    eor v3.16b, v3.16b, v3.16b
    eor v4.16b, v4.16b, v4.16b
    eor v5.16b, v5.16b, v5.16b
    eor v6.16b, v6.16b, v6.16b
    eor v7.16b, v7.16b, v7.16b
    eor v16.16b, v16.16b, v16.16b
    eor v17.16b, v17.16b, v17.16b
    eor v18.16b, v18.16b, v18.16b
    eor v19.16b, v19.16b, v19.16b
    eor v20.16b, v20.16b, v20.16b
    mov x0, xzr
    mov x1, xzr
    mov x2, xzr
    mov x3, xzr
    mov x4, xzr
    mov x5, xzr
    ret
AREION_FUNC_END(areion_pq_gf128_polymac_pmull)

AREION_FUNC_START(areion_pq_vole_xor_row_neon)
.Lvole_neon_loop64:
    cmp x2, #64
    b.lo .Lvole_neon_loop16
    ld1 { v0.16b, v1.16b, v2.16b, v3.16b }, [x1], #64
    ld1 { v4.16b, v5.16b, v6.16b, v7.16b }, [x0]
    eor v4.16b, v4.16b, v0.16b
    eor v5.16b, v5.16b, v1.16b
    eor v6.16b, v6.16b, v2.16b
    eor v7.16b, v7.16b, v3.16b
    st1 { v4.16b, v5.16b, v6.16b, v7.16b }, [x0], #64
    sub x2, x2, #64
    b .Lvole_neon_loop64

.Lvole_neon_loop16:
    cmp x2, #16
    b.lo .Lvole_neon_tail
    ld1 { v0.16b }, [x1], #16
    ld1 { v1.16b }, [x0]
    eor v1.16b, v1.16b, v0.16b
    st1 { v1.16b }, [x0], #16
    sub x2, x2, #16
    b .Lvole_neon_loop16

.Lvole_neon_tail:
    cbz x2, .Lvole_neon_done
.Lvole_neon_byte_loop:
    ldrb w3, [x1], #1
    ldrb w4, [x0]
    eor w4, w4, w3
    strb w4, [x0], #1
    subs x2, x2, #1
    b.ne .Lvole_neon_byte_loop

.Lvole_neon_done:
    eor v0.16b, v0.16b, v0.16b
    eor v1.16b, v1.16b, v1.16b
    eor v2.16b, v2.16b, v2.16b
    eor v3.16b, v3.16b, v3.16b
    eor v4.16b, v4.16b, v4.16b
    eor v5.16b, v5.16b, v5.16b
    eor v6.16b, v6.16b, v6.16b
    eor v7.16b, v7.16b, v7.16b
    mov x0, xzr
    mov x1, xzr
    mov x2, xzr
    mov x3, xzr
    mov x4, xzr
    ret
AREION_FUNC_END(areion_pq_vole_xor_row_neon)

AREION_FUNC_START(areion_pq_dump_simd_regs)
    str x1, [x0, #512]
    str x2, [x0, #520]
    str x3, [x0, #528]
    str x4, [x0, #536]
    str x5, [x0, #544]
    str x6, [x0, #552]
    str x7, [x0, #560]
    str x8, [x0, #568]
    str x9, [x0, #576]
    str x10, [x0, #584]
    str x11, [x0, #592]
    str x12, [x0, #600]
    str x13, [x0, #608]
    str x14, [x0, #616]
    str x15, [x0, #624]
    str x16, [x0, #632]
    str x17, [x0, #640]
    str xzr, [x0, #648]
    str xzr, [x0, #656]
    str xzr, [x0, #664]
    str xzr, [x0, #672]
    str xzr, [x0, #680]
    str xzr, [x0, #688]
    str xzr, [x0, #696]
    st1 {v0.16b, v1.16b, v2.16b, v3.16b}, [x0], #64
    st1 {v4.16b, v5.16b, v6.16b, v7.16b}, [x0], #64
    st1 {v8.16b, v9.16b, v10.16b, v11.16b}, [x0], #64
    st1 {v12.16b, v13.16b, v14.16b, v15.16b}, [x0], #64
    st1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x0], #64
    st1 {v20.16b, v21.16b, v22.16b, v23.16b}, [x0], #64
    st1 {v24.16b, v25.16b, v26.16b, v27.16b}, [x0], #64
    st1 {v28.16b, v29.16b, v30.16b, v31.16b}, [x0]
    eor v0.16b, v0.16b, v0.16b
    eor v1.16b, v1.16b, v1.16b
    eor v2.16b, v2.16b, v2.16b
    eor v3.16b, v3.16b, v3.16b
    eor v4.16b, v4.16b, v4.16b
    eor v5.16b, v5.16b, v5.16b
    eor v6.16b, v6.16b, v6.16b
    eor v7.16b, v7.16b, v7.16b
    eor v16.16b, v16.16b, v16.16b
    eor v17.16b, v17.16b, v17.16b
    eor v18.16b, v18.16b, v18.16b
    eor v19.16b, v19.16b, v19.16b
    eor v20.16b, v20.16b, v20.16b
    eor v21.16b, v21.16b, v21.16b
    eor v22.16b, v22.16b, v22.16b
    eor v23.16b, v23.16b, v23.16b
    eor v24.16b, v24.16b, v24.16b
    eor v25.16b, v25.16b, v25.16b
    eor v26.16b, v26.16b, v26.16b
    eor v27.16b, v27.16b, v27.16b
    eor v28.16b, v28.16b, v28.16b
    eor v29.16b, v29.16b, v29.16b
    eor v30.16b, v30.16b, v30.16b
    eor v31.16b, v31.16b, v31.16b
    mov v8.d[1], xzr
    mov v9.d[1], xzr
    mov v10.d[1], xzr
    mov v11.d[1], xzr
    mov v12.d[1], xzr
    mov v13.d[1], xzr
    mov v14.d[1], xzr
    mov v15.d[1], xzr
    mov x0, xzr
    mov x1, xzr
    mov x2, xzr
    mov x3, xzr
    mov x4, xzr
    mov x5, xzr
    mov x6, xzr
    mov x7, xzr
    mov x8, xzr
    mov x9, xzr
    mov x10, xzr
    mov x11, xzr
    mov x12, xzr
    mov x13, xzr
    mov x14, xzr
    mov x15, xzr
    mov x16, xzr
    mov x17, xzr
    ret
AREION_FUNC_END(areion_pq_dump_simd_regs)

AREION_FUNC_START(areion_pq_clobber_scratch_gprs_asm)
    eor v0.16b, v0.16b, v0.16b
    eor v1.16b, v1.16b, v1.16b
    eor v2.16b, v2.16b, v2.16b
    eor v3.16b, v3.16b, v3.16b
    eor v4.16b, v4.16b, v4.16b
    eor v5.16b, v5.16b, v5.16b
    eor v6.16b, v6.16b, v6.16b
    eor v7.16b, v7.16b, v7.16b
    eor v16.16b, v16.16b, v16.16b
    eor v17.16b, v17.16b, v17.16b
    eor v18.16b, v18.16b, v18.16b
    eor v19.16b, v19.16b, v19.16b
    eor v20.16b, v20.16b, v20.16b
    eor v21.16b, v21.16b, v21.16b
    eor v22.16b, v22.16b, v22.16b
    eor v23.16b, v23.16b, v23.16b
    eor v24.16b, v24.16b, v24.16b
    eor v25.16b, v25.16b, v25.16b
    eor v26.16b, v26.16b, v26.16b
    eor v27.16b, v27.16b, v27.16b
    eor v28.16b, v28.16b, v28.16b
    eor v29.16b, v29.16b, v29.16b
    eor v30.16b, v30.16b, v30.16b
    eor v31.16b, v31.16b, v31.16b
    mov v8.d[1], xzr
    mov v9.d[1], xzr
    mov v10.d[1], xzr
    mov v11.d[1], xzr
    mov v12.d[1], xzr
    mov v13.d[1], xzr
    mov v14.d[1], xzr
    mov v15.d[1], xzr
    mov x0, xzr
    mov x1, xzr
    mov x2, xzr
    mov x3, xzr
    mov x4, xzr
    mov x5, xzr
    mov x6, xzr
    mov x7, xzr
    mov x8, xzr
    mov x9, xzr
    mov x10, xzr
    mov x11, xzr
    mov x12, xzr
    mov x13, xzr
    mov x14, xzr
    mov x15, xzr
    mov x16, xzr
    mov x17, xzr
    ret
AREION_FUNC_END(areion_pq_clobber_scratch_gprs_asm)

AREION_FUNC_START(areion_pq_dirty_simd_reg_for_test)
    mov x12, x0
    mov x0, #0x5555555555555555
    eor x12, x12, x0
    mov v2.d[0], x12
    mov x0, xzr
    ret
AREION_FUNC_END(areion_pq_dirty_simd_reg_for_test)

#endif /* __aarch64__ || _M_ARM64 */

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
