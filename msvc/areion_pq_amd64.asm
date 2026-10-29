; Copyright (c) 2026 Andrey Kuvshinov
; SPDX-License-Identifier: Apache-2.0 OR MIT

EXTERN areion_pq_rc_p1:BYTE
EXTERN areion_pq_rc_p2:BYTE

.code

PUBLIC areion_pq_extract_witness256_aesni
ALIGN 16
areion_pq_extract_witness256_aesni PROC
    db 0F3h, 00Fh, 01Eh, 0FAh ; endbr64
    mov rax, rcx
    mov r10, rdx
    mov rdx, r8
    mov rcx, r9
    mov r11, QWORD PTR [rsp + 40]
    mov r9, QWORD PTR [rsp + 48]
    movdqu xmm0, XMMWORD PTR [rdx]
    movdqu xmm1, XMMWORD PTR [rdx + 16]
    movdqu xmm2, XMMWORD PTR [rcx]
    movdqu xmm3, XMMWORD PTR [rcx + 16]
    pxor xmm0, xmm2
    pxor xmm1, xmm3
    pxor xmm4, xmm4
    movdqu xmm2, XMMWORD PTR [r9]
    movdqa xmm3, xmm0
    aesenc xmm3, xmm2
    aesenc xmm3, xmm1
    aesenclast xmm0, xmm4
    movdqa xmm1, xmm3
    movdqu XMMWORD PTR [r10], xmm0
    movdqu XMMWORD PTR [r10 + 16], xmm1
    movdqu xmm2, XMMWORD PTR [r9 + 16]
    movdqa xmm3, xmm1
    aesenc xmm3, xmm2
    aesenc xmm3, xmm0
    aesenclast xmm1, xmm4
    movdqa xmm0, xmm3
    movdqu XMMWORD PTR [r10 + 32], xmm1
    movdqu XMMWORD PTR [r10 + 48], xmm0
    movdqu xmm2, XMMWORD PTR [r9 + 32]
    movdqa xmm3, xmm0
    aesenc xmm3, xmm2
    aesenc xmm3, xmm1
    aesenclast xmm0, xmm4
    movdqa xmm1, xmm3
    movdqu XMMWORD PTR [r10 + 64], xmm0
    movdqu XMMWORD PTR [r10 + 80], xmm1
    movdqu xmm2, XMMWORD PTR [r9 + 48]
    movdqa xmm3, xmm1
    aesenc xmm3, xmm2
    aesenc xmm3, xmm0
    aesenclast xmm1, xmm4
    movdqa xmm0, xmm3
    movdqu XMMWORD PTR [r10 + 96], xmm1
    movdqu XMMWORD PTR [r10 + 112], xmm0
    movdqu xmm2, XMMWORD PTR [r9 + 64]
    movdqa xmm3, xmm0
    aesenc xmm3, xmm2
    aesenc xmm3, xmm1
    aesenclast xmm0, xmm4
    movdqa xmm1, xmm3
    movdqu XMMWORD PTR [r10 + 128], xmm0
    movdqu XMMWORD PTR [r10 + 144], xmm1
    movdqu xmm2, XMMWORD PTR [r9 + 80]
    movdqa xmm3, xmm1
    aesenc xmm3, xmm2
    aesenc xmm3, xmm0
    aesenclast xmm1, xmm4
    movdqa xmm0, xmm3
    movdqu XMMWORD PTR [r10 + 160], xmm1
    movdqu XMMWORD PTR [r10 + 176], xmm0
    movdqu xmm2, XMMWORD PTR [r9 + 96]
    movdqa xmm3, xmm0
    aesenc xmm3, xmm2
    aesenc xmm3, xmm1
    aesenclast xmm0, xmm4
    movdqa xmm1, xmm3
    movdqu XMMWORD PTR [r10 + 192], xmm0
    movdqu XMMWORD PTR [r10 + 208], xmm1
    movdqu xmm2, XMMWORD PTR [r9 + 112]
    movdqa xmm3, xmm1
    aesenc xmm3, xmm2
    aesenc xmm3, xmm0
    aesenclast xmm1, xmm4
    movdqa xmm0, xmm3
    movdqu XMMWORD PTR [r10 + 224], xmm1
    movdqu XMMWORD PTR [r10 + 240], xmm0
    movdqu xmm2, XMMWORD PTR [r9 + 128]
    movdqa xmm3, xmm0
    aesenc xmm3, xmm2
    aesenc xmm3, xmm1
    aesenclast xmm0, xmm4
    movdqa xmm1, xmm3
    movdqu XMMWORD PTR [r10 + 256], xmm0
    movdqu XMMWORD PTR [r10 + 272], xmm1
    movdqu xmm2, XMMWORD PTR [r9 + 144]
    movdqa xmm3, xmm1
    aesenc xmm3, xmm2
    aesenc xmm3, xmm0
    aesenclast xmm1, xmm4
    movdqa xmm0, xmm3
    movdqu xmm2, XMMWORD PTR [r11]
    movdqu xmm3, XMMWORD PTR [r11 + 16]
    pxor xmm0, xmm2
    pxor xmm1, xmm3
    movdqu XMMWORD PTR [rax], xmm0
    movdqu XMMWORD PTR [rax + 16], xmm1
    pxor xmm0, xmm0
    pxor xmm1, xmm1
    pxor xmm2, xmm2
    pxor xmm3, xmm3
    pxor xmm4, xmm4
    xor rax, rax
    xor rcx, rcx
    xor rdx, rdx
    xor r8, r8
    xor r9, r9
    xor r10, r10
    xor r11, r11
    ret
areion_pq_extract_witness256_aesni ENDP

PUBLIC areion_pq_extract_witness256_vex
ALIGN 16
areion_pq_extract_witness256_vex PROC
    db 0F3h, 00Fh, 01Eh, 0FAh ; endbr64
    mov rax, rcx
    mov r10, rdx
    mov rdx, r8
    mov rcx, r9
    mov r11, QWORD PTR [rsp + 40]
    mov r9, QWORD PTR [rsp + 48]
    vmovdqu xmm0, XMMWORD PTR [rdx]
    vmovdqu xmm1, XMMWORD PTR [rdx + 16]
    vpxor xmm0, xmm0, XMMWORD PTR [rcx]
    vpxor xmm1, xmm1, XMMWORD PTR [rcx + 16]
    vpxor xmm4, xmm4, xmm4
    vaesenc xmm3, xmm0, XMMWORD PTR [r9]
    vaesenclast xmm0, xmm0, xmm4
    vaesenc xmm1, xmm3, xmm1
    vmovdqu XMMWORD PTR [r10], xmm0
    vmovdqu XMMWORD PTR [r10 + 16], xmm1
    vaesenc xmm3, xmm1, XMMWORD PTR [r9 + 16]
    vaesenclast xmm1, xmm1, xmm4
    vaesenc xmm0, xmm3, xmm0
    vmovdqu XMMWORD PTR [r10 + 32], xmm1
    vmovdqu XMMWORD PTR [r10 + 48], xmm0
    vaesenc xmm3, xmm0, XMMWORD PTR [r9 + 32]
    vaesenclast xmm0, xmm0, xmm4
    vaesenc xmm1, xmm3, xmm1
    vmovdqu XMMWORD PTR [r10 + 64], xmm0
    vmovdqu XMMWORD PTR [r10 + 80], xmm1
    vaesenc xmm3, xmm1, XMMWORD PTR [r9 + 48]
    vaesenclast xmm1, xmm1, xmm4
    vaesenc xmm0, xmm3, xmm0
    vmovdqu XMMWORD PTR [r10 + 96], xmm1
    vmovdqu XMMWORD PTR [r10 + 112], xmm0
    vaesenc xmm3, xmm0, XMMWORD PTR [r9 + 64]
    vaesenclast xmm0, xmm0, xmm4
    vaesenc xmm1, xmm3, xmm1
    vmovdqu XMMWORD PTR [r10 + 128], xmm0
    vmovdqu XMMWORD PTR [r10 + 144], xmm1
    vaesenc xmm3, xmm1, XMMWORD PTR [r9 + 80]
    vaesenclast xmm1, xmm1, xmm4
    vaesenc xmm0, xmm3, xmm0
    vmovdqu XMMWORD PTR [r10 + 160], xmm1
    vmovdqu XMMWORD PTR [r10 + 176], xmm0
    vaesenc xmm3, xmm0, XMMWORD PTR [r9 + 96]
    vaesenclast xmm0, xmm0, xmm4
    vaesenc xmm1, xmm3, xmm1
    vmovdqu XMMWORD PTR [r10 + 192], xmm0
    vmovdqu XMMWORD PTR [r10 + 208], xmm1
    vaesenc xmm3, xmm1, XMMWORD PTR [r9 + 112]
    vaesenclast xmm1, xmm1, xmm4
    vaesenc xmm0, xmm3, xmm0
    vmovdqu XMMWORD PTR [r10 + 224], xmm1
    vmovdqu XMMWORD PTR [r10 + 240], xmm0
    vaesenc xmm3, xmm0, XMMWORD PTR [r9 + 128]
    vaesenclast xmm0, xmm0, xmm4
    vaesenc xmm1, xmm3, xmm1
    vmovdqu XMMWORD PTR [r10 + 256], xmm0
    vmovdqu XMMWORD PTR [r10 + 272], xmm1
    vaesenc xmm3, xmm1, XMMWORD PTR [r9 + 144]
    vaesenclast xmm1, xmm1, xmm4
    vaesenc xmm0, xmm3, xmm0
    vpxor xmm0, xmm0, XMMWORD PTR [r11]
    vpxor xmm1, xmm1, XMMWORD PTR [r11 + 16]
    vmovdqu XMMWORD PTR [rax], xmm0
    vmovdqu XMMWORD PTR [rax + 16], xmm1
    vpxor xmm0, xmm0, xmm0
    vpxor xmm1, xmm1, xmm1
    vpxor xmm3, xmm3, xmm3
    vpxor xmm4, xmm4, xmm4
    xor rax, rax
    xor rcx, rcx
    xor rdx, rdx
    xor r8, r8
    xor r9, r9
    xor r10, r10
    xor r11, r11
    ret
areion_pq_extract_witness256_vex ENDP

PUBLIC areion_pq_gf128_mul_pclmul
ALIGN 16
areion_pq_gf128_mul_pclmul PROC
    db 0F3h, 00Fh, 01Eh, 0FAh ; endbr64
    mov rax, rcx
    mov r9, r8
    mov r8, rdx
    movdqu xmm0, XMMWORD PTR [r8]
    movdqu xmm1, XMMWORD PTR [r9]
    movdqa xmm2, xmm0
    pclmulqdq xmm2, xmm1, 0
    movdqa xmm3, xmm0
    pclmulqdq xmm3, xmm1, 17
    movdqa xmm4, xmm0
    psrldq xmm4, 8
    pxor xmm4, xmm0
    movdqa xmm5, xmm1
    psrldq xmm5, 8
    pxor xmm5, xmm1
    pclmulqdq xmm4, xmm5, 0
    pxor xmm4, xmm2
    pxor xmm4, xmm3
    movdqa xmm5, xmm4
    pslldq xmm5, 8
    pxor xmm2, xmm5
    psrldq xmm4, 8
    pxor xmm3, xmm4
    mov r10, 135
    movq xmm0, r10
    punpcklqdq xmm0, xmm0
    movdqa xmm4, xmm3
    pclmulqdq xmm4, xmm0, 17
    movdqa xmm5, xmm4
    pslldq xmm5, 8
    pxor xmm2, xmm5
    psrldq xmm4, 8
    pxor xmm3, xmm4
    pclmulqdq xmm3, xmm0, 0
    pxor xmm2, xmm3
    movdqu XMMWORD PTR [rax], xmm2
    pxor xmm0, xmm0
    pxor xmm1, xmm1
    pxor xmm2, xmm2
    pxor xmm3, xmm3
    pxor xmm4, xmm4
    pxor xmm5, xmm5
    xor rcx, rcx
    xor rax, rax
    xor rdx, rdx
    xor r8, r8
    xor r9, r9
    xor r10, r10
    ret
areion_pq_gf128_mul_pclmul ENDP

PUBLIC areion_pq_gf128_mul_vpclmul
ALIGN 16
areion_pq_gf128_mul_vpclmul PROC
    db 0F3h, 00Fh, 01Eh, 0FAh ; endbr64
    mov rax, rcx
    mov r9, r8
    mov r8, rdx
    vmovdqu xmm0, XMMWORD PTR [r8]
    vmovdqu xmm1, XMMWORD PTR [r9]
    vpclmulqdq xmm2, xmm0, xmm1, 0
    vpclmulqdq xmm3, xmm0, xmm1, 17
    vpsrldq xmm4, xmm0, 8
    vpxor xmm4, xmm4, xmm0
    vpsrldq xmm5, xmm1, 8
    vpxor xmm5, xmm5, xmm1
    vpclmulqdq xmm4, xmm4, xmm5, 0
    vpxor xmm4, xmm4, xmm2
    vpxor xmm4, xmm4, xmm3
    vpslldq xmm5, xmm4, 8
    vpxor xmm2, xmm2, xmm5
    vpsrldq xmm4, xmm4, 8
    vpxor xmm3, xmm3, xmm4
    mov r10, 135
    vmovq xmm0, r10
    vpunpcklqdq xmm0, xmm0, xmm0
    vpclmulqdq xmm4, xmm3, xmm0, 17
    vpslldq xmm5, xmm4, 8
    vpxor xmm2, xmm2, xmm5
    vpsrldq xmm4, xmm4, 8
    vpxor xmm3, xmm3, xmm4
    vpclmulqdq xmm3, xmm3, xmm0, 0
    vpxor xmm2, xmm2, xmm3
    vmovdqu XMMWORD PTR [rax], xmm2
    vpxor xmm0, xmm0, xmm0
    vpxor xmm1, xmm1, xmm1
    vpxor xmm2, xmm2, xmm2
    vpxor xmm3, xmm3, xmm3
    vpxor xmm4, xmm4, xmm4
    vpxor xmm5, xmm5, xmm5
    xor rcx, rcx
    xor rax, rax
    xor rdx, rdx
    xor r8, r8
    xor r9, r9
    xor r10, r10
    ret
areion_pq_gf128_mul_vpclmul ENDP

PUBLIC areion_pq_gf128_polymac_pclmul
ALIGN 16
areion_pq_gf128_polymac_pclmul PROC
    db 0F3h, 00Fh, 01Eh, 0FAh ; endbr64
    mov rax, rcx
    mov rcx, r8
    mov r8, rdx
    mov r10, r9
    mov r9, rcx
    mov r11, QWORD PTR [rsp + 40]
    test r10, r10
    jle polymac_pclmul_done
    movdqu xmm0, XMMWORD PTR [rax]
    mov rcx, 135
polymac_pclmul_loop:
    movdqu xmm1, XMMWORD PTR [r11]
    movdqa xmm2, xmm0
    pclmulqdq xmm2, xmm1, 0
    movdqa xmm3, xmm0
    pclmulqdq xmm3, xmm1, 17
    movdqa xmm4, xmm0
    psrldq xmm4, 8
    pxor xmm4, xmm0
    movdqa xmm5, xmm1
    psrldq xmm5, 8
    pxor xmm5, xmm1
    pclmulqdq xmm4, xmm5, 0
    pxor xmm4, xmm2
    pxor xmm4, xmm3
    movdqa xmm5, xmm4
    pslldq xmm5, 8
    pxor xmm2, xmm5
    psrldq xmm4, 8
    pxor xmm3, xmm4
    movdqu xmm0, XMMWORD PTR [r8]
    movdqu xmm1, XMMWORD PTR [r9]
    movdqa xmm4, xmm0
    psrldq xmm4, 8
    pxor xmm4, xmm0
    movdqa xmm5, xmm1
    psrldq xmm5, 8
    pxor xmm5, xmm1
    pclmulqdq xmm4, xmm5, 0
    movdqa xmm5, xmm0
    pclmulqdq xmm5, xmm1, 0
    pxor xmm4, xmm5
    pxor xmm2, xmm5
    movdqa xmm5, xmm0
    pclmulqdq xmm5, xmm1, 17
    pxor xmm4, xmm5
    pxor xmm3, xmm5
    movdqa xmm5, xmm4
    pslldq xmm5, 8
    pxor xmm2, xmm5
    psrldq xmm4, 8
    pxor xmm3, xmm4
    movq xmm0, rcx
    punpcklqdq xmm0, xmm0
    movdqa xmm4, xmm3
    pclmulqdq xmm4, xmm0, 17
    movdqa xmm5, xmm4
    pslldq xmm5, 8
    pxor xmm2, xmm5
    psrldq xmm4, 8
    pxor xmm3, xmm4
    pclmulqdq xmm3, xmm0, 0
    pxor xmm2, xmm3
    movdqa xmm0, xmm2
    add r8, 16
    add r9, 16
    dec r10
    jnz polymac_pclmul_loop
    movdqu XMMWORD PTR [rax], xmm0
polymac_pclmul_done:
    pxor xmm0, xmm0
    pxor xmm1, xmm1
    pxor xmm2, xmm2
    pxor xmm3, xmm3
    pxor xmm4, xmm4
    pxor xmm5, xmm5
    xor rax, rax
    xor rcx, rcx
    xor rdx, rdx
    xor r8, r8
    xor r9, r9
    xor r10, r10
    xor r11, r11
    ret
areion_pq_gf128_polymac_pclmul ENDP

PUBLIC areion_pq_gf128_polymac_vpclmul
ALIGN 16
areion_pq_gf128_polymac_vpclmul PROC
    db 0F3h, 00Fh, 01Eh, 0FAh ; endbr64
    mov rax, rcx
    mov rcx, r8
    mov r8, rdx
    mov r10, r9
    mov r9, rcx
    mov r11, QWORD PTR [rsp + 40]
    test r10, r10
    jle polymac_vpclmul_done
    vmovdqu xmm0, XMMWORD PTR [rax]
    mov rcx, 135
polymac_vpclmul_loop:
    vmovdqu xmm1, XMMWORD PTR [r11]
    vpclmulqdq xmm2, xmm0, xmm1, 0
    vpclmulqdq xmm3, xmm0, xmm1, 17
    vpsrldq xmm4, xmm0, 8
    vpxor xmm4, xmm4, xmm0
    vpsrldq xmm5, xmm1, 8
    vpxor xmm5, xmm5, xmm1
    vpclmulqdq xmm4, xmm4, xmm5, 0
    vpxor xmm4, xmm4, xmm2
    vpxor xmm4, xmm4, xmm3
    vpslldq xmm5, xmm4, 8
    vpxor xmm2, xmm2, xmm5
    vpsrldq xmm4, xmm4, 8
    vpxor xmm3, xmm3, xmm4
    vmovdqu xmm0, XMMWORD PTR [r8]
    vmovdqu xmm1, XMMWORD PTR [r9]
    vpsrldq xmm4, xmm0, 8
    vpxor xmm4, xmm4, xmm0
    vpsrldq xmm5, xmm1, 8
    vpxor xmm5, xmm5, xmm1
    vpclmulqdq xmm4, xmm4, xmm5, 0
    vpclmulqdq xmm5, xmm0, xmm1, 0
    vpxor xmm4, xmm4, xmm5
    vpxor xmm2, xmm2, xmm5
    vpclmulqdq xmm5, xmm0, xmm1, 17
    vpxor xmm4, xmm4, xmm5
    vpxor xmm3, xmm3, xmm5
    vpslldq xmm5, xmm4, 8
    vpxor xmm2, xmm2, xmm5
    vpsrldq xmm4, xmm4, 8
    vpxor xmm3, xmm3, xmm4
    vmovq xmm0, rcx
    vpunpcklqdq xmm0, xmm0, xmm0
    vpclmulqdq xmm4, xmm3, xmm0, 17
    vpslldq xmm5, xmm4, 8
    vpxor xmm2, xmm2, xmm5
    vpsrldq xmm4, xmm4, 8
    vpxor xmm3, xmm3, xmm4
    vpclmulqdq xmm3, xmm3, xmm0, 0
    vpxor xmm0, xmm2, xmm3
    add r8, 16
    add r9, 16
    dec r10
    jnz polymac_vpclmul_loop
    vmovdqu XMMWORD PTR [rax], xmm0
polymac_vpclmul_done:
    vpxor xmm0, xmm0, xmm0
    vpxor xmm1, xmm1, xmm1
    vpxor xmm2, xmm2, xmm2
    vpxor xmm3, xmm3, xmm3
    vpxor xmm4, xmm4, xmm4
    vpxor xmm5, xmm5, xmm5
    xor rax, rax
    xor rcx, rcx
    xor rdx, rdx
    xor r8, r8
    xor r9, r9
    xor r10, r10
    xor r11, r11
    ret
areion_pq_gf128_polymac_vpclmul ENDP

PUBLIC areion_pq_vole_xor_row_sse2
ALIGN 16
areion_pq_vole_xor_row_sse2 PROC
    db 0F3h, 00Fh, 01Eh, 0FAh ; endbr64
    mov r9, rcx
    mov r10, r8
    mov r8, rdx
vole_sse2_loop16:
    cmp r10, 16
    jb vole_sse2_tail
    movdqu xmm0, XMMWORD PTR [r8]
    movdqu xmm1, XMMWORD PTR [r9]
    pxor xmm1, xmm0
    movdqu XMMWORD PTR [r9], xmm1
    add r8, 16
    add r9, 16
    sub r10, 16
    jmp vole_sse2_loop16
vole_sse2_tail:
    test r10, r10
    jz vole_sse2_done
vole_sse2_byte_loop:
    movzx eax, BYTE PTR [r8]
    xor BYTE PTR [r9], al
    inc r8
    inc r9
    dec r10
    jnz vole_sse2_byte_loop
vole_sse2_done:
    pxor xmm0, xmm0
    pxor xmm1, xmm1
    xor rcx, rcx
    xor rax, rax
    xor rdx, rdx
    xor r8, r8
    xor r9, r9
    xor r10, r10
    ret
areion_pq_vole_xor_row_sse2 ENDP

PUBLIC areion_pq_vole_xor_row_avx2
ALIGN 16
areion_pq_vole_xor_row_avx2 PROC
    db 0F3h, 00Fh, 01Eh, 0FAh ; endbr64
    mov r9, rcx
    mov r10, r8
    mov r8, rdx
vole_avx2_loop32:
    cmp r10, 32
    jb vole_avx2_loop16
    vmovdqu ymm0, YMMWORD PTR [r8]
    vpxor ymm0, ymm0, YMMWORD PTR [r9]
    vmovdqu YMMWORD PTR [r9], ymm0
    add r8, 32
    add r9, 32
    sub r10, 32
    jmp vole_avx2_loop32
vole_avx2_loop16:
    cmp r10, 16
    jb vole_avx2_tail
    vmovdqu xmm0, XMMWORD PTR [r8]
    vpxor xmm0, xmm0, XMMWORD PTR [r9]
    vmovdqu XMMWORD PTR [r9], xmm0
    add r8, 16
    add r9, 16
    sub r10, 16
    jmp vole_avx2_loop16
vole_avx2_tail:
    test r10, r10
    jz vole_avx2_done
vole_avx2_byte_loop:
    movzx eax, BYTE PTR [r8]
    xor BYTE PTR [r9], al
    inc r8
    inc r9
    dec r10
    jnz vole_avx2_byte_loop
vole_avx2_done:
    vpxor xmm0, xmm0, xmm0
    xor rcx, rcx
    xor rax, rax
    xor rdx, rdx
    xor r8, r8
    xor r9, r9
    xor r10, r10
    vzeroupper
    ret
areion_pq_vole_xor_row_avx2 ENDP

PUBLIC areion_pq_vole_xor_row_avx512
ALIGN 16
areion_pq_vole_xor_row_avx512 PROC
    db 0F3h, 00Fh, 01Eh, 0FAh ; endbr64
    mov r9, rcx
    mov r10, r8
    mov r8, rdx
vole_avx512_loop64:
    cmp r10, 64
    jb vole_avx512_loop16
    vmovdqu64 zmm0, ZMMWORD PTR [r8]
    vpxorq zmm0, zmm0, ZMMWORD PTR [r9]
    vmovdqu64 ZMMWORD PTR [r9], zmm0
    add r8, 64
    add r9, 64
    sub r10, 64
    jmp vole_avx512_loop64
vole_avx512_loop16:
    cmp r10, 16
    jb vole_avx512_tail
    vmovdqu xmm0, XMMWORD PTR [r8]
    vpxor xmm0, xmm0, XMMWORD PTR [r9]
    vmovdqu XMMWORD PTR [r9], xmm0
    add r8, 16
    add r9, 16
    sub r10, 16
    jmp vole_avx512_loop16
vole_avx512_tail:
    test r10, r10
    jz vole_avx512_done
vole_avx512_byte_loop:
    movzx eax, BYTE PTR [r8]
    xor BYTE PTR [r9], al
    inc r8
    inc r9
    dec r10
    jnz vole_avx512_byte_loop
vole_avx512_done:
    vpxord xmm0, xmm0, xmm0
    xor rcx, rcx
    xor rax, rax
    xor rdx, rdx
    xor r8, r8
    xor r9, r9
    xor r10, r10
    vzeroupper
    ret
areion_pq_vole_xor_row_avx512 ENDP

PUBLIC areion_pq_dump_simd_regs
ALIGN 16
areion_pq_dump_simd_regs PROC
    db 0F3h, 00Fh, 01Eh, 0FAh ; endbr64
    mov QWORD PTR [rcx + 512], rax
    mov QWORD PTR [rcx + 520], 0
    mov QWORD PTR [rcx + 528], 0
    mov QWORD PTR [rcx + 536], 0
    mov QWORD PTR [rcx + 544], r8
    mov QWORD PTR [rcx + 552], r9
    mov QWORD PTR [rcx + 560], r10
    mov QWORD PTR [rcx + 568], r11
    mov QWORD PTR [rcx + 576], 0
    mov QWORD PTR [rcx + 584], 0
    mov QWORD PTR [rcx + 592], 0
    mov rax, rcx
    mov ecx, edx
    movdqu XMMWORD PTR [rax], xmm0
    movdqu XMMWORD PTR [rax + 16], xmm1
    movdqu XMMWORD PTR [rax + 32], xmm2
    movdqu XMMWORD PTR [rax + 48], xmm3
    movdqu XMMWORD PTR [rax + 64], xmm4
    movdqu XMMWORD PTR [rax + 80], xmm5
    movdqu XMMWORD PTR [rax + 96], xmm6
    movdqu XMMWORD PTR [rax + 112], xmm7
    movdqu XMMWORD PTR [rax + 128], xmm8
    movdqu XMMWORD PTR [rax + 144], xmm9
    movdqu XMMWORD PTR [rax + 160], xmm10
    movdqu XMMWORD PTR [rax + 176], xmm11
    movdqu XMMWORD PTR [rax + 192], xmm12
    movdqu XMMWORD PTR [rax + 208], xmm13
    movdqu XMMWORD PTR [rax + 224], xmm14
    movdqu XMMWORD PTR [rax + 240], xmm15
    test ecx, ecx
    jz pq_dump_done
    vmovdqu64 XMMWORD PTR [rax + 256], xmm16
    vmovdqu64 XMMWORD PTR [rax + 272], xmm17
    vmovdqu64 XMMWORD PTR [rax + 288], xmm18
    vmovdqu64 XMMWORD PTR [rax + 304], xmm19
    vmovdqu64 XMMWORD PTR [rax + 320], xmm20
    vmovdqu64 XMMWORD PTR [rax + 336], xmm21
    vmovdqu64 XMMWORD PTR [rax + 352], xmm22
    vmovdqu64 XMMWORD PTR [rax + 368], xmm23
    vmovdqu64 XMMWORD PTR [rax + 384], xmm24
    vmovdqu64 XMMWORD PTR [rax + 400], xmm25
    vmovdqu64 XMMWORD PTR [rax + 416], xmm26
    vmovdqu64 XMMWORD PTR [rax + 432], xmm27
    vmovdqu64 XMMWORD PTR [rax + 448], xmm28
    vmovdqu64 XMMWORD PTR [rax + 464], xmm29
    vmovdqu64 XMMWORD PTR [rax + 480], xmm30
    vmovdqu64 XMMWORD PTR [rax + 496], xmm31
    vpxord xmm16, xmm16, xmm16
    vpxord xmm17, xmm17, xmm17
    vpxord xmm18, xmm18, xmm18
    vpxord xmm19, xmm19, xmm19
    vpxord xmm20, xmm20, xmm20
    vpxord xmm21, xmm21, xmm21
    vpxord xmm22, xmm22, xmm22
    vpxord xmm23, xmm23, xmm23
    vpxord xmm24, xmm24, xmm24
    vpxord xmm25, xmm25, xmm25
    vpxord xmm26, xmm26, xmm26
    vpxord xmm27, xmm27, xmm27
    vpxord xmm28, xmm28, xmm28
    vpxord xmm29, xmm29, xmm29
    vpxord xmm30, xmm30, xmm30
    vpxord xmm31, xmm31, xmm31
    vzeroupper
pq_dump_done:
    pxor xmm0, xmm0
    pxor xmm1, xmm1
    pxor xmm2, xmm2
    pxor xmm3, xmm3
    pxor xmm4, xmm4
    pxor xmm5, xmm5
    xor rax, rax
    xor rcx, rcx
    xor rdx, rdx
    xor r8, r8
    xor r9, r9
    xor r10, r10
    xor r11, r11
    ret
areion_pq_dump_simd_regs ENDP

PUBLIC areion_pq_clobber_scratch_gprs_asm
ALIGN 16
areion_pq_clobber_scratch_gprs_asm PROC
    db 0F3h, 00Fh, 01Eh, 0FAh ; endbr64
    pxor xmm0, xmm0
    pxor xmm1, xmm1
    pxor xmm2, xmm2
    pxor xmm3, xmm3
    pxor xmm4, xmm4
    pxor xmm5, xmm5
    xor rax, rax
    xor rcx, rcx
    xor rdx, rdx
    xor r8, r8
    xor r9, r9
    xor r10, r10
    xor r11, r11
    ret
areion_pq_clobber_scratch_gprs_asm ENDP

PUBLIC areion_pq_dirty_simd_reg_for_test
ALIGN 16
areion_pq_dirty_simd_reg_for_test PROC
    db 0F3h, 00Fh, 01Eh, 0FAh ; endbr64
    mov r10, rcx
    mov rax, 6148914691236517205
    xor r10, rax
    movq xmm2, r10
    xor rax, rax
    ret
areion_pq_dirty_simd_reg_for_test ENDP

END
