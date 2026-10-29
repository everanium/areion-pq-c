/*
 * Copyright (c) 2026 Andrey Kuvshinov
 *
 * Dual-licensed under Apache-2.0 OR MIT.
 * See LICENSE-APACHE and LICENSE-MIT for details.
 */

#ifndef AREION_ASM_ABI_H
#define AREION_ASM_ABI_H

#if defined(__APPLE__)
#define AREION_SYM(name) _##name
#else
#define AREION_SYM(name) name
#endif

#if defined(__APPLE__) && (defined(__aarch64__) || defined(__arm64__) || defined(_M_ARM64))
#define AREION_ASM_SEP %%
#else
#define AREION_ASM_SEP ;
#endif

#if defined(__x86_64__) || defined(_M_X64)
#define AREION_CET_BTI_LANDING .byte 0xf3, 0x0f, 0x1e, 0xfa AREION_ASM_SEP
#elif defined(__aarch64__) || defined(__arm64__) || defined(_M_ARM64)
#define AREION_CET_BTI_LANDING hint #34 AREION_ASM_SEP
#else
#define AREION_CET_BTI_LANDING
#endif

#if defined(__ELF__)
#define AREION_FUNC_START(name) \
    .globl AREION_SYM(name) AREION_ASM_SEP \
    .hidden AREION_SYM(name) AREION_ASM_SEP \
    .type AREION_SYM(name), %function AREION_ASM_SEP \
    .p2align 4 AREION_ASM_SEP \
AREION_SYM(name): AREION_ASM_SEP \
    AREION_CET_BTI_LANDING

#define AREION_FUNC_END(name) \
    .size AREION_SYM(name), .-AREION_SYM(name)
#elif defined(__APPLE__)
#define AREION_FUNC_START(name) \
    .globl AREION_SYM(name) AREION_ASM_SEP \
    .private_extern AREION_SYM(name) AREION_ASM_SEP \
    .p2align 4 AREION_ASM_SEP \
AREION_SYM(name): AREION_ASM_SEP \
    AREION_CET_BTI_LANDING

#define AREION_FUNC_END(name)
#else
#define AREION_FUNC_START(name) \
    .globl AREION_SYM(name) AREION_ASM_SEP \
    .p2align 4 AREION_ASM_SEP \
AREION_SYM(name): AREION_ASM_SEP \
    AREION_CET_BTI_LANDING

#define AREION_FUNC_END(name)
#endif

#if defined(__aarch64__) || defined(__arm64__) || defined(_M_ARM64)
#if defined(__APPLE__)
#define AREION_ARM64_ADR(reg, sym) \
    adrp reg, AREION_SYM(sym)@PAGE AREION_ASM_SEP \
    add reg, reg, AREION_SYM(sym)@PAGEOFF
#else
#define AREION_ARM64_ADR(reg, sym) \
    adrp reg, AREION_SYM(sym) AREION_ASM_SEP \
    add reg, reg, :lo12:AREION_SYM(sym)
#endif
#endif

#endif /* AREION_ASM_ABI_H */
