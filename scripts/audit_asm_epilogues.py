#!/usr/bin/env python3
# Copyright (c) 2026 Andrey Kuvshinov
# Dual-licensed under Apache-2.0 OR MIT.
"""
Static & disassembly auditor for GNU GAS (areion_pq_amd64.S, areion_pq_arm64.S),
Microsoft MASM/armasm64 (msvc/areion_pq_amd64.asm, msvc/areion_pq_arm64.asm),
and compiled ELF/COFF object files (.o) in areion-pq-c.

Verifies:
1. Function inventory (all assembly kernels for witness extraction, GF(2^128) mul/polymac, VOLE XOR).
2. Epilogue register zeroization (100% of touched vector & GPR registers wiped before RET).
3. Windows x64 (_WIN64) ABI compliance (XMM6..XMM15, RSI, RDI save/restore + stack slot wipe,
   R12..R15/RBX/RBP untouched, vzeroupper right before ret).
4. ARM64 AAPCS64 ABI compliance (zero stack frame, v8..v15 and x18..x30 untouched).
5. Disassembly (objdump -d) verification of compiled x86_64 (SysV and _WIN64) and aarch64 object files.
"""

import platform
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

C_DIR = Path(__file__).resolve().parent.parent

SKIP_FUNCS = {
    "cpuid",
    "_cpuid",
    "areion_pq_cpuid",
    "_areion_pq_cpuid",
    "areion_pq_xgetbv",
    "_areion_pq_xgetbv",
    "dumpSIMDRegs",
    "_dumpSIMDRegs",
    "areion_pq_dump_simd_regs",
    "_areion_pq_dump_simd_regs",
    "dumpDone",
    "_dumpDone",
    "clobberScratchGPRs",
    "_clobberScratchGPRs",
    "areion_pq_clobber_scratch_gprs_asm",
    "_areion_pq_clobber_scratch_gprs_asm",
    "dirtySIMDRegForTest",
    "_dirtySIMDRegForTest",
    "areion_pq_dirty_simd_reg_for_test",
    "_areion_pq_dirty_simd_reg_for_test",
}

EXPECTED_X86_KERNELS = [
    "areion_pq_extract_witness256_aesni",
    "areion_pq_extract_witness256_vex",
    "areion_pq_gf128_mul_pclmul",
    "areion_pq_gf128_mul_vpclmul",
    "areion_pq_gf128_polymac_pclmul",
    "areion_pq_gf128_polymac_vpclmul",
    "areion_pq_vole_xor_row_sse2",
    "areion_pq_vole_xor_row_avx2",
    "areion_pq_vole_xor_row_avx512",
]

EXPECTED_ARM64_KERNELS = [
    "areion_pq_extract_witness256_arm64",
    "areion_pq_gf128_mul_pmull",
    "areion_pq_gf128_polymac_pmull",
    "areion_pq_vole_xor_row_neon",
]


def strip_c_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    out = []
    for line in text.splitlines():
        if "//" in line:
            line = line.split("//", 1)[0]
        out.append(line)
    return "\n".join(out)


def eval_abi_lines(body: str, win64: bool) -> list[str]:
    out = []
    state = "BOTH"
    for raw in body.splitlines():
        s = raw.strip()
        if not s:
            continue
        if s in ("#if !defined(_WIN64)", "#ifndef _WIN64"):
            state = "SYSV"
            continue
        if s in ("#if defined(_WIN64)", "#ifdef _WIN64"):
            state = "WIN64"
            continue
        if s == "#else":
            state = "WIN64" if state == "SYSV" else "SYSV"
            continue
        if s.startswith("#endif"):
            state = "BOTH"
            continue
        if state == "BOTH" or (win64 and state == "WIN64") or (not win64 and state == "SYSV"):
            out.append(s)
    return out


X86_GPR_MAP = {
    "rax": "rax", "eax": "rax", "ax": "rax", "al": "rax", "ah": "rax",
    "rcx": "rcx", "ecx": "rcx", "cx": "rcx", "cl": "rcx", "ch": "rcx",
    "rdx": "rdx", "edx": "rdx", "dx": "rdx", "dl": "rdx", "dh": "rdx",
    "rsi": "rsi", "esi": "rsi", "si": "rsi", "sil": "rsi",
    "rdi": "rdi", "edi": "rdi", "di": "rdi", "dil": "rdi",
    "r8": "r8", "r8d": "r8", "r8w": "r8", "r8b": "r8",
    "r9": "r9", "r9d": "r9", "r9w": "r9", "r9b": "r9",
    "r10": "r10", "r10d": "r10", "r10w": "r10", "r10b": "r10",
    "r11": "r11", "r11d": "r11", "r11w": "r11", "r11b": "r11",
}
X86_GPR_RE = "|".join(sorted(X86_GPR_MAP.keys(), key=len, reverse=True))


def split_body_and_epilogue(lines: list[str], zero_re: re.Pattern[str]) -> tuple[str, str]:
    idx = len(lines)
    while idx > 0:
        ln = lines[idx - 1].strip()
        if ln in ("ret", "retq", "vzeroupper") or ln.endswith(":") or zero_re.match(ln):
            idx -= 1
        else:
            break
    return "\n".join(lines[:idx]), "\n".join(lines[idx:])


def audit_c_amd64_S_and_masm() -> int:
    s_name = "areion_pq_amd64.S"
    masm_name = "areion_pq_amd64.asm"
    s_text = strip_c_comments((C_DIR / s_name).read_text(encoding="utf-8"))
    masm_text = (C_DIR / "msvc" / masm_name).read_text(encoding="utf-8")

    s_blocks = re.findall(r"AREION_FUNC_START\((\w+)\)(.*?)AREION_FUNC_END\(\1\)", s_text, flags=re.S)
    masm_blocks = re.findall(r"(\w+)\s+PROC\b(.*?)\1\s+ENDP", masm_text, flags=re.S)
    assert [b[0] for b in s_blocks] == [b[0] for b in masm_blocks], (
        f"Function list mismatch between {s_name} and {masm_name}"
    )

    att_zero_re = re.compile(
        r"^(?:(?:pxor|vpxor|vpxord|vpxorq)\s+%[xyz]mm(\d+),\s*%[xyz]mm\1(?:,\s*%[xyz]mm\1)?|"
        r"xorq\s+%(rax|rcx|rdx|rsi|rdi|r8|r9|r10|r11),\s*%\2)$"
    )
    masm_zero_re = re.compile(
        r"^(?:(?:pxor|vpxor|vpxord|vpxorq)\s+[xyz]mm(\d+),\s*[xyz]mm\1(?:,\s*[xyz]mm\1)?|"
        r"xor\s+(rax|rcx|rdx|rsi|rdi|r8|r9|r10|r11),\s*\2)$"
    )

    total_s = 0
    total_masm = 0
    found_x86 = set()
    for (fn, s_body), (_, m_body) in zip(s_blocks, masm_blocks):
        if fn in SKIP_FUNCS:
            continue
        total_s += 1
        total_masm += 1
        if fn in EXPECTED_X86_KERNELS:
            found_x86.add(fn)

        for forbidden in ("rbx", "rbp", "r12", "r13", "r14", "r15"):
            assert not re.search(rf"\b{forbidden}\b", s_body), f"{s_name}:{fn} touches callee-saved %{forbidden}"
            assert not re.search(rf"\b{forbidden}\b", m_body), f"{masm_name}:{fn} touches callee-saved {forbidden}"

        touched_xmm_win = sorted(set(int(x) for x in re.findall(r"\b[xyz]mm(\d+)\b", m_body) if 6 <= int(x) <= 15))
        touched_gpr_win = [g for g in ("rsi", "rdi") if re.search(rf"\b{g}\b", m_body)]
        if touched_xmm_win or touched_gpr_win:
            m_sub = re.search(r"sub rsp, (\d+)", m_body)
            m_add = re.search(r"add rsp, (\d+)", m_body)
            assert m_sub and m_add and m_sub.group(1) == m_add.group(1), f"{masm_name}:{fn} mismatched rsp sub/add"
            frame_sz = int(m_sub.group(1))
            assert frame_sz % 16 == 8, f"{masm_name}:{fn} Win64 frame size {frame_sz} does not align RSP to 16 bytes"
            for x in touched_xmm_win:
                m_save = re.search(rf"v?movdqu XMMWORD PTR \[rsp(?:\s*\+\s*(\d+))?\], xmm{x}\b", m_body)
                assert m_save, f"{masm_name}:{fn} missing Win64 save for xmm{x}"
                off = int(m_save.group(1) or 0)
                if off == 0:
                    assert re.search(rf"v?movdqu xmm{x}, XMMWORD PTR \[rsp(?:\s*\+\s*0)?\]", m_body), (
                        f"{masm_name}:{fn} missing restore for xmm{x}"
                    )
                    assert re.search(r"mov QWORD PTR \[rsp(?:\s*\+\s*0)?\], 0", m_body), (
                        f"{masm_name}:{fn} missing low QWORD stack wipe for xmm{x}"
                    )
                else:
                    assert re.search(rf"v?movdqu xmm{x}, XMMWORD PTR \[rsp \+ {off}\]", m_body), (
                        f"{masm_name}:{fn} missing restore for xmm{x}"
                    )
                    assert f"mov QWORD PTR [rsp + {off}], 0" in m_body, (
                        f"{masm_name}:{fn} missing low QWORD stack wipe for xmm{x}"
                    )
                assert f"mov QWORD PTR [rsp + {off + 8}], 0" in m_body, (
                    f"{masm_name}:{fn} missing high QWORD stack wipe for xmm{x}"
                )
            for g in touched_gpr_win:
                m_save = re.search(rf"mov QWORD PTR \[rsp(?:\s*\+\s*(\d+))?\], {g}\b", m_body)
                assert m_save, f"{masm_name}:{fn} missing Win64 save for {g}"
                off = int(m_save.group(1) or 0)
                if off == 0:
                    assert re.search(rf"mov {g}, QWORD PTR \[rsp(?:\s*\+\s*0)?\]", m_body), (
                        f"{masm_name}:{fn} missing Win64 restore for {g}"
                    )
                    assert re.search(r"mov QWORD PTR \[rsp(?:\s*\+\s*0)?\], 0", m_body), (
                        f"{masm_name}:{fn} missing Win64 stack wipe for {g}"
                    )
                else:
                    assert f"mov {g}, QWORD PTR [rsp + {off}]" in m_body, f"{masm_name}:{fn} missing Win64 restore for {g}"
                    assert f"mov QWORD PTR [rsp + {off}], 0" in m_body, f"{masm_name}:{fn} missing Win64 stack wipe for {g}"

        for abi_label, is_win64 in (("SysV", False), ("_WIN64", True)):
            abi_lines = eval_abi_lines(s_body, is_win64)
            core_txt, epi_txt = split_body_and_epilogue(abi_lines, att_zero_re)
            all_vec = set(int(x) for x in re.findall(r"%[xyz]mm(\d+)\b", core_txt))
            zeroed_vec = set(
                int(m.group(1))
                for m in re.finditer(r"\b(?:pxor|vpxor|vpxord|vpxorq)\s+%[xyz]mm(\d+),\s*%[xyz]mm\1(?:,\s*%[xyz]mm\1)?\b", epi_txt)
            )
            unzero_v = sorted(all_vec - zeroed_vec)
            extra_v = sorted(zeroed_vec - all_vec)
            assert not unzero_v and not extra_v, (
                f"{s_name}:{fn} [{abi_label}] vector parity mismatch: unzero_v={unzero_v}, extra_v={extra_v}"
            )

            all_gpr = set(X86_GPR_MAP[r] for r in re.findall(rf"%({X86_GPR_RE})\b", core_txt))
            zeroed_gpr = set(
                m.group(1)
                for m in re.finditer(r"\bxorq\s+%(rax|rcx|rdx|rsi|rdi|r8|r9|r10|r11),\s*%\1\b", epi_txt)
            )
            unzero_g = sorted(all_gpr - zeroed_gpr)
            extra_g = sorted(zeroed_gpr - all_gpr)
            assert not unzero_g and not extra_g, (
                f"{s_name}:{fn} [{abi_label}] GPR parity mismatch: unzero_g={unzero_g}, extra_g={extra_g}"
            )

        m_lines = [l.strip() for l in m_body.splitlines() if l.strip()]
        m_core_txt, m_epi_txt = split_body_and_epilogue(m_lines[1:], masm_zero_re)
        m_all_vec = set(int(x) for x in re.findall(r"\b[xyz]mm(\d+)\b", m_core_txt))
        m_zeroed_vec = set(
            int(m.group(1))
            for m in re.finditer(r"\b(?:pxor|vpxor|vpxord|vpxorq)\s+[xyz]mm(\d+),\s*[xyz]mm\1(?:,\s*[xyz]mm\1)?\b", m_epi_txt)
        )
        assert m_all_vec == m_zeroed_vec, (
            f"{masm_name}:{fn} vector parity mismatch: unzero_v={sorted(m_all_vec - m_zeroed_vec)}, extra_v={sorted(m_zeroed_vec - m_all_vec)}"
        )
        m_all_gpr = set(X86_GPR_MAP[r] for r in re.findall(rf"\b({X86_GPR_RE})\b", m_core_txt))
        m_zeroed_gpr = set(
            m.group(1)
            for m in re.finditer(r"\bxor\s+(rax|rcx|rdx|rsi|rdi|r8|r9|r10|r11),\s*\1\b", m_epi_txt)
        )
        assert m_all_gpr == m_zeroed_gpr, (
            f"{masm_name}:{fn} GPR parity mismatch: unzero_g={sorted(m_all_gpr - m_zeroed_gpr)}, extra_g={sorted(m_zeroed_gpr - m_all_gpr)}"
        )

        uses_wide_vec = bool(re.search(r"\b[yz]mm\d+\b|\bxmm(?:1[6-9]|2\d|3[01])\b", m_body))
        assert m_lines[0] == "db 0F3h, 00Fh, 01Eh, 0FAh ; endbr64", (
            f"{masm_name}:{fn} does not start with endbr64 (got {m_lines[0]})"
        )
        assert m_lines[-1] == "ret", f"{masm_name}:{fn} does not end with ret"
        if uses_wide_vec:
            assert m_lines[-2] == "vzeroupper", (
                f"{masm_name}:{fn} does not have vzeroupper immediately before ret (got {m_lines[-2]})"
            )

    assert found_x86 == set(EXPECTED_X86_KERNELS), (
        f"Missing x86 PQ kernels: {set(EXPECTED_X86_KERNELS) - found_x86}"
    )
    print(
        f"OK [C amd64 .S & msvc/{masm_name}]: Audited {total_s} .S functions (SysV + _WIN64) and {total_masm} MASM PROC functions. "
        f"100% ABI & epilogue clean (unzero_v=0, extra_v=0, unzero_g=0, extra_g=0)."
    )
    return total_s


def audit_c_arm64_S_and_armasm() -> int:
    s_text = strip_c_comments((C_DIR / "areion_pq_arm64.S").read_text(encoding="utf-8"))
    m_text = (C_DIR / "msvc" / "areion_pq_arm64.asm").read_text(encoding="utf-8")

    s_blocks = re.findall(r"AREION_FUNC_START\((\w+)\)(.*?)AREION_FUNC_END\(\1\)", s_text, flags=re.S)
    m_blocks = re.findall(r"(\w+)\s+PROC\b(.*?)ENDP", m_text, flags=re.S)
    assert [b[0] for b in s_blocks] == [b[0] for b in m_blocks], (
        "Function list mismatch between areion_pq_arm64.S and msvc/areion_pq_arm64.asm"
    )

    arm_zero_re = re.compile(
        r"^(?:eor\s+v(\d+)\.16b,\s*v\1\.16b,\s*v\1\.16b|mov\s+x(\d+),\s*xzr)$"
    )

    total = 0
    found_arm64 = set()
    for (fn, s_body), (_, m_body) in zip(s_blocks, m_blocks):
        if fn in SKIP_FUNCS:
            continue
        total += 1
        if fn in EXPECTED_ARM64_KERNELS:
            found_arm64.add(fn)
        for r in range(18, 31):
            assert not re.search(rf"\b[xw]{r}\b", s_body), f"areion_pq_arm64.S:{fn} touches x{r}/w{r}"
            assert not re.search(rf"\b[xw]{r}\b", m_body), f"msvc/areion_pq_arm64.asm:{fn} touches x{r}/w{r}"

        touched_v_callee = sorted(set(int(v) for v in re.findall(r"\b[vdq](\d+)\b", s_body) if 8 <= int(v) <= 15))
        assert not touched_v_callee, f"areion_pq_arm64.S:{fn} touches callee-saved v8..v15: {touched_v_callee}"
        assert not re.search(r"\b(?:sub|add)\s+sp,\s*sp\b", s_body), f"areion_pq_arm64.S:{fn} allocates stack frame"

        for src_label, body_txt in (("areion_pq_arm64.S", s_body), ("msvc/areion_pq_arm64.asm", m_body)):
            lines = [l.strip() for l in body_txt.splitlines() if l.strip() and not l.strip().startswith("hint")]
            core_txt, epi_txt = split_body_and_epilogue(lines, arm_zero_re)
            all_v = set(int(v) for v in re.findall(r"\bv(\d+)\b", core_txt))
            zeroed_v = set(
                int(m.group(1))
                for m in re.finditer(r"\beor\s+v(\d+)\.16b,\s*v\1\.16b,\s*v\1\.16b\b", epi_txt)
            )
            assert all_v == zeroed_v, (
                f"{src_label}:{fn} V-reg parity mismatch: unzero_v={sorted(all_v - zeroed_v)}, extra_v={sorted(zeroed_v - all_v)}"
            )

            all_x = set(int(r) for r in re.findall(r"\b[xw](\d+)\b", core_txt))
            zeroed_x = set(
                int(m.group(1))
                for m in re.finditer(r"\bmov\s+x(\d+),\s*xzr\b", epi_txt)
            )
            assert all_x == zeroed_x, (
                f"{src_label}:{fn} X-reg parity mismatch: unzero_g={sorted(all_x - zeroed_x)}, extra_g={sorted(zeroed_x - all_x)}"
            )

    assert found_arm64 == set(EXPECTED_ARM64_KERNELS), (
        f"Missing arm64 PQ kernels: {set(EXPECTED_ARM64_KERNELS) - found_arm64}"
    )
    print(
        f"OK [C arm64 .S & msvc/areion_pq_arm64.asm]: Audited {total} functions. "
        f"100% stackless AAPCS64 ABI & epilogue clean (unzero_v=0, extra_v=0, unzero_g=0, extra_g=0)."
    )
    return total


def audit_objdump() -> None:
    if not sys.platform.startswith("linux") or not shutil.which("objdump") or not shutil.which("readelf"):
        print("SKIP [objdump -d]: Non-Linux host or missing ELF objdump/readelf.")
        return
    x86_srcs = ["areion_pq_amd64.S"]
    x86_sysv_count = 0
    x86_win64_count = 0
    arm_fn_count = 0
    mach = platform.machine().lower()
    x86_cc = "gcc" if mach in ("x86_64", "amd64") else shutil.which("x86_64-linux-gnu-gcc")
    x86_objdump = "objdump" if mach in ("x86_64", "amd64") else shutil.which("x86_64-linux-gnu-objdump")
    arm_cc = "gcc" if mach in ("aarch64", "arm64") else shutil.which("aarch64-linux-gnu-gcc")
    arm_objdump = "objdump" if mach in ("aarch64", "arm64") else shutil.which("aarch64-linux-gnu-objdump")
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        if x86_cc and x86_objdump:
            for src in x86_srcs:
                obj_sysv = tmp / f"{src}.sysv.o"
                obj_win64 = tmp / f"{src}.win64.o"
                subprocess.run([x86_cc, "-I", str(C_DIR), "-c", str(C_DIR / src), "-o", str(obj_sysv)], check=True)
                subprocess.run([x86_cc, "-I", str(C_DIR), "-D_WIN64", "-c", str(C_DIR / src), "-o", str(obj_win64)], check=True)

                out_sysv = subprocess.check_output([x86_objdump, "-d", "--no-show-raw-insn", str(obj_sysv)], text=True)
                for blk in re.split(r"(?=^[0-9a-f]+ <\w+>:\n)", out_sysv, flags=re.M):
                    m_hdr = re.match(r"^[0-9a-f]+ <(\w+)>:\n(.*)", blk, flags=re.S)
                    if not m_hdr:
                        continue
                    fn, body = m_hdr.group(1), m_hdr.group(2)
                    if fn in SKIP_FUNCS:
                        continue
                    x86_sysv_count += 1
                    rsp_refs = re.findall(r"[^\s,]*\(%rsp\)", body)
                    assert not rsp_refs, f"{src}:{fn} has unexpected stack references in SysV object: {rsp_refs}"
                    assert not re.search(r"\b(?:sub|add)\b[^\n]*%rsp", body), (
                        f"{src}:{fn} adjusts %rsp in SysV object"
                    )
                    insns = [
                        l.strip()
                        for l in body.strip().splitlines()
                        if l.strip() and not l.strip().endswith(":") and not re.search(r"\b(nop|nopl|nopw|cs nopw)\b|xchg\s+%ax,%ax", l)
                    ]
                    assert insns[0].endswith("endbr64"), f"{src}:{fn} does not start with endbr64: {insns[0]}"
                    assert insns[-1].endswith("ret") or insns[-1].endswith("retq"), f"{src}:{fn} does not end with ret: {insns[-1]}"

                notes_sysv = subprocess.check_output(["readelf", "-n", str(obj_sysv)], text=True)
                assert "IBT" in notes_sysv and "SHSTK" in notes_sysv, f"{src} missing CET IBT/SHSTK note: {notes_sysv}"

                out_win64 = subprocess.check_output([x86_objdump, "-d", "--no-show-raw-insn", str(obj_win64)], text=True)
                for blk in re.split(r"(?=^[0-9a-f]+ <\w+>:\n)", out_win64, flags=re.M):
                    m_hdr = re.match(r"^[0-9a-f]+ <(\w+)>:\n(.*)", blk, flags=re.S)
                    if not m_hdr:
                        continue
                    fn, body = m_hdr.group(1), m_hdr.group(2)
                    if fn in SKIP_FUNCS:
                        continue
                    x86_win64_count += 1
                    insns = [
                        l.strip()
                        for l in body.strip().splitlines()
                        if l.strip() and not l.strip().endswith(":") and not re.search(r"\b(nop|nopl|nopw|cs nopw)\b|xchg\s+%ax,%ax", l)
                    ]
                    assert insns[0].endswith("endbr64"), f"{src} (_WIN64):{fn} does not start with endbr64: {insns[0]}"
                    assert insns[-1].endswith("ret") or insns[-1].endswith("retq"), (
                        f"{src} (_WIN64):{fn} does not end with ret: {insns[-1]}"
                    )

        if arm_cc and arm_objdump:
            obj_arm = tmp / "areion_pq_arm64.o"
            subprocess.run(
                [arm_cc, "-I", str(C_DIR), "-march=armv8-a+crypto", "-c", str(C_DIR / "areion_pq_arm64.S"), "-o", str(obj_arm)],
                check=True,
            )
            notes_arm = subprocess.check_output(["readelf", "-n", str(obj_arm)], text=True)
            assert "BTI" in notes_arm and "PAC" in notes_arm, f"areion_pq_arm64.o missing BTI/PAC note: {notes_arm}"
            out_arm = subprocess.check_output([arm_objdump, "-d", "--no-show-raw-insn", str(obj_arm)], text=True)
            for blk in re.split(r"(?=^[0-9a-f]+ <\w+>:\n)", out_arm, flags=re.M):
                m_hdr = re.match(r"^[0-9a-f]+ <(\w+)>:\n(.*)", blk, flags=re.S)
                if not m_hdr:
                    continue
                fn, body = m_hdr.group(1), m_hdr.group(2)
                if fn in SKIP_FUNCS:
                    continue
                arm_fn_count += 1
                sp_refs = [l.strip() for l in body.splitlines() if "sp" in l]
                assert not sp_refs, f"areion_pq_arm64.o:{fn} unexpected sp instruction: {sp_refs}"
                insns = [l.strip() for l in body.strip().splitlines() if l.strip() and not l.strip().endswith(":") and not re.search(r"\bnop\b", l)]
                assert "bti\tc" in insns[0] or "hint\t#0x22" in insns[0], (
                    f"areion_pq_arm64.o:{fn} does not start with bti c: {insns[0]}"
                )
                assert insns[-1].endswith("ret"), f"areion_pq_arm64.o:{fn} does not end with ret: {insns[-1]}"

    print(
        f"OK [objdump -d]: Verified {x86_sysv_count} SysV x86_64, {x86_win64_count} _WIN64 x86_64, "
        f"and {arm_fn_count} aarch64 compiled object functions. Zero secret stack spills."
    )


def main() -> int:
    audit_c_amd64_S_and_masm()
    audit_c_arm64_S_and_armasm()
    audit_objdump()
    return 0


if __name__ == "__main__":
    sys.exit(main())
