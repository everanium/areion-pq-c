#!/usr/bin/env python3
# Copyright (c) 2026 Andrey Kuvshinov
# Dual-licensed under Apache-2.0 OR MIT.
"""
Self-contained generator for Microsoft MASM (msvc/areion_pq_amd64.asm) and
ARMASM64 (msvc/areion_pq_arm64.asm) assembly files directly from the C
repository's GNU GAS (areion_pq_amd64.S and areion_pq_arm64.S) sources.
"""

from pathlib import Path
import re
import sys

C_REPO = Path(__file__).resolve().parent.parent

MASM_MNEMONIC_MAP = {
    "movabsq": "mov",
    "movl": "mov",
    "movb": "mov",
    "movzbl": "movzx",
    "xorq": "xor",
    "xorl": "xor",
    "xorb": "xor",
    "addq": "add",
    "addl": "add",
    "subq": "sub",
    "subl": "sub",
    "cmpq": "cmp",
    "cmpl": "cmp",
    "testq": "test",
    "testl": "test",
    "andq": "and",
    "andl": "and",
    "orq": "or",
    "orl": "or",
    "shrq": "shr",
    "shrl": "shr",
    "shlq": "shl",
    "shll": "shl",
    "leaq": "lea",
    "decq": "dec",
    "incq": "inc",
    "retq": "ret",
}

BRANCH_MNEMONICS = {
    "jz", "jnz", "je", "jne", "jmp",
    "jb", "jae", "jbe", "ja",
    "jl", "jge", "jle", "jg",
    "jc", "jnc", "js", "jns",
}


def strip_c_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    out = []
    for line in text.splitlines():
        if "//" in line:
            line = line.split("//", 1)[0]
        out.append(line)
    return "\n".join(out)


def split_operands(s: str) -> list[str]:
    out = []
    cur = []
    depth = 0
    for ch in s:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur).strip())
    return out


def eval_win64_lines(body: str) -> list[str]:
    """Extracts the lines active when _WIN64 is defined."""
    out = []
    state = "BOTH"  # BOTH, NOT_WIN64, WIN64
    for raw in body.splitlines():
        s = raw.strip()
        if not s:
            continue
        if s in ("#if !defined(_WIN64)", "#ifndef _WIN64"):
            state = "NOT_WIN64"
            continue
        if s in ("#if defined(_WIN64)", "#ifdef _WIN64"):
            state = "WIN64"
            continue
        if s == "#else":
            state = "WIN64" if state == "NOT_WIN64" else "NOT_WIN64"
            continue
        if s.startswith("#endif"):
            state = "BOTH"
            continue
        if state in ("BOTH", "WIN64"):
            out.append(s)
    return out


def infer_mem_ptr_prefix(mnem: str, ops: list[str]) -> str:
    if mnem == "leaq":
        return ""
    if mnem in ("movzbl", "xorb", "movb"):
        return "BYTE PTR "
    if mnem in ("movq", "xorq", "addq", "subq", "cmpq", "testq", "andq", "orq", "shrq", "shlq", "decq", "incq"):
        if mnem == "movq" and any("%xmm" in o for o in ops):
            return "QWORD PTR "
        return "QWORD PTR "
    if mnem in ("movl", "xorl", "addl", "subl", "cmpl", "testl", "andl", "orl", "shrl", "shll"):
        return "DWORD PTR "
    if mnem in (
        "vinserti128",
        "vextracti128",
        "vinserti32x4",
        "vextracti32x4",
        "vbroadcasti128",
        "vbroadcasti32x4",
    ):
        return "XMMWORD PTR "
    if mnem in ("vinserti64x4", "vextracti64x4"):
        return "YMMWORD PTR "
    joined = " ".join(ops)
    if "%zmm" in joined:
        return "ZMMWORD PTR "
    if "%ymm" in joined:
        return "YMMWORD PTR "
    return "XMMWORD PTR "


def convert_att_op_to_masm(op: str, ptr_prefix: str) -> str:
    op = op.strip()
    if op.startswith("$"):
        val = int(op[1:], 0)
        return str(val)
    if op.startswith("%"):
        return op[1:]
    m_sym = re.match(r"^(?:(-?\d+)\+)?AREION_SYM\((\w+)\)\(%rip\)$", op)
    if m_sym:
        disp, sym = m_sym.group(1), m_sym.group(2)
        if disp and int(disp) != 0:
            return f"{ptr_prefix}[{sym} + {disp}]"
        return f"{ptr_prefix}[{sym}]"
    m_mem = re.match(r"^(-?\d+)?\(%(\w+)(?:,\s*%(\w+)(?:,\s*(\d+))?)?\)$", op)
    if m_mem:
        disp, base, idx, scale = m_mem.group(1), m_mem.group(2), m_mem.group(3), m_mem.group(4)
        expr = base
        if idx:
            if scale and int(scale) != 1:
                expr += f" + {idx}*{scale}"
            else:
                expr += f" + {idx}"
        if disp and (int(disp) != 0 or (base == "rsp" and not idx)):
            dval = int(disp)
            if dval < 0:
                expr += f" - {-dval}"
            else:
                expr += f" + {dval}"
        return f"{ptr_prefix}[{expr}]"
    return op


def translate_s_to_masm(s_filename: str, msvc_filename: str, check_only: bool = False) -> None:
    s_path = C_REPO / s_filename
    if not s_path.exists():
        return
    text = strip_c_comments(s_path.read_text(encoding="utf-8"))
    funcs = re.findall(
        r"AREION_FUNC_START\((\w+)\)\s*(.*?)AREION_FUNC_END\(\1\)",
        text,
        re.S,
    )

    masm_lines = [
        "; Copyright (c) 2026 Andrey Kuvshinov",
        "; SPDX-License-Identifier: Apache-2.0 OR MIT",
        "",
        "EXTERN areion_pq_rc_p1:BYTE",
        "EXTERN areion_pq_rc_p2:BYTE",
        "",
        ".code",
        "",
    ]

    for fname, body in funcs:
        win_lines = eval_win64_lines(body)
        masm_lines.extend([
            f"PUBLIC {fname}",
            "ALIGN 16",
            f"{fname} PROC",
            "    db 0F3h, 00Fh, 01Eh, 0FAh ; endbr64",
        ])
        for line in win_lines:
            if line.endswith(":"):
                lbl = line[:-1].strip()
                if lbl.startswith(".L"):
                    lbl = lbl[2:]
                masm_lines.append(f"{lbl}:")
                continue
            parts = line.split(None, 1)
            mnem = parts[0]
            if len(parts) == 1:
                masm_mnem = MASM_MNEMONIC_MAP.get(mnem, mnem)
                masm_lines.append(f"    {masm_mnem}")
                continue
            ops_att = split_operands(parts[1])
            if mnem in BRANCH_MNEMONICS:
                target = ops_att[0]
                if target.startswith(".L"):
                    target = target[2:]
                masm_lines.append(f"    {mnem} {target}")
                continue
            ptr_prefix = infer_mem_ptr_prefix(mnem, ops_att)
            if mnem == "movq":
                masm_mnem = "movq" if any("%xmm" in o for o in ops_att) else "mov"
            else:
                masm_mnem = MASM_MNEMONIC_MAP.get(mnem, mnem)
            ops_masm = [convert_att_op_to_masm(o, ptr_prefix) for o in reversed(ops_att)]
            masm_lines.append(f"    {masm_mnem} {', '.join(ops_masm)}")

        masm_lines.extend([
            f"{fname} ENDP",
            "",
        ])

    masm_lines.append("END")
    masm_lines.append("")
    content = "\n".join(masm_lines)
    out_path = C_REPO / "msvc" / msvc_filename
    if check_only:
        assert out_path.exists() and out_path.read_text(encoding="utf-8") == content, (
            f"msvc/{msvc_filename} is out of sync with {s_filename}"
        )
    else:
        out_path.write_text(content, encoding="utf-8")


def translate_arm64_s_to_armasm(s_filename: str, msvc_filename: str, check_only: bool = False) -> None:
    s_path = C_REPO / s_filename
    if not s_path.exists():
        return
    text = strip_c_comments(s_path.read_text(encoding="utf-8"))
    funcs = re.findall(
        r"AREION_FUNC_START\((\w+)\)\s*(.*?)AREION_FUNC_END\(\1\)",
        text,
        re.S,
    )

    armasm_lines = [
        "; Copyright (c) 2026 Andrey Kuvshinov",
        "; SPDX-License-Identifier: Apache-2.0 OR MIT",
        "",
        "    AREA |.text|, CODE, READONLY, ALIGN=4",
        "    IMPORT areion_pq_rc_p1",
        "    IMPORT areion_pq_rc_p2",
        "",
    ]

    for fname, body in funcs:
        armasm_lines.extend([
            f"    EXPORT {fname}",
            f"{fname} PROC",
            "    hint #34 ; bti c",
        ])
        for raw in body.splitlines():
            s = raw.strip()
            if not s or s.startswith("#"):
                continue
            if s.endswith(":"):
                lbl = s[:-1].strip()
                if lbl.startswith(".L"):
                    lbl = lbl[2:]
                armasm_lines.append(f"{lbl}:")
                continue
            m_adr = re.match(r"^AREION_ARM64_ADR\((x\d+),\s*(\w+)\)$", s)
            if m_adr:
                reg, sym = m_adr.group(1), m_adr.group(2)
                armasm_lines.append(f"    adrp {reg}, {sym}")
                armasm_lines.append(f"    add {reg}, {reg}, {sym}")
                continue
            s_conv = re.sub(r"\.L(\w+)", r"\1", s)
            armasm_lines.append(f"    {s_conv}")
        armasm_lines.extend([
            "    ENDP",
            "",
        ])

    armasm_lines.append("    END")
    armasm_lines.append("")
    content = "\n".join(armasm_lines)
    out_path = C_REPO / "msvc" / msvc_filename
    if check_only:
        assert out_path.exists() and out_path.read_text(encoding="utf-8") == content, (
            f"msvc/{msvc_filename} is out of sync with {s_filename}"
        )
    else:
        out_path.write_text(content, encoding="utf-8")


def main() -> int:
    check_only = "--check" in sys.argv[1:]
    (C_REPO / "msvc").mkdir(parents=True, exist_ok=True)
    translate_s_to_masm("areion_pq_amd64.S", "areion_pq_amd64.asm", check_only=check_only)
    translate_arm64_s_to_armasm("areion_pq_arm64.S", "areion_pq_arm64.asm", check_only=check_only)
    if check_only:
        print("OK: All MSVC (msvc/areion_pq_*.asm) assembly files are in sync with .S sources.")
    else:
        print("OK: Generated all MSVC (msvc/areion_pq_*.asm) assembly files from .S sources.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
