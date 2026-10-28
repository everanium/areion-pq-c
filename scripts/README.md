## Areion-PQ Auxiliary Scripts

This directory contains standalone verification, benchmarking, and code-generation tooling for `areion-pq-c`.

## Tools

### 1. `verify_cross_kat.py`

Cross-language tier-by-tier and full Cartesian product (`Go[tier_A] x C[tier_B]`) KAT parity harness comparing Go (`areion-pq`) and C (`areion-pq-c`) across all exported finite-field primitives, 288-S-box and 576-S-box witness extractors/verifiers, `FAEST-Areion` (`VOLE-in-the-Head` + `QuickSilver`) signatures, `SLH-DSA-Areion` (`NIST FIPS 205`) tweakable hashes and signatures, `AreionKDF`, `Areion-TEM2-SIV` wide-block AEAD, `Areion-HPKE`, and tier introspection functions across all execution tiers (`purego` <-> `purec`, `aesni`, `vex`, `vaesavx2`, `avx512` on `x86-64`, `purec` and `arm64` under `qemu-aarch64-static -cpu max`, and Big-Endian `s390x` under `qemu-s390x-static`), asserting 100% bit-for-bit equality. Looks up the Go repository via `AREION_PQ_GO_DIR` or adjacent relative paths (`../areion-pq`).

```bash
AREION_PQ_GO_DIR=/home/andrew/go/src/areion-pq python3 scripts/verify_cross_kat.py
```

### 2. `run_bench.py`

Automated multi-tier benchmark runner that executes `./areion_pq_test --bench` across all supported hardware dispatch tiers on the current host (`purec`, `aesni`, `vex`, `vaesavx2`, `avx512` on `x86-64`; `purec`, `arm64` on `aarch64`) and outputs a consolidated Markdown table with throughput (`MB/s`) and latency (`ns/op`).

```bash
python3 scripts/run_bench.py
```

### 3. `gen_msvc_asm.py`

Self-contained generator for Microsoft MASM (`ml64.exe`, `msvc/areion_pq_amd64.asm`) and ARMASM64 (`armasm64.exe`, `msvc/areion_pq_arm64.asm`) assembly files directly from the C repository's GNU GAS (`areion_pq_amd64.S` and `areion_pq_arm64.S`) sources.

```bash
python3 scripts/gen_msvc_asm.py
```

### 4. `audit_asm_epilogues.py`

Static and disassembly (`objdump -d`) auditor for GNU GAS (`areion_pq_amd64.S`, `areion_pq_arm64.S`), Microsoft MASM / ARMASM64 (`msvc/areion_pq_amd64.asm`, `msvc/areion_pq_arm64.asm`), and compiled object files (`.o`). Verifies:
- Zero-byte stack frames on SysV x86-64 and AAPCS64 ARM64 functions
- 100% epilogue vector (`xmm`/`ymm`/`zmm`/`v0..v31`) and working GPR zeroization before `ret`
- Windows x64 (`_WIN64`) non-volatile register (`XMM6..XMM15`, `RSI`, `RDI`) save/restore and stack-slot wiping
- `vzeroupper` placement immediately before `ret` in wide-vector (`YMM`/`ZMM`) functions
- ARM64 AAPCS64 (`v8..v15`, `x18..x30`) callee-saved register preservation and `bti c` / `endbr64` landing pads

```bash
python3 scripts/audit_asm_epilogues.py
```
