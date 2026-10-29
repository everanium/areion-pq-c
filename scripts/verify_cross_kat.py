#!/usr/bin/env python3
# Copyright (c) 2026 Andrey Kuvshinov
# Dual-licensed under Apache-2.0 OR MIT.
"""Cross-language tier-by-tier KAT parity harness comparing Go (areion-pq) and C (areion-pq-c)."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

C_REPO = Path(__file__).resolve().parent.parent


def _resolve_areion_c_repo() -> Path:
    env_dir = os.environ.get("AREION_C_DIR")
    if env_dir:
        return Path(env_dir).resolve()
    cand = (C_REPO / "../areion-c").resolve()
    return cand


def _resolve_go_repo() -> Path:
    env_dir = os.environ.get("AREION_PQ_GO_DIR")
    if env_dir:
        return Path(env_dir).resolve()
    for rel in (
        "../areion-pq", "../../areion-pq", "../../go/src/areion-pq", "../../../go/src/areion-pq",
    ):
        cand = (C_REPO / rel).resolve()
        if (cand / "go.mod").exists():
            return cand
    return Path("/home/andrew/go/src/areion-pq").resolve()


def _resolve_areion_go_repo() -> Path:
    env_dir = os.environ.get("AREION_GO_DIR")
    if env_dir:
        return Path(env_dir).resolve()
    for rel in (
        "../areion", "../../areion", "../../go/src/areion", "../../../go/src/areion",
    ):
        cand = (C_REPO / rel).resolve()
        if (cand / "go.mod").exists():
            return cand
    return Path("/home/andrew/go/src/areion").resolve()


AREION_C_REPO = _resolve_areion_c_repo()
GO_REPO = _resolve_go_repo()
AREION_GO_REPO = _resolve_areion_go_repo()

GO_DUMPER_SRC = r"""package main

import (
	"encoding/hex"
	"fmt"
	"os"

	areionpq "github.com/everanium/areion-pq"
)

func fillPattern(buf []byte, seed byte) {
	for i := range buf {
		buf[i] = byte((uint(i)*37 + uint(seed)*13 + 0x5a) & 0xFF)
	}
}

func printHex(label string, b []byte) {
	fmt.Printf("%s=%s\n", label, hex.EncodeToString(b))
}

func printBool(label string, ok bool) {
	if ok {
		fmt.Printf("%s=01\n", label)
	} else {
		fmt.Printf("%s=00\n", label)
	}
}

func main() {
	fullMode := false
	tier := ""
	for _, arg := range os.Args[1:] {
		if arg == "--full" {
			fullMode = true
		} else if tier == "" {
			tier = arg
		}
	}
	if tier != "" {
		if tier == "purec" {
			tier = "purego"
		}
		if err := areionpq.SetTier(tier); err != nil {
			fmt.Fprintf(os.Stderr, "Unsupported tier: %s (%v)\n", tier, err)
			os.Exit(2)
		}
	}

	// 1. Finite field & witness primitives
	var gf256Tbl [256 * 5]byte
	for i := 0; i < 256; i++ {
		a := byte(i)
		b := byte((i*17 + 3) & 0xFF)
		gf256Tbl[i*5+0] = areionpq.GF256Mul(a, b)
		gf256Tbl[i*5+1] = areionpq.GF256Sq(a)
		gf256Tbl[i*5+2] = areionpq.GF256Inv(a)
		gf256Tbl[i*5+3] = areionpq.GF256Affine(a)
		gf256Tbl[i*5+4] = areionpq.GF256AffineInv(a)
	}
	printHex("GF256Table", gf256Tbl[:])

	var a16, b16, chi16 [16]byte
	fillPattern(a16[:], 0x01)
	fillPattern(b16[:], 0x02)
	out16 := areionpq.GF128Mul(&a16, &b16)
	printHex("GF128Mul", out16[:])

	var polyA, polyB [4][16]byte
	for i := 0; i < 4; i++ {
		fillPattern(polyA[i][:], byte(0x03+i))
		fillPattern(polyB[i][:], byte(0x07+i))
	}
	fillPattern(chi16[:], 0x0B)
	mac16 := areionpq.GF128PolyMAC(polyA[:], polyB[:], &chi16)
	printHex("GF128PolyMAC", mac16[:])

	var a32, b32, k32 [32]byte
	fillPattern(a32[:], 0x0C)
	fillPattern(b32[:], 0x0D)
	out32 := areionpq.GF256FieldMul(&a32, &b32)
	printHex("GF256FieldMul", out32[:])

	fillPattern(a32[:], 0x0E)
	fillPattern(b32[:], 0x0F)
	out32 = areionpq.MulOrtho256(&a32, &b32)
	printHex("MulOrtho256", out32[:])

	fillPattern(k32[:], 0x10)
	out32 = areionpq.OrthoSigma256(&k32)
	printHex("OrthoSigma256", out32[:])

	var m32, k1_32, k2_32 [32]byte
	var c256, c256p2, cem2 [32]byte
	var w256, w256p2 [288]byte
	var wem2 [576]byte
	fillPattern(m32[:], 0x11)
	fillPattern(k1_32[:], 0x12)
	fillPattern(k2_32[:], 0x13)
	areionpq.ExtractWitness256(&c256, &w256, &m32, &k1_32, &k2_32)
	printHex("ExtractWitness256_C", c256[:])
	printHex("ExtractWitness256_W", w256[:])
	printBool("VerifyWitness256", areionpq.VerifyWitness256(&m32, &c256, &k1_32, &k2_32, &w256))

	fillPattern(m32[:], 0x14)
	fillPattern(k1_32[:], 0x15)
	fillPattern(k2_32[:], 0x16)
	areionpq.ExtractWitness256P2(&c256p2, &w256p2, &m32, &k1_32, &k2_32)
	printHex("ExtractWitness256P2_C", c256p2[:])
	printHex("ExtractWitness256P2_W", w256p2[:])
	printBool("VerifyWitness256P2", areionpq.VerifyWitness256P2(&m32, &c256p2, &k1_32, &k2_32, &w256p2))

	fillPattern(m32[:], 0x17)
	fillPattern(k1_32[:], 0x18)
	fillPattern(k2_32[:], 0x19)
	areionpq.ExtractWitnessEM2_256(&cem2, &wem2, &m32, &k1_32, &k2_32)
	printHex("ExtractWitnessEM2_256_C", cem2[:])
	printHex("ExtractWitnessEM2_256_W", wem2[:])
	printBool("VerifyWitnessEM2_256", areionpq.VerifyWitnessEM2_256(&m32, &cem2, &k1_32, &k2_32, &wem2))

	// 2. Track 1: FAEST-Areion
	var seed32, opt32 [32]byte
	var seed64 [64]byte
	var opt16 [16]byte
	var msg33 [33]byte

	fillPattern(seed32[:], 0x20)
	fillPattern(msg33[:], 0x21)
	fillPattern(opt16[:], 0x22)
	pk128s, sk128s := areionpq.FAESTKeygen128s(&seed32)
	sig128s := areionpq.FAESTSign128s(&sk128s, msg33[:], &opt16)
	printHex("FAEST128s_PK", pk128s[:])
	printHex("FAEST128s_SK", sk128s[:])
	printHex("FAEST128s_Sig", sig128s[:])
	printBool("FAEST128s_Verify", areionpq.FAESTVerify128s(&pk128s, msg33[:], &sig128s))

	fillPattern(seed32[:], 0x23)
	fillPattern(msg33[:], 0x24)
	fillPattern(opt16[:], 0x25)
	pk128f, sk128f := areionpq.FAESTKeygen128f(&seed32)
	sig128f := areionpq.FAESTSign128f(&sk128f, msg33[:], &opt16)
	printHex("FAEST128f_PK", pk128f[:])
	printHex("FAEST128f_SK", sk128f[:])
	printHex("FAEST128f_Sig", sig128f[:])
	printBool("FAEST128f_Verify", areionpq.FAESTVerify128f(&pk128f, msg33[:], &sig128f))

	fillPattern(seed64[:], 0x26)
	fillPattern(msg33[:], 0x27)
	fillPattern(opt32[:], 0x28)
	pk256s, sk256s := areionpq.FAESTKeygen256s(&seed64)
	sig256s := areionpq.FAESTSign256s(&sk256s, msg33[:], &opt32)
	printHex("FAEST256s_PK", pk256s[:])
	printHex("FAEST256s_SK", sk256s[:])
	printHex("FAEST256s_Sig", sig256s[:])
	printBool("FAEST256s_Verify", areionpq.FAESTVerify256s(&pk256s, msg33[:], &sig256s))

	fillPattern(seed64[:], 0x29)
	fillPattern(msg33[:], 0x2A)
	fillPattern(opt32[:], 0x2B)
	pk256f, sk256f := areionpq.FAESTKeygen256f(&seed64)
	sig256f := areionpq.FAESTSign256f(&sk256f, msg33[:], &opt32)
	printHex("FAEST256f_PK", pk256f[:])
	printHex("FAEST256f_SK", sk256f[:])
	printHex("FAEST256f_Sig", sig256f[:])
	printBool("FAEST256f_Verify", areionpq.FAESTVerify256f(&pk256f, msg33[:], &sig256f))

	fillPattern(seed64[:], 0x2C)
	fillPattern(msg33[:], 0x2D)
	fillPattern(opt32[:], 0x2E)
	pkem2s, skem2s := areionpq.FAESTEM2Keygen256s(&seed64)
	sigem2s := areionpq.FAESTEM2Sign256s(&skem2s, msg33[:], &opt32)
	printHex("FAESTEM2_256s_PK", pkem2s[:])
	printHex("FAESTEM2_256s_SK", skem2s[:])
	printHex("FAESTEM2_256s_Sig", sigem2s[:])
	printBool("FAESTEM2_256s_Verify", areionpq.FAESTEM2Verify256s(&pkem2s, msg33[:], &sigem2s))

	fillPattern(seed64[:], 0x2F)
	fillPattern(msg33[:], 0x30)
	fillPattern(opt32[:], 0x31)
	pkem2f, skem2f := areionpq.FAESTEM2Keygen256f(&seed64)
	sigem2f := areionpq.FAESTEM2Sign256f(&skem2f, msg33[:], &opt32)
	printHex("FAESTEM2_256f_PK", pkem2f[:])
	printHex("FAESTEM2_256f_SK", skem2f[:])
	printHex("FAESTEM2_256f_Sig", sigem2f[:])
	printBool("FAESTEM2_256f_Verify", areionpq.FAESTEM2Verify256f(&pkem2f, msg33[:], &sigem2f))

	// 3. Track 2: SLH-DSA-Areion
	var pkSeed16, skSeed16, m1_16, m2_16 [16]byte
	var pkSeed32, skSeed32, adrs32, m1_32, m2_32 [32]byte
	var adrs4 [4][32]byte
	fillPattern(pkSeed16[:], 0x40)
	fillPattern(skSeed16[:], 0x41)
	kPub128, kSK128 := areionpq.SLHExpandSeed128(&pkSeed16, &skSeed16)
	printHex("SLHExpandSeed128_KPub", kPub128[:])
	printHex("SLHExpandSeed128_KSK", kSK128[:])

	fillPattern(pkSeed32[:], 0x42)
	fillPattern(skSeed32[:], 0x43)
	kPub256, kSK256 := areionpq.SLHExpandSeed256(&pkSeed32, &skSeed32)
	printHex("SLHExpandSeed256_KPub", kPub256[:])
	printHex("SLHExpandSeed256_KSK", kSK256[:])

	fillPattern(adrs32[:], 0x44)
	cadrs := areionpq.SLHCompactADRS(&adrs32)
	printHex("SLHCompactADRS", cadrs[:])

	prf128 := areionpq.SLHPRF128(&kSK128, &adrs32)
	printHex("SLHPRF128", prf128[:])
	prf256 := areionpq.SLHPRF256(&kSK256, &adrs32)
	printHex("SLHPRF256", prf256[:])

	for m := 0; m < 4; m++ {
		fillPattern(adrs4[m][:], byte(0x45+m))
	}
	prf256x4 := areionpq.SLHPRF256x4(&kSK256, &adrs4)
	var flat128 [128]byte
	for m := 0; m < 4; m++ {
		copy(flat128[m*32:(m+1)*32], prf256x4[m][:])
	}
	printHex("SLHPRF256x4", flat128[:])

	fillPattern(m1_16[:], 0x49)
	fillPattern(m1_32[:], 0x4A)
	fillPattern(m2_16[:], 0x4B)
	fillPattern(m2_32[:], 0x4C)
	f128 := areionpq.SLHF128(&pkSeed16, &kPub128, &adrs32, &m1_16)
	printHex("SLHF128", f128[:])
	f256 := areionpq.SLHF256(&kPub256, &adrs32, &m1_32)
	printHex("SLHF256", f256[:])
	ftem256 := areionpq.SLHFTEM256(&kPub256, &adrs32, &m1_32)
	printHex("SLHFTEM256", ftem256[:])
	h128 := areionpq.SLHH128(&pkSeed16, &kPub128, &adrs32, &m1_16, &m2_16)
	printHex("SLHH128", h128[:])
	h256 := areionpq.SLHH256(&kPub256, &adrs32, &m1_32, &m2_32)
	printHex("SLHH256", h256[:])

	var blks16 [5][16]byte
	var blks32 [5][32]byte
	for i := 0; i < 5; i++ {
		fillPattern(blks16[i][:], byte(0x50+i))
		fillPattern(blks32[i][:], byte(0x55+i))
	}
	tl128 := areionpq.SLHTl128(&kPub128, &adrs32, blks16[:])
	printHex("SLHTl128", tl128[:])
	tl256 := areionpq.SLHTl256(&kPub256, &adrs32, blks32[:])
	printHex("SLHTl256", tl256[:])

	var slhSeed48 [48]byte
	var slhSeed96 [96]byte
	fillPattern(slhSeed48[:], 0x60)
	fillPattern(msg33[:], 0x61)
	fillPattern(opt16[:], 0x62)
	slhPK128f, slhSK128f := areionpq.SLHDSAKeygen128f(&slhSeed48)
	slhSig128f := areionpq.SLHDSASign128f(&slhSK128f, msg33[:], &opt16)
	printHex("SLHDSA128f_PK", slhPK128f[:])
	printHex("SLHDSA128f_SK", slhSK128f[:])
	printHex("SLHDSA128f_Sig", slhSig128f[:])
	printBool("SLHDSA128f_Verify", areionpq.SLHDSAVerify128f(&slhPK128f, msg33[:], &slhSig128f))

	fillPattern(slhSeed96[:], 0x63)
	fillPattern(msg33[:], 0x64)
	fillPattern(opt32[:], 0x65)
	slhPK256f, slhSK256f := areionpq.SLHDSAKeygen256f(&slhSeed96)
	slhSig256f := areionpq.SLHDSASign256f(&slhSK256f, msg33[:], &opt32)
	printHex("SLHDSA256f_PK", slhPK256f[:])
	printHex("SLHDSA256f_SK", slhSK256f[:])
	printHex("SLHDSA256f_Sig", slhSig256f[:])
	printBool("SLHDSA256f_Verify", areionpq.SLHDSAVerify256f(&slhPK256f, msg33[:], &slhSig256f))

	fillPattern(slhSeed96[:], 0x66)
	fillPattern(msg33[:], 0x67)
	fillPattern(opt32[:], 0x68)
	slhPKTEM256f, slhSKTEM256f := areionpq.SLHDSATEMKeygen256f(&slhSeed96)
	slhSigTEM256f := areionpq.SLHDSATEMSign256f(&slhSKTEM256f, msg33[:], &opt32)
	printHex("SLHDSATEM256f_PK", slhPKTEM256f[:])
	printHex("SLHDSATEM256f_SK", slhSKTEM256f[:])
	printHex("SLHDSATEM256f_Sig", slhSigTEM256f[:])
	printBool("SLHDSATEM256f_Verify", areionpq.SLHDSATEMVerify256f(&slhPKTEM256f, msg33[:], &slhSigTEM256f))

	if fullMode {
		fillPattern(slhSeed48[:], 0x69)
		fillPattern(msg33[:], 0x6A)
		fillPattern(opt16[:], 0x6B)
		slhPK128s, slhSK128s := areionpq.SLHDSAKeygen128s(&slhSeed48)
		slhSig128s := areionpq.SLHDSASign128s(&slhSK128s, msg33[:], &opt16)
		printHex("SLHDSA128s_PK", slhPK128s[:])
		printHex("SLHDSA128s_SK", slhSK128s[:])
		printHex("SLHDSA128s_Sig", slhSig128s[:])
		printBool("SLHDSA128s_Verify", areionpq.SLHDSAVerify128s(&slhPK128s, msg33[:], &slhSig128s))

		fillPattern(slhSeed96[:], 0x6C)
		fillPattern(msg33[:], 0x6D)
		fillPattern(opt32[:], 0x6E)
		slhPK256s, slhSK256s := areionpq.SLHDSAKeygen256s(&slhSeed96)
		slhSig256s := areionpq.SLHDSASign256s(&slhSK256s, msg33[:], &opt32)
		printHex("SLHDSA256s_PK", slhPK256s[:])
		printHex("SLHDSA256s_SK", slhSK256s[:])
		printHex("SLHDSA256s_Sig", slhSig256s[:])
		printBool("SLHDSA256s_Verify", areionpq.SLHDSAVerify256s(&slhPK256s, msg33[:], &slhSig256s))
	}

	// 4. Track 3: Areion-HPKE, KDF & TEM2-SIV
	var kdfSec [48]byte
	var kdfCtx [29]byte
	var kdfOut [300]byte
	fillPattern(kdfSec[:], 0x70)
	fillPattern(kdfCtx[:], 0x71)
	areionpq.KDFExpand(kdfSec[:], kdfCtx[:], kdfOut[:])
	printHex("KDFExpand", kdfOut[:])

	var sivKey [128]byte
	var sivNonce [32]byte
	var sivAD [300]byte
	var sivPT [333]byte
	fillPattern(sivKey[:], 0x72)
	fillPattern(sivNonce[:], 0x73)
	fillPattern(sivAD[:], 0x74)
	fillPattern(sivPT[:], 0x75)
	_, emptyTag := areionpq.TEM2SIVEncrypt(&sivKey, &sivNonce, nil, nil)
	printHex("TEM2SIV_Empty_Tag", emptyTag[:])
	sivCT, sivTag := areionpq.TEM2SIVEncrypt(&sivKey, &sivNonce, sivAD[:], sivPT[:])
	printHex("TEM2SIV_Full_CT", sivCT)
	printHex("TEM2SIV_Full_Tag", sivTag[:])
	_, sivOK := areionpq.TEM2SIVDecrypt(&sivKey, &sivNonce, sivAD[:], sivCT, &sivTag)
	printBool("TEM2SIV_Full_OK", sivOK)

	var hpkeShared [32]byte
	var hpkeInfo [25]byte
	var hpkeAD [37]byte
	var hpkePT [145]byte
	fillPattern(hpkeShared[:], 0x76)
	fillPattern(hpkeInfo[:], 0x77)
	fillPattern(hpkeAD[:], 0x78)
	fillPattern(hpkePT[:], 0x79)
	demKey, baseNonce := areionpq.HPKEDeriveKeys(&hpkeShared, hpkeInfo[:])
	printHex("HPKEDeriveKeys_Key", demKey[:])
	printHex("HPKEDeriveKeys_Nonce", baseNonce[:])
	hpkeCT, hpkeTag := areionpq.HPKESealDet(&hpkeShared, hpkeInfo[:], 0x0102030405060708, hpkeAD[:], hpkePT[:])
	printHex("HPKESealDet_CT", hpkeCT)
	printHex("HPKESealDet_Tag", hpkeTag[:])
	_, hpkeOK := areionpq.HPKEOpenDet(&hpkeShared, hpkeInfo[:], 0x0102030405060708, hpkeAD[:], hpkeCT, &hpkeTag)
	printBool("HPKEOpenDet_OK", hpkeOK)

	fmt.Printf("_meta_tier=%s\n", areionpq.Tier())
	fmt.Printf("_meta_tier_code=%d\n", areionpq.TierCode())
}
"""


def parse_kv(output: str) -> dict[str, str]:
    res = {}
    for line in output.splitlines():
        line = line.strip()
        if "=" in line:
            k, v = line.split("=", 1)
            res[k] = v
    return res


def check_introspection(label: str, tier: str, go_map: dict[str, str], c_map: dict[str, str]) -> bool:
    exp_go_tier = "purego" if tier == "purec" else tier
    exp_c_tier = tier
    if go_map.get("_meta_tier") != exp_go_tier or c_map.get("_meta_tier") != exp_c_tier:
        print(f"FAIL [{label}] Tier introspection mismatch: Go={go_map.get('_meta_tier')} C={c_map.get('_meta_tier')}", file=sys.stderr)
        return False
    if "_meta_tier_code" not in go_map or "_meta_tier_code" not in c_map:
        print(f"FAIL [{label}] TierCode missing", file=sys.stderr)
        return False
    return True


def strip_meta(kv: dict[str, str]) -> dict[str, str]:
    return {k: v for k, v in kv.items() if not k.startswith("_meta_")}


def main() -> int:
    if not GO_REPO.exists():
        print(f"SKIP: Go reference repo {GO_REPO} not found.")
        return 0

    full_mode = "--full" in sys.argv[1:]
    full_args = ["--full"] if full_mode else []

    go_runs: dict[str, dict[str, str]] = {}
    c_runs: dict[str, dict[str, str]] = {}

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        subprocess.run(["make", "-C", str(C_REPO), "areion_pq_test"], check=True)
        c_bin_x86 = C_REPO / "areion_pq_test"

        go_mod_dir = tmp / "godump"
        go_mod_dir.mkdir()
        (go_mod_dir / "go.mod").write_text(
            f"module godump\n\ngo 1.24\n\n"
            f"require (\n"
            f"\tgithub.com/everanium/areion v0.1.6\n"
            f"\tgithub.com/everanium/areion-pq v0.2.0\n"
            f")\n\n"
            f"replace github.com/everanium/areion => {AREION_GO_REPO}\n"
            f"replace github.com/everanium/areion-pq => {GO_REPO}\n",
            encoding="utf-8",
        )
        if (GO_REPO / "go.sum").exists():
            shutil.copy(GO_REPO / "go.sum", go_mod_dir / "go.sum")
        (go_mod_dir / "main.go").write_text(GO_DUMPER_SRC, encoding="utf-8")

        subprocess.run(["go", "mod", "tidy"], cwd=go_mod_dir, check=True)
        go_bin_x86 = tmp / "godump_x86"
        subprocess.run(["go", "build", "-o", str(go_bin_x86), "."], cwd=go_mod_dir, check=True)

        x86_tiers = ["purec", "aesni", "vex", "vaesavx2", "avx512"]
        for tier in x86_tiers:
            c_proc = subprocess.run([str(c_bin_x86), "--dump-kat", tier, *full_args], capture_output=True, text=True)
            if c_proc.returncode == 2:
                print(f"SKIP tier {tier} (not supported on current CPU)")
                continue
            assert c_proc.returncode == 0, c_proc.stderr
            go_proc = subprocess.run([str(go_bin_x86), tier, *full_args], capture_output=True, text=True, check=True)

            c_raw = parse_kv(c_proc.stdout)
            go_raw = parse_kv(go_proc.stdout)
            if not check_introspection(f"x86_64/{tier}", tier, go_raw, c_raw):
                return 1
            c_map = strip_meta(c_raw)
            go_map = strip_meta(go_raw)
            for k, go_val in go_map.items():
                c_val = c_map.get(k)
                if c_val != go_val:
                    print(f"FAIL [{tier}] {k}:\n  Go = {go_val[:128]}\n  C  = {(c_val or '')[:128]}", file=sys.stderr)
                    return 1
            go_label = f"x86_64/{'purego' if tier == 'purec' else tier}"
            c_label = f"x86_64/{tier}"
            go_runs[go_label] = go_map
            c_runs[c_label] = c_map
            print(f"PASS [x86_64 tier={tier:8s}]: {len(go_map)} KAT vectors + introspection checks 100% identical")

        areion_c_srcs = [
            "constants.c", "cpu.c", "cpu_amd64.c", "cpu_arm64.c", "cpu_other.c",
            "areion_purec.c", "areion_amd64.c", "areion_arm64.c", "areion_other.c",
        ]
        pq_c_srcs = [
            "constants.c", "cpu.c", "cpu_amd64.c", "cpu_arm64.c", "cpu_other.c",
            "areion_pq_purec.c", "areion_pq_amd64.c", "areion_pq_arm64.c", "areion_pq_other.c",
            "areion_pq_test.c",
        ]

        if shutil.which("aarch64-linux-gnu-gcc") and shutil.which("qemu-aarch64-static") and AREION_C_REPO.exists():
            c_bin_arm64 = tmp / "areion_pq_test_arm64"
            subprocess.run(
                [
                    "aarch64-linux-gnu-gcc", "-std=c99", "-O3", "-march=armv8-a+crypto", "-static",
                    "-I", str(C_REPO), "-I", str(AREION_C_REPO),
                    *[str(AREION_C_REPO / s) for s in areion_c_srcs],
                    str(AREION_C_REPO / "areion_arm64.S"),
                    *[str(C_REPO / s) for s in pq_c_srcs],
                    str(C_REPO / "areion_pq_arm64.S"),
                    "-o", str(c_bin_arm64),
                ],
                check=True,
            )
            go_bin_arm64 = tmp / "godump_arm64"
            env = dict(**subprocess.os.environ, GOOS="linux", GOARCH="arm64", CGO_ENABLED="0")
            subprocess.run(["go", "build", "-o", str(go_bin_arm64), "."], cwd=go_mod_dir, env=env, check=True)

            for tier in ["purec", "arm64"]:
                c_proc = subprocess.run(
                    ["qemu-aarch64-static", "-cpu", "max", str(c_bin_arm64), "--dump-kat", tier],
                    capture_output=True, text=True, check=True,
                )
                go_proc = subprocess.run(
                    ["qemu-aarch64-static", "-cpu", "max", str(go_bin_arm64), tier],
                    capture_output=True, text=True, check=True,
                )
                c_raw = parse_kv(c_proc.stdout)
                go_raw = parse_kv(go_proc.stdout)
                if not check_introspection(f"aarch64/{tier}", tier, go_raw, c_raw):
                    return 1
                c_map = strip_meta(c_raw)
                go_map = strip_meta(go_raw)
                for k, go_val in go_map.items():
                    c_val = c_map.get(k)
                    if c_val != go_val:
                        print(f"FAIL [arm64/{tier}] {k}:\n  Go = {go_val[:128]}\n  C  = {(c_val or '')[:128]}", file=sys.stderr)
                        return 1
                go_label = f"aarch64/{'purego' if tier == 'purec' else tier}"
                c_label = f"aarch64/{tier}"
                go_runs[go_label] = go_map
                c_runs[c_label] = c_map
                print(f"PASS [aarch64 tier={tier:8s}]: {len(go_map)} KAT vectors + introspection checks 100% identical")

        s390x_cc = None
        if shutil.which("s390x-linux-gnu-gcc"):
            s390x_cc = ["s390x-linux-gnu-gcc", "-std=c99", "-O2", "-static"]
        elif shutil.which("zig"):
            s390x_cc = ["zig", "cc", "-target", "s390x-linux-musl", "-std=c99", "-O2", "-static"]

        if s390x_cc is not None and shutil.which("qemu-s390x-static") and AREION_C_REPO.exists():
            c_bin_s390x = tmp / "areion_pq_test_s390x"
            subprocess.run(
                [
                    *s390x_cc, "-I", str(C_REPO), "-I", str(AREION_C_REPO),
                    *[str(AREION_C_REPO / s) for s in areion_c_srcs],
                    *[str(C_REPO / s) for s in pq_c_srcs],
                    "-o", str(c_bin_s390x),
                ],
                check=True,
            )
            go_bin_s390x = tmp / "godump_s390x"
            env = dict(**subprocess.os.environ, GOOS="linux", GOARCH="s390x", CGO_ENABLED="0")
            subprocess.run(["go", "build", "-o", str(go_bin_s390x), "."], cwd=go_mod_dir, env=env, check=True)

            c_proc = subprocess.run(
                ["qemu-s390x-static", str(c_bin_s390x), "--dump-kat", "purec"],
                capture_output=True, text=True, check=True,
            )
            go_proc = subprocess.run(
                ["qemu-s390x-static", str(go_bin_s390x), "purec"],
                capture_output=True, text=True, check=True,
            )
            c_raw = parse_kv(c_proc.stdout)
            go_raw = parse_kv(go_proc.stdout)
            if not check_introspection("s390x/purec", "purec", go_raw, c_raw):
                return 1
            c_map = strip_meta(c_raw)
            go_map = strip_meta(go_raw)
            for k, go_val in go_map.items():
                c_val = c_map.get(k)
                if c_val != go_val:
                    print(f"FAIL [s390x/purec] {k}:\n  Go = {go_val[:128]}\n  C  = {(c_val or '')[:128]}", file=sys.stderr)
                    return 1
            go_runs["s390x/purego"] = go_map
            c_runs["s390x/purec"] = c_map
            print(f"PASS [s390x   tier=purec   ]: {len(go_map)} KAT vectors + introspection checks 100% identical (Big-Endian)")

    print("\n--- Cross-Language Cartesian Product Matrix Check: Go[tier_A] x C[tier_B] ---")
    pairs_checked = 0
    for go_label, go_map in go_runs.items():
        for c_label, c_map in c_runs.items():
            common_keys = [k for k in go_map if k in c_map]
            for k in common_keys:
                go_val = go_map[k]
                c_val = c_map.get(k)
                if c_val != go_val:
                    print(f"FAIL Matrix [Go[{go_label}] <-> C[{c_label}]] on {k}:\n  Go = {go_val[:128]}\n  C  = {(c_val or '')[:128]}", file=sys.stderr)
                    return 1
            pairs_checked += 1
            print(f"PASS Matrix Pair [{pairs_checked:2d}]: Go[{go_label:16s}] <-> C[{c_label:16s}] ({len(common_keys)} KAT vectors)")

    print(
        f"\nALL CROSS-LANGUAGE GO <-> C KAT CHECKS PASSED "
        f"({len(go_runs)} Go tiers x {len(c_runs)} C tiers = {pairs_checked} matrix pairs)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
