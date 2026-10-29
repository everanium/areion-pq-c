## Areion-PQ: Post-Quantum Signatures (`FAEST-Areion`, `SLH-DSA-Areion`) & Wide-Block Hybrid Encryption (`Areion-HPKE`, `Areion-TEM2-SIV`) C + Assembly Reference Library

C99 + Assembly reference implementation of three post-quantum and beyond-birthday-bound cryptographic tracks built on the **Areion-256** and **Areion-512** permutations:
1. **`FAEST-Areion`**: `VOLE-in-the-Head` (`VOLEitH`) and `QuickSilver` degree-2 polynomial zero-knowledge signatures with the **288-S-box Round-9 Free-Witness Theorem** (`FAEST-Areion-128{s,f}`, `FAEST-Areion-256{s,f}`, `FAEST-Areion-EM2-256{s,f}`).
2. **`SLH-DSA-Areion`**: `NIST FIPS 205` stateless hash-based signatures instantiated with clamped-capacity `DM512`, middle-tweak `TEM`, and `SoEM256` PRFs (`SLH-DSA-Areion-128{f,s}`, `SLH-DSA-Areion-256{f,s}`, `SLH-DSA-Areion-TEM-256f`).
3. **`Areion-HPKE` & `Areion-TEM2-SIV`**: Post-quantum Hybrid Public-Key Encryption DEM (`AreionKDF` + deterministic HPKE sealing) and 512-bit wide-block misuse-resistant authenticated encryption (`TEM2-SIV`) with `2^341.3` classical / `2^170.7` quantum Beyond-Birthday-Bound (BBB) security.

Built on **[`everanium/areion-c`](https://github.com/everanium/areion-c)**. Companion Go + Assembly reference library: **[`everanium/areion-pq`](https://github.com/everanium/areion-pq)**.

[![C Standard: C99 / C11](https://img.shields.io/badge/C-C99_%2F_C11-blue.svg)](areion_pq.h)
[![static-analysis: passing](https://img.shields.io/badge/static--analysis-passing-green)](Makefile)
[![Coverage](https://img.shields.io/badge/coverage-99%25-brightgreen)](https://github.com/everanium/areion-pq-c)
[![License: Apache-2.0 / MIT](https://img.shields.io/badge/License-Apache_2.0_OR_MIT-blue.svg)](#license)

---

## Overview

`libareion_pq` constructs post-quantum signatures, key derivation, and wide-block authenticated encryption directly over hardware-accelerated `Areion-256` (10-round) and `Areion-512` (15-round) permutations ([Isobe et al., TCHES 2023](https://doi.org/10.46586/tches.v2023.i2.115-154); [ePrint 2023/794](https://eprint.iacr.org/2023/794)):

- **Track 1 — `FAEST-Areion` (`VOLE-in-the-Head` Zero-Knowledge Signatures)**: Exploits the 2-branch Feistel structure of 10-round `Areion-256` so that Round 9 requires **zero committed witness bytes** (`32` free S-boxes out of `320` total S-boxes; `288` witness bytes = `2,304` bits for `Areion-256`, and `576` witness bytes = `4,608` bits for 20-round `Areion-EM2-256`). Every S-box transition `(X, S)` is verified over `GF(2^8)` via the coupled degree-2 bilinear equations `Sq(X) * Y ⊕ X = 0` and `Sq(Y) * X ⊕ Y = 0` (`Y = AffineInv(S)`), which achieve `100%` completeness (`256 / 256` valid pairs, including `(0x00, 0x63)`) and `100%` soundness (`65,280 / 65,280` invalid pairs rejected) under `QuickSilver` `GF(2^128)` polynomial authentication.
- **Track 2 — `SLH-DSA-Areion` (`NIST FIPS 205` Stateless Hash-Based Signatures)**: Replaces sequential 64/80-round `SHA-2` and `SHAKE256` compression in `NIST FIPS 205` with single-call `areion_dm512` (`60` hardware AES instructions per 64-byte compression), 4-way batched `areion_soem256x4` address PRFs, and middle-tweak `areion_tem_encrypt256`, after a one-time seed expansion (`areion_pq_slh_expand_seed128/256`). Clamped-capacity `DM512` (`areion_pq_slh_f256`, `areion_pq_slh_f128`, `areion_pq_slh_h128`) and middle-tweak `TEM` (`areion_pq_slh_f_tem256`) preserve full `256 / 256` tweak capacity rank and eliminate feed-forward tweak cancellation.
- **Track 3 — `Areion-HPKE` & `Areion-TEM2-SIV` Wide-Block AEAD**: Combines a domain-separated `areion_dm512` + `areion_soem512x4` sponge key derivation function (`areion_pq_kdf_expand`), deterministic HPKE key schedule and sequence-numbered sealing (`areion_pq_hpke_derive_keys`, `areion_pq_hpke_seal_det`, `areion_pq_hpke_open_det`), and 512-bit wide-block Synthetic IV authenticated encryption (`areion_pq_tem2_siv_encrypt` / `areion_pq_tem2_siv_decrypt`) built from `areion_soem512x4` tag authentication and 4-way `areion_tem2_encrypt512x4` / `areion_tem2_decrypt512x4` wide-block tweakable encryption (`2^341.3` classical / `2^170.7` quantum BBB security).
- **Multi-Tier Hardware Dispatch & Portable Fallback**: Automatic runtime selection across `AVX-512 VAES + VPCLMULQDQ`, `AVX2 + VAES + VPCLMULQDQ`, `AVX + AES-NI + PCLMULQDQ (VEX)`, legacy `AES-NI + PCLMULQDQ`, `ARMv8 Crypto (AESE/AESMC + PMULL/PMULL2)`, and a constant-time 64-bit bitsliced software fallback (`purec`), verified at startup by a FIPS 140-3 Known-Answer Self-Test (`areion_pq_selftest`).
- **Constant-Time & Zeroization Hardening**: Zero external dependencies, strict ISO C99 / C11 / C++ (`extern "C"`), zero secret-dependent branches or table lookups, zero heap allocations (`malloc`/`free` never invoked), Intel CET `endbr64` + ARM64 `bti c` landing pads, automatic zeroization of unauthenticated `TEM2-SIV` / `HPKE` plaintext buffers, and epilogue scrubbing of temporary stack frames, SIMD vector registers (`XMM`/`YMM`/`ZMM`/`v0–v31`), and scratch GPRs before every return.

---

## Public API (`areion_pq.h`)

**See [`API.md`](API.md) for the complete function-by-function specification, C prototypes, macro definitions, and SUPERCOP / PQClean wrapper interfaces.**

| Category | Exported Symbols (`areion_pq.h`) | Key / Seed | State / Witness / Sig | Summary |
| :--- | :--- | :---: | :---: | :--- |
| **[Constants & Sizes](API.md#1-types-and-constants)** | `AREION_PQ_VERSION*`, `AREION_PQ_API`, `AREION_PQ_BLOCK_SIZE`, `AREION_PQ_STATE{256,512}_SIZE`, `AREION_PQ_WITNESS{256,_EM2_256}_SIZE`, `AREION_PQ_FAEST*`, `AREION_PQ_SLHDSA*`, `AREION_PQ_TEM2_SIV_*`, `AREION_PQ_HPKE_*` | 32–128 B | 16–49,856 B | Semantic version macros, visibility macros, and byte-length constants across all three tracks |
| **[Tier Types & Dispatch](API.md#2-runtime-dispatch-self-test-and-memory-zeroization)** | `areion_pq_tier_t` (`AREION_PQ_TIER_AUTO`..`AREION_PQ_TIER_ARM64`), `areion_pq_tier{,_code,_supported}`, `areion_pq_available_tiers`, `areion_pq_set_tier{,_code}`, `areion_pq_use_hardware_acceleration`, `areion_pq_selftest`, `areion_pq_zeroize` | — | — | Runtime ISA tier introspection/override (synchronized with `areion-c`), FIPS 140-3 CAST `areion_pq_selftest`, and DSE-safe `areion_pq_zeroize` |
| **[Finite Fields & Orthomorphisms](API.md#31-gf28-gf2128-gf2256-and-key-orthomorphisms)** | `areion_pq_gf256_{mul,sq,inv,affine,affine_inv}`, `areion_pq_gf128_{mul,polymac}`, `areion_pq_gf256_field_mul`, `areion_pq_mul_ortho256`, `areion_pq_ortho_sigma256` | 1–32 B | 1–32 B | Constant-time `GF(2^8)`, `GF(2^128)`, and `GF(2^256)` arithmetic, Horner `PolyMAC`, and `GF(2)`-linear key orthomorphisms |
| **[288-S-Box Witness Primitives](API.md#32-288-s-box-and-576-s-box-witness-extraction-and-algebraic-verification)** | `areion_pq_extract_witness256{,_p2}`, `areion_pq_verify_witness256{,_p2}`, `areion_pq_extract_witness_em2_256`, `areion_pq_verify_witness_em2_256` | 2 × 32 B | 288 / 576 B | Hardware-accelerated 288-byte (`P1`, `P2`) and 576-byte (`2-EM`) witness extraction and constant-time degree-2 `GF(2^8)` verification |
| **[Track 1: `FAEST-Areion`](API.md#4-track-1-faest-areion-vole-in-the-head-zero-knowledge-signatures)** | `areion_pq_faest_{keygen,sign,verify}{128s,128f,256s,256f}`, `areion_pq_faest_em2_{keygen,sign,verify}{256s,256f}` (`areion_pq_faest_{keygen,sign,verify}_em2_{256s,256f}`) | 32–96 B | 6,448–30,368 B | `VOLE-in-the-Head` + `QuickSilver` zero-knowledge signatures over `Areion-256` (`128s/f`, `256s/f`) and 20-round `Areion-EM2-256` (`EM2-256s/f`) |
| **[Track 2: `SLH-DSA-Areion` Hashes](API.md#51-seed-expansion-address-compression-and-tweakable-hash-primitives)** | `areion_pq_slh_expand_seed{128,256}`, `areion_pq_slh_compact_adrs`, `areion_pq_slh_prf{128,256,256x4}`, `areion_pq_slh_f{128,256,_tem256}`, `areion_pq_slh_h{128,256}`, `areion_pq_slh_tl{128,256}` | 16–64 B | 16 / 32 B | `FIPS 205` seed expansion, 128-bit injective `ADRS` compression, `SoEM256` PRFs, and clamped-capacity `DM512` / middle-tweak `TEM` hashes |
| **[Track 2: `SLH-DSA-Areion` Signatures](API.md#52-key-generation-signing-and-verification-entry-points)** | `areion_pq_slhdsa_{keygen,sign,verify}{128f,128s,256f,256s}`, `areion_pq_slhdsa_tem_{keygen,sign,verify}256f` | 32–128 B | 7,856–49,856 B | Stateless hash-based keygen, signing, and verification for `128f`, `128s`, `256f`, `256s` (`DM512-Clamped`), and `TEM-256f` (`TEM-MiddleTweak`) |
| **[Track 3: `Areion-HPKE` & `TEM2-SIV`](API.md#6-track-3-areion-hpke-key-derivation-deterministic-hpke-and-areion-tem2-siv-wide-block-aead)** | `areion_pq_kdf_expand`, `areion_pq_tem2_siv_{encrypt,decrypt}`, `areion_pq_hpke_derive_keys`, `areion_pq_hpke_{seal,open}_det` | 32–128 B | 32 B tag | `DM512` + `SoEM512x4` KDF, 512-bit wide-block `TEM2-SIV` MRAE (`2^341.3` BBB), and deterministic HPKE DEM sealing |
| **[SUPERCOP & PQClean Wrappers](API.md#8-supercop-ebacs-and-pqclean-c99-wrappers-supercop-pqclean)** | `supercop/crypto_sign/*` (10), `supercop/crypto_aead/areion_tem2_siv512`, `pqclean/crypto_sign/*` (4) | 32–128 B | 32–49,856 B | 11 standard `SUPERCOP` (`eBACS`) `ref` directories and 4 standalone `PQClean` `clean` packages |

---

## Cryptographic Constructions & Security

### 1. Track 1: `FAEST-Areion` (`VOLE-in-the-Head` Zero-Knowledge Signatures)

`FAEST-Areion` adapts the `FAEST` ([Baum et al., CRYPTO 2023](https://eprint.iacr.org/2023/996)) `VOLE-in-the-Head` (`VOLEitH`) and `QuickSilver` ([Yang et al., CCS 2021](https://eprint.iacr.org/2021/076)) paradigm to the 10-round `Areion-256` permutation.

#### Key Orthomorphisms (`areion_pq_mul_ortho256` and `areion_pq_ortho_sigma256`)
An unconstrained Even-Mansour relation `C = P1(M ⊕ K1) ⊕ K2` with independent `(K1, K2)` has `2^256` valid key pairs per `(M, C)` and admits a trivial 1-query forgery (`K2 = P1(M ⊕ K1) ⊕ C` for arbitrary `K1`). Setting `K2 = K1` eliminates extra key degrees of freedom in 1-round `EM`, but in 2-round `EM2` (`C = P2(P1(M ⊕ K1) ⊕ K2) ⊕ K1 ⊕ K2`) causes the outer whitening mask `K1 ⊕ K2` to vanish. `FAEST-Areion` derives `K2 = L(K1)` via a `GF(2)`-linear orthomorphism `L` on `{0,1}^256` (`rank(L) = 256 / 256` and `rank(I ⊕ L) = 256 / 256`):

- **Public-Tweak Orthomorphism (`areion_pq_mul_ortho256`, used in `FAEST-Areion-128{s,f}` and `FAEST-Areion-256{s,f}`)**:
  ```text
  K2 = (GF128Mul(T[0:16], K1[0:16]), GF128Mul(T[16:32], K1[16:32]))
  C  = P1_256(M ⊕ K1) ⊕ K2
  ```
  where `(T, M)` are expanded from `PK.seed` via `areion_soem512` and clamped so `T[0] |= 0x02`, `T[16] |= 0x02` (`T_0, T_1` not in `{0, 1}`), guaranteeing that both `K1 -> K2` and `K1 -> K1 ⊕ K2` are bijections over `GF(2)^256` while remaining strictly linear in the secret witness wires `K1`.
- **Fixed-Key Feistel Orthomorphism (`areion_pq_ortho_sigma256`, used in `FAEST-Areion-EM2-256{s,f}`)**:
  ```text
  K2 = sigma(K1_L || K1_R) = K1_R || (K1_L ⊕ K1_R)
  C  = P2_256(P1_256(M ⊕ K1) ⊕ K2) ⊕ K1 ⊕ K2
  ```
  Since `sigma^2 ⊕ sigma ⊕ id = 0`, all three whitening masks `(K1, K2, K1 ⊕ K2)` have full `GF(2)` rank `256 / 256` with zero multiplication gates.

#### The 288-S-Box Round-9 Free-Witness Theorem
Each round `r` (`0 <= r < 10`) of `Areion-256` updates the 16-byte active branch `A_r` and passive branch `B_r` via two 16-byte S-box layers (`32` S-boxes/round, `320` S-boxes total):
```text
A_next_r = ShiftRows(SubBytes(A_r))
U_r      = MixColumns(A_next_r) ⊕ RC[r]
B_next_r = B_r ⊕ MixColumns(ShiftRows(SubBytes(U_r)))
```
Because `ShiftRows` and `MixColumns` are invertible `GF(2)`-linear maps, recording the 32-byte post-round state `(A_next_r, B_next_r)` for rounds `r = 0..8` (`9 × 32 = 288` bytes = `2,304` bits) fixes both the input `(x0^(9), x1^(9)) = (A_next_8, B_next_8)` to Round 9 and, via the public boundary equation `(x0^(10), x1^(10)) = C ⊕ K2`, the output `(A_next_9, B_next_9)` of Round 9 with **zero committed witness bits in Round 9 (`32` free S-boxes = `256` bits saved)**:
```text
S^(r,1) = InvShiftRows(A_next_r)
X^(r,2) = MixColumns(A_next_r) ⊕ RC[r]
S^(r,2) = InvShiftRows(InvMixColumns(B_r ⊕ B_next_r))
```
In 20-round `FAEST-Areion-EM2-256`, committing `576` witness bytes (`288 B` for `P1` + `288 B` for `P2`) similarly determines all `640` S-boxes (`64` free S-boxes = `512` bits saved).

#### Coupled Degree-2 `QuickSilver` S-Box Equations over `GF(2^8)`
For every S-box input byte `X` and output byte `S = Affine(X^254)`, let `Y = areion_pq_gf256_affine_inv(S) = X^254` in `GF(2^8) = GF(2)[z] / (z^8 + z^4 + z^3 + z + 1)` (`0x11B`). The naive relation `X * Y ⊕ 1 = 0` fails when `X = 0x00` (`S = 0x63`, `Y = 0x00`), whereas a single degree-2 relation `Sq(X) * Y ⊕ X = 0` admits `255` spurious solutions `(X = 0x00, S != 0x63)`. `libareion_pq` enforces the coupled bilinear pair:
```text
C1(X, S) = GF256Mul(GF256Sq(X), Y) ⊕ X = 0
C2(X, S) = GF256Mul(GF256Sq(Y), X) ⊕ Y = 0
```
Since `GF256Sq` and `GF256AffineInv` are `GF(2)`-linear on bit wires, `C1` and `C2` are quadratic (`degree 2`) in the committed VOLE bit tags and achieve `100%` completeness (`256 / 256` valid pairs) and `100%` soundness (`0 / 65,280` invalid pairs accepted; see [`everanium/areion-pq/analysis/README.md` (Section B)](https://github.com/everanium/areion-pq/blob/main/analysis/README.md#b-quicksilver-gf28-degree-2-s-box-completeness-and-soundness)).

#### Parameter Sets & Comparison with `FAEST-256` and `FAEST-EM-256` (`Rijndael-256`)

| Scheme / Parameter Set | Underlying OWF | S-Boxes (Free) | Witness L (Bytes / Bits) | GGM Trees (tau) | PK (B) | SK (B) | Signature (B) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **FAEST-Areion-128s** | 10r Areion-256 (MulOrtho256) | 320 (32 free) | 304 B (2,432 b) | 13 | 48 | 64 | **6,448** |
| **FAEST-Areion-128f** | 10r Areion-256 (MulOrtho256) | 320 (32 free) | 304 B (2,432 b) | 16 | 48 | 64 | **7,456** |
| **FAEST-Areion-256s** | 10r Areion-256 (MulOrtho256) | 320 (32 free) | 320 B (2,560 b) | 26 | 64 | 96 | **18,208** |
| **FAEST-Areion-256f** | 10r Areion-256 (MulOrtho256) | 320 (32 free) | 320 B (2,560 b) | 32 | 64 | 96 | **20,512** |
| **FAEST-Areion-EM2-256s** | 20r Areion-EM2-256 (OrthoSigma256) | 640 (64 free) | 608 B (4,864 b) | 26 | 64 | 96 | **25,696** |
| **FAEST-Areion-EM2-256f** | 20r Areion-EM2-256 (OrthoSigma256) | 640 (64 free) | 608 B (4,864 b) | 32 | 64 | 96 | **30,368** |
| FAEST-EM-256 (NIST Round 2) | 14r Rijndael-256 | 448 (0 free) | 480 B (3,840 b) | 32 | 64 | 96 | ~25,100 |
| FAEST-256 (NIST Round 2) | 2 × 14r AES-256 + KeySched | 500 (0 free) | 512 B (4,096 b) | 32 | 64 | 96 | ~26,700 |

Compared to 14-round `Rijndael-256` (`FAEST-EM-256`, `480 B` witness) and `FAEST-256` (`512 B` witness), `FAEST-Areion-256{s,f}` reduces the committed witness length by **33.3%** and **37.5%** (`320 B` total: `32 B` key + `288 B` S-box witness) while executing without cross-lane `PSHUFB` / `VTBL` byte shuffles.

---

### 2. Track 2: `SLH-DSA-Areion` (`NIST FIPS 205` Stateless Hash-Based Signatures)

`SLH-DSA-Areion` instantiates the `NIST FIPS 205` (`SPHINCS+`) framework with `Areion-256` and `Areion-512` primitives:

1. **One-Time Seed Expansion (`areion_pq_slh_expand_seed128` / `areion_pq_slh_expand_seed256`)**: Expands `PK.seed` into a 64-byte public key schedule `K_pub = K_pub1 || K_pub2` via `(areion_dm256(PK.seed), P2_256(PK.seed) ⊕ PK.seed)` and `SK.seed` into a 64-byte secret key schedule `K_sk`.
2. **Clamped-Capacity `DM512` Tweakable Hashes (Profile I — `areion_pq_slh_f128`, `areion_pq_slh_f256`, `areion_pq_slh_h128`, `areion_pq_slh_h256`, `areion_pq_slh_tl128`, `areion_pq_slh_tl256`)**:
   A naive feed-forward construction `F_naive(K_pub, ADRS, M1) = areion_tem_encrypt256(K_pub, ADRS, M1) ⊕ M1 = areion_dm256(M1 ⊕ W(ADRS))` suffers total tweak cancellation (`quotient rank = 0 / 256`), allowing a 1-query multi-target collision `M1' = M1 ⊕ W(ADRS) ⊕ W(ADRS')`. Instead:
   - **`areion_pq_slh_f256` (`DM512-Clamped`)** evaluates `areion_dm512((ADRS ⊕ K_pub1) || (M1 ⊕ K_pub2))`, clamping the 256-bit whitened address `ADRS ⊕ K_pub1` in the left 32-byte capacity half of `P1_512` (`quotient rank = 256 / 256`).
   - **`areion_pq_slh_f128` and `areion_pq_slh_h128`** pack `(PK.seed || ADRS || M1) ⊕ K_pub` and `(PK.seed || areion_pq_slh_compact_adrs(ADRS) || M1 || M2) ⊕ K_pub` into a single `areion_dm512` call, where `areion_pq_slh_compact_adrs` extracts all 16 active `FIPS 205` address bytes (`GF(2)` rank `128 / 128`).
3. **Middle-Tweak `TEM` Tweakable Hash (Profile II — `areion_pq_slh_f_tem256` for `SLH-DSA-Areion-TEM-256f`)**:
   ```text
   SLHFTEM256(K_pub, ADRS, M1) = areion_tem_encrypt256(K_pub, M1, ADRS) ⊕ M1
                               = P1_256(ADRS ⊕ W(M1)) ⊕ W(M1) ⊕ M1,   W(M1) = P2_256(M1 ⊕ K_pub2) ⊕ K_pub1
   ```
   Feeding `M1` through `P2_256` as the nonlinear tweak mask while encrypting `ADRS` inside `P1_256` decouples `ADRS` from the outer feed-forward `⊕ W(M1) ⊕ M1` (`quotient rank = 256 / 256`; see [`everanium/areion-pq/analysis/README.md` (Section D)](https://github.com/everanium/areion-pq/blob/main/analysis/README.md#d-slh-dsa-areion-tweak-cancellation-rank-audit-and-ipm-multi-target-bounds)).
4. **4-Way Batched `WOTS+` Secret-Key PRFs (`areion_pq_slh_prf256x4`) and 4-Way `WOTS+` Chain Evaluation**: Evaluates `areion_soem256x4` and `areion_permute512x4` across 4 `WOTS+` chains in parallel.

#### Parameter Sets & Comparison with `NIST FIPS 205` (`SLH-DSA-SHA2` / `SLH-DSA-SHAKE`)

| Parameter Set | Category | n (B) | (h, d, h', a, k, len) | PK (B) | SK (B) | Signature (B) | Tweakable Chain Hash F |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **SLH-DSA-Areion-128f** | Cat 1 | 16 | (66, 22, 3, 6, 33, 35) | 32 | 64 | **17,088** | 1 × 15r DM512 (60 AES insts) |
| **SLH-DSA-Areion-128s** | Cat 1 | 16 | (63, 7, 9, 12, 14, 35) | 32 | 64 | **7,856** | 1 × 15r DM512 (60 AES insts) |
| **SLH-DSA-Areion-256f** | Cat 5 | 32 | (68, 17, 4, 9, 35, 67) | 64 | 128 | **49,856** | 1 × 15r DM512-Clamped (60 AES insts) |
| **SLH-DSA-Areion-256s** | Cat 5 | 32 | (64, 8, 8, 14, 22, 67) | 64 | 128 | **29,792** | 1 × 15r DM512-Clamped (60 AES insts) |
| **SLH-DSA-Areion-TEM-256f** | Cat 5 | 32 | (68, 17, 4, 9, 35, 67) | 64 | 128 | **49,856** | 1 × TEM-MiddleTweak (40 AES insts) |
| SLH-DSA-SHA2-128f / 256f | Cat 1 / 5 | 16 / 32 | FIPS 205 standard | 32 / 64 | 64 / 128 | 17,088 / 49,856 | 64r SHA-256 / 80r SHA-512 |
| SLH-DSA-SHAKE-128f / 256f | Cat 1 / 5 | 16 / 32 | FIPS 205 standard | 32 / 64 | 64 / 128 | 17,088 / 49,856 | 24r Keccak-f[1600] (136 B rate) |

---

### 3. Track 3: `Areion-HPKE` & `Areion-TEM2-SIV` Wide-Block AEAD

1. **`areion_pq_kdf_expand`**: Absorbs variable-length `secret` and `context` blocks through a domain-separated `areion_dm512` sponge (`32 B` rate, `32 B` capacity), derives a 128-byte `areion_soem512` key via `P1_256` and `P2_256`, and expands arbitrary-length key material at 256 bytes per iteration using 4-way `areion_soem512x4`.
2. **`Areion-TEM2-SIV` (`areion_pq_tem2_siv_encrypt` / `areion_pq_tem2_siv_decrypt`)**:
   - **SIV Authentication**: Absorbs the 32-byte `nonce`, `ad`, and `plaintext` in 256-byte (`4 × 64 B`) chunks via 4-way `areion_soem512x4` with per-block counter and domain separation, finalized by `areion_dm512` into a 32-byte (256-bit) synthetic IV `tag`.
   - **Wide-Block Encryption**: Encrypts full 64-byte (512-bit) blocks via 4-way `areion_tem2_encrypt512x4` / `areion_tem2_decrypt512x4` tweaked by `tag || nonce[0:16] || block_counter || domain` (and any partial tail `< 64 B` via `areion_soem512`). Because `areion_soem512` and `TEM2-512` operate on 512-bit states over independent `(P1_512, P2_512)`, `Areion-TEM2-SIV` achieves **Beyond-Birthday-Bound (BBB) security up to `2^341.3` classical queries (`2^170.7` quantum queries)** and full 256-bit nonce-misuse resistance (MRAE).
3. **Deterministic HPKE Key Derivation & Sealing (`areion_pq_hpke_derive_keys`, `areion_pq_hpke_seal_det`, `areion_pq_hpke_open_det`)**: Derives a 128-byte DEM key and 32-byte base nonce from a 32-byte KEM shared secret (such as `ML-KEM-768` from `NIST FIPS 203`) and context `info`, and seals/opens sequence-numbered payloads (`base_nonce ⊕ seq`) with `Areion-TEM2-SIV`.

| AEAD Construction | Block Size | Key Size | Nonce / Tag | Classical Bound | Quantum Bound | Nonce-Misuse Behavior |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| AES-256-GCM (SP 800-38D) | 128 b | 256 b | 96 b / 128 b | 2^64.0 | 2^32.0 | Catastrophic (GHASH key recovery + stream reuse) |
| AES-256-GCM-SIV (RFC 8452) | 128 b | 256 b | 96 b / 128 b | 2^64.0 | 2^32.0 | 128-bit MRAE (capped by 128-bit block birthday bound) |
| **Areion-TEM2-SIV** | **512 b** | **1024 b** | **256 b / 256 b** | **2^341.3 (2n/3)** | **2^170.7** | **Full 256-bit SIV + 512-bit wide-block TPRP MRAE** |

---

## Hardware Acceleration & ABI Support

`libareion_pq` automatically detects host CPU features and OS SIMD context support (`CPUID` + `XGETBV` on `x86-64`, `getauxval(AT_HWCAP)` / `sysctlbyname` on `arm64`) and synchronizes its active tier with the underlying `areion-c` permutation tier:

| Tier | Architectures | Instructions Used | Accelerated Primitives |
| :--- | :--- | :--- | :--- |
| **`avx512`** | Intel Ice Lake, Tiger Lake, Rocket Lake, Xeon Ice Lake-SP+; AMD Zen 4+ (`AVX-512F/DQ/BW/VL + VAES + VPCLMULQDQ`) | `VAESENC`, `VAESENCLAST`, `VPCLMULQDQ`, `VPXORQ`, `VMOVDQU64` | 512-bit ZMM `VOLE` row XOR (`areion_pq_vole_xor_row_avx512`), 4-way ZMM `areion_soem{256,512}x4` & `areion_tem2_{encrypt,decrypt}512x4`, VEX `areion_pq_extract_witness256_vex` & `areion_pq_gf128_{mul,polymac}_vpclmul` |
| **`vaesavx2`** | Intel Alder Lake+; AMD Zen 3 (`AVX2 + VAES + VPCLMULQDQ`) | `VAESENC`, `VAESENCLAST`, `VPCLMULQDQ`, `VPXOR`, `VMOVDQU` | 256-bit YMM `VOLE` row XOR (`areion_pq_vole_xor_row_avx2`), 4-way YMM `areion_soem{256,512}x4` & `areion_tem2_{encrypt,decrypt}512x4`, VEX `areion_pq_extract_witness256_vex` & `areion_pq_gf128_{mul,polymac}_vpclmul` |
| **`vex`** | Intel Sandy Bridge+, AMD Bulldozer+ (`AVX + AES-NI + PCLMULQDQ`) | 3-operand VEX `VAESENC`, `VAESENCLAST`, `VPCLMULQDQ`, `VPXOR`, `VPSRLDQ`, `VPSLLDQ` | Zero-copy VEX `areion_pq_extract_witness256_vex`, `areion_pq_gf128_mul_vpclmul`, `areion_pq_gf128_polymac_vpclmul`, SSE2 `VOLE` row XOR |
| **`aesni`** | Intel Westmere+ (`AES-NI + PCLMULQDQ` without `AVX`) | Legacy 2-operand `AESENC`, `AESENCLAST`, `PCLMULQDQ`, `PXOR`, `PSRLDQ`, `PSLLDQ` | `areion_pq_extract_witness256_aesni`, `areion_pq_gf128_mul_pclmul`, `areion_pq_gf128_polymac_pclmul`, `areion_pq_vole_xor_row_sse2` |
| **`arm64`** | ARMv8 Cryptographic Extension, Apple Silicon, AWS Graviton (`NEON + AES + PMULL`) | `AESE`, `AESMC`, `PMULL`, `PMULL2`, `EXT`, `EOR` | `areion_pq_extract_witness256_arm64`, `areion_pq_gf128_mul_pmull`, `areion_pq_gf128_polymac_pmull`, 64-byte unrolled `areion_pq_vole_xor_row_neon` |
| **`purec`** | All architectures — verified across 9 `qemu-*-static` targets (`aarch64`, `riscv64`, `s390x` 64-bit BE, `ppc64le`, `arm` 32-bit, `i386` 32-bit, `mips64` 64-bit BE, `mips` 32-bit BE, `loongarch64`) plus native `x86-64` | Constant-time 64-bit bitsliced Boyar–Peralta S-boxes & maskless `GF(2^128)` arithmetic | Portable constant-time software implementations across all primitives |

> **Cross-OS & Cross-Assembler Support:**
> - **GNU GAS / Clang Integrated Assembler (`.S`)**: Supports Linux ELF (`x86_64`, `aarch64`), macOS Mach-O (`x86_64`, `arm64`), and Windows MinGW-w64 COFF (`x86_64`) via `asm_abi.h` (including automatic Windows x64 `XMM6..XMM15` non-volatile save/restore and parameter register remapping).
> - **Microsoft Visual Studio (`msvc/*.asm`)**: Pre-generated MASM (`ml64.exe`) and ARMASM64 (`armasm64.exe`) sources selected automatically by `CMakeLists.txt` when building with MSVC.

> **Register and stack zeroization:** Every hardware assembly kernel in `areion_pq_amd64.S` and `areion_pq_arm64.S` executes with a zero-byte stack frame and clears all touched vector registers (`PXOR` / `VPXOR` / `VPXORD` + `VZEROUPPER` on `x86-64`; `EOR` on `v0..v31` on `arm64`) and scratch general-purpose registers (`XORQ` on `x86-64`; `MOV xN, xzr` on `arm64`) before returning. Composite C routines scrub local buffers via DSE-resistant `areion_pq_secure_wipe` (`volatile uint8_t *` + compiler barrier), wipe their 6,144-byte software stack frame (`areion_pq_wipe_software_stack`), and clobber volatile scratch GPRs (`areion_pq_clobber_scratch_gprs`). Verified across all tiers by `areion_pq_zeroize_test.c` (with mandatory negative stack and SIMD/GPR controls).

---

## Benchmarks

### 1. Intel® Core™ i7-11700K @ 3.60GHz (Rocket Lake, x86-64)

3-run averaged throughput measured across all 5 execution tiers on the same physical CPU (`./areion_pq_test --bench --tier=<tier>`, `f = 3.60 GHz`):

#### Finite-Field, Witness Extraction, KDF & Wide-Block AEAD Primitives (MB/s, ns/op)

| Operation | `purec` | `aesni` | `vex` | `vaesavx2` | `avx512` | `c/B` (best) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **`areion_pq_gf128_mul` (16 B)** | 46.6 (345.76 ns) | 4,853.5 (3.31 ns) | 5,017.1 (3.19 ns) | 5,382.7 (2.98 ns) | 5,516.5 (2.91 ns) | 0.65 c/B |
| **`areion_pq_gf128_polymac` (256 B)** | 33.3 (7,691.06 ns) | 2,387.5 (107.24 ns) | 2,440.4 (104.90 ns) | 2,443.0 (104.79 ns) | 2,469.9 (103.65 ns) | 1.46 c/B |
| **`areion_pq_extract_witness256` (288 B)** | 221.3 (1,304.27 ns) | 46,314.0 (6.22 ns) | 47,533.5 (6.06 ns) | 45,366.1 (6.38 ns) | 46,080.2 (6.27 ns) | 0.08 c/B |
| **`areion_pq_verify_witness256` (288 B)** | 29.6 (9,760.52 ns) | 14,747.6 (19.58 ns) | 15,979.8 (18.06 ns) | 15,588.2 (18.55 ns) | 15,144.3 (19.23 ns) | 0.23 c/B |
| **`areion_pq_extract_witness_em2_256` (576 B)** | 248.8 (2,318.18 ns) | 23,905.1 (24.33 ns) | 27,604.2 (21.29 ns) | 28,893.8 (20.00 ns) | 28,813.8 (20.12 ns) | 0.13 c/B |
| **`areion_pq_verify_witness_em2_256` (576 B)** | 30.5 (18,909.01 ns) | 13,545.3 (42.57 ns) | 13,294.6 (43.41 ns) | 12,901.9 (44.74 ns) | 12,945.4 (44.68 ns) | 0.27 c/B |
| **`areion_pq_kdf_expand` (1,024 B)** | 48.6 (21,114.42 ns) | 1,341.4 (766.05 ns) | 1,680.5 (609.79 ns) | 2,101.9 (487.81 ns) | 2,025.6 (505.61 ns) | 1.71 c/B |
| **`areion_pq_tem2_siv_encrypt` (4,096 B)** | 26.2 (156,385.42 ns) | 683.2 (6,020.88 ns) | 857.8 (4,776.26 ns) | 1,381.7 (2,967.79 ns) | 1,649.4 (2,484.74 ns) | 2.18 c/B |
| **`areion_pq_tem2_siv_decrypt` (4,096 B)** | 24.2 (169,301.43 ns) | 526.0 (7,787.15 ns) | 564.8 (7,254.39 ns) | 971.4 (4,219.40 ns) | 1,274.4 (3,218.91 ns) | 2.83 c/B |

#### Post-Quantum Signatures: `FAEST-Areion` & `SLH-DSA-Areion` (ops/s, ns/op)

| Operation | `purec` | `aesni` | `vex` | `vaesavx2` | `avx512` | Speedup vs `purec` |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **`areion_pq_faest_sign128f`** | 27.0 (36,974,500 ns) | 552.8 (1,808,885 ns) | 606.7 (1,648,396 ns) | 785.7 (1,272,776 ns) | 813.8 (1,228,771 ns) | 30.1× |
| **`areion_pq_faest_verify128f`** | 28.0 (35,736,583 ns) | 627.1 (1,594,740 ns) | 628.1 (1,592,010 ns) | 827.5 (1,208,531 ns) | 866.8 (1,153,620 ns) | 31.0× |
| **`areion_pq_faest_sign256f`** | 11.4 (87,556,667 ns) | 265.7 (3,763,812 ns) | 265.8 (3,762,771 ns) | 326.8 (3,060,052 ns) | 360.3 (2,775,635 ns) | 31.5× |
| **`areion_pq_faest_verify256f`** | 11.6 (86,222,500 ns) | 286.4 (3,491,333 ns) | 279.2 (3,581,208 ns) | 329.9 (3,031,167 ns) | 344.1 (2,905,833 ns) | 29.7× |
| **`areion_pq_faest_em2_sign256f`** | 7.0 (142,550,167 ns) | 173.6 (5,759,896 ns) | 177.0 (5,650,000 ns) | 216.5 (4,619,479 ns) | 214.0 (4,673,396 ns) | 30.9× |
| **`areion_pq_faest_em2_verify256f`** | 7.0 (142,130,167 ns) | 198.3 (5,043,500 ns) | 187.6 (5,331,812 ns) | 234.8 (4,258,708 ns) | 259.5 (3,853,646 ns) | 36.9× |
| **`areion_pq_slhdsa_sign128f`** | 7.3 (137,675,083 ns) | 368.4 (2,714,188 ns) | 364.3 (2,745,333 ns) | 368.9 (2,710,562 ns) | 364.8 (2,740,927 ns) | 50.8× |
| **`areion_pq_slhdsa_verify128f`** | 114.7 (8,718,479 ns) | 5,982.5 (167,154 ns) | 5,981.7 (167,176 ns) | 5,938.4 (168,395 ns) | 5,932.1 (168,576 ns) | 52.2× |
| **`areion_pq_slhdsa_sign256f`** | 4.0 (250,967,833 ns) | 166.8 (5,995,312 ns) | 171.7 (5,823,479 ns) | 176.7 (5,659,354 ns) | 169.3 (5,907,083 ns) | 44.3× |
| **`areion_pq_slhdsa_verify256f`** | 77.4 (12,919,125 ns) | 4,403.2 (227,105 ns) | 4,393.5 (227,611 ns) | 4,273.0 (234,030 ns) | 4,327.5 (231,079 ns) | 56.9× |
| **`areion_pq_slhdsa_tem_sign256f`** | 1.7 (597,355,333 ns) | 85.3 (11,728,125 ns) | 85.3 (11,719,083 ns) | 85.7 (11,674,375 ns) | 85.1 (11,746,792 ns) | 51.2× |
| **`areion_pq_slhdsa_tem_verify256f`** | 59.6 (16,765,458 ns) | 3,011.1 (332,103 ns) | 3,031.9 (329,827 ns) | 3,022.3 (330,875 ns) | 3,048.8 (327,997 ns) | 51.1× |

On Intel® Core™ i7-11700K, `areion_pq_slhdsa_verify128f` completes in **`167.2 us` (`5,983 ops/s`)** and `areion_pq_slhdsa_verify256f` in **`227.1 us` (`4,403 ops/s`)**, while `areion_pq_faest_sign128f` / `areion_pq_faest_verify128f` run in **`1.23 ms` / `1.15 ms`**, `areion_pq_faest_sign256f` / `areion_pq_faest_verify256f` in **`2.78 ms` / `2.91 ms`**, `areion_pq_kdf_expand` reaches **`2,101.9 MB/s`** (`1.71 c/B`), and `areion_pq_tem2_siv_encrypt` reaches **`1,649.4 MB/s`** (`2.18 c/B`) on `avx512`.

### 2. AWS Graviton 4 (`c8g.4xlarge`, Neoverse-V2, 16 vCPUs, ARM64)

3-run averaged throughput measured on AWS Graviton 4 (`./areion_pq_test --bench --tier=<tier>`, `purec` bitsliced fallback vs `arm64` ARMv8 Cryptographic Extension at `f = 2.80 GHz`):

#### Finite-Field, Witness Extraction, KDF & Wide-Block AEAD Primitives (MB/s, ns/op)

| Operation | `purec` | `arm64` | `c/B` (`arm64`) |
| :--- | :---: | :---: | :---: |
| **`areion_pq_gf128_mul` (16 B)** | 36.5 (439.14 ns) | 3,745.5 (4.27 ns) | 0.75 c/B |
| **`areion_pq_gf128_polymac` (256 B)** | 48.8 (5,241.21 ns) | 1,718.1 (149.01 ns) | 1.63 c/B |
| **`areion_pq_extract_witness256` (288 B)** | 198.5 (1,451.15 ns) | 19,501.6 (14.77 ns) | 0.14 c/B |
| **`areion_pq_verify_witness256` (288 B)** | 30.8 (9,352.90 ns) | 8,756.2 (32.89 ns) | 0.32 c/B |
| **`areion_pq_extract_witness_em2_256` (576 B)** | 218.6 (2,634.85 ns) | 11,734.2 (49.09 ns) | 0.24 c/B |
| **`areion_pq_verify_witness_em2_256` (576 B)** | 31.1 (18,510.95 ns) | 6,684.3 (86.17 ns) | 0.42 c/B |
| **`areion_pq_kdf_expand` (1,024 B)** | 42.5 (24,071.62 ns) | 1,067.0 (959.81 ns) | 2.62 c/B |
| **`areion_pq_tem2_siv_encrypt` (4,096 B)** | 23.6 (173,796.22 ns) | 585.8 (6,991.58 ns) | 4.78 c/B |
| **`areion_pq_tem2_siv_decrypt` (4,096 B)** | 21.9 (187,320.64 ns) | 548.3 (7,470.99 ns) | 5.11 c/B |

#### Post-Quantum Signatures: `FAEST-Areion` & `SLH-DSA-Areion` (ops/s, ns/op)

| Operation | `purec` | `arm64` | Speedup vs `purec` |
| :--- | :---: | :---: | :---: |
| **`areion_pq_faest_sign128f`** | 24.5 (40,824,583 ns) | 473.1 (2,113,729 ns) | 19.3× |
| **`areion_pq_faest_verify128f`** | 25.0 (40,046,667 ns) | 513.4 (1,947,833 ns) | 20.6× |
| **`areion_pq_faest_sign256f`** | 10.0 (100,239,833 ns) | 208.7 (4,792,708 ns) | 20.9× |
| **`areion_pq_faest_verify256f`** | 10.2 (98,201,667 ns) | 225.1 (4,441,750 ns) | 22.1× |
| **`areion_pq_faest_em2_sign256f`** | 6.2 (160,186,833 ns) | 129.6 (7,716,750 ns) | 20.8× |
| **`areion_pq_faest_em2_verify256f`** | 6.3 (157,686,167 ns) | 142.1 (7,035,917 ns) | 22.4× |
| **`areion_pq_slhdsa_sign128f`** | 5.8 (172,348,667 ns) | 180.9 (5,528,417 ns) | 31.2× |
| **`areion_pq_slhdsa_verify128f`** | 94.5 (10,585,188 ns) | 2,964.2 (337,359 ns) | 31.4× |
| **`areion_pq_slhdsa_sign256f`** | 3.4 (294,538,833 ns) | 111.0 (9,012,625 ns) | 32.7× |
| **`areion_pq_slhdsa_verify256f`** | 65.9 (15,163,500 ns) | 2,310.1 (432,875 ns) | 35.0× |
| **`areion_pq_slhdsa_tem_sign256f`** | 1.4 (706,022,333 ns) | 42.6 (23,467,167 ns) | 30.1× |
| **`areion_pq_slhdsa_tem_verify256f`** | 48.9 (20,445,833 ns) | 1,541.2 (648,844 ns) | 31.5× |

On AWS Graviton 4 (`arm64`), `areion_pq_slhdsa_verify128f` completes in **`337.4 us` (`2,964 ops/s`)** and `areion_pq_slhdsa_verify256f` in **`432.9 us` (`2,310 ops/s`)**, while `areion_pq_faest_sign128f` / `areion_pq_faest_verify128f` run in **`2.11 ms` / `1.95 ms`** and `areion_pq_faest_sign256f` / `areion_pq_faest_verify256f` in **`4.79 ms` / `4.44 ms`**.

---

## SUPERCOP (`eBACS`) & PQClean C99 Wrappers (`supercop/`, `pqclean/`)

Standard SUPERCOP (`eBACS`) C99 `ref` wrappers (`api.h` + `sign.c` / `encrypt.c`) and standalone PQClean `clean` packages (`api.h`, `sign.c`, `Makefile`) are provided in [`supercop/`](supercop/) and [`pqclean/`](pqclean/) and tested automatically during `make test` (`make test-supercop` and `test_signatures_and_wrappers()` in `areion_pq_test.c`):

- **SUPERCOP (`supercop/`, 11 schemes)**:
  - `supercop/crypto_sign/faest_areion128s/ref/` (`crypto_sign` → `areion_pq_faest_{keygen,sign,verify}128s`)
  - `supercop/crypto_sign/faest_areion128f/ref/` (`crypto_sign` → `areion_pq_faest_{keygen,sign,verify}128f`)
  - `supercop/crypto_sign/faest_areion256s/ref/` (`crypto_sign` → `areion_pq_faest_{keygen,sign,verify}256s`)
  - `supercop/crypto_sign/faest_areion256f/ref/` (`crypto_sign` → `areion_pq_faest_{keygen,sign,verify}256f`)
  - `supercop/crypto_sign/faest_areion_em2_256s/ref/` (`crypto_sign` → `areion_pq_faest_em2_{keygen,sign,verify}256s`)
  - `supercop/crypto_sign/faest_areion_em2_256f/ref/` (`crypto_sign` → `areion_pq_faest_em2_{keygen,sign,verify}256f`)
  - `supercop/crypto_sign/slh_dsa_areion128f/ref/` (`crypto_sign` → `areion_pq_slhdsa_{keygen,sign,verify}128f`)
  - `supercop/crypto_sign/slh_dsa_areion128s/ref/` (`crypto_sign` → `areion_pq_slhdsa_{keygen,sign,verify}128s`)
  - `supercop/crypto_sign/slh_dsa_areion256f/ref/` (`crypto_sign` → `areion_pq_slhdsa_{keygen,sign,verify}256f`)
  - `supercop/crypto_sign/slh_dsa_areion256s/ref/` (`crypto_sign` → `areion_pq_slhdsa_{keygen,sign,verify}256s`)
  - `supercop/crypto_aead/areion_tem2_siv512/ref/` (`crypto_aead` → `areion_pq_tem2_siv_{encrypt,decrypt}`)
- **PQClean (`pqclean/`, 4 schemes)**:
  - `pqclean/crypto_sign/faest-areion-128f/clean/` (`PQCLEAN_FAESTAREION128F_CLEAN_*`)
  - `pqclean/crypto_sign/faest-areion-256f/clean/` (`PQCLEAN_FAESTAREION256F_CLEAN_*`)
  - `pqclean/crypto_sign/slh-dsa-areion-128f/clean/` (`PQCLEAN_SLHDSAAREION128F_CLEAN_*`)
  - `pqclean/crypto_sign/slh-dsa-areion-256f/clean/` (`PQCLEAN_SLHDSAAREION256F_CLEAN_*`)

---

## Reproduce

### 1. Build & Run Complete Test Suite (`make`)
```bash
# Build static/shared libraries and run unit + SUPERCOP + PQClean + pairwise tier matrix + zeroization + epilogue audit + ELF security (GNU_STACK, CET/BTI, nm -D) tests:
make test

# Run full signature test matrix (including all slow S-profile and EM2 variants):
./areion_pq_test --full

# Run extended dudect Welch's t-test constant-time timing verification:
./areion_pq_test --dudect

# Run active tier benchmark:
make bench

# Run live Go <-> C tier-by-tier and full Cartesian product (Go[tier_A] x C[tier_B]) KAT cross-verification:
make cross-kat

# Run static analysis suite (gcc -fanalyzer, clang-tidy, cppcheck):
make lint

# Run dynamic sanitizers (GCC/Clang ASan+UBSan with -fno-sanitize-recover=all, Clang MSan, Clang TSan):
make test-sanitizers

# Run Valgrind Memcheck / TIMECOP constant-time taint verification:
valgrind --error-exitcode=1 --track-origins=yes ./areion_pq_test
valgrind --error-exitcode=1 --track-origins=yes ./areion_pq_zeroize_test

# Run cross-architecture verification across qemu-*-static targets (aarch64+crypto, riscv64, s390x BE, ppc64le, arm, i386, mips64 BE, mips BE, loongarch64):
make test-qemu
```

### 2. Test & Benchmark Specific Execution Tiers
The environment variable `AREION_PQ_FORCE_TIER` (or `areion_pq_set_tier()`) forces the execution tier:
```bash
# Test individual tiers:
AREION_PQ_FORCE_TIER=purec    ./areion_pq_test && AREION_PQ_FORCE_TIER=purec    ./areion_pq_zeroize_test
AREION_PQ_FORCE_TIER=aesni    ./areion_pq_test && AREION_PQ_FORCE_TIER=aesni    ./areion_pq_zeroize_test
AREION_PQ_FORCE_TIER=vex      ./areion_pq_test && AREION_PQ_FORCE_TIER=vex      ./areion_pq_zeroize_test
AREION_PQ_FORCE_TIER=vaesavx2 ./areion_pq_test && AREION_PQ_FORCE_TIER=vaesavx2 ./areion_pq_zeroize_test
AREION_PQ_FORCE_TIER=avx512   ./areion_pq_test && AREION_PQ_FORCE_TIER=avx512   ./areion_pq_zeroize_test
AREION_PQ_FORCE_TIER=arm64    ./areion_pq_test && AREION_PQ_FORCE_TIER=arm64    ./areion_pq_zeroize_test

# Benchmark individual tiers:
./areion_pq_test --bench --tier=purec
./areion_pq_test --bench --tier=aesni
./areion_pq_test --bench --tier=vex
./areion_pq_test --bench --tier=vaesavx2
./areion_pq_test --bench --tier=avx512
./areion_pq_test --bench --tier=arm64
```

### 3. Build & Test with CMake
```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

---

## Usage Example

```c
#include "areion_pq.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    uint8_t faest_seed[AREION_PQ_FAEST128_SEED_SIZE] = {0};
    uint8_t faest_pk[AREION_PQ_FAEST128_PK_SIZE];
    uint8_t faest_sk[AREION_PQ_FAEST128_SK_SIZE];
    uint8_t faest_sig[AREION_PQ_FAEST128F_SIG_SIZE];
    uint8_t slh_seed[AREION_PQ_SLHDSA128_SEED_SIZE] = {0};
    uint8_t slh_pk[AREION_PQ_SLHDSA128_PK_SIZE];
    uint8_t slh_sk[AREION_PQ_SLHDSA128_SK_SIZE];
    uint8_t slh_sig[AREION_PQ_SLHDSA128F_SIG_SIZE];
    uint8_t shared_secret[AREION_PQ_HPKE_SHARED_SIZE] = {0x42};
    const uint8_t msg[] = "post-quantum authenticated message";
    const uint8_t info[] = "areion-pq-hpke-context";
    const uint8_t ad[] = "associated-header";
    uint8_t ct[sizeof(msg) - 1U];
    uint8_t pt[sizeof(msg) - 1U];
    uint8_t tag[AREION_PQ_TEM2_SIV_TAG_SIZE];
    int ok_faest, ok_slh, ok_hpke;

    /* 0. Optional FIPS 140-3 Cryptographic Algorithm Self-Test (CAST) */
    if (areion_pq_selftest() != 0) {
        return 1;
    }

    /* 1. Track 1: FAEST-Areion-128f zero-knowledge signature */
    areion_pq_faest_keygen128f(faest_pk, faest_sk, faest_seed);
    areion_pq_faest_sign128f(faest_sig, faest_sk, msg, sizeof(msg) - 1U, NULL);
    ok_faest = areion_pq_faest_verify128f(faest_pk, msg, sizeof(msg) - 1U, faest_sig);

    /* 2. Track 2: SLH-DSA-Areion-128f stateless hash-based signature */
    areion_pq_slhdsa_keygen128f(slh_pk, slh_sk, slh_seed);
    areion_pq_slhdsa_sign128f(slh_sig, slh_sk, msg, sizeof(msg) - 1U, NULL);
    ok_slh = areion_pq_slhdsa_verify128f(slh_pk, msg, sizeof(msg) - 1U, slh_sig);

    /* 3. Track 3: Deterministic HPKE + Areion-TEM2-SIV Wide-Block AEAD */
    areion_pq_hpke_seal_det(
        ct, tag, shared_secret,
        info, sizeof(info) - 1U, 0ULL,
        ad, sizeof(ad) - 1U,
        msg, sizeof(msg) - 1U);
    ok_hpke = areion_pq_hpke_open_det(
        pt, shared_secret,
        info, sizeof(info) - 1U, 0ULL,
        ad, sizeof(ad) - 1U,
        ct, sizeof(ct), tag);

    printf("Active tier: %s | FAEST-128f: %d | SLH-DSA-128f: %d | HPKE: %d\n",
           areion_pq_tier(), ok_faest, ok_slh,
           ok_hpke && (memcmp(pt, msg, sizeof(pt)) == 0));

    /* 4. Scrub sensitive secret keys and plaintext before returning */
    areion_pq_zeroize(faest_sk, sizeof(faest_sk));
    areion_pq_zeroize(slh_sk, sizeof(slh_sk));
    areion_pq_zeroize(shared_secret, sizeof(shared_secret));
    areion_pq_zeroize(pt, sizeof(pt));
    return (ok_faest == 1 && ok_slh == 1 && ok_hpke == 1) ? 0 : 1;
}
```

---

## References

1. **Areion: Highly-Efficient Permutations and Its Applications to Hash Functions for Short Input**
   Takanori Isobe, Ryoma Ito, Fukang Liu, Kazuhiko Minematsu, Motoki Nakahashi, Kosei Sakamoto, Rentaro Shiba.
   *IACR Transactions on Cryptographic Hardware and Embedded Systems (TCHES)*, Volume 2023, Issue 2, pp. 115–154, [doi:10.46586/tches.v2023.i2.115-154](https://doi.org/10.46586/tches.v2023.i2.115-154); extended version [IACR ePrint 2023/794](https://eprint.iacr.org/2023/794).

2. **Publicly Verifiable Zero-Knowledge and Post-Quantum Signatures from VOLE-in-the-Head (FAEST)**
   Carsten Baum, Lennart Braun, Cyprien Delpech de Saint Guilhem, Michael Klooß, Emmanuela Orsini, Lawrence Roy, Peter Scholl.
   *CRYPTO 2023*, Part V, Lecture Notes in Computer Science, vol. 14085, pp. 581–615, [doi:10.1007/978-3-031-38554-4_19](https://doi.org/10.1007/978-3-031-38554-4_19), [IACR ePrint 2023/996](https://eprint.iacr.org/2023/996).

3. **QuickSilver: Efficient and Affordable Zero-Knowledge Proofs for Circuits and Polynomials over Any Field**
   Kang Yang, Pratik Sarkar, Chenkai Weng, Xiao Wang.
   *ACM CCS 2021*, pp. 2986–3001, [doi:10.1145/3460120.3484556](https://doi.org/10.1145/3460120.3484556), [IACR ePrint 2021/076](https://eprint.iacr.org/2021/076).

4. **Stateless Hash-Based Digital Signature Standard (SLH-DSA)**
   National Institute of Standards and Technology (NIST).
   *Federal Information Processing Standards Publication 205 (FIPS 205)*, August 2024, [doi:10.6028/NIST.FIPS.205](https://doi.org/10.6028/NIST.FIPS.205).

5. **Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)**
   National Institute of Standards and Technology (NIST).
   *Federal Information Processing Standards Publication 203 (FIPS 203)*, August 2024, [doi:10.6028/NIST.FIPS.203](https://doi.org/10.6028/NIST.FIPS.203).

6. **How to Build Pseudorandom Functions from Public Random Permutations (SoEM22)**
   Yu Long Chen, Eran Lambooij, Bart Mennink.
   *CRYPTO 2019*, Part I, LNCS vol. 11692, pp. 266–293, [IACR ePrint 2019/554](https://eprint.iacr.org/2019/554).

7. **Tweaking Even-Mansour Ciphers**
   Benoît Cogliati, Rodolphe Lampe, Yannick Seurin, *CRYPTO 2015*, Part I, LNCS vol. 9215, pp. 189–208; and Avijit Dutta, **Minimizing the Two-Round Tweakable Even-Mansour Cipher**, *ASIACRYPT 2020*, Part I, LNCS vol. 12491, pp. 601–629.

---

## License

Dual-licensed under either:
- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

Copyright (c) 2026 Andrey Kuvshinov.
