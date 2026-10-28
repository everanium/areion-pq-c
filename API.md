## Public API Reference (`areion_pq.h`)

Complete C99 / C11 / C++ (`extern "C"`) reference for all exported macros, constants, types, functions, SUPERCOP (`eBACS`) wrappers, and PQClean wrappers in `libareion_pq` ([`areion_pq.h`](areion_pq.h)).
For architectural details, security proofs, algebraic analysis, and benchmarks, see [`README.md`](README.md).
Built on **[`everanium/areion-c`](https://github.com/everanium/areion-c)**; companion Go + Assembly reference library: **[`everanium/areion-pq`](https://github.com/everanium/areion-pq)** ([`API.md`](https://github.com/everanium/areion-pq/blob/main/API.md)).

---

## Table of Contents

1. [Types and Constants](#1-types-and-constants)
2. [Runtime Dispatch, Self-Test, and Memory Zeroization](#2-runtime-dispatch-self-test-and-memory-zeroization)
3. [Finite-Field Arithmetic, Orthomorphisms, and 288-S-Box Witness Primitives](#3-finite-field-arithmetic-orthomorphisms-and-288-s-box-witness-primitives)
4. [Track 1: FAEST-Areion VOLE-in-the-Head Zero-Knowledge Signatures](#4-track-1-faest-areion-vole-in-the-head-zero-knowledge-signatures)
5. [Track 2: SLH-DSA-Areion Stateless Hash-Based Signatures (NIST FIPS 205)](#5-track-2-slh-dsa-areion-stateless-hash-based-signatures-nist-fips-205)
6. [Track 3: Areion-HPKE Key Derivation, Deterministic HPKE, and Areion-TEM2-SIV Wide-Block AEAD](#6-track-3-areion-hpke-key-derivation-deterministic-hpke-and-areion-tem2-siv-wide-block-aead)
7. [Pre-C23 `_Generic` Multi-Dimensional `const` Array Macros](#7-pre-c23-_generic-multi-dimensional-const-array-macros)
8. [SUPERCOP (`eBACS`) and PQClean C99 Wrappers (`supercop/`, `pqclean/`)](#8-supercop-ebacs-and-pqclean-c99-wrappers-supercop-pqclean)
9. [Zeroization, Stack Hygiene, and ABI Guarantees](#9-zeroization-stack-hygiene-and-abi-guarantees)
10. [Usage Examples](#10-usage-examples)

---

### 1. Types and Constants

Version macros, block/state/witness/key/signature size constants (in bytes), and the runtime dispatch tier enumeration `areion_pq_tier_t` defined in [`areion_pq.h`](areion_pq.h).

#### 1.1 Version & Symbol Visibility Macros

| Macro | Value | Description |
| :--- | :---: | :--- |
| `AREION_PQ_VERSION` | `"0.1.0"` | Null-terminated semantic version string |
| `AREION_PQ_VERSION_STRING` | `"0.1.0"` | Alias for `AREION_PQ_VERSION` |
| `AREION_PQ_VERSION_MAJOR` | `0` | Major version number |
| `AREION_PQ_VERSION_MINOR` | `1` | Minor version number |
| `AREION_PQ_VERSION_PATCH` | `0` | Patch version number |
| `AREION_PQ_API` | platform-specific | Shared-library symbol export attribute (`__attribute__((visibility("default")))` or `__declspec(dllexport)`) |
| `AREION_API` | platform-specific | Defaults to `__attribute__((visibility("hidden")))` when `areion.h` is included through `areion_pq.h` so `libareion_pq.so` exports only `areion_pq_*` symbols |

#### 1.2 Finite-Field, Permutation State, and Witness Size Constants

| Constant Macro | Value (Bytes) | Description |
| :--- | :---: | :--- |
| `AREION_PQ_BLOCK_SIZE` | `16` | 128-bit AES / `GF(2^128)` block size in bytes |
| `AREION_PQ_STATE256_SIZE` | `32` | 256-bit `Areion-256` permutation state size in bytes |
| `AREION_PQ_STATE512_SIZE` | `64` | 512-bit `Areion-512` permutation state size in bytes |
| `AREION_PQ_WITNESS256_SIZE` | `288` | Committed S-box witness size in bytes for 10-round `Areion-256` (`9 × 32 B`; Round 9 has 32 free S-boxes) |
| `AREION_PQ_WITNESS_EM2_256_SIZE` / `AREION_PQ_WITNESSEM2_256_SIZE` | `576` | Committed S-box witness size in bytes for 20-round `Areion-EM2-256` (`2 × 288 B` across `P1` and `P2`) |

#### 1.3 Track 1 (`FAEST-Areion`) Key and Signature Size Constants

| Constant Macro | Value (Bytes) | Description |
| :--- | :---: | :--- |
| `AREION_PQ_FAEST128_SEED_SIZE` | `32` | Keygen seed size for `FAEST-Areion-128{s,f}` (`K(16) \|\| PK.seed(16)`) |
| `AREION_PQ_FAEST128_PUBLIC_KEY_SIZE` / `AREION_PQ_FAEST128_PK_SIZE` | `48` | Public key size for `FAEST-Areion-128{s,f}` (`PK.seed(16) \|\| C(32)`) |
| `AREION_PQ_FAEST128_SECRET_KEY_SIZE` / `AREION_PQ_FAEST128_SK_SIZE` | `64` | Secret key size for `FAEST-Areion-128{s,f}` (`K(16) \|\| PK.seed(16) \|\| C(32)`) |
| `AREION_PQ_FAEST128S_SIG_SIZE` | `6448` | Signature size for `FAEST-Areion-128s` (`tau = 13`, small signature profile) |
| `AREION_PQ_FAEST128F_SIG_SIZE` | `7456` | Signature size for `FAEST-Areion-128f` (`tau = 16`, fast signing profile) |
| `AREION_PQ_FAEST256_SEED_SIZE` | `64` | Keygen seed size for `FAEST-Areion-256{s,f}` (`K1(32) \|\| PK.seed(32)`) |
| `AREION_PQ_FAEST256_PUBLIC_KEY_SIZE` / `AREION_PQ_FAEST256_PK_SIZE` | `64` | Public key size for `FAEST-Areion-256{s,f}` (`PK.seed(32) \|\| C(32)`) |
| `AREION_PQ_FAEST256_SECRET_KEY_SIZE` / `AREION_PQ_FAEST256_SK_SIZE` | `96` | Secret key size for `FAEST-Areion-256{s,f}` (`K1(32) \|\| PK.seed(32) \|\| C(32)`) |
| `AREION_PQ_FAEST256S_SIG_SIZE` | `18208` | Signature size for `FAEST-Areion-256s` (`tau = 26`, small signature profile) |
| `AREION_PQ_FAEST256F_SIG_SIZE` | `20512` | Signature size for `FAEST-Areion-256f` (`tau = 32`, fast signing profile) |
| `AREION_PQ_FAEST_EM2_256_SEED_SIZE` / `AREION_PQ_FAESTEM2256_SEED_SIZE` | `64` | Keygen seed size for `FAEST-Areion-EM2-256{s,f}` (`K1(32) \|\| PK.seed(32)`) |
| `AREION_PQ_FAEST_EM2_256_PUBLIC_KEY_SIZE` / `AREION_PQ_FAESTEM2256_PUBLIC_KEY_SIZE` / `AREION_PQ_FAEST_EM2_256_PK_SIZE` | `64` | Public key size for `FAEST-Areion-EM2-256{s,f}` (`PK.seed(32) \|\| C(32)`) |
| `AREION_PQ_FAEST_EM2_256_SECRET_KEY_SIZE` / `AREION_PQ_FAESTEM2256_SECRET_KEY_SIZE` / `AREION_PQ_FAEST_EM2_256_SK_SIZE` | `96` | Secret key size for `FAEST-Areion-EM2-256{s,f}` (`K1(32) \|\| PK.seed(32) \|\| C(32)`) |
| `AREION_PQ_FAEST_EM2_256S_SIG_SIZE` / `AREION_PQ_FAESTEM2256S_SIG_SIZE` | `25696` | Signature size for `FAEST-Areion-EM2-256s` (`tau = 26`, 20-round `2-EM` small profile) |
| `AREION_PQ_FAEST_EM2_256F_SIG_SIZE` / `AREION_PQ_FAESTEM2256F_SIG_SIZE` | `30368` | Signature size for `FAEST-Areion-EM2-256f` (`tau = 32`, 20-round `2-EM` fast profile) |

#### 1.4 Track 2 (`SLH-DSA-Areion`) Key and Signature Size Constants

| Constant Macro | Value (Bytes) | Description |
| :--- | :---: | :--- |
| `AREION_PQ_SLHDSA128_SEED_SIZE` | `48` | Keygen seed size for `SLH-DSA-Areion-128{f,s}` (`SK.seed(16) \|\| SK.prf(16) \|\| PK.seed(16)`) |
| `AREION_PQ_SLHDSA128_PUBLIC_KEY_SIZE` / `AREION_PQ_SLHDSA128_PK_SIZE` | `32` | Public key size for `SLH-DSA-Areion-128{f,s}` (`PK.seed(16) \|\| PK.root(16)`) |
| `AREION_PQ_SLHDSA128_SECRET_KEY_SIZE` / `AREION_PQ_SLHDSA128_SK_SIZE` | `64` | Secret key size for `SLH-DSA-Areion-128{f,s}` (`SK.seed(16) \|\| SK.prf(16) \|\| PK.seed(16) \|\| PK.root(16)`) |
| `AREION_PQ_SLHDSA128F_SIG_SIZE` | `17088` | Signature size for `SLH-DSA-Areion-128f` (FIPS 205 Category 1 fast profile) |
| `AREION_PQ_SLHDSA128S_SIG_SIZE` | `7856` | Signature size for `SLH-DSA-Areion-128s` (FIPS 205 Category 1 small profile) |
| `AREION_PQ_SLHDSA256_SEED_SIZE` | `96` | Keygen seed size for `SLH-DSA-Areion-{,TEM-}256{f,s}` (`SK.seed(32) \|\| SK.prf(32) \|\| PK.seed(32)`) |
| `AREION_PQ_SLHDSA256_PUBLIC_KEY_SIZE` / `AREION_PQ_SLHDSA256_PK_SIZE` | `64` | Public key size for `SLH-DSA-Areion-{,TEM-}256{f,s}` (`PK.seed(32) \|\| PK.root(32)`) |
| `AREION_PQ_SLHDSA256_SECRET_KEY_SIZE` / `AREION_PQ_SLHDSA256_SK_SIZE` | `128` | Secret key size for `SLH-DSA-Areion-{,TEM-}256{f,s}` (`SK.seed(32) \|\| SK.prf(32) \|\| PK.seed(32) \|\| PK.root(32)`) |
| `AREION_PQ_SLHDSA256F_SIG_SIZE` | `49856` | Signature size for `SLH-DSA-Areion-256f` (FIPS 205 Category 5 fast profile, `DM512-Clamped`) |
| `AREION_PQ_SLHDSA256S_SIG_SIZE` | `29792` | Signature size for `SLH-DSA-Areion-256s` (FIPS 205 Category 5 small profile, `DM512-Clamped`) |
| `AREION_PQ_SLHDSA_TEM256F_SIG_SIZE` | `49856` | Signature size for `SLH-DSA-Areion-TEM-256f` (FIPS 205 Category 5 fast profile, `TEM-MiddleTweak`) |

#### 1.5 Track 3 (`Areion-HPKE` & `Areion-TEM2-SIV`) Size Constants

| Constant Macro | Value (Bytes) | Description |
| :--- | :---: | :--- |
| `AREION_PQ_TEM2_SIV_KEY_SIZE` / `AREION_PQ_TEM2SIV_KEY_SIZE` | `128` | 1024-bit `Areion-TEM2-SIV` AEAD key size (`K1(64) \|\| K2(64)`) |
| `AREION_PQ_TEM2_SIV_NONCE_SIZE` / `AREION_PQ_TEM2SIV_NONCE_SIZE` | `32` | 256-bit `Areion-TEM2-SIV` nonce size |
| `AREION_PQ_TEM2_SIV_TAG_SIZE` / `AREION_PQ_TEM2SIV_TAG_SIZE` | `32` | 256-bit `Areion-TEM2-SIV` synthetic IV authentication tag size |
| `AREION_PQ_HPKE_SHARED_SIZE` | `32` | 256-bit KEM shared secret size (`ML-KEM-768`) |
| `AREION_PQ_HPKE_KEY_SEED_SIZE` | `64` | 512-bit `ML-KEM-768` deterministic key generation seed size (`d(32) \|\| z(32)`) |

#### 1.6 Dispatch Tier Enumeration (`areion_pq_tier_t`)

| Enumerator | Value | Tier Name (`areion_pq_tier()`) | Required ISA Extensions |
| :--- | :---: | :---: | :--- |
| `AREION_PQ_TIER_AUTO` | `0` | *(auto-selected)* | Restores automatic CPU feature detection when passed to `areion_pq_set_tier_code` |
| `AREION_PQ_TIER_PUREC` | `1` | `"purec"` | Portable constant-time 64-bit bitsliced software fallback (all architectures) |
| `AREION_PQ_TIER_AESNI` | `2` | `"aesni"` | `x86-64` legacy 2-operand SSE `AES-NI` + `PCLMULQDQ` (128-bit XMM) |
| `AREION_PQ_TIER_VEX` | `3` | `"vex"` | `x86-64` `AVX + AES-NI + PCLMULQDQ` 3-operand VEX-encoded XMM |
| `AREION_PQ_TIER_VAESAVX2` | `4` | `"vaesavx2"` | `x86-64` `AVX2 + VAES + VPCLMULQDQ` (256-bit YMM Vector AES) |
| `AREION_PQ_TIER_AVX512` | `5` | `"avx512"` | `x86-64` `AVX-512F + AVX-512DQ + AVX-512BW + AVX-512VL + VAES + VPCLMULQDQ` (512-bit ZMM) |
| `AREION_PQ_TIER_ARM64` | `6` | `"arm64"` | `ARM64` `NEON + ARMv8 Cryptographic Extension` (`AESE` / `AESMC` / `PMULL` / `PMULL2`) |

---

### 2. Runtime Dispatch, Self-Test, and Memory Zeroization

Runtime CPU feature detection and tier override (automatically synchronized with the underlying `areion-c` permutation tier), FIPS 140-3 Known-Answer Self-Test (CAST), and DSE-resistant memory scrubbing.

| Function | C Prototype (`areion_pq.h`) | Description |
| :--- | :--- | :--- |
| `areion_pq_tier` | `const char *areion_pq_tier(void)` | Returns the active dispatch tier name (`"avx512"`, `"vaesavx2"`, `"vex"`, `"aesni"`, `"arm64"`, or `"purec"`) |
| `areion_pq_tier_code` | `areion_pq_tier_t areion_pq_tier_code(void)` | Returns the active `areion_pq_tier_t` enum value (`AREION_PQ_TIER_PUREC`..`AREION_PQ_TIER_ARM64`) |
| `areion_pq_available_tiers` | `size_t areion_pq_available_tiers(const char **out, size_t max_out)` | Populates `out[0..count-1]` with supported tier names on the current CPU (up to `max_out` entries) and returns the total number of supported tiers (safe with `out == NULL`) |
| `areion_pq_set_tier` | `int areion_pq_set_tier(const char *name)` | Overrides the active tier by string name (`"auto"`, `"purec"`, `"purego"`, `"aesni"`, `"vex"`, `"vaesavx2"`, `"avx512"`, `"arm64"`, plus aliases `"neon"`/`"sve"`/`"sve2"` and `"scalar"`/`"gpr"`) and synchronizes `areion-c`; returns `0` on success, `-1` if unsupported; also configurable via `AREION_PQ_FORCE_TIER` or `AREION_FORCE_TIER` |
| `areion_pq_set_tier_code` | `int areion_pq_set_tier_code(areion_pq_tier_t id)` | Overrides the active tier by `areion_pq_tier_t` (`AREION_PQ_TIER_AUTO` restores auto-detection) and synchronizes `areion-c`; returns `0` on success, `-1` if unsupported |
| `areion_pq_tier_supported` | `bool areion_pq_tier_supported(areion_pq_tier_t tier)` | Returns `true` if `tier` is supported by the current CPU, OS SIMD state, and build |
| `areion_pq_use_hardware_acceleration` | `void areion_pq_use_hardware_acceleration(bool enable)` | Enables (`true`, restoring `AREION_PQ_TIER_AUTO`) or disables (`false`, forcing `"purec"`) hardware acceleration |
| `areion_pq_selftest` | `int areion_pq_selftest(void)` | FIPS 140-3 Known-Answer Self-Test (CAST) across `areion_selftest()`, `GF(2^8)` degree-2 S-box equations, `GF(2^128)` multiplication, 288/576-S-box witness extraction & verification, and `TEM2-SIV` roundtrip (`0` on pass, `-1` on failure) |
| `areion_pq_zeroize` | `void areion_pq_zeroize(void *ptr, size_t len)` | DSE-resistant zeroization of `len` bytes at `ptr` (safe when `ptr == NULL` or `len == 0`) |

---

### 3. Finite-Field Arithmetic, Orthomorphisms, and 288-S-Box Witness Primitives

Constant-time arithmetic in `GF(2^8)`, `GF(2^128)`, and `GF(2^256)`, `GF(2)`-linear key orthomorphisms, and 288-byte / 576-byte S-box witness extraction and degree-2 algebraic verification.

#### 3.1 `GF(2^8)`, `GF(2^128)`, `GF(2^256)`, and Key Orthomorphisms

| Function | C Prototype (`areion_pq.h`) | Domain / Width | Description |
| :--- | :--- | :---: | :--- |
| `areion_pq_gf256_mul` | `uint8_t areion_pq_gf256_mul(uint8_t a, uint8_t b)` | `GF(2^8)` (1 B) | Constant-time product in `GF(2)[z] / (z^8 + z^4 + z^3 + z + 1)` (modulus `0x11B`) |
| `areion_pq_gf256_sq` | `uint8_t areion_pq_gf256_sq(uint8_t a)` | `GF(2^8)` (1 B) | Constant-time squaring `a^2` in `GF(2^8)` modulo `0x11B` |
| `areion_pq_gf256_inv` | `uint8_t areion_pq_gf256_inv(uint8_t a)` | `GF(2^8)` (1 B) | Constant-time inversion `a^254` in `GF(2^8)` modulo `0x11B` (with `0 -> 0`) |
| `areion_pq_gf256_affine` | `uint8_t areion_pq_gf256_affine(uint8_t a)` | `GF(2)^8` (1 B) | Forward FIPS 197 AES affine transformation over `GF(2)` (including `⊕ 0x63`); `areion_pq_gf256_affine(areion_pq_gf256_inv(x)) == S(x)` |
| `areion_pq_gf256_affine_inv` | `uint8_t areion_pq_gf256_affine_inv(uint8_t s)` | `GF(2)^8` (1 B) | Inverse AES affine map (`u = s ⊕ 0x63`, then inverse `GF(2)` matrix); maps `s = S(x)` to `y = areion_pq_gf256_inv(x)` |
| `areion_pq_gf128_mul` | `void areion_pq_gf128_mul(uint8_t out[16], const uint8_t a[16], const uint8_t b[16])` | `GF(2^128)` (16 B) | Hardware-dispatched (`VPCLMULQDQ` / `PCLMULQDQ` / `PMULL`) product in `GF(2)[x] / (x^128 + x^7 + x^2 + x + 1)` (`0x87`); safe for in-place aliasing |
| `areion_pq_gf128_polymac` | `void areion_pq_gf128_polymac(uint8_t out[16], const uint8_t *a, const uint8_t *b, size_t count, const uint8_t chi[16])` | `GF(2^128)` (16 B) | Hardware-dispatched Horner polynomial accumulation `acc = GF128Mul(acc, chi) ⊕ GF128Mul(a[i], b[i])` over `i = 0..count-1` (`16 * count` bytes from `a` and `b`) |
| `areion_pq_gf256_field_mul` | `void areion_pq_gf256_field_mul(uint8_t out[32], const uint8_t a[32], const uint8_t b[32])` | `GF(2^256)` (32 B) | Karatsuba multiplication in the quadratic extension `GF(2^128)[Y] / (Y^2 + Y + alpha)` where `alpha = 0x87`; safe for in-place aliasing |
| `areion_pq_mul_ortho256` | `void areion_pq_mul_ortho256(uint8_t out[32], const uint8_t t[32], const uint8_t k[32])` | 32 B → 32 B | 2-lane `GF(2^128)` public-tweak orthomorphism `(GF128Mul(T[0:16], K[0:16]), GF128Mul(T[16:32], K[16:32]))` |
| `areion_pq_ortho_sigma256` | `void areion_pq_ortho_sigma256(uint8_t out[32], const uint8_t k[32])` | 32 B → 32 B | Fixed-key Feistel orthomorphism `sigma(K_L \|\| K_R) = K_R \|\| (K_L ⊕ K_R)` (`sigma^2 ⊕ sigma ⊕ id = 0`) |

#### 3.2 288-S-Box and 576-S-Box Witness Extraction and Algebraic Verification

By the Free-Round Witness Theorem, recording the 288 state bytes of rounds `0..8` of 10-round `Areion-256` fixes all 320 S-box input/output pairs across rounds `0..9` with zero committed witness bytes in Round 9 (`32` free S-boxes). Each S-box pair `(X, S)` is verified via the coupled degree-2 `GF(2^8)` bilinear identities `Sq(X) * Y ⊕ X == 0` and `Sq(Y) * X ⊕ Y == 0` where `Y = areion_pq_gf256_affine_inv(S)`. Verification functions return `1` if valid and `0` if invalid.

| Function | C Prototype (`areion_pq.h`) | Witness Size | S-Boxes (Free) | Description |
| :--- | :--- | :---: | :---: | :--- |
| `areion_pq_extract_witness256` | `void areion_pq_extract_witness256(uint8_t c[32], uint8_t w[288], const uint8_t m[32], const uint8_t k1[32], const uint8_t k2[32])` | 288 B | 320 (32 free) | Computes `C = P1_256(M ⊕ K1) ⊕ K2` and extracts the 288-byte committed witness for rounds `0..8` of `P1` |
| `areion_pq_extract_witness256_p2` | `void areion_pq_extract_witness256_p2(uint8_t c[32], uint8_t w[288], const uint8_t m[32], const uint8_t k1[32], const uint8_t k2[32])` | 288 B | 320 (32 free) | Computes `C = P2_256(M ⊕ K1) ⊕ K2` and extracts the 288-byte committed witness for rounds `0..8` of `P2` |
| `areion_pq_verify_witness256` | `int areion_pq_verify_witness256(const uint8_t m[32], const uint8_t c[32], const uint8_t k1[32], const uint8_t k2[32], const uint8_t w[288])` | 288 B | 320 (32 free) | Constant-time algebraic verification of all 320 S-box degree-2 `GF(2^8)` equations of `P1_256` (`1` = valid, `0` = invalid) |
| `areion_pq_verify_witness256_p2` | `int areion_pq_verify_witness256_p2(const uint8_t m[32], const uint8_t c[32], const uint8_t k1[32], const uint8_t k2[32], const uint8_t w[288])` | 288 B | 320 (32 free) | Constant-time algebraic verification of all 320 S-box degree-2 `GF(2^8)` equations of `P2_256` (`1` = valid, `0` = invalid) |
| `areion_pq_extract_witness_em2_256` | `void areion_pq_extract_witness_em2_256(uint8_t c[32], uint8_t w[576], const uint8_t m[32], const uint8_t k1[32], const uint8_t k2[32])` | 576 B | 640 (64 free) | Computes `C = P2_256(P1_256(M ⊕ K1) ⊕ K2) ⊕ K1 ⊕ K2` and extracts the 576-byte witness (`288 B` `P1` + `288 B` `P2`) |
| `areion_pq_verify_witness_em2_256` | `int areion_pq_verify_witness_em2_256(const uint8_t m[32], const uint8_t c[32], const uint8_t k1[32], const uint8_t k2[32], const uint8_t w[576])` | 576 B | 640 (64 free) | Constant-time algebraic verification of all 640 S-box degree-2 `GF(2^8)` equations across `P1_256` and `P2_256` (`1` = valid, `0` = invalid) |

---

### 4. Track 1: FAEST-Areion VOLE-in-the-Head Zero-Knowledge Signatures

Post-quantum zero-knowledge signature schemes built on the `Areion-256` one-way function `C = P1_256(M ⊕ K1) ⊕ MulOrtho256(T, K1)` (`FAEST-Areion-128{s,f}` and `FAEST-Areion-256{s,f}`) and the 20-round 2-round Even-Mansour one-way function `C = P2_256(P1_256(M ⊕ K1) ⊕ sigma(K1)) ⊕ K1 ⊕ sigma(K1)` (`FAEST-Areion-EM2-256{s,f}`). Pass `opt_rand = NULL` for deterministic signing or a random 16/32-byte buffer to hedge against fault/side-channel attacks. Verification functions return `1` if valid and `0` if invalid.

| Function | C Prototype (`areion_pq.h`) | Seed / PK / SK | Signature | Security Category |
| :--- | :--- | :---: | :---: | :--- |
| `areion_pq_faest_keygen128s` | `void areion_pq_faest_keygen128s(uint8_t pk[48], uint8_t sk[64], const uint8_t seed[32])` | 32 / 48 / 64 B | — | NIST Category 1 (`lambda = 128`, `tau = 13`) |
| `areion_pq_faest_sign128s` | `void areion_pq_faest_sign128s(uint8_t sig[6448], const uint8_t sk[64], const uint8_t *msg, size_t msg_len, const uint8_t opt_rand[16])` | SK: 64 B | 6,448 B | NIST Category 1 small signature profile |
| `areion_pq_faest_verify128s` | `int areion_pq_faest_verify128s(const uint8_t pk[48], const uint8_t *msg, size_t msg_len, const uint8_t sig[6448])` | PK: 48 B | 6,448 B | Constant-time `QuickSilver` + GGM verification |
| `areion_pq_faest_keygen128f` | `void areion_pq_faest_keygen128f(uint8_t pk[48], uint8_t sk[64], const uint8_t seed[32])` | 32 / 48 / 64 B | — | NIST Category 1 (`lambda = 128`, `tau = 16`) |
| `areion_pq_faest_sign128f` | `void areion_pq_faest_sign128f(uint8_t sig[7456], const uint8_t sk[64], const uint8_t *msg, size_t msg_len, const uint8_t opt_rand[16])` | SK: 64 B | 7,456 B | NIST Category 1 fast signing profile |
| `areion_pq_faest_verify128f` | `int areion_pq_faest_verify128f(const uint8_t pk[48], const uint8_t *msg, size_t msg_len, const uint8_t sig[7456])` | PK: 48 B | 7,456 B | Constant-time `QuickSilver` + GGM verification |
| `areion_pq_faest_keygen256s` | `void areion_pq_faest_keygen256s(uint8_t pk[64], uint8_t sk[96], const uint8_t seed[64])` | 64 / 64 / 96 B | — | NIST Category 5 (`lambda = 256`, `tau = 26`) |
| `areion_pq_faest_sign256s` | `void areion_pq_faest_sign256s(uint8_t sig[18208], const uint8_t sk[96], const uint8_t *msg, size_t msg_len, const uint8_t opt_rand[32])` | SK: 96 B | 18,208 B | NIST Category 5 small signature profile |
| `areion_pq_faest_verify256s` | `int areion_pq_faest_verify256s(const uint8_t pk[64], const uint8_t *msg, size_t msg_len, const uint8_t sig[18208])` | PK: 64 B | 18,208 B | Constant-time `QuickSilver` + GGM verification |
| `areion_pq_faest_keygen256f` | `void areion_pq_faest_keygen256f(uint8_t pk[64], uint8_t sk[96], const uint8_t seed[64])` | 64 / 64 / 96 B | — | NIST Category 5 (`lambda = 256`, `tau = 32`) |
| `areion_pq_faest_sign256f` | `void areion_pq_faest_sign256f(uint8_t sig[20512], const uint8_t sk[96], const uint8_t *msg, size_t msg_len, const uint8_t opt_rand[32])` | SK: 96 B | 20,512 B | NIST Category 5 fast signing profile |
| `areion_pq_faest_verify256f` | `int areion_pq_faest_verify256f(const uint8_t pk[64], const uint8_t *msg, size_t msg_len, const uint8_t sig[20512])` | PK: 64 B | 20,512 B | Constant-time `QuickSilver` + GGM verification |
| `areion_pq_faest_em2_keygen256s` | `void areion_pq_faest_em2_keygen256s(uint8_t pk[64], uint8_t sk[96], const uint8_t seed[64])` | 64 / 64 / 96 B | — | NIST Category 5 20-round `2-EM` (`tau = 26`); macro alias: `areion_pq_faest_keygen_em2_256s` |
| `areion_pq_faest_em2_sign256s` | `void areion_pq_faest_em2_sign256s(uint8_t sig[25696], const uint8_t sk[96], const uint8_t *msg, size_t msg_len, const uint8_t opt_rand[32])` | SK: 96 B | 25,696 B | NIST Category 5 `2-EM` small signature profile; macro alias: `areion_pq_faest_sign_em2_256s` |
| `areion_pq_faest_em2_verify256s` | `int areion_pq_faest_em2_verify256s(const uint8_t pk[64], const uint8_t *msg, size_t msg_len, const uint8_t sig[25696])` | PK: 64 B | 25,696 B | Constant-time 640-S-box `QuickSilver` verification; macro alias: `areion_pq_faest_verify_em2_256s` |
| `areion_pq_faest_em2_keygen256f` | `void areion_pq_faest_em2_keygen256f(uint8_t pk[64], uint8_t sk[96], const uint8_t seed[64])` | 64 / 64 / 96 B | — | NIST Category 5 20-round `2-EM` (`tau = 32`); macro alias: `areion_pq_faest_keygen_em2_256f` |
| `areion_pq_faest_em2_sign256f` | `void areion_pq_faest_em2_sign256f(uint8_t sig[30368], const uint8_t sk[96], const uint8_t *msg, size_t msg_len, const uint8_t opt_rand[32])` | SK: 96 B | 30,368 B | NIST Category 5 `2-EM` fast signing profile; macro alias: `areion_pq_faest_sign_em2_256f` |
| `areion_pq_faest_em2_verify256f` | `int areion_pq_faest_em2_verify256f(const uint8_t pk[64], const uint8_t *msg, size_t msg_len, const uint8_t sig[30368])` | PK: 64 B | 30,368 B | Constant-time 640-S-box `QuickSilver` verification; macro alias: `areion_pq_faest_verify_em2_256f` |

---

### 5. Track 2: SLH-DSA-Areion Stateless Hash-Based Signatures (NIST FIPS 205)

Stateless hash-based signatures conforming to the `NIST FIPS 205` hypertree + `FORS` + `WOTS+` architecture, instantiated with domain-separated `Areion-512` Davies-Meyer (`areion_dm512`), `areion_soem256` / `areion_soem256x4` PRFs, and middle-tweak `areion_tem_encrypt256`.

#### 5.1 Seed Expansion, Address Compression, and Tweakable Hash Primitives

| Function | C Prototype (`areion_pq.h`) | Output | Description |
| :--- | :--- | :---: | :--- |
| `areion_pq_slh_expand_seed128` | `void areion_pq_slh_expand_seed128(uint8_t k_pub[64], uint8_t k_sk[64], const uint8_t pk_seed[16], const uint8_t sk_seed[16])` | 2 × 64 B | Expands 16-byte `PK.seed` and optional `SK.seed` (`k_sk` or `sk_seed` may be `NULL` during verify) into 64-byte `K_pub` and `K_sk` |
| `areion_pq_slh_expand_seed256` | `void areion_pq_slh_expand_seed256(uint8_t k_pub[64], uint8_t k_sk[64], const uint8_t pk_seed[32], const uint8_t sk_seed[32])` | 2 × 64 B | Expands 32-byte `PK.seed` and optional `SK.seed` (`k_sk` or `sk_seed` may be `NULL` during verify) into 64-byte `K_pub` and `K_sk` |
| `areion_pq_slh_compact_adrs` | `void areion_pq_slh_compact_adrs(uint8_t out[16], const uint8_t adrs[32])` | 16 B | Extracts all 16 active bytes (`128` bits, `GF(2)` rank `128 / 128`) of a 32-byte `FIPS 205` `ADRS` structure |
| `areion_pq_slh_prf128` | `void areion_pq_slh_prf128(uint8_t out[16], const uint8_t k_sk[64], const uint8_t adrs[32])` | 16 B | Secret-key address PRF `areion_soem256(K_sk, ADRS)[0:16]` for `n = 16` |
| `areion_pq_slh_prf256` | `void areion_pq_slh_prf256(uint8_t out[32], const uint8_t k_sk[64], const uint8_t adrs[32])` | 32 B | Secret-key address PRF `areion_soem256(K_sk, ADRS)` for `n = 32` |
| `areion_pq_slh_prf256x4` | `void areion_pq_slh_prf256x4(uint8_t out[4][32], const uint8_t k_sk[64], const uint8_t adrs[4][32])` | 4 × 32 B | 4-way parallel `areion_soem256x4` evaluation of `areion_pq_slh_prf256` across 4 distinct addresses |
| `areion_pq_slh_f128` | `void areion_pq_slh_f128(uint8_t out[16], const uint8_t pk_seed[16], const uint8_t k_pub[64], const uint8_t adrs[32], const uint8_t m1[16])` | 16 B | Category 1 tweakable chain hash `areion_dm512((PK.seed \|\| ADRS \|\| M_1) ⊕ K_pub)[0:16]` (`384`-bit clamped tweak capacity) |
| `areion_pq_slh_f256` | `void areion_pq_slh_f256(uint8_t out[32], const uint8_t k_pub[64], const uint8_t adrs[32], const uint8_t m1[32])` | 32 B | Profile I (`DM512-Clamped`) tweakable chain hash `areion_dm512((ADRS ⊕ K_pub1) \|\| (M_1 ⊕ K_pub2))` (`256`-bit clamped tweak capacity) |
| `areion_pq_slh_f_tem256` | `void areion_pq_slh_f_tem256(uint8_t out[32], const uint8_t k_pub[64], const uint8_t adrs[32], const uint8_t m1[32])` | 32 B | Profile II (`TEM-MiddleTweak`) tweakable chain hash `areion_tem_encrypt256(K_pub, M_1, ADRS) ⊕ M_1` |
| `areion_pq_slh_h128` | `void areion_pq_slh_h128(uint8_t out[16], const uint8_t pk_seed[16], const uint8_t k_pub[64], const uint8_t adrs[32], const uint8_t m1[16], const uint8_t m2[16])` | 16 B | Category 1 2-to-1 Merkle tree hash `areion_dm512((PK.seed \|\| ADRS_compact \|\| M_1 \|\| M_2) ⊕ K_pub)[0:16]` |
| `areion_pq_slh_h256` | `void areion_pq_slh_h256(uint8_t out[32], const uint8_t k_pub[64], const uint8_t adrs[32], const uint8_t m1[32], const uint8_t m2[32])` | 32 B | Category 5 2-step cascaded `areion_dm512` 2-to-1 Merkle tree hash `H(K_pub, ADRS, M_1 \|\| M_2)` |
| `areion_pq_slh_tl128` | `void areion_pq_slh_tl128(uint8_t out[16], const uint8_t k_pub[64], const uint8_t adrs[32], const uint8_t *blocks, size_t num_blocks)` | 16 B | Category 1 multi-block tweakable hash `T_l(K_pub, ADRS, blocks)` compressing `num_blocks` 16-byte `WOTS+` / `FORS` public-key blocks |
| `areion_pq_slh_tl256` | `void areion_pq_slh_tl256(uint8_t out[32], const uint8_t k_pub[64], const uint8_t adrs[32], const uint8_t *blocks, size_t num_blocks)` | 32 B | Category 5 multi-block tweakable hash `T_l(K_pub, ADRS, blocks)` compressing `num_blocks` 32-byte `WOTS+` / `FORS` public-key blocks |

#### 5.2 Key Generation, Signing, and Verification Entry Points

Pass `opt_rand = NULL` for deterministic signing or a random 16/32-byte buffer for hedged signing. Verification functions return `1` if valid and `0` if invalid.

| Function | C Prototype (`areion_pq.h`) | Seed / PK / SK | Signature | Profile & Security Category |
| :--- | :--- | :---: | :---: | :--- |
| `areion_pq_slhdsa_keygen128f` | `void areion_pq_slhdsa_keygen128f(uint8_t pk[32], uint8_t sk[64], const uint8_t seed[48])` | 48 / 32 / 64 B | — | FIPS 205 Cat 1 fast (`n=16, h=66, d=22, a=6, k=33`) |
| `areion_pq_slhdsa_sign128f` | `void areion_pq_slhdsa_sign128f(uint8_t sig[17088], const uint8_t sk[64], const uint8_t *msg, size_t msg_len, const uint8_t opt_rand[16])` | SK: 64 B | 17,088 B | FIPS 205 Cat 1 fast signing (`opt_rand = NULL` -> deterministic) |
| `areion_pq_slhdsa_verify128f` | `int areion_pq_slhdsa_verify128f(const uint8_t pk[32], const uint8_t *msg, size_t msg_len, const uint8_t sig[17088])` | PK: 32 B | 17,088 B | Constant-time root comparison |
| `areion_pq_slhdsa_keygen128s` | `void areion_pq_slhdsa_keygen128s(uint8_t pk[32], uint8_t sk[64], const uint8_t seed[48])` | 48 / 32 / 64 B | — | FIPS 205 Cat 1 small (`n=16, h=63, d=7, a=12, k=14`) |
| `areion_pq_slhdsa_sign128s` | `void areion_pq_slhdsa_sign128s(uint8_t sig[7856], const uint8_t sk[64], const uint8_t *msg, size_t msg_len, const uint8_t opt_rand[16])` | SK: 64 B | 7,856 B | FIPS 205 Cat 1 small signing (`opt_rand = NULL` -> deterministic) |
| `areion_pq_slhdsa_verify128s` | `int areion_pq_slhdsa_verify128s(const uint8_t pk[32], const uint8_t *msg, size_t msg_len, const uint8_t sig[7856])` | PK: 32 B | 7,856 B | Constant-time root comparison |
| `areion_pq_slhdsa_keygen256f` | `void areion_pq_slhdsa_keygen256f(uint8_t pk[64], uint8_t sk[128], const uint8_t seed[96])` | 96 / 64 / 128 B | — | FIPS 205 Cat 5 fast (`n=32, h=68, d=17, a=9, k=35`, Profile I `DM512-Clamped`) |
| `areion_pq_slhdsa_sign256f` | `void areion_pq_slhdsa_sign256f(uint8_t sig[49856], const uint8_t sk[128], const uint8_t *msg, size_t msg_len, const uint8_t opt_rand[32])` | SK: 128 B | 49,856 B | FIPS 205 Cat 5 fast signing (4-way `WOTS+` batched) |
| `areion_pq_slhdsa_verify256f` | `int areion_pq_slhdsa_verify256f(const uint8_t pk[64], const uint8_t *msg, size_t msg_len, const uint8_t sig[49856])` | PK: 64 B | 49,856 B | Constant-time root comparison |
| `areion_pq_slhdsa_keygen256s` | `void areion_pq_slhdsa_keygen256s(uint8_t pk[64], uint8_t sk[128], const uint8_t seed[96])` | 96 / 64 / 128 B | — | FIPS 205 Cat 5 small (`n=32, h=64, d=8, a=14, k=22`, Profile I `DM512-Clamped`) |
| `areion_pq_slhdsa_sign256s` | `void areion_pq_slhdsa_sign256s(uint8_t sig[29792], const uint8_t sk[128], const uint8_t *msg, size_t msg_len, const uint8_t opt_rand[32])` | SK: 128 B | 29,792 B | FIPS 205 Cat 5 small signing (4-way `WOTS+` batched) |
| `areion_pq_slhdsa_verify256s` | `int areion_pq_slhdsa_verify256s(const uint8_t pk[64], const uint8_t *msg, size_t msg_len, const uint8_t sig[29792])` | PK: 64 B | 29,792 B | Constant-time root comparison |
| `areion_pq_slhdsa_tem_keygen256f` | `void areion_pq_slhdsa_tem_keygen256f(uint8_t pk[64], uint8_t sk[128], const uint8_t seed[96])` | 96 / 64 / 128 B | — | FIPS 205 Cat 5 fast (`n=32, h=68, d=17, a=9, k=35`, Profile II `TEM-MiddleTweak`) |
| `areion_pq_slhdsa_tem_sign256f` | `void areion_pq_slhdsa_tem_sign256f(uint8_t sig[49856], const uint8_t sk[128], const uint8_t *msg, size_t msg_len, const uint8_t opt_rand[32])` | SK: 128 B | 49,856 B | FIPS 205 Cat 5 `TEM-MiddleTweak` signing |
| `areion_pq_slhdsa_tem_verify256f` | `int areion_pq_slhdsa_tem_verify256f(const uint8_t pk[64], const uint8_t *msg, size_t msg_len, const uint8_t sig[49856])` | PK: 64 B | 49,856 B | Constant-time root comparison |

---

### 6. Track 3: Areion-HPKE Key Derivation, Deterministic HPKE, and Areion-TEM2-SIV Wide-Block AEAD

Sponge-based key derivation (`areion_pq_kdf_expand`), 512-bit wide-block misuse-resistant authenticated encryption (`Areion-TEM2-SIV`) with `2^341.3` classical / `2^170.7` quantum BBB security, and deterministic HPKE DEM key derivation and sealing (`areion_pq_hpke_*`). All encryption/decryption functions support in-place operation (`ciphertext == plaintext`) and automatically zeroize the destination plaintext buffer if authentication fails.

| Function | C Prototype (`areion_pq.h`) | Key / Nonce / Tag | Description |
| :--- | :--- | :---: | :--- |
| `areion_pq_kdf_expand` | `void areion_pq_kdf_expand(uint8_t *dst, size_t dst_len, const uint8_t *secret, size_t secret_len, const uint8_t *context, size_t context_len)` | arbitrary → `dst_len` | Absorbs `secret` and `context` via a domain-separated `areion_dm512` sponge (`32 B` rate, `32 B` capacity) and expands pseudorandom output into `dst` using 4-way `areion_soem512x4` |
| `areion_pq_tem2_siv_encrypt` | `void areion_pq_tem2_siv_encrypt(uint8_t *ciphertext, uint8_t tag[32], const uint8_t key[128], const uint8_t nonce[32], const uint8_t *ad, size_t ad_len, const uint8_t *plaintext, size_t pt_len)` | 128 / 32 / 32 B | Computes 32-byte SIV `tag` over `(nonce, ad, plaintext)` via `areion_soem512x4` and encrypts `plaintext` into `ciphertext` (`ciphertext` may alias `plaintext`) via `areion_tem2_encrypt512x4` |
| `areion_pq_tem2_siv_decrypt` | `int areion_pq_tem2_siv_decrypt(uint8_t *plaintext, const uint8_t key[128], const uint8_t nonce[32], const uint8_t *ad, size_t ad_len, const uint8_t *ciphertext, size_t ct_len, const uint8_t tag[32])` | 128 / 32 / 32 B | Decrypts `ciphertext` into `plaintext` (`plaintext` may alias `ciphertext`) and verifies `tag` in constant time (`1` = valid, `0` = invalid); **zeroizes `plaintext[0..ct_len-1]` on failure** |
| `areion_pq_hpke_derive_keys` | `void areion_pq_hpke_derive_keys(uint8_t dem_key[128], uint8_t base_nonce[32], const uint8_t shared_secret[32], const uint8_t *info, size_t info_len)` | 32 B → 128 + 32 B | Derives a 128-byte `TEM2-SIV` DEM key and 32-byte base nonce from `shared_secret` and `info` via `areion_pq_kdf_expand` |
| `areion_pq_hpke_seal_det` | `void areion_pq_hpke_seal_det(uint8_t *ciphertext, uint8_t tag[32], const uint8_t shared_secret[32], const uint8_t *info, size_t info_len, uint64_t seq, const uint8_t *ad, size_t ad_len, const uint8_t *plaintext, size_t pt_len)` | 32 B + `seq` → CT + 32 B | Deterministically seals `plaintext` under `shared_secret`, `info`, and sequence number `seq` (`base_nonce ⊕ seq`) |
| `areion_pq_hpke_open_det` | `int areion_pq_hpke_open_det(uint8_t *plaintext, const uint8_t shared_secret[32], const uint8_t *info, size_t info_len, uint64_t seq, const uint8_t *ad, size_t ad_len, const uint8_t *ciphertext, size_t ct_len, const uint8_t tag[32])` | 32 B + `seq` → PT | Opens and authenticates a ciphertext produced by `areion_pq_hpke_seal_det` (`1` = valid, `0` = invalid; zeroizes `plaintext` on failure) |

---

### 7. Pre-C23 `_Generic` Multi-Dimensional `const` Array Macros

In ISO C99 / C11 / C17 (prior to C23 N2607), passing a non-`const` 2D array such as `uint8_t adrs[4][32]` to a parameter of type `const uint8_t adrs[4][32]` (which decays to `const uint8_t (*)[32]`) triggers a pedantic pointer-target qualifier warning under `-Wpedantic`.

To make calling `areion_pq_slh_prf256x4` warning-free under `-std=c99 -Wpedantic` and `-std=c11 -Wpedantic` without sacrificing type safety:
- [`areion_pq.h`](areion_pq.h) defines the function-like wrapper macro `areion_pq_slh_prf256x4(out, k_sk, adrs)` using `AREION_CONST_U8_32(adrs)` (which uses C11 `_Generic` when `__STDC_VERSION__ >= 201112L` to accept only `uint8_t (*)[32]` or `const uint8_t (*)[32]`).
- Taking the address of the function (`&areion_pq_slh_prf256x4`) or parenthesizing its name (`(areion_pq_slh_prf256x4)(...)`) bypasses the macro and references the underlying extern function symbol directly.

---

### 8. SUPERCOP (`eBACS`) and PQClean C99 Wrappers (`supercop/`, `pqclean/`)

#### 8.1 SUPERCOP (`eBACS`) C99 Wrappers (`supercop/`)

Standard SUPERCOP (`eBACS`) C99 `ref` wrappers (`api.h` + `sign.c` / `encrypt.c`) are provided in [`supercop/`](supercop/) across 11 directories (10 `crypto_sign` schemes and 1 `crypto_aead` scheme) and verified automatically by `make test`:

| SUPERCOP Directory | SUPERCOP Interface | Underlying `libareion_pq` Entry Points | Seed / PK / SK / Sig (or Key / Nonce / Tag) |
| :--- | :--- | :--- | :---: |
| `supercop/crypto_sign/faest_areion128s/ref/` | `crypto_sign` | `areion_pq_faest_{keygen,sign,verify}128s` | 32 / 48 / 64 / 6,448 B |
| `supercop/crypto_sign/faest_areion128f/ref/` | `crypto_sign` | `areion_pq_faest_{keygen,sign,verify}128f` | 32 / 48 / 64 / 7,456 B |
| `supercop/crypto_sign/faest_areion256s/ref/` | `crypto_sign` | `areion_pq_faest_{keygen,sign,verify}256s` | 64 / 64 / 96 / 18,208 B |
| `supercop/crypto_sign/faest_areion256f/ref/` | `crypto_sign` | `areion_pq_faest_{keygen,sign,verify}256f` | 64 / 64 / 96 / 20,512 B |
| `supercop/crypto_sign/faest_areion_em2_256s/ref/` | `crypto_sign` | `areion_pq_faest_em2_{keygen,sign,verify}256s` | 64 / 64 / 96 / 25,696 B |
| `supercop/crypto_sign/faest_areion_em2_256f/ref/` | `crypto_sign` | `areion_pq_faest_em2_{keygen,sign,verify}256f` | 64 / 64 / 96 / 30,368 B |
| `supercop/crypto_sign/slh_dsa_areion128f/ref/` | `crypto_sign` | `areion_pq_slhdsa_{keygen,sign,verify}128f` | 48 / 32 / 64 / 17,088 B |
| `supercop/crypto_sign/slh_dsa_areion128s/ref/` | `crypto_sign` | `areion_pq_slhdsa_{keygen,sign,verify}128s` | 48 / 32 / 64 / 7,856 B |
| `supercop/crypto_sign/slh_dsa_areion256f/ref/` | `crypto_sign` | `areion_pq_slhdsa_{keygen,sign,verify}256f` | 96 / 64 / 128 / 49,856 B |
| `supercop/crypto_sign/slh_dsa_areion256s/ref/` | `crypto_sign` | `areion_pq_slhdsa_{keygen,sign,verify}256s` | 96 / 64 / 128 / 29,792 B |
| `supercop/crypto_aead/areion_tem2_siv512/ref/` | `crypto_aead` | `areion_pq_tem2_siv_{encrypt,decrypt}` | Key: 128 B / Nonce: 32 B / Tag: 32 B |

Each `supercop/crypto_sign/<scheme>/ref/api.h` defines `CRYPTO_SECRETKEYBYTES`, `CRYPTO_PUBLICKEYBYTES`, `CRYPTO_BYTES`, `CRYPTO_SEEDBYTES`, `CRYPTO_VERSION` (`"0.1.0"`), and the 6 SUPERCOP C99 entry points (`0` on success, `-1` on verification failure):
```c
int crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk, const unsigned char *seed);
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
int crypto_sign_signature(unsigned char *sig, unsigned long long *siglen, const unsigned char *m, unsigned long long mlen, const unsigned char *sk);
int crypto_sign_verify(const unsigned char *sig, unsigned long long siglen, const unsigned char *m, unsigned long long mlen, const unsigned char *pk);
int crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m, unsigned long long mlen, const unsigned char *sk);
int crypto_sign_open(unsigned char *m, unsigned long long *mlen, const unsigned char *sm, unsigned long long smlen, const unsigned char *pk);
```
`supercop/crypto_aead/areion_tem2_siv512/ref/api.h` defines `CRYPTO_KEYBYTES` (`128`), `CRYPTO_NSECBYTES` (`0`), `CRYPTO_NPUBBYTES` (`32`), `CRYPTO_ABYTES` (`32`), `CRYPTO_NOOVERLAP` (`1`), `CRYPTO_VERSION` (`"0.1.0"`), and:
```c
int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen, const unsigned char *m, unsigned long long mlen, const unsigned char *ad, unsigned long long adlen, const unsigned char *nsec, const unsigned char *npub, const unsigned char *k);
int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen, unsigned char *nsec, const unsigned char *c, unsigned long long clen, const unsigned char *ad, unsigned long long adlen, const unsigned char *npub, const unsigned char *k);
```

#### 8.2 PQClean C99 Wrappers (`pqclean/`)

Standalone PQClean-compatible C99 `clean` packages (`api.h`, `sign.c`, `Makefile`) are provided in [`pqclean/`](pqclean/) for 4 signature schemes:

| PQClean Directory | Namespace Prefix (`<NS>`) | Alias Prefix (`<ALT_NS>`) | `CRYPTO_ALGNAME` | Seed / PK / SK / Sig |
| :--- | :--- | :--- | :--- | :---: |
| `pqclean/crypto_sign/faest-areion-128f/clean/` | `PQCLEAN_FAESTAREION128F_CLEAN` | `PQCLEAN_FAEST_AREION_128F_CLEAN` | `"FAEST-Areion-128f"` | 32 / 48 / 64 / 7,456 B |
| `pqclean/crypto_sign/faest-areion-256f/clean/` | `PQCLEAN_FAESTAREION256F_CLEAN` | `PQCLEAN_FAEST_AREION_256F_CLEAN` | `"FAEST-Areion-256f"` | 64 / 64 / 96 / 20,512 B |
| `pqclean/crypto_sign/slh-dsa-areion-128f/clean/` | `PQCLEAN_SLHDSAAREION128F_CLEAN` | `PQCLEAN_SLH_DSA_AREION_128F_CLEAN` | `"SLH-DSA-Areion-128f"` | 48 / 32 / 64 / 17,088 B |
| `pqclean/crypto_sign/slh-dsa-areion-256f/clean/` | `PQCLEAN_SLHDSAAREION256F_CLEAN` | `PQCLEAN_SLH_DSA_AREION_256F_CLEAN` | `"SLH-DSA-Areion-256f"` | 96 / 64 / 128 / 49,856 B |

Each `pqclean/crypto_sign/<scheme>/clean/api.h` exports both `<NS>_*` and `<ALT_NS>_*` macros (`_CRYPTO_SECRETKEYBYTES`, `_CRYPTO_PUBLICKEYBYTES`, `_CRYPTO_BYTES`, `_CRYPTO_SEEDBYTES`, `_CRYPTO_ALGNAME`) and 6 functions (`0` on success, `-1` on verification failure):
```c
int <NS>_crypto_sign_seed_keypair(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
int <NS>_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int <NS>_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
int <NS>_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
int <NS>_crypto_sign(uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen, const uint8_t *sk);
int <NS>_crypto_sign_open(uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen, const uint8_t *pk);
```

---

### 9. Zeroization, Stack Hygiene, and ABI Guarantees

All assembly kernels (`areion_pq_amd64.S`, `areion_pq_arm64.S`, `msvc/*.asm`) and C routines (`areion_pq_purec.c`, `cpu.c`) enforce strict post-call register, stack, and ABI hygiene:

1. **Zero-Spill Assembly Kernels:** Hardware kernels for `areion_pq_extract_witness256_{aesni,vex,arm64}`, `areion_pq_gf128_mul_{pclmul,vpclmul,pmull}`, `areion_pq_gf128_polymac_{pclmul,vpclmul,pmull}`, and `areion_pq_vole_xor_row_{sse2,avx2,avx512,neon}` execute with a zero-byte stack frame and zero intermediate stack spills.
2. **Vector & GPR Epilogue Scrubbing:** Every assembly kernel zeroes all touched SIMD vector registers (`PXOR` / `VPXOR` / `VPXORD` + `VZEROUPPER` on `x86-64`; `EOR` on `v0..v31` on `arm64`) and volatile scratch general-purpose registers (`XORQ` on `x86-64`; `MOV xN, xzr` on `arm64`) before `ret`.
3. **Software Stack & Buffer Scrubbing:** Composite C functions explicitly scrub local buffers via DSE-resistant `areion_pq_secure_wipe` (`volatile uint8_t *` + compiler memory barrier), scrub their 6,144-byte software stack frame (`areion_pq_wipe_software_stack`), and clobber volatile SIMD/GPR registers (`areion_pq_clobber_scratch_gprs`).
4. **Unverified Plaintext & Message Zeroization:** `areion_pq_tem2_siv_decrypt`, `areion_pq_hpke_open_det`, and all SUPERCOP / PQClean `crypto_sign_open` and `crypto_aead_decrypt` wrappers immediately wipe the output buffer to all-zeros whenever tag or signature verification fails.
5. **Cross-ABI, CET/BTI & Shared-Library Symbol Hygiene:** Assembly entry points emit Intel CET `endbr64` (`x86-64`) and ARMv8.5-A `bti c` (`arm64`) landing pads plus `.note.GNU-stack` and `.note.gnu.property` sections, preserve Windows x64 non-volatile registers (`rdi`, `rsi`, `rbx`, `rbp`, `r12..r15`, `xmm6..xmm15`), and keep all internal and `areion-c` base symbols hidden (`-fvisibility=hidden`) so `libareion_pq.so` exports strictly `areion_pq_*` symbols.

---

### 10. Usage Examples

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
