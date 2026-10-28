/*
 * Copyright (c) 2026 Andrey Kuvshinov
 *
 * Dual-licensed under Apache-2.0 OR MIT.
 * See LICENSE-APACHE and LICENSE-MIT for details.
 */

#ifndef PQCLEAN_SLHDSAAREION128F_CLEAN_API_H
#define PQCLEAN_SLHDSAAREION128F_CLEAN_API_H

#include <stddef.h>
#include <stdint.h>

#define PQCLEAN_SLHDSAAREION128F_CLEAN_CRYPTO_SECRETKEYBYTES 64
#define PQCLEAN_SLHDSAAREION128F_CLEAN_CRYPTO_PUBLICKEYBYTES 32
#define PQCLEAN_SLHDSAAREION128F_CLEAN_CRYPTO_BYTES          17088
#define PQCLEAN_SLHDSAAREION128F_CLEAN_CRYPTO_SEEDBYTES      48
#define PQCLEAN_SLHDSAAREION128F_CLEAN_CRYPTO_ALGNAME        "SLH-DSA-Areion-128f"

#define PQCLEAN_SLH_DSA_AREION_128F_CLEAN_CRYPTO_SECRETKEYBYTES PQCLEAN_SLHDSAAREION128F_CLEAN_CRYPTO_SECRETKEYBYTES
#define PQCLEAN_SLH_DSA_AREION_128F_CLEAN_CRYPTO_PUBLICKEYBYTES PQCLEAN_SLHDSAAREION128F_CLEAN_CRYPTO_PUBLICKEYBYTES
#define PQCLEAN_SLH_DSA_AREION_128F_CLEAN_CRYPTO_BYTES          PQCLEAN_SLHDSAAREION128F_CLEAN_CRYPTO_BYTES
#define PQCLEAN_SLH_DSA_AREION_128F_CLEAN_CRYPTO_SEEDBYTES      PQCLEAN_SLHDSAAREION128F_CLEAN_CRYPTO_SEEDBYTES
#define PQCLEAN_SLH_DSA_AREION_128F_CLEAN_CRYPTO_ALGNAME        PQCLEAN_SLHDSAAREION128F_CLEAN_CRYPTO_ALGNAME

int PQCLEAN_SLHDSAAREION128F_CLEAN_crypto_sign_seed_keypair(
    uint8_t *pk, uint8_t *sk, const uint8_t *seed);

int PQCLEAN_SLHDSAAREION128F_CLEAN_crypto_sign_keypair(
    uint8_t *pk, uint8_t *sk);

int PQCLEAN_SLHDSAAREION128F_CLEAN_crypto_sign_signature(
    uint8_t *sig, size_t *siglen,
    const uint8_t *m, size_t mlen, const uint8_t *sk);

int PQCLEAN_SLHDSAAREION128F_CLEAN_crypto_sign_verify(
    const uint8_t *sig, size_t siglen,
    const uint8_t *m, size_t mlen, const uint8_t *pk);

int PQCLEAN_SLHDSAAREION128F_CLEAN_crypto_sign(
    uint8_t *sm, size_t *smlen,
    const uint8_t *m, size_t mlen, const uint8_t *sk);

int PQCLEAN_SLHDSAAREION128F_CLEAN_crypto_sign_open(
    uint8_t *m, size_t *mlen,
    const uint8_t *sm, size_t smlen, const uint8_t *pk);

#define PQCLEAN_SLH_DSA_AREION_128F_CLEAN_crypto_sign_seed_keypair PQCLEAN_SLHDSAAREION128F_CLEAN_crypto_sign_seed_keypair
#define PQCLEAN_SLH_DSA_AREION_128F_CLEAN_crypto_sign_keypair      PQCLEAN_SLHDSAAREION128F_CLEAN_crypto_sign_keypair
#define PQCLEAN_SLH_DSA_AREION_128F_CLEAN_crypto_sign_signature    PQCLEAN_SLHDSAAREION128F_CLEAN_crypto_sign_signature
#define PQCLEAN_SLH_DSA_AREION_128F_CLEAN_crypto_sign_verify       PQCLEAN_SLHDSAAREION128F_CLEAN_crypto_sign_verify
#define PQCLEAN_SLH_DSA_AREION_128F_CLEAN_crypto_sign              PQCLEAN_SLHDSAAREION128F_CLEAN_crypto_sign
#define PQCLEAN_SLH_DSA_AREION_128F_CLEAN_crypto_sign_open         PQCLEAN_SLHDSAAREION128F_CLEAN_crypto_sign_open

#endif /* PQCLEAN_SLHDSAAREION128F_CLEAN_API_H */
