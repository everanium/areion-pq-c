/*
 * Copyright (c) 2026 Andrey Kuvshinov
 *
 * Dual-licensed under Apache-2.0 OR MIT.
 * See LICENSE-APACHE and LICENSE-MIT for details.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "api.h"
#include "../../../../areion_pq.h"

#if defined(PQCLEAN_HAS_RANDOMBYTES)
extern int randombytes(uint8_t *output, size_t n);
#endif

int PQCLEAN_SLHDSAAREION256F_CLEAN_crypto_sign_seed_keypair(
    uint8_t *pk, uint8_t *sk, const uint8_t *seed)
{
    areion_pq_slhdsa_keygen256f(pk, sk, seed);
    return 0;
}

int PQCLEAN_SLHDSAAREION256F_CLEAN_crypto_sign_keypair(
    uint8_t *pk, uint8_t *sk)
{
    uint8_t seed[PQCLEAN_SLHDSAAREION256F_CLEAN_CRYPTO_SEEDBYTES];
#if defined(PQCLEAN_HAS_RANDOMBYTES)
    (void)randombytes(seed, sizeof(seed));
#else
    memset(seed, 0, sizeof(seed));
#endif
    areion_pq_slhdsa_keygen256f(pk, sk, seed);
    areion_pq_zeroize(seed, sizeof(seed));
    return 0;
}

int PQCLEAN_SLHDSAAREION256F_CLEAN_crypto_sign_signature(
    uint8_t *sig, size_t *siglen,
    const uint8_t *m, size_t mlen, const uint8_t *sk)
{
    uint8_t opt_rand[32];
    memset(opt_rand, 0, sizeof(opt_rand));
    areion_pq_slhdsa_sign256f(sig, sk, m, mlen, opt_rand);
    *siglen = (size_t)PQCLEAN_SLHDSAAREION256F_CLEAN_CRYPTO_BYTES;
    return 0;
}

int PQCLEAN_SLHDSAAREION256F_CLEAN_crypto_sign_verify(
    const uint8_t *sig, size_t siglen,
    const uint8_t *m, size_t mlen, const uint8_t *pk)
{
    if (siglen != (size_t)PQCLEAN_SLHDSAAREION256F_CLEAN_CRYPTO_BYTES) {
        return -1;
    }
    return areion_pq_slhdsa_verify256f(pk, m, mlen, sig) == 1 ? 0 : -1;
}

int PQCLEAN_SLHDSAAREION256F_CLEAN_crypto_sign(
    uint8_t *sm, size_t *smlen,
    const uint8_t *m, size_t mlen, const uint8_t *sk)
{
    uint8_t opt_rand[32];
    size_t i;
    for (i = 0; i < mlen; i++) {
        sm[PQCLEAN_SLHDSAAREION256F_CLEAN_CRYPTO_BYTES + mlen - 1U - i] = m[mlen - 1U - i];
    }
    memset(opt_rand, 0, sizeof(opt_rand));
    areion_pq_slhdsa_sign256f(sm, sk, sm + PQCLEAN_SLHDSAAREION256F_CLEAN_CRYPTO_BYTES, mlen, opt_rand);
    *smlen = mlen + (size_t)PQCLEAN_SLHDSAAREION256F_CLEAN_CRYPTO_BYTES;
    return 0;
}

int PQCLEAN_SLHDSAAREION256F_CLEAN_crypto_sign_open(
    uint8_t *m, size_t *mlen,
    const uint8_t *sm, size_t smlen, const uint8_t *pk)
{
    size_t msg_len;
    size_t i;
    if (smlen < (size_t)PQCLEAN_SLHDSAAREION256F_CLEAN_CRYPTO_BYTES) {
        *mlen = 0;
        return -1;
    }
    msg_len = smlen - (size_t)PQCLEAN_SLHDSAAREION256F_CLEAN_CRYPTO_BYTES;
    if (areion_pq_slhdsa_verify256f(
            pk, sm + PQCLEAN_SLHDSAAREION256F_CLEAN_CRYPTO_BYTES, msg_len, sm) != 1) {
        memset(m, 0, msg_len);
        *mlen = 0;
        return -1;
    }
    for (i = 0; i < msg_len; i++) {
        m[i] = sm[PQCLEAN_SLHDSAAREION256F_CLEAN_CRYPTO_BYTES + i];
    }
    *mlen = msg_len;
    return 0;
}
