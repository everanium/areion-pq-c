/*
 * Copyright (c) 2026 Andrey Kuvshinov
 *
 * Dual-licensed under Apache-2.0 OR MIT.
 * See LICENSE-APACHE and LICENSE-MIT for details.
 */

#include <stddef.h>
#include <string.h>
#include "api.h"
#include "../../../../areion_pq.h"

#if defined(SUPERCOP_HAS_RANDOMBYTES)
extern void randombytes(unsigned char *x, unsigned long long xlen);
#endif

int crypto_sign_seed_keypair(
    unsigned char *pk,
    unsigned char *sk,
    const unsigned char *seed)
{
    areion_pq_faest_em2_keygen256f(pk, sk, seed);
    return 0;
}

int crypto_sign_keypair(
    unsigned char *pk,
    unsigned char *sk)
{
    unsigned char seed[CRYPTO_SEEDBYTES];
#if defined(SUPERCOP_HAS_RANDOMBYTES)
    randombytes(seed, (unsigned long long)sizeof(seed));
#else
    memset(seed, 0, sizeof(seed));
#endif
    areion_pq_faest_em2_keygen256f(pk, sk, seed);
    areion_pq_zeroize(seed, sizeof(seed));
    return 0;
}

int crypto_sign_signature(
    unsigned char *sig,
    unsigned long long *siglen,
    const unsigned char *m,
    unsigned long long mlen,
    const unsigned char *sk)
{
    unsigned char opt_rand[32];
    memset(opt_rand, 0, sizeof(opt_rand));
    areion_pq_faest_em2_sign256f(sig, sk, m, (size_t)mlen, opt_rand);
    *siglen = (unsigned long long)CRYPTO_BYTES;
    return 0;
}

int crypto_sign_verify(
    const unsigned char *sig,
    unsigned long long siglen,
    const unsigned char *m,
    unsigned long long mlen,
    const unsigned char *pk)
{
    if (siglen != (unsigned long long)CRYPTO_BYTES) {
        return -1;
    }
    return areion_pq_faest_em2_verify256f(pk, m, (size_t)mlen, sig) == 1 ? 0 : -1;
}

int crypto_sign(
    unsigned char *sm,
    unsigned long long *smlen,
    const unsigned char *m,
    unsigned long long mlen,
    const unsigned char *sk)
{
    unsigned char opt_rand[32];
    unsigned long long i;
    for (i = 0; i < mlen; i++) {
        sm[CRYPTO_BYTES + mlen - 1ULL - i] = m[mlen - 1ULL - i];
    }
    memset(opt_rand, 0, sizeof(opt_rand));
    areion_pq_faest_em2_sign256f(sm, sk, sm + CRYPTO_BYTES, (size_t)mlen, opt_rand);
    *smlen = mlen + (unsigned long long)CRYPTO_BYTES;
    return 0;
}

int crypto_sign_open(
    unsigned char *m,
    unsigned long long *mlen,
    const unsigned char *sm,
    unsigned long long smlen,
    const unsigned char *pk)
{
    unsigned long long msg_len;
    unsigned long long i;
    if (smlen < (unsigned long long)CRYPTO_BYTES) {
        *mlen = 0;
        return -1;
    }
    msg_len = smlen - (unsigned long long)CRYPTO_BYTES;
    if (areion_pq_faest_em2_verify256f(pk, sm + CRYPTO_BYTES, (size_t)msg_len, sm) != 1) {
        memset(m, 0, (size_t)msg_len);
        *mlen = 0;
        return -1;
    }
    for (i = 0; i < msg_len; i++) {
        m[i] = sm[CRYPTO_BYTES + i];
    }
    *mlen = msg_len;
    return 0;
}
