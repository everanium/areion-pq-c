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

int crypto_aead_encrypt(
    unsigned char *c,
    unsigned long long *clen,
    const unsigned char *m,
    unsigned long long mlen,
    const unsigned char *ad,
    unsigned long long adlen,
    const unsigned char *nsec,
    const unsigned char *npub,
    const unsigned char *k)
{
    unsigned char tag[CRYPTO_ABYTES];
    (void)nsec;
    areion_pq_tem2_siv_encrypt(c, tag, k, npub, ad, (size_t)adlen, m, (size_t)mlen);
    memcpy(c + (size_t)mlen, tag, (size_t)CRYPTO_ABYTES);
    areion_pq_zeroize(tag, sizeof(tag));
    if (clen != NULL) {
        *clen = mlen + (unsigned long long)CRYPTO_ABYTES;
    }
    return 0;
}

int crypto_aead_decrypt(
    unsigned char *m,
    unsigned long long *mlen,
    unsigned char *nsec,
    const unsigned char *c,
    unsigned long long clen,
    const unsigned char *ad,
    unsigned long long adlen,
    const unsigned char *npub,
    const unsigned char *k)
{
    unsigned long long pt_len;
    (void)nsec;
    if (clen < (unsigned long long)CRYPTO_ABYTES) {
        if (mlen != NULL) {
            *mlen = 0ULL;
        }
        return -1;
    }
    pt_len = clen - (unsigned long long)CRYPTO_ABYTES;
    if (!areion_pq_tem2_siv_decrypt(m, k, npub, ad, (size_t)adlen, c, (size_t)pt_len, c + (size_t)pt_len)) {
        if (mlen != NULL) {
            *mlen = 0ULL;
        }
        return -1;
    }
    if (mlen != NULL) {
        *mlen = pt_len;
    }
    return 0;
}
