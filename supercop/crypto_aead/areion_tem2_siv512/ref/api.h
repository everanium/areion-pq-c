/*
 * Copyright (c) 2026 Andrey Kuvshinov
 *
 * Dual-licensed under Apache-2.0 OR MIT.
 * See LICENSE-APACHE and LICENSE-MIT for details.
 */

#ifndef SUPERCOP_CRYPTO_AEAD_AREION_TEM2_SIV512_API_H
#define SUPERCOP_CRYPTO_AEAD_AREION_TEM2_SIV512_API_H

#define CRYPTO_KEYBYTES  128
#define CRYPTO_NSECBYTES 0
#define CRYPTO_NPUBBYTES 32
#define CRYPTO_ABYTES    32
#define CRYPTO_NOOVERLAP 1
#define CRYPTO_VERSION   "0.2.0"

int crypto_aead_encrypt(
    unsigned char *c,
    unsigned long long *clen,
    const unsigned char *m,
    unsigned long long mlen,
    const unsigned char *ad,
    unsigned long long adlen,
    const unsigned char *nsec,
    const unsigned char *npub,
    const unsigned char *k);

int crypto_aead_decrypt(
    unsigned char *m,
    unsigned long long *mlen,
    unsigned char *nsec,
    const unsigned char *c,
    unsigned long long clen,
    const unsigned char *ad,
    unsigned long long adlen,
    const unsigned char *npub,
    const unsigned char *k);

#endif /* SUPERCOP_CRYPTO_AEAD_AREION_TEM2_SIV512_API_H */
