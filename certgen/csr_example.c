/* csr_example.c
 *
 * Copyright (C) 2006-2019 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/*
 * Example of parsing a DER-encoded certificate and extracting
 * public key and subject name information.
 *
 */

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/ed25519.h>

#define MAX_TEMP_SIZE 1024

int main(void)
{
    int ret;
    ed25519_key key;
    WC_RNG rng;
    Cert req;
    byte der[MAX_TEMP_SIZE], pem[MAX_TEMP_SIZE];
    int  derSz, pemSz;
    word32 ed25519_key_sz = 32;
    byte ed25519_der[ed25519_key_sz+2];



    ret = wc_ed25519_init(&key);
    if (ret != 0) {
        printf("ECC init key failed: %d\n", ret);
        goto exit;
    }

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("Init rng failed: %d\n", ret);
        goto exit;
    }

    ret = wc_ed25519_make_key(&rng, 32, &key);
    if (ret != 0) {
        printf("ECC make key failed: %d\n", ret);
        goto exit;
    }

    ret = wc_ed25519_export_public(&key, ed25519_der+2, &ed25519_key_sz);
    ed25519_der[0] = 0x30;
    ed25519_der[1] = 0x2e;

    if (ret != 0) {
        printf("Export key failed\n: %d\n", ret);
        goto exit;
    }
#if 0
    printf("Exported pubkey %i bytes\n", ed25519_der_sz);

    memset(pem, 0, sizeof(pem));
    ret = wc_DerToPem(der, 34, pem, sizeof(pem), ED25519_TYPE);
    if (ret <= 0) {
        printf("DER to PEM failed: %d\n", ret);
        goto exit;
    }
    pemSz = ret;
    printf("%s (%d)", pem, pemSz);
#endif

    ret = wc_InitCert(&req);
    if (ret != 0) {
        printf("Init Cert failed: %d\n", ret);
        goto exit;
    }
    strncpy(req.subject.country, "US", CTC_NAME_SIZE);
    strncpy(req.subject.state, "OR", CTC_NAME_SIZE);
    strncpy(req.subject.locality, "Portland", CTC_NAME_SIZE);
    strncpy(req.subject.org, "wolfSSL", CTC_NAME_SIZE);
    strncpy(req.subject.unit, "Development", CTC_NAME_SIZE);
    strncpy(req.subject.commonName, "www.wolfssl.com", CTC_NAME_SIZE);
    strncpy(req.subject.email, "info@wolfssl.com", CTC_NAME_SIZE);
    ret = wc_MakeCertReq_ex(&req, der, sizeof(der), ED25519_TYPE, &key);
    if (ret <= 0) {
        printf("Make Cert Req failed: %d\n", ret);
        goto exit;
    }
    derSz = ret;

    req.sigType = CTC_ED25519;
    ret = wc_SignCert_ex(req.bodySz, req.sigType, der, sizeof(der), ED25519_TYPE, &key, &rng);
    if (ret <= 0) {
        printf("Sign Cert failed: %d\n", ret);
        goto exit;
    }
    derSz = ret;

    memset(pem, 0, sizeof(pem));
    ret = wc_DerToPem(der, derSz, pem, sizeof(pem), CERTREQ_TYPE);
    if (ret <= 0) {
        printf("DER to PEM failed: %d\n", ret);
        goto exit;
    }
    pemSz = ret;
    printf("%s\n", pem);

exit:
    wc_ed25519_free(&key);
    wc_FreeRng(&rng);

    return ret;
}
