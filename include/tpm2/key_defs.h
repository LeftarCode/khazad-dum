#pragma once
#include <tss2/tss2_esys.h>

namespace Moria {
const TPM2B_PUBLIC kPrimaryDefaultEcc =
    {.size = 0,
     .publicArea = {
         .type = TPM2_ALG_ECC,
         .nameAlg = TPM2_ALG_SHA256,
         .objectAttributes = (TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_DECRYPT |
                              TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                              TPMA_OBJECT_SENSITIVEDATAORIGIN),
         .authPolicy = {.size = 0, .buffer = {}},
         .parameters = {.eccDetail =
                            {.symmetric =
                                 {
                                     .algorithm = TPM2_ALG_NULL,
                                     .keyBits = {.aes = 128},
                                     .mode = {.aes = TPM2_ALG_CFB},
                                 },
                             .scheme =
                                 {
                                     .scheme = TPM2_ALG_ECDH,
                                     .details = {.ecdh = {.hashAlg = TPM2_ALG_SHA256}},
                                 },
                             .curveID = TPM2_ECC_NIST_P256,
                             .kdf = {.scheme = TPM2_ALG_NULL, .details = {}}}},
         .unique = {.ecc = {.x = {.size = 0, .buffer = {}},
                            .y = {.size = 0, .buffer = {}}}},
     }};

const TPM2B_PUBLIC kPrimaryDefaultSeal = {
    .size = 0,
    .publicArea = {
        .type = TPM2_ALG_KEYEDHASH,
        .nameAlg = TPM2_ALG_SHA256,
        .objectAttributes = (TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT),
        .authPolicy = {.size = 0, .buffer = {}},
        .parameters = {.keyedHashDetail = {.scheme = TPM2_ALG_NULL}},
        .unique = {.keyedHash = {.size = 32}},
    }};

const TPM2B_PUBLIC kPrimaryDefaultRSA = {
    .size = 0,
    .publicArea =
        {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes =
                (TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_RESTRICTED |
                 TPMA_OBJECT_DECRYPT | TPMA_OBJECT_FIXEDTPM |
                 TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy =
                {
                    .size = 0,
                },
            .parameters = {.rsaDetail =
                               {
                                   .symmetric = {.algorithm = TPM2_ALG_AES,
                                                 .keyBits = {.aes = 128},
                                                 .mode = {.aes = TPM2_ALG_CFB}},
                                   .scheme = {.scheme = TPM2_ALG_NULL},
                                   .keyBits = 2048,
                                   .exponent = 0,
                               }},
            .unique = {.rsa =
                           {
                               .size = 0,
                               .buffer = {},
                           }},
        },
};

const TPM2B_PUBLIC kKeyDefaultRSA = {
    .size = 0,
    .publicArea =
        {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes =
                (TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_DECRYPT |
                 TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy =
                {
                    .size = 0,
                },
            .parameters = {.rsaDetail =
                               {
                                   .symmetric = {.algorithm = TPM2_ALG_NULL},
                                   .scheme = {.scheme = TPM2_ALG_RSAES},
                                   .keyBits = 2048,
                                   .exponent = 0,
                               }},
            .unique = {.rsa =
                           {
                               .size = 0,
                               .buffer = {},
                           }},
        },
};

};  // namespace Moria