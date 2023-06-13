#pragma once
#include <tss2/tss2_esys.h>

namespace Moria {
const TPM2B_PUBLIC kDefaultEcc =
    {.size = 0,
     .publicArea = {
         .type = TPM2_ALG_ECC,
         .nameAlg = TPM2_ALG_SHA256,
         .objectAttributes =
             (TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_RESTRICTED |
              TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_FIXEDTPM |
              TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN),
         .authPolicy = {.size = 0, .buffer = {}},
         .parameters = {.eccDetail =
                            {.symmetric =
                                 {
                                     .algorithm = TPM2_ALG_NULL,
                                     .keyBits = {.aes = 128},
                                     .mode = {.aes = TPM2_ALG_CFB},
                                 },
                             .scheme = {.scheme = TPM2_ALG_ECDSA,
                                        .details = {.ecdsa = {.hashAlg = TPM2_ALG_SHA256}}},
                             .curveID = TPM2_ECC_NIST_P256,
                             .kdf = {.scheme = TPM2_ALG_NULL, .details = {}}}},
         .unique = {.ecc = {.x = {.size = 0, .buffer = {}},
                            .y = {.size = 0, .buffer = {}}}},
     }};
};