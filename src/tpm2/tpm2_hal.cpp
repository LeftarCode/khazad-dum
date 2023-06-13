#include "tpm2/tpm2_hal.h"

#include <cstring>
#include <iostream>

#include "utils/tpm2_exception.h"
#define UNUSED(x) (void)(x)

#pragma GCC diagnostic ignored "-Wmissing-field-initializers"

namespace Moria {
TPM2_HAL::TPM2_HAL() {
  TSS2_RC r;

  r = Esys_Initialize(&ctx, NULL, NULL);
  if (r != TSS2_RC_SUCCESS) {
    throw TPM2Exception("Could not initialize TPM2 ESYS");
  }
}

std::unique_ptr<CryptKey> TPM2_HAL::createPrimaryKey() {
  TSS2_RC r;
  ESYS_TR objectHandle = ESYS_TR_NONE;
  ESYS_TR session = ESYS_TR_NONE;
  TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_NULL};

  TPM2B_PUBLIC *outPublic = NULL;
  TPM2B_CREATION_DATA *creationData = NULL;
  TPM2B_DIGEST *creationHash = NULL;
  TPMT_TK_CREATION *creationTicket = NULL;

  r = Esys_StartAuthSession(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                            ESYS_TR_NONE, ESYS_TR_NONE, NULL, TPM2_SE_HMAC,
                            &symmetric, TPM2_ALG_SHA256, &session);
  if (r != TSS2_RC_SUCCESS) {
    throw TPM2Exception("Could not start auth session");
  }

  TPM2B_SENSITIVE_CREATE inSensitive = {
      .size = 0,
      .sensitive = {.userAuth =
                        {
                            .size = 0,
                            .buffer = {0},
                        },
                    .data = {.size = 0, .buffer = {0}}}};

  TPM2B_PUBLIC inPublicECC = {
      .size = 0,
      .publicArea = {
          .type = TPM2_ALG_ECC,
          .nameAlg = TPM2_ALG_SHA256,
          .objectAttributes =
              (TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_RESTRICTED |
               TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_FIXEDTPM |
               TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN),
          .authPolicy = {.size = 0, .buffer = {}},
          .parameters = {.eccDetail = {.symmetric =
                                           {
                                               .algorithm = TPM2_ALG_NULL,
                                               .keyBits = {.aes = 128},
                                               .mode = {.aes = TPM2_ALG_CFB},
                                           },
                                       .scheme =
                                           {
                                               .scheme = TPM2_ALG_ECDSA,
                                               .details = {.ecdsa = {.hashAlg =
                                                                         TPM2_ALG_SHA256}}},
                                       .curveID = TPM2_ECC_NIST_P256,
                                       .kdf =
                                           {.scheme = TPM2_ALG_NULL,
                                            .details = {}}}},
          .unique = {.ecc = {.x = {.size = 0, .buffer = {}},
                             .y = {.size = 0, .buffer = {}}}},
      }};
  TPM2B_DATA outsideInfo = {.size = 0, .buffer = {}};

  TPML_PCR_SELECTION creationPCR = {.count = 0};

  TPM2B_AUTH authValue = {.size = 0, .buffer = {}};

  r = Esys_TR_SetAuth(ctx, ESYS_TR_RH_OWNER, &authValue);
  if (r != TSS2_RC_SUCCESS) {
    throw TPM2Exception("Could not authorize to ESYS_TR_RH_OWNER");
  }

  r = Esys_CreatePrimary(ctx, ESYS_TR_RH_OWNER, session, ESYS_TR_NONE,
                         ESYS_TR_NONE, &inSensitive, &inPublicECC, &outsideInfo,
                         &creationPCR, &objectHandle, &outPublic, &creationData,
                         &creationHash, &creationTicket);
  if (r != TSS2_RC_SUCCESS) {
    throw TPM2Exception("Could not create primary key");
  }

  std::array<std::byte, 32> x;
  std::array<std::byte, 32> y;
  memcpy(std::begin(x), outPublic->publicArea.unique.ecc.x.buffer, 32);
  memcpy(std::begin(y), outPublic->publicArea.unique.ecc.y.buffer, 32);
  return std::make_unique<CryptKey>(x, y);
};
};  // namespace Moria