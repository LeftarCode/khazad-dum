#include "tpm2/tpm2_hal.h"

#include <cstring>
#include <iostream>

#include "tpm2/key_defs.h"
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

  // TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_NULL};
  // r = Esys_StartAuthSession(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
  //                           ESYS_TR_NONE, ESYS_TR_NONE, NULL, TPM2_SE_HMAC,
  //                           &symmetric, TPM2_ALG_SHA256, &session);
  // if (r != TSS2_RC_SUCCESS) {
  //   throw TPM2Exception("Could not start auth session");
  // }
}

std::unique_ptr<PrimaryObject> TPM2_HAL::createPrimaryObject() {
  TSS2_RC r;
  ESYS_TR primaryHandle = ESYS_TR_NONE;

  TPM2B_PUBLIC *outPublic = NULL;
  TPM2B_CREATION_DATA *creationData = NULL;
  TPM2B_DIGEST *creationHash = NULL;
  TPMT_TK_CREATION *creationTicket = NULL;

  TPM2B_AUTH authValuePrimary = {.size = 5, .buffer = {1, 2, 3, 4, 5}};

  TPM2B_SENSITIVE_CREATE inSensitivePrimary = {
      .size = 0,
      .sensitive =
          {
              .userAuth =
                  {
                      .size = 0,
                      .buffer = {0},
                  },
              .data =
                  {
                      .size = 0,
                      .buffer = {0},
                  },
          },
  };

  inSensitivePrimary.sensitive.userAuth = authValuePrimary;

  TPM2B_PUBLIC inPublic = kPrimaryDefaultRSA;

  TPM2B_DATA outsideInfo = {
      .size = 0,
      .buffer = {},
  };

  TPML_PCR_SELECTION creationPCR = {
      .count = 0,
  };

  TPM2B_AUTH authValue = {.size = 0, .buffer = {}};

  r = Esys_TR_SetAuth(ctx, ESYS_TR_RH_OWNER, &authValue);
  if (r != TSS2_RC_SUCCESS) {
    throw TPM2Exception("Could not authorize to ESYS_TR_RH_OWNER.");
  }

  r = Esys_CreatePrimary(ctx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                         ESYS_TR_NONE, &inSensitivePrimary, &inPublic,
                         &outsideInfo, &creationPCR, &primaryHandle, &outPublic,
                         NULL, NULL, NULL);
  if (r != TSS2_RC_SUCCESS) {
    throw TPM2Exception("Could not create primary object.");
  }

  std::array<std::byte, 256> key;
  memcpy(std::begin(key), outPublic->publicArea.unique.rsa.buffer, 256);
  return std::make_unique<PrimaryObject>(primaryHandle, key);
};

std::unique_ptr<CryptKey> TPM2_HAL::createKey(
    std::unique_ptr<PrimaryObject> pPrimaryObject) {
  TSS2_RC r;

  TPM2B_PUBLIC *outPublic2 = NULL;
  TPM2B_PRIVATE *outPrivate2 = NULL;
  TPM2B_CREATION_DATA *creationData2 = NULL;
  TPM2B_DIGEST *creationHash2 = NULL;
  TPMT_TK_CREATION *creationTicket2 = NULL;

  TPM2B_AUTH authValuePrimary = {.size = 5, .buffer = {1, 2, 3, 4, 5}};

  r = Esys_TR_SetAuth(ctx, pPrimaryObject->getHandle(), &authValuePrimary);
  if (r != TSS2_RC_SUCCESS) {
    throw TPM2Exception("Could not authorize to provided primary object.");
  }

  TPM2B_AUTH authKey2 = {.size = 6, .buffer = {6, 7, 8, 9, 10, 11}};

  TPM2B_SENSITIVE_CREATE inSensitive2 = {
      .size = 0,
      .sensitive = {.userAuth = {.size = 0, .buffer = {0}},
                    .data = {.size = 0, .buffer = {}}}};

  inSensitive2.sensitive.userAuth = authKey2;

  TPM2B_PUBLIC inPublic2 = kPrimaryDefaultEcc;
  TPM2B_DATA outsideInfo2 = {
      .size = 0,
      .buffer = {},
  };

  TPML_PCR_SELECTION creationPCR2 = {
      .count = 0,
  };

  r = Esys_Create(ctx, pPrimaryObject->getHandle(), ESYS_TR_PASSWORD,
                  ESYS_TR_NONE, ESYS_TR_NONE, &inSensitive2, &inPublic2,
                  &outsideInfo2, &creationPCR2, &outPrivate2, &outPublic2,
                  &creationData2, &creationHash2, &creationTicket2);
  if (r != TSS2_RC_SUCCESS) {
    throw TPM2Exception("Cloud not create key.");
  }

  std::array<std::byte, 32> x;
  std::array<std::byte, 32> y;
  memcpy(std::begin(x), outPublic2->publicArea.unique.ecc.x.buffer, 32);
  memcpy(std::begin(y), outPublic2->publicArea.unique.ecc.y.buffer, 32);
  return std::make_unique<CryptKey>(1, x, y);
};

std::vector<std::byte> TPM2_HAL::encrypt(std::unique_ptr<PrimaryObject> pKey) {
  TSS2_RC r;
  TPM2B_MAX_BUFFER *outData = NULL;
  TPM2B_IV *ivOut = NULL;

  TPM2B_IV ivIn = {.size = 16,
                   .buffer = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 16}};

  TPM2B_MAX_BUFFER inData = {
      .size = 16, .buffer = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 16}};

  TPMI_YES_NO decrypt = TPM2_YES;
  TPMI_YES_NO encrypt = TPM2_NO;
  TPMI_ALG_CIPHER_MODE mode = TPM2_ALG_NULL;

  TPM2B_PUBLIC inPublicECC = kPrimaryDefaultEcc;

  ESYS_TR loadedKeyHandle = ESYS_TR_NONE;
  r = Esys_Load(ctx, pKey->getHandle(), ESYS_TR_PASSWORD, ESYS_TR_NONE,
                ESYS_TR_NONE, NULL, &inPublicECC, &loadedKeyHandle);
  if (r != TSS2_RC_SUCCESS) {
    throw TPM2Exception("Could not load provided key");
  }
  // r = Esys_EncryptDecrypt(ctx, pKey->getHandle(), ESYS_TR_PASSWORD,
  //                         ESYS_TR_NONE, ESYS_TR_NONE, encrypt, mode, &ivIn,
  //                         &inData, &outData, &ivOut);
  return std::vector<std::byte>();
}
};  // namespace Moria