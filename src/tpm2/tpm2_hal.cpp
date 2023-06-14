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

  TPM2B_PUBLIC *outPublic = nullptr;
  TPM2B_CREATION_DATA *creationData = nullptr;
  TPM2B_DIGEST *creationHash = nullptr;
  TPMT_TK_CREATION *creationTicket = nullptr;

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

  r = Esys_TR_SetAuth(ctx, ESYS_TR_RH_ENDORSEMENT, &authValue);
  if (r != TSS2_RC_SUCCESS) {
    throw TPM2Exception("Could not authorize to ESYS_TR_RH_ENDORSEMENT.");
  }

  r = Esys_CreatePrimary(ctx, ESYS_TR_RH_ENDORSEMENT, ESYS_TR_PASSWORD,
                         ESYS_TR_NONE, ESYS_TR_NONE, &inSensitivePrimary,
                         &inPublic, &outsideInfo, &creationPCR, &primaryHandle,
                         &outPublic, nullptr, nullptr, nullptr);
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

  TPM2B_PUBLIC *outPublic = nullptr;
  TPM2B_PRIVATE *outPrivate = nullptr;
  TPM2B_CREATION_DATA *creationData = nullptr;
  TPM2B_DIGEST *creationHash = nullptr;
  TPMT_TK_CREATION *creationTicket = nullptr;

  TPM2B_AUTH authValuePrimary = {.size = 5, .buffer = {1, 2, 3, 4, 5}};

  r = Esys_TR_SetAuth(ctx, pPrimaryObject->getHandle(), &authValuePrimary);
  if (r != TSS2_RC_SUCCESS) {
    throw TPM2Exception("Could not authorize to provided primary object.");
  }

  TPM2B_AUTH authKey = {.size = 6, .buffer = {6, 7, 8, 9, 10, 11}};

  TPM2B_SENSITIVE_CREATE inSensitive = {
      .size = 0,
      .sensitive = {.userAuth = {.size = 0, .buffer = {0}},
                    .data = {.size = 0, .buffer = {}}}};

  inSensitive.sensitive.userAuth = authKey;

  TPM2B_PUBLIC inPublic = kPrimaryDefaultRSA;
  TPM2B_DATA outsideInfo = {
      .size = 0,
      .buffer = {},
  };

  TPML_PCR_SELECTION creationPCR = {
      .count = 0,
  };

  r = Esys_Create(ctx, pPrimaryObject->getHandle(), ESYS_TR_PASSWORD,
                  ESYS_TR_NONE, ESYS_TR_NONE, &inSensitive, &inPublic,
                  &outsideInfo, &creationPCR, &outPrivate, &outPublic, nullptr,
                  nullptr, nullptr);
  if (r != TSS2_RC_SUCCESS) {
    throw TPM2Exception("Could not create key.");
  }

  std::array<std::byte, 256> publicKey;
  std::array<std::byte, 228> ecnryptedPrivateKey;
  memcpy(std::begin(publicKey), outPublic->publicArea.unique.rsa.buffer, 256);
  memcpy(std::begin(ecnryptedPrivateKey), outPrivate->buffer, 228);
  return std::make_unique<CryptKey>(pPrimaryObject->getHandle(), publicKey,
                                    ecnryptedPrivateKey);
};

std::vector<std::byte> TPM2_HAL::encrypt(std::unique_ptr<CryptKey> pKey) {
  TSS2_RC r;
  TPM2B_MAX_BUFFER *outData = nullptr;

  TPM2B_AUTH authKey = {.size = 6, .buffer = {6, 7, 8, 9, 10, 11}};
  TPM2B_MAX_BUFFER inData = {
      .size = 32,
      .buffer = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}};

  TPMI_YES_NO encrypt = TPM2_NO;
  TPMI_ALG_CIPHER_MODE mode = TPM2_ALG_NULL;

  TPM2B_PUBLIC inPublicECC = kPrimaryDefaultRSA;
  inPublicECC.publicArea.unique.rsa.size = pKey->getPublicKey().size();
  memcpy(inPublicECC.publicArea.unique.rsa.buffer,
         std::begin(pKey->getPublicKey()), pKey->getPublicKey().size());
  TPM2B_PRIVATE inPrivateRSA;
  inPrivateRSA.size = pKey->getEncryptedPrivateKey().size();
  memcpy(inPrivateRSA.buffer, std::begin(pKey->getEncryptedPrivateKey()),
         pKey->getEncryptedPrivateKey().size());

  ESYS_TR loadedKeyHandle = ESYS_TR_NONE;
  r = Esys_Load(ctx, pKey->getParentHandle(), ESYS_TR_PASSWORD, ESYS_TR_NONE,
                ESYS_TR_NONE, &inPrivateRSA, &inPublicECC, &loadedKeyHandle);
  if (r != TSS2_RC_SUCCESS) {
    throw TPM2Exception("Could not load provided key");
  }

  r = Esys_TR_SetAuth(ctx, loadedKeyHandle, &authKey);
  if (r != TSS2_RC_SUCCESS) {
    throw TPM2Exception("Could not authorize to provided key.");
  }

  r = Esys_EncryptDecrypt2(ctx, loadedKeyHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                           ESYS_TR_NONE, &inData, encrypt, mode, nullptr,
                           &outData, nullptr);
  if (r != TSS2_RC_SUCCESS) {
    throw TPM2Exception("Could not encrypt data with provided key");
  }

  return std::vector<std::byte>();
}
};  // namespace Moria