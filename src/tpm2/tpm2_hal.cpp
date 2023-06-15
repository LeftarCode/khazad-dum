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

  Esys_Free(outPublic);

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

  TPM2B_PUBLIC inPublic = kKeyDefaultRSA;
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
  std::array<std::byte, 196> encryptedPrivateKey;
  memcpy(std::begin(publicKey), outPublic->publicArea.unique.rsa.buffer, 256);
  memcpy(std::begin(encryptedPrivateKey), outPrivate->buffer, 196);

  Esys_Free(outPublic);
  Esys_Free(creationData);
  Esys_Free(creationHash);
  Esys_Free(creationTicket);

  return std::make_unique<CryptKey>(pPrimaryObject->getHandle(), publicKey,
                                    encryptedPrivateKey);
};

std::vector<std::byte> TPM2_HAL::encrypt(
    const std::unique_ptr<CryptKey> &pKey) {
  TSS2_RC r;

  TPM2B_PUBLIC *outPublic = NULL;
  TPM2B_PUBLIC_KEY_RSA *cipher = NULL;

  TPM2B_AUTH authKey = {.size = 6, .buffer = {6, 7, 8, 9, 10, 11}};

  TPM2B_PUBLIC inPublic = kPrimaryDefaultRSA;

  TPM2B_DATA outsideInfo = {
      .size = 0,
      .buffer = {},
  };

  TPML_PCR_SELECTION creationPCR = {
      .count = 0,
  };

  TPM2B_PUBLIC inPublic2 = kKeyDefaultRSA;
  inPublic2.publicArea.unique.rsa.size = pKey->getPublicKey().size();
  memcpy(inPublic2.publicArea.unique.rsa.buffer,
         std::begin(pKey->getPublicKey()), pKey->getPublicKey().size());
  TPM2B_PRIVATE inPrivateRSA;
  inPrivateRSA.size = pKey->getEncryptedPrivateKey().size();
  memcpy(inPrivateRSA.buffer, std::begin(pKey->getEncryptedPrivateKey()),
         pKey->getEncryptedPrivateKey().size());

  ESYS_TR loadedKeyHandle = ESYS_TR_NONE;
  r = Esys_Load(ctx, pKey->getParentHandle(), ESYS_TR_PASSWORD, ESYS_TR_NONE,
                ESYS_TR_NONE, &inPrivateRSA, &inPublic2, &loadedKeyHandle);
  if (r != TSS2_RC_SUCCESS) {
    throw TPM2Exception("Could not load provided key");
  }

  r = Esys_TR_SetAuth(ctx, loadedKeyHandle, &authKey);
  if (r != TSS2_RC_SUCCESS) {
    throw TPM2Exception("Could not authorize to provieded key");
  }

  size_t plain_size = 3;
  TPM2B_PUBLIC_KEY_RSA plain = {.size = plain_size, .buffer = {1, 2, 3}};
  TPMT_RSA_DECRYPT scheme;
  scheme.scheme = TPM2_ALG_RSAES;

  r = Esys_RSA_Encrypt(ctx, loadedKeyHandle, ESYS_TR_NONE, ESYS_TR_NONE,
                       ESYS_TR_NONE, &plain, &scheme, nullptr, &cipher);
  if (r != TSS2_RC_SUCCESS) {
    throw TPM2Exception("Could not encrypt data using provieded key");
  }

  std::vector<std::byte> ciphertext;
  ciphertext.resize(cipher->size);
  memcpy(ciphertext.data(), cipher->buffer, cipher->size);
  return ciphertext;
}

std::vector<std::byte> TPM2_HAL::decrypt(
    const std::unique_ptr<CryptKey> &pKey,
    const std::vector<std::byte> &ciphertext) {
  TSS2_RC r;

  TPM2B_PUBLIC *outPublic = NULL;
  TPM2B_PUBLIC_KEY_RSA cipher;
  TPM2B_PUBLIC_KEY_RSA *plain = NULL;

  cipher.size = ciphertext.size();
  memcpy(cipher.buffer, ciphertext.data(), ciphertext.size());

  TPM2B_AUTH authKey = {.size = 6, .buffer = {6, 7, 8, 9, 10, 11}};

  TPM2B_PUBLIC inPublic = kPrimaryDefaultRSA;

  TPM2B_DATA outsideInfo = {
      .size = 0,
      .buffer = {},
  };

  TPML_PCR_SELECTION creationPCR = {
      .count = 0,
  };

  TPM2B_PUBLIC inPublic2 = kKeyDefaultRSA;
  inPublic2.publicArea.unique.rsa.size = pKey->getPublicKey().size();
  memcpy(inPublic2.publicArea.unique.rsa.buffer,
         std::begin(pKey->getPublicKey()), pKey->getPublicKey().size());
  TPM2B_PRIVATE inPrivateRSA;
  inPrivateRSA.size = pKey->getEncryptedPrivateKey().size();
  memcpy(inPrivateRSA.buffer, std::begin(pKey->getEncryptedPrivateKey()),
         pKey->getEncryptedPrivateKey().size());

  ESYS_TR loadedKeyHandle = ESYS_TR_NONE;
  r = Esys_Load(ctx, pKey->getParentHandle(), ESYS_TR_PASSWORD, ESYS_TR_NONE,
                ESYS_TR_NONE, &inPrivateRSA, &inPublic2, &loadedKeyHandle);
  if (r != TSS2_RC_SUCCESS) {
    throw TPM2Exception("Could not load provided key");
  }

  r = Esys_TR_SetAuth(ctx, loadedKeyHandle, &authKey);
  if (r != TSS2_RC_SUCCESS) {
    throw TPM2Exception("Could not authorize to provieded key");
  }

  TPMT_RSA_DECRYPT scheme;
  scheme.scheme = TPM2_ALG_RSAES;

  r = Esys_RSA_Decrypt(ctx, loadedKeyHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                       ESYS_TR_NONE, &cipher, &scheme, nullptr, &plain);
  if (r != TSS2_RC_SUCCESS) {
    throw TPM2Exception("Could not decrypt data using provieded key");
  }

  std::vector<std::byte> plaintext;
  plaintext.resize(plain->size);
  memcpy(plaintext.data(), plain->buffer, plain->size);
  return plaintext;
}
};  // namespace Moria