#include "tpm2/tpm2_hal.h"

#include <cstring>
#include <iostream>

#include "tpm2/key_defs.h"
#include "utils/tpm2_exception.h"
#define UNUSED(x) (void)(x)

#pragma GCC diagnostic ignored "-Wmissing-field-initializers"

#define TSS2_ESYS_RC_GENERAL_FAILURE \
  ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | TSS2_BASE_RC_GENERAL_FAILURE))
#define TSS2_ESYS_RC_NOT_IMPLEMENTED \
  ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | TSS2_BASE_RC_NOT_IMPLEMENTED))
#define TSS2_ESYS_RC_ABI_MISMATCH \
  ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | TSS2_BASE_RC_ABI_MISMATCH))
#define TSS2_ESYS_RC_BAD_REFERENCE \
  ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | TSS2_BASE_RC_BAD_REFERENCE))
#define TSS2_ESYS_RC_INSUFFICIENT_BUFFER \
  ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | TSS2_BASE_RC_INSUFFICIENT_BUFFER))
#define TSS2_ESYS_RC_BAD_SEQUENCE \
  ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | TSS2_BASE_RC_BAD_SEQUENCE))
#define TSS2_ESYS_RC_INVALID_SESSIONS \
  ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | TSS2_BASE_RC_INVALID_SESSIONS))
#define TSS2_ESYS_RC_TRY_AGAIN \
  ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | TSS2_BASE_RC_TRY_AGAIN))
#define TSS2_ESYS_RC_IO_ERROR \
  ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | TSS2_BASE_RC_IO_ERROR))
#define TSS2_ESYS_RC_BAD_VALUE \
  ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | TSS2_BASE_RC_BAD_VALUE))
#define TSS2_ESYS_RC_NO_DECRYPT_PARAM \
  ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | TSS2_BASE_RC_NO_DECRYPT_PARAM))
#define TSS2_ESYS_RC_NO_ENCRYPT_PARAM \
  ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | TSS2_BASE_RC_NO_ENCRYPT_PARAM))
#define TSS2_ESYS_RC_BAD_SIZE \
  ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | TSS2_BASE_RC_BAD_SIZE))
#define TSS2_ESYS_RC_MALFORMED_RESPONSE \
  ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | TSS2_BASE_RC_MALFORMED_RESPONSE))
#define TSS2_ESYS_RC_INSUFFICIENT_CONTEXT \
  ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | TSS2_BASE_RC_INSUFFICIENT_CONTEXT))
#define TSS2_ESYS_RC_INSUFFICIENT_RESPONSE \
  ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | TSS2_BASE_RC_INSUFFICIENT_RESPONSE))
#define TSS2_ESYS_RC_INCOMPATIBLE_TCTI \
  ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | TSS2_BASE_RC_INCOMPATIBLE_TCTI))
#define TSS2_ESYS_RC_BAD_TCTI_STRUCTURE \
  ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | TSS2_BASE_RC_BAD_TCTI_STRUCTURE))
#define TSS2_ESYS_RC_MEMORY \
  ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | TSS2_BASE_RC_MEMORY))
#define TSS2_ESYS_RC_BAD_TR \
  ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | TSS2_BASE_RC_BAD_TR))
#define TSS2_ESYS_RC_MULTIPLE_DECRYPT_SESSIONS \
  ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | TSS2_BASE_RC_MULTIPLE_DECRYPT_SESSIONS))
#define TSS2_ESYS_RC_MULTIPLE_ENCRYPT_SESSIONS \
  ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | TSS2_BASE_RC_MULTIPLE_ENCRYPT_SESSIONS))
#define TSS2_ESYS_RC_NOT_SUPPORTED \
  ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | TSS2_BASE_RC_NOT_SUPPORTED))
#define TSS2_ESYS_RC_RSP_AUTH_FAILED \
  ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | TSS2_BASE_RC_RSP_AUTH_FAILED))
#define TSS2_ESYS_RC_CALLBACK_NULL \
  ((TSS2_RC)(TSS2_ESAPI_RC_LAYER | TSS2_BASE_RC_CALLBACK_NULL))

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

std::unique_ptr<PrimaryObject> TPM2_HAL::createPrimaryObject(std::string data) {
  TSS2_RC r;
  ESYS_TR primaryHandle = ESYS_TR_NONE;
  TPM2B_PUBLIC *outPublic = nullptr;
  TPM2B_AUTH authValuePrimary = {.size = 5, .buffer = {1, 2, 3, 4, 5}};

  std::cout << "CREATE_PRIMARY_OBJECT: " << data << std::endl;

  // EXCAPTION IF DATA.SIZE > 256

  TPM2B_SENSITIVE_CREATE inSensitivePrimary = {
      .size = 0,
      .sensitive =
          {
              .data =
                  {
                      .size = 0,
                      .buffer = {0},
                  },
          },
  };

  inSensitivePrimary.sensitive.userAuth = authValuePrimary;
  inSensitivePrimary.sensitive.data.size = data.size();
  memcpy(inSensitivePrimary.sensitive.data.buffer, data.c_str(), data.size());

  TPM2B_PUBLIC inPublic = kPrimaryDefaultEcc;
  if (data.size() > 0) {
    inPublic = kPrimaryDefaultSeal;
  }

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

  ECPointCoord x;
  memcpy(std::begin(x), outPublic->publicArea.unique.ecc.x.buffer, 32);
  ECPointCoord y;
  memcpy(std::begin(y), outPublic->publicArea.unique.ecc.y.buffer, 32);

  Esys_Free(outPublic);

  return std::make_unique<PrimaryObject>(primaryHandle, x, y);
};

ECDHSecret TPM2_HAL::generateSharedKey(
    const std::unique_ptr<PrimaryObject> &primaryKey,
    const TPM2B_ECC_POINT &inPoint) {
  TPM2B_ECC_POINT *zPoint = NULL;
  TSS2_RC r = Esys_ECDH_ZGen(ctx, primaryKey->getHandle(), ESYS_TR_PASSWORD,
                             ESYS_TR_NONE, ESYS_TR_NONE, &inPoint, &zPoint);

  if (r != TSS2_RC_SUCCESS) {
    throw TPM2Exception("Could not generate shared key (ECDH).");
  }

  ECDHSecret secret;
  memcpy(std::begin(secret), zPoint->point.x.buffer, 32);

  Esys_Free(zPoint);

  return secret;
}

std::string TPM2_HAL::unsealSecret(
    const std::shared_ptr<PrimaryObject> &primaryKey) {
  TPM2B_SENSITIVE_DATA outSensitiveData = {
      .size = 0,
      .buffer = {0},
  };
  TPM2B_SENSITIVE_DATA *pOutSensitiveData = &outSensitiveData;

  TSS2_RC r = Esys_Unseal(ctx, primaryKey->getHandle(), ESYS_TR_PASSWORD,
                          ESYS_TR_NONE, ESYS_TR_NONE, &pOutSensitiveData);
  if (r != TSS2_RC_SUCCESS) {
    throw TPM2Exception("Could not unseal data!");
  }

  std::cout << outSensitiveData.buffer << std::endl;
}
};  // namespace Moria