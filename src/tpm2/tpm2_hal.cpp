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

  TPM2B_PUBLIC inPublic = kPrimaryDefaultEcc;

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
};  // namespace Moria