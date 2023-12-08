#pragma once
#include <openssl/sha.h>
#include <tss2/tss2_esys.h>

#include <memory>

#include "./crypt_key.h"
#include "./primary_object.h"
#include "utils/type_defs.h"

namespace Moria {
class TPM2_HAL {
 private:
  ESYS_CONTEXT* ctx;
  ESYS_TR session = ESYS_TR_NONE;

 public:
  TPM2_HAL();
  std::unique_ptr<PrimaryObject> createPrimaryObject(std::string data = "");
  std::unique_ptr<CryptKey> createKey(
      std::unique_ptr<PrimaryObject> pPrimaryObject);
  ECPointCoord generateSharedKey(
      const std::unique_ptr<PrimaryObject>& primaryKey,
      const TPM2B_ECC_POINT& inPoint);
  std::string unsealSecret(const std::shared_ptr<PrimaryObject>& primaryKey);
};

};  // namespace Moria