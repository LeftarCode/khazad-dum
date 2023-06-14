#pragma once
#include <tss2/tss2_esys.h>

#include <memory>

#include "./crypt_key.h"
#include "./primary_object.h"

namespace Moria {
class TPM2_HAL {
 private:
  ESYS_CONTEXT *ctx;
  ESYS_TR session = ESYS_TR_NONE;

 public:
  TPM2_HAL();
  std::unique_ptr<PrimaryObject> createPrimaryObject();
  std::unique_ptr<CryptKey> createKey(
      std::unique_ptr<PrimaryObject> pPrimaryObject);
  std::vector<std::byte> encrypt(std::unique_ptr<PrimaryObject> pKey);
};

};  // namespace Moria