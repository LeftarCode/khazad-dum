#pragma once
#include <openssl/sha.h>
#include <tss2/tss2_esys.h>

#include <memory>

#include "./crypt_key.h"
#include "./primary_object.h"

namespace Moria {
class TPM2_HAL {
 private:
  ESYS_CONTEXT* ctx;
  ESYS_TR session = ESYS_TR_NONE;

 public:
  TPM2_HAL();
  std::unique_ptr<PrimaryObject> createPrimaryObject();
  std::unique_ptr<CryptKey> createKey(
      std::unique_ptr<PrimaryObject> pPrimaryObject);
  std::array<std::byte, 32> generateSharedKey(
      const std::unique_ptr<PrimaryObject>& primaryKey,
      const TPM2B_ECC_POINT& inPoint);
};

};  // namespace Moria