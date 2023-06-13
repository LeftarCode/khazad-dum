#pragma once
#include <tss2/tss2_esys.h>

#include <memory>

#include "./crypt_key.h"

namespace Moria {
class TPM2_HAL {
 private:
  ESYS_CONTEXT *ctx;
  ESYS_TR session = ESYS_TR_NONE;

 public:
  TPM2_HAL();
  std::unique_ptr<CryptKey> createPrimaryKey();
};

};  // namespace Moria