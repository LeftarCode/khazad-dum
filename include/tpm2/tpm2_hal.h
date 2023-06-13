#pragma once
#include <tss2/tss2_esys.h>

#include <memory>

#include "./crypt_key.h"

namespace Moria {
class TPM2_HAL {
 private:
  ESYS_CONTEXT *ctx;

 public:
  TPM2_HAL();
  std::unique_ptr<CryptKey> createPrimaryKey();
};

};  // namespace Moria