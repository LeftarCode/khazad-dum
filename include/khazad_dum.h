#pragma once
#include <fstream>
#include <iostream>

#include "crypto/ec/ec_key_converter.h"
#include "crypto/symmetric/aes_processor.h"
#include "tpm2/tpm2_hal.h"
#include "utils/macros.h"

namespace Moria {
class KhazadDum {
  Moria::TPM2_HAL* tpm2hal = new Moria::TPM2_HAL;

 public:
  void createPolicy(std::string policyOutputFilename);
  void encryptSecrets(std::string policyInputFilename,
                      std::string secretsInputFilename,
                      std::string privateKeyInputFilename);
  void decryptSecrets(std::string policyInputFilename);
};
};  // namespace Moria