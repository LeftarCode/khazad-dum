#pragma once
#include <fstream>
#include <iostream>

#include "crypto/ec/ec_key_converter.h"
#include "crypto/symmetric/aes_processor.h"
#include "tpm2/tpm2_hal.h"
#include "utils/macros.h"

namespace Moria {

class KhazadDum {
  TPM2_HAL* tpm2hal = new TPM2_HAL;

  std::string convertBytesVectorToHexString(const std::vector<std::byte>& v);
  std::string convert32BytesArrayToHexString(
      const std::array<std::byte, 32>& a);
  std::string convert16BytesArrayToHexString(
      const std::array<std::byte, 16>& a);
  std::string convert12BytesArrayToHexString(
      const std::array<std::byte, 12>& a);

  std::vector<std::byte> convertHexStringToBytesVector(const std::string& s);
  std::array<std::byte, 32> convertHexStringTo32BytesArray(
      const std::string& s);
  std::array<std::byte, 16> convertHexStringTo16BytesArray(
      const std::string& s);
  std::array<std::byte, 12> convertHexStringTo12BytesArray(
      const std::string& s);

 public:
  void createPolicy(std::string policyOutputFilename);
  void encryptSecrets(std::string policyInputFilename,
                      std::string secretsInputFilename,
                      std::string privateKeyInputFilename);
  std::vector<Secret> decryptSecrets(std::string policyInputFilename);
  void sealSecrets(std::vector<Secret> secrets);
};
};  // namespace Moria