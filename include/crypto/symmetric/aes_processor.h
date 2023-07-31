#pragma once

#include <openssl/evp.h>

#include <array>
#include <string>

#include "utils/type_defs.h"

namespace Moria {
enum SymmetricEncryptionType { kAES256GCM };

class AESProcessor {
  SymmetricEncryptionType type;
  EVP_CIPHER_CTX *ctx;
  ECPointCoord key;

 public:
  AESProcessor(SymmetricEncryptionType type, ECPointCoord key);
  ~AESProcessor();
  std::array<std::byte, 12> generateInitialVector();
  std::string encrypt(std::string cleartext, std::array<std::byte, 12> iv);
  std::string decrypt(std::string ciphertext, std::array<std::byte, 12> iv);
};
}  // namespace Moria