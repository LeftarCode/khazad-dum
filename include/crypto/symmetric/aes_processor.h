#pragma once

#include <openssl/evp.h>

#include <array>
#include <string>
#include <vector>

#include "utils/type_defs.h"

namespace Moria {
enum SymmetricEncryptionType { kAES256GCM };

class AESProcessor {
  SymmetricEncryptionType type;
  EVP_CIPHER_CTX* ctx;
  ECPointCoord key;

 public:
  AESProcessor(SymmetricEncryptionType type, ECPointCoord key);
  ~AESProcessor();
  std::array<std::byte, 12> generateInitialVector();
  EncryptedSecret encryptSecret(const Secret& secret);
  Secret decryptSecret(const EncryptedSecret& encryptedSecret);
};
}  // namespace Moria