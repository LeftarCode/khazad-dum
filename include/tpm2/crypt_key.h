#pragma once
#include <tss2/tss2_esys.h>

#include <array>
#include <cstddef>
#include <nlohmann/json.hpp>

namespace Moria {
enum KeyType { kEllipticCurve, kRSA, kAES };

class CryptKey {
 private:
  KeyType type;
  ESYS_TR parentHandle;
  std::array<std::byte, 256> publicKey;
  std::array<std::byte, 228> ecnryptedPrivateKey;

 public:
  CryptKey(ESYS_TR parentHandle, std::array<std::byte, 256> publicKey,
           std::array<std::byte, 228> ecnryptedPrivateKey);
  std::array<std::byte, 256> getPublicKey();
  std::array<std::byte, 228> getEncryptedPrivateKey();
  nlohmann::json serialize();
  ESYS_TR getParentHandle();
};

};  // namespace Moria