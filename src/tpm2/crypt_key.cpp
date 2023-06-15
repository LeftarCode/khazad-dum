#include "tpm2/crypt_key.h"

#include <iomanip>
#include <iostream>
#include <sstream>

namespace Moria {
CryptKey::CryptKey(ESYS_TR parentHandle, std::array<std::byte, 256> publicKey,
                   std::array<std::byte, 196> ecnryptedPrivateKey)
    : publicKey(publicKey),
      ecnryptedPrivateKey(ecnryptedPrivateKey),
      parentHandle(parentHandle) {}
std::array<std::byte, 256> CryptKey::getPublicKey() { return publicKey; }
std::array<std::byte, 196> CryptKey::getEncryptedPrivateKey() {
  return ecnryptedPrivateKey;
}

nlohmann::json CryptKey::serialize() {
  std::ostringstream pubstream;
  std::ostringstream privstream;
  for (auto byte : publicKey) {
    pubstream << std::setw(2) << std::setfill('0') << std::hex
              << +static_cast<unsigned char>(byte);
  }

  for (auto byte : ecnryptedPrivateKey) {
    privstream << std::setw(2) << std::setfill('0') << std::hex
               << +static_cast<unsigned char>(byte);
  }

  nlohmann::json keyJSON = {{"public", pubstream.str()},
                            {"encryptedPrivateKey", privstream.str()}};

  return keyJSON;
}

ESYS_TR CryptKey::getParentHandle() { return parentHandle; }
};  // namespace Moria