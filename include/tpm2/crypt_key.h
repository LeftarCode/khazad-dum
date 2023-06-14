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
  ESYS_TR handle;
  std::array<std::byte, 32> x, y;

 public:
  CryptKey(ESYS_TR handle, std::array<std::byte, 32> x,
           std::array<std::byte, 32> y);
  std::array<std::byte, 32> getX();
  std::array<std::byte, 32> getY();
  nlohmann::json serialize();
  ESYS_TR getHandle();
};

};  // namespace Moria