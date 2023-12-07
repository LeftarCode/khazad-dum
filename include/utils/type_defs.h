#pragma once
#include <vector>

namespace Moria {
typedef std::pair<std::array<std::byte, 32>, std::array<std::byte, 32>>
    ECPublicKeyPoint;
typedef std::array<std::byte, 32> ECDHSecret;
typedef std::array<std::byte, 32> ECPointCoord;

class EncryptedSecret {
 public:
  std::string name;
  std::array<std::byte, 12> iv;
  std::array<std::byte, 16> tag;
  std::vector<std::byte> value;
};

class Secret {
 public:
  std::string name;
  std::string value;
};
}  // namespace Moria