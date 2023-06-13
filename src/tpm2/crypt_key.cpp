#include "tpm2/crypt_key.h"

#include <iomanip>
#include <iostream>
#include <sstream>

namespace Moria {
CryptKey::CryptKey(std::array<std::byte, 32> x, std::array<std::byte, 32> y)
    : x(x), y(y) {}
std::array<std::byte, 32> CryptKey::getX() { return x; }
std::array<std::byte, 32> CryptKey::getY() { return y; }

nlohmann::json CryptKey::serialize() {
  std::ostringstream xstream;
  std::ostringstream ystream;
  for (auto byte : x) {
    xstream << std::setw(2) << std::setfill('0') << std::hex
            << +static_cast<unsigned char>(byte);
  }

  for (auto byte : y) {
    ystream << std::setw(2) << std::setfill('0') << std::hex
            << +static_cast<unsigned char>(byte);
  }

  nlohmann::json keyJSON = {
      {"x", xstream.str()},
      {"y", ystream.str()},
  };

  return keyJSON;
}
};  // namespace Moria