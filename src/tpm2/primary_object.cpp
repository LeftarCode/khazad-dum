#include "tpm2/primary_object.h"

#include <iomanip>
#include <iostream>
#include <sstream>

namespace Moria {
PrimaryObject::PrimaryObject(ESYS_TR handle, std::array<std::byte, 256> key)
    : key(key), handle(handle) {}
std::array<std::byte, 256> PrimaryObject::getKey() { return key; }

nlohmann::json PrimaryObject::serialize() {
  std::ostringstream keyStream;
  for (auto byte : key) {
    keyStream << std::setw(2) << std::setfill('0') << std::hex
              << +static_cast<unsigned char>(byte);
  }

  nlohmann::json keyJSON = {
      {"pub_key", keyStream.str()},
  };

  return keyJSON;
}

ESYS_TR PrimaryObject::getHandle() { return handle; }
};  // namespace Moria