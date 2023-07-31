#include "tpm2/primary_object.h"

#include <iomanip>
#include <iostream>
#include <sstream>

namespace Moria {
PrimaryObject::PrimaryObject(ESYS_TR handle, ECPointCoord x, ECPointCoord y)
    : x(x), y(y), handle(handle) {}
ECPointCoord PrimaryObject::getX() { return x; }
ECPointCoord PrimaryObject::getY() { return y; }

nlohmann::json PrimaryObject::serialize() {
  std::ostringstream xStream;
  std::ostringstream yStream;
  for (auto byte : x) {
    xStream << std::setw(2) << std::setfill('0') << std::hex
            << +static_cast<unsigned char>(byte);
  }
  for (auto byte : y) {
    yStream << std::setw(2) << std::setfill('0') << std::hex
            << +static_cast<unsigned char>(byte);
  }

  nlohmann::json keyJSON = {
      {"pub_key", {{"x", xStream.str()}, {"y", yStream.str()}}},
  };

  return keyJSON;
}

ESYS_TR PrimaryObject::getHandle() { return handle; }
};  // namespace Moria