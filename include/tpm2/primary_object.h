#pragma once
#include <tss2/tss2_esys.h>

#include <array>
#include <cstddef>
#include <nlohmann/json.hpp>

namespace Moria {
class PrimaryObject {
 private:
  ESYS_TR handle;
  std::array<std::byte, 256> key;

 public:
  PrimaryObject(ESYS_TR handle, std::array<std::byte, 256> key);
  std::array<std::byte, 256> getKey();
  nlohmann::json serialize();
  ESYS_TR getHandle();
};
};  // namespace Moria