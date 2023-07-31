#pragma once
#include <tss2/tss2_esys.h>

#include <array>
#include <cstddef>
#include <nlohmann/json.hpp>

#include "utils/type_defs.h"

namespace Moria {
class PrimaryObject {
 private:
  ESYS_TR handle;
  std::array<std::byte, 32> x, y;

 public:
  PrimaryObject(ESYS_TR handle, ECPointCoord x, ECPointCoord y);
  ECPointCoord getX();
  ECPointCoord getY();
  nlohmann::json serialize();
  ESYS_TR getHandle();
};
};  // namespace Moria