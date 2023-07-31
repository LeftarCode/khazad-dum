#pragma once
#include <array>
#include <string>
#include <utility>

#include "utils/type_defs.h"

namespace Moria {
class ECKeyConverter {
 public:
  ECPublicKeyPoint convertPEMToPoint(const std::string& pem);
  ECDHSecret generateSharedKey(const std::string& pem,
                               ECPublicKeyPoint inPoint);
  ECPublicKeyPoint converHexStringToPoint(const std::string& x,
                                          const std::string& y);
};
}  // namespace Moria