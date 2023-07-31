#pragma once

namespace Moria {
class AESProcessor {
 public:
  std::array<std::byte, 32> generateInitialVector();
};
}  // namespace Moria