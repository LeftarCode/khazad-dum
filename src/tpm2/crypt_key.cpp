#include "tpm2/crypt_key.h"

namespace Moria {
CryptKey::CryptKey(std::array<std::byte, 32> x, std::array<std::byte, 32> y)
    : x(x), y(y) {}
std::array<std::byte, 32> CryptKey::getX() { return y; }
std::array<std::byte, 32> CryptKey::getY() { return y; }
};  // namespace Moria