#pragma once

namespace Moria {
typedef std::pair<std::array<std::byte, 32>, std::array<std::byte, 32>>
    ECPublicKeyPoint;
typedef std::array<std::byte, 32> ECDHSecret;
typedef std::array<std::byte, 32> ECPointCoord;
}  // namespace Moria