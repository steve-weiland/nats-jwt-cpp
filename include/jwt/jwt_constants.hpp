#pragma once
#include <cstddef>

namespace jwt {

inline constexpr int JWT_VERSION = 2;

inline constexpr const char* JWT_ALGORITHM = "ed25519-nkey";

inline constexpr const char* JWT_TYPE = "JWT";

inline constexpr std::size_t MAX_JWT_SIZE = 1024 * 1024;  // Go's MaxTokenSize

}
