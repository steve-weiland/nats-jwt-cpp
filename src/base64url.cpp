#include "base64url.hpp"
#include <stdexcept>
#include "jwt/jwt_errors.hpp"
#include <array>

namespace jwt::internal {

namespace {
    // Base64 URL alphabet (RFC 4648): differs from standard in chars 62 and 63
    constexpr char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    // Lookup table for decoding (maps ASCII value to 6-bit value, 0xFF = invalid)
    constexpr std::array<std::uint8_t, 256> createDecodeLookup() {
        std::array<std::uint8_t, 256> lookup{};
        for (auto& val : lookup) val = 0xFF;  // Initialize all to invalid

        for (std::uint8_t i = 0; i < 64; ++i) {
            lookup[static_cast<std::uint8_t>(alphabet[i])] = i;
        }
        // No '=': Go's base64.RawURLEncoding refuses padding anywhere, and a
        // token string must have exactly one valid spelling (string-keyed
        // caches, dedup, revocation by token text) — measured: `token=` used
        // to decode and verify here while Go said "illegal base64 data".

        return lookup;
    }

    constexpr auto decode_lookup = createDecodeLookup();
}

std::string base64url_encode(std::span<const std::uint8_t> data) {
    if (data.empty()) {
        return "";
    }

    std::string result;
    // Reserve space: 4 output chars per 3 input bytes (upper bound)
    result.reserve((data.size() * 4 + 2) / 3);

    size_t i = 0;
    // Process complete 3-byte groups
    while (i + 2 < data.size()) {
        std::uint32_t triple = (static_cast<std::uint32_t>(data[i]) << 16) |
                                (static_cast<std::uint32_t>(data[i + 1]) << 8) |
                                 static_cast<std::uint32_t>(data[i + 2]);

        result.push_back(alphabet[(triple >> 18) & 0x3F]);
        result.push_back(alphabet[(triple >> 12) & 0x3F]);
        result.push_back(alphabet[(triple >> 6) & 0x3F]);
        result.push_back(alphabet[triple & 0x3F]);

        i += 3;
    }

    // Handle remaining 1 or 2 bytes (without padding)
    if (i < data.size()) {
        std::uint32_t remaining = static_cast<std::uint32_t>(data[i]) << 16;
        result.push_back(alphabet[(remaining >> 18) & 0x3F]);

        if (i + 1 < data.size()) {
            // 2 bytes remaining -> 3 output chars
            remaining |= static_cast<std::uint32_t>(data[i + 1]) << 8;
            result.push_back(alphabet[(remaining >> 12) & 0x3F]);
            result.push_back(alphabet[(remaining >> 6) & 0x3F]);
        } else {
            // 1 byte remaining -> 2 output chars
            result.push_back(alphabet[(remaining >> 12) & 0x3F]);
        }
    }

    return result;
}

std::vector<std::uint8_t> base64url_decode(std::string_view input) {
    if (input.empty()) {
        return {};
    }

    // Reserve space: 3 output bytes per 4 input chars (upper bound)
    std::vector<std::uint8_t> result;
    result.reserve((input.size() * 3) / 4 + 1);

    size_t i = 0;
    // Process complete 4-char groups
    while (i + 3 < input.size()) {
        std::uint8_t a = decode_lookup[static_cast<std::uint8_t>(input[i])];
        std::uint8_t b = decode_lookup[static_cast<std::uint8_t>(input[i + 1])];
        std::uint8_t c = decode_lookup[static_cast<std::uint8_t>(input[i + 2])];
        std::uint8_t d = decode_lookup[static_cast<std::uint8_t>(input[i + 3])];

        if (a == 0xFF || b == 0xFF || c == 0xFF || d == 0xFF) {
            throw MalformedTokenError("Invalid Base64 URL character in input");
        }

        std::uint32_t quad = (static_cast<std::uint32_t>(a) << 18) |
                              (static_cast<std::uint32_t>(b) << 12) |
                              (static_cast<std::uint32_t>(c) << 6) |
                               static_cast<std::uint32_t>(d);

        result.push_back(static_cast<std::uint8_t>((quad >> 16) & 0xFF));
        result.push_back(static_cast<std::uint8_t>((quad >> 8) & 0xFF));
        result.push_back(static_cast<std::uint8_t>(quad & 0xFF));

        i += 4;
    }

    // Handle remaining chars
    size_t remaining = input.size() - i;
    if (remaining > 0) {
        if (remaining == 1) {
            throw MalformedTokenError("Invalid Base64 URL input length");
        }

        std::uint8_t a = decode_lookup[static_cast<std::uint8_t>(input[i])];
        std::uint8_t b = decode_lookup[static_cast<std::uint8_t>(input[i + 1])];

        if (a == 0xFF || b == 0xFF) {
            throw MalformedTokenError("Invalid Base64 URL character in input");
        }

        std::uint32_t partial = (static_cast<std::uint32_t>(a) << 18) |
                                 (static_cast<std::uint32_t>(b) << 12);

        result.push_back(static_cast<std::uint8_t>((partial >> 16) & 0xFF));

        if (remaining == 3) {
            std::uint8_t c = decode_lookup[static_cast<std::uint8_t>(input[i + 2])];
            if (c == 0xFF) {
                throw MalformedTokenError("Invalid Base64 URL character in input");
            }
            partial |= static_cast<std::uint32_t>(c) << 6;
            result.push_back(static_cast<std::uint8_t>((partial >> 8) & 0xFF));
        }
    }

    return result;
}

}

