#include "jwt_utils.hpp"
#include "jwt/jwt_constants.hpp"
#include "base64url.hpp"
#include <nkeys/nkeys.hpp>
#include <nlohmann/json.hpp>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <array>
#include <stdexcept>

namespace jwt::internal {

std::string generateJti() {
    std::array<std::uint8_t, 16> random_bytes{};
    nkeys::secureRandomBytes(random_bytes);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (auto byte : random_bytes) {
        oss << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return oss.str();
}

std::int64_t getCurrentTimestamp() {
    using namespace std::chrono;
    return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

std::string createHeader() {
    nlohmann::json header;
    header["typ"] = JWT_TYPE;
    header["alg"] = JWT_ALGORITHM;
    return header.dump();
}

JwtParts parseJwt(std::string_view jwt) {
    // Cap before doing ANY work (Go: MaxTokenSize, checked first in Decode)
    if (jwt.size() > MAX_JWT_SIZE) {
        throw std::invalid_argument(
            "Token size " + std::to_string(jwt.size()) +
            " exceeds maximum of " + std::to_string(MAX_JWT_SIZE) + " bytes");
    }

    // Find the two dots separating header.payload.signature
    size_t first_dot = jwt.find('.');
    if (first_dot == std::string_view::npos) {
        throw std::invalid_argument("Invalid JWT format: missing first '.'");
    }

    size_t second_dot = jwt.find('.', first_dot + 1);
    if (second_dot == std::string_view::npos) {
        throw std::invalid_argument("Invalid JWT format: missing second '.'");
    }

    // Check for extra parts (more than 2 dots)
    if (jwt.find('.', second_dot + 1) != std::string_view::npos) {
        throw std::invalid_argument("Invalid JWT format: too many parts");
    }

    // Extract the three parts
    std::string header_b64(jwt.substr(0, first_dot));
    std::string payload_b64(jwt.substr(first_dot + 1, second_dot - first_dot - 1));
    std::string signature_b64(jwt.substr(second_dot + 1));

    // Validate all parts are non-empty
    if (header_b64.empty()) {
        throw std::invalid_argument("Invalid JWT format: empty header");
    }
    if (payload_b64.empty()) {
        throw std::invalid_argument("Invalid JWT format: empty payload");
    }
    if (signature_b64.empty()) {
        throw std::invalid_argument("Invalid JWT format: empty signature");
    }

    // Create signing input (what was actually signed)
    std::string signing_input = header_b64 + "." + payload_b64;

    return JwtParts{
        std::move(header_b64),
        std::move(payload_b64),
        std::move(signature_b64),
        std::move(signing_input)
    };
}

bool verifySignature(const std::string& issuer_public_key,
                     const std::string& signing_input,
                     const std::string& signature_b64) {
    try {
        // Decode the Base64 URL signature
        std::vector<std::uint8_t> signature_bytes = base64url_decode(signature_b64);

        // Ed25519 signatures must be exactly 64 bytes
        if (signature_bytes.size() != 64) {
            throw std::invalid_argument(
                "Invalid signature size: expected 64 bytes, got " +
                std::to_string(signature_bytes.size())
            );
        }

        // Create public key from the issuer's public key string
        auto public_key = nkeys::FromPublicKey(issuer_public_key);

        // Convert signing input to byte span
        std::span<const std::uint8_t> signing_bytes(
            reinterpret_cast<const std::uint8_t*>(signing_input.data()),
            signing_input.size()
        );

        // Verify the signature (Ed25519 verification)
        return public_key->verify(signing_bytes, signature_bytes);

    } catch (const std::exception& e) {
        // Any error during verification means invalid signature
        throw std::invalid_argument(
            std::string("Signature verification failed: ") + e.what()
        );
    }
}

}
