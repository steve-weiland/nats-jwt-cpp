#pragma once

#include <string>
#include <cstdint>
#include <vector>
#include <span>

namespace jwt::internal {

/// Generate a random JWT ID (32 hex chars from 16 random bytes)
/// @return 32-character hex string
std::string generateJti();

/// Get current Unix timestamp in seconds
/// @return Unix timestamp (seconds since epoch)
std::int64_t getCurrentTimestamp();

/// Create JWT header as JSON string
/// @return JSON string: {"typ":"JWT","alg":"ed25519-nkey"}
std::string createHeader();

/// Parsed JWT components
struct JwtParts {
    std::string header_b64;
    std::string payload_b64;
    std::string signature_b64;
    std::string signing_input;  // "header.payload"
};

/// Parse JWT string into its components
/// @param jwt JWT string in format "header.payload.signature"
/// @return JwtParts structure with separated components
/// @throws std::invalid_argument if JWT format is invalid
JwtParts parseJwt(std::string_view jwt);

/// Verify JWT signature using Ed25519 public key
/// @param issuer_public_key Public key string (e.g., "OABC..." or "AABC...")
/// @param signing_input The "header.payload" string that was signed
/// @param signature_b64 Base64 URL encoded signature
/// @return true if signature is valid, false otherwise (malformed inputs
///         are false, never a throw)
bool verifySignature(const std::string& issuer_public_key,
                     const std::string& signing_input,
                     const std::string& signature_b64);

}

