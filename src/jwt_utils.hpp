#pragma once

#include <string>
#include <string_view>
#include <cstdint>
#include <vector>
#include <span>
#include "jwt/claims.hpp"
#include <nkeys/nkeys.hpp>

namespace jwt::internal {

/// A SignFn over an in-process keypair (the encode(seed) path). The keypair
/// must outlive the returned function.
SignFn signerFor(const nkeys::KeyPair& kp);

/// Finish an encode (Go's doEncode tail): base64url the header and payload,
/// hand "header.payload" to the signer, VERIFY the returned signature against
/// issuerPublicKey (throws SignatureError on mismatch or bad length), and
/// assemble header.payload.signature.
std::string signAndAssemble(const std::string& payloadJson,
                            const std::string& issuerPublicKey,
                            const SignFn& sign);

/// Compute the claim ID the way Go's jwt does: SHA-512/256 over the claims
/// JSON serialized WITHOUT the jti field, base32-encoded without padding
/// (52 chars). Deterministic and content-derived; each library hashes its own
/// serialization, so values differ from Go's for the same logical claims.
/// @param payloadJsonWithoutJti the payload JSON, jti absent
/// @return 52-character base32 string
std::string computeJti(std::string_view payloadJsonWithoutJti);

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

