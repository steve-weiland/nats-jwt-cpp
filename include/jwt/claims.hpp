#pragma once
#include <string>
#include <string_view>
#include <memory>
#include <cstdint>
#include <optional>
#include <functional>
#include <span>
#include <vector>

namespace jwt {

/// External signer (Go: SignFn). Called with the issuer public key the token
/// will name and the exact bytes to sign (the "header.payload" signing
/// input); must return the 64-byte Ed25519 signature made by that key's
/// private half — which never has to enter this process (HSM/KMS custody).
/// Exceptions thrown by the signer propagate unwrapped.
using SignFn = std::function<std::vector<std::uint8_t>(std::string_view issuerPublicKey,
                                                       std::span<const std::uint8_t> signingInput)>;

/// Base class for all JWT claims
class Claims {
public:
    virtual ~Claims() = default;

    /// Get the subject (public key of the claim holder)
    [[nodiscard]] virtual std::string subject() const = 0;

    /// Get the issuer (public key of the signer)
    [[nodiscard]] virtual std::string issuer() const = 0;

    /// Get the claim name
    [[nodiscard]] virtual std::optional<std::string> name() const = 0;

    /// Get the issued-at timestamp (Unix seconds)
    [[nodiscard]] virtual std::int64_t issuedAt() const = 0;

    /// Get the expiration timestamp (Unix seconds, 0 = no expiration)
    [[nodiscard]] virtual std::int64_t expires() const = 0;

    /// Encode the claims to a JWT string signed with the given seed; the
    /// issuer is DERIVED from the seed (Go's doEncode), never taken on trust.
    [[nodiscard]] virtual std::string encode(const std::string& seed) const = 0;

    /// Encode with an external signer (Go: EncodeWithSigner). issuerPublicKey
    /// plays the keypair's role — it becomes `iss` and is checked against the
    /// claim type's allowed issuer kinds BEFORE the signer is called; the
    /// signer produces the signature. Divergence from Go, deliberate: the
    /// returned signature is verified against issuerPublicKey and a mismatch
    /// throws SignatureError — a mis-keyed HSM must not mint an unverifiable
    /// token.
    [[nodiscard]] virtual std::string encodeWithSigner(const std::string& issuerPublicKey,
                                                       const SignFn& sign) const = 0;

    /// Validate the claims structure
    virtual void validate() const = 0;
};

/// Decode a JWT string into claims
[[nodiscard]] std::unique_ptr<Claims> decode(const std::string& jwt);

/// Verify a JWT signature
[[nodiscard]] bool verify(const std::string& jwt);

}
