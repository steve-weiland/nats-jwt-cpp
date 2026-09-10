#pragma once
#include <string>
#include <string_view>
#include <memory>
#include <cstdint>
#include <optional>
#include <functional>
#include <span>
#include <vector>
#include "jwt/validation_results.hpp"

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

    /// `aud` (Go: ClaimsData.Audience); empty = absent.
    [[nodiscard]] virtual std::string audience() const = 0;

    /// `nbf` (Go: ClaimsData.NotBefore), Unix seconds; 0 = absent. Go's only
    /// not-before rule: nbf > now is "claim is not yet valid" (iat is never
    /// checked).
    [[nodiscard]] virtual std::int64_t notBefore() const = 0;

    /// `nats.tags` (Go: GenericFields.Tags). Decoded as-is; use addTags for
    /// Go's TagList.Add normalization.
    [[nodiscard]] virtual const std::vector<std::string>& tags() const = 0;

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

    /// Go's Validate: append EVERY finding — structural errors, the claim
    /// type's rules, Go's two warnings, and the exp/nbf time checks — to vr.
    /// Never throws for a finding. Decode does not run this (an advisory
    /// failure must not make a token un-inspectable); encode does.
    virtual void validate(ValidationResults& vr) const = 0;

    /// Throwing form: the structural check, then validate(vr), then throw the
    /// first BLOCKING issue as InvalidClaimsError. Time checks and warnings
    /// never throw (Go parity: an expired token encodes and decodes).
    virtual void validate() const = 0;
};

/// Go's TagList.Add: lower-case, trim, drop empties, de-duplicate.
void addTags(std::vector<std::string>& tags, const std::vector<std::string>& add);
/// Go's TagList.Contains: case-insensitive, trimmed.
[[nodiscard]] bool tagsContain(const std::vector<std::string>& tags, std::string_view tag);

/// Decode a JWT string into claims
[[nodiscard]] std::unique_ptr<Claims> decode(const std::string& jwt);

/// Verify a JWT signature
[[nodiscard]] bool verify(const std::string& jwt);

}
