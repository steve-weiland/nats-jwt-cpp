#pragma once
#include "jwt/claims.hpp"
#include <optional>
#include <string>
#include <vector>

namespace jwt {

/// Generic claims (Go: GenericClaims) — the standard claim fields plus the
/// `nats` object as raw JSON, for claim types this library has no struct for.
/// decode() returns one for any unknown type; decodeGeneric reads ANY token
/// (known types included) this way. Divergence, measured: Go's own Decode
/// cannot read Go's own v2 generic tokens (its unknown-type branch reports
/// version -1 and applies the v1 signature rule); DecodeGeneric is Go's
/// working path, and both of ours work.
class GenericClaims : public Claims {
public:
    explicit GenericClaims(const std::string& subject);
    ~GenericClaims() override;

    // Claims interface
    [[nodiscard]] std::string subject() const override;
    [[nodiscard]] std::string issuer() const override;
    [[nodiscard]] std::optional<std::string> name() const override;
    [[nodiscard]] std::int64_t issuedAt() const override;
    [[nodiscard]] std::int64_t expires() const override;
    [[nodiscard]] std::string audience() const override;
    [[nodiscard]] std::int64_t notBefore() const override;
    /// Always empty for generics — tags, if any, live in data()["tags"].
    [[nodiscard]] const std::vector<std::string>& tags() const override;
    /// Any signing key type may issue a generic (Go: ExpectedPrefixes nil).
    [[nodiscard]] std::string encode(const std::string& seed) const override;
    [[nodiscard]] std::string encodeWithSigner(const std::string& issuerPublicKey,
                                               const SignFn& sign) const override;
    void validate(ValidationResults& vr) const override;
    void validate() const override;

    void setName(const std::string& name);
    void setExpires(std::int64_t exp);
    void setAudience(const std::string& audience);
    void setNotBefore(std::int64_t nbf);
    /// The nats object (Go: Data) as JSON text — this library keeps its JSON
    /// engine private (pimpl), so the payload crosses the API as a string.
    /// setDataJson must be a JSON object; encode stamps "version": 2 into it.
    [[nodiscard]] std::string dataJson() const;
    void setDataJson(const std::string& jsonObject);
    /// Go's GenericClaims.ClaimType(): data["type"] if it is one of the six
    /// known types, else "generic" ("" when there is no type at all).
    [[nodiscard]] std::string claimType() const;

private:
    friend std::unique_ptr<GenericClaims> decodeGeneric(const std::string&);
    void checkStructure() const;
    class Impl;
    std::unique_ptr<Impl> impl_;
};

/// Go's DecodeGeneric: authenticated; the signature rule follows the HEADER
/// alg ("ed25519" = v1, payload-only), and for v1 the top-level type/tags are
/// copied into data(). No issuer-kind rule.
[[nodiscard]] std::unique_ptr<GenericClaims> decodeGeneric(const std::string& jwt);

}
