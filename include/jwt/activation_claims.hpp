#pragma once
#include "jwt/account_claims.hpp"
#include "jwt/claims.hpp"
#include <vector>

namespace jwt {

/// Activation claims (Go: ActivationClaims) — the signed grant an exporting
/// account hands an importer for a PRIVATE (token_req) export. The claim's
/// SUBJECT is the grantee account's public key (or "public"); the nats object
/// carries the import subject and kind.
class ActivationClaims : public Claims {
public:
    explicit ActivationClaims(const std::string& granteeAccountPublicKey);
    ~ActivationClaims() override;

    // Claims interface
    [[nodiscard]] std::string subject() const override;
    [[nodiscard]] std::string issuer() const override;
    [[nodiscard]] std::optional<std::string> name() const override;
    [[nodiscard]] std::int64_t issuedAt() const override;
    [[nodiscard]] std::int64_t expires() const override;
    [[nodiscard]] std::string audience() const override;
    [[nodiscard]] std::int64_t notBefore() const override;
    [[nodiscard]] const std::vector<std::string>& tags() const override;
    [[nodiscard]] std::string encode(const std::string& seed) const override;
    [[nodiscard]] std::string encodeWithSigner(const std::string& issuerPublicKey,
                                               const SignFn& sign) const override;
    void validate(ValidationResults& vr) const override;
    void validate() const override;

    // Activation-specific
    void setName(const std::string& name);
    void setExpires(std::int64_t exp);
    void setAudience(const std::string& audience);
    void setNotBefore(std::int64_t nbf);
    /// Mutable tags — jwt::addTags(claims.tags(), {...}) for Go's Add semantics.
    [[nodiscard]] std::vector<std::string>& tags();
    void setImportSubject(const std::string& subject);
    [[nodiscard]] std::string importSubject() const;
    void setImportType(ExportType type);
    [[nodiscard]] ExportType importType() const;
    void setIssuerAccount(const std::string& accountPublicKey);
    [[nodiscard]] std::optional<std::string> issuerAccount() const;

private:
    friend std::unique_ptr<ActivationClaims> decodeActivationClaims(const std::string&);
    void checkStructure() const;
    class Impl;
    std::unique_ptr<Impl> impl_;
};

/// Decode an activation JWT (authenticated).
[[nodiscard]] std::unique_ptr<ActivationClaims> decodeActivationClaims(const std::string& jwt);

}
