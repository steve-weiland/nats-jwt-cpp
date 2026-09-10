#pragma once
#include "jwt/claims.hpp"
#include <string>
#include <vector>

namespace jwt {

/// Operator-level claims (top of trust hierarchy)
class OperatorClaims : public Claims {
public:
    /// Create operator claims with the given public key
    explicit OperatorClaims(const std::string& operatorPublicKey);
    ~OperatorClaims() override;

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

    // Operator-specific
    void setName(const std::string& name);
    void setExpires(std::int64_t exp);
    void setAudience(const std::string& audience);
    void setNotBefore(std::int64_t nbf);
    /// Mutable tags — jwt::addTags(claims.tags(), {...}) for Go's Add semantics.
    [[nodiscard]] std::vector<std::string>& tags();
    void addSigningKey(const std::string& publicKey);
    [[nodiscard]] const std::vector<std::string>& signingKeys() const;

    /// nats-account-server-style resolver URL (any scheme; tools append
    /// /accounts/<id> etc).
    void setAccountServerURL(const std::string& url);
    [[nodiscard]] std::string accountServerURL() const;

    /// NATS URLs tools may connect to — nats/tls/ws/wss only, no
    /// credentials, no path.
    [[nodiscard]] std::vector<std::string>& operatorServiceURLs();
    [[nodiscard]] const std::vector<std::string>& operatorServiceURLs() const;

    /// Public key of the system account ($SYS events/monitoring).
    void setSystemAccount(const std::string& accountPublicKey);
    [[nodiscard]] std::string systemAccount() const;

    /// Minimum server version, "<major>.<minor>.<update>".
    void setAssertServerVersion(const std::string& version);
    [[nodiscard]] std::string assertServerVersion() const;

    /// When true, accounts/users must be issued by signing keys, never the
    /// identity key.
    void setStrictSigningKeyUsage(bool strict);
    [[nodiscard]] bool strictSigningKeyUsage() const;

private:
    friend std::unique_ptr<OperatorClaims> decodeOperatorClaims(const std::string&);
    void checkStructure() const;
    class Impl;
    std::unique_ptr<Impl> impl_;
};

/// Decode an operator JWT
[[nodiscard]] std::unique_ptr<OperatorClaims> decodeOperatorClaims(const std::string& jwt);

}
