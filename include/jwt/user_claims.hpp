#pragma once
#include "jwt/claims.hpp"
#include "jwt/permissions.hpp"
#include <optional>
#include <vector>

namespace jwt {

/// User-level claims (bottom of trust hierarchy)
class UserClaims : public Claims {
public:
    /// Create user claims with the given public key
    explicit UserClaims(const std::string& userPublicKey);
    ~UserClaims() override;

    // Claims interface
    [[nodiscard]] std::string subject() const override;
    [[nodiscard]] std::string issuer() const override;
    [[nodiscard]] std::optional<std::string> name() const override;
    [[nodiscard]] std::int64_t issuedAt() const override;
    [[nodiscard]] std::int64_t expires() const override;
    [[nodiscard]] std::string encode(const std::string& seed) const override;
    [[nodiscard]] std::string encodeWithSigner(const std::string& issuerPublicKey,
                                               const SignFn& sign) const override;
    void validate() const override;

    // User-specific
    void setName(const std::string& name);
    void setExpires(std::int64_t exp);
    void setIssuer(const std::string& issuerKey);
    void setIssuerAccount(const std::string& accountPublicKey);
    [[nodiscard]] std::optional<std::string> issuerAccount() const;

    /// Pub/sub permissions — mutate in place, Go-style:
    ///   claims.permissions().pub.allow = {"demo.>"};
    [[nodiscard]] Permissions& permissions();
    [[nodiscard]] const Permissions& permissions() const;

    /// Limits (-1 = unlimited; 0 is omitted on the wire = denied by server).
    [[nodiscard]] UserLimits& limits();
    [[nodiscard]] const UserLimits& limits() const;

    /// Connection flags (Go: BearerToken / ProxyRequired /
    /// AllowedConnectionTypes on UserPermissionLimits). bearer_token skips
    /// nonce-signing at connect (websocket/browser clients); proxy_required is
    /// a nats-server 2.11+ feature; connection types are ConnectionType::*
    /// strings, unvalidated here (as in Go — the server enforces them).
    void setBearerToken(bool bearer);
    [[nodiscard]] bool isBearerToken() const;
    void setProxyRequired(bool required);
    [[nodiscard]] bool proxyRequired() const;
    [[nodiscard]] std::vector<std::string>& allowedConnectionTypes();
    [[nodiscard]] const std::vector<std::string>& allowedConnectionTypes() const;

    /// Scoped users carry NO permissions/limits of their own — the server
    /// applies the issuing scope's template (Go: SetScoped). setScoped(false)
    /// restores the -1 no-limit defaults.
    void setScoped(bool scoped);
    /// True when no permission or limit is set (Go: HasEmptyPermissions) —
    /// required of users issued by a scoped signing key.
    [[nodiscard]] bool hasEmptyPermissions() const;

private:
    friend std::unique_ptr<UserClaims> decodeUserClaims(const std::string&);
    class Impl;
    std::unique_ptr<Impl> impl_;
};

/// Decode a user JWT
[[nodiscard]] std::unique_ptr<UserClaims> decodeUserClaims(const std::string& jwt);

/// Format a user JWT and seed into a creds file
[[nodiscard]] std::string formatUserConfig(const std::string& jwt, const std::string& seed);

}
