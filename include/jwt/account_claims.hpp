#pragma once
#include "jwt/claims.hpp"
#include "jwt/permissions.hpp"
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace jwt {

/// JetStream limits (Go: JetStreamLimits) — 0 means disabled, -1 unlimited.
/// On the wire these fields sit FLAT inside the account's "limits" object.
struct JetStreamLimits {
    std::int64_t memStorage = 0;
    std::int64_t diskStorage = 0;
    std::int64_t streams = 0;
    std::int64_t consumer = 0;
    std::int64_t maxAckPending = 0;
    std::int64_t memoryMaxStreamBytes = 0;
    std::int64_t diskMaxStreamBytes = 0;
    bool maxBytesRequired = false;

    bool operator==(const JetStreamLimits&) const = default;
};

/// Account limits (Go: OperatorLimits) — -1 = unlimited; absent-on-wire
/// bools are false. Plain jetStream and tieredLimits are mutually exclusive.
struct AccountLimits {
    std::int64_t subs = -1;
    std::int64_t data = -1;
    std::int64_t payload = -1;
    std::int64_t imports = -1;
    std::int64_t exports = -1;
    bool wildcardExports = true;
    bool disallowBearer = false;
    std::int64_t conn = -1;
    std::int64_t leafNodeConn = -1;
    JetStreamLimits jetStream;
    std::map<std::string, JetStreamLimits> tieredLimits;  ///< "R1"/"R3" → limits
};

/// One weighted subject mapping (Go: WeightedMapping). weight 0 means 100.
struct WeightedMapping {
    std::string subject;
    std::uint8_t weight = 0;
    std::string cluster;
};

/// Account-level claims (middle of trust hierarchy)
class AccountClaims : public Claims {
public:
    /// Create account claims with the given public key
    explicit AccountClaims(const std::string& accountPublicKey);
    ~AccountClaims() override;

    // Claims interface
    [[nodiscard]] std::string subject() const override;
    [[nodiscard]] std::string issuer() const override;
    [[nodiscard]] std::optional<std::string> name() const override;
    [[nodiscard]] std::int64_t issuedAt() const override;
    [[nodiscard]] std::int64_t expires() const override;
    [[nodiscard]] std::string encode(const std::string& seed) const override;
    void validate() const override;

    // Account-specific
    void setName(const std::string& name);
    void setExpires(std::int64_t exp);
    void setIssuer(const std::string& issuerKey);
    void addSigningKey(const std::string& publicKey);
    [[nodiscard]] const std::vector<std::string>& signingKeys() const;

    /// Attaches a SCOPED signing key: users issued by scope.key get the
    /// scope's permission/limit template applied by the server (and must
    /// themselves carry none — see UserClaims::setScoped). The key is also
    /// listed in signingKeys().
    void setScope(const UserScope& scope);
    /// The scope for a signing key, if that key is scoped.
    [[nodiscard]] std::optional<UserScope> getScope(const std::string& signingKey) const;

    /// Account limits — mutate in place: claims.limits().conn = 10;
    [[nodiscard]] AccountLimits& limits();
    [[nodiscard]] const AccountLimits& limits() const;

    /// Default pub/sub permissions for users of this account that carry none.
    [[nodiscard]] Permissions& defaultPermissions();
    [[nodiscard]] const Permissions& defaultPermissions() const;

    /// Weighted subject mappings: from-subject → weighted destinations.
    [[nodiscard]] std::map<std::string, std::vector<WeightedMapping>>& mappings();
    [[nodiscard]] const std::map<std::string, std::vector<WeightedMapping>>& mappings() const;

    void setDescription(const std::string& description);
    [[nodiscard]] std::string description() const;
    void setInfoURL(const std::string& url);
    [[nodiscard]] std::string infoURL() const;

private:
    friend std::unique_ptr<AccountClaims> decodeAccountClaims(const std::string&);
    class Impl;
    std::unique_ptr<Impl> impl_;
};

/// Decode an account JWT
[[nodiscard]] std::unique_ptr<AccountClaims> decodeAccountClaims(const std::string& jwt);

}
