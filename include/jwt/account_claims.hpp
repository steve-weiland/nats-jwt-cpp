#pragma once
#include "jwt/claims.hpp"
#include "jwt/permissions.hpp"
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace jwt {

/// Wildcard revocation subject — revokes every key issued at/before the
/// revocation timestamp (Go: jwt.All).
inline constexpr const char* RevokeAll = "*";

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

/// Export/import kind (Go: ExportType) — "stream" or "service" on the wire.
enum class ExportType { Unknown, Stream, Service };

/// Latency tracking config for a service export (Go: ServiceLatency).
/// sampling is 1..100 (percent) or 0, which serializes as "headers".
struct ServiceLatency {
    int sampling = 0;
    std::string results;
};

/// A subject this account offers to other accounts (Go: Export).
struct Export {
    std::string name;
    std::string subject;
    ExportType type = ExportType::Unknown;
    bool tokenReq = false;                              ///< private: importers need an activation token
    std::map<std::string, std::int64_t> revocations;    ///< revoked activations
    std::string responseType;                           ///< services: "", "Singleton", "Stream", "Chunked"
    std::int64_t responseThresholdNanos = 0;            ///< services only; Go time.Duration
    std::optional<ServiceLatency> latency;              ///< services only
    unsigned accountTokenPosition = 0;                  ///< wildcard subjects only
    bool advertise = false;
    bool allowTrace = false;                            ///< services only (exports)
    std::string description;
    std::string infoURL;
};

/// A subject this account consumes from another account (Go: Import).
struct Import {
    std::string name;
    std::string subject;
    std::string account;        ///< the exporting account's public key
    std::string token;          ///< activation JWT (required for private exports)
    std::string to;             ///< deprecated — use localSubject
    std::string localSubject;   ///< local name for the imported subject
    ExportType type = ExportType::Unknown;
    bool share = false;         ///< services only: share request info for latency
    bool allowTrace = false;    ///< streams only (imports)
};

/// Wildcard for ExternalAuthorization::allowedAccounts — the callout may
/// place users in ANY account (Go: jwt.AnyAccount). Must then be the only entry.
inline constexpr const char* AnyAccount = "*";

/// Auth-callout configuration of an account (Go: ExternalAuthorization).
/// When authUsers is non-empty, nats-server delegates authentication of
/// every other user connecting into this account to the callout service
/// (which itself connects as one of authUsers). allowedAccounts lists the
/// accounts the service may place clients into (or {AnyAccount}); xkey is
/// the service's x25519 public key when requests must be encrypted.
struct ExternalAuthorization {
    std::vector<std::string> authUsers;        ///< user public keys running the callout
    std::vector<std::string> allowedAccounts;  ///< account public keys, or {AnyAccount}
    std::string xkey;                          ///< curve ("X…") public key, optional

    [[nodiscard]] bool isEnabled() const { return !authUsers.empty(); }
    bool operator==(const ExternalAuthorization&) const = default;
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
    [[nodiscard]] std::string audience() const override;
    [[nodiscard]] std::int64_t notBefore() const override;
    [[nodiscard]] const std::vector<std::string>& tags() const override;
    [[nodiscard]] std::string encode(const std::string& seed) const override;
    [[nodiscard]] std::string encodeWithSigner(const std::string& issuerPublicKey,
                                               const SignFn& sign) const override;
    void validate(ValidationResults& vr) const override;
    void validate() const override;

    // Account-specific
    void setName(const std::string& name);
    void setExpires(std::int64_t exp);
    void setAudience(const std::string& audience);
    void setNotBefore(std::int64_t nbf);
    /// Mutable tags — jwt::addTags(claims.tags(), {...}) for Go's Add semantics.
    [[nodiscard]] std::vector<std::string>& tags();
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

    /// Auth callout config — mutate in place (Go: Account.Authorization).
    /// Always on the wire ({} when unset), like Go.
    [[nodiscard]] ExternalAuthorization& authorization();
    [[nodiscard]] const ExternalAuthorization& authorization() const;
    /// Adds callout service users (Go: EnableExternalAuthorization).
    void enableExternalAuthorization(const std::vector<std::string>& userPublicKeys);
    [[nodiscard]] bool hasExternalAuthorization() const;

    /// Revokes every JWT for pubKey (or RevokeAll) issued at/before NOW.
    void revoke(const std::string& pubKey);
    /// Revokes every JWT for pubKey issued at/before unixTimestamp. A newer
    /// existing revocation is kept (can't move a revocation into the future).
    void revokeAt(const std::string& pubKey, std::int64_t unixTimestamp);
    void clearRevocation(const std::string& pubKey);
    /// True if pubKey (or RevokeAll) is revoked at/after claimIssuedAt —
    /// pass the JWT's ISSUE time, never "now" (Go's warning applies here too).
    [[nodiscard]] bool isRevoked(const std::string& pubKey, std::int64_t claimIssuedAt) const;
    [[nodiscard]] const std::map<std::string, std::int64_t>& revocations() const;

    /// Subjects offered to / consumed from other accounts.
    [[nodiscard]] std::vector<Export>& exports();
    [[nodiscard]] const std::vector<Export>& exports() const;
    [[nodiscard]] std::vector<Import>& imports();
    [[nodiscard]] const std::vector<Import>& imports() const;

    void setDescription(const std::string& description);
    [[nodiscard]] std::string description() const;
    void setInfoURL(const std::string& url);
    [[nodiscard]] std::string infoURL() const;

private:
    friend std::unique_ptr<AccountClaims> decodeAccountClaims(const std::string&);
    void checkStructure() const;
    class Impl;
    std::unique_ptr<Impl> impl_;
};

/// Decode an account JWT
[[nodiscard]] std::unique_ptr<AccountClaims> decodeAccountClaims(const std::string& jwt);

}
