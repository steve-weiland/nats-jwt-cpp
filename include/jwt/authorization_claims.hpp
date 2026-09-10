#pragma once
#include "jwt/claims.hpp"
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace jwt {

/// Auth callout (Go: AuthorizationRequestClaims / AuthorizationResponseClaims).
/// nats-server delegates authentication to a service: it publishes an
/// authorization_request JWT it signed with its SERVER key, and the service
/// answers with an authorization_response JWT signed by the callout ACCOUNT
/// (or one of its signing keys, naming the account in issuer_account) that
/// carries either the user JWT to admit or an error.
///
/// Measured on nats-server 2.10 (operator mode): the request's `aud` is the
/// constant "nats-authorization-request", its `sub` the callout account; the
/// response's `sub` must be the request's user_nkey and its `aud` the
/// request's server_id.id.

/// Constant `aud` of every server-minted authorization request.
inline constexpr const char* AuthRequestAudience = "nats-authorization-request";

/// Static info about the requesting server (Go: ServerID). name/host/id are
/// always on the wire; the rest is omitempty.
struct ServerID {
    std::string name;
    std::string host;
    std::string id;
    std::string version;
    std::string cluster;
    std::vector<std::string> tags;
    std::string xkey;
    bool operator==(const ServerID&) const = default;
};

/// What the server knows about the connecting client (Go: ClientInformation).
struct ClientInformation {
    std::string host;
    std::uint64_t id = 0;
    std::string user;
    std::string name;
    std::vector<std::string> tags;
    std::string nameTag;
    std::string kind;
    std::string type;
    std::string mqttId;
    std::string nonce;
    bool operator==(const ClientInformation&) const = default;
};

/// The client's CONNECT options (Go: ConnectOptions). `protocol` is never
/// omitted on the wire; every other field is omitempty.
struct ConnectOptions {
    std::string jwt;
    std::string nkey;
    std::string signedNonce;   ///< "sig"
    std::string token;         ///< "auth_token"
    std::string username;      ///< "user"
    std::string password;      ///< "pass"
    std::string name;
    std::string lang;
    std::string version;
    int protocol = 0;
    bool operator==(const ConnectOptions&) const = default;
};

/// TLS state of the client connection, if any (Go: ClientTLS).
struct ClientTLS {
    std::string version;
    std::string cipher;
    std::vector<std::string> certs;                       ///< unverified peer certs, PEM
    std::vector<std::vector<std::string>> verifiedChains; ///< [0] is the peer cert
    bool operator==(const ClientTLS&) const = default;
};

/// What a server asks an auth callout service (Go: AuthorizationRequestClaims).
/// Issued by a SERVER key only.
class AuthorizationRequestClaims : public Claims {
public:
    /// subject: the callout account's public key (what the server puts there)
    explicit AuthorizationRequestClaims(const std::string& subject);
    ~AuthorizationRequestClaims() override;

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

    void setName(const std::string& name);
    void setExpires(std::int64_t exp);
    /// `aud` — the server sets AuthRequestAudience. Empty = absent.
    void setAudience(const std::string& audience);
    void setNotBefore(std::int64_t nbf);
    [[nodiscard]] std::vector<std::string>& tags();

    [[nodiscard]] ServerID& server();
    [[nodiscard]] const ServerID& server() const;
    /// The user public key the server generated for this connection; the
    /// response (and the user JWT inside it) must be for exactly this key.
    void setUserNkey(const std::string& userPublicKey);
    [[nodiscard]] std::string userNkey() const;
    [[nodiscard]] ClientInformation& clientInformation();
    [[nodiscard]] const ClientInformation& clientInformation() const;
    [[nodiscard]] ConnectOptions& connectOptions();
    [[nodiscard]] const ConnectOptions& connectOptions() const;
    [[nodiscard]] std::optional<ClientTLS>& tls();
    [[nodiscard]] const std::optional<ClientTLS>& tls() const;
    void setRequestNonce(const std::string& nonce);
    [[nodiscard]] std::string requestNonce() const;

private:
    friend std::unique_ptr<AuthorizationRequestClaims> decodeAuthorizationRequestClaims(const std::string&);
    void checkStructure() const;
    class Impl;
    std::unique_ptr<Impl> impl_;
};

/// Decode an authorization request (authenticated — the signature must verify
/// against the embedded server key).
[[nodiscard]] std::unique_ptr<AuthorizationRequestClaims>
decodeAuthorizationRequestClaims(const std::string& jwt);

// ---- xkey-encrypted callout traffic (beyond Go's jwt: this is nkeys + server
// logic there). Measured on nats-server 2.10: when the callout account's
// `authorization.xkey` is set, the request body is a NaCl sealed box ("xkv1"
// prefix) from the SERVER's curve key to that xkey; the server's curve public
// key is in the `Nats-Server-Xkey` header AND in the signed claim
// (server_id.xkey); the response may be sealed back to it or sent as plain
// JWT text — the server treats any body not starting with "eyJ" as sealed.

/// The server's rule for "is this body sealed?": it does not start with "eyJ".
[[nodiscard]] bool isSealedCalloutBody(std::span<const std::uint8_t> body);

/// Open a sealed request body with the service's curve seed ("SX…") and the
/// server's curve public key ("X…", from the Nats-Server-Xkey header) →
/// the request JWT text. A body that is not sealed is MalformedTokenError;
/// a box that does not open is nkeys' DecryptionError (key material).
[[nodiscard]] std::string openAuthorizationRequest(std::span<const std::uint8_t> sealedBody,
                                                   std::string_view serverXKey,
                                                   std::string_view serviceCurveSeed);

/// openAuthorizationRequest + authenticated decode + the check that makes the
/// unauthenticated header trustworthy: the SIGNED claim's server_id.xkey must
/// equal the header key the box was opened with (InvalidClaimsError otherwise).
[[nodiscard]] std::unique_ptr<AuthorizationRequestClaims>
decodeSealedAuthorizationRequest(std::span<const std::uint8_t> sealedBody,
                                 std::string_view serverXKey,
                                 std::string_view serviceCurveSeed);

/// Seal a response JWT to the server's curve key with the service's curve seed
/// (the server opens it with its pair + the account's xkey).
[[nodiscard]] std::vector<std::uint8_t> sealAuthorizationResponse(const std::string& responseJwt,
                                                                  std::string_view serverXKey,
                                                                  std::string_view serviceCurveSeed);

/// The callout service's answer (Go: AuthorizationResponseClaims). Issued by
/// an ACCOUNT key: the callout account itself, or one of its signing keys
/// with setIssuerAccount naming the account.
class AuthorizationResponseClaims : public Claims {
public:
    /// subject: the request's user_nkey
    explicit AuthorizationResponseClaims(const std::string& userPublicKey);
    ~AuthorizationResponseClaims() override;

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

    void setName(const std::string& name);
    void setExpires(std::int64_t exp);
    /// `aud` — REQUIRED: the requesting server's ID (a server public key).
    void setAudience(const std::string& serverPublicKey);
    void setNotBefore(std::int64_t nbf);
    [[nodiscard]] std::vector<std::string>& tags();
    /// The user JWT to admit (exactly one of jwt / error must be set).
    void setJwt(const std::string& userJwt);
    [[nodiscard]] std::string jwt() const;
    /// Why the client is refused (exactly one of jwt / error must be set).
    void setError(const std::string& error);
    [[nodiscard]] std::string error() const;
    /// When signed by an account SIGNING key: the account's public key.
    void setIssuerAccount(const std::string& accountPublicKey);
    [[nodiscard]] std::optional<std::string> issuerAccount() const;

private:
    friend std::unique_ptr<AuthorizationResponseClaims> decodeAuthorizationResponseClaims(const std::string&);
    void checkStructure() const;
    class Impl;
    std::unique_ptr<Impl> impl_;
};

/// Decode an authorization response (authenticated).
[[nodiscard]] std::unique_ptr<AuthorizationResponseClaims>
decodeAuthorizationResponseClaims(const std::string& jwt);

}
