#include "jwt/authorization_claims.hpp"
#include "jwt/jwt_constants.hpp"
#include "jwt/jwt_errors.hpp"
#include "base64url.hpp"
#include "jwt_utils.hpp"
#include <nkeys/nkeys.hpp>
#include <nlohmann/json.hpp>

namespace jwt {

namespace {
    using json = nlohmann::json;

    // Shared decode preamble: parse, check header alg, parse payload, check
    // nats.type/version, verify the signature against the embedded issuer.
    json decodePayloadOfType(const std::string& token, const char* type) {
        using namespace internal;
        auto parts = parseJwt(token);
        auto header_bytes = base64url_decode(parts.header_b64);
        json header;
        try {
            header = json::parse(std::string(header_bytes.begin(), header_bytes.end()));
        } catch (const json::exception& e) {
            throw MalformedTokenError(std::string("Invalid JWT header JSON: ") + e.what());
        }
        if (!header.contains("alg") || header["alg"] != JWT_ALGORITHM) {
            throw InvalidClaimsError(
                "Unsupported algorithm: expected '" + std::string(JWT_ALGORITHM) + "'");
        }
        auto payload_bytes = base64url_decode(parts.payload_b64);
        json payload;
        try {
            payload = json::parse(std::string(payload_bytes.begin(), payload_bytes.end()));
        } catch (const json::exception& e) {
            throw MalformedTokenError(std::string("Invalid JWT payload JSON: ") + e.what());
        }
        if (!payload.contains("nats") || !payload["nats"].is_object()) {
            throw InvalidClaimsError("Missing 'nats' object in JWT payload");
        }
        const auto& nats = payload["nats"];
        if (!nats.contains("type") || nats["type"] != type) {
            throw InvalidClaimsError(std::string("JWT type mismatch: expected '") + type + "'");
        }
        if (!nats.contains("version") || nats["version"] != JWT_VERSION) {
            throw InvalidClaimsError("Unsupported JWT version");
        }
        try {
            const std::string issuer = payload.at("iss").get<std::string>();
            (void)payload.at("sub").get<std::string>();
            (void)payload.at("iat").get<std::int64_t>();
            if (!verifySignature(issuer, parts.signing_input, parts.signature_b64)) {
                throw SignatureError("JWT signature verification failed");
            }
        } catch (const json::exception& e) {
            throw MalformedTokenError(std::string("Invalid JWT payload: ") + e.what());
        }
        return payload;
    }

    void putIfSet(json& o, const char* key, const std::string& v) {
        if (!v.empty()) o[key] = v; else o.erase(key);
    }
    void putIfSet(json& o, const char* key, const std::vector<std::string>& v) {
        if (!v.empty()) o[key] = v; else o.erase(key);
    }

    json serverIdToJson(const ServerID& s) {
        json o = {{"name", s.name}, {"host", s.host}, {"id", s.id}};  // never omitted
        putIfSet(o, "version", s.version);
        putIfSet(o, "cluster", s.cluster);
        putIfSet(o, "tags", s.tags);
        putIfSet(o, "xkey", s.xkey);
        return o;
    }
    ServerID serverIdFromJson(const json& j) {
        ServerID s;
        s.name = j.value("name", "");
        s.host = j.value("host", "");
        s.id = j.value("id", "");
        s.version = j.value("version", "");
        s.cluster = j.value("cluster", "");
        if (j.contains("tags") && j["tags"].is_array()) s.tags = j["tags"].get<std::vector<std::string>>();
        s.xkey = j.value("xkey", "");
        return s;
    }

    json clientInfoToJson(const ClientInformation& c) {
        json o = json::object();
        putIfSet(o, "host", c.host);
        if (c.id != 0) o["id"] = c.id;
        putIfSet(o, "user", c.user);
        putIfSet(o, "name", c.name);
        putIfSet(o, "tags", c.tags);
        putIfSet(o, "name_tag", c.nameTag);
        putIfSet(o, "kind", c.kind);
        putIfSet(o, "type", c.type);
        putIfSet(o, "mqtt_id", c.mqttId);
        putIfSet(o, "nonce", c.nonce);
        return o;
    }
    ClientInformation clientInfoFromJson(const json& j) {
        ClientInformation c;
        c.host = j.value("host", "");
        c.id = j.value("id", std::uint64_t{0});
        c.user = j.value("user", "");
        c.name = j.value("name", "");
        if (j.contains("tags") && j["tags"].is_array()) c.tags = j["tags"].get<std::vector<std::string>>();
        c.nameTag = j.value("name_tag", "");
        c.kind = j.value("kind", "");
        c.type = j.value("type", "");
        c.mqttId = j.value("mqtt_id", "");
        c.nonce = j.value("nonce", "");
        return c;
    }

    json connectOptsToJson(const ConnectOptions& c) {
        json o = json::object();
        putIfSet(o, "jwt", c.jwt);
        putIfSet(o, "nkey", c.nkey);
        putIfSet(o, "sig", c.signedNonce);
        putIfSet(o, "auth_token", c.token);
        putIfSet(o, "user", c.username);
        putIfSet(o, "pass", c.password);
        putIfSet(o, "name", c.name);
        putIfSet(o, "lang", c.lang);
        putIfSet(o, "version", c.version);
        o["protocol"] = c.protocol;  // Go: no omitempty
        return o;
    }
    ConnectOptions connectOptsFromJson(const json& j) {
        ConnectOptions c;
        c.jwt = j.value("jwt", "");
        c.nkey = j.value("nkey", "");
        c.signedNonce = j.value("sig", "");
        c.token = j.value("auth_token", "");
        c.username = j.value("user", "");
        c.password = j.value("pass", "");
        c.name = j.value("name", "");
        c.lang = j.value("lang", "");
        c.version = j.value("version", "");
        c.protocol = j.value("protocol", 0);
        return c;
    }

    json clientTlsToJson(const ClientTLS& t) {
        json o = json::object();
        putIfSet(o, "version", t.version);
        putIfSet(o, "cipher", t.cipher);
        putIfSet(o, "certs", t.certs);
        if (!t.verifiedChains.empty()) o["verified_chains"] = t.verifiedChains;
        return o;
    }
    ClientTLS clientTlsFromJson(const json& j) {
        ClientTLS t;
        t.version = j.value("version", "");
        t.cipher = j.value("cipher", "");
        if (j.contains("certs") && j["certs"].is_array()) t.certs = j["certs"].get<std::vector<std::string>>();
        if (j.contains("verified_chains") && j["verified_chains"].is_array())
            t.verifiedChains = j["verified_chains"].get<std::vector<std::vector<std::string>>>();
        return t;
    }

    json basePayload(std::int64_t iat, const std::string& iss, const std::string& sub,
                     const std::optional<std::string>& name, std::int64_t exp, const std::string& aud) {
        json p = {{"iat", iat}, {"iss", iss}, {"sub", sub}};
        if (name) p["name"] = *name;
        if (exp > 0) p["exp"] = exp;
        if (!aud.empty()) p["aud"] = aud;
        return p;
    }
} // namespace

// ───────────────────────── AuthorizationRequestClaims ─────────────────────────

class AuthorizationRequestClaims::Impl {
public:
    json natsRaw_ = json::object();
    std::string subject_;
    std::string issuer_;
    std::optional<std::string> name_;
    std::int64_t issuedAt_ = 0;
    std::int64_t expires_ = 0;
    std::string audience_;
    ServerID server_;
    std::string userNkey_;
    ClientInformation client_;
    ConnectOptions connect_;
    std::optional<ClientTLS> tls_;
    std::string requestNonce_;
};

AuthorizationRequestClaims::AuthorizationRequestClaims(const std::string& subject)
    : impl_(std::make_unique<Impl>()) {
    impl_->subject_ = subject;
}
AuthorizationRequestClaims::~AuthorizationRequestClaims() = default;

std::string AuthorizationRequestClaims::subject() const { return impl_->subject_; }
std::string AuthorizationRequestClaims::issuer() const { return impl_->issuer_; }
std::optional<std::string> AuthorizationRequestClaims::name() const { return impl_->name_; }
std::int64_t AuthorizationRequestClaims::issuedAt() const { return impl_->issuedAt_; }
std::int64_t AuthorizationRequestClaims::expires() const { return impl_->expires_; }
void AuthorizationRequestClaims::setName(const std::string& name) { impl_->name_ = name; }
void AuthorizationRequestClaims::setExpires(std::int64_t exp) { impl_->expires_ = exp; }
void AuthorizationRequestClaims::setAudience(const std::string& audience) { impl_->audience_ = audience; }
std::string AuthorizationRequestClaims::audience() const { return impl_->audience_; }
ServerID& AuthorizationRequestClaims::server() { return impl_->server_; }
const ServerID& AuthorizationRequestClaims::server() const { return impl_->server_; }
void AuthorizationRequestClaims::setUserNkey(const std::string& k) { impl_->userNkey_ = k; }
std::string AuthorizationRequestClaims::userNkey() const { return impl_->userNkey_; }
ClientInformation& AuthorizationRequestClaims::clientInformation() { return impl_->client_; }
const ClientInformation& AuthorizationRequestClaims::clientInformation() const { return impl_->client_; }
ConnectOptions& AuthorizationRequestClaims::connectOptions() { return impl_->connect_; }
const ConnectOptions& AuthorizationRequestClaims::connectOptions() const { return impl_->connect_; }
std::optional<ClientTLS>& AuthorizationRequestClaims::tls() { return impl_->tls_; }
const std::optional<ClientTLS>& AuthorizationRequestClaims::tls() const { return impl_->tls_; }
void AuthorizationRequestClaims::setRequestNonce(const std::string& nonce) { impl_->requestNonce_ = nonce; }
std::string AuthorizationRequestClaims::requestNonce() const { return impl_->requestNonce_; }

void AuthorizationRequestClaims::validate() const {
    if (impl_->subject_.empty()) {
        throw InvalidClaimsError("Authorization request subject cannot be empty");
    }
    // Go: "User nkey is required" / "not a valid user public key"
    if (impl_->userNkey_.empty()) {
        throw InvalidClaimsError("Authorization request user nkey is required");
    }
    if (!nkeys::IsValidPublicUserKey(impl_->userNkey_)) {
        throw InvalidClaimsError("Authorization request user nkey \"" + impl_->userNkey_ +
                                 "\" is not a valid user public key");
    }
}

std::string AuthorizationRequestClaims::encode(const std::string& seed) const {
    auto keypair = nkeys::FromSeed(seed);
    return encodeWithSigner(keypair->publicString(), internal::signerFor(*keypair));
}

std::string AuthorizationRequestClaims::encodeWithSigner(const std::string& issuerPublicKey,
                                                         const SignFn& sign) const {
    using namespace internal;
    // Go's ExpectedPrefixes for requests: servers only.
    impl_->issuer_ = issuerPublicKey;
    if (!nkeys::IsValidPublicServerKey(impl_->issuer_)) {
        throw InvalidClaimsError("Authorization request JWTs must be signed by a server key");
    }
    impl_->issuedAt_ = getCurrentTimestamp();
    validate();

    json payload = basePayload(impl_->issuedAt_, impl_->issuer_, impl_->subject_, impl_->name_,
                               impl_->expires_, impl_->audience_);
    json nats = impl_->natsRaw_;
    nats["server_id"] = serverIdToJson(impl_->server_);
    nats["user_nkey"] = impl_->userNkey_;
    nats["client_info"] = clientInfoToJson(impl_->client_);
    nats["connect_opts"] = connectOptsToJson(impl_->connect_);
    if (impl_->tls_) nats["client_tls"] = clientTlsToJson(*impl_->tls_); else nats.erase("client_tls");
    putIfSet(nats, "request_nonce", impl_->requestNonce_);
    nats["type"] = "authorization_request";
    nats["version"] = JWT_VERSION;
    payload["nats"] = nats;
    payload["jti"] = computeJti(payload.dump());
    return signAndAssemble(payload.dump(), issuerPublicKey, sign);
}

std::unique_ptr<AuthorizationRequestClaims> decodeAuthorizationRequestClaims(const std::string& jwt) {
    json payload = decodePayloadOfType(jwt, "authorization_request");
    const auto& nats = payload["nats"];
    auto claims = std::make_unique<AuthorizationRequestClaims>(payload["sub"].get<std::string>());
    auto& d = *claims->impl_;
    d.natsRaw_ = nats;
    d.issuer_ = payload["iss"].get<std::string>();
    d.issuedAt_ = payload["iat"].get<std::int64_t>();
    if (payload.contains("name")) d.name_ = payload["name"].get<std::string>();
    if (payload.contains("exp")) d.expires_ = payload["exp"].get<std::int64_t>();
    d.audience_ = payload.value("aud", "");
    if (nats.contains("server_id") && nats["server_id"].is_object()) d.server_ = serverIdFromJson(nats["server_id"]);
    d.userNkey_ = nats.value("user_nkey", "");
    if (nats.contains("client_info") && nats["client_info"].is_object())
        d.client_ = clientInfoFromJson(nats["client_info"]);
    if (nats.contains("connect_opts") && nats["connect_opts"].is_object())
        d.connect_ = connectOptsFromJson(nats["connect_opts"]);
    if (nats.contains("client_tls") && nats["client_tls"].is_object())
        d.tls_ = clientTlsFromJson(nats["client_tls"]);
    d.requestNonce_ = nats.value("request_nonce", "");
    claims->validate();
    return claims;
}

// ───────────────────────── AuthorizationResponseClaims ─────────────────────────

class AuthorizationResponseClaims::Impl {
public:
    json natsRaw_ = json::object();
    std::string subject_;
    std::string issuer_;
    std::optional<std::string> name_;
    std::int64_t issuedAt_ = 0;
    std::int64_t expires_ = 0;
    std::string audience_;
    std::string jwt_;
    std::string error_;
    std::optional<std::string> issuerAccount_;
};

AuthorizationResponseClaims::AuthorizationResponseClaims(const std::string& userPublicKey)
    : impl_(std::make_unique<Impl>()) {
    impl_->subject_ = userPublicKey;
}
AuthorizationResponseClaims::~AuthorizationResponseClaims() = default;

std::string AuthorizationResponseClaims::subject() const { return impl_->subject_; }
std::string AuthorizationResponseClaims::issuer() const { return impl_->issuer_; }
std::optional<std::string> AuthorizationResponseClaims::name() const { return impl_->name_; }
std::int64_t AuthorizationResponseClaims::issuedAt() const { return impl_->issuedAt_; }
std::int64_t AuthorizationResponseClaims::expires() const { return impl_->expires_; }
void AuthorizationResponseClaims::setName(const std::string& name) { impl_->name_ = name; }
void AuthorizationResponseClaims::setExpires(std::int64_t exp) { impl_->expires_ = exp; }
void AuthorizationResponseClaims::setAudience(const std::string& a) { impl_->audience_ = a; }
std::string AuthorizationResponseClaims::audience() const { return impl_->audience_; }
void AuthorizationResponseClaims::setJwt(const std::string& j) { impl_->jwt_ = j; }
std::string AuthorizationResponseClaims::jwt() const { return impl_->jwt_; }
void AuthorizationResponseClaims::setError(const std::string& e) { impl_->error_ = e; }
std::string AuthorizationResponseClaims::error() const { return impl_->error_; }
void AuthorizationResponseClaims::setIssuerAccount(const std::string& a) { impl_->issuerAccount_ = a; }
std::optional<std::string> AuthorizationResponseClaims::issuerAccount() const { return impl_->issuerAccount_; }

void AuthorizationResponseClaims::validate() const {
    // Go's Validate, verbatim rules
    if (!nkeys::IsValidPublicUserKey(impl_->subject_)) {
        throw InvalidClaimsError("Authorization response subject must be a user public key");
    }
    if (!nkeys::IsValidPublicServerKey(impl_->audience_)) {
        throw InvalidClaimsError("Authorization response audience must be a server public key");
    }
    if (impl_->error_.empty() && impl_->jwt_.empty()) {
        throw InvalidClaimsError("Authorization response requires error or jwt");
    }
    if (!impl_->error_.empty() && !impl_->jwt_.empty()) {
        throw InvalidClaimsError("Authorization response may set only error or jwt");
    }
    if (impl_->issuerAccount_ && !nkeys::IsValidPublicAccountKey(*impl_->issuerAccount_)) {
        throw InvalidClaimsError("Authorization response issuer_account is not an account public key");
    }
}

std::string AuthorizationResponseClaims::encode(const std::string& seed) const {
    auto keypair = nkeys::FromSeed(seed);
    return encodeWithSigner(keypair->publicString(), internal::signerFor(*keypair));
}

std::string AuthorizationResponseClaims::encodeWithSigner(const std::string& issuerPublicKey,
                                                          const SignFn& sign) const {
    using namespace internal;
    // Go's ExpectedPrefixes for responses: accounts only.
    impl_->issuer_ = issuerPublicKey;
    if (!nkeys::IsValidPublicAccountKey(impl_->issuer_)) {
        throw InvalidClaimsError("Authorization response JWTs must be signed by an account key");
    }
    impl_->issuedAt_ = getCurrentTimestamp();
    validate();

    json payload = basePayload(impl_->issuedAt_, impl_->issuer_, impl_->subject_, impl_->name_,
                               impl_->expires_, impl_->audience_);
    json nats = impl_->natsRaw_;
    putIfSet(nats, "jwt", impl_->jwt_);
    putIfSet(nats, "error", impl_->error_);
    if (impl_->issuerAccount_) nats["issuer_account"] = *impl_->issuerAccount_;
    else nats.erase("issuer_account");
    nats["type"] = "authorization_response";
    nats["version"] = JWT_VERSION;
    payload["nats"] = nats;
    payload["jti"] = computeJti(payload.dump());
    return signAndAssemble(payload.dump(), issuerPublicKey, sign);
}

std::unique_ptr<AuthorizationResponseClaims> decodeAuthorizationResponseClaims(const std::string& jwt) {
    json payload = decodePayloadOfType(jwt, "authorization_response");
    const auto& nats = payload["nats"];
    auto claims = std::make_unique<AuthorizationResponseClaims>(payload["sub"].get<std::string>());
    auto& d = *claims->impl_;
    d.natsRaw_ = nats;
    d.issuer_ = payload["iss"].get<std::string>();
    d.issuedAt_ = payload["iat"].get<std::int64_t>();
    if (payload.contains("name")) d.name_ = payload["name"].get<std::string>();
    if (payload.contains("exp")) d.expires_ = payload["exp"].get<std::int64_t>();
    d.audience_ = payload.value("aud", "");
    d.jwt_ = nats.value("jwt", "");
    d.error_ = nats.value("error", "");
    if (nats.contains("issuer_account")) d.issuerAccount_ = nats["issuer_account"].get<std::string>();
    claims->validate();
    return claims;
}

}
