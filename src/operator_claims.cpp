#include "jwt/operator_claims.hpp"
#include "jwt/jwt_constants.hpp"
#include "jwt/jwt_errors.hpp"
#include "base64url.hpp"
#include "jwt_utils.hpp"
#include <cctype>
#include <nkeys/nkeys.hpp>
#include <nlohmann/json.hpp>
#include <stdexcept>

namespace jwt {

namespace {

    // Minimal URL split faithful to the Go checks: scheme presence, user-info
    // detection, path detection. (Go uses net/url; the rules we enforce are
    // exactly the ones its Validate checks.)
    struct MiniURL {
        std::string scheme, authority, path;
        bool hasUserInfo = false, valid = false;
    };

    MiniURL splitURL(const std::string& url) {
        MiniURL out;
        auto sep = url.find("://");
        if (sep == std::string::npos || sep == 0) return out;
        out.scheme = url.substr(0, sep);
        for (auto& c : out.scheme) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        auto rest = url.substr(sep + 3);
        auto slash = rest.find('/');
        out.authority = slash == std::string::npos ? rest : rest.substr(0, slash);
        out.path = slash == std::string::npos ? "" : rest.substr(slash);
        out.hasUserInfo = out.authority.find('@') != std::string::npos;
        out.valid = !out.authority.empty();
        return out;
    }

    void validateOperatorWiring(const std::string& accountServerURL,
                                const std::vector<std::string>& serviceURLs,
                                const std::string& systemAccount,
                                const std::string& assertServerVersion,
                                const std::vector<std::string>& signingKeys) {
        if (!accountServerURL.empty() && !splitURL(accountServerURL).valid) {
            throw InvalidClaimsError("account server url \"" + accountServerURL +
                                     "\" requires a protocol");
        }
        for (const auto& u : serviceURLs) {
            if (u.empty()) continue;
            auto parsed = splitURL(u);
            if (!parsed.valid) {
                throw InvalidClaimsError("error parsing operator service url \"" + u + "\"");
            }
            if (parsed.hasUserInfo) {
                throw InvalidClaimsError("operator service url \"" + u +
                                         "\" - credentials are not supported");
            }
            if (!parsed.path.empty()) {
                throw InvalidClaimsError("operator service url \"" + u +
                                         "\" - paths are not supported");
            }
            if (parsed.scheme != "nats" && parsed.scheme != "tls" &&
                parsed.scheme != "ws" && parsed.scheme != "wss") {
                throw InvalidClaimsError("operator service url \"" + u +
                                         "\" - protocol not supported (nats, tls, ws, wss only)");
            }
        }
        for (const auto& k : signingKeys) {
            if (!nkeys::IsValidPublicOperatorKey(k)) {
                throw InvalidClaimsError(k + " is not an operator public key");
            }
        }
        if (!systemAccount.empty() && !nkeys::IsValidPublicAccountKey(systemAccount)) {
            throw InvalidClaimsError(systemAccount + " is not an account public key");
        }
        if (!assertServerVersion.empty()) {
            int dots = 0;
            bool ok = !assertServerVersion.empty();
            std::string part;
            auto checkPart = [&](const std::string& p) {
                return !p.empty() && p.find_first_not_of("0123456789") == std::string::npos;
            };
            for (char c : assertServerVersion) {
                if (c == '.') { ++dots; ok = ok && checkPart(part); part.clear(); }
                else part += c;
            }
            ok = ok && checkPart(part) && dots == 2;
            if (!ok) {
                throw InvalidClaimsError(
                    "asserted server version must be of the form <major>.<minor>.<update>");
            }
        }
    }

} // namespace

class OperatorClaims::Impl {
public:
    // The full nats object as decoded (or Go's defaults for fresh claims):
    // encode re-serializes it so un-ported fields survive decode→re-encode —
    // dropping them (or resetting to defaults) would silently change what a
    // re-signed JWT grants.
    nlohmann::json natsRaw_ = nlohmann::json::object();
    std::string subject_;
    std::string issuer_;
    std::optional<std::string> name_;
    std::int64_t issuedAt_ = 0;
    std::int64_t expires_ = 0;
    std::vector<std::string> signingKeys_;
    std::string accountServerURL_;
    std::vector<std::string> operatorServiceURLs_;
    std::string systemAccount_;
    std::string assertServerVersion_;
    bool strictSigningKeyUsage_ = false;
};

OperatorClaims::OperatorClaims(const std::string& operatorPublicKey)
    : impl_(std::make_unique<Impl>()) {
    impl_->subject_ = operatorPublicKey;
    impl_->issuer_ = operatorPublicKey;  // Self-signed
}

OperatorClaims::~OperatorClaims() = default;

std::string OperatorClaims::subject() const { return impl_->subject_; }
std::string OperatorClaims::issuer() const { return impl_->issuer_; }
std::optional<std::string> OperatorClaims::name() const { return impl_->name_; }
std::int64_t OperatorClaims::issuedAt() const { return impl_->issuedAt_; }
std::int64_t OperatorClaims::expires() const { return impl_->expires_; }

void OperatorClaims::setName(const std::string& name) { impl_->name_ = name; }
void OperatorClaims::setExpires(std::int64_t exp) { impl_->expires_ = exp; }
void OperatorClaims::addSigningKey(const std::string& publicKey) {
    impl_->signingKeys_.push_back(publicKey);
}
const std::vector<std::string>& OperatorClaims::signingKeys() const {
    return impl_->signingKeys_;
}

void OperatorClaims::setAccountServerURL(const std::string& url) {
    impl_->accountServerURL_ = url;
}
std::string OperatorClaims::accountServerURL() const { return impl_->accountServerURL_; }
std::vector<std::string>& OperatorClaims::operatorServiceURLs() {
    return impl_->operatorServiceURLs_;
}
const std::vector<std::string>& OperatorClaims::operatorServiceURLs() const {
    return impl_->operatorServiceURLs_;
}
void OperatorClaims::setSystemAccount(const std::string& accountPublicKey) {
    impl_->systemAccount_ = accountPublicKey;
}
std::string OperatorClaims::systemAccount() const { return impl_->systemAccount_; }
void OperatorClaims::setAssertServerVersion(const std::string& version) {
    impl_->assertServerVersion_ = version;
}
std::string OperatorClaims::assertServerVersion() const { return impl_->assertServerVersion_; }
void OperatorClaims::setStrictSigningKeyUsage(bool strict) {
    impl_->strictSigningKeyUsage_ = strict;
}
bool OperatorClaims::strictSigningKeyUsage() const { return impl_->strictSigningKeyUsage_; }

std::string OperatorClaims::encode(const std::string& seed) const {
    using namespace internal;
    using json = nlohmann::json;

    // Go's doEncode: the issuer IS the signing key — derived, never taken on
    // trust from a setter (iss can then never disagree with the signature) —
    // and iat is stamped fresh at every encode.
    auto keypair = nkeys::FromSeed(seed);
    impl_->issuer_ = keypair->publicString();
    if (!nkeys::IsValidPublicOperatorKey(impl_->issuer_)) {
        throw InvalidClaimsError("Operator JWTs must be signed by an operator key");
    }
    impl_->issuedAt_ = getCurrentTimestamp();

    validate();

    std::int64_t iat = impl_->issuedAt_;

    // Build payload JSON — jti is computed OVER this serialization with the
    // jti field absent (Go: c.ID="" then hash), then inserted.
    json payload = {
        {"iat", iat},
        {"iss", impl_->issuer_},
        {"sub", impl_->subject_}
    };

    if (impl_->name_) {
        payload["name"] = *impl_->name_;
    }
    if (impl_->expires_ > 0) {
        payload["exp"] = impl_->expires_;
    }

    validateOperatorWiring(impl_->accountServerURL_, impl_->operatorServiceURLs_,
                           impl_->systemAccount_, impl_->assertServerVersion_,
                           impl_->signingKeys_);

    // NATS-specific claims: start from the carried nats object, then
    // overwrite the fields this port manages.
    json nats_claims = impl_->natsRaw_;
    if (!impl_->signingKeys_.empty()) {
        nats_claims["signing_keys"] = impl_->signingKeys_;
    } else {
        nats_claims.erase("signing_keys");
    }
    if (!impl_->accountServerURL_.empty())
        nats_claims["account_server_url"] = impl_->accountServerURL_;
    else nats_claims.erase("account_server_url");
    if (!impl_->operatorServiceURLs_.empty())
        nats_claims["operator_service_urls"] = impl_->operatorServiceURLs_;
    else nats_claims.erase("operator_service_urls");
    if (!impl_->systemAccount_.empty())
        nats_claims["system_account"] = impl_->systemAccount_;
    else nats_claims.erase("system_account");
    if (!impl_->assertServerVersion_.empty())
        nats_claims["assert_server_version"] = impl_->assertServerVersion_;
    else nats_claims.erase("assert_server_version");
    if (impl_->strictSigningKeyUsage_)
        nats_claims["strict_signing_key_usage"] = true;
    else nats_claims.erase("strict_signing_key_usage");
    nats_claims["type"] = "operator";
    nats_claims["version"] = JWT_VERSION;
    payload["nats"] = nats_claims;

    payload["jti"] = computeJti(payload.dump());

    // Create JWT: header.payload.signature
    std::string header_json = createHeader();
    std::string payload_json = payload.dump();

    // Convert strings to byte spans for encoding
    std::span<const std::uint8_t> header_bytes(
        reinterpret_cast<const std::uint8_t*>(header_json.data()),
        header_json.size()
    );
    std::span<const std::uint8_t> payload_bytes(
        reinterpret_cast<const std::uint8_t*>(payload_json.data()),
        payload_json.size()
    );

    std::string header_b64 = base64url_encode(header_bytes);
    std::string payload_b64 = base64url_encode(payload_bytes);

    // Sign "header.payload"
    std::string signing_input = header_b64 + "." + payload_b64;
    std::span<const std::uint8_t> signing_bytes(
        reinterpret_cast<const std::uint8_t*>(signing_input.data()),
        signing_input.size()
    );

    auto signature_bytes = keypair->sign(signing_bytes);
    std::string signature_b64 = base64url_encode(signature_bytes);

    return signing_input + "." + signature_b64;
}

void OperatorClaims::validate() const {
    if (impl_->subject_.empty()) {
        throw InvalidClaimsError("Operator subject cannot be empty");
    }
    if (impl_->issuer_.empty()) {
        throw InvalidClaimsError("Operator issuer cannot be empty");
    }
    if (impl_->subject_[0] != 'O') {
        throw InvalidClaimsError("Operator subject must start with 'O'");
    }
}

std::unique_ptr<OperatorClaims> decodeOperatorClaims(const std::string& jwt) {
    using namespace internal;
    using json = nlohmann::json;

    // Parse JWT into its three components
    auto parts = parseJwt(jwt);

    // Decode and validate header
    auto header_bytes = base64url_decode(parts.header_b64);
    std::string header_json(header_bytes.begin(), header_bytes.end());
    json header;
    try {
        header = json::parse(header_json);
    } catch (const json::exception& e) {
        throw MalformedTokenError(std::string("Invalid JWT header JSON: ") + e.what());
    }

    if (!header.contains("alg") || header["alg"] != JWT_ALGORITHM) {
        throw InvalidClaimsError(
            "Unsupported algorithm: expected '" + std::string(JWT_ALGORITHM) + "'"
        );
    }

    // Decode and parse payload
    auto payload_bytes = base64url_decode(parts.payload_b64);
    std::string payload_json(payload_bytes.begin(), payload_bytes.end());
    json payload;
    try {
        payload = json::parse(payload_json);
    } catch (const json::exception& e) {
        throw MalformedTokenError(std::string("Invalid JWT payload JSON: ") + e.what());
    }

    // Validate NATS-specific claims
    if (!payload.contains("nats")) {
        throw InvalidClaimsError("Missing 'nats' object in JWT payload");
    }
    auto nats = payload["nats"];

    if (!nats.contains("type") || nats["type"] != "operator") {
        throw InvalidClaimsError(
            "JWT type mismatch: expected 'operator', got '" +
            (nats.contains("type") ? nats["type"].get<std::string>() : "missing") + "'"
        );
    }

    if (!nats.contains("version") || nats["version"] != JWT_VERSION) {
        throw InvalidClaimsError(
            "Unsupported JWT version: expected " + std::to_string(JWT_VERSION)
        );
    }

    // Extract required fields
    std::string subject = payload.at("sub").get<std::string>();
    std::string issuer = payload.at("iss").get<std::string>();

    // Decode is AUTHENTICATED, as in Go: the signature over header.payload
    // must verify against the embedded issuer, or the claims never reach the
    // caller (an unauthenticated decode hands out attacker-edited claims).
    if (!verifySignature(issuer, parts.signing_input, parts.signature_b64)) {
        throw SignatureError("JWT signature verification failed");
    }
    std::int64_t iat = payload.at("iat").get<std::int64_t>();

    // Create OperatorClaims object
    auto claims = std::make_unique<OperatorClaims>(subject);
    claims->impl_->natsRaw_ = nats;

    // Populate required fields (direct access via friend declaration)
    claims->impl_->issuer_ = issuer;
    claims->impl_->issuedAt_ = iat;

    // Populate optional fields
    if (payload.contains("name")) {
        claims->setName(payload["name"].get<std::string>());
    }

    if (payload.contains("exp")) {
        claims->setExpires(payload["exp"].get<std::int64_t>());
    }

    claims->impl_->accountServerURL_ = nats.value("account_server_url", "");
    if (nats.contains("operator_service_urls")) {
        claims->impl_->operatorServiceURLs_ =
            nats["operator_service_urls"].get<std::vector<std::string>>();
    }
    claims->impl_->systemAccount_ = nats.value("system_account", "");
    claims->impl_->assertServerVersion_ = nats.value("assert_server_version", "");
    claims->impl_->strictSigningKeyUsage_ = nats.value("strict_signing_key_usage", false);

    // Extract signing keys if present
    if (nats.contains("signing_keys") && nats["signing_keys"].is_array()) {
        for (const auto& key : nats["signing_keys"]) {
            claims->addSigningKey(key.get<std::string>());
        }
    }

    // Validate the decoded claims
    claims->validate();

    return claims;
}

}
