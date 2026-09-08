#include "jwt/account_claims.hpp"
#include "jwt/jwt_constants.hpp"
#include "base64url.hpp"
#include "jwt_utils.hpp"
#include <nlohmann/json.hpp>
#include <stdexcept>

namespace jwt {

class AccountClaims::Impl {
public:
    std::string subject_;
    std::string issuer_;
    std::optional<std::string> name_;
    std::int64_t issuedAt_ = 0;
    std::int64_t expires_ = 0;
    std::vector<std::string> signingKeys_;
};

AccountClaims::AccountClaims(const std::string& accountPublicKey)
    : impl_(std::make_unique<Impl>()) {
    impl_->subject_ = accountPublicKey;
}

AccountClaims::~AccountClaims() = default;

std::string AccountClaims::subject() const { return impl_->subject_; }
std::string AccountClaims::issuer() const { return impl_->issuer_; }
std::optional<std::string> AccountClaims::name() const { return impl_->name_; }
std::int64_t AccountClaims::issuedAt() const { return impl_->issuedAt_; }
std::int64_t AccountClaims::expires() const { return impl_->expires_; }

void AccountClaims::setName(const std::string& name) { impl_->name_ = name; }
void AccountClaims::setExpires(std::int64_t exp) { impl_->expires_ = exp; }
void AccountClaims::setIssuer(const std::string& issuerKey) { impl_->issuer_ = issuerKey; }
void AccountClaims::addSigningKey(const std::string& publicKey) {
    impl_->signingKeys_.push_back(publicKey);
}
const std::vector<std::string>& AccountClaims::signingKeys() const {
    return impl_->signingKeys_;
}

std::string AccountClaims::encode(const std::string& seed) const {
    using namespace internal;
    using json = nlohmann::json;

    validate();

    // Auto-generate JTI and issuedAt
    std::string jti = generateJti();
    std::int64_t iat = (impl_->issuedAt_ == 0) ? getCurrentTimestamp() : impl_->issuedAt_;

    // Build payload JSON
    json payload = {
        {"jti", jti},
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

    // NATS-specific claims
    json nats_claims = {
        {"type", "account"},
        {"version", JWT_VERSION}
    };
    if (!impl_->signingKeys_.empty()) {
        nats_claims["signing_keys"] = impl_->signingKeys_;
    }
    payload["nats"] = nats_claims;

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

    auto signature_bytes = signData(seed, signing_bytes);
    std::string signature_b64 = base64url_encode(signature_bytes);

    return signing_input + "." + signature_b64;
}

void AccountClaims::validate() const {
    if (impl_->subject_.empty()) {
        throw std::invalid_argument("Account subject cannot be empty");
    }
    if (impl_->issuer_.empty()) {
        throw std::invalid_argument("Account issuer cannot be empty (must be signed by Operator)");
    }
    if (impl_->subject_[0] != 'A') {
        throw std::invalid_argument("Account subject must start with 'A'");
    }
    if (impl_->issuer_[0] != 'O') {
        throw std::invalid_argument("Account issuer must be an Operator (start with 'O')");
    }
    if (impl_->expires_ > 0 && impl_->issuedAt_ > 0 &&
        impl_->expires_ <= impl_->issuedAt_) {
        throw std::invalid_argument("Expiration must be after issuedAt");
    }
}

std::unique_ptr<AccountClaims> decodeAccountClaims(const std::string& jwt) {
    using namespace internal;
    using json = nlohmann::json;

    // Parse JWT into its three components
    auto parts = parseJwt(jwt);

    // Decode and validate header
    auto header_bytes = base64url_decode(parts.header_b64);
    std::string header_json(header_bytes.begin(), header_bytes.end());
    auto header = json::parse(header_json);

    if (!header.contains("alg") || header["alg"] != JWT_ALGORITHM) {
        throw std::invalid_argument(
            "Unsupported algorithm: expected '" + std::string(JWT_ALGORITHM) + "'"
        );
    }

    // Decode and parse payload
    auto payload_bytes = base64url_decode(parts.payload_b64);
    std::string payload_json(payload_bytes.begin(), payload_bytes.end());
    auto payload = json::parse(payload_json);

    // Validate NATS-specific claims
    if (!payload.contains("nats")) {
        throw std::invalid_argument("Missing 'nats' object in JWT payload");
    }
    auto nats = payload["nats"];

    if (!nats.contains("type") || nats["type"] != "account") {
        throw std::invalid_argument(
            "JWT type mismatch: expected 'account', got '" +
            (nats.contains("type") ? nats["type"].get<std::string>() : "missing") + "'"
        );
    }

    if (!nats.contains("version") || nats["version"] != JWT_VERSION) {
        throw std::invalid_argument(
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
        throw std::invalid_argument("JWT signature verification failed");
    }
    std::int64_t iat = payload.at("iat").get<std::int64_t>();

    // Create AccountClaims object
    auto claims = std::make_unique<AccountClaims>(subject);

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
