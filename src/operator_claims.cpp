#include "jwt/operator_claims.hpp"
#include "jwt/jwt_constants.hpp"
#include "base64url.hpp"
#include "jwt_utils.hpp"
#include <nkeys/nkeys.hpp>
#include <nlohmann/json.hpp>
#include <stdexcept>

namespace jwt {

class OperatorClaims::Impl {
public:
    std::string subject_;
    std::string issuer_;
    std::optional<std::string> name_;
    std::int64_t issuedAt_ = 0;
    std::int64_t expires_ = 0;
    std::vector<std::string> signingKeys_;
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

std::string OperatorClaims::encode(const std::string& seed) const {
    using namespace internal;
    using json = nlohmann::json;

    // Go's doEncode: the issuer IS the signing key — derived, never taken on
    // trust from a setter (iss can then never disagree with the signature) —
    // and iat is stamped fresh at every encode.
    auto keypair = nkeys::FromSeed(seed);
    impl_->issuer_ = keypair->publicString();
    if (!nkeys::IsValidPublicOperatorKey(impl_->issuer_)) {
        throw std::invalid_argument("Operator JWTs must be signed by an operator key");
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

    // NATS-specific claims
    json nats_claims = {
        {"type", "operator"},
        {"version", JWT_VERSION}
    };
    if (!impl_->signingKeys_.empty()) {
        nats_claims["signing_keys"] = impl_->signingKeys_;
    }
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
        throw std::invalid_argument("Operator subject cannot be empty");
    }
    if (impl_->issuer_.empty()) {
        throw std::invalid_argument("Operator issuer cannot be empty");
    }
    if (impl_->subject_[0] != 'O') {
        throw std::invalid_argument("Operator subject must start with 'O'");
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

    if (!nats.contains("type") || nats["type"] != "operator") {
        throw std::invalid_argument(
            "JWT type mismatch: expected 'operator', got '" +
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

    // Create OperatorClaims object
    auto claims = std::make_unique<OperatorClaims>(subject);

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
