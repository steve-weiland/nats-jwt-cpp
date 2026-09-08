#include "jwt/user_claims.hpp"
#include "jwt/jwt_constants.hpp"
#include "jwt/jwt_errors.hpp"
#include "base64url.hpp"
#include "jwt_utils.hpp"
#include <nkeys/nkeys.hpp>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <sstream>

namespace jwt {

class UserClaims::Impl {
public:
    // The full nats object as decoded, or Go's NewUserClaims defaults for
    // fresh claims (no-limit subs/data/payload, empty pub/sub permissions) —
    // nats-server treats absent limits as zero, making the user unusable.
    // Carried through re-encode so un-ported fields survive.
    nlohmann::json natsRaw_ = {
        {"pub", nlohmann::json::object()},
        {"sub", nlohmann::json::object()},
        {"subs", -1}, {"data", -1}, {"payload", -1},
    };
    std::string subject_;
    std::string issuer_;
    std::optional<std::string> name_;
    std::int64_t issuedAt_ = 0;
    std::int64_t expires_ = 0;
    std::optional<std::string> issuerAccount_;
};

UserClaims::UserClaims(const std::string& userPublicKey)
    : impl_(std::make_unique<Impl>()) {
    impl_->subject_ = userPublicKey;
}

UserClaims::~UserClaims() = default;

std::string UserClaims::subject() const { return impl_->subject_; }
std::string UserClaims::issuer() const { return impl_->issuer_; }
std::optional<std::string> UserClaims::name() const { return impl_->name_; }
std::int64_t UserClaims::issuedAt() const { return impl_->issuedAt_; }
std::int64_t UserClaims::expires() const { return impl_->expires_; }

void UserClaims::setName(const std::string& name) { impl_->name_ = name; }
void UserClaims::setExpires(std::int64_t exp) { impl_->expires_ = exp; }
void UserClaims::setIssuer(const std::string& issuerKey) { impl_->issuer_ = issuerKey; }
void UserClaims::setIssuerAccount(const std::string& accountPublicKey) {
    impl_->issuerAccount_ = accountPublicKey;
}
std::optional<std::string> UserClaims::issuerAccount() const {
    return impl_->issuerAccount_;
}

std::string UserClaims::encode(const std::string& seed) const {
    using namespace internal;
    using json = nlohmann::json;

    // Go's doEncode: the issuer IS the signing key — derived, never taken on
    // trust from a setter (iss can then never disagree with the signature) —
    // and iat is stamped fresh at every encode.
    auto keypair = nkeys::FromSeed(seed);
    impl_->issuer_ = keypair->publicString();
    if (!nkeys::IsValidPublicAccountKey(impl_->issuer_)) {
        throw InvalidClaimsError("User JWTs must be signed by an account key");
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

    // NATS-specific claims: start from the carried nats object, then
    // overwrite the fields this port manages.
    json nats_claims = impl_->natsRaw_;
    if (impl_->issuerAccount_) {
        nats_claims["issuer_account"] = *impl_->issuerAccount_;
    } else {
        nats_claims.erase("issuer_account");
    }
    nats_claims["type"] = "user";
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

void UserClaims::validate() const {
    if (impl_->subject_.empty()) {
        throw InvalidClaimsError("User subject cannot be empty");
    }
    if (impl_->issuer_.empty()) {
        throw InvalidClaimsError("User issuer cannot be empty (must be signed by Account)");
    }
    if (impl_->subject_[0] != 'U') {
        throw InvalidClaimsError("User subject must start with 'U'");
    }
    if (impl_->issuer_[0] != 'A') {
        throw InvalidClaimsError("User issuer must be an Account (start with 'A')");
    }
}

std::unique_ptr<UserClaims> decodeUserClaims(const std::string& jwt) {
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

    if (!nats.contains("type") || nats["type"] != "user") {
        throw InvalidClaimsError(
            "JWT type mismatch: expected 'user', got '" +
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

    // Create UserClaims object
    auto claims = std::make_unique<UserClaims>(subject);
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

    // Extract issuer_account if present
    if (nats.contains("issuer_account")) {
        claims->setIssuerAccount(nats["issuer_account"].get<std::string>());
    }

    // Validate the decoded claims
    claims->validate();

    return claims;
}

std::string formatUserConfig(const std::string& jwt, const std::string& seed) {
    if (jwt.empty()) {
        throw InvalidClaimsError("JWT cannot be empty");
    }
    if (seed.size() < 2 || seed[0] != 'S' || seed[1] != 'U') {
        throw InvalidClaimsError("Seed must be a user seed (starting with 'SU')");
    }

    // Go's FormatUserConfig validates the BUNDLE, not just the strings: the
    // token must decode as a user JWT, and the seed must belong to the JWT's
    // subject — a mismatched pair fails at connect time, far from the mistake.
    auto claims = decodeUserClaims(jwt);
    auto kp = nkeys::FromSeed(seed);
    if (kp->publicString() != claims->subject()) {
        throw InvalidClaimsError("nkey seed does not match the JWT subject");
    }

    // Byte-identical to Go's FormatUserConfig (golden-tested against the live
    // Go library). The JWT MUST be one unwrapped line: the armor regex used by
    // Go and every NATS client captures a single line between the markers —
    // wrapping made the file unparseable ("expected 3 chunks").
    std::ostringstream oss;
    oss << "-----BEGIN NATS USER JWT-----\n";
    oss << jwt << "\n";
    oss << "------END NATS USER JWT------\n";
    oss << "\n";
    oss << "************************* IMPORTANT *************************\n";
    oss << "NKEY Seed printed below can be used to sign and prove identity.\n";
    oss << "NKEYs are sensitive and should be treated as secrets.\n";
    oss << "\n";
    oss << "-----BEGIN USER NKEY SEED-----\n";
    oss << seed << "\n";
    oss << "------END USER NKEY SEED------\n";
    oss << "\n";
    oss << "*************************************************************\n";

    return oss.str();
}

}
