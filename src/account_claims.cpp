#include "jwt/account_claims.hpp"
#include "jwt/jwt_constants.hpp"
#include "jwt/jwt_errors.hpp"
#include "base64url.hpp"
#include "jwt_utils.hpp"
#include "scope_serialization.hpp"
#include <algorithm>
#include <map>
#include <nkeys/nkeys.hpp>
#include <nlohmann/json.hpp>
#include <stdexcept>

namespace jwt {

class AccountClaims::Impl {
public:
    // The full nats object as decoded, or Go's NewAccountClaims defaults for
    // fresh claims. The defaults matter operationally: nats-server treats
    // ABSENT limits as ZERO — an account without them can never connect
    // (measured against a real server: "maximum account active connections
    // exceeded"). Go emits no-limit (-1) fields; so do we. Carrying the
    // decoded object through re-encode keeps un-ported fields (real limits,
    // mappings, imports…) intact — resetting them to defaults would be
    // silent privilege escalation on the re-sign flow.
    nlohmann::json natsRaw_ = {
        {"limits", {{"subs", -1}, {"data", -1}, {"payload", -1},
                    {"imports", -1}, {"exports", -1}, {"wildcards", true},
                    {"conn", -1}, {"leaf", -1}}},
        {"default_permissions", {{"pub", nlohmann::json::object()},
                                 {"sub", nlohmann::json::object()}}},
        {"authorization", nlohmann::json::object()},
    };
    std::string subject_;
    std::string issuer_;
    std::optional<std::string> name_;
    std::int64_t issuedAt_ = 0;
    std::int64_t expires_ = 0;
    std::vector<std::string> signingKeys_;
    std::map<std::string, UserScope> scopes_;
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

void AccountClaims::setScope(const UserScope& scope) {
    if (std::find(impl_->signingKeys_.begin(), impl_->signingKeys_.end(), scope.key) ==
        impl_->signingKeys_.end()) {
        impl_->signingKeys_.push_back(scope.key);
    }
    impl_->scopes_[scope.key] = scope;
}

std::optional<UserScope> AccountClaims::getScope(const std::string& signingKey) const {
    auto it = impl_->scopes_.find(signingKey);
    if (it == impl_->scopes_.end()) return std::nullopt;
    return it->second;
}

std::string AccountClaims::encode(const std::string& seed) const {
    using namespace internal;
    using json = nlohmann::json;

    // Go's doEncode: the issuer IS the signing key — derived, never taken on
    // trust from a setter (iss can then never disagree with the signature) —
    // and iat is stamped fresh at every encode.
    auto keypair = nkeys::FromSeed(seed);
    impl_->issuer_ = keypair->publicString();
    if (!nkeys::IsValidPublicOperatorKey(impl_->issuer_) &&
        !nkeys::IsValidPublicAccountKey(impl_->issuer_)) {
        throw InvalidClaimsError("Account JWTs must be signed by an operator or account key");
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
    if (!impl_->signingKeys_.empty()) {
        // Go serializes signing keys SORTED, plain keys as strings and
        // scoped keys as user_scope objects, in one mixed array.
        auto sorted = impl_->signingKeys_;
        std::sort(sorted.begin(), sorted.end());
        json keys = json::array();
        for (const auto& key : sorted) {
            auto it = impl_->scopes_.find(key);
            if (it != impl_->scopes_.end()) {
                keys.push_back(internal::userScopeToJson(it->second));
            } else {
                keys.push_back(key);
            }
        }
        nats_claims["signing_keys"] = keys;
    } else {
        nats_claims.erase("signing_keys");
    }
    nats_claims["type"] = "account";
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

void AccountClaims::validate() const {
    if (impl_->subject_.empty()) {
        throw InvalidClaimsError("Account subject cannot be empty");
    }
    if (impl_->issuer_.empty()) {
        throw InvalidClaimsError("Account issuer cannot be empty (must be signed by Operator)");
    }
    if (impl_->subject_[0] != 'A') {
        throw InvalidClaimsError("Account subject must start with 'A'");
    }
    // Go's ExpectedPrefixes for accounts: {operator, account} — self-signed
    // accounts are the documented flow (self-sign, hand to operator, re-sign).
    if (impl_->issuer_[0] != 'O' && impl_->issuer_[0] != 'A') {
        throw InvalidClaimsError("Account issuer must be an Operator or Account (start with 'O' or 'A')");
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

    if (!nats.contains("type") || nats["type"] != "account") {
        throw InvalidClaimsError(
            "JWT type mismatch: expected 'account', got '" +
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

    // Create AccountClaims object
    auto claims = std::make_unique<AccountClaims>(subject);
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

    // Extract signing keys if present — a mixed array: plain keys are
    // strings, scoped keys are user_scope objects (Go's SigningKeys map)
    if (nats.contains("signing_keys") && nats["signing_keys"].is_array()) {
        for (const auto& key : nats["signing_keys"]) {
            if (key.is_string()) {
                claims->addSigningKey(key.get<std::string>());
            } else if (key.is_object() && key.value("kind", "") == "user_scope") {
                claims->setScope(internal::userScopeFromJson(key));
            } else {
                throw InvalidClaimsError("unknown signing key entry in account JWT");
            }
        }
    }

    // Validate the decoded claims
    claims->validate();

    return claims;
}

}
