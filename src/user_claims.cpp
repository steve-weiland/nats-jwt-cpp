#include "jwt/user_claims.hpp"
#include "jwt/jwt_constants.hpp"
#include "jwt/jwt_errors.hpp"
#include "base64url.hpp"
#include "jwt_utils.hpp"
#include "scope_serialization.hpp"
#include <nkeys/nkeys.hpp>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <arpa/inet.h>

namespace jwt {

namespace {

    using json = nlohmann::json;

    // Go's checkPermission: "subject" or "subject queue"; queues only where
    // permitted (subscriptions), never a third token.
    void validatePermissionSubject(const std::string& entry, bool permitQueue) {
        std::vector<std::string> tokens;
        std::size_t pos = 0;
        while (pos <= entry.size()) {
            auto next = entry.find(' ', pos);
            if (next == std::string::npos) {
                tokens.push_back(entry.substr(pos));
                break;
            }
            tokens.push_back(entry.substr(pos, next - pos));
            pos = next + 1;
        }
        if (tokens.size() > 2) {
            throw InvalidClaimsError("Permission subject \"" + entry +
                                     "\" contains too many spaces");
        }
        if (tokens.size() == 2 && !permitQueue) {
            throw InvalidClaimsError("Permission subject \"" + entry +
                                     "\" is not allowed to contain queue");
        }
        for (const auto& t : tokens) {
            if (t.empty()) {
                throw InvalidClaimsError("Permission subject \"" + entry +
                                         "\" contains an empty token");
            }
        }
    }

    void validatePermissions(const Permissions& p) {
        for (const auto& s : p.sub.allow) validatePermissionSubject(s, true);
        for (const auto& s : p.sub.deny) validatePermissionSubject(s, true);
        for (const auto& s : p.pub.allow) validatePermissionSubject(s, false);
        for (const auto& s : p.pub.deny) validatePermissionSubject(s, false);
    }

    // Go: net.ParseCIDR — require addr/prefix with a parseable v4/v6 address
    // and an in-range prefix length.
    void validateCidr(const std::string& cidr) {
        auto slash = cidr.find('/');
        bool ok = false;
        if (slash != std::string::npos && slash > 0 && slash + 1 < cidr.size()) {
            const std::string addr = cidr.substr(0, slash);
            const std::string prefixStr = cidr.substr(slash + 1);
            unsigned char buf[16];
            int family = addr.find(':') != std::string::npos ? AF_INET6 : AF_INET;
            if (inet_pton(family, addr.c_str(), buf) == 1 &&
                !prefixStr.empty() &&
                prefixStr.find_first_not_of("0123456789") == std::string::npos) {
                const long prefix = std::strtol(prefixStr.c_str(), nullptr, 10);
                ok = prefix >= 0 && prefix <= (family == AF_INET6 ? 128 : 32);
            }
        }
        if (!ok) {
            throw InvalidClaimsError("invalid cidr \"" + cidr + "\" in user src limits");
        }
    }

    // Go: time.Parse("15:04:05", ...) — strict HH:MM:SS.
    void validateTimeOfDay(const std::string& t, const char* which) {
        bool ok = t.size() == 8 && t[2] == ':' && t[5] == ':';
        if (ok) {
            for (std::size_t i : {0u, 1u, 3u, 4u, 6u, 7u}) {
                if (t[i] < '0' || t[i] > '9') { ok = false; break; }
            }
        }
        if (ok) {
            const int h = (t[0] - '0') * 10 + (t[1] - '0');
            const int m = (t[3] - '0') * 10 + (t[4] - '0');
            const int sec = (t[6] - '0') * 10 + (t[7] - '0');
            ok = h <= 23 && m <= 59 && sec <= 59;
        }
        if (!ok) {
            throw InvalidClaimsError(std::string(which) + " in time range is invalid \"" + t + "\"");
        }
    }

    // Divergence from Go, documented: Go validates locale against the IANA
    // tzdb (time.LoadLocation); portable C++ tzdb access is not reliable
    // across our supported toolchains, so any non-empty string is accepted.
    void validateLimits(const UserLimits& l) {
        for (const auto& cidr : l.src) validateCidr(cidr);
        for (const auto& tr : l.times) {
            validateTimeOfDay(tr.start, "start");
            validateTimeOfDay(tr.end, "end");
        }
    }

} // namespace

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
    Permissions permissions_;
    UserLimits limits_;
    bool bearerToken_ = false;
    bool proxyRequired_ = false;
    std::vector<std::string> allowedConnectionTypes_;
    std::string subject_;
    std::string issuer_;
    std::optional<std::string> name_;
    std::int64_t issuedAt_ = 0;
    std::int64_t expires_ = 0;
    std::string audience_;
    std::int64_t notBefore_ = 0;
    std::vector<std::string> tags_;
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
std::string UserClaims::audience() const { return impl_->audience_; }
void UserClaims::setAudience(const std::string& audience) { impl_->audience_ = audience; }
std::int64_t UserClaims::notBefore() const { return impl_->notBefore_; }
void UserClaims::setNotBefore(std::int64_t nbf) { impl_->notBefore_ = nbf; }
std::vector<std::string>& UserClaims::tags() { return impl_->tags_; }
const std::vector<std::string>& UserClaims::tags() const { return impl_->tags_; }
void UserClaims::setIssuer(const std::string& issuerKey) { impl_->issuer_ = issuerKey; }
void UserClaims::setIssuerAccount(const std::string& accountPublicKey) {
    impl_->issuerAccount_ = accountPublicKey;
}
std::optional<std::string> UserClaims::issuerAccount() const {
    return impl_->issuerAccount_;
}
Permissions& UserClaims::permissions() { return impl_->permissions_; }
const Permissions& UserClaims::permissions() const { return impl_->permissions_; }
UserLimits& UserClaims::limits() { return impl_->limits_; }
const UserLimits& UserClaims::limits() const { return impl_->limits_; }

void UserClaims::setBearerToken(bool bearer) { impl_->bearerToken_ = bearer; }
bool UserClaims::isBearerToken() const { return impl_->bearerToken_; }
void UserClaims::setProxyRequired(bool required) { impl_->proxyRequired_ = required; }
bool UserClaims::proxyRequired() const { return impl_->proxyRequired_; }
std::vector<std::string>& UserClaims::allowedConnectionTypes() {
    return impl_->allowedConnectionTypes_;
}
const std::vector<std::string>& UserClaims::allowedConnectionTypes() const {
    return impl_->allowedConnectionTypes_;
}

void UserClaims::setScoped(bool scoped) {
    // Go's SetScoped: scoped users carry NO permissions or limits of their
    // own (all zero — omitted on the wire); the server applies the scope's
    // template. Unscoping restores the -1 no-limit defaults. The connection
    // flags are part of UserPermissionLimits too, so they reset either way.
    impl_->bearerToken_ = false;
    impl_->proxyRequired_ = false;
    impl_->allowedConnectionTypes_.clear();
    if (scoped) {
        impl_->permissions_ = Permissions{};
        impl_->limits_ = UserLimits{0, 0, 0, {}, {}, ""};
    } else {
        impl_->permissions_ = Permissions{};
        impl_->limits_ = UserLimits{};
    }
}

bool UserClaims::hasEmptyPermissions() const {
    const auto& p = impl_->permissions_;
    const auto& l = impl_->limits_;
    // Go: reflect.DeepEqual against the zero UserPermissionLimits — the
    // connection flags count too.
    return p.pub.empty() && p.sub.empty() && !p.resp && l.subs == 0 &&
           l.data == 0 && l.payload == 0 && l.src.empty() && l.times.empty() &&
           l.locale.empty() && !impl_->bearerToken_ && !impl_->proxyRequired_ &&
           impl_->allowedConnectionTypes_.empty();
}

std::string UserClaims::encode(const std::string& seed) const {
    // the seed path is the signer path with an in-process keypair
    auto keypair = nkeys::FromSeed(seed);
    return encodeWithSigner(keypair->publicString(), internal::signerFor(*keypair));
}

std::string UserClaims::encodeWithSigner(const std::string& issuerPublicKey,
                                         const SignFn& sign) const {
    using namespace internal;
    using json = nlohmann::json;

    // Go's doEncode: the issuer IS the signing key — derived, never taken on
    // trust from a setter (iss can then never disagree with the signature) —
    // and iat is stamped fresh at every encode.
    impl_->issuer_ = issuerPublicKey;
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
    if (!impl_->audience_.empty()) payload["aud"] = impl_->audience_;
    if (impl_->notBefore_ > 0) payload["nbf"] = impl_->notBefore_;

    validatePermissions(impl_->permissions_);
    validateLimits(impl_->limits_);

    // NATS-specific claims: start from the carried nats object, then
    // overwrite every field this port manages (erasing keys whose typed
    // value is empty — Go's omitempty; stale raw values must never leak).
    json nats_claims = impl_->natsRaw_;
    if (impl_->issuerAccount_) {
        nats_claims["issuer_account"] = *impl_->issuerAccount_;
    } else {
        nats_claims.erase("issuer_account");
    }
    nats_claims["pub"] = internal::permissionToJson(impl_->permissions_.pub);
    nats_claims["sub"] = internal::permissionToJson(impl_->permissions_.sub);
    if (impl_->permissions_.resp) {
        nats_claims["resp"] = {{"max", impl_->permissions_.resp->maxMsgs},
                               {"ttl", impl_->permissions_.resp->ttlNanos}};
    } else {
        nats_claims.erase("resp");
    }
    for (auto [key, value] : {std::pair<const char*, std::int64_t>{"subs", impl_->limits_.subs},
                              {"data", impl_->limits_.data},
                              {"payload", impl_->limits_.payload}}) {
        if (value != 0) nats_claims[key] = value; else nats_claims.erase(key);
    }
    if (!impl_->limits_.src.empty()) nats_claims["src"] = impl_->limits_.src;
    else nats_claims.erase("src");
    if (!impl_->limits_.times.empty()) {
        json times = json::array();
        for (const auto& tr : impl_->limits_.times) {
            times.push_back({{"start", tr.start}, {"end", tr.end}});
        }
        nats_claims["times"] = times;
    } else {
        nats_claims.erase("times");
    }
    if (!impl_->limits_.locale.empty()) nats_claims["times_location"] = impl_->limits_.locale;
    else nats_claims.erase("times_location");
    if (impl_->bearerToken_) nats_claims["bearer_token"] = true;
    else nats_claims.erase("bearer_token");
    if (impl_->proxyRequired_) nats_claims["proxy_required"] = true;
    else nats_claims.erase("proxy_required");
    if (!impl_->allowedConnectionTypes_.empty()) {
        nats_claims["allowed_connection_types"] = impl_->allowedConnectionTypes_;
    } else {
        nats_claims.erase("allowed_connection_types");
    }
    if (!impl_->tags_.empty()) nats_claims["tags"] = impl_->tags_;
    else nats_claims.erase("tags");
    nats_claims["type"] = "user";
    nats_claims["version"] = JWT_VERSION;
    payload["nats"] = nats_claims;

    payload["jti"] = computeJti(payload.dump());

    // Go's doEncode tail: header.payload → signer → (verified) signature
    return signAndAssemble(payload.dump(), issuerPublicKey, sign);
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

    // Typed permission/limit fields (fix-plan #1+#2)
    auto& perms = claims->impl_->permissions_;
    if (nats.contains("pub")) perms.pub = internal::permissionFromJson(nats["pub"]);
    if (nats.contains("sub")) perms.sub = internal::permissionFromJson(nats["sub"]);
    if (nats.contains("resp") && nats["resp"].is_object()) {
        perms.resp = ResponsePermission{nats["resp"].value("max", 0),
                                        nats["resp"].value("ttl", std::int64_t{0})};
    }
    auto& lims = claims->impl_->limits_;
    lims.subs = nats.value("subs", std::int64_t{0});
    lims.data = nats.value("data", std::int64_t{0});
    lims.payload = nats.value("payload", std::int64_t{0});
    if (nats.contains("src")) {
        // Go's CIDRList accepts a JSON array or a comma-separated string
        if (nats["src"].is_array()) {
            lims.src = nats["src"].get<std::vector<std::string>>();
        } else if (nats["src"].is_string()) {
            std::string all = nats["src"].get<std::string>();
            std::size_t pos = 0;
            while (pos <= all.size()) {
                auto next = all.find(',', pos);
                std::string piece = all.substr(pos, next == std::string::npos
                                                        ? std::string::npos : next - pos);
                std::transform(piece.begin(), piece.end(), piece.begin(),
                               [](unsigned char ch) { return std::tolower(ch); });
                if (!piece.empty()) lims.src.push_back(piece);
                if (next == std::string::npos) break;
                pos = next + 1;
            }
        }
    }
    if (nats.contains("times") && nats["times"].is_array()) {
        for (const auto& tr : nats["times"]) {
            lims.times.push_back({tr.value("start", ""), tr.value("end", "")});
        }
    }
    lims.locale = nats.value("times_location", "");
    claims->impl_->bearerToken_ = nats.value("bearer_token", false);
    claims->impl_->proxyRequired_ = nats.value("proxy_required", false);
    if (nats.contains("allowed_connection_types") && nats["allowed_connection_types"].is_array()) {
        claims->impl_->allowedConnectionTypes_ =
            nats["allowed_connection_types"].get<std::vector<std::string>>();
    }

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
    claims->impl_->audience_ = payload.value("aud", "");
    claims->impl_->notBefore_ = payload.value("nbf", std::int64_t{0});
    if (nats.contains("tags") && nats["tags"].is_array())
        claims->impl_->tags_ = nats["tags"].get<std::vector<std::string>>();

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
