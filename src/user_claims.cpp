#include "jwt/user_claims.hpp"
#include "jwt/jwt_constants.hpp"
#include "jwt/jwt_errors.hpp"
#include "base64url.hpp"
#include "jwt_utils.hpp"
#include "scope_serialization.hpp"
#include "subject_utils.hpp"
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

    // Go: net.ParseCIDR — require addr/prefix with a parseable v4/v6 address
    // and an in-range prefix length.
    void validateCidr(const std::string& cidr, ValidationResults& vr) {
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
            vr.addError("invalid cidr \"" + cidr + "\" in user src limits");
        }
    }

    // Go: time.Parse("15:04:05", ...) — measured: the "15" hour verb takes
    // ONE or two digits ("9:00:00" parses), minutes/seconds exactly two.
    void validateTimeOfDay(const std::string& t, const char* which, ValidationResults& vr) {
        const auto parts = internal::splitOn(t, ':');
        bool ok = parts.size() == 3 && (parts[0].size() == 1 || parts[0].size() == 2) &&
                  parts[1].size() == 2 && parts[2].size() == 2;
        for (const auto& part : parts) ok = ok && internal::isDigits(part);
        if (ok) {
            ok = std::stoi(parts[0]) <= 23 && std::stoi(parts[1]) <= 59 && std::stoi(parts[2]) <= 59;
        }
        if (!ok) {
            vr.addError(std::string(which) + " in time range is invalid \"" + t + "\"");
        }
    }

    // Divergence from Go, documented: Go validates locale against the IANA
    // tzdb (time.LoadLocation); portable C++ tzdb access is not reliable
    // across our supported toolchains, so any non-empty string is accepted.
    void validateLimits(const UserLimits& l, ValidationResults& vr) {
        for (const auto& cidr : l.src) validateCidr(cidr, vr);
        for (const auto& tr : l.times) {
            validateTimeOfDay(tr.start, "start", vr);
            validateTimeOfDay(tr.end, "end", vr);
        }
    }

} // namespace

class UserClaims::Impl {
public:
    // The full nats object as decoded, carried through re-encode so un-ported
    // fields survive. Every typed field (pub/sub, the -1 no-limit defaults
    // nats-server needs — absent limits mean ZERO there) is written over it
    // at encode, so a fresh object needs no defaults of its own.
    nlohmann::json natsRaw_ = nlohmann::json::object();
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
    // Go: omitempty — "" means unset
    if (accountPublicKey.empty()) impl_->issuerAccount_.reset();
    else impl_->issuerAccount_ = accountPublicKey;
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
    // Go's SetScoped(true): scoped users carry NO permissions or limits of
    // their own (the whole UserPermissionLimits zeroed — flags included; all
    // omitted on the wire); the server applies the scope's template.
    // SetScoped(false) resets ONLY Limits to the -1 no-limit defaults and
    // keeps permissions and flags (Go user_claims.go:79-88).
    if (scoped) {
        impl_->permissions_ = Permissions{};
        impl_->limits_ = UserLimits{0, 0, 0, {}, {}, ""};
        impl_->bearerToken_ = false;
        impl_->proxyRequired_ = false;
        impl_->allowedConnectionTypes_.clear();
    } else {
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
    internal::checkIssuerKind(issuerPublicKey, "A", "User");
    impl_->issuer_ = issuerPublicKey;
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

    if (impl_->name_ && !impl_->name_->empty()) {  // Go: omitempty
        payload["name"] = *impl_->name_;
    }
    if (impl_->expires_ > 0) {
        payload["exp"] = impl_->expires_;
    }
    if (!impl_->audience_.empty()) payload["aud"] = impl_->audience_;
    if (impl_->notBefore_ > 0) payload["nbf"] = impl_->notBefore_;


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

void UserClaims::validate(ValidationResults& vr) const {
    internal::addTimeChecks(vr, impl_->expires_, impl_->notBefore_);
    internal::validatePermissions(impl_->permissions_, vr);
    validateLimits(impl_->limits_, vr);
    if (impl_->issuerAccount_ && !nkeys::IsValidPublicAccountKey(*impl_->issuerAccount_)) {
        vr.addError("account_id is not an account public key");
    }
}

void UserClaims::validate() const {
    checkStructure();
    ValidationResults vr;
    validate(vr);
    internal::throwFirstBlocking(vr);
}

void UserClaims::checkStructure() const {
    if (impl_->subject_.empty()) {
        throw InvalidClaimsError("User subject cannot be empty");
    }
    if (impl_->issuer_.empty()) {
        throw InvalidClaimsError("User issuer cannot be empty (must be signed by Account)");
    }
    internal::checkSubjectKind(impl_->subject_, 'U', "User");
    internal::checkIssuerKind(impl_->issuer_, "A", "User");
}

std::unique_ptr<UserClaims> decodeUserClaims(const std::string& jwt) {
    using namespace internal;
    using json = nlohmann::json;

    // Parse JWT into its three components
    // Go's Decode: header validity, payload-derived version, per-version
    // signature rule, v1 → v2 migration — shared in decodeEnvelope.
    auto env = decodeEnvelope(jwt);
    const json& payload = env.payload;
    return guardJson([&]() -> std::unique_ptr<UserClaims> {
    auto nats = payload["nats"];
    if (!nats.contains("type") || nats["type"] != "user") {
        throw InvalidClaimsError(
            "JWT type mismatch: expected 'user', got '" +
            (nats.contains("type") ? nats["type"].get<std::string>() : "missing") + "'"
        );
    }

    std::string subject = payload.at("sub").get<std::string>();
    std::string issuer = payload.at("iss").get<std::string>();
    std::int64_t iat = intField(payload, "iat", 0);  // Go: omitempty → 0

    // Create UserClaims object
    auto claims = std::make_unique<UserClaims>(subject);
    claims->impl_->natsRaw_ = nats;

    // Typed permission/limit fields (fix-plan #1+#2)
    auto& perms = claims->impl_->permissions_;
    if (const auto* o = objectField(nats, "pub")) perms.pub = internal::permissionFromJson(*o);
    if (const auto* o = objectField(nats, "sub")) perms.sub = internal::permissionFromJson(*o);
    if (const auto* o = objectField(nats, "resp")) {
        perms.resp = ResponsePermission{static_cast<int>(intField(*o, "max", 0)), intField(*o, "ttl", 0)};
    }
    auto& lims = claims->impl_->limits_;
    lims.subs = intField(nats, "subs", 0);
    lims.data = intField(nats, "data", 0);
    lims.payload = intField(nats, "payload", 0);
    if (nats.contains("src")) {
        // Go's CIDRList accepts a JSON array or a comma-separated string
        if (nats["src"].is_array()) {
            lims.src = nats["src"].get<std::vector<std::string>>();
        } else if (nats["src"].is_string()) {
            // Go: CIDRList.Set → TagList.Add: lower-case, TRIM, drop empties, de-dup
            addTags(lims.src, internal::splitOn(nats["src"].get<std::string>(), ','));
        } else {
            throw MalformedTokenError("field 'src' must be an array or a string");
        }
    }
    if (const auto* a = arrayField(nats, "times")) {
        for (const auto& tr : *a) lims.times.push_back({tr.value("start", ""), tr.value("end", "")});
    }
    lims.locale = nats.value("times_location", "");
    claims->impl_->bearerToken_ = nats.value("bearer_token", false);
    claims->impl_->proxyRequired_ = nats.value("proxy_required", false);
    if (const auto* a = arrayField(nats, "allowed_connection_types")) {
        claims->impl_->allowedConnectionTypes_ = a->get<std::vector<std::string>>();
    }

    // Populate required fields (direct access via friend declaration)
    claims->impl_->issuer_ = issuer;
    claims->impl_->issuedAt_ = iat;

    // Populate optional fields
    if (payload.contains("name")) {
        claims->setName(payload["name"].get<std::string>());
    }

    claims->setExpires(intField(payload, "exp", 0));
    claims->impl_->audience_ = payload.value("aud", "");
    claims->impl_->notBefore_ = intField(payload, "nbf", 0);
    if (const auto* a = arrayField(nats, "tags")) claims->impl_->tags_ = a->get<std::vector<std::string>>();

    // Extract issuer_account if present
    if (nats.contains("issuer_account")) {
        claims->setIssuerAccount(nats["issuer_account"].get<std::string>());
    }

    // Validate the decoded claims
    claims->checkStructure();
    return claims;
    });
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
