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
                                const std::vector<std::string>& signingKeys,
                                ValidationResults& vr) {
        if (!accountServerURL.empty() && !splitURL(accountServerURL).valid) {
            vr.addError("account server url \"" + accountServerURL +
                                     "\" requires a protocol");
        }
        for (const auto& u : serviceURLs) {
            if (u.empty()) continue;
            auto parsed = splitURL(u);
            if (!parsed.valid) {
                vr.addError("error parsing operator service url \"" + u + "\"");
                continue;
            }
            if (parsed.hasUserInfo) {
                vr.addError("operator service url \"" + u +
                                         "\" - credentials are not supported");
            }
            if (!parsed.path.empty()) {
                vr.addError("operator service url \"" + u +
                                         "\" - paths are not supported");
            }
            if (parsed.scheme != "nats" && parsed.scheme != "tls" &&
                parsed.scheme != "ws" && parsed.scheme != "wss") {
                vr.addError("operator service url \"" + u +
                            "\" - protocol not supported (only 'nats', 'tls', 'ws', 'wss' only)");
            }
        }
        for (const auto& k : signingKeys) {
            if (!nkeys::IsValidPublicOperatorKey(k)) {
                vr.addError(k + " is not an operator public key");
            }
        }
        if (!systemAccount.empty() && !nkeys::IsValidPublicAccountKey(systemAccount)) {
            vr.addError(systemAccount + " is not an account public key");
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
                vr.addError(
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
    std::string audience_;
    std::int64_t notBefore_ = 0;
    std::vector<std::string> tags_;
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
std::string OperatorClaims::audience() const { return impl_->audience_; }
void OperatorClaims::setAudience(const std::string& audience) { impl_->audience_ = audience; }
std::int64_t OperatorClaims::notBefore() const { return impl_->notBefore_; }
void OperatorClaims::setNotBefore(std::int64_t nbf) { impl_->notBefore_ = nbf; }
std::vector<std::string>& OperatorClaims::tags() { return impl_->tags_; }
const std::vector<std::string>& OperatorClaims::tags() const { return impl_->tags_; }
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
    // the seed path is the signer path with an in-process keypair
    auto keypair = nkeys::FromSeed(seed);
    return encodeWithSigner(keypair->publicString(), internal::signerFor(*keypair));
}

std::string OperatorClaims::encodeWithSigner(const std::string& issuerPublicKey,
                                             const SignFn& sign) const {
    using namespace internal;
    using json = nlohmann::json;

    // Go's doEncode: the issuer IS the signing key — derived, never taken on
    // trust from a setter (iss can then never disagree with the signature) —
    // and iat is stamped fresh at every encode.
    internal::checkIssuerKind(issuerPublicKey, "O", "Operator");
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
    if (!impl_->tags_.empty()) nats_claims["tags"] = impl_->tags_;
    else nats_claims.erase("tags");
    nats_claims["type"] = "operator";
    nats_claims["version"] = JWT_VERSION;
    payload["nats"] = nats_claims;

    payload["jti"] = computeJti(payload.dump());

    // Go's doEncode tail: header.payload → signer → (verified) signature
    return signAndAssemble(payload.dump(), issuerPublicKey, sign);
}

void OperatorClaims::validate(ValidationResults& vr) const {
    internal::addTimeChecks(vr, impl_->expires_, impl_->notBefore_);
    validateOperatorWiring(impl_->accountServerURL_, impl_->operatorServiceURLs_,
                           impl_->systemAccount_, impl_->assertServerVersion_,
                           impl_->signingKeys_, vr);
}

void OperatorClaims::validate() const {
    checkStructure();
    ValidationResults vr;
    validate(vr);
    internal::throwFirstBlocking(vr);
}

void OperatorClaims::checkStructure() const {
    if (impl_->subject_.empty()) {
        throw InvalidClaimsError("Operator subject cannot be empty");
    }
    if (impl_->issuer_.empty()) {
        throw InvalidClaimsError("Operator issuer cannot be empty");
    }
    internal::checkSubjectKind(impl_->subject_, 'O', "Operator");
    // Go's ExpectedPrefixes, enforced at decode as Go's Decode does
    internal::checkIssuerKind(impl_->issuer_, "O", "Operator");
}

std::unique_ptr<OperatorClaims> decodeOperatorClaims(const std::string& jwt) {
    using namespace internal;
    using json = nlohmann::json;

    // Parse JWT into its three components
    // Go's Decode: header validity, payload-derived version, per-version
    // signature rule, v1 → v2 migration — shared in decodeEnvelope.
    auto env = decodeEnvelope(jwt);
    const json& payload = env.payload;
    return guardJson([&]() -> std::unique_ptr<OperatorClaims> {
    auto nats = payload["nats"];
    if (!nats.contains("type") || nats["type"] != "operator") {
        throw InvalidClaimsError(
            "JWT type mismatch: expected 'operator', got '" +
            (nats.contains("type") ? nats["type"].get<std::string>() : "missing") + "'"
        );
    }

    std::string subject = payload.at("sub").get<std::string>();
    std::string issuer = payload.at("iss").get<std::string>();
    std::int64_t iat = intField(payload, "iat", 0);  // Go: omitempty → 0

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

    claims->setExpires(intField(payload, "exp", 0));
    claims->impl_->audience_ = payload.value("aud", "");
    claims->impl_->notBefore_ = intField(payload, "nbf", 0);
    if (const auto* a = arrayField(nats, "tags")) claims->impl_->tags_ = a->get<std::vector<std::string>>();

    claims->impl_->accountServerURL_ = nats.value("account_server_url", "");
    if (const auto* a = arrayField(nats, "operator_service_urls")) {
        claims->impl_->operatorServiceURLs_ = a->get<std::vector<std::string>>();
    }
    claims->impl_->systemAccount_ = nats.value("system_account", "");
    claims->impl_->assertServerVersion_ = nats.value("assert_server_version", "");
    claims->impl_->strictSigningKeyUsage_ = nats.value("strict_signing_key_usage", false);

    // Extract signing keys if present
    if (const auto* a = arrayField(nats, "signing_keys")) {
        for (const auto& key : *a) claims->addSigningKey(key.get<std::string>());
    }

    // Validate the decoded claims
    claims->checkStructure();
    return claims;
    });
}

}
