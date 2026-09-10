#include "jwt/activation_claims.hpp"
#include "jwt/jwt_constants.hpp"
#include "jwt/jwt_errors.hpp"
#include "base64url.hpp"
#include "jwt_utils.hpp"
#include <nkeys/nkeys.hpp>
#include <nlohmann/json.hpp>
#include <stdexcept>

namespace jwt {

namespace {
    const char* exportTypeToString(ExportType t) {
        switch (t) {
            case ExportType::Stream: return "stream";
            case ExportType::Service: return "service";
            default: return "unknown";
        }
    }
}

class ActivationClaims::Impl {
public:
    nlohmann::json natsRaw_ = nlohmann::json::object();
    std::string subject_;
    std::string issuer_;
    std::optional<std::string> name_;
    std::int64_t issuedAt_ = 0;
    std::int64_t expires_ = 0;
    std::string audience_;
    std::int64_t notBefore_ = 0;
    std::vector<std::string> tags_;
    std::string importSubject_;
    ExportType importType_ = ExportType::Unknown;
    std::optional<std::string> issuerAccount_;
};

ActivationClaims::ActivationClaims(const std::string& granteeAccountPublicKey)
    : impl_(std::make_unique<Impl>()) {
    impl_->subject_ = granteeAccountPublicKey;
}

ActivationClaims::~ActivationClaims() = default;

std::string ActivationClaims::subject() const { return impl_->subject_; }
std::string ActivationClaims::issuer() const { return impl_->issuer_; }
std::optional<std::string> ActivationClaims::name() const { return impl_->name_; }
std::int64_t ActivationClaims::issuedAt() const { return impl_->issuedAt_; }
std::int64_t ActivationClaims::expires() const { return impl_->expires_; }
void ActivationClaims::setName(const std::string& name) { impl_->name_ = name; }
void ActivationClaims::setExpires(std::int64_t exp) { impl_->expires_ = exp; }
std::string ActivationClaims::audience() const { return impl_->audience_; }
void ActivationClaims::setAudience(const std::string& audience) { impl_->audience_ = audience; }
std::int64_t ActivationClaims::notBefore() const { return impl_->notBefore_; }
void ActivationClaims::setNotBefore(std::int64_t nbf) { impl_->notBefore_ = nbf; }
std::vector<std::string>& ActivationClaims::tags() { return impl_->tags_; }
const std::vector<std::string>& ActivationClaims::tags() const { return impl_->tags_; }
void ActivationClaims::setImportSubject(const std::string& subject) {
    impl_->importSubject_ = subject;
}
std::string ActivationClaims::importSubject() const { return impl_->importSubject_; }
void ActivationClaims::setImportType(ExportType type) { impl_->importType_ = type; }
ExportType ActivationClaims::importType() const { return impl_->importType_; }
void ActivationClaims::setIssuerAccount(const std::string& accountPublicKey) {
    impl_->issuerAccount_ = accountPublicKey;
}
std::optional<std::string> ActivationClaims::issuerAccount() const {
    return impl_->issuerAccount_;
}

std::string ActivationClaims::encode(const std::string& seed) const {
    // the seed path is the signer path with an in-process keypair
    auto keypair = nkeys::FromSeed(seed);
    return encodeWithSigner(keypair->publicString(), internal::signerFor(*keypair));
}

std::string ActivationClaims::encodeWithSigner(const std::string& issuerPublicKey,
                                               const SignFn& sign) const {
    using namespace internal;
    using json = nlohmann::json;

    // Go's doEncode: issuer derived from the seed; activations may be issued
    // by accounts or operators (ExpectedPrefixes).
    internal::checkIssuerKind(issuerPublicKey, "AO", "Activation");
    impl_->issuer_ = issuerPublicKey;
    impl_->issuedAt_ = getCurrentTimestamp();

    validate();

    json payload = {
        {"iat", impl_->issuedAt_},
        {"iss", impl_->issuer_},
        {"sub", impl_->subject_}
    };
    if (impl_->name_ && !impl_->name_->empty()) payload["name"] = *impl_->name_;  // Go: omitempty
    if (impl_->expires_ > 0) payload["exp"] = impl_->expires_;
    if (!impl_->audience_.empty()) payload["aud"] = impl_->audience_;
    if (impl_->notBefore_ > 0) payload["nbf"] = impl_->notBefore_;

    json nats_claims = impl_->natsRaw_;
    nats_claims["subject"] = impl_->importSubject_;
    nats_claims["kind"] = exportTypeToString(impl_->importType_);
    if (impl_->issuerAccount_) nats_claims["issuer_account"] = *impl_->issuerAccount_;
    else nats_claims.erase("issuer_account");
    if (!impl_->tags_.empty()) nats_claims["tags"] = impl_->tags_;
    else nats_claims.erase("tags");
    nats_claims["type"] = "activation";
    nats_claims["version"] = JWT_VERSION;
    payload["nats"] = nats_claims;

    payload["jti"] = computeJti(payload.dump());

    // Go's doEncode tail: header.payload → signer → (verified) signature
    return signAndAssemble(payload.dump(), issuerPublicKey, sign);
}

void ActivationClaims::validate(ValidationResults& vr) const {
    internal::addTimeChecks(vr, impl_->expires_, impl_->notBefore_);
    if (impl_->importSubject_.empty()) vr.addError("subject cannot be empty");  // Go: Subject.Validate
    if (impl_->importType_ != ExportType::Stream && impl_->importType_ != ExportType::Service) {
        vr.addError("invalid import type: \"" + std::string(exportTypeToString(impl_->importType_)) + "\"");
    }
    if (impl_->issuerAccount_ && !nkeys::IsValidPublicAccountKey(*impl_->issuerAccount_)) {
        vr.addError("account_id is not an account public key");
    }
}

void ActivationClaims::validate() const {
    checkStructure();
    ValidationResults vr;
    validate(vr);
    internal::throwFirstBlocking(vr);
}

void ActivationClaims::checkStructure() const {
    if (impl_->subject_.empty()) {
        throw InvalidClaimsError("Activation subject cannot be empty");
    }
    // Go's Encode: the grantee must be an account key (its own test refuses
    // the literal "public"); import subject/kind are Go's ADVISORY rules and
    // live in validate(vr) so Go-mintable tokens stay decodable.
    internal::checkSubjectKind(impl_->subject_, 'A', "Activation");
    internal::checkIssuerKind(impl_->issuer_, "AO", "Activation");
}

std::unique_ptr<ActivationClaims> decodeActivationClaims(const std::string& jwt) {
    using namespace internal;
    using json = nlohmann::json;

    // Go's Decode: header validity, payload-derived version, per-version
    // signature rule, v1 → v2 migration — shared in decodeEnvelope.
    auto env = decodeEnvelope(jwt);
    const json& payload = env.payload;
    return guardJson([&]() -> std::unique_ptr<ActivationClaims> {
    auto nats = payload["nats"];
    if (!nats.contains("type") || nats["type"] != "activation") {
        throw InvalidClaimsError("JWT type mismatch: expected 'activation'");
    }

    std::string subject = payload.at("sub").get<std::string>();
    std::string issuer = payload.at("iss").get<std::string>();

    auto claims = std::make_unique<ActivationClaims>(subject);
    claims->impl_->natsRaw_ = nats;
    claims->impl_->issuer_ = issuer;
    claims->impl_->issuedAt_ = intField(payload, "iat", 0);
    if (payload.contains("name")) claims->setName(payload["name"].get<std::string>());
    claims->setExpires(intField(payload, "exp", 0));
    claims->impl_->audience_ = payload.value("aud", "");
    claims->impl_->notBefore_ = intField(payload, "nbf", 0);
    if (const auto* a = arrayField(nats, "tags")) claims->impl_->tags_ = a->get<std::vector<std::string>>();
    claims->impl_->importSubject_ = nats.value("subject", "");
    const std::string kind = nats.value("kind", "");
    claims->impl_->importType_ = kind == "stream"  ? ExportType::Stream
                                 : kind == "service" ? ExportType::Service
                                                     : ExportType::Unknown;
    if (nats.contains("issuer_account")) {
        claims->impl_->issuerAccount_ = nats["issuer_account"].get<std::string>();
    }
    claims->checkStructure();
    return claims;
    });
}

}
