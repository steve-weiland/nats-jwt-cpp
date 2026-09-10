#include "jwt/generic_claims.hpp"
#include "jwt/jwt_constants.hpp"
#include "jwt/jwt_errors.hpp"
#include "base64url.hpp"
#include "jwt_utils.hpp"
#include <nkeys/nkeys.hpp>

namespace jwt {

using json = nlohmann::json;

class GenericClaims::Impl {
public:
    json data_ = json::object();
    std::string subject_;
    std::string issuer_;
    std::optional<std::string> name_;
    std::int64_t issuedAt_ = 0;
    std::int64_t expires_ = 0;
    std::string audience_;
    std::int64_t notBefore_ = 0;
};

GenericClaims::GenericClaims(const std::string& subject) : impl_(std::make_unique<Impl>()) {
    impl_->subject_ = subject;
}
GenericClaims::~GenericClaims() = default;

std::string GenericClaims::subject() const { return impl_->subject_; }
std::string GenericClaims::issuer() const { return impl_->issuer_; }
std::optional<std::string> GenericClaims::name() const { return impl_->name_; }
std::int64_t GenericClaims::issuedAt() const { return impl_->issuedAt_; }
std::int64_t GenericClaims::expires() const { return impl_->expires_; }
std::string GenericClaims::audience() const { return impl_->audience_; }
std::int64_t GenericClaims::notBefore() const { return impl_->notBefore_; }
const std::vector<std::string>& GenericClaims::tags() const {
    static const std::vector<std::string> none;
    return none;
}
void GenericClaims::setName(const std::string& name) { impl_->name_ = name; }
void GenericClaims::setExpires(std::int64_t exp) { impl_->expires_ = exp; }
void GenericClaims::setAudience(const std::string& a) { impl_->audience_ = a; }
void GenericClaims::setNotBefore(std::int64_t nbf) { impl_->notBefore_ = nbf; }
std::string GenericClaims::dataJson() const { return impl_->data_.dump(); }
void GenericClaims::setDataJson(const std::string& jsonObject) {
    json parsed;
    try {
        parsed = json::parse(jsonObject);
    } catch (const json::exception& e) {
        throw InvalidClaimsError(std::string("generic claim data is not valid JSON: ") + e.what());
    }
    if (!parsed.is_object()) throw InvalidClaimsError("generic claim data must be a JSON object");
    impl_->data_ = std::move(parsed);
}

std::string GenericClaims::claimType() const {
    // Go: Data["type"] (or Data["nats"]["type"]); a known type is reported as
    // itself, anything else (or "generic") is "generic"
    json v;
    if (impl_->data_.contains("type")) v = impl_->data_["type"];
    else if (impl_->data_.contains("nats") && impl_->data_["nats"].is_object() &&
             impl_->data_["nats"].contains("type")) v = impl_->data_["nats"]["type"];
    if (!v.is_string()) return "";
    const std::string t = v.get<std::string>();
    for (const char* known : {"operator", "account", "user", "activation",
                              "authorization_request", "authorization_response"}) {
        if (t == known) return t;
    }
    return "generic";
}

void GenericClaims::checkStructure() const {
    if (impl_->subject_.empty()) throw InvalidClaimsError("Generic claim subject cannot be empty");
}

void GenericClaims::validate(ValidationResults& vr) const {
    internal::addTimeChecks(vr, impl_->expires_, impl_->notBefore_);
}

void GenericClaims::validate() const {
    checkStructure();
    ValidationResults vr;
    validate(vr);
    internal::throwFirstBlocking(vr);
}

std::string GenericClaims::encode(const std::string& seed) const {
    auto keypair = nkeys::FromSeed(seed);
    return encodeWithSigner(keypair->publicString(), internal::signerFor(*keypair));
}

std::string GenericClaims::encodeWithSigner(const std::string& issuerPublicKey,
                                            const SignFn& sign) const {
    using namespace internal;
    // Go's ExpectedPrefixes is nil for generics: any signing key; still a key
    if (!nkeys::IsValidPublicKey(issuerPublicKey)) {
        throw InvalidClaimsError("Generic JWTs must be signed by an nkey");
    }
    impl_->issuer_ = issuerPublicKey;
    impl_->issuedAt_ = getCurrentTimestamp();
    validate();
    json payload = {{"iat", impl_->issuedAt_}, {"iss", impl_->issuer_}, {"sub", impl_->subject_}};
    if (impl_->name_) payload["name"] = *impl_->name_;
    if (impl_->expires_ > 0) payload["exp"] = impl_->expires_;
    if (!impl_->audience_.empty()) payload["aud"] = impl_->audience_;
    if (impl_->notBefore_ > 0) payload["nbf"] = impl_->notBefore_;
    json nats = impl_->data_.is_object() ? impl_->data_ : json::object();
    nats["version"] = JWT_VERSION;  // Go: updateVersion
    payload["nats"] = nats;
    payload["jti"] = computeJti(payload.dump());
    return signAndAssemble(payload.dump(), issuerPublicKey, sign);
}

std::unique_ptr<GenericClaims> decodeGeneric(const std::string& jwt) {
    using namespace internal;
    auto parts = parseJwt(jwt);
    auto header_bytes = base64url_decode(parts.header_b64);
    const std::string headerJson(header_bytes.begin(), header_bytes.end());
    validateHeader(headerJson);
    std::string alg = json::parse(headerJson).value("alg", "");
    for (auto& c : alg) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    auto payload_bytes = base64url_decode(parts.payload_b64);
    json payload;
    try {
        payload = json::parse(std::string(payload_bytes.begin(), payload_bytes.end()));
    } catch (const json::exception& e) {
        throw MalformedTokenError(std::string("Invalid JWT payload JSON: ") + e.what());
    }
    std::string issuer, subject;
    try {
        issuer = payload.at("iss").get<std::string>();
        subject = payload.at("sub").get<std::string>();
    } catch (const json::exception& e) {
        throw MalformedTokenError(std::string("Invalid JWT payload: ") + e.what());
    }
    // Go's DecodeGeneric: the signature rule follows the HEADER alg
    const bool v1 = alg == "ed25519";
    if (!verifySignature(issuer, v1 ? parts.payload_b64 : parts.signing_input, parts.signature_b64)) {
        throw SignatureError(v1 ? "claim failed V1 signature verification"
                                : "claim failed V2 signature verification");
    }
    auto claims = std::make_unique<GenericClaims>(subject);
    auto& d = *claims->impl_;
    d.issuer_ = issuer;
    d.issuedAt_ = payload.value("iat", std::int64_t{0});
    if (payload.contains("name")) d.name_ = payload["name"].get<std::string>();
    d.expires_ = payload.value("exp", std::int64_t{0});
    d.audience_ = payload.value("aud", "");
    d.notBefore_ = payload.value("nbf", std::int64_t{0});
    d.data_ = payload.contains("nats") && payload["nats"].is_object() ? payload["nats"] : json::object();
    if (v1) {
        // Go copies the v1 top-level type and tags into the data map
        if (payload.contains("type") && payload["type"].is_string() && !payload["type"].get<std::string>().empty())
            d.data_["type"] = payload["type"];
        if (payload.contains("tags") && payload["tags"].is_array() && !payload["tags"].empty())
            d.data_["tags"] = payload["tags"];
    }
    claims->checkStructure();
    return claims;
}

}
