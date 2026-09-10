#include "jwt/account_claims.hpp"
#include "jwt/activation_claims.hpp"
#include "jwt/jwt_constants.hpp"
#include "jwt/jwt_errors.hpp"
#include "base64url.hpp"
#include "jwt_utils.hpp"
#include "scope_serialization.hpp"
#include <algorithm>
#include <chrono>
#include <map>
#include <nkeys/nkeys.hpp>
#include <nlohmann/json.hpp>
#include <stdexcept>

namespace jwt {

namespace {

    using json = nlohmann::json;

    // JetStream fields sit FLAT in the target object (Go embeds the struct).
    void jetStreamLimitsInto(json& out, const JetStreamLimits& j) {
        if (j.memStorage != 0) out["mem_storage"] = j.memStorage;
        if (j.diskStorage != 0) out["disk_storage"] = j.diskStorage;
        if (j.streams != 0) out["streams"] = j.streams;
        if (j.consumer != 0) out["consumer"] = j.consumer;
        if (j.maxAckPending != 0) out["max_ack_pending"] = j.maxAckPending;
        if (j.memoryMaxStreamBytes != 0) out["mem_max_stream_bytes"] = j.memoryMaxStreamBytes;
        if (j.diskMaxStreamBytes != 0) out["disk_max_stream_bytes"] = j.diskMaxStreamBytes;
        if (j.maxBytesRequired) out["max_bytes_required"] = true;
    }

    JetStreamLimits jetStreamLimitsFrom(const json& j) {
        JetStreamLimits out;
        out.memStorage = j.value("mem_storage", std::int64_t{0});
        out.diskStorage = j.value("disk_storage", std::int64_t{0});
        out.streams = j.value("streams", std::int64_t{0});
        out.consumer = j.value("consumer", std::int64_t{0});
        out.maxAckPending = j.value("max_ack_pending", std::int64_t{0});
        out.memoryMaxStreamBytes = j.value("mem_max_stream_bytes", std::int64_t{0});
        out.diskMaxStreamBytes = j.value("disk_max_stream_bytes", std::int64_t{0});
        out.maxBytesRequired = j.value("max_bytes_required", false);
        return out;
    }

    json accountLimitsToJson(const AccountLimits& l) {
        json out = json::object();
        if (l.subs != 0) out["subs"] = l.subs;
        if (l.data != 0) out["data"] = l.data;
        if (l.payload != 0) out["payload"] = l.payload;
        if (l.imports != 0) out["imports"] = l.imports;
        if (l.exports != 0) out["exports"] = l.exports;
        if (l.wildcardExports) out["wildcards"] = true;  // false is ABSENT (bool omitempty)
        if (l.disallowBearer) out["disallow_bearer"] = true;
        if (l.conn != 0) out["conn"] = l.conn;
        if (l.leafNodeConn != 0) out["leaf"] = l.leafNodeConn;
        jetStreamLimitsInto(out, l.jetStream);
        if (!l.tieredLimits.empty()) {
            json tiers = json::object();
            for (const auto& [name, tier] : l.tieredLimits) {
                json t = json::object();
                jetStreamLimitsInto(t, tier);
                tiers[name] = t;
            }
            out["tiered_limits"] = tiers;
        }
        return out;
    }

    AccountLimits accountLimitsFromJson(const json& j) {
        AccountLimits l;
        l.subs = j.value("subs", std::int64_t{0});
        l.data = j.value("data", std::int64_t{0});
        l.payload = j.value("payload", std::int64_t{0});
        l.imports = j.value("imports", std::int64_t{0});
        l.exports = j.value("exports", std::int64_t{0});
        l.wildcardExports = j.value("wildcards", false);
        l.disallowBearer = j.value("disallow_bearer", false);
        l.conn = j.value("conn", std::int64_t{0});
        l.leafNodeConn = j.value("leaf", std::int64_t{0});
        l.jetStream = jetStreamLimitsFrom(j);
        if (j.contains("tiered_limits") && j["tiered_limits"].is_object()) {
            for (const auto& [name, tier] : j["tiered_limits"].items()) {
                l.tieredLimits[name] = jetStreamLimitsFrom(tier);
            }
        }
        return l;
    }

    // Go's OperatorLimits.Validate + Mapping.Validate — Go treats these as
    // ADVISORY (its tests say "don't block encoding!!!"); we enforce at
    // encode, a documented divergence consistent with the user-claims port.
    void validateAccountConfig(const AccountLimits& limits,
                               const std::map<std::string, std::vector<WeightedMapping>>& mappings,
                               ValidationResults& vr) {
        if (!limits.tieredLimits.empty()) {
            if (!(limits.jetStream == JetStreamLimits{})) {
                vr.addError("JetStream Limits and tiered JetStream Limits are mutually exclusive");
            }
            if (limits.tieredLimits.count("")) {
                vr.addError("Tiered JetStream Limits can not contain a blank \"\" tier name");
            }
        }
        // Go's Mapping.Validate, control flow and texts verbatim (a bad weight
        // still counts toward the total — Go reports both; "it's" is Go's).
        for (const auto& [from, wms] : mappings) {
            std::map<std::string, std::uint32_t> perCluster;
            std::uint32_t total = 0;
            for (const auto& wm : wms) {
                const std::uint32_t weight = wm.weight == 0 ? 100 : wm.weight;  // Go GetWeight
                if (weight > 100) {
                    vr.addError("Mapping \"" + from + "\" has a weight " + std::to_string(weight) +
                                " that exceeds 100");
                }
                if (!wm.cluster.empty()) {
                    auto& t = perCluster[wm.cluster];
                    t += weight;
                    if (t > 100) {
                        vr.addError("Mapping \"" + from + "\" in cluster \"" + wm.cluster +
                                    "\" exceeds 100% among all of it's weighted to mappings");
                    }
                } else {
                    total += weight;
                }
            }
            if (total > 100) {
                vr.addError("Mapping \"" + from + "\" exceeds 100% among all of it's weighted to mappings");
            }
        }
    }

    const char* exportTypeStr(ExportType t) {
        switch (t) {
            case ExportType::Stream: return "stream";
            case ExportType::Service: return "service";
            default: return "unknown";
        }
    }

    ExportType exportTypeFrom(const std::string& s) {
        if (s == "stream") return ExportType::Stream;
        if (s == "service") return ExportType::Service;
        return ExportType::Unknown;
    }

    json exportToJson(const Export& e) {
        json out = json::object();
        if (!e.name.empty()) out["name"] = e.name;
        if (!e.subject.empty()) out["subject"] = e.subject;
        if (e.type != ExportType::Unknown) out["type"] = exportTypeStr(e.type);
        if (e.tokenReq) out["token_req"] = true;
        if (!e.revocations.empty()) out["revocations"] = e.revocations;
        if (!e.responseType.empty()) out["response_type"] = e.responseType;
        if (e.responseThresholdNanos != 0) out["response_threshold"] = e.responseThresholdNanos;
        if (e.latency) {
            // both fields always present; sampling 0 serializes as "headers"
            json lat = json::object();
            if (e.latency->sampling == 0) lat["sampling"] = "headers";
            else lat["sampling"] = e.latency->sampling;
            lat["results"] = e.latency->results;
            out["service_latency"] = lat;
        }
        if (e.accountTokenPosition != 0) out["account_token_position"] = e.accountTokenPosition;
        if (e.advertise) out["advertise"] = true;
        if (e.allowTrace) out["allow_trace"] = true;
        if (!e.description.empty()) out["description"] = e.description;
        if (!e.infoURL.empty()) out["info_url"] = e.infoURL;
        return out;
    }

    Export exportFromJson(const json& j) {
        Export e;
        e.name = j.value("name", "");
        e.subject = j.value("subject", "");
        e.type = exportTypeFrom(j.value("type", ""));
        e.tokenReq = j.value("token_req", false);
        if (j.contains("revocations") && j["revocations"].is_object()) {
            for (const auto& [k, v] : j["revocations"].items()) {
                e.revocations[k] = v.get<std::int64_t>();
            }
        }
        e.responseType = j.value("response_type", "");
        e.responseThresholdNanos = j.value("response_threshold", std::int64_t{0});
        if (j.contains("service_latency") && j["service_latency"].is_object()) {
            const auto& lat = j["service_latency"];
            ServiceLatency sl;
            if (lat.contains("sampling") && lat["sampling"].is_string()) sl.sampling = 0;
            else sl.sampling = lat.value("sampling", 0);
            sl.results = lat.value("results", "");
            e.latency = sl;
        }
        e.accountTokenPosition = j.value("account_token_position", 0u);
        e.advertise = j.value("advertise", false);
        e.allowTrace = j.value("allow_trace", false);
        e.description = j.value("description", "");
        e.infoURL = j.value("info_url", "");
        return e;
    }

    json importToJson(const Import& i) {
        json out = json::object();
        if (!i.name.empty()) out["name"] = i.name;
        if (!i.subject.empty()) out["subject"] = i.subject;
        if (!i.account.empty()) out["account"] = i.account;
        if (!i.token.empty()) out["token"] = i.token;
        if (!i.to.empty()) out["to"] = i.to;
        if (!i.localSubject.empty()) out["local_subject"] = i.localSubject;
        if (i.type != ExportType::Unknown) out["type"] = exportTypeStr(i.type);
        if (i.share) out["share"] = true;
        if (i.allowTrace) out["allow_trace"] = true;
        return out;
    }

    Import importFromJson(const json& j) {
        Import i;
        i.name = j.value("name", "");
        i.subject = j.value("subject", "");
        i.account = j.value("account", "");
        i.token = j.value("token", "");
        i.to = j.value("to", "");
        i.localSubject = j.value("local_subject", "");
        i.type = exportTypeFrom(j.value("type", ""));
        i.share = j.value("share", false);
        i.allowTrace = j.value("allow_trace", false);
        return i;
    }

    // Go's Export.Validate / Import.Validate — enforced at encode (Go's are
    // advisory), matching the rest of this port.
    // Go's ExternalAuthorization.Validate, verbatim rules.
    void validateExternalAuthorization(const ExternalAuthorization& a, ValidationResults& vr) {
        if (!a.allowedAccounts.empty() && a.authUsers.empty()) {
            vr.addError(
                "External authorization cannot have accounts without users specified");
        }
        for (const auto& u : a.authUsers) {
            if (!nkeys::IsValidPublicUserKey(u)) {
                vr.addError("AuthUser \"" + u + "\" is not a valid user public key");
            }
        }
        for (const auto& acc : a.allowedAccounts) {
            if (acc == AnyAccount) {
                if (a.allowedAccounts.size() > 1) {
                    vr.addError(
                        std::string("AllowedAccounts can only be a list of accounts or \"") +
                        AnyAccount + "\"");
                }
            } else if (!nkeys::IsValidPublicAccountKey(acc)) {
                vr.addError("Account \"" + acc + "\" is not a valid account public key");
            }
        }
        if (!a.xkey.empty() && !nkeys::IsValidPublicCurveKey(a.xkey)) {
            vr.addError("XKey \"" + a.xkey + "\" is not a valid public xkey");
        }
    }

    json externalAuthorizationToJson(const ExternalAuthorization& a) {
        json o = json::object();  // Go: a struct field, never omitted
        if (!a.authUsers.empty()) o["auth_users"] = a.authUsers;
        if (!a.allowedAccounts.empty()) o["allowed_accounts"] = a.allowedAccounts;
        if (!a.xkey.empty()) o["xkey"] = a.xkey;
        return o;
    }

    ExternalAuthorization externalAuthorizationFromJson(const json& j) {
        ExternalAuthorization a;
        if (j.contains("auth_users") && j["auth_users"].is_array())
            a.authUsers = j["auth_users"].get<std::vector<std::string>>();
        if (j.contains("allowed_accounts") && j["allowed_accounts"].is_array())
            a.allowedAccounts = j["allowed_accounts"].get<std::vector<std::string>>();
        a.xkey = j.value("xkey", "");
        return a;
    }

    void validateExportsImports(const std::vector<Export>& exports,
                                const std::vector<Import>& imports, ValidationResults& vr) {
        for (const auto& e : exports) {
            if (e.type != ExportType::Stream && e.type != ExportType::Service) {
                vr.addError("invalid export type for \"" + e.subject + "\"");
            }
            if (e.type == ExportType::Stream) {
                if (!e.responseType.empty()) {
                    vr.addError("invalid response type for stream \"" + e.subject + "\"");
                }
                if (e.allowTrace) {
                    vr.addError("AllowTrace only valid for service export");
                }
                if (e.latency) {
                    vr.addError("latency tracking only permitted for services");
                }
                if (e.responseThresholdNanos > 0) {
                    vr.addError("response threshold only valid for services");
                }
            } else {
                if (!e.responseType.empty() && e.responseType != "Singleton" &&
                    e.responseType != "Stream" && e.responseType != "Chunked") {
                    vr.addError("invalid response type for service: \"" +
                                             e.responseType + "\"");
                }
            }
            if (e.responseThresholdNanos < 0) {
                vr.addError("negative response threshold is invalid");
            }
            if (e.latency && (e.latency->sampling < 0 || e.latency->sampling > 100)) {
                vr.addError("sampling percentage needs to be between 1-100 (or 0 for headers)");
            }
            if (e.accountTokenPosition > 0) {
                if (e.subject.find('*') == std::string::npos &&
                    e.subject.find('>') == std::string::npos) {
                    vr.addError(
                        "Account Token Position can only be used with wildcard subjects");
                }
            }
        }
        for (const auto& i : imports) {
            if (i.type != ExportType::Stream && i.type != ExportType::Service) {
                vr.addError("invalid import type for \"" + i.subject + "\"");
            }
            if (i.type == ExportType::Service && i.allowTrace) {
                vr.addError("AllowTrace only valid for stream import");
            }
            if (i.account.empty()) {
                vr.addError("account to import from is not specified");
            }
            if (!i.to.empty()) {
                vr.addWarning("the field to has been deprecated (use LocalSubject instead)");
            }
            if (!i.localSubject.empty() && !i.to.empty()) {
                vr.addError("Local Subject replaces To");
            }
            if (i.share && i.type != ExportType::Service) {
                vr.addError(
                    "sharing information (for latency tracking) is only valid for services");
            }
            if (!i.token.empty()) {
                std::unique_ptr<ActivationClaims> act;
                try {
                    act = decodeActivationClaims(i.token);
                } catch (const Error&) {
                    vr.addError("import \"" + i.subject + "\" contains an invalid activation token");
                    continue;
                }
                const auto issuerAccount = act->issuerAccount();
                if (act->issuer() != i.account &&
                    (!issuerAccount || *issuerAccount != i.account)) {
                    vr.addError("activation token doesn't match account for import \"" +
                                             i.subject + "\"");
                }
            }
        }
    }

} // namespace

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
        {"authorization", nlohmann::json::object()},
    };
    AccountLimits limits_;              // Go defaults: -1 no-limits (see encode)
    Permissions defaultPermissions_;
    std::map<std::string, std::vector<WeightedMapping>> mappings_;
    std::vector<Export> exports_;
    std::vector<Import> imports_;
    std::map<std::string, std::int64_t> revocations_;
    ExternalAuthorization authorization_;
    std::string description_;
    std::string infoURL_;
    std::string subject_;
    std::string issuer_;
    std::optional<std::string> name_;
    std::int64_t issuedAt_ = 0;
    std::int64_t expires_ = 0;
    std::string audience_;
    std::int64_t notBefore_ = 0;
    std::vector<std::string> tags_;
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
std::string AccountClaims::audience() const { return impl_->audience_; }
void AccountClaims::setAudience(const std::string& audience) { impl_->audience_ = audience; }
std::int64_t AccountClaims::notBefore() const { return impl_->notBefore_; }
void AccountClaims::setNotBefore(std::int64_t nbf) { impl_->notBefore_ = nbf; }
std::vector<std::string>& AccountClaims::tags() { return impl_->tags_; }
const std::vector<std::string>& AccountClaims::tags() const { return impl_->tags_; }
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

AccountLimits& AccountClaims::limits() { return impl_->limits_; }
const AccountLimits& AccountClaims::limits() const { return impl_->limits_; }
Permissions& AccountClaims::defaultPermissions() { return impl_->defaultPermissions_; }
const Permissions& AccountClaims::defaultPermissions() const { return impl_->defaultPermissions_; }
std::map<std::string, std::vector<WeightedMapping>>& AccountClaims::mappings() {
    return impl_->mappings_;
}
const std::map<std::string, std::vector<WeightedMapping>>& AccountClaims::mappings() const {
    return impl_->mappings_;
}
std::vector<Export>& AccountClaims::exports() { return impl_->exports_; }
const std::vector<Export>& AccountClaims::exports() const { return impl_->exports_; }
std::vector<Import>& AccountClaims::imports() { return impl_->imports_; }
const std::vector<Import>& AccountClaims::imports() const { return impl_->imports_; }

void AccountClaims::revoke(const std::string& pubKey) {
    revokeAt(pubKey, std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count());
}

void AccountClaims::revokeAt(const std::string& pubKey, std::int64_t unixTimestamp) {
    // A newer existing revocation is kept — a revocation can be moved into
    // the past but never into the future (Go: RevocationList.Revoke).
    auto it = impl_->revocations_.find(pubKey);
    if (it != impl_->revocations_.end() && it->second > unixTimestamp) return;
    impl_->revocations_[pubKey] = unixTimestamp;
}

void AccountClaims::clearRevocation(const std::string& pubKey) {
    impl_->revocations_.erase(pubKey);
}

bool AccountClaims::isRevoked(const std::string& pubKey, std::int64_t claimIssuedAt) const {
    auto all = impl_->revocations_.find(RevokeAll);
    if (all != impl_->revocations_.end() && all->second >= claimIssuedAt) return true;
    auto it = impl_->revocations_.find(pubKey);
    return it != impl_->revocations_.end() && it->second >= claimIssuedAt;
}

const std::map<std::string, std::int64_t>& AccountClaims::revocations() const {
    return impl_->revocations_;
}

void AccountClaims::setDescription(const std::string& description) {
    impl_->description_ = description;
}
std::string AccountClaims::description() const { return impl_->description_; }
void AccountClaims::setInfoURL(const std::string& url) { impl_->infoURL_ = url; }
ExternalAuthorization& AccountClaims::authorization() { return impl_->authorization_; }
const ExternalAuthorization& AccountClaims::authorization() const { return impl_->authorization_; }
void AccountClaims::enableExternalAuthorization(const std::vector<std::string>& userPublicKeys) {
    for (const auto& u : userPublicKeys) {
        auto& users = impl_->authorization_.authUsers;
        if (std::find(users.begin(), users.end(), u) == users.end()) users.push_back(u);
    }
}
bool AccountClaims::hasExternalAuthorization() const { return impl_->authorization_.isEnabled(); }
std::string AccountClaims::infoURL() const { return impl_->infoURL_; }

std::string AccountClaims::encode(const std::string& seed) const {
    // the seed path is the signer path with an in-process keypair
    auto keypair = nkeys::FromSeed(seed);
    return encodeWithSigner(keypair->publicString(), internal::signerFor(*keypair));
}

std::string AccountClaims::encodeWithSigner(const std::string& issuerPublicKey,
                                            const SignFn& sign) const {
    using namespace internal;
    using json = nlohmann::json;

    // Go's doEncode: the issuer IS the signing key — derived, never taken on
    // trust from a setter (iss can then never disagree with the signature) —
    // and iat is stamped fresh at every encode.
    impl_->issuer_ = issuerPublicKey;
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
    if (!impl_->audience_.empty()) payload["aud"] = impl_->audience_;
    if (impl_->notBefore_ > 0) payload["nbf"] = impl_->notBefore_;

    // NATS-specific claims: start from the carried nats object, then
    // overwrite the fields this port manages.

    json nats_claims = impl_->natsRaw_;
    nats_claims["limits"] = accountLimitsToJson(impl_->limits_);
    nats_claims["default_permissions"] = {
        {"pub", internal::permissionToJson(impl_->defaultPermissions_.pub)},
        {"sub", internal::permissionToJson(impl_->defaultPermissions_.sub)}};
    if (!impl_->mappings_.empty()) {
        json maps = json::object();
        for (const auto& [from, wms] : impl_->mappings_) {
            json arr = json::array();
            for (const auto& wm : wms) {
                json entry = {{"subject", wm.subject}};
                if (wm.weight != 0) entry["weight"] = wm.weight;
                if (!wm.cluster.empty()) entry["cluster"] = wm.cluster;
                arr.push_back(entry);
            }
            maps[from] = arr;
        }
        nats_claims["mappings"] = maps;
    } else {
        nats_claims.erase("mappings");
    }
    if (!impl_->exports_.empty()) {
        json arr = json::array();
        for (const auto& e : impl_->exports_) arr.push_back(exportToJson(e));
        nats_claims["exports"] = arr;
    } else {
        nats_claims.erase("exports");
    }
    if (!impl_->imports_.empty()) {
        json arr = json::array();
        for (const auto& i : impl_->imports_) arr.push_back(importToJson(i));
        nats_claims["imports"] = arr;
    } else {
        nats_claims.erase("imports");
    }
    if (!impl_->revocations_.empty()) nats_claims["revocations"] = impl_->revocations_;
    else nats_claims.erase("revocations");
    nats_claims["authorization"] = externalAuthorizationToJson(impl_->authorization_);
    if (!impl_->description_.empty()) nats_claims["description"] = impl_->description_;
    else nats_claims.erase("description");
    if (!impl_->infoURL_.empty()) nats_claims["info_url"] = impl_->infoURL_;
    else nats_claims.erase("info_url");
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
    if (!impl_->tags_.empty()) nats_claims["tags"] = impl_->tags_;
    else nats_claims.erase("tags");
    nats_claims["type"] = "account";
    nats_claims["version"] = JWT_VERSION;
    payload["nats"] = nats_claims;

    payload["jti"] = computeJti(payload.dump());

    // Go's doEncode tail: header.payload → signer → (verified) signature
    return signAndAssemble(payload.dump(), issuerPublicKey, sign);
}

void AccountClaims::validate(ValidationResults& vr) const {
    internal::addTimeChecks(vr, impl_->expires_, impl_->notBefore_);
    validateAccountConfig(impl_->limits_, impl_->mappings_, vr);
    validateExportsImports(impl_->exports_, impl_->imports_, vr);
    validateExternalAuthorization(impl_->authorization_, vr);
    // Go: IsEmpty is the ZERO value, so this fires even for the -1 no-limit
    // defaults (measured on Go's own self-signed golden)
    const auto& l = impl_->limits_;
    const bool limitsEmpty = l.subs == 0 && l.data == 0 && l.payload == 0 && l.imports == 0 &&
                             l.exports == 0 && !l.wildcardExports && !l.disallowBearer &&
                             l.conn == 0 && l.leafNodeConn == 0 &&
                             l.jetStream == JetStreamLimits{} && l.tieredLimits.empty();
    if (nkeys::IsValidPublicAccountKey(impl_->issuer_) && !limitsEmpty) {
        vr.addWarning("self-signed account JWTs shouldn't contain operator limits");
    }
}

void AccountClaims::validate() const {
    checkStructure();
    ValidationResults vr;
    validate(vr);
    internal::throwFirstBlocking(vr);
}

void AccountClaims::checkStructure() const {
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
    // Go's Decode: header validity, payload-derived version, per-version
    // signature rule, v1 → v2 migration — shared in decodeEnvelope.
    auto env = decodeEnvelope(jwt);
    const json& payload = env.payload;
    auto nats = payload["nats"];
    if (!nats.contains("type") || nats["type"] != "account") {
        throw InvalidClaimsError(
            "JWT type mismatch: expected 'account', got '" +
            (nats.contains("type") ? nats["type"].get<std::string>() : "missing") + "'"
        );
    }

    std::string subject = payload.at("sub").get<std::string>();
    std::string issuer = payload.at("iss").get<std::string>();
    std::int64_t iat = payload.at("iat").get<std::int64_t>();

    // Create AccountClaims object
    auto claims = std::make_unique<AccountClaims>(subject);
    claims->impl_->natsRaw_ = nats;

    // Typed account configuration (fix-plan group 1)
    if (nats.contains("limits") && nats["limits"].is_object()) {
        claims->impl_->limits_ = accountLimitsFromJson(nats["limits"]);
    } else {
        claims->impl_->limits_ = AccountLimits{0, 0, 0, 0, 0, false, false, 0, 0, {}, {}};
    }
    if (nats.contains("default_permissions") && nats["default_permissions"].is_object()) {
        const auto& dp = nats["default_permissions"];
        if (dp.contains("pub")) claims->impl_->defaultPermissions_.pub =
            internal::permissionFromJson(dp["pub"]);
        if (dp.contains("sub")) claims->impl_->defaultPermissions_.sub =
            internal::permissionFromJson(dp["sub"]);
    } else {
        claims->impl_->defaultPermissions_ = Permissions{};
    }
    if (nats.contains("mappings") && nats["mappings"].is_object()) {
        for (const auto& [from, arr] : nats["mappings"].items()) {
            std::vector<WeightedMapping> wms;
            for (const auto& entry : arr) {
                wms.push_back({entry.value("subject", ""),
                               static_cast<std::uint8_t>(entry.value("weight", 0)),
                               entry.value("cluster", "")});
            }
            claims->impl_->mappings_[from] = std::move(wms);
        }
    }
    if (nats.contains("exports") && nats["exports"].is_array()) {
        for (const auto& e : nats["exports"]) {
            claims->impl_->exports_.push_back(exportFromJson(e));
        }
    }
    if (nats.contains("imports") && nats["imports"].is_array()) {
        for (const auto& i : nats["imports"]) {
            claims->impl_->imports_.push_back(importFromJson(i));
        }
    }
    if (nats.contains("revocations") && nats["revocations"].is_object()) {
        for (const auto& [key, ts] : nats["revocations"].items()) {
            claims->impl_->revocations_[key] = ts.get<std::int64_t>();
        }
    }
    if (nats.contains("authorization") && nats["authorization"].is_object()) {
        claims->impl_->authorization_ = externalAuthorizationFromJson(nats["authorization"]);
    }
    claims->impl_->description_ = nats.value("description", "");
    claims->impl_->infoURL_ = nats.value("info_url", "");

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
    claims->checkStructure();

    return claims;
}

}
