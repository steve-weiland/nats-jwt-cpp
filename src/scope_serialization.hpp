#pragma once
// Internal: (de)serialization shared between user and account claims for the
// Permissions/Limits family — wire shapes measured from Go (see tests).
#include "jwt/permissions.hpp"
#include <nlohmann/json.hpp>
#include "jwt_utils.hpp"

namespace jwt::internal {

inline nlohmann::json permissionToJson(const Permission& p) {
    nlohmann::json out = nlohmann::json::object();
    if (!p.allow.empty()) out["allow"] = p.allow;
    if (!p.deny.empty()) out["deny"] = p.deny;
    return out;
}

inline Permission permissionFromJson(const nlohmann::json& j) {
    Permission p;
    if (const auto* a = arrayField(j, "allow")) p.allow = a->get<std::vector<std::string>>();
    if (const auto* a = arrayField(j, "deny")) p.deny = a->get<std::vector<std::string>>();
    return p;
}

// Go's UserPermissionLimits, written FRESH (no carry layer): pub/sub always
// present; everything else per omitempty.
inline nlohmann::json userPermissionLimitsToJson(const Permissions& perms,
                                                 const UserLimits& limits,
                                                 bool bearerToken, bool proxyRequired,
                                                 const std::vector<std::string>& connTypes) {
    nlohmann::json out = nlohmann::json::object();
    out["pub"] = permissionToJson(perms.pub);
    out["sub"] = permissionToJson(perms.sub);
    if (perms.resp) out["resp"] = {{"max", perms.resp->maxMsgs}, {"ttl", perms.resp->ttlNanos}};
    if (limits.subs != 0) out["subs"] = limits.subs;
    if (limits.data != 0) out["data"] = limits.data;
    if (limits.payload != 0) out["payload"] = limits.payload;
    if (!limits.src.empty()) out["src"] = limits.src;
    if (!limits.times.empty()) {
        nlohmann::json times = nlohmann::json::array();
        for (const auto& tr : limits.times) times.push_back({{"start", tr.start}, {"end", tr.end}});
        out["times"] = times;
    }
    if (!limits.locale.empty()) out["times_location"] = limits.locale;
    if (bearerToken) out["bearer_token"] = true;
    if (proxyRequired) out["proxy_required"] = true;
    if (!connTypes.empty()) out["allowed_connection_types"] = connTypes;
    return out;
}

inline void userPermissionLimitsFromJson(const nlohmann::json& j, Permissions& perms,
                                         UserLimits& limits, bool& bearerToken,
                                         bool& proxyRequired,
                                         std::vector<std::string>& connTypes) {
    if (const auto* o = objectField(j, "pub")) perms.pub = permissionFromJson(*o);
    if (const auto* o = objectField(j, "sub")) perms.sub = permissionFromJson(*o);
    if (const auto* o = objectField(j, "resp")) {
        perms.resp = ResponsePermission{
            static_cast<int>(intField(*o, "max", 0)), intField(*o, "ttl", 0)};
    }
    // Go's SigningKeys.UnmarshalJSON starts from NewUserScope(): NatsLimits
    // preset to NoLimit — an absent template limit means UNLIMITED
    limits.subs = intField(j, "subs", -1);
    limits.data = intField(j, "data", -1);
    limits.payload = intField(j, "payload", -1);
    if (const auto* a = arrayField(j, "src")) limits.src = a->get<std::vector<std::string>>();
    if (const auto* a = arrayField(j, "times"))
        for (const auto& tr : *a)
            limits.times.push_back({tr.value("start", ""), tr.value("end", "")});
    limits.locale = j.value("times_location", "");
    bearerToken = j.value("bearer_token", false);
    proxyRequired = j.value("proxy_required", false);
    if (const auto* a = arrayField(j, "allowed_connection_types"))
        connTypes = a->get<std::vector<std::string>>();
}

// Go's UserScope: kind/key/role/template/description, none omitempty.
inline nlohmann::json userScopeToJson(const UserScope& s) {
    return {{"kind", "user_scope"},
            {"key", s.key},
            {"role", s.role},
            {"template", userPermissionLimitsToJson(s.permissions, s.limits,
                                                    s.bearerToken, s.proxyRequired,
                                                    s.allowedConnectionTypes)},
            {"description", s.description}};
}

inline UserScope userScopeFromJson(const nlohmann::json& j) {
    UserScope s;
    s.key = j.value("key", "");
    s.role = j.value("role", "");
    s.description = j.value("description", "");
    if (const auto* t = objectField(j, "template")) {
        userPermissionLimitsFromJson(*t, s.permissions, s.limits,
                                     s.bearerToken, s.proxyRequired, s.allowedConnectionTypes);
    }
    return s;
}

} // namespace jwt::internal
