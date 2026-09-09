#pragma once
// Internal: (de)serialization shared between user and account claims for the
// Permissions/Limits family — wire shapes measured from Go (see tests).
#include "jwt/permissions.hpp"
#include <nlohmann/json.hpp>

namespace jwt::internal {

inline nlohmann::json permissionToJson(const Permission& p) {
    nlohmann::json out = nlohmann::json::object();
    if (!p.allow.empty()) out["allow"] = p.allow;
    if (!p.deny.empty()) out["deny"] = p.deny;
    return out;
}

inline Permission permissionFromJson(const nlohmann::json& j) {
    Permission p;
    if (j.contains("allow")) p.allow = j["allow"].get<std::vector<std::string>>();
    if (j.contains("deny")) p.deny = j["deny"].get<std::vector<std::string>>();
    return p;
}

// Go's UserPermissionLimits, written FRESH (no carry layer): pub/sub always
// present; everything else per omitempty.
inline nlohmann::json userPermissionLimitsToJson(const Permissions& perms,
                                                 const UserLimits& limits,
                                                 bool bearerToken,
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
    if (!connTypes.empty()) out["allowed_connection_types"] = connTypes;
    return out;
}

inline void userPermissionLimitsFromJson(const nlohmann::json& j, Permissions& perms,
                                         UserLimits& limits, bool& bearerToken,
                                         std::vector<std::string>& connTypes) {
    if (j.contains("pub")) perms.pub = permissionFromJson(j["pub"]);
    if (j.contains("sub")) perms.sub = permissionFromJson(j["sub"]);
    if (j.contains("resp") && j["resp"].is_object()) {
        perms.resp = ResponsePermission{j["resp"].value("max", 0),
                                        j["resp"].value("ttl", std::int64_t{0})};
    }
    limits.subs = j.value("subs", std::int64_t{0});
    limits.data = j.value("data", std::int64_t{0});
    limits.payload = j.value("payload", std::int64_t{0});
    if (j.contains("src") && j["src"].is_array())
        limits.src = j["src"].get<std::vector<std::string>>();
    if (j.contains("times") && j["times"].is_array())
        for (const auto& tr : j["times"])
            limits.times.push_back({tr.value("start", ""), tr.value("end", "")});
    limits.locale = j.value("times_location", "");
    bearerToken = j.value("bearer_token", false);
    if (j.contains("allowed_connection_types"))
        connTypes = j["allowed_connection_types"].get<std::vector<std::string>>();
}

// Go's UserScope: kind/key/role/template/description, none omitempty.
inline nlohmann::json userScopeToJson(const UserScope& s) {
    return {{"kind", "user_scope"},
            {"key", s.key},
            {"role", s.role},
            {"template", userPermissionLimitsToJson(s.permissions, s.limits,
                                                    s.bearerToken, s.allowedConnectionTypes)},
            {"description", s.description}};
}

inline UserScope userScopeFromJson(const nlohmann::json& j) {
    UserScope s;
    s.key = j.value("key", "");
    s.role = j.value("role", "");
    s.description = j.value("description", "");
    if (j.contains("template")) {
        userPermissionLimitsFromJson(j["template"], s.permissions, s.limits,
                                     s.bearerToken, s.allowedConnectionTypes);
    }
    return s;
}

} // namespace jwt::internal
