#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace jwt {

/// Subject allow/deny lists (Go: Permission). A sub entry may carry a queue
/// group as "subject queue" — legal only for subscriptions.
struct Permission {
    std::vector<std::string> allow;
    std::vector<std::string> deny;

    [[nodiscard]] bool empty() const { return allow.empty() && deny.empty(); }
};

/// Response permission (Go: ResponsePermission). ttlNanos is Go's
/// time.Duration on the wire: NANOSECONDS in the "ttl" field.
struct ResponsePermission {
    int maxMsgs = 0;
    std::int64_t ttlNanos = 0;
};

/// User pub/sub permissions (Go: Permissions).
struct Permissions {
    Permission pub;
    Permission sub;
    std::optional<ResponsePermission> resp;
};

/// A daily validity window, "HH:MM:SS" (Go: TimeRange, format 15:04:05).
struct TimeRange {
    std::string start;
    std::string end;
};

/// User limits (Go: Limits = NatsLimits + UserLimits). -1 = no limit; a
/// value of 0 is OMITTED on the wire, and nats-server treats absent as zero.
struct UserLimits {
    std::int64_t subs = -1;
    std::int64_t data = -1;
    std::int64_t payload = -1;
    std::vector<std::string> src;     ///< CIDR blocks the user may connect from
    std::vector<TimeRange> times;     ///< daily validity windows
    std::string locale;               ///< IANA timezone for times ("times_location")
};

/// Connection types a user may be limited to (Go's ConnectionType*
/// constants). Go's jwt does NOT validate these strings — the server does —
/// so any string is accepted; these are the ones nats-server knows.
namespace ConnectionType {
    inline constexpr const char* Standard   = "STANDARD";
    inline constexpr const char* Websocket  = "WEBSOCKET";
    inline constexpr const char* Leafnode   = "LEAFNODE";
    inline constexpr const char* LeafnodeWS = "LEAFNODE_WS";
    inline constexpr const char* Mqtt       = "MQTT";
    inline constexpr const char* MqttWS     = "MQTT_WS";
    inline constexpr const char* InProcess  = "IN_PROCESS";
}

/// A scoped signing key (Go: UserScope) — an account signing key that
/// imposes a permission/limit TEMPLATE on every user it issues. The server
/// replaces the user's (required-empty) permissions with this template.
struct UserScope {
    std::string key;          ///< the scoped signing key ("A…")
    std::string role;
    std::string description;
    Permissions permissions;  ///< template permissions
    UserLimits limits;        ///< template limits
    bool bearerToken = false;                        ///< no nonce signing (browser/ws clients)
    bool proxyRequired = false;                      ///< must connect through a proxy (server 2.11+)
    std::vector<std::string> allowedConnectionTypes; ///< ConnectionType::* strings
};

} // namespace jwt
