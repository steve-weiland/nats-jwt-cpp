#include "jwt/jwt.hpp"
#include "jwt/operator_claims.hpp"
#include "jwt/account_claims.hpp"
#include "jwt/user_claims.hpp"
#include "jwt/activation_claims.hpp"
#include "jwt/authorization_claims.hpp"
#include "jwt/generic_claims.hpp"
#include "base64url.hpp"
#include "jwt_utils.hpp"
#include <nlohmann/json.hpp>
#include <stdexcept>

namespace jwt {

std::unique_ptr<Claims> decode(const std::string& jwt) {
    using namespace internal;
    using json = nlohmann::json;

    auto parts = parseJwt(jwt);

    auto payload_bytes = base64url_decode(parts.payload_b64);
    std::string payload_json(payload_bytes.begin(), payload_bytes.end());
    json payload;
    try {
        payload = json::parse(payload_json);
    } catch (const json::exception& e) {
        throw MalformedTokenError(std::string("Invalid JWT payload JSON: ") + e.what());
    }

    // Go's identifier: a top-level type marks the v1 layout, else nats.type.
    // Unknown types decode as GenericClaims (Go: loadClaims' default);
    // cluster/server are refused by Go and by us.
    // Go's identifier: type fields are strings or an unmarshal error; an
    // EMPTY top-level type falls through to nats.type (Go: Kind())
    std::string type;
    if (payload.contains("type")) {
        if (!payload["type"].is_string()) throw MalformedTokenError("JWT 'type' is not a string");
        type = payload["type"].get<std::string>();
    }
    if (type.empty() && payload.contains("nats") && payload["nats"].is_object() &&
        payload["nats"].contains("type")) {
        if (!payload["nats"]["type"].is_string()) throw MalformedTokenError("JWT nats.type is not a string");
        type = payload["nats"]["type"].get<std::string>();
    }

    if (type == "operator") return decodeOperatorClaims(jwt);
    if (type == "account") return decodeAccountClaims(jwt);
    if (type == "user") return decodeUserClaims(jwt);
    if (type == "activation") return decodeActivationClaims(jwt);
    if (type == "authorization_request") return decodeAuthorizationRequestClaims(jwt);
    if (type == "authorization_response") return decodeAuthorizationResponseClaims(jwt);
    if (type == "cluster") throw InvalidClaimsError("ClusterClaims are not supported");
    if (type == "server") throw InvalidClaimsError("ServerClaims are not supported");
    return decodeGeneric(jwt);
}

bool verify(const std::string& jwt) {
    using namespace internal;
    using json = nlohmann::json;

    try {
        auto parts = parseJwt(jwt);

        auto payload_bytes = base64url_decode(parts.payload_b64);
        std::string payload_json(payload_bytes.begin(), payload_bytes.end());
        auto payload = json::parse(payload_json);

        // Extract issuer (the public key that signed this JWT)
        if (!payload.contains("iss")) {
            return false;
        }
        std::string issuer = payload["iss"].get<std::string>();

        return verifySignature(issuer, parts.signing_input, parts.signature_b64);

    } catch (...) {
        // Any exception means verification failed
        return false;
    }
}

}
