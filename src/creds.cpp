#include "jwt/creds.hpp"
#include "jwt/jwt.hpp"
#include <nkeys/nkeys.hpp>
#include <chrono>
#include <sstream>

namespace jwt {

std::string parseDecoratedJWT(std::string_view contents) {
    return nkeys::ParseDecoratedJWT(contents);
}

std::unique_ptr<nkeys::KeyPair> parseDecoratedNKey(std::string_view contents) {
    return nkeys::ParseDecoratedNKey(contents);
}

std::unique_ptr<nkeys::KeyPair> parseDecoratedUserNKey(std::string_view contents) {
    return nkeys::ParseDecoratedUserNKey(contents);
}

namespace {
    // Go's formatJwt template: kind uppercased, trailing blank line included.
    std::string armorJwt(const std::string& kind, const std::string& token) {
        std::ostringstream oss;
        oss << "-----BEGIN NATS " << kind << " JWT-----\n";
        oss << token << "\n";
        oss << "------END NATS " << kind << " JWT------\n";
        oss << "\n";
        return oss.str();
    }
}

std::string decorateJWT(const std::string& jwt) {
    // Authenticated decode, as in Go — decorate only what verifies.
    auto claims = decode(jwt);
    std::string kind;
    if (dynamic_cast<const OperatorClaims*>(claims.get())) {
        kind = "OPERATOR";
    } else if (dynamic_cast<const AccountClaims*>(claims.get())) {
        kind = "ACCOUNT";
    } else if (dynamic_cast<const ActivationClaims*>(claims.get())) {
        kind = "ACTIVATION";
    } else {
        kind = "USER";
    }
    return armorJwt(kind, jwt);
}

std::string decorateSeed(std::string_view seed) {
    std::string kind;
    if (seed.size() >= 2 && seed[0] == 'S') {
        switch (seed[1]) {
            case 'U': kind = "USER"; break;
            case 'A': kind = "ACCOUNT"; break;
            case 'O': kind = "OPERATOR"; break;
            default: break;
        }
    }
    if (kind.empty()) {
        throw InvalidClaimsError("seed is not an operator, account or user seed");
    }
    // Byte-identical to Go's DecorateSeed template.
    std::ostringstream oss;
    oss << "************************* IMPORTANT *************************\n";
    oss << "NKEY Seed printed below can be used to sign and prove identity.\n";
    oss << "NKEYs are sensitive and should be treated as secrets.\n";
    oss << "\n";
    oss << "-----BEGIN " << kind << " NKEY SEED-----\n";
    oss << seed << "\n";
    oss << "------END " << kind << " NKEY SEED------\n";
    oss << "\n";
    oss << "*************************************************************\n";
    return oss.str();
}

std::string issueUserJWT(const std::string& scopedSigningKeySeed,
                         const std::string& accountId,
                         const std::string& publicUserKey,
                         const std::string& name,
                         std::int64_t expirationSeconds) {
    if (!nkeys::IsValidPublicAccountKey(accountId)) {
        throw InvalidClaimsError("issueUserJWT requires an account key for accountId");
    }
    if (!nkeys::IsValidPublicUserKey(publicUserKey)) {
        throw InvalidClaimsError("issueUserJWT requires a user key for publicUserKey");
    }
    UserClaims claims(publicUserKey);
    claims.setScoped(true);
    claims.setIssuerAccount(accountId);
    claims.setName(name.empty() ? publicUserKey : name);
    if (expirationSeconds > 0) {
        claims.setExpires(std::chrono::duration_cast<std::chrono::seconds>(
                              std::chrono::system_clock::now().time_since_epoch())
                              .count() +
                          expirationSeconds);
    }
    return claims.encode(scopedSigningKeySeed);
}

} // namespace jwt
