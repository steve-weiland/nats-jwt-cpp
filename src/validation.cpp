#include "jwt/validation.hpp"
#include "jwt/jwt.hpp"
#include "jwt/operator_claims.hpp"
#include "jwt/account_claims.hpp"
#include "jwt/user_claims.hpp"
#include <chrono>
#include <sstream>

namespace jwt {

namespace {
    /**
     * Get current Unix timestamp in seconds
     */
    std::int64_t getCurrentTime() {
        auto now = std::chrono::system_clock::now();
        auto since_epoch = now.time_since_epoch();
        return std::chrono::duration_cast<std::chrono::seconds>(since_epoch).count();
    }

    /**
     * Get the claim type from subject key prefix
     */
    std::string getClaimType(const std::string& subject) {
        if (subject.empty()) return "unknown";
        switch (subject[0]) {
            case 'O': return "operator";
            case 'A': return "account";
            case 'U': return "user";
            default: return "unknown";
        }
    }
}

ValidationResult validateExpiration(const Claims& claims, std::int64_t clockSkewSeconds) {
    std::int64_t exp = claims.expires();

    // If expires is 0 or negative, the JWT never expires
    if (exp <= 0) {
        return ValidationResult::success();
    }

    std::int64_t now = getCurrentTime();
    std::int64_t expiresWithSkew = exp + clockSkewSeconds;

    if (now > expiresWithSkew) {
        std::ostringstream oss;
        oss << "JWT has expired (exp: " << exp << ", now: " << now << ")";
        return ValidationResult::failure(oss.str());
    }

    return ValidationResult::success();
}

ValidationResult validateNotBefore(const Claims& claims, std::int64_t clockSkewSeconds) {
    // Go's only not-before rule (ClaimsData.Validate): nbf > now is "claim is
    // not yet valid". iat is NEVER checked — the earlier iat-based rule here
    // was an invention (corrected with group 6a; nats-server treats Go's
    // time checks as blocking for user auth, so nbf is what matters).
    std::int64_t nbf = claims.notBefore();
    if (nbf <= 0) {
        return ValidationResult::success();
    }

    std::int64_t now = getCurrentTime();
    if (nbf - clockSkewSeconds > now) {
        std::ostringstream oss;
        oss << "claim is not yet valid (nbf: " << nbf << ", now: " << now << ")";
        return ValidationResult::failure(oss.str());
    }

    return ValidationResult::success();
}

ValidationResult validateTiming(const Claims& claims, const ValidationOptions& opts) {
    if (opts.checkNotBefore) {
        auto nbfResult = validateNotBefore(claims, opts.clockSkewSeconds);
        if (!nbfResult.valid) {
            return nbfResult;
        }
    }

    if (opts.checkExpiration) {
        auto expResult = validateExpiration(claims, opts.clockSkewSeconds);
        if (!expResult.valid) {
            return expResult;
        }
    }

    return ValidationResult::success();
}

ValidationResult validateIssuerChain(const Claims& child, const Claims& parent) {
    std::string childIssuer = child.issuer();
    std::string parentSubject = parent.subject();

    if (childIssuer.empty()) {
        return ValidationResult::failure("Child issuer is empty");
    }

    if (parentSubject.empty()) {
        return ValidationResult::failure("Parent subject is empty");
    }

    // The parent vouches for its identity key AND its signing keys — Go's
    // canonical flow issues children by signing key (the operator's account
    // JWTs, the account's user JWTs), so subject-only matching rejected the
    // very setup the Go README demonstrates.
    bool issuerVouchedFor = (childIssuer == parentSubject);
    if (!issuerVouchedFor) {
        const std::vector<std::string>* signingKeys = nullptr;
        if (const auto* op = dynamic_cast<const OperatorClaims*>(&parent)) {
            signingKeys = &op->signingKeys();
        } else if (const auto* acc = dynamic_cast<const AccountClaims*>(&parent)) {
            signingKeys = &acc->signingKeys();
        }
        if (signingKeys) {
            for (const auto& key : *signingKeys) {
                if (childIssuer == key) {
                    issuerVouchedFor = true;
                    break;
                }
            }
        }
    }
    if (!issuerVouchedFor) {
        std::ostringstream oss;
        oss << "Issuer chain broken: child issuer '" << childIssuer
            << "' is neither parent subject '" << parentSubject
            << "' nor one of its signing keys";
        return ValidationResult::failure(oss.str());
    }

    // A child issued by a signing key names its account via issuer_account —
    // when present it must be THIS account, or the child belongs elsewhere.
    // Users and auth-callout responses both carry it (the server applies the
    // same rule to responses: issuer is the account key or a signing key).
    {
        std::optional<std::string> issuerAccount;
        if (const auto* user = dynamic_cast<const UserClaims*>(&child)) {
            issuerAccount = user->issuerAccount();
        } else if (const auto* resp = dynamic_cast<const AuthorizationResponseClaims*>(&child)) {
            issuerAccount = resp->issuerAccount();
        }
        if (issuerAccount && *issuerAccount != parentSubject) {
            std::ostringstream oss;
            oss << "issuer_account '" << *issuerAccount
                << "' does not match the account subject '" << parentSubject << "'";
            return ValidationResult::failure(oss.str());
        }
    }

    // A user issued by a SCOPED signing key must carry no permissions or
    // limits of its own (Go: ValidateScopedSigner) — the scope's template
    // governs it; anything self-set would be an escalation past the scope.
    if (const auto* user = dynamic_cast<const UserClaims*>(&child)) {
        if (const auto* acc = dynamic_cast<const AccountClaims*>(&parent)) {
            if (acc->getScope(childIssuer) && !user->hasEmptyPermissions()) {
                return ValidationResult::failure(
                    "scoped users require no permissions or limits set");
            }
        }
    }

    return ValidationResult::success();
}

ValidationResult validateKeyHierarchy(const Claims& child, const Claims& parent) {
    std::string childSubject = child.subject();
    std::string childIssuer = child.issuer();
    std::string parentSubject = parent.subject();

    if (childSubject.empty() || childIssuer.empty() || parentSubject.empty()) {
        return ValidationResult::failure("Empty subject or issuer in key hierarchy validation");
    }

    char childType = childSubject[0];
    char issuerType = childIssuer[0];
    char parentType = parentSubject[0];

    // Verify issuer and parent have same type
    if (issuerType != parentType) {
        std::ostringstream oss;
        oss << "Issuer type mismatch: child issuer type '" << issuerType
            << "' does not match parent type '" << parentType << "'";
        return ValidationResult::failure(oss.str());
    }

    // Verify hierarchy rules
    if (childType == 'O' && parentType == 'O') {
        // Operator self-signed - OK
        if (childSubject != parentSubject) {
            return ValidationResult::failure("Operator must be self-signed");
        }
    } else if (childType == 'A' && parentType == 'O') {
        // Account signed by Operator - OK
    } else if (childType == 'U' && parentType == 'A') {
        // User signed by Account - OK
    } else {
        std::ostringstream oss;
        oss << "Invalid hierarchy: " << getClaimType(childSubject)
            << " cannot be signed by " << getClaimType(parentSubject);
        return ValidationResult::failure(oss.str());
    }

    return ValidationResult::success();
}

ValidationResult validate(const std::string& jwt, const ValidationOptions& opts) {
    // Decode JWT
    std::unique_ptr<Claims> claims;
    try {
        claims = decode(jwt);
    } catch (const std::exception& e) {
        std::ostringstream oss;
        oss << "Failed to decode JWT: " << e.what();
        return ValidationResult::failure(oss.str());
    }

    // Check signature if requested
    if (opts.checkSignature) {
        bool valid = verify(jwt);
        if (!valid) {
            return ValidationResult::failure("Invalid JWT signature");
        }
    }

    // Validate timing
    auto timingResult = validateTiming(*claims, opts);
    if (!timingResult.valid) {
        return timingResult;
    }

    // Perform structural validation
    try {
        claims->validate();
    } catch (const std::exception& e) {
        std::ostringstream oss;
        oss << "Structural validation failed: " << e.what();
        return ValidationResult::failure(oss.str());
    }

    return ValidationResult::success();
}

ValidationResult validate(const Claims& claims, const ValidationOptions& opts) {
    // Validate timing
    auto timingResult = validateTiming(claims, opts);
    if (!timingResult.valid) {
        return timingResult;
    }

    // Perform structural validation
    try {
        claims.validate();
    } catch (const std::exception& e) {
        std::ostringstream oss;
        oss << "Structural validation failed: " << e.what();
        return ValidationResult::failure(oss.str());
    }

    return ValidationResult::success();
}

ValidationResult validateChain(const std::vector<std::string>& jwts, const ValidationOptions& opts) {
    if (jwts.empty()) {
        return ValidationResult::failure("Empty JWT chain");
    }

    // Decode all JWTs
    std::vector<std::unique_ptr<Claims>> claimsChain;
    for (size_t i = 0; i < jwts.size(); ++i) {
        // Validate each JWT individually
        auto result = validate(jwts[i], opts);
        if (!result.valid) {
            std::ostringstream oss;
            oss << "JWT at index " << i << " failed validation: " << result.error.value_or("unknown error");
            return ValidationResult::failure(oss.str());
        }

        // Decode for chain validation
        try {
            claimsChain.push_back(decode(jwts[i]));
        } catch (const std::exception& e) {
            std::ostringstream oss;
            oss << "Failed to decode JWT at index " << i << ": " << e.what();
            return ValidationResult::failure(oss.str());
        }
    }

    // Validate chain relationships if requested
    if (opts.checkIssuerChain && claimsChain.size() > 1) {
        for (size_t i = 1; i < claimsChain.size(); ++i) {
            const Claims& child = *claimsChain[i];
            const Claims& parent = *claimsChain[i - 1];

            // Validate issuer chain
            auto chainResult = validateIssuerChain(child, parent);
            if (!chainResult.valid) {
                std::ostringstream oss;
                oss << "Chain validation failed at index " << i << ": " << chainResult.error.value_or("unknown error");
                return ValidationResult::failure(oss.str());
            }

            // Validate key hierarchy
            auto hierarchyResult = validateKeyHierarchy(child, parent);
            if (!hierarchyResult.valid) {
                std::ostringstream oss;
                oss << "Hierarchy validation failed at index " << i << ": " << hierarchyResult.error.value_or("unknown error");
                return ValidationResult::failure(oss.str());
            }
        }
    }

    return ValidationResult::success();
}

}
