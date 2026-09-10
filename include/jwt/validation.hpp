#pragma once

#include "jwt/claims.hpp"
#include <string>
#include <optional>
#include <vector>
#include <cstdint>

namespace jwt {

/**
 * Validation result indicating success or failure with optional error message
 */
struct ValidationResult {
    bool valid;
    std::optional<std::string> error;

    explicit operator bool() const { return valid; }

    static ValidationResult success() {
        return ValidationResult{true, std::nullopt};
    }

    static ValidationResult failure(const std::string& msg) {
        return ValidationResult{false, msg};
    }
};

/**
 * Options for configuring JWT validation behavior
 */
struct ValidationOptions {
    // Time-based validation
    bool checkExpiration = true;        // Check if JWT has expired
    bool checkNotBefore = false;        // Check if JWT is not yet valid (nbf claim)
    std::int64_t clockSkewSeconds = 0;  // Allow clock skew tolerance

    // Signature validation
    bool checkSignature = true;         // Verify signature

    // Chain validation
    bool checkIssuerChain = false;      // Verify issuer chain (parent signed child)

    static ValidationOptions strict() {
        ValidationOptions opts;
        opts.checkExpiration = true;
        opts.checkNotBefore = true;
        opts.checkSignature = true;
        opts.checkIssuerChain = true;
        opts.clockSkewSeconds = 0;
        return opts;
    }

    static ValidationOptions permissive() {
        ValidationOptions opts;
        opts.checkExpiration = false;
        opts.checkNotBefore = false;
        opts.checkSignature = false;
        opts.checkIssuerChain = false;
        opts.clockSkewSeconds = 300;  // 5 minutes
        return opts;
    }
};

/**
 * Check if a JWT has expired based on current time
 * @param claims The claims to validate
 * @param clockSkewSeconds Clock skew tolerance in seconds
 * @return ValidationResult indicating if the JWT is expired
 */
ValidationResult validateExpiration(const Claims& claims, std::int64_t clockSkewSeconds = 0);

/**
 * Check if a JWT is not yet valid (nbf - not before). Go parity: only `nbf`
 * is consulted; `iat` is never a validity bound.
 * @param claims The claims to validate
 * @param clockSkewSeconds Clock skew tolerance in seconds
 * @return ValidationResult indicating if the JWT is not yet valid
 */
ValidationResult validateNotBefore(const Claims& claims, std::int64_t clockSkewSeconds = 0);

/**
 * Perform comprehensive time-based validation
 * @param claims The claims to validate
 * @param opts Validation options
 * @return ValidationResult with details of any failures
 */
ValidationResult validateTiming(const Claims& claims, const ValidationOptions& opts = ValidationOptions{});

/**
 * Validate the issuer chain - verify that the child's issuer matches the parent's subject
 * @param child The child claims (signed by parent)
 * @param parent The parent claims (issuer)
 * @return ValidationResult indicating if the chain is valid
 */
ValidationResult validateIssuerChain(const Claims& child, const Claims& parent);

/**
 * Validate the signing key type matches expected hierarchy
 * @param child The child claims
 * @param parent The parent claims
 * @return ValidationResult indicating if the key types match hierarchy rules
 */
ValidationResult validateKeyHierarchy(const Claims& child, const Claims& parent);

/**
 * Perform comprehensive validation on a JWT string
 * @param jwt The JWT string to validate
 * @param opts Validation options
 * @return ValidationResult with details of any failures
 */
ValidationResult validate(const std::string& jwt, const ValidationOptions& opts = ValidationOptions{});

/**
 * Perform comprehensive validation on decoded claims
 * @param claims The claims to validate
 * @param opts Validation options
 * @return ValidationResult with details of any failures
 */
ValidationResult validate(const Claims& claims, const ValidationOptions& opts = ValidationOptions{});

/**
 * Validate a complete trust chain (Operator -> Account -> User)
 * @param jwts Vector of JWT strings in hierarchy order [operator, account, user]
 * @param opts Validation options
 * @return ValidationResult with details of any failures
 */
ValidationResult validateChain(const std::vector<std::string>& jwts, const ValidationOptions& opts = ValidationOptions{});

}
