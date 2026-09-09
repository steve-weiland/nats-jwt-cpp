# Security Policy

## Overview

nats-jwt-cpp is a JWT authentication library that handles sensitive cryptographic operations and identity assertions. This document outlines security considerations, best practices, and the library's security design.

## Reporting Security Vulnerabilities

If you discover a security vulnerability, please report it privately:

1. **Do not** open a public GitHub issue
2. Email the maintainer with details about the vulnerability
3. Include steps to reproduce, potential impact, and suggested fixes if available
4. Allow reasonable time for a fix before public disclosure

## Security Design

### Cryptographic Foundation

**Ed25519 Signatures (via nkeys-cpp)**
- Implementation: nkeys-cpp wrapping [Monocypher](https://monocypher.org/) 4.x
- Algorithm: Ed25519 (Curve25519 + SHA-512)
- Key size: 256-bit (32 bytes)
- Signature size: 512-bit (64 bytes)
- Security level: 128-bit (equivalent to AES-128)

**JWT Algorithm**
- Header: `{"typ": "JWT", "alg": "ed25519-nkey"}`
- Signature: Ed25519 over `header.payload` (Base64 URL encoded)
- Encoding: Base64 URL without padding (RFC 4648 §5)

### JWT-Specific Security Features

**Claim Validation**
- Subject/Issuer verification
- Expiration timestamp checking (`exp` field)
- Issued-at timestamp validation (`iat` field)
- Trust hierarchy enforcement (Operator → Account → User)
- Required field validation

**Signature Verification**
- `decode()`/`decodeXClaims()` are AUTHENTICATED: the Ed25519 signature over
  `header.payload` is verified against the embedded issuer before any claims
  are returned (Go-parity). A tampered or mis-signed token throws
  `jwt::SignatureError`.
- Verification proves the token was signed by the key it NAMES — trust in
  that key comes from chain validation (`validateChain` /
  `validateIssuerChain`) against an operator you already trust, never from
  the token itself.
- Constant-time comparison (via nkeys-cpp)
- Key type validation (User JWT signed by Account key, etc.)

### External Signers (HSM / KMS custody)

`encodeWithSigner(issuerPublicKey, SignFn)` mirrors Go's `EncodeWithSigner`:
the library never sees the private key. What it guarantees, and what it
cannot:

- **The issuer is still derived.** `issuerPublicKey` becomes `iss` and is
  checked against the claim type's allowed issuer kinds BEFORE the signer is
  called; the signer cannot change who the token claims to be from.
- **The signature is verified before the token is emitted** (divergence from
  Go, which emits whatever the callback returns). A callback wired to the
  wrong key handle, or returning a malformed signature, throws
  `jwt::SignatureError` instead of minting a token every decoder rejects.
- **The signer sees exactly what is signed**: the `header.payload` bytes and
  the public key it is expected to sign for — enough for a policy layer to
  refuse signing tokens it does not like.
- **Not covered:** the security of the signer itself. A compromised HSM
  interface signs whatever it is asked to; the callback's own exceptions
  propagate unwrapped so its failure modes stay visible.

### Auth Callout

`decodeAuthorizationRequestClaims` is authenticated like every other decode:
the request must verify against the SERVER key it names. That proves the
request came from *a* server holding that key — a callout service must still
check that it is addressed to it (`audience() == AuthRequestAudience`,
`subject()` == its own account) and, when it authorizes on the client's
sentinel credential, decode `connectOptions().jwt` (authenticated) rather
than trusting `clientInformation()` strings. On the response side the library
enforces the server's structural rules at encode (sub = a user key, aud = a
server key, exactly one of jwt/error, issuer_account an account key, account
issuer); binding the response to the *right* request — `sub` = the request's
`userNkey()`, `aud` = the request's `server().id` — is the service's job, and
nats-server refuses anything else. xkey-encrypted callout traffic is not
implemented.

### Memory Security

**Sensitive Data Handling**

JWT tokens themselves are public (signed, not encrypted), but the library must protect:

1. **Seeds/Private Keys**: Handled by nkeys-cpp with automatic wiping
2. **Temporary Buffers**: Wiped after encoding/decoding operations
3. **RAII Guards**: Exception-safe cleanup of sensitive data

**Delegation to nkeys-cpp**

This library does not implement cryptographic primitives. All sensitive operations (key generation, signing, verification) are delegated to nkeys-cpp, which provides:
- Automatic memory wiping
- Exception-safe key handling
- Secure random number generation

### Input Validation

All public APIs perform strict validation:

- **JWT Format**: Must be `header.payload.signature` format
- **Base64 Encoding**: Valid Base64 URL characters only
- **JSON Payloads**: Valid JSON structure required
- **Claim Fields**: Required fields must be present
- **Key Types**: Issuer key type must match claim type
- **Signature Length**: Must be exactly 64 bytes
- **Maximum Size**: JWT limited to 10MB (configurable via `MAX_JWT_SIZE`)

Invalid input results in exceptions, never undefined behavior.

## Best Practices for Users

### Token Management

**DO:**
- ✅ Set appropriate expiration times on JWTs
- ✅ Verify signatures before trusting claims
- ✅ Check expiration timestamps before accepting tokens
- ✅ Validate issuer/subject relationships (trust hierarchy)
- ✅ Store seeds securely (use nkeys-cpp best practices)
- ✅ Transmit JWTs over secure channels (TLS/HTTPS)
- ✅ Revoke compromised tokens (via NATS infrastructure)

**DON'T:**
- ❌ Accept expired tokens
- ❌ Skip signature verification
- ❌ Trust claims without validating issuer
- ❌ Store sensitive data in JWT payload (JWTs are signed, not encrypted)
- ❌ Use infinite expiration (`exp = 0`) in production
- ❌ Reuse operator/account signing keys carelessly

### JWT Verification Workflow

**Critical Verification Steps:**

```cpp
// 1. Decode JWT (this verifies signature automatically)
try {
    auto claims = jwt::decodeUserClaims(token);

    // 2. Check expiration
    if (claims->expires() != 0 && claims->expires() < currentTime()) {
        throw std::runtime_error("Token expired");
    }

    // 3. Validate issuer (must be trusted account key)
    if (!isTrustedAccount(claims->issuer())) {
        throw std::runtime_error("Untrusted issuer");
    }

    // 4. Use claims safely
    std::cout << "Authenticated user: " << claims->subject() << "\n";

} catch (const std::exception& e) {
    // Handle verification failure
    std::cerr << "JWT verification failed: " << e.what() << "\n";
}
```

**Never:**
- Skip signature verification
- Accept tokens without checking expiration
- Trust issuer without validation
- Use JWT payload as encrypted data

### Trust Hierarchy

**Operator → Account → User**

Each level can only sign JWTs for the level below:

```
Operator (self-signed)
  └─> Account JWT (signed by operator key or operator signing key)
       └─> User JWT (signed by account key or account signing key)
```

**Validation Rules:**
- Operator JWT: `subject == issuer` (self-signed)
- Account JWT: `issuer` must be operator key
- User JWT: `issuer` must be account key
- Signing keys: Must be in parent's `signing_keys` list

### Exception Safety

All encoding/decoding functions use exception-safe patterns:

```cpp
try {
    std::string jwt = claims.encode(seed);
    // Even if exception thrown, nkeys-cpp has wiped seed
} catch (const std::exception& e) {
    // Handle error safely
}
```

## Security Features

### Compile-Time Protections

When built with `JWT_ENABLE_HARDENING=ON` (default), the following protections are enabled:

**Stack Protection**
- `-fstack-protector-strong`: Guards stack against buffer overflows

**Fortified Sources**
- `-D_FORTIFY_SOURCE=2`: Buffer overflow checks (Release builds)

**Position Independent Execution (Linux)**
- `-Wl,-z,relro,-z,now`: Read-only relocations, prevents GOT overwrites

### Runtime Sanitizers

Development builds can enable:

**AddressSanitizer** (`-DJWT_ENABLE_ASAN=ON`)
- Detects memory errors (use-after-free, buffer overflows)
- ~2x slowdown, use in testing

**UndefinedBehaviorSanitizer** (`-DJWT_ENABLE_UBSAN=ON`)
- Detects undefined behavior at runtime
- Minimal performance impact

## Known Limitations

### Platform Support

- **Cryptography**: Depends on nkeys-cpp platform support
  - macOS/Linux: Fully supported
  - Windows: Limited by nkeys-cpp RNG support

### JWT Security Properties

**JWTs are Signed, Not Encrypted**
- Payload is visible to anyone (Base64 encoded)
- Signature proves authenticity, not confidentiality
- **Never** put secrets in JWT payload

**Expiration is Advisory**
- Token expiration enforced by verifier, not cryptographically
- Compromised token valid until expiration
- No built-in revocation (use NATS revocation mechanisms)

### Denial of Service

The library does not protect against:
- Excessive JWT size (enforced by `MAX_JWT_SIZE` constant)
- CPU exhaustion from signature verification
- Memory exhaustion from large claim sets

## Threat Model

### In Scope

The library protects against:
- ✅ JWT forgery (Ed25519 signature security)
- ✅ Token tampering (signature verification)
- ✅ Key confusion (prefix validation via nkeys-cpp)
- ✅ Timing attacks (constant-time signature verification)
- ✅ Trust hierarchy violations (issuer validation)
- ✅ Expired token acceptance (expiration checking)

### Out of Scope

The library does NOT protect against:
- ❌ Compromised private keys (key management is user responsibility)
- ❌ Token theft (use TLS/HTTPS for transmission)
- ❌ Replay attacks (application-level concern, use nonces if needed)
- ❌ Token revocation (use NATS revocation lists)
- ❌ Payload confidentiality (JWTs are signed, not encrypted)
- ❌ Physical access to running process
- ❌ Root/admin level attackers

## Cryptographic Assurance

### Algorithm Security

**Ed25519** is considered secure against all known attacks:
- No known practical attacks against Curve25519
- Conservative security margin
- Immune to many side-channel attacks
- Widely peer-reviewed and deployed

**Not Quantum-Resistant**: Ed25519 is vulnerable to quantum computers with Shor's algorithm.

### Implementation Security

- Uses [nkeys-cpp](https://github.com/steve-weiland/nkeys-cpp) for all cryptographic operations
- nkeys-cpp uses [Monocypher](https://monocypher.org/), an audited library
- No custom cryptographic code ("don't roll your own crypto")

## Compliance

This library is suitable for:
- General-purpose authentication
- Internal service-to-service authentication
- NATS-based microservices
- Developer tooling and automation

This library is NOT certified for:
- FIPS 140-2/140-3 compliance
- Medical device software
- Payments (PCI-DSS)
- Government classified systems

Always consult security/compliance experts for regulated environments.

## Security Checklist for Integrators

Before deploying nats-jwt-cpp in production:

- [ ] Seeds stored securely (use nkeys-cpp best practices)
- [ ] Build includes hardening flags (`JWT_ENABLE_HARDENING=ON`)
- [ ] Signature verification never skipped
- [ ] Expiration timestamps checked on all tokens
- [ ] Issuer validation enforces trust hierarchy
- [ ] JWTs transmitted only over secure channels (TLS/HTTPS)
- [ ] No sensitive data in JWT payload
- [ ] Token expiration times set appropriately (not infinite)
- [ ] Tested with sanitizers during development
- [ ] Exception handling reviewed for security
- [ ] Security incident response plan in place
- [ ] Regular dependency updates (nkeys-cpp, nlohmann/json)

## JWT-Specific Threats

### Token Theft

**Threat**: Attacker intercepts JWT during transmission

**Mitigation**:
- Use TLS/HTTPS for all JWT transmission
- Use short expiration times
- Implement token revocation at application level

### Token Replay

**Threat**: Attacker reuses captured JWT

**Mitigation**:
- Use short expiration times
- Implement nonce/jti validation if needed
- Monitor for suspicious patterns

### Expired Token Acceptance

**Threat**: Application accepts expired tokens

**Mitigation**:
- Always check `expires()` field before accepting token
- Reject tokens with `exp` < current time
- Use reasonable clock skew tolerance (e.g., 5 minutes)

### Trust Hierarchy Violation

**Threat**: User token signed by untrusted account

**Mitigation**:
- Validate `issuer` field matches trusted account
- Check account JWT was signed by trusted operator
- Maintain whitelist of trusted operator keys

## Updates and Maintenance

- Monitor this repository for security updates
- Subscribe to GitHub releases for notifications
- Review nkeys-cpp releases for cryptographic updates
- Review nlohmann/json releases for parsing vulnerabilities
- Keep compiler and standard library updated

## References

- [NATS JWT Specification](https://github.com/nats-io/jwt)
- [nkeys-cpp Security](https://github.com/steve-weiland/nkeys-cpp/blob/main/SECURITY.md)
- [Ed25519 Signature Scheme](https://ed25519.cr.yp.to/)
- [JWT RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)
- [Base64 URL Encoding (RFC 4648)](https://datatracker.ietf.org/doc/html/rfc4648#section-5)
- [OWASP JWT Security](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
