# nats-jwt-cpp

[![CI](https://github.com/steve-weiland/nats-jwt-cpp/actions/workflows/ci.yml/badge.svg)](https://github.com/steve-weiland/nats-jwt-cpp/actions/workflows/ci.yml)

A C++20 port of the [NATS JWT](https://github.com/nats-io/jwt) Go library for
Ed25519-based authentication tokens. Wire-compatible with the Go
implementation — compatibility is continuously measured against it by a live
interop matrix in CI (`tests/interop/`), including creds files parsed by the
same armor regex real NATS clients use.

## Features

- **Three-tier hierarchy**: Operator → Account → User claims
- **Authenticated decode**: signature verified against the embedded issuer
  before claims are returned (Go-parity; tampered tokens throw)
- **Ed25519 signatures**: Secure cryptography via nkeys-cpp
- **JWT validation**: Time-based, chain (signing-key aware), and hierarchy
  validation
- **NATS credentials**: Generate standard `.creds` files (byte-identical to
  Go's format)
- **Typed errors**: every failure derives from `jwt::Error`
- **CLI tool**: `jwt++` command-line utility
- **Modern C++20**: Type-safe API with RAII, exceptions, and smart pointers

## Scope

This is a deliberate PARTIAL port — what NATS authentication needs, not the
whole Go surface. Ported: the three claim types with name/expiry/signing-keys/
issuer_account, **user permissions (pub/sub allow/deny, response permissions)
and limits (subs/data/payload, src CIDRs, time windows)** — enforced against a
real nats-server in CI — encode/decode/verify, timing + chain validation,
creds generation AND parsing (`parseDecoratedJWT`/`parseDecoratedNKey`/
`parseDecoratedUserNKey`, plus `decorateJWT`/`decorateSeed`, byte-identical to
Go). Un-ported fields survive decode→re-encode untouched. NOT ported (by
choice): audience/tags, v1 token reading, auth-callout claims, activation
hashID. External signers ARE ported: `encodeWithSigner(issuerPublicKey,
SignFn)` on every claim type (Go's EncodeWithSigner) — the private key stays
in your HSM/KMS, and the returned signature is verified against the named
issuer before a token is emitted (a deliberate divergence: Go emits whatever
the callback returns). User connection flags ARE ported (`bearer_token`,
`proxy_required`, `allowed_connection_types`, on users and inside scope
templates): a WEBSOCKET-only user being refused over plain TCP is a real-
server CI gate; bearer and proxy_required are Go-wire-gated only (the nats
CLI always signs the nonce; proxy_required needs nats-server 2.11+). Scoped signing keys ARE ported (`UserScope` +
`issueUserJWT`) — a permissionless scoped user governed by the account's
template is enforced against a real nats-server in CI. Account configuration
is ported too: typed limits (JetStream + tiered), default permissions,
weighted subject mappings, description/info — a conn=1 account refusing a
second connection is likewise a CI gate, as is a revoked user's creds being
refused (revocation lists: `revoke`/`revokeAt`/`isRevoked` + `RevokeAll`).
Cross-account sharing is ported — typed exports/imports and `ActivationClaims`
— with a token-gated export served across accounts on a real nats-server as
the CI gate. Operator resolver wiring (account/service URLs, system
account, version assertion, strict signing-key usage) is ported — the server
honoring a C++-minted `system_account` over `$SYS` is likewise gated.

## Quick Start

### Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

Dependencies (nkeys-cpp, nlohmann/json, GoogleTest) are auto-fetched via CMake.

### Library Usage

```cpp
#include <jwt/jwt.hpp>
#include <nkeys/nkeys.hpp>

// Create operator JWT (self-signed)
auto operator_kp = nkeys::CreateOperator();
jwt::OperatorClaims op_claims(operator_kp->publicString());
op_claims.setName("My Operator");
std::string op_jwt = op_claims.encode(operator_kp->seedString());

// Create account JWT (signed by operator) — the issuer is DERIVED from the
// signing seed, exactly like Go; there is no issuer to set.
auto account_kp = nkeys::CreateAccount();
jwt::AccountClaims acc_claims(account_kp->publicString());
std::string acc_jwt = acc_claims.encode(operator_kp->seedString());

// Create user JWT (signed by account)
auto user_kp = nkeys::CreateUser();
jwt::UserClaims user_claims(user_kp->publicString());
user_claims.permissions().pub.allow = {"orders.>"};   // least-privilege, Go-style
user_claims.permissions().sub.allow = {"orders.>", "_INBOX.>"};
user_claims.limits().payload = 65536;
std::string user_jwt = user_claims.encode(account_kp->seedString());

// Decode and inspect — decode is AUTHENTICATED: the signature is verified
// against the embedded issuer, or this throws jwt::SignatureError. (Trust in
// that issuer comes from chain validation below.)
auto decoded = jwt::decodeUserClaims(user_jwt);
std::cout << decoded->name().value_or("") << "\n";

// Validate complete chain
std::vector<std::string> chain = {op_jwt, acc_jwt, user_jwt};
auto result = jwt::validateChain(chain, jwt::ValidationOptions::strict());

// Generate NATS credentials file
std::string creds = jwt::formatUserConfig(user_jwt, user_kp->seedString());

// Key custody elsewhere (HSM/KMS): sign through a callback — only the PUBLIC
// key is passed in; it becomes `iss` and the signature is checked against it
std::string hsm_signed = user_claims.encodeWithSigner(account_kp->publicString(),
    [](std::string_view issuer_pub, std::span<const std::uint8_t> signing_input) {
        return my_hsm.sign_ed25519(issuer_pub, signing_input);  // 64 bytes
    });
```

### CLI Tool

```bash
# Encode operator JWT
jwt++ --encode --type operator --inkey operator.seed --name "My Op"

# Encode account JWT (signed by operator; issuer derived from sign-key)
jwt++ --encode --type account --inkey account.seed --sign-key operator.seed

# Encode user JWT (signed by account)
jwt++ --encode --type user --inkey user.seed --sign-key account.seed

# Decode JWT
jwt++ --decode token.jwt

# Verify signature
jwt++ --verify token.jwt

# Generate credentials file
jwt++ --generate-creds --inkey user.seed user.jwt
```

## Using the Library

**CMake (`find_package`)** — install [nkeys-cpp](https://github.com/steve-weiland/nkeys-cpp)
first (exporting requires it), then this library, then:

```cmake
find_package(natsjwt 1.0 CONFIG REQUIRED)

target_link_libraries(my_app PRIVATE natsjwt::jwt)
# add nkeys::nkeys too if you call nkeys APIs directly (key generation)
```

**Embedding (`add_subdirectory` / `FetchContent`)** — no install needed;
nkeys-cpp is fetched automatically, and tests/CLI/install rules stay out of
your build:

```cmake
include(FetchContent)
FetchContent_Declare(natsjwt
    GIT_REPOSITORY https://github.com/steve-weiland/nats-jwt-cpp.git
    GIT_TAG v1.0.0)
FetchContent_MakeAvailable(natsjwt)

target_link_libraries(my_app PRIVATE natsjwt::jwt)
```

**pkg-config** — `c++ -std=c++20 app.cpp $(pkg-config --cflags --libs natsjwt)`.

All consumption paths (find_package static + shared, pkg-config,
add_subdirectory embed) are exercised by `tests/packaging/test.sh` in CI —
the installed library is `libnatsjwt`, not a collision-prone `libjwt`.

## End-to-End: a Real nats-server

The Go README ends by wiring its JWTs into a running server; here that is a
standing CI gate. `cpp_driver bootstrap` mints the full flow — operator with
a signing key; account self-signed, then re-signed by the operator signing
key; user issued by an account signing key with `issuer_account`; `u.creds`;
and a memory-resolver `resolver.conf` — and `tests/e2e-server/run.sh` boots a
real `nats-server` with it, runs an authenticated request/reply round trip,
and confirms a creds-less connection is refused. Fresh claims carry Go's
default no-limit fields (a server treats absent limits as zero), and decoded
claims carry their full `nats` object through re-encode, so re-signing never
drops or resets fields this port doesn't model.

## Requirements

- **Compiler**: C++20 (GCC 10+, Clang 12+, MSVC 19.29+)
- **CMake**: 3.21+
- **Dependencies**: Auto-fetched when not installed (nkeys-cpp pinned to a tag, nlohmann/json, GoogleTest); a system nkeys-cpp is preferred and required for `cmake --install`

## License

Licensed under the [Apache License 2.0](LICENSE) — the same license as the
Go [NATS JWT](https://github.com/nats-io/jwt) library this project is a port
of, and as [nkeys-cpp](https://github.com/steve-weiland/nkeys-cpp). See
[NOTICE](NOTICE).
