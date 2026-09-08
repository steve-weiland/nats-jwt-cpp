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
issuer_account, encode/decode/verify, timing + chain validation, creds
generation. NOT ported (by choice): user permissions (pub/sub allow/deny) and
limits, account limits/imports/exports, activation claims, scoped signing
keys, audience/tags, v1 token reading, creds parsing (nkeys-cpp provides
`ParseDecoratedJWT`/`ParseDecoratedUserNKey`).

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

## Requirements

- **Compiler**: C++20 (GCC 10+, Clang 12+, MSVC 19.29+)
- **CMake**: 3.21+
- **Dependencies**: Auto-fetched (nkeys-cpp, nlohmann/json, GoogleTest)

## License

Licensed under the [Apache License 2.0](LICENSE) — the same license as the
Go [NATS JWT](https://github.com/nats-io/jwt) library this project is a port
of, and as [nkeys-cpp](https://github.com/steve-weiland/nkeys-cpp). See
[NOTICE](NOTICE).
