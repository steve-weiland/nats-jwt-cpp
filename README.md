# nats-jwt-cpp

[![CI](https://github.com/steve-weiland/nats-jwt-cpp/actions/workflows/ci.yml/badge.svg)](https://github.com/steve-weiland/nats-jwt-cpp/actions/workflows/ci.yml)

A C++20 port of the [NATS JWT](https://github.com/nats-io/jwt) Go library for
Ed25519-based authentication tokens. Wire-compatible with the Go
implementation — compatibility is continuously measured against it by a live
interop matrix in CI (`tests/interop/`), including creds files parsed by the
same armor regex real NATS clients use.

## Features

A complete C++20 port of Go's [nats-io/jwt v2](https://github.com/nats-io/jwt),
gated against the Go library and a real nats-server in CI.

- **Every claim type**: operator, account, user, activation, authorization
  request/response (auth callout), and generic claims for anything else
- **Authenticated decode**: the signature is verified against the embedded
  issuer and the issuer's key kind is enforced per claim type before any
  claim is returned (Go's `Decode`); tampered or mis-signed tokens throw
- **Full account configuration**: limits (incl. JetStream and tiered
  limits), default permissions, weighted subject mappings, exports/imports
  with activation tokens, revocation lists, plain and scoped signing keys,
  external authorization (auth callout) config, resolver wiring on operators
- **User permissions and limits**: pub/sub allow/deny, response permissions,
  subscription/data/payload limits, source CIDRs, time windows, bearer and
  connection-type flags — enforced against a real nats-server in CI
- **Auth callout**: decode server-minted authorization requests and mint
  responses; xkey-encrypted (sealed) callout traffic supported, with the
  server's curve key cross-checked between the header and the signed claim
- **External signers**: `encodeWithSigner` signs through a callback so
  private keys can stay in an HSM/KMS; the returned signature is verified
  before a token is emitted
- **Go-shaped validation**: `validate(ValidationResults&)` accumulates every
  finding with Go's texts (blocking errors, warnings, exp/nbf time checks);
  the throwing `validate()` and encode refuse blocking issues, while decode
  keeps Go-mintable-but-flawed tokens inspectable
- **Chain and timing validation**: issuer chains through identity and signing
  keys, scoped-signer rules, `exp`/`nbf`
- **Credentials**: generate and parse `.creds` files byte-identically to Go
  (`formatUserConfig`, `parseDecoratedJWT`, `decorateJWT`, `issueUserJWT`)
- **Legacy and tooling**: v1 tokens decode and re-encode as v2; activation
  `hashID()` for nsc-style storage
- **Hardened input handling**: every failure is a `jwt::Error`, integers are
  read strictly, base64url is canonical, tokens are capped at 1 MB before
  any work
- **CLI tool**: `jwt++` for encoding, decoding, verifying and creds
- **Modern C++20**: type-safe API with pimpl, RAII, exceptions and smart
  pointers; the public headers pull in no third-party headers (the creds
  parsers return a forward-declared `nkeys::KeyPair`, so consumers of those
  two functions include nkeys themselves)

Not ported: the account `trace` / `cluster_traffic` fields (carried through
re-encode untouched, not typed or validated).

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

// nsc-style report: every finding, Go's model — expiry is a time check, not
// an error, so a tool can inspect an expired token without failing
jwt::ValidationResults report;
decoded->validate(report);
for (const auto& issue : report.issues())
    std::cerr << (issue.blocking ? "error: " : "warning: ") << issue.description << "\n";
if (report.isBlocking(/*includeTimeChecks=*/true)) { /* refuse */ }

// Generate NATS credentials file
std::string creds = jwt::formatUserConfig(user_jwt, user_kp->seedString());

// Auth callout service: answer a nats-server authorization request
auto rq = jwt::decodeAuthorizationRequestClaims(request_jwt);   // signed by the SERVER key
jwt::AuthorizationResponseClaims rs(rq->userNkey());             // for exactly this user nkey
rs.setAudience(rq->server().id);                                 // to exactly this server
if (rq->connectOptions().password == "secret") {
    jwt::UserClaims admitted(rq->userNkey());                    // the grant: a user JWT
    admitted.permissions().pub.allow = {"orders.>"};
    rs.setJwt(admitted.encode(target_account_seed));
} else {
    rs.setError("bad credentials");
}
std::string response_jwt = rs.encode(callout_account_seed);      // account key (or signing key + setIssuerAccount)

// Encrypted auth callout (account authorization.xkey set): the body is a
// sealed box, the server's curve key is in the Nats-Server-Xkey header
if (jwt::isSealedCalloutBody(body)) {
    auto rq = jwt::decodeSealedAuthorizationRequest(body, header_xkey, service_curve_seed);
    // ... decide as above, then:
    auto sealed = jwt::sealAuthorizationResponse(response_jwt, header_xkey, service_curve_seed);
}

// Key custody elsewhere (HSM/KMS): sign through a callback — only the PUBLIC
// key is passed in; it becomes `iss` and the signature is checked against it
std::string hsm_signed = user_claims.encodeWithSigner(account_kp->publicString(),
    [](std::string_view issuer_pub, std::span<const std::uint8_t> signing_input) {
        // (placeholder: whatever your HSM/KMS client exposes) — 64 raw bytes
        return my_hsm.sign_ed25519(issuer_pub, signing_input);
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
    GIT_TAG v1.7.0)
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
