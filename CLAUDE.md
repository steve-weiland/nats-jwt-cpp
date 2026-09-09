# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with
code in this repository.

## Project Overview

nats-jwt-cpp is a C++20 port of the Go [NATS JWT](https://github.com/nats-io/jwt)
library (v2): operator/account/user claims, Ed25519-signed JWTs via
[nkeys-cpp](https://github.com/steve-weiland/nkeys-cpp), timing/chain
validation, and `.creds` generation. It is a deliberate PARTIAL port — see the
README's Scope section for what is and isn't included. Wire compatibility with
the Go implementation is the defining requirement and is continuously measured
(see Gates).

## Conventions (violations are review-rejectable)

- **Compatibility is measured, never assumed.** Behavioral questions are
  settled by running the reference Go library (`tests/interop/probe/`), not by
  recalling it. Precedents: the 64-char creds wrapping "for readability" made
  every creds file unparseable by real clients; the "stricter" exp≤iat
  structural check rejected tokens Go itself mints.
- **Decode is authenticated.** `decode()`/`decodeXClaims()` verify the
  signature against the embedded issuer before returning claims — an
  unauthenticated decode hands out attacker-edited claims (measured: a
  tampered payload decoded fine pre-fix while Go refused). Never add a decode
  path that skips verification.
- **The issuer is derived, never trusted from a setter.** `encode(seed)` sets
  `iss` from the seed's public key (Go's doEncode) and enforces Go's
  ExpectedPrefixes (operator←operator, account←operator|account, user←account).
  A token whose `iss` disagrees with its signature must be unmintable.
- **Trust flows through the chain.** Signature verification proves the token
  was signed by the key it NAMES; `validateChain`/`validateIssuerChain`
  (subject ∪ signing keys, `issuer_account` must name the parent) establish
  whether that key is trusted. Self-signed accounts decode (Go's documented
  flow) but do not chain.
- **Throw only `jwt::Error`-derived types** (`jwt_errors.hpp`):
  MalformedTokenError / InvalidClaimsError / SignatureError, each also
  deriving its historical std base. nkeys::Error propagates for key material.
  Translate nlohmann exceptions at parse sites — they must not leak.
- **Claims must be server-usable and re-sign-safe.** Fresh account/user
  claims emit Go's default no-limit fields — nats-server treats ABSENT limits
  as ZERO (measured: "maximum account active connections exceeded" from a
  real server). Decoded claims carry their full `nats` object through
  re-encode so un-ported fields (real limits, mappings, imports…) survive the
  re-sign flow — resetting them to defaults would be silent privilege
  escalation.
- **Docs state measured truth only** (history: "License TBD", a README example
  demonstrating a redundant setIssuer dance, tests that asserted the
  creds-breaking bug).

## Build & Test

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Options: `JWT_WARNINGS_AS_ERRORS`, `JWT_USE_SYSTEM_GTEST` (default ON; forced
off under sanitizers — an uninstrumented GTest under ASAN reports a bogus
container-overflow), `JWT_ENABLE_ASAN`, `JWT_ENABLE_UBSAN`,
`JWT_ENABLE_HARDENING` (default ON), `JWT_USE_SYSTEM_NKEYS` (default ON;
falls back to FetchContent pinned to a tagged nkeys-cpp release),
`JWT_BUILD_TESTS` (defaults to `PROJECT_IS_TOP_LEVEL`).

**Gates before claiming done** (CI runs all of these on every push —
`.github/workflows/ci.yml` — but run them locally first):

- full ctest on macOS AND the Linux container:

```bash
docker run --rm -v "$PWD":/src:ro alpine:3.20 sh -c \
  'apk add -q build-base cmake linux-headers git && cp -r /src /w && cd /w && \
   rm -rf build* cmake-build-* && cmake -S . -B b >/dev/null && \
   cmake --build b -j >/dev/null && ctest --test-dir b'
```

- the real-server gate for anything touching claim content or creds:
  `tests/e2e-server/run.sh <build-dir>` (docker) — a fully C++-minted chain
  (bootstrap mode: the Go README flow verbatim + resolver.conf) must
  authenticate against nats:2.10-alpine, with a no-creds negative control.

- the live Go interop matrix for anything wire-relevant:
  `tests/interop/run.sh <build-dir>` — C++-minted tokens through Go's
  authenticated Decode, creds through the real armor regex, Go's canonical
  artifacts (self-signed account included) through C++ decode, the Go README
  chain through strict validation, tamper rejection both sides. The probe pins
  the PUBLISHED nats-io/jwt; `go mod edit -replace` to probe a local checkout.

## Working discipline

- Red-first: a fix lands with the test that failed against the old code.
  Sabotage-verify new tests: break the code, watch the RIGHT assertion fail,
  restore (grep both ways). Golden vectors produced by an INDEPENDENT
  implementation where possible (the jti hash golden is Python hashlib; the
  creds golden is the live Go library's output).
- Minimal change per commit; every commit reviewed by a human first.

## Architecture

- `include/jwt/` — public API: `Claims` base + Operator/Account/User claims
  (pimpl), `validation.hpp` (ValidationResult/Options, timing + chain),
  `jwt_errors.hpp` (typed errors), constants (MAX_JWT_SIZE = Go's 1MB, checked
  BEFORE any work).
- `src/jwt_utils.*` — parseJwt (size cap first), verifySignature (answers
  bool, never throws — malformed input is "no"), computeJti (vendored
  SHA-512/256, FIPS 180-4 §5.3.6.2, of the payload serialized jti-less,
  base32 no padding — Go's algorithm over OUR serialization, so values differ
  from Go's for the same logical claims by design).
- `include/jwt/permissions.hpp` — typed user Permissions/Limits (Go's User
  schema, ported completely): resp.ttl is NANOSECONDS on the wire; queue
  subjects ("subj queue") legal only in sub; a 0 limit is OMITTED (server
  treats absent as zero); src decodes from array OR comma string (Go
  leniency). Divergence, documented: Go validates locale against the IANA
  tzdb, we accept any string. Typed fields OWN their keys on encode (erased
  when empty); everything untyped still rides natsRaw_.
- `src/base64url.*` — RFC 4648 URL alphabet, no padding.
- Claim JSON is nlohmann (alphabetical key order — irrelevant to Go, which
  ignores order); header is `{"typ":"JWT","alg":"ed25519-nkey"}`.
- `src/tools/jwt-main.cpp` — `jwt++` CLI. `--sign-key` determines the issuer;
  there is no `--issuer` flag (it was dead weight once encode derived it).
- `tests/fixtures/` — REAL Go-minted artifacts (operator/account/user JWTs,
  the self-signed account, an already-expired operator, a byte-golden creds
  file + its seed), regenerable via the probe.

## Known gaps

Scope cuts are documented in the README (bearer/conn-type user flags,
aud/tags, v1 reading, auth-callout, external signers, activation hashID). User permissions/limits ARE ported — real-server-enforced in CI
(e2e check 3) — creds parse/decorate is ported (creds.hpp: parse trio
delegates to nkeys-cpp; decorate is authenticated and byte-golden vs Go) —
and scoped signing keys are ported (UserScope in a SORTED mixed signing_keys
array; issueUserJWT mints permissionless scoped users; the chain and the
real server both reject scoped users carrying their own permissions —
e2e check 4). Account configuration is typed too (limits incl. flat-in-limits
JetStream fields + tiered_limits, default_permissions, mappings with Go's
weight-0-means-100 rule, description/info_url) — account conn limits are
real-server-enforced (e2e check 5). Divergence, documented: Go's account
Validate is advisory ("don't block encoding" per its own tests); we enforce
mapping/tier rules at encode, consistent with the user-claims port.
Revocation lists are ported (revoke/revokeAt/clearRevocation/isRevoked +
RevokeAll; issue-time semantics — never pass "now" to isRevoked) —
real-server-enforced. Cross-account sharing is ported: typed Export/Import on
accounts and ActivationClaims as a fourth claim type (decode dispatch +
decorateJWT "ACTIVATION"); import tokens are cross-checked against the
import's account at encode; latency sampling 0 serializes as "headers";
response_threshold is NANOSECONDS. The e2e serves a token_req export across
accounts through a C++-minted activation. Operator resolver wiring is ported
(account_server_url, operator_service_urls with the nats/tls/ws/wss
no-creds/no-path rules, system_account, assert_server_version,
strict_signing_key_usage; signing keys validated as real operator keys) —
the e2e proves the server honors a C++-minted system_account via $SYS.
The library is consumable four ways (find_package(natsjwt) static/shared,
pkg-config, add_subdirectory embed — all gated by `tests/packaging/test.sh`,
which installs a real nkeys-cpp and thereby also exercises the system-nkeys
build path). Installing requires a system nkeys-cpp (a FetchContent-built one
cannot be exported); building does not. nkeys-cpp's symbol-collision handling
does NOT apply here (nothing vendored except the internal SHA-512/256 core),
but the installed library is deliberately `libnatsjwt`, and the package
`natsjwt` — plain `jwt` names collide with thalhammer/jwt-cpp.

## Release ritual

The tag's tree must report the version it claims — tag v1.1.0 once shipped a
tree saying 1.0.0 because the tag came first. The order is: version-set
commit → tag → bump commit, always:

```bash
# 1. set the release version (single source of truth: package config,
#    natsjwt.pc, jwt++ --version all derive from it)
#    edit CMakeLists.txt: project(nats-jwt-cpp VERSION X.Y.0 LANGUAGES CXX)
git commit -am "Set version to X.Y.0"

# 2. tag THAT commit
git tag -a vX.Y.0 -m "vX.Y.0 — <summary>"

# 3. bump for the next cycle
#    edit CMakeLists.txt: project(nats-jwt-cpp VERSION X.(Y+1).0 LANGUAGES CXX)
git commit -am "Bump version to X.(Y+1).0 for the next change"

git push origin main vX.Y.0
# verify before announcing:
git show vX.Y.0:CMakeLists.txt | grep "^project("
```

## When review catches you violating a convention

Fix the code, then encode the violated rule into this file so the class of
error dies, not the instance.
