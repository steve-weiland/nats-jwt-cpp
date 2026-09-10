# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with
code in this repository.

## Project Overview

nats-jwt-cpp is a C++20 port of the Go [NATS JWT](https://github.com/nats-io/jwt)
library (v2): operator/account/user claims, Ed25519-signed JWTs via
[nkeys-cpp](https://github.com/steve-weiland/nkeys-cpp), timing/chain
validation, and `.creds` generation. It is a complete port of the Go surface
(the only omission: the account trace/cluster_traffic fields, carried through
re-encode untouched but not typed). Wire compatibility with
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
  A token whose `iss` disagrees with its signature must be unmintable — which
  is why `encodeWithSigner` (Go: EncodeWithSigner; the seed path is a wrapper
  over it, `internal::signAndAssemble`) verifies the callback's signature
  against the advertised key and throws SignatureError otherwise. Go trusts
  the callback; we don't — a mis-keyed HSM is one config error away.
- **Trust flows through the chain.** Signature verification proves the token
  was signed by the key it NAMES; `validateChain`/`validateIssuerChain`
  (subject ∪ signing keys, `issuer_account` must name the parent) establish
  whether that key is trusted. Self-signed accounts decode (Go's documented
  flow) but do not chain.
- **Throw only `jwt::Error`-derived types** (`jwt_errors.hpp`):
  MalformedTokenError / InvalidClaimsError / SignatureError, each also
  deriving its historical std base. nkeys::Error propagates for key material.
  nlohmann exceptions must not leak: every typed decoder body runs inside
  `internal::guardJson` (json exception → MalformedTokenError), and fields
  are read with the strict readers in `jwt_utils.hpp` (`intField`,
  `uintField`, `arrayField`, `objectField`) — Go's encoding/json refuses a
  wrong-typed or out-of-range value, nlohmann silently converts a float and
  wraps an integer (measured: `nats.version` 2^32+2 read as 2). Header
  shape errors are caught BEFORE the signature check (unauthenticated bytes).
  The review that found the leaks: a header `[]` terminated a caller that
  honored the documented `catch (const jwt::Error&)` contract.
- **Go's ExpectedPrefixes hold at decode, for every type.**
  `internal::checkIssuerKind` runs in each `checkStructure` (decode) AND
  `encodeWithSigner`: operator←O, account←O|A, user←A, activation←A|O,
  authorization_request←N, authorization_response←A; subjects are checked
  as FULL keys (`checkSubjectKind`), not by first byte. Measured before the
  fix: an operator signed by an account key and a callout request signed
  by a USER key decoded, and the operator even passed strict chain
  validation as a root.
- **Claims must be server-usable and re-sign-safe.** Fresh account/user
  claims emit Go's default no-limit fields — nats-server treats ABSENT limits
  as ZERO (measured: "maximum account active connections exceeded" from a
  real server). Decoded claims carry their full `nats` object through
  re-encode so un-ported fields (real limits, mappings, imports…) survive the
  re-sign flow — resetting them to defaults would be silent privilege
  escalation.
- **Validation has one source of truth.** Each claim type's
  `validate(ValidationResults&)` holds Go's rules (blocking errors, the two
  warnings, exp/nbf time checks) and accumulates every finding; the
  throwing `validate()` runs the structural check and then throws the first
  BLOCKING issue. Encode calls the throwing form (we enforce what Go only
  advises — documented divergence), decode calls ONLY `checkStructure()`:
  Go's Encode does not validate, so Go mints tokens its own Validate flags,
  and those must stay decodable (the #6 lesson; interop check 11 compares
  our report to Go's line for line). Never add a throw inside a rule
  validator; add an issue.
- **Go's Subject rules live in one place** — `src/subject_utils.hpp`
  (Subject.Validate, HasWildCards, IsContainedIn, RenamingSubject,
  Info.Validate, checkPermission). Every account/user rule that touches a
  subject goes through it; interop check 11 compares our report to Go's
  line for line on Go-minted flawed tokens (exports, imports, limits, user
  permissions), so a text or rule drift shows up there. Go can MINT what
  its own Validate flags (Encode does not validate), and Go REFUSES to
  marshal some invalid values (a SamplingRate outside 1..100 is
  "unknown sampling rate") — a golden can only carry flaws Go can write.
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
`JWT_BUILD_TESTS`, `JWT_BUILD_CLI`, `JWT_INSTALL` (all default to
`PROJECT_IS_TOP_LEVEL`), `JWT_BUILD_DRIVER` (the interop/e2e cpp_driver,
default = JWT_BUILD_TESTS; the e2e toolbox image builds it alone).

**Gates before claiming done** (CI runs all of these on every push to main and every PR —
`.github/workflows/ci.yml` — but run them locally first):

- full ctest on macOS AND the Linux container:

```bash
docker run --rm -v "$PWD":/src:ro alpine:3.20 sh -c \
  'apk add -q build-base cmake linux-headers git && cp -r /src /w && cd /w && \
   rm -rf build* cmake-build-* && cmake -S . -B b >/dev/null && \
   cmake --build b -j >/dev/null && ctest --test-dir b'
```

- the real-server gate for anything touching claim content or creds:
  `tests/e2e-server/run.sh <build-dir>` (docker; builds the toolbox image
  from `tests/e2e-server/Dockerfile` first, ~2 min cold) — a fully C++-minted chain
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

- `include/jwt/` — public API: `Claims` base + seven claim types (pimpl):
  `operator_claims.hpp`, `account_claims.hpp` (+ limits/exports/imports/
  revocations/authorization types), `user_claims.hpp` + `permissions.hpp`,
  `activation_claims.hpp`, `authorization_claims.hpp`, `generic_claims.hpp`;
  `validation.hpp` (ValidationResult/Options, timing + chain),
  `validation_results.hpp` (Go's accumulated report), `creds.hpp` (creds
  parse/decorate, issueUserJWT), `jwt_errors.hpp` (typed errors), constants
  (MAX_JWT_SIZE = Go's 1MB, checked BEFORE any work). No public header
  includes nkeys or nlohmann.
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
  when empty); everything untyped still rides natsRaw_. The connection flags
  (bearer_token / proxy_required / allowed_connection_types) are part of Go's
  UserPermissionLimits: they live on users AND in scope templates, SetScoped
  zeroes them, and hasEmptyPermissions counts them (Go: DeepEqual) — the
  server refuses a WEBSOCKET-only user over TCP (e2e check 9 — logged as
  "authentication error"; "Connection type not allowed" only at -D).
  Connection-type strings are unvalidated, as in Go.
- `src/jwt_utils.*` — a second vendored hash, SHA-256 (FIPS 180-4 §6.2),
  used ONLY for `ActivationClaims::hashID()` (Go: HashID — note it uses
  STANDARD base32 WITH padding, 56 chars, unlike the jti's no-pad base32;
  `cleanSubject` cuts at the first wildcard token, leading wildcard → "_").
  NIST-vector tested; Go-golden gated (interop check 13).
- `src/jwt_utils.*` — `decodeEnvelope` (header/version/signature/v1
  migration, shared by every typed decoder), `signAndAssemble` (the encode
  tail), `addTimeChecks`/`throwFirstBlocking` (the validation report).
- `src/base64url.*` — RFC 4648 URL alphabet, no padding.
- Claim JSON is nlohmann (alphabetical key order — irrelevant to Go, which
  ignores order); the emitted header is `{"alg":"ed25519-nkey","typ":"JWT"}`
  (alphabetical, unlike Go's typ-first — wire-irrelevant).
- `src/tools/jwt-main.cpp` — `jwt++` CLI. `--sign-key` determines the issuer;
  there is no `--issuer` flag (it was dead weight once encode derived it).
- `tests/fixtures/` — REAL Go-minted artifacts (operator/account/user JWTs,
  the self-signed account, an already-expired operator, a byte-golden creds
  file + its seed), regenerable via the probe.

## Known gaps

The port is complete but for the account trace/cluster_traffic fields. Encrypted callout (§7a): the request body is a sealed box
("xkv1") when the account has an xkey; the server's curve key is in the
`Nats-Server-Xkey` header AND the signed `server_id.xkey` —
`decodeSealedAuthorizationRequest` requires them to agree. The e2e's callout
service is `cpp_driver callout-serve`, a real NATS client
(`tests/interop/nats_min_client.hpp`: INFO/CONNECT with nonce signature,
SUB, MSG/HMSG with headers, PUB) because `nats reply --command` cannot carry
a binary body or the header; a production daemon should use nats.c. v1 reading + GenericClaims are ported
(group 6b): `internal::decodeEnvelope` is the ONE decode preamble (Go's
Header.Valid leniency — typ case-insensitive, alg lower-cased "ed25519" or
"ed25519-nkey"; version from the PAYLOAD: a top-level type means v1; v1
signs the payload chunk only; > 2 is "newer version"; 0 is an error like
Go's loaders) and migrates v1 into the v2 layout (activation import "type"
→ "kind", user `max` dropped and subs/data/payload preset to -1). Go's
DecodeGeneric picks the signature rule from the HEADER alg instead — mirrored
in decodeGeneric. Measured Go bug, not mirrored: Go's Decode fails on Go's own
v2 generics (unknown-type branch → version -1 → v1 rule); our decode()
dispatches unknown types to decodeGeneric. GenericClaims data is JSON TEXT
on the public API — no public header may include nlohmann (packaging gate). `aud`/`nbf`/`tags` are
on the Claims base (group 6a). Correction recorded there: the old
`validateNotBefore` used iat as the not-before bound — Go has a real `nbf`
and NEVER checks iat; nats-server treats Go's time checks as blocking for
user auth (auth.go `IsBlocking(true)`), so a future nbf is refused (e2e
check 11). Tags are normalized ONLY via `addTags` (Go: TagList.Add); decode
keeps them as-is (Go: plain unmarshal). Auth callout is
ported — `ExternalAuthorization` on accounts (ALWAYS on the wire, `{}` when
unset — Go never omits the struct), `AuthorizationRequestClaims` (issued by
SERVER keys only; `aud` is the constant "nats-authorization-request") and
`AuthorizationResponseClaims` (account key or signing key + issuer_account;
`aud` REQUIRED = server ID, `sub` = the request's user_nkey). Measured on
nats-server 2.10.29, operator mode: the callout fires only for clients that
present a user JWT of the external-auth account (a "sentinel" credential —
plain user/password alone gets "Authentication requires a user JWT"), the
server needs a system account (it panics in newRespInbox without one), and
the nats CLI DROPS `--creds` when `--user/--password` are also given, so the
e2e authorizes on the sentinel's identity. The e2e's callout service is
`nats reply --command` in a toolbox image (`tests/e2e-server/Dockerfile`:
Linux cpp_driver + nats CLI) — the host driver cannot run inside nats-box.
External signers are ported
(`encodeWithSigner`; the interop gate pushes signer-minted tokens through Go
Decode). User permissions/limits ARE ported — real-server-enforced in CI
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
