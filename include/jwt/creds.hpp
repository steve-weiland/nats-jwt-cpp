#pragma once
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

namespace nkeys {
    class KeyPair;  // returned by the parse functions; include <nkeys/nkeys.hpp>
                    // (and link nkeys::nkeys) to use it
}

namespace jwt {

/// Extracts the JWT from a decorated .creds file; bare JWT content is
/// returned unmodified. Delegates to nkeys-cpp, whose behavior was measured
/// against Go (including the armor regex real NATS clients use).
/// Throws nkeys::CredsError when the content can't be parsed.
[[nodiscard]] std::string parseDecoratedJWT(std::string_view contents);

/// Finds the seed in a decorated .creds file (or a bare seed line) and
/// creates the key pair. Throws nkeys::CredsError when no seed is found.
[[nodiscard]] std::unique_ptr<nkeys::KeyPair> parseDecoratedNKey(std::string_view contents);

/// parseDecoratedNKey restricted to USER seeds — anything else throws.
[[nodiscard]] std::unique_ptr<nkeys::KeyPair> parseDecoratedUserNKey(std::string_view contents);

/// Armors a JWT by its claim type ("-----BEGIN NATS USER JWT-----" etc.),
/// byte-identical to Go's DecorateJWT. The token is DECODED first
/// (authenticated) — junk or tampered tokens throw.
[[nodiscard]] std::string decorateJWT(const std::string& jwt);

/// Armors an operator/account/user seed with Go's DecorateSeed template,
/// byte-identical. Throws InvalidClaimsError for non-signing seeds.
[[nodiscard]] std::string decorateSeed(std::string_view seed);

/// Go's IssueUserJWT: mints a SCOPED user (no permissions of its own — the
/// account's scope template governs it) issued by an account scoped signing
/// key, with issuer_account set. name defaults to the user's public key;
/// expirationSeconds > 0 sets exp = now + that (0 = never expires).
/// Divergence, documented: Go's optional tags parameter is not ported (tags
/// are an un-ported field).
[[nodiscard]] std::string issueUserJWT(const std::string& scopedSigningKeySeed,
                                       const std::string& accountId,
                                       const std::string& publicUserKey,
                                       const std::string& name = "",
                                       std::int64_t expirationSeconds = 0);

} // namespace jwt
