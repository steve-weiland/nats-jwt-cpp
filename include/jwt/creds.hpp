#pragma once
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

} // namespace jwt
