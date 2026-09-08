#include "jwt_utils.hpp"
#include "jwt/jwt_errors.hpp"
#include "jwt/jwt_constants.hpp"
#include "base64url.hpp"
#include <nkeys/nkeys.hpp>
#include <nlohmann/json.hpp>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <array>
#include <stdexcept>

namespace jwt::internal {

// ---------------- SHA-512/256 (vendored) ----------------
// Go's claim ID is SHA-512/256 of the serialized claims; no dependency here
// provides that variant (it is SHA-512's compression with different initial
// hash values, truncated to 256 bits — FIPS 180-4 §5.3.6.2). Validated
// against the NIST "abc" vector and an independent implementation in tests.
namespace sha512_256 {

    constexpr std::uint64_t K[80] = {
        0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
        0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
        0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
        0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
        0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
        0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
        0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
        0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
        0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
        0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
        0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
        0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
        0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
        0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
        0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
        0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
        0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
        0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
        0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
        0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
    };

    constexpr std::uint64_t rotr(std::uint64_t x, int n) noexcept {
        return (x >> n) | (x << (64 - n));
    }

    inline void compress(std::uint64_t h[8], const std::uint8_t block[128]) noexcept {
        std::uint64_t w[80];
        for (int i = 0; i < 16; ++i) {
            w[i] = 0;
            for (int b = 0; b < 8; ++b) w[i] = (w[i] << 8) | block[8 * i + b];
        }
        for (int i = 16; i < 80; ++i) {
            const auto s0 = rotr(w[i - 15], 1) ^ rotr(w[i - 15], 8) ^ (w[i - 15] >> 7);
            const auto s1 = rotr(w[i - 2], 19) ^ rotr(w[i - 2], 61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        std::uint64_t a = h[0], b = h[1], c = h[2], d = h[3];
        std::uint64_t e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 80; ++i) {
            const auto S1 = rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41);
            const auto ch = (e & f) ^ (~e & g);
            const auto t1 = hh + S1 + ch + K[i] + w[i];
            const auto S0 = rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39);
            const auto maj = (a & b) ^ (a & c) ^ (b & c);
            const auto t2 = S0 + maj;
            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    // 32-byte digest of msg — SHA-512/256 initial hash values, output truncated.
    inline std::array<std::uint8_t, 32> digest(std::string_view msg) {
        std::uint64_t h[8] = {
            0x22312194fc2bf72cULL, 0x9f555fa3c84c64c2ULL, 0x2393b86b6f53b151ULL,
            0x963877195940eabdULL, 0x96283ee2a88effe3ULL, 0xbe5e1e2553863992ULL,
            0x2b0199fc2c85b8aaULL, 0x0eb72ddc81c52ca2ULL,
        };
        const auto* data = reinterpret_cast<const std::uint8_t*>(msg.data());
        std::size_t len = msg.size(), off = 0;
        while (len - off >= 128) { compress(h, data + off); off += 128; }

        std::uint8_t block[256] = {};
        const std::size_t rem = len - off;
        std::copy_n(data + off, rem, block);
        block[rem] = 0x80;
        const std::size_t total = (rem + 1 + 16 <= 128) ? 128 : 256;
        const std::uint64_t bitlen = static_cast<std::uint64_t>(len) * 8;
        for (int i = 0; i < 8; ++i)
            block[total - 1 - i] = static_cast<std::uint8_t>(bitlen >> (8 * i));
        compress(h, block);
        if (total == 256) compress(h, block + 128);

        std::array<std::uint8_t, 32> out{};
        for (int i = 0; i < 4; ++i)
            for (int b = 0; b < 8; ++b)
                out[8 * i + b] = static_cast<std::uint8_t>(h[i] >> (56 - 8 * b));
        return out;
    }

} // namespace sha512_256

std::string computeJti(std::string_view payloadJsonWithoutJti) {
    const auto hash = sha512_256::digest(payloadJsonWithoutJti);

    // Base32 (RFC 4648 alphabet), no padding — Go's
    // base32.StdEncoding.WithPadding(NoPadding). 32 bytes → 52 chars.
    static constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string out;
    out.reserve(52);
    std::uint32_t buffer = 0;
    int bits = 0;
    for (auto byte : hash) {
        buffer = (buffer << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out.push_back(alphabet[(buffer >> bits) & 0x1F]);
        }
    }
    if (bits > 0) out.push_back(alphabet[(buffer << (5 - bits)) & 0x1F]);
    return out;
}

std::int64_t getCurrentTimestamp() {
    using namespace std::chrono;
    return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

std::string createHeader() {
    nlohmann::json header;
    header["typ"] = JWT_TYPE;
    header["alg"] = JWT_ALGORITHM;
    return header.dump();
}

JwtParts parseJwt(std::string_view jwt) {
    // Cap before doing ANY work (Go: MaxTokenSize, checked first in Decode)
    if (jwt.size() > MAX_JWT_SIZE) {
        throw MalformedTokenError(
            "Token size " + std::to_string(jwt.size()) +
            " exceeds maximum of " + std::to_string(MAX_JWT_SIZE) + " bytes");
    }

    // Find the two dots separating header.payload.signature
    size_t first_dot = jwt.find('.');
    if (first_dot == std::string_view::npos) {
        throw MalformedTokenError("Invalid JWT format: missing first '.'");
    }

    size_t second_dot = jwt.find('.', first_dot + 1);
    if (second_dot == std::string_view::npos) {
        throw MalformedTokenError("Invalid JWT format: missing second '.'");
    }

    // Check for extra parts (more than 2 dots)
    if (jwt.find('.', second_dot + 1) != std::string_view::npos) {
        throw MalformedTokenError("Invalid JWT format: too many parts");
    }

    // Extract the three parts
    std::string header_b64(jwt.substr(0, first_dot));
    std::string payload_b64(jwt.substr(first_dot + 1, second_dot - first_dot - 1));
    std::string signature_b64(jwt.substr(second_dot + 1));

    // Validate all parts are non-empty
    if (header_b64.empty()) {
        throw MalformedTokenError("Invalid JWT format: empty header");
    }
    if (payload_b64.empty()) {
        throw MalformedTokenError("Invalid JWT format: empty payload");
    }
    if (signature_b64.empty()) {
        throw MalformedTokenError("Invalid JWT format: empty signature");
    }

    // Create signing input (what was actually signed)
    std::string signing_input = header_b64 + "." + payload_b64;

    return JwtParts{
        std::move(header_b64),
        std::move(payload_b64),
        std::move(signature_b64),
        std::move(signing_input)
    };
}

bool verifySignature(const std::string& issuer_public_key,
                     const std::string& signing_input,
                     const std::string& signature_b64) {
    // Answers "does this verify?" — malformed input is just "no", never a
    // throw (the old version threw and its caller caught `...`, exceptions
    // as control flow). Callers who need an error translate false themselves.
    try {
        std::vector<std::uint8_t> signature_bytes = base64url_decode(signature_b64);
        auto public_key = nkeys::FromPublicKey(issuer_public_key);
        std::span<const std::uint8_t> signing_bytes(
            reinterpret_cast<const std::uint8_t*>(signing_input.data()),
            signing_input.size()
        );
        // nkeys verify() is noexcept and length-checks the signature itself
        return public_key->verify(signing_bytes, signature_bytes);
    } catch (...) {
        return false;
    }
}

}
