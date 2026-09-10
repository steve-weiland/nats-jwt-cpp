#include <gtest/gtest.h>
#include "jwt/jwt.hpp"
#include <nkeys/nkeys.hpp>
#include <nlohmann/json.hpp>
#include "../src/base64url.hpp"
#include "../src/jwt_utils.hpp"
#include <functional>
#include <algorithm>
#include <type_traits>
#include <fstream>
#include <sstream>
#include <cstdio>

TEST(JwtTest, PlaceholderTest) {
    // Placeholder test to ensure test framework works
    EXPECT_TRUE(true);
}

// Integration test for complete JWT encoding
TEST(JwtEncodingTest, OperatorAccountUserChain) {
    // Create Operator and encode JWT
    auto operator_kp = nkeys::CreateOperator();
    auto op_claims = jwt::OperatorClaims(operator_kp->publicString());
    op_claims.setName("Test Operator");

    std::string operator_jwt = op_claims.encode(operator_kp->seedString());

    // Verify JWT structure (3 parts)
    size_t first_dot = operator_jwt.find('.');
    size_t second_dot = operator_jwt.find('.', first_dot + 1);
    ASSERT_NE(first_dot, std::string::npos);
    ASSERT_NE(second_dot, std::string::npos);
    ASSERT_EQ(operator_jwt.find('.', second_dot + 1), std::string::npos);

    // Decode and verify operator JWT payload
    std::string payload_b64 = operator_jwt.substr(first_dot + 1, second_dot - first_dot - 1);
    auto payload_bytes = jwt::internal::base64url_decode(payload_b64);
    std::string payload_json(payload_bytes.begin(), payload_bytes.end());
    auto payload = nlohmann::json::parse(payload_json);

    EXPECT_EQ(payload["sub"], operator_kp->publicString());
    EXPECT_EQ(payload["iss"], operator_kp->publicString()); // Self-signed
    EXPECT_EQ(payload["name"], "Test Operator");
    EXPECT_TRUE(payload.contains("jti"));
    EXPECT_TRUE(payload.contains("iat"));
    EXPECT_EQ(payload["nats"]["type"], "operator");
    EXPECT_EQ(payload["nats"]["version"], 2);

    // Create Account signed by Operator
    auto account_kp = nkeys::CreateAccount();
    auto acc_claims = jwt::AccountClaims(account_kp->publicString());
    acc_claims.setIssuer(operator_kp->publicString());
    acc_claims.setName("Test Account");

    std::string account_jwt = acc_claims.encode(operator_kp->seedString());

    // Verify account JWT structure
    first_dot = account_jwt.find('.');
    second_dot = account_jwt.find('.', first_dot + 1);
    ASSERT_NE(first_dot, std::string::npos);
    ASSERT_NE(second_dot, std::string::npos);

    payload_b64 = account_jwt.substr(first_dot + 1, second_dot - first_dot - 1);
    payload_bytes = jwt::internal::base64url_decode(payload_b64);
    payload_json = std::string(payload_bytes.begin(), payload_bytes.end());
    payload = nlohmann::json::parse(payload_json);

    EXPECT_EQ(payload["sub"], account_kp->publicString());
    EXPECT_EQ(payload["iss"], operator_kp->publicString()); // Signed by operator
    EXPECT_EQ(payload["nats"]["type"], "account");

    // Create User signed by Account
    auto user_kp = nkeys::CreateUser();
    auto user_claims = jwt::UserClaims(user_kp->publicString());
    user_claims.setIssuer(account_kp->publicString());
    user_claims.setIssuerAccount(account_kp->publicString());
    user_claims.setName("Test User");

    std::string user_jwt = user_claims.encode(account_kp->seedString());

    // Verify user JWT structure
    first_dot = user_jwt.find('.');
    second_dot = user_jwt.find('.', first_dot + 1);
    ASSERT_NE(first_dot, std::string::npos);
    ASSERT_NE(second_dot, std::string::npos);

    payload_b64 = user_jwt.substr(first_dot + 1, second_dot - first_dot - 1);
    payload_bytes = jwt::internal::base64url_decode(payload_b64);
    payload_json = std::string(payload_bytes.begin(), payload_bytes.end());
    payload = nlohmann::json::parse(payload_json);

    EXPECT_EQ(payload["sub"], user_kp->publicString());
    EXPECT_EQ(payload["iss"], account_kp->publicString()); // Signed by account
    EXPECT_EQ(payload["nats"]["type"], "user");
    EXPECT_EQ(payload["nats"]["issuer_account"], account_kp->publicString());

    // All JWTs should be non-empty
    EXPECT_FALSE(operator_jwt.empty());
    EXPECT_FALSE(account_jwt.empty());
    EXPECT_FALSE(user_jwt.empty());
}

// Round-trip test: Operator encode → decode
TEST(JwtDecodingTest, OperatorRoundTrip) {
    auto operator_kp = nkeys::CreateOperator();

    // Create and encode operator claims
    auto original = jwt::OperatorClaims(operator_kp->publicString());
    original.setName("Test Operator");
    const auto signingKey = nkeys::CreateOperator()->publicString();
    original.addSigningKey(signingKey);

    std::string jwt_string = original.encode(operator_kp->seedString());

    // Decode the JWT
    auto decoded = jwt::decodeOperatorClaims(jwt_string);

    // Verify all fields match
    EXPECT_EQ(decoded->subject(), original.subject());
    EXPECT_EQ(decoded->issuer(), original.issuer());
    EXPECT_EQ(decoded->name(), original.name());
    EXPECT_GT(decoded->issuedAt(), 0);
    EXPECT_EQ(decoded->expires(), 0); // Not set
    EXPECT_EQ(decoded->signingKeys().size(), 1);
    EXPECT_EQ(decoded->signingKeys()[0], signingKey);
}

// Round-trip test: Account encode → decode
TEST(JwtDecodingTest, AccountRoundTrip) {
    auto operator_kp = nkeys::CreateOperator();
    auto account_kp = nkeys::CreateAccount();

    // Create and encode account claims
    auto original = jwt::AccountClaims(account_kp->publicString());
    original.setIssuer(operator_kp->publicString());
    original.setName("Test Account");
    original.setExpires(9999999999);
    // real account keys: Go's Account.Validate (SigningKeys.Validate) and our
    // encode both refuse fake ones
    const std::string sk1 = nkeys::CreateAccount()->publicString();
    const std::string sk2 = nkeys::CreateAccount()->publicString();
    original.addSigningKey(sk1);
    original.addSigningKey(sk2);

    std::string jwt_string = original.encode(operator_kp->seedString());

    // Decode the JWT
    auto decoded = jwt::decodeAccountClaims(jwt_string);

    // Verify all fields match
    EXPECT_EQ(decoded->subject(), original.subject());
    EXPECT_EQ(decoded->issuer(), original.issuer());
    EXPECT_EQ(decoded->name(), original.name());
    EXPECT_GT(decoded->issuedAt(), 0);
    EXPECT_EQ(decoded->expires(), 9999999999);
    EXPECT_EQ(decoded->signingKeys().size(), 2);
    // Go serializes signing keys SORTED; compare as sets
    std::vector<std::string> want{sk1, sk2}, got = decoded->signingKeys();
    std::sort(want.begin(), want.end()); std::sort(got.begin(), got.end());
    EXPECT_EQ(got, want);
}

// Round-trip test: User encode → decode
TEST(JwtDecodingTest, UserRoundTrip) {
    auto account_kp = nkeys::CreateAccount();
    auto user_kp = nkeys::CreateUser();

    // Create and encode user claims
    auto original = jwt::UserClaims(user_kp->publicString());
    original.setIssuer(account_kp->publicString());
    original.setIssuerAccount(account_kp->publicString());
    original.setName("Test User");
    original.setExpires(8888888888);

    std::string jwt_string = original.encode(account_kp->seedString());

    // Decode the JWT
    auto decoded = jwt::decodeUserClaims(jwt_string);

    // Verify all fields match
    EXPECT_EQ(decoded->subject(), original.subject());
    EXPECT_EQ(decoded->issuer(), original.issuer());
    EXPECT_EQ(decoded->name(), original.name());
    EXPECT_EQ(decoded->issuerAccount(), original.issuerAccount());
    EXPECT_GT(decoded->issuedAt(), 0);
    EXPECT_EQ(decoded->expires(), 8888888888);
}

// Test generic decode with all three types
TEST(JwtDecodingTest, GenericDecodeAllTypes) {
    // Operator JWT
    auto operator_kp = nkeys::CreateOperator();
    auto op_claims = jwt::OperatorClaims(operator_kp->publicString());
    op_claims.setName("Generic Operator");
    std::string op_jwt = op_claims.encode(operator_kp->seedString());

    auto decoded_op = jwt::decode(op_jwt);
    EXPECT_EQ(decoded_op->subject(), operator_kp->publicString());
    EXPECT_EQ(decoded_op->name().value(), "Generic Operator");

    // Account JWT
    auto account_kp = nkeys::CreateAccount();
    auto acc_claims = jwt::AccountClaims(account_kp->publicString());
    acc_claims.setIssuer(operator_kp->publicString());
    acc_claims.setName("Generic Account");
    std::string acc_jwt = acc_claims.encode(operator_kp->seedString());

    auto decoded_acc = jwt::decode(acc_jwt);
    EXPECT_EQ(decoded_acc->subject(), account_kp->publicString());
    EXPECT_EQ(decoded_acc->issuer(), operator_kp->publicString());

    // User JWT
    auto user_kp = nkeys::CreateUser();
    auto user_claims = jwt::UserClaims(user_kp->publicString());
    user_claims.setIssuer(account_kp->publicString());
    user_claims.setName("Generic User");
    std::string user_jwt = user_claims.encode(account_kp->seedString());

    auto decoded_user = jwt::decode(user_jwt);
    EXPECT_EQ(decoded_user->subject(), user_kp->publicString());
    EXPECT_EQ(decoded_user->issuer(), account_kp->publicString());
}

// Test signature verification - valid signature
TEST(JwtVerificationTest, ValidSignature) {
    auto operator_kp = nkeys::CreateOperator();
    auto op_claims = jwt::OperatorClaims(operator_kp->publicString());
    std::string jwt_string = op_claims.encode(operator_kp->seedString());

    // Verify with correct signature
    EXPECT_TRUE(jwt::verify(jwt_string));
}

// Test signature verification - corrupted JWT
TEST(JwtVerificationTest, CorruptedJwt) {
    auto operator_kp = nkeys::CreateOperator();
    auto op_claims = jwt::OperatorClaims(operator_kp->publicString());
    std::string jwt_string = op_claims.encode(operator_kp->seedString());

    // Find signature part (after second dot)
    size_t second_dot = jwt_string.rfind('.');

    // Corrupt the signature in the middle where all 6 bits matter
    // (not the last character which may have padding bits)
    size_t middle_of_sig = second_dot + 1 + 43;  // Middle of 86-char signature
    char original_char = jwt_string[middle_of_sig];

    // Change to a different character (A→B ensures all bits change)
    jwt_string[middle_of_sig] = (original_char == 'A') ? 'B' : 'A';

    // Verification should fail
    EXPECT_FALSE(jwt::verify(jwt_string));
}

// Test signature verification - wrong issuer
TEST(JwtVerificationTest, WrongIssuer) {
    // encode() now derives iss from the signing seed (fix #5), so a
    // mis-signed token can't be MINTED through the API — forge it at the
    // byte level: splice a different issuer into a validly signed payload.
    auto operator_kp = nkeys::CreateOperator();
    auto wrong_operator_kp = nkeys::CreateOperator();

    auto op_claims = jwt::OperatorClaims(operator_kp->publicString());
    std::string token = op_claims.encode(operator_kp->seedString());

    auto first = token.find('.');
    auto second = token.find('.', first + 1);
    auto payload_bytes = jwt::internal::base64url_decode(
        token.substr(first + 1, second - first - 1));
    std::string json(payload_bytes.begin(), payload_bytes.end());
    auto pos = json.find(operator_kp->publicString());
    ASSERT_NE(pos, std::string::npos);
    json.replace(pos, operator_kp->publicString().size(), wrong_operator_kp->publicString());
    std::span<const std::uint8_t> span(
        reinterpret_cast<const std::uint8_t*>(json.data()), json.size());
    std::string forged = token.substr(0, first + 1) +
                         jwt::internal::base64url_encode(span) + token.substr(second);

    EXPECT_FALSE(jwt::verify(forged));
}

// Test malformed JWT - missing parts
TEST(JwtDecodingTest, MalformedJwtMissingParts) {
    EXPECT_THROW((void)jwt::decode("header.payload"), std::invalid_argument);
    EXPECT_THROW((void)jwt::decode("onlyonepart"), std::invalid_argument);
    EXPECT_THROW((void)jwt::decode(""), std::invalid_argument);
}

// Test malformed JWT - too many parts
TEST(JwtDecodingTest, MalformedJwtTooManyParts) {
    EXPECT_THROW((void)jwt::decode("a.b.c.d"), std::invalid_argument);
}

// Test malformed JWT - empty parts
TEST(JwtDecodingTest, MalformedJwtEmptyParts) {
    EXPECT_THROW((void)jwt::decode(".payload.signature"), std::invalid_argument);
    EXPECT_THROW((void)jwt::decode("header..signature"), std::invalid_argument);
    EXPECT_THROW((void)jwt::decode("header.payload."), std::invalid_argument);
}

// Test invalid Base64
TEST(JwtDecodingTest, InvalidBase64) {
    EXPECT_THROW((void)jwt::decode("!!!.@@@.###"), std::exception);
}

// Test type mismatch - decode account as operator
TEST(JwtDecodingTest, TypeMismatchAccountAsOperator) {
    auto operator_kp = nkeys::CreateOperator();
    auto account_kp = nkeys::CreateAccount();

    auto acc_claims = jwt::AccountClaims(account_kp->publicString());
    acc_claims.setIssuer(operator_kp->publicString());
    std::string acc_jwt = acc_claims.encode(operator_kp->seedString());

    // Try to decode as operator - should throw
    EXPECT_THROW((void)jwt::decodeOperatorClaims(acc_jwt), std::invalid_argument);
}

// Test type mismatch - decode user as account
TEST(JwtDecodingTest, TypeMismatchUserAsAccount) {
    auto account_kp = nkeys::CreateAccount();
    auto user_kp = nkeys::CreateUser();

    auto user_claims = jwt::UserClaims(user_kp->publicString());
    user_claims.setIssuer(account_kp->publicString());
    std::string user_jwt = user_claims.encode(account_kp->seedString());

    // Try to decode as account - should throw
    EXPECT_THROW((void)jwt::decodeAccountClaims(user_jwt), std::invalid_argument);
}

// Test minimal JWT (no optional fields)
TEST(JwtDecodingTest, MinimalJwt) {
    auto operator_kp = nkeys::CreateOperator();

    // Create operator with only required fields
    auto op_claims = jwt::OperatorClaims(operator_kp->publicString());
    // Don't set name, expires, or signing keys

    std::string jwt_string = op_claims.encode(operator_kp->seedString());
    auto decoded = jwt::decodeOperatorClaims(jwt_string);

    EXPECT_EQ(decoded->subject(), operator_kp->publicString());
    EXPECT_FALSE(decoded->name().has_value());
    EXPECT_EQ(decoded->expires(), 0);
    EXPECT_TRUE(decoded->signingKeys().empty());
}

// ============================================================================
// formatUserConfig Tests (Creds File Generation)
// ============================================================================

TEST(FormatUserConfigTest, GeneratesValidCredsFile) {
    auto account_kp = nkeys::CreateAccount();
    auto user_kp = nkeys::CreateUser();

    // Create and encode user JWT
    jwt::UserClaims claims(user_kp->publicString());
    claims.setIssuer(account_kp->publicString());
    claims.setName("Test User");

    std::string jwt_string = claims.encode(account_kp->seedString());
    std::string seed = user_kp->seedString();

    // Format creds file
    std::string creds = jwt::formatUserConfig(jwt_string, seed);

    // Verify format structure
    EXPECT_NE(creds.find("-----BEGIN NATS USER JWT-----"), std::string::npos);
    EXPECT_NE(creds.find("------END NATS USER JWT------"), std::string::npos);
    EXPECT_NE(creds.find("-----BEGIN USER NKEY SEED-----"), std::string::npos);
    EXPECT_NE(creds.find("------END USER NKEY SEED------"), std::string::npos);
    EXPECT_NE(creds.find("IMPORTANT"), std::string::npos);
    EXPECT_NE(creds.find("NKEYs are sensitive"), std::string::npos);

    // Verify JWT is present in the creds file
    EXPECT_NE(creds.find(jwt_string.substr(0, 20)), std::string::npos);

    // Verify seed is present
    EXPECT_NE(creds.find(seed), std::string::npos);
}

namespace {
    std::string readFixtureFile(const std::string& name) {
        std::ifstream f(std::string(JWT_TEST_FIXTURES_DIR "/") + name, std::ios::binary);
        EXPECT_TRUE(f.is_open()) << "fixture " << name;
        std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        return s;
    }
    std::string trimNl(std::string s) {
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
        return s;
    }
}

// The one output whose whole purpose is consumption by OTHER NATS software.
// Golden: tests/fixtures/user.creds is the LIVE Go library's FormatUserConfig
// output for fixtures user.jwt + user.seed — C++ must match byte for byte.
// (The old 64-char wrapping broke the armor regex every NATS client uses:
// Go ParseDecoratedJWT failed with "expected 3 chunks".)
TEST(FormatUserConfigTest, MatchesGoByteForByte) {
    const auto jwt_string = trimNl(readFixtureFile("user.jwt"));
    const auto seed = trimNl(readFixtureFile("user.seed"));
    const auto golden = readFixtureFile("user.creds");
    EXPECT_EQ(jwt::formatUserConfig(jwt_string, seed), golden);
}

TEST(FormatUserConfigTest, JwtIsOneUnwrappedLine) {
    auto account_kp = nkeys::CreateAccount();
    auto user_kp = nkeys::CreateUser();

    jwt::UserClaims claims(user_kp->publicString());
    claims.setIssuer(account_kp->publicString());

    std::string jwt_string = claims.encode(account_kp->seedString());
    std::string creds = jwt::formatUserConfig(jwt_string, user_kp->seedString());

    // The armor regex used by NATS clients captures ONE line between the
    // markers — the entire JWT must sit on it, unwrapped.
    EXPECT_NE(creds.find("-----BEGIN NATS USER JWT-----\n" + jwt_string +
                         "\n------END NATS USER JWT------\n"),
              std::string::npos)
        << "JWT must be a single unwrapped line between the armor markers";
}

// Go validates the bundle: the seed must belong to the JWT's subject —
// otherwise the creds file fails at connect time, far from the mistake.
TEST(FormatUserConfigTest, RejectsSeedNotMatchingJwtSubject) {
    auto account_kp = nkeys::CreateAccount();
    auto user_kp = nkeys::CreateUser();
    auto other_kp = nkeys::CreateUser();

    jwt::UserClaims claims(user_kp->publicString());
    claims.setIssuer(account_kp->publicString());
    std::string jwt_string = claims.encode(account_kp->seedString());

    EXPECT_THROW((void)jwt::formatUserConfig(jwt_string, other_kp->seedString()),
        std::invalid_argument
    );
}

TEST(FormatUserConfigTest, RejectsNonUserJwt) {
    auto operator_kp = nkeys::CreateOperator();
    auto user_kp = nkeys::CreateUser();

    jwt::OperatorClaims claims(operator_kp->publicString());
    std::string op_jwt = claims.encode(operator_kp->seedString());

    EXPECT_THROW((void)jwt::formatUserConfig(op_jwt, user_kp->seedString()),
        std::invalid_argument
    );
}

TEST(FormatUserConfigTest, RejectsEmptyJwt) {
    auto user_kp = nkeys::CreateUser();
    EXPECT_THROW((void)jwt::formatUserConfig("", user_kp->seedString()),
        std::invalid_argument
    );
}

TEST(FormatUserConfigTest, RejectsEmptySeed) {
    auto account_kp = nkeys::CreateAccount();
    auto user_kp = nkeys::CreateUser();

    jwt::UserClaims claims(user_kp->publicString());
    claims.setIssuer(account_kp->publicString());
    std::string jwt_string = claims.encode(account_kp->seedString());

    EXPECT_THROW((void)jwt::formatUserConfig(jwt_string, ""),
        std::invalid_argument
    );
}

TEST(FormatUserConfigTest, RejectsNonUserSeed) {
    auto account_kp = nkeys::CreateAccount();
    auto user_kp = nkeys::CreateUser();

    jwt::UserClaims claims(user_kp->publicString());
    claims.setIssuer(account_kp->publicString());
    std::string jwt_string = claims.encode(account_kp->seedString());

    // Try to use account seed instead of user seed
    EXPECT_THROW((void)jwt::formatUserConfig(jwt_string, account_kp->seedString()),
        std::invalid_argument
    );
}

// Go decodes the JWT before bundling — junk that isn't a user JWT is
// rejected, not wrapped up as credentials.
TEST(FormatUserConfigTest, RejectsUndecodableJwt) {
    auto user_kp = nkeys::CreateUser();
    EXPECT_THROW((void)jwt::formatUserConfig("header.payload.sig", user_kp->seedString()),
        std::exception
    );
}

TEST(FormatUserConfigTest, CredsFileCanBeWrittenToFile) {
    auto account_kp = nkeys::CreateAccount();
    auto user_kp = nkeys::CreateUser();

    jwt::UserClaims claims(user_kp->publicString());
    claims.setIssuer(account_kp->publicString());
    claims.setName("Test User");

    std::string jwt_string = claims.encode(account_kp->seedString());
    std::string creds = jwt::formatUserConfig(jwt_string, user_kp->seedString());

    // Write to temporary file
    std::string temp_file = "/tmp/test_user.creds";
    std::ofstream ofs(temp_file);
    ASSERT_TRUE(ofs.is_open());
    ofs << creds;
    ofs.close();

    // Read it back
    std::ifstream ifs(temp_file);
    ASSERT_TRUE(ifs.is_open());
    std::string read_creds((std::istreambuf_iterator<char>(ifs)),
                           std::istreambuf_iterator<char>());
    ifs.close();

    // Verify content matches
    EXPECT_EQ(read_creds, creds);

    // Clean up
    std::remove(temp_file.c_str());
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}


// ============================================================================
// Decode authentication (fix #2) — Go's Decode is parse + signature verify +
// size cap; an unauthenticated decode hands attacker-edited claims to the
// caller (measured: a name=TAMPERED-ADMIN payload swap decoded fine here
// while Go failed with "claim failed V2 signature verification").
// ============================================================================

namespace {
    // Re-encode the payload with one field changed, keeping the signature.
    std::string tamperName(const std::string& token, const std::string& newName) {
        auto first = token.find('.');
        auto second = token.find('.', first + 1);
        auto payload_b64 = token.substr(first + 1, second - first - 1);
        auto bytes = jwt::internal::base64url_decode(payload_b64);
        std::string json(bytes.begin(), bytes.end());
        auto pos = json.find("\"name\":\"");
        EXPECT_NE(pos, std::string::npos) << "token has no name field to tamper";
        auto valStart = pos + 8;
        auto valEnd = json.find('"', valStart);
        json = json.substr(0, valStart) + newName + json.substr(valEnd);
        std::span<const std::uint8_t> span(
            reinterpret_cast<const std::uint8_t*>(json.data()), json.size());
        return token.substr(0, first + 1) + jwt::internal::base64url_encode(span) +
               token.substr(second);
    }
}

TEST(DecodeAuthTest, TamperedUserTokenFailsDecode) {
    auto account_kp = nkeys::CreateAccount();
    auto user_kp = nkeys::CreateUser();
    jwt::UserClaims claims(user_kp->publicString());
    claims.setIssuer(account_kp->publicString());
    claims.setName("alice");
    auto token = claims.encode(account_kp->seedString());

    auto tampered = tamperName(token, "TAMPERED-ADMIN");
    EXPECT_THROW((void)jwt::decodeUserClaims(tampered), std::exception);
    EXPECT_THROW((void)jwt::decode(tampered), std::exception);
    // the untampered token still decodes
    EXPECT_EQ(jwt::decodeUserClaims(token)->name().value_or(""), "alice");
}

TEST(DecodeAuthTest, TamperedOperatorTokenFailsDecode) {
    auto op_kp = nkeys::CreateOperator();
    jwt::OperatorClaims claims(op_kp->publicString());
    claims.setName("op");
    auto token = claims.encode(op_kp->seedString());
    EXPECT_THROW((void)jwt::decodeOperatorClaims(tamperName(token, "evil")), std::exception);
}

TEST(DecodeAuthTest, TokenSignedByOtherKeyFailsDecode) {
    // iss says account A, but the bytes were signed by account B — the
    // signature must be checked against the EMBEDDED issuer. encode() can no
    // longer mint this (fix #5 derives iss from the seed), so the forgery is
    // hand-assembled: payload claiming A, signature by B over those bytes.
    auto a = nkeys::CreateAccount();
    auto b = nkeys::CreateAccount();
    auto user_kp = nkeys::CreateUser();

    std::string header = R"({"typ":"JWT","alg":"ed25519-nkey"})";
    std::string payload = R"({"iat":1700000000,"iss":")" + a->publicString() +
                          R"(","jti":"x","sub":")" + user_kp->publicString() +
                          R"(","nats":{"type":"user","version":2}})";
    auto b64 = [](const std::string& s) {
        std::span<const std::uint8_t> sp(
            reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
        return jwt::internal::base64url_encode(sp);
    };
    std::string signing_input = b64(header) + "." + b64(payload);
    auto kp = nkeys::FromSeed(b->seedString());
    std::span<const std::uint8_t> si(
        reinterpret_cast<const std::uint8_t*>(signing_input.data()), signing_input.size());
    auto sig = kp->sign(si);
    std::string forged = signing_input + "." + jwt::internal::base64url_encode(sig);

    EXPECT_THROW((void)jwt::decodeUserClaims(forged), std::exception);
    // ...while the signature itself IS a valid signature by B: only the
    // issuer binding makes it a forgery.
    EXPECT_TRUE(kp->verify(si, sig));
}

TEST(DecodeAuthTest, GenericDecodeRejectsWrongAlgorithmHeader) {
    // Only the typed decoders checked the header; generic decode() must too.
    auto op_kp = nkeys::CreateOperator();
    jwt::OperatorClaims claims(op_kp->publicString());
    auto token = claims.encode(op_kp->seedString());
    auto first = token.find('.');
    std::string badHeader = R"({"typ":"JWT","alg":"none"})";
    std::span<const std::uint8_t> span(
        reinterpret_cast<const std::uint8_t*>(badHeader.data()), badHeader.size());
    auto forged = jwt::internal::base64url_encode(span) + token.substr(first);
    EXPECT_THROW((void)jwt::decode(forged), std::exception);
}

TEST(DecodeAuthTest, OversizedTokenRejected) {
    // Go caps tokens at 1MB before doing ANY work on them. The token here is
    // VALID (signed, well-formed) — only its size makes it rejectable, so
    // this can't pass by accident on a parse error.
    auto op_kp = nkeys::CreateOperator();
    jwt::OperatorClaims claims(op_kp->publicString());
    claims.setName(std::string(jwt::MAX_JWT_SIZE, 'x'));
    auto huge = claims.encode(op_kp->seedString());
    ASSERT_GT(huge.size(), jwt::MAX_JWT_SIZE);
    EXPECT_THROW((void)jwt::decode(huge), std::exception);
    EXPECT_THROW((void)jwt::decodeOperatorClaims(huge), std::exception);
    EXPECT_FALSE(jwt::verify(huge));
}

TEST(DecodeAuthTest, MaxSizeMatchesGo) {
    EXPECT_EQ(jwt::MAX_JWT_SIZE, 1024u * 1024u) << "Go's MaxTokenSize is 1MB";
}


// ============================================================================
// jti as deterministic content hash (fix #8) — Go computes the claim ID as
// SHA-512/256 over the claims JSON serialized with jti absent, base32-encoded
// without padding. Random hex lost the content-derived property (dedup,
// audit); the hash is over OUR serialization (field order differs from Go's),
// so values differ across libraries by design — the ALGORITHM is what's
// ported. Golden below cross-checked against Python hashlib sha512_256.
// ============================================================================

TEST(JtiTest, ComputeJtiMatchesIndependentImplementation) {
    const std::string payload =
        R"({"iat":1700000000,"iss":"OTEST","sub":"OTEST","nats":{"type":"operator","version":2}})";
    EXPECT_EQ(jwt::internal::computeJti(payload),
              "LO5EK7HX57LMUUMGQ3OGKGPPPFDT2OM774DHUQ723EAXEILCW6QQ");
}

namespace {
    std::string jtiOf(const std::string& token) {
        auto first = token.find('.');
        auto second = token.find('.', first + 1);
        auto bytes = jwt::internal::base64url_decode(
            token.substr(first + 1, second - first - 1));
        auto payload = nlohmann::json::parse(std::string(bytes.begin(), bytes.end()));
        return payload.at("jti").get<std::string>();
    }
}

TEST(JtiTest, JtiIsContentDerivedBase32) {
    auto okp = nkeys::CreateOperator();
    jwt::OperatorClaims claims(okp->publicString());
    claims.setName("alpha");
    auto jti = jtiOf(claims.encode(okp->seedString()));

    // SHA-512/256 → 32 bytes → 52 base32 chars, no padding (Go's shape)
    EXPECT_EQ(jti.size(), 52u);
    for (char c : jti) {
        EXPECT_TRUE((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7')) << c;
    }

    // Same content + same second → same jti (deterministic); different
    // content → different jti. Both tokens carry iat stamped in the same
    // call sequence — retry once if the second ticked over between encodes.
    for (int attempt = 0; attempt < 3; ++attempt) {
        jwt::OperatorClaims a(okp->publicString());
        a.setName("alpha");
        jwt::OperatorClaims b(okp->publicString());
        b.setName("beta");
        auto ja1 = claims.encode(okp->seedString());
        auto ja2 = a.encode(okp->seedString());
        auto jb = b.encode(okp->seedString());
        if (jtiOf(ja1) != jtiOf(ja2)) continue;  // second boundary hit
        EXPECT_EQ(jtiOf(ja1), jtiOf(ja2));
        EXPECT_NE(jtiOf(ja1), jtiOf(jb));
        return;
    }
    FAIL() << "could not encode twice within one second across 3 attempts";
}


// ============================================================================
// Error taxonomy (U5) — every library failure derives from jwt::Error (and
// its historical std base, so existing catch sites keep working):
//   MalformedTokenError  (invalid_argument): not a parseable JWT at all
//   InvalidClaimsError   (invalid_argument): parses, but wrong/ill-formed claims
//   SignatureError       (runtime_error):    authentication failed
// nkeys::Error can also propagate from key material handling (bad seeds).
// ============================================================================

static_assert(std::is_base_of_v<jwt::Error, jwt::MalformedTokenError>);
static_assert(std::is_base_of_v<jwt::Error, jwt::InvalidClaimsError>);
static_assert(std::is_base_of_v<jwt::Error, jwt::SignatureError>);
static_assert(std::is_base_of_v<std::invalid_argument, jwt::MalformedTokenError>);
static_assert(std::is_base_of_v<std::invalid_argument, jwt::InvalidClaimsError>);
static_assert(std::is_base_of_v<std::runtime_error, jwt::SignatureError>);

TEST(ErrorTaxonomyTest, MalformedTokensThrowMalformedTokenError) {
    EXPECT_THROW((void)jwt::decode("not-a-jwt"), jwt::MalformedTokenError);
    EXPECT_THROW((void)jwt::decode("a.b"), jwt::MalformedTokenError);
    EXPECT_THROW((void)jwt::decode("!!!.@@@.###"), jwt::MalformedTokenError);
}

TEST(ErrorTaxonomyTest, JunkJsonPayloadIsMalformedNotALeakedJsonException) {
    // valid base64url whose bytes aren't JSON — pre-taxonomy this leaked a
    // raw nlohmann exception through decode.
    auto b64 = [](const std::string& s) {
        std::span<const std::uint8_t> sp(
            reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
        return jwt::internal::base64url_encode(sp);
    };
    std::string tok = b64(R"({"typ":"JWT","alg":"ed25519-nkey"})") + "." +
                      b64("this is not json") + "." + b64("sig");
    EXPECT_THROW((void)jwt::decode(tok), jwt::MalformedTokenError);
    EXPECT_THROW((void)jwt::decodeUserClaims(tok), jwt::MalformedTokenError);
}

TEST(ErrorTaxonomyTest, WrongClaimsThrowInvalidClaimsError) {
    auto okp = nkeys::CreateOperator();
    jwt::OperatorClaims oc(okp->publicString());
    auto op_jwt = oc.encode(okp->seedString());
    // decode an operator token as an account
    EXPECT_THROW((void)jwt::decodeAccountClaims(op_jwt), jwt::InvalidClaimsError);
    // encode with the wrong signer type
    auto ukp = nkeys::CreateUser();
    jwt::UserClaims uc(ukp->publicString());
    EXPECT_THROW((void)uc.encode(okp->seedString()), jwt::InvalidClaimsError);
}

TEST(ErrorTaxonomyTest, TamperedTokensThrowSignatureError) {
    auto akp = nkeys::CreateAccount();
    auto ukp = nkeys::CreateUser();
    jwt::UserClaims claims(ukp->publicString());
    claims.setName("alice");
    auto tampered = tamperName(claims.encode(akp->seedString()), "EVIL");
    EXPECT_THROW((void)jwt::decodeUserClaims(tampered), jwt::SignatureError);
}

TEST(ErrorTaxonomyTest, EverythingIsCatchableAsJwtError) {
    const std::vector<std::function<void()>> throwers = {
        [] { (void)jwt::decode("junk"); },
        [] { auto okp = nkeys::CreateOperator();
             jwt::OperatorClaims oc(okp->publicString());
             (void)jwt::decodeUserClaims(oc.encode(okp->seedString())); },
    };
    for (const auto& t : throwers) {
        try {
            t();
            FAIL() << "expected a throw";
        } catch (const jwt::Error& e) {
            EXPECT_STRNE(e.what(), "");
        }
    }
    // Key-material failures stay nkeys-typed — callers can tell the layers apart.
    auto ukp = nkeys::CreateUser();
    jwt::UserClaims uc(ukp->publicString());
    EXPECT_THROW((void)uc.encode("not-a-seed"), nkeys::Error);
}


// ============================================================================
// Server-usable claims — found by the real-nats-server gate: Go's
// NewAccountClaims/NewUserClaims emit default NO-limit fields (-1); ours
// omitted them and nats-server treats ABSENT limits as ZERO — accounts that
// can never connect ("maximum account active connections exceeded").
// And the flip side: re-encoding decoded claims must PRESERVE the nats
// object's un-ported fields — otherwise the README's re-sign flow would
// silently replace an account's REAL limits with unlimited defaults.
// ============================================================================

namespace {
    nlohmann::json natsOf(const std::string& token) {
        auto first = token.find('.');
        auto second = token.find('.', first + 1);
        auto bytes = jwt::internal::base64url_decode(
            token.substr(first + 1, second - first - 1));
        return nlohmann::json::parse(std::string(bytes.begin(), bytes.end())).at("nats");
    }
}

TEST(ServerUsableClaimsTest, FreshAccountCarriesGoDefaultLimits) {
    auto okp = nkeys::CreateOperator();
    auto akp = nkeys::CreateAccount();
    jwt::AccountClaims ac(akp->publicString());
    auto nats = natsOf(ac.encode(okp->seedString()));

    const nlohmann::json goDefaults = {
        {"subs", -1}, {"data", -1}, {"payload", -1}, {"imports", -1},
        {"exports", -1}, {"wildcards", true}, {"conn", -1}, {"leaf", -1}};
    EXPECT_EQ(nats.at("limits"), goDefaults);
    EXPECT_EQ(nats.at("default_permissions"),
              nlohmann::json({{"pub", nlohmann::json::object()},
                              {"sub", nlohmann::json::object()}}));
}

TEST(ServerUsableClaimsTest, FreshUserCarriesGoDefaultLimits) {
    auto akp = nkeys::CreateAccount();
    auto ukp = nkeys::CreateUser();
    jwt::UserClaims uc(ukp->publicString());
    auto nats = natsOf(uc.encode(akp->seedString()));

    EXPECT_EQ(nats.at("subs"), -1);
    EXPECT_EQ(nats.at("data"), -1);
    EXPECT_EQ(nats.at("payload"), -1);
    EXPECT_EQ(nats.at("pub"), nlohmann::json::object());
    EXPECT_EQ(nats.at("sub"), nlohmann::json::object());
}

TEST(ServerUsableClaimsTest, ReEncodePreservesUnportedNatsFields) {
    // An account with CUSTOM limits (conn capped at 5) and an un-ported field
    // (mappings), hand-signed so it decodes. Re-signing it (the README's
    // operator re-sign flow) must keep both — replacing them with unlimited
    // defaults would be silent privilege escalation.
    auto akp = nkeys::CreateAccount();
    auto okp = nkeys::CreateOperator();
    std::string header = R"({"typ":"JWT","alg":"ed25519-nkey"})";
    std::string payload = R"({"iat":1700000000,"iss":")" + akp->publicString() +
        R"(","jti":"x","sub":")" + akp->publicString() +
        R"(","nats":{"limits":{"subs":-1,"data":-1,"payload":-1,"imports":-1,)"
        R"("exports":-1,"wildcards":true,"conn":5,"leaf":-1},)"
        R"("exports":[{"name":"q","subject":"q.>","type":"service"}],)"
        R"("cluster_traffic":"owner",)"
        R"("type":"account","version":2}})";
    auto b64 = [](const std::string& s) {
        std::span<const std::uint8_t> sp(
            reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
        return jwt::internal::base64url_encode(sp);
    };
    std::string signing_input = b64(header) + "." + b64(payload);
    auto kp = nkeys::FromSeed(akp->seedString());
    std::span<const std::uint8_t> si(
        reinterpret_cast<const std::uint8_t*>(signing_input.data()), signing_input.size());
    std::string token = signing_input + "." +
                        jwt::internal::base64url_encode(kp->sign(si));

    auto claims = jwt::decodeAccountClaims(token);
    // conn is TYPED now — the custom value must arrive in the accessor too
    EXPECT_EQ(claims->limits().conn, 5);
    auto nats = natsOf(claims->encode(okp->seedString()));
    EXPECT_EQ(nats.at("limits").at("conn"), 5) << "custom limit lost on re-encode";
    EXPECT_EQ(nats.at("exports")[0].at("subject"), "q.>")
        << "un-ported field (exports) lost on re-encode";
    EXPECT_EQ(nats.at("cluster_traffic"), "owner")
        << "un-ported field (cluster_traffic) lost on re-encode";
    EXPECT_EQ(nats.at("type"), "account");
}

// ============================================================================
// Creds parsing + decorating (fix-plan "not-ported" #13) — the parse trio
// delegates to nkeys-cpp (whose behavior was itself measured against Go);
// decorateJWT/decorateSeed are new, gated byte-for-byte on live Go output.
// ============================================================================

namespace {
    std::string fixtureBytes(const std::string& name) {
        std::ifstream f(std::string(JWT_TEST_FIXTURES_DIR "/") + name, std::ios::binary);
        EXPECT_TRUE(f.is_open()) << "fixture " << name;
        return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
    }
    std::string fixtureLine(const std::string& name) {
        auto s = fixtureBytes(name);
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
        return s;
    }
}

TEST(CredsTest, ParseDecoratedJWTFromGoCreds) {
    EXPECT_EQ(jwt::parseDecoratedJWT(fixtureBytes("user.creds")),
              fixtureLine("user.jwt"));
    // bare JWT content passes through unmodified
    EXPECT_EQ(jwt::parseDecoratedJWT(fixtureLine("user.jwt")),
              fixtureLine("user.jwt"));
}

TEST(CredsTest, ParseDecoratedNKeysFromGoCreds) {
    auto creds = fixtureBytes("user.creds");
    auto kp = jwt::parseDecoratedNKey(creds);
    EXPECT_EQ(kp->seedString(), fixtureLine("user.seed"));
    auto ukp = jwt::parseDecoratedUserNKey(creds);
    auto user = jwt::decodeUserClaims(fixtureLine("user.jwt"));
    EXPECT_EQ(ukp->publicString(), user->subject());
}

TEST(CredsTest, DecorateJWTMatchesGoByteForByte) {
    EXPECT_EQ(jwt::decorateJWT(fixtureLine("user.jwt")),
              fixtureBytes("user.jwt.decorated"));
    // account JWTs armor with their own kind
    EXPECT_EQ(jwt::decorateJWT(fixtureLine("account.jwt")),
              fixtureBytes("account.jwt.decorated"));
}

TEST(CredsTest, DecorateSeedMatchesGoByteForByte) {
    EXPECT_EQ(jwt::decorateSeed(fixtureLine("user.seed")),
              fixtureBytes("user.seed.decorated"));
}

TEST(CredsTest, DecorateJWTIsAuthenticated) {
    // Go's DecorateJWT decodes first — junk and tampered tokens are refused.
    EXPECT_THROW((void)jwt::decorateJWT("not-a-jwt"), jwt::Error);
    auto tampered = tamperName(
        [] {
            auto okp = nkeys::CreateOperator();
            jwt::OperatorClaims oc(okp->publicString());
            oc.setName("op");
            return oc.encode(okp->seedString());
        }(),
        "evil");
    EXPECT_THROW((void)jwt::decorateJWT(tampered), jwt::SignatureError);
}

TEST(CredsTest, DecorateSeedRejectsNonSigningSeeds) {
    EXPECT_THROW((void)jwt::decorateSeed("SXNOTASIGNINGSEED"), jwt::InvalidClaimsError);
    EXPECT_THROW((void)jwt::decorateSeed("S"), jwt::InvalidClaimsError);
}

// ============================================================================
// External signer — encodeWithSigner (fix-plan group 5b). Go's
// EncodeWithSigner(kp, fn): kp contributes ONLY its public key (issuer +
// ExpectedPrefixes), fn signs the "header.payload" bytes — the private key
// never enters this process (HSM/KMS custody). Divergence, deliberate: the
// callback's signature is VERIFIED against the advertised key before the
// token is emitted; Go emits whatever fn returns.
// ============================================================================

namespace {
    struct SignerCase {
        const char* name;
        std::function<std::unique_ptr<nkeys::KeyPair>()> makeSigner;  // right key type for the claim
        std::function<std::unique_ptr<jwt::Claims>()> makeClaims;
    };
    std::vector<SignerCase> signerCases() {
        return {
            {"operator", [] { return nkeys::CreateOperator(); },
             [] { return std::unique_ptr<jwt::Claims>(
                      new jwt::OperatorClaims(nkeys::CreateOperator()->publicString())); }},
            {"account", [] { return nkeys::CreateOperator(); },
             [] { return std::unique_ptr<jwt::Claims>(
                      new jwt::AccountClaims(nkeys::CreateAccount()->publicString())); }},
            {"user", [] { return nkeys::CreateAccount(); },
             [] { return std::unique_ptr<jwt::Claims>(
                      new jwt::UserClaims(nkeys::CreateUser()->publicString())); }},
            {"activation", [] { return nkeys::CreateAccount(); },
             [] {
                 auto a = std::make_unique<jwt::ActivationClaims>(nkeys::CreateAccount()->publicString());
                 a->setImportSubject("billing.charge");
                 a->setImportType(jwt::ExportType::Service);
                 return std::unique_ptr<jwt::Claims>(a.release());
             }},
        };
    }
    nlohmann::json payloadOf(const std::string& token) {
        auto p = jwt::internal::parseJwt(token);
        auto bytes = jwt::internal::base64url_decode(p.payload_b64);
        return nlohmann::json::parse(std::string(bytes.begin(), bytes.end()));
    }
    // the "HSM": owns the keypair; the caller only ever sees the public key
    jwt::SignFn hsm(const nkeys::KeyPair& kp) {
        return [&kp](std::string_view, std::span<const std::uint8_t> data) { return kp.sign(data); };
    }
}

TEST(ExternalSignerTest, CallbackTokenEqualsSeedPathAndDecodes) {
    for (const auto& c : signerCases()) {
        SCOPED_TRACE(c.name);
        auto kp = c.makeSigner();
        auto claims = c.makeClaims();
        auto viaSeed = claims->encode(kp->seedString());
        auto viaSigner = claims->encodeWithSigner(kp->publicString(), hsm(*kp));
        EXPECT_TRUE(jwt::verify(viaSigner));
        auto decoded = jwt::decode(viaSigner);  // authenticated
        EXPECT_EQ(decoded->issuer(), kp->publicString());
        // same claims → same payload, modulo the fresh iat (and jti over it)
        auto a = payloadOf(viaSeed), b = payloadOf(viaSigner);
        EXPECT_LE(std::abs(a.at("iat").get<std::int64_t>() - b.at("iat").get<std::int64_t>()), 1);
        for (auto* k : {"iat", "jti"}) { a.erase(k); b.erase(k); }
        EXPECT_EQ(a, b);
    }
}

TEST(ExternalSignerTest, CallbackReceivesAdvertisedKeyAndTheSigningInput) {
    auto akp = nkeys::CreateAccount();
    jwt::UserClaims uc(nkeys::CreateUser()->publicString());
    std::string seenKey;
    std::string seenInput;
    auto token = uc.encodeWithSigner(akp->publicString(),
        [&](std::string_view pub, std::span<const std::uint8_t> data) {
            seenKey = std::string(pub);
            seenInput.assign(reinterpret_cast<const char*>(data.data()), data.size());
            return akp->sign(data);
        });
    EXPECT_EQ(seenKey, akp->publicString());
    EXPECT_EQ(seenInput, jwt::internal::parseJwt(token).signing_input);
}

TEST(ExternalSignerTest, SignatureFromTheWrongKeyIsRefused) {
    // an HSM handed the wrong key handle: the token would name akp as issuer
    // but carry another key's signature — unverifiable by every decoder.
    // Go would emit it; we refuse (the class of bug fix-plan #5 killed).
    auto akp = nkeys::CreateAccount();
    auto other = nkeys::CreateAccount();
    for (const auto& c : signerCases()) {
        SCOPED_TRACE(c.name);
        auto kp = c.makeSigner();
        auto wrong = c.makeSigner();
        auto claims = c.makeClaims();
        EXPECT_THROW((void)claims->encodeWithSigner(kp->publicString(), hsm(*wrong)),
                     jwt::SignatureError);
    }
    jwt::UserClaims uc(nkeys::CreateUser()->publicString());
    // malformed lengths are refused too
    EXPECT_THROW((void)uc.encodeWithSigner(akp->publicString(),
                     [](std::string_view, std::span<const std::uint8_t>) {
                         return std::vector<std::uint8_t>(10, 0xAB); }),
                 jwt::SignatureError);
    EXPECT_THROW((void)uc.encodeWithSigner(akp->publicString(),
                     [](std::string_view, std::span<const std::uint8_t>) {
                         return std::vector<std::uint8_t>{}; }),
                 jwt::SignatureError);
}

TEST(ExternalSignerTest, PrefixRulesApplyToTheAdvertisedKeyBeforeSigning) {
    // Go's ExpectedPrefixes run on kp's public key; the callback is never
    // reached for a disallowed issuer type (or a garbage key)
    auto okp = nkeys::CreateOperator();
    bool called = false;
    auto counting = [&](std::string_view, std::span<const std::uint8_t> d) { called = true; return okp->sign(d); };
    jwt::UserClaims uc(nkeys::CreateUser()->publicString());
    EXPECT_THROW((void)uc.encodeWithSigner(okp->publicString(), counting), jwt::InvalidClaimsError);
    EXPECT_THROW((void)uc.encodeWithSigner("not-a-key", counting), jwt::InvalidClaimsError);
    EXPECT_FALSE(called);
}

TEST(ExternalSignerTest, SignerExceptionsPropagateUnwrapped) {
    // the callback's failure is the caller's error (Go returns fn's err as-is)
    struct HsmDown : std::runtime_error { using std::runtime_error::runtime_error; };
    auto akp = nkeys::CreateAccount();
    jwt::UserClaims uc(nkeys::CreateUser()->publicString());
    EXPECT_THROW((void)uc.encodeWithSigner(akp->publicString(),
                     [](std::string_view, std::span<const std::uint8_t>) -> std::vector<std::uint8_t> {
                         throw HsmDown("hsm unreachable"); }),
                 HsmDown);
}
