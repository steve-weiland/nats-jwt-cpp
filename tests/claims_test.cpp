#include <gtest/gtest.h>
#include "jwt/claims.hpp"
#include "jwt/validation.hpp"
#include "jwt/jwt_errors.hpp"
#include "jwt/operator_claims.hpp"
#include "jwt/account_claims.hpp"
#include "jwt/user_claims.hpp"
#include <nkeys/nkeys.hpp>

// ============================================================================
// OperatorClaims Tests
// ============================================================================

TEST(OperatorClaimsTest, ConstructorSetsSubject) {
    auto kp = nkeys::CreateOperator();
    jwt::OperatorClaims claims(kp->publicString());

    EXPECT_EQ(claims.subject(), kp->publicString());
}

TEST(OperatorClaimsTest, ConstructorSetsSelfSigned) {
    auto kp = nkeys::CreateOperator();
    jwt::OperatorClaims claims(kp->publicString());

    // Operator is self-signed
    EXPECT_EQ(claims.issuer(), kp->publicString());
    EXPECT_EQ(claims.subject(), claims.issuer());
}

TEST(OperatorClaimsTest, SetNameWorks) {
    auto kp = nkeys::CreateOperator();
    jwt::OperatorClaims claims(kp->publicString());

    EXPECT_FALSE(claims.name().has_value());

    claims.setName("Test Operator");
    EXPECT_TRUE(claims.name().has_value());
    EXPECT_EQ(claims.name().value(), "Test Operator");
}

TEST(OperatorClaimsTest, SetExpiresWorks) {
    auto kp = nkeys::CreateOperator();
    jwt::OperatorClaims claims(kp->publicString());

    EXPECT_EQ(claims.expires(), 0);

    claims.setExpires(9999999999);
    EXPECT_EQ(claims.expires(), 9999999999);
}

TEST(OperatorClaimsTest, AddSigningKeysWorks) {
    auto kp = nkeys::CreateOperator();
    jwt::OperatorClaims claims(kp->publicString());

    EXPECT_TRUE(claims.signingKeys().empty());

    claims.addSigningKey("OABC123");
    EXPECT_EQ(claims.signingKeys().size(), 1);
    EXPECT_EQ(claims.signingKeys()[0], "OABC123");

    claims.addSigningKey("OXYZ789");
    EXPECT_EQ(claims.signingKeys().size(), 2);
    EXPECT_EQ(claims.signingKeys()[1], "OXYZ789");
}

TEST(OperatorClaimsTest, IssuedAtDefaultsToZero) {
    auto kp = nkeys::CreateOperator();
    jwt::OperatorClaims claims(kp->publicString());

    EXPECT_EQ(claims.issuedAt(), 0);
}

TEST(OperatorClaimsTest, ValidateSucceedsForValidClaims) {
    auto kp = nkeys::CreateOperator();
    jwt::OperatorClaims claims(kp->publicString());

    EXPECT_NO_THROW(claims.validate());
}

TEST(OperatorClaimsTest, ValidateFailsForEmptySubject) {
    jwt::OperatorClaims claims("");

    EXPECT_THROW(claims.validate(), std::invalid_argument);
}

TEST(OperatorClaimsTest, ValidateFailsForNonOperatorSubject) {
    auto kp = nkeys::CreateAccount();  // Wrong type
    jwt::OperatorClaims claims(kp->publicString());

    EXPECT_THROW(claims.validate(), std::invalid_argument);
}

TEST(OperatorClaimsTest, ExpiryIsValidityNotStructure) {
    // Go encodes AND decodes already-expired tokens — being expired is a
    // TIMING failure (validateExpiration), never a structural one. The old
    // structural check made expired credentials undecodable, uninspectable.
    auto kp = nkeys::CreateOperator();
    jwt::OperatorClaims claims(kp->publicString());
    auto jwt_str = claims.encode(kp->seedString());
    auto decoded = jwt::decodeOperatorClaims(jwt_str);

    decoded->setExpires(1);  // long past
    EXPECT_NO_THROW(decoded->validate());
    EXPECT_FALSE(jwt::validateExpiration(*decoded).valid);
}

// ============================================================================
// AccountClaims Tests
// ============================================================================

TEST(AccountClaimsTest, ConstructorSetsSubject) {
    auto kp = nkeys::CreateAccount();
    jwt::AccountClaims claims(kp->publicString());

    EXPECT_EQ(claims.subject(), kp->publicString());
}

TEST(AccountClaimsTest, IssuerNotSetByDefault) {
    auto kp = nkeys::CreateAccount();
    jwt::AccountClaims claims(kp->publicString());

    // Issuer should be empty initially (will be set via setIssuer)
    EXPECT_TRUE(claims.issuer().empty());
}

TEST(AccountClaimsTest, SetIssuerWorks) {
    auto account_kp = nkeys::CreateAccount();
    auto operator_kp = nkeys::CreateOperator();

    jwt::AccountClaims claims(account_kp->publicString());
    claims.setIssuer(operator_kp->publicString());

    EXPECT_EQ(claims.issuer(), operator_kp->publicString());
}

TEST(AccountClaimsTest, SetNameWorks) {
    auto kp = nkeys::CreateAccount();
    jwt::AccountClaims claims(kp->publicString());

    EXPECT_FALSE(claims.name().has_value());

    claims.setName("Test Account");
    EXPECT_TRUE(claims.name().has_value());
    EXPECT_EQ(claims.name().value(), "Test Account");
}

TEST(AccountClaimsTest, SetExpiresWorks) {
    auto kp = nkeys::CreateAccount();
    jwt::AccountClaims claims(kp->publicString());

    EXPECT_EQ(claims.expires(), 0);

    claims.setExpires(8888888888);
    EXPECT_EQ(claims.expires(), 8888888888);
}

TEST(AccountClaimsTest, AddSigningKeysWorks) {
    auto kp = nkeys::CreateAccount();
    jwt::AccountClaims claims(kp->publicString());

    EXPECT_TRUE(claims.signingKeys().empty());

    claims.addSigningKey("AABC123");
    EXPECT_EQ(claims.signingKeys().size(), 1);
    EXPECT_EQ(claims.signingKeys()[0], "AABC123");
}

TEST(AccountClaimsTest, ValidateFailsForEmptySubject) {
    jwt::AccountClaims claims("");
    auto operator_kp = nkeys::CreateOperator();
    claims.setIssuer(operator_kp->publicString());

    EXPECT_THROW(claims.validate(), std::invalid_argument);
}

TEST(AccountClaimsTest, ValidateFailsForEmptyIssuer) {
    auto kp = nkeys::CreateAccount();
    jwt::AccountClaims claims(kp->publicString());

    EXPECT_THROW(claims.validate(), std::invalid_argument);
}

TEST(AccountClaimsTest, ValidateFailsForNonAccountSubject) {
    auto user_kp = nkeys::CreateUser();  // Wrong type
    auto operator_kp = nkeys::CreateOperator();

    jwt::AccountClaims claims(user_kp->publicString());
    claims.setIssuer(operator_kp->publicString());

    EXPECT_THROW(claims.validate(), std::invalid_argument);
}

TEST(AccountClaimsTest, ValidateFailsForNonOperatorIssuer) {
    auto account_kp = nkeys::CreateAccount();
    auto user_kp = nkeys::CreateUser();  // Wrong type

    jwt::AccountClaims claims(account_kp->publicString());
    claims.setIssuer(user_kp->publicString());

    EXPECT_THROW(claims.validate(), std::invalid_argument);
}

// ============================================================================
// UserClaims Tests
// ============================================================================

TEST(UserClaimsTest, ConstructorSetsSubject) {
    auto kp = nkeys::CreateUser();
    jwt::UserClaims claims(kp->publicString());

    EXPECT_EQ(claims.subject(), kp->publicString());
}

TEST(UserClaimsTest, IssuerNotSetByDefault) {
    auto kp = nkeys::CreateUser();
    jwt::UserClaims claims(kp->publicString());

    EXPECT_TRUE(claims.issuer().empty());
}

TEST(UserClaimsTest, SetIssuerWorks) {
    auto user_kp = nkeys::CreateUser();
    auto account_kp = nkeys::CreateAccount();

    jwt::UserClaims claims(user_kp->publicString());
    claims.setIssuer(account_kp->publicString());

    EXPECT_EQ(claims.issuer(), account_kp->publicString());
}

TEST(UserClaimsTest, SetNameWorks) {
    auto kp = nkeys::CreateUser();
    jwt::UserClaims claims(kp->publicString());

    EXPECT_FALSE(claims.name().has_value());

    claims.setName("Test User");
    EXPECT_TRUE(claims.name().has_value());
    EXPECT_EQ(claims.name().value(), "Test User");
}

TEST(UserClaimsTest, SetExpiresWorks) {
    auto kp = nkeys::CreateUser();
    jwt::UserClaims claims(kp->publicString());

    EXPECT_EQ(claims.expires(), 0);

    claims.setExpires(7777777777);
    EXPECT_EQ(claims.expires(), 7777777777);
}

TEST(UserClaimsTest, IssuerAccountNotSetByDefault) {
    auto kp = nkeys::CreateUser();
    jwt::UserClaims claims(kp->publicString());

    EXPECT_FALSE(claims.issuerAccount().has_value());
}

TEST(UserClaimsTest, SetIssuerAccountWorks) {
    auto user_kp = nkeys::CreateUser();
    auto account_kp = nkeys::CreateAccount();

    jwt::UserClaims claims(user_kp->publicString());
    claims.setIssuerAccount(account_kp->publicString());

    EXPECT_TRUE(claims.issuerAccount().has_value());
    EXPECT_EQ(claims.issuerAccount().value(), account_kp->publicString());
}

TEST(UserClaimsTest, ValidateFailsForEmptySubject) {
    jwt::UserClaims claims("");
    auto account_kp = nkeys::CreateAccount();
    claims.setIssuer(account_kp->publicString());

    EXPECT_THROW(claims.validate(), std::invalid_argument);
}

TEST(UserClaimsTest, ValidateFailsForEmptyIssuer) {
    auto kp = nkeys::CreateUser();
    jwt::UserClaims claims(kp->publicString());

    EXPECT_THROW(claims.validate(), std::invalid_argument);
}

TEST(UserClaimsTest, ValidateFailsForNonUserSubject) {
    auto account_kp = nkeys::CreateAccount();  // Wrong type
    auto issuer_kp = nkeys::CreateAccount();

    jwt::UserClaims claims(account_kp->publicString());
    claims.setIssuer(issuer_kp->publicString());

    EXPECT_THROW(claims.validate(), std::invalid_argument);
}

TEST(UserClaimsTest, ValidateFailsForNonAccountIssuer) {
    auto user_kp = nkeys::CreateUser();
    auto operator_kp = nkeys::CreateOperator();  // Wrong type

    jwt::UserClaims claims(user_kp->publicString());
    claims.setIssuer(operator_kp->publicString());

    EXPECT_THROW(claims.validate(), std::invalid_argument);
}

// ============================================================================
// Integration Tests - Trust Hierarchy
// ============================================================================

TEST(ClaimsIntegrationTest, OperatorSignsAccount) {
    auto operator_kp = nkeys::CreateOperator();
    auto account_kp = nkeys::CreateAccount();

    // Create operator
    jwt::OperatorClaims op_claims(operator_kp->publicString());
    op_claims.setName("MyOperator");

    // Create account signed by operator
    jwt::AccountClaims acc_claims(account_kp->publicString());
    acc_claims.setIssuer(operator_kp->publicString());
    acc_claims.setName("MyAccount");

    // Encode account with operator's seed
    std::string account_jwt = acc_claims.encode(operator_kp->seedString());

    // Verify account JWT
    EXPECT_TRUE(jwt::verify(account_jwt));

    // Decode and verify fields
    auto decoded = jwt::decodeAccountClaims(account_jwt);
    EXPECT_EQ(decoded->subject(), account_kp->publicString());
    EXPECT_EQ(decoded->issuer(), operator_kp->publicString());
}

TEST(ClaimsIntegrationTest, AccountSignsUser) {
    auto account_kp = nkeys::CreateAccount();
    auto user_kp = nkeys::CreateUser();

    // Create user signed by account
    jwt::UserClaims user_claims(user_kp->publicString());
    user_claims.setIssuer(account_kp->publicString());
    user_claims.setIssuerAccount(account_kp->publicString());
    user_claims.setName("MyUser");

    // Encode user with account's seed
    std::string user_jwt = user_claims.encode(account_kp->seedString());

    // Verify user JWT
    EXPECT_TRUE(jwt::verify(user_jwt));

    // Decode and verify fields
    auto decoded = jwt::decodeUserClaims(user_jwt);
    EXPECT_EQ(decoded->subject(), user_kp->publicString());
    EXPECT_EQ(decoded->issuer(), account_kp->publicString());
    EXPECT_EQ(decoded->issuerAccount().value(), account_kp->publicString());
}

TEST(ClaimsIntegrationTest, CompleteHierarchy) {
    // Create full hierarchy: Operator -> Account -> User
    auto operator_kp = nkeys::CreateOperator();
    auto account_kp = nkeys::CreateAccount();
    auto user_kp = nkeys::CreateUser();

    // Operator (self-signed)
    jwt::OperatorClaims op_claims(operator_kp->publicString());
    op_claims.setName("Root Operator");
    std::string op_jwt = op_claims.encode(operator_kp->seedString());
    EXPECT_TRUE(jwt::verify(op_jwt));

    // Account (signed by operator)
    jwt::AccountClaims acc_claims(account_kp->publicString());
    acc_claims.setIssuer(operator_kp->publicString());
    acc_claims.setName("Test Account");
    std::string acc_jwt = acc_claims.encode(operator_kp->seedString());
    EXPECT_TRUE(jwt::verify(acc_jwt));

    // User (signed by account)
    jwt::UserClaims user_claims(user_kp->publicString());
    user_claims.setIssuer(account_kp->publicString());
    user_claims.setIssuerAccount(account_kp->publicString());
    user_claims.setName("Test User");
    std::string user_jwt = user_claims.encode(account_kp->seedString());
    EXPECT_TRUE(jwt::verify(user_jwt));

    // Verify the chain
    auto decoded_op = jwt::decodeOperatorClaims(op_jwt);
    auto decoded_acc = jwt::decodeAccountClaims(acc_jwt);
    auto decoded_user = jwt::decodeUserClaims(user_jwt);

    // Operator is self-signed
    EXPECT_EQ(decoded_op->subject(), decoded_op->issuer());

    // Account is signed by operator
    EXPECT_EQ(decoded_acc->issuer(), decoded_op->subject());

    // User is signed by account
    EXPECT_EQ(decoded_user->issuer(), decoded_acc->subject());
}

// ============================================================================
// Edge Cases
// ============================================================================

TEST(ClaimsEdgeCaseTest, EmptyOptionalFields) {
    auto kp = nkeys::CreateOperator();
    jwt::OperatorClaims claims(kp->publicString());

    // No name set
    EXPECT_FALSE(claims.name().has_value());

    // No expires set (defaults to 0)
    EXPECT_EQ(claims.expires(), 0);

    // No signing keys
    EXPECT_TRUE(claims.signingKeys().empty());

    // Should still encode/decode successfully
    std::string jwt = claims.encode(kp->seedString());
    auto decoded = jwt::decodeOperatorClaims(jwt);

    EXPECT_FALSE(decoded->name().has_value());
    EXPECT_EQ(decoded->expires(), 0);
    EXPECT_TRUE(decoded->signingKeys().empty());
}

TEST(ClaimsEdgeCaseTest, VeryLongName) {
    auto kp = nkeys::CreateOperator();
    jwt::OperatorClaims claims(kp->publicString());

    std::string long_name(1000, 'x');
    claims.setName(long_name);

    std::string jwt = claims.encode(kp->seedString());
    auto decoded = jwt::decodeOperatorClaims(jwt);

    EXPECT_EQ(decoded->name().value(), long_name);
}

TEST(ClaimsEdgeCaseTest, ManySigningKeys) {
    auto kp = nkeys::CreateOperator();
    jwt::OperatorClaims claims(kp->publicString());

    // Add 100 signing keys
    for (int i = 0; i < 100; i++) {
        claims.addSigningKey("OKEY" + std::to_string(i));
    }

    EXPECT_EQ(claims.signingKeys().size(), 100);

    std::string jwt = claims.encode(kp->seedString());
    auto decoded = jwt::decodeOperatorClaims(jwt);

    EXPECT_EQ(decoded->signingKeys().size(), 100);
    EXPECT_EQ(decoded->signingKeys()[0], "OKEY0");
    EXPECT_EQ(decoded->signingKeys()[99], "OKEY99");
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

// ============================================================================
// User permissions + limits (fix-plan "not-ported" #1+#2) — Go's User schema,
// ported completely and gated on Go-minted goldens. Wire facts measured:
// resp = {"max","ttl"} with ttl in NANOSECONDS; queue subjects ("subj queue")
// legal only in sub, max two tokens; src marshals as an array but Go's
// decoder also accepts a comma string; empty lists are omitted (omitempty)
// while pub/sub objects always serialize.
// ============================================================================

#include <nlohmann/json.hpp>
#include "../src/base64url.hpp"
#include <fstream>

namespace {
    std::string readFixture2(const std::string& name) {
        std::ifstream f(std::string(JWT_TEST_FIXTURES_DIR "/") + name, std::ios::binary);
        EXPECT_TRUE(f.is_open()) << "fixture " << name;
        std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
        return s;
    }
    nlohmann::json natsObjectOf(const std::string& token) {
        auto first = token.find('.');
        auto second = token.find('.', first + 1);
        auto bytes = jwt::internal::base64url_decode(
            token.substr(first + 1, second - first - 1));
        return nlohmann::json::parse(std::string(bytes.begin(), bytes.end())).at("nats");
    }
    // The rich claims from the Go probe's genrichuser, rebuilt via the C++ API.
    void buildRichClaims(jwt::UserClaims& uc) {
        uc.setName("rich");
        auto& p = uc.permissions();
        p.pub.allow = {"demo.>", "orders.*.created"};
        p.pub.deny = {"demo.secret"};
        p.sub.allow = {"demo.>", "jobs.* workers"};
        p.sub.deny = {"demo.internal.>"};
        p.resp = jwt::ResponsePermission{5, 2000000000LL};
        auto& l = uc.limits();
        l.subs = 100;
        l.data = 1 << 20;
        l.payload = 4096;
        l.src = {"10.0.0.0/8", "192.168.1.0/24"};
        l.times = {{"08:00:00", "17:00:00"}};
        l.locale = "America/Los_Angeles";
    }
}

TEST(UserPermissionsTest, DecodesGoRichUserIntoTypedFields) {
    auto uc = jwt::decodeUserClaims(readFixture2("user-rich.jwt"));
    const auto& p = uc->permissions();
    EXPECT_EQ(p.pub.allow, (std::vector<std::string>{"demo.>", "orders.*.created"}));
    EXPECT_EQ(p.pub.deny, (std::vector<std::string>{"demo.secret"}));
    EXPECT_EQ(p.sub.allow, (std::vector<std::string>{"demo.>", "jobs.* workers"}));
    EXPECT_EQ(p.sub.deny, (std::vector<std::string>{"demo.internal.>"}));
    ASSERT_TRUE(p.resp.has_value());
    EXPECT_EQ(p.resp->maxMsgs, 5);
    EXPECT_EQ(p.resp->ttlNanos, 2000000000LL);  // 2s, Go time.Duration = nanos
    const auto& l = uc->limits();
    EXPECT_EQ(l.subs, 100);
    EXPECT_EQ(l.data, 1 << 20);
    EXPECT_EQ(l.payload, 4096);
    EXPECT_EQ(l.src, (std::vector<std::string>{"10.0.0.0/8", "192.168.1.0/24"}));
    ASSERT_EQ(l.times.size(), 1u);
    EXPECT_EQ(l.times[0].start, "08:00:00");
    EXPECT_EQ(l.times[0].end, "17:00:00");
    EXPECT_EQ(l.locale, "America/Los_Angeles");
}

TEST(UserPermissionsTest, EncodeMatchesGoWireShapeExactly) {
    // Build the same claims Go's genrichuser built; the entire nats object
    // must equal the Go golden's (json equality is order-insensitive).
    auto akp = nkeys::CreateAccount();
    auto ukp = nkeys::CreateUser();
    jwt::UserClaims uc(ukp->publicString());
    buildRichClaims(uc);
    auto ours = natsObjectOf(uc.encode(akp->seedString()));
    auto golden = natsObjectOf(readFixture2("user-rich.jwt"));
    EXPECT_EQ(ours, golden);
}

TEST(UserPermissionsTest, DefaultsAndOmitemptyMatchGo) {
    auto akp = nkeys::CreateAccount();
    auto ukp = nkeys::CreateUser();
    jwt::UserClaims uc(ukp->publicString());
    auto nats = natsObjectOf(uc.encode(akp->seedString()));
    // fresh: empty pub/sub objects, -1 limits, and NO optional keys
    EXPECT_EQ(nats.at("pub"), nlohmann::json::object());
    EXPECT_EQ(nats.at("subs"), -1);
    for (const char* absent : {"resp", "src", "times", "times_location"}) {
        EXPECT_FALSE(nats.contains(absent)) << absent;
    }
    // Go's omitempty: a zero limit is OMITTED (absent means zero server-side)
    uc.limits().subs = 0;
    auto nats2 = natsObjectOf(uc.encode(akp->seedString()));
    EXPECT_FALSE(nats2.contains("subs"));
}

TEST(UserPermissionsTest, ClearedFieldsAreOmittedOnReEncode) {
    // decode the rich fixture, clear the denies, re-encode: the deny keys
    // must vanish (typed fields own their keys; stale raw values must not
    // leak through the carry-layer).
    auto uc = jwt::decodeUserClaims(readFixture2("user-rich.jwt"));
    uc->permissions().pub.deny.clear();
    uc->permissions().sub.deny.clear();
    uc->permissions().resp.reset();
    auto akp = nkeys::CreateAccount();
    auto nats = natsObjectOf(uc->encode(akp->seedString()));
    EXPECT_FALSE(nats.at("pub").contains("deny"));
    EXPECT_FALSE(nats.at("sub").contains("deny"));
    EXPECT_FALSE(nats.contains("resp"));
    EXPECT_EQ(nats.at("pub").at("allow"),
              (std::vector<std::string>{"demo.>", "orders.*.created"}));
}

TEST(UserPermissionsTest, ValidationRulesMatchGo) {
    auto akp = nkeys::CreateAccount();
    auto ukp = nkeys::CreateUser();

    // queue subjects are legal in sub...
    jwt::UserClaims ok(ukp->publicString());
    ok.permissions().sub.allow = {"jobs.* workers"};
    EXPECT_NO_THROW((void)ok.encode(akp->seedString()));

    // ...but not in pub
    jwt::UserClaims badPub(ukp->publicString());
    badPub.permissions().pub.allow = {"jobs.* workers"};
    EXPECT_THROW((void)badPub.encode(akp->seedString()), jwt::InvalidClaimsError);

    // three space-separated tokens: never valid
    jwt::UserClaims tooMany(ukp->publicString());
    tooMany.permissions().sub.allow = {"a b c"};
    EXPECT_THROW((void)tooMany.encode(akp->seedString()), jwt::InvalidClaimsError);

    // invalid CIDR
    jwt::UserClaims badCidr(ukp->publicString());
    badCidr.limits().src = {"not-a-cidr"};
    EXPECT_THROW((void)badCidr.encode(akp->seedString()), jwt::InvalidClaimsError);

    // malformed time range ("8:00" — Go requires 15:04:05 format)
    jwt::UserClaims badTime(ukp->publicString());
    badTime.limits().times = {{"8:00", "17:00:00"}};
    EXPECT_THROW((void)badTime.encode(akp->seedString()), jwt::InvalidClaimsError);
}

TEST(UserPermissionsTest, SrcAcceptsCommaStringOnDecode) {
    // Go's CIDRList unmarshals either a JSON array or a comma string; match.
    auto akp = nkeys::CreateAccount();
    auto ukp = nkeys::CreateUser();
    std::string header = R"({"typ":"JWT","alg":"ed25519-nkey"})";
    std::string payload = R"({"iat":1700000000,"iss":")" + akp->publicString() +
        R"(","jti":"x","sub":")" + ukp->publicString() +
        R"(","nats":{"src":"10.0.0.0/8,192.168.1.0/24","type":"user","version":2}})";
    auto b64 = [](const std::string& s) {
        std::span<const std::uint8_t> sp(
            reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
        return jwt::internal::base64url_encode(sp);
    };
    std::string si = b64(header) + "." + b64(payload);
    auto kp = nkeys::FromSeed(akp->seedString());
    std::span<const std::uint8_t> sib(
        reinterpret_cast<const std::uint8_t*>(si.data()), si.size());
    auto uc = jwt::decodeUserClaims(si + "." + jwt::internal::base64url_encode(kp->sign(sib)));
    EXPECT_EQ(uc->limits().src, (std::vector<std::string>{"10.0.0.0/8", "192.168.1.0/24"}));
}
