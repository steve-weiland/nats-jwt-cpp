#include <gtest/gtest.h>
#include "jwt/claims.hpp"
#include "jwt/validation.hpp"
#include "jwt/jwt_errors.hpp"
#include "jwt/creds.hpp"
#include "jwt/operator_claims.hpp"
#include "jwt/account_claims.hpp"
#include "jwt/activation_claims.hpp"
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

    const auto k1 = nkeys::CreateOperator()->publicString();
    claims.addSigningKey(k1);
    EXPECT_EQ(claims.signingKeys().size(), 1);
    EXPECT_EQ(claims.signingKeys()[0], k1);

    const auto k2 = nkeys::CreateOperator()->publicString();
    claims.addSigningKey(k2);
    EXPECT_EQ(claims.signingKeys().size(), 2);
    EXPECT_EQ(claims.signingKeys()[1], k2);
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
        claims.addSigningKey(nkeys::CreateOperator()->publicString());
    }

    EXPECT_EQ(claims.signingKeys().size(), 100);

    std::string jwt = claims.encode(kp->seedString());
    auto decoded = jwt::decodeOperatorClaims(jwt);

    EXPECT_EQ(decoded->signingKeys().size(), 100);
    // signing keys serialize SORTED (Go); order-insensitive containment check
    std::vector<std::string> in = claims.signingKeys(), out = decoded->signingKeys();
    std::sort(in.begin(), in.end());
    std::sort(out.begin(), out.end());
    EXPECT_EQ(in, out);
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

// ============================================================================
// Scoped signing keys + IssueUserJWT (fix-plan "not-ported" #8 + #14) — wire
// facts measured from Go: signing_keys serializes SORTED, plain keys as
// strings and scopes as {kind:"user_scope", key, role, template, description}
// (none omitempty); SetScoped zeroes UserPermissionLimits so a scoped user's
// wire has pub:{}, sub:{} and NO subs/data/payload; ValidateScopedSigner
// demands scoped users carry no permissions or limits of their own.
// ============================================================================

TEST(ScopedSigningKeysTest, DecodesGoScopedAccount) {
    auto ac = jwt::decodeAccountClaims(readFixture2("acc-scoped.jwt"));
    ASSERT_EQ(ac->signingKeys().size(), 2u);

    // find which key carries the scope
    std::optional<jwt::UserScope> scope;
    std::string plainKey;
    for (const auto& k : ac->signingKeys()) {
        if (auto s = ac->getScope(k)) scope = s;
        else plainKey = k;
    }
    ASSERT_TRUE(scope.has_value());
    EXPECT_FALSE(plainKey.empty());
    EXPECT_EQ(scope->role, "demo-only");
    EXPECT_EQ(scope->description, "may only touch demo.>");
    EXPECT_EQ(scope->permissions.pub.allow, (std::vector<std::string>{"demo.>"}));
    EXPECT_EQ(scope->permissions.sub.allow,
              (std::vector<std::string>{"demo.>", "_INBOX.>"}));
    EXPECT_EQ(scope->limits.subs, -1);
    EXPECT_EQ(scope->limits.payload, 4096);
}

TEST(ScopedSigningKeysTest, ReEncodePreservesScopeByteFaithfully) {
    // decode the Go golden, re-sign with a fresh operator: the whole nats
    // object must survive EQUAL — scope, sorted mixed array, and all.
    auto ac = jwt::decodeAccountClaims(readFixture2("acc-scoped.jwt"));
    auto okp = nkeys::CreateOperator();
    auto ours = natsObjectOf(ac->encode(okp->seedString()));
    auto golden = natsObjectOf(readFixture2("acc-scoped.jwt"));
    EXPECT_EQ(ours, golden);
}

TEST(ScopedSigningKeysTest, SigningKeysSerializeSorted) {
    auto akp = nkeys::CreateAccount();
    jwt::AccountClaims ac(akp->publicString());
    // add several keys in whatever order they come — wire must be sorted
    std::vector<std::string> keys;
    for (int i = 0; i < 3; ++i) {
        keys.push_back(nkeys::CreateAccount()->publicString());
        ac.addSigningKey(keys.back());
    }
    auto nats = natsObjectOf(ac.encode(akp->seedString()));
    auto onWire = nats.at("signing_keys").get<std::vector<std::string>>();
    auto sorted = onWire;
    std::sort(sorted.begin(), sorted.end());
    EXPECT_EQ(onWire, sorted);
}

TEST(ScopedSigningKeysTest, SetScopedZeroesPermissionLimits) {
    auto ukp = nkeys::CreateUser();
    auto akp = nkeys::CreateAccount();
    jwt::UserClaims uc(ukp->publicString());
    uc.permissions().pub.allow = {"x"};
    EXPECT_FALSE(uc.hasEmptyPermissions());
    uc.setScoped(true);
    EXPECT_TRUE(uc.hasEmptyPermissions());
    auto nats = natsObjectOf(uc.encode(akp->seedString()));
    EXPECT_EQ(nats.at("pub"), nlohmann::json::object());
    for (const char* absent : {"subs", "data", "payload"}) {
        EXPECT_FALSE(nats.contains(absent)) << absent;
    }
    // setScoped(false) restores Go's -1 defaults
    uc.setScoped(false);
    EXPECT_EQ(uc.limits().subs, -1);
}

TEST(ScopedSigningKeysTest, IssueUserJWTMatchesGoShape) {
    auto akp = nkeys::CreateAccount();
    auto scopedSK = nkeys::CreateAccount();
    auto ukp = nkeys::CreateUser();
    auto token = jwt::issueUserJWT(scopedSK->seedString(), akp->publicString(),
                                   ukp->publicString());
    // Go's IssueUserJWT wire: scoped (empty) user + issuer_account, nothing else
    auto nats = natsObjectOf(token);
    nlohmann::json expected = {
        {"pub", nlohmann::json::object()}, {"sub", nlohmann::json::object()},
        {"issuer_account", akp->publicString()},
        {"type", "user"}, {"version", 2}};
    EXPECT_EQ(nats, expected);
    auto decoded = jwt::decodeUserClaims(token);
    EXPECT_EQ(decoded->name().value_or(""), ukp->publicString());  // Go defaults name to the user key
    EXPECT_EQ(decoded->issuer(), scopedSK->publicString());

    // parameter validation, as in Go
    EXPECT_THROW((void)jwt::issueUserJWT(scopedSK->seedString(), ukp->publicString(),
                                         ukp->publicString()),
                 jwt::InvalidClaimsError);
}

TEST(ScopedSigningKeysTest, ChainRejectsScopedUserWithOwnPermissions) {
    auto akp = nkeys::CreateAccount();
    auto scopedSK = nkeys::CreateAccount();
    jwt::AccountClaims ac(akp->publicString());
    jwt::UserScope scope;
    scope.key = scopedSK->publicString();
    scope.role = "limited";
    scope.permissions.pub.allow = {"demo.>"};
    ac.setScope(scope);
    auto okp = nkeys::CreateOperator();
    auto acc = jwt::decodeAccountClaims(ac.encode(okp->seedString()));

    // scoped-issued user with EMPTY permissions: chains fine
    auto ukp = nkeys::CreateUser();
    auto good = jwt::decodeUserClaims(jwt::issueUserJWT(
        scopedSK->seedString(), akp->publicString(), ukp->publicString()));
    EXPECT_TRUE(jwt::validateIssuerChain(*good, *acc).valid);

    // scoped-issued user smuggling its OWN permissions: the chain must fail
    // (Go: "scoped users require no permissions or limits set" — otherwise
    // the user could escalate past the scope template)
    jwt::UserClaims bad(ukp->publicString());
    bad.setIssuerAccount(akp->publicString());
    bad.permissions().pub.allow = {"secret.>"};
    auto badUser = jwt::decodeUserClaims(bad.encode(scopedSK->seedString()));
    EXPECT_FALSE(jwt::validateIssuerChain(*badUser, *acc).valid);
}

// ============================================================================
// Account configuration (fix-plan group 1) — typed account limits (JetStream
// fields FLAT inside "limits", tiered_limits nested), default_permissions,
// mappings, description/info_url. Wire facts measured from Go: bool omitempty
// means wildcards:false is ABSENT; weight 0 means 100; tiered and plain JS
// limits are mutually exclusive. Go does NOT block encoding of rule-violating
// mappings (its Validate is advisory) — we enforce at encode, documented.
// ============================================================================

namespace {
    void buildRichAccount(jwt::AccountClaims& ac) {
        ac.setName("rich-account");
        ac.setDescription("tenant with quotas");
        ac.setInfoURL("https://example.com/tenant");
        auto& l = ac.limits();
        l.subs = 500;
        l.data = 1LL << 30;
        l.payload = 65536;
        l.imports = 4;
        l.exports = 2;
        l.wildcardExports = false;
        l.disallowBearer = true;
        l.conn = 10;
        l.leafNodeConn = 2;
        l.jetStream = jwt::JetStreamLimits{1 << 20, 1LL << 30, 10, 100, 1000,
                                           1 << 19, 1LL << 29, true};
        ac.defaultPermissions().pub.allow = {"app.>"};
        ac.defaultPermissions().sub.deny = {"app.internal.>"};
        ac.mappings()["orders.v1.*"] = {{"orders.v2.*", 80, ""},
                                        {"orders.v1shadow.*", 20, ""}};
    }
}

TEST(AccountConfigTest, DecodesGoRichAccountIntoTypedFields) {
    auto ac = jwt::decodeAccountClaims(readFixture2("acc-rich.jwt"));
    const auto& l = ac->limits();
    EXPECT_EQ(l.subs, 500);
    EXPECT_EQ(l.data, 1LL << 30);
    EXPECT_EQ(l.payload, 65536);
    EXPECT_EQ(l.imports, 4);
    EXPECT_EQ(l.exports, 2);
    EXPECT_FALSE(l.wildcardExports);   // absent on the wire = false
    EXPECT_TRUE(l.disallowBearer);
    EXPECT_EQ(l.conn, 10);
    EXPECT_EQ(l.leafNodeConn, 2);
    EXPECT_EQ(l.jetStream.memStorage, 1 << 20);
    EXPECT_EQ(l.jetStream.diskStorage, 1LL << 30);
    EXPECT_EQ(l.jetStream.streams, 10);
    EXPECT_EQ(l.jetStream.consumer, 100);
    EXPECT_EQ(l.jetStream.maxAckPending, 1000);
    EXPECT_EQ(l.jetStream.memoryMaxStreamBytes, 1 << 19);
    EXPECT_EQ(l.jetStream.diskMaxStreamBytes, 1LL << 29);
    EXPECT_TRUE(l.jetStream.maxBytesRequired);
    EXPECT_TRUE(l.tieredLimits.empty());

    EXPECT_EQ(ac->defaultPermissions().pub.allow, (std::vector<std::string>{"app.>"}));
    EXPECT_EQ(ac->defaultPermissions().sub.deny,
              (std::vector<std::string>{"app.internal.>"}));

    ASSERT_EQ(ac->mappings().count("orders.v1.*"), 1u);
    const auto& wm = ac->mappings().at("orders.v1.*");
    ASSERT_EQ(wm.size(), 2u);
    EXPECT_EQ(wm[0].subject, "orders.v2.*");
    EXPECT_EQ(wm[0].weight, 80);
    EXPECT_EQ(wm[1].weight, 20);

    EXPECT_EQ(ac->description(), "tenant with quotas");
    EXPECT_EQ(ac->infoURL(), "https://example.com/tenant");
}

TEST(AccountConfigTest, RichAccountWireEqualsGo) {
    auto akp = nkeys::CreateAccount();
    jwt::AccountClaims ac(akp->publicString());
    buildRichAccount(ac);
    auto ours = natsObjectOf(ac.encode(akp->seedString()));
    auto golden = natsObjectOf(readFixture2("acc-rich.jwt"));
    EXPECT_EQ(ours, golden);
}

TEST(AccountConfigTest, TieredLimitsRoundTripGoGolden) {
    auto ac = jwt::decodeAccountClaims(readFixture2("acc-tiered.jwt"));
    ASSERT_EQ(ac->limits().tieredLimits.size(), 2u);
    EXPECT_EQ(ac->limits().tieredLimits.at("R1").memStorage, 1 << 20);
    EXPECT_EQ(ac->limits().tieredLimits.at("R3").consumer, 10);
    // re-encode: the whole nats object must survive equal (tiers included)
    auto okp = nkeys::CreateOperator();
    EXPECT_EQ(natsObjectOf(ac->encode(okp->seedString())),
              natsObjectOf(readFixture2("acc-tiered.jwt")));
}

TEST(AccountConfigTest, ValidationRulesMatchGo) {
    auto akp = nkeys::CreateAccount();

    // tiered and plain JetStream limits are mutually exclusive
    jwt::AccountClaims both(akp->publicString());
    both.limits().jetStream.memStorage = 1;
    both.limits().tieredLimits["R1"] = {};
    EXPECT_THROW((void)both.encode(akp->seedString()), jwt::InvalidClaimsError);

    // no blank tier name
    jwt::AccountClaims blank(akp->publicString());
    blank.limits().tieredLimits[""] = {};
    EXPECT_THROW((void)blank.encode(akp->seedString()), jwt::InvalidClaimsError);

    // a single mapping weight over 100
    jwt::AccountClaims heavy(akp->publicString());
    heavy.mappings()["a.*"] = {{"b.*", 120, ""}};
    EXPECT_THROW((void)heavy.encode(akp->seedString()), jwt::InvalidClaimsError);

    // weight 0 counts as 100 (Go's GetWeight): 0 + 20 = 120 in the default
    // cluster → over
    jwt::AccountClaims zeroHundred(akp->publicString());
    zeroHundred.mappings()["a.*"] = {{"b.*", 0, ""}, {"c.*", 20, ""}};
    EXPECT_THROW((void)zeroHundred.encode(akp->seedString()), jwt::InvalidClaimsError);

    // per-cluster sums are independent: 80 in "east" + 80 in "west" is fine
    jwt::AccountClaims clustered(akp->publicString());
    clustered.mappings()["a.*"] = {{"b.*", 80, "east"}, {"c.*", 80, "west"}};
    EXPECT_NO_THROW((void)clustered.encode(akp->seedString()));
}

// ============================================================================
// Revocation lists (fix-plan group 2) — Go semantics measured: Revoke keeps a
// NEWER existing entry (can't move a revocation into the future); IsRevoked
// compares against the claim's ISSUE time (ts >= iat — re-issuing after the
// revocation timestamp makes the key valid again); "*" revokes all keys.
// Wire: nats.revocations = {pubkey|"*": unix-ts}, omitempty.
// ============================================================================

TEST(RevocationTest, DecodesGoRevocations) {
    auto ac = jwt::decodeAccountClaims(readFixture2("acc-revoked.jwt"));
    const auto& revs = ac->revocations();
    ASSERT_EQ(revs.size(), 2u);
    ASSERT_EQ(revs.count(jwt::RevokeAll), 1u);
    EXPECT_EQ(revs.at(jwt::RevokeAll), 1600000000);
    for (const auto& [key, ts] : revs) {
        if (key != jwt::RevokeAll) {
            EXPECT_EQ(key[0], 'U');
            EXPECT_EQ(ts, 1700000000);
        }
    }
}

TEST(RevocationTest, RevocationWireEqualsGo) {
    // rebuild the golden's claims with the same keys → identical nats object
    auto golden = jwt::decodeAccountClaims(readFixture2("acc-revoked.jwt"));
    std::string userKey;
    for (const auto& [key, ts] : golden->revocations()) {
        if (key != jwt::RevokeAll) userKey = key;
    }
    jwt::AccountClaims ac(golden->subject());
    ac.setName("rev");
    ac.revokeAt(userKey, 1700000000);
    ac.revokeAt(jwt::RevokeAll, 1600000000);
    auto akp = nkeys::CreateAccount();
    EXPECT_EQ(natsObjectOf(ac.encode(akp->seedString())),
              natsObjectOf(readFixture2("acc-revoked.jwt")));

    // and decode→re-encode of the golden itself survives equal
    auto okp = nkeys::CreateOperator();
    EXPECT_EQ(natsObjectOf(golden->encode(okp->seedString())),
              natsObjectOf(readFixture2("acc-revoked.jwt")));
}

TEST(RevocationTest, SemanticsMatchGo) {
    auto akp = nkeys::CreateAccount();
    auto ukp = nkeys::CreateUser();
    jwt::AccountClaims ac(akp->publicString());
    const auto u = ukp->publicString();

    // revoke keeps the NEWER entry
    ac.revokeAt(u, 2000);
    ac.revokeAt(u, 1000);
    EXPECT_EQ(ac.revocations().at(u), 2000);
    ac.revokeAt(u, 3000);
    EXPECT_EQ(ac.revocations().at(u), 3000);

    // isRevoked: revocation ts >= claim ISSUE time
    EXPECT_TRUE(ac.isRevoked(u, 3000));   // issued at the revocation instant
    EXPECT_TRUE(ac.isRevoked(u, 2999));
    EXPECT_FALSE(ac.isRevoked(u, 3001));  // re-issued after → valid again

    // wildcard covers everyone issued at/before its timestamp
    auto other = nkeys::CreateUser()->publicString();
    EXPECT_FALSE(ac.isRevoked(other, 100));
    ac.revokeAt(jwt::RevokeAll, 500);
    EXPECT_TRUE(ac.isRevoked(other, 100));
    EXPECT_FALSE(ac.isRevoked(other, 501));

    ac.clearRevocation(u);
    EXPECT_EQ(ac.revocations().count(u), 0u);

    // no revocations key on the wire when empty
    jwt::AccountClaims clean(akp->publicString());
    EXPECT_FALSE(natsObjectOf(clean.encode(akp->seedString())).contains("revocations"));
}

// ============================================================================
// Imports / exports / activations (fix-plan group 3) — wire facts measured:
// export type is "stream"/"service"; response_threshold is NANOSECONDS;
// service_latency emits both fields (sampling 0 serializes as "headers");
// activation is a FOURTH claim type whose nats object is
// {subject: import subject, kind: stream|service, type:"activation"} and
// whose top-level sub is the TARGET account (or "public").
// ============================================================================

TEST(CrossAccountTest, DecodesGoExportsIntoTypedFields) {
    auto ac = jwt::decodeAccountClaims(readFixture2("acc-exports.jwt"));
    const auto& ex = ac->exports();
    ASSERT_EQ(ex.size(), 2u);

    EXPECT_EQ(ex[0].name, "billing");
    EXPECT_EQ(ex[0].subject, "billing.charge");
    EXPECT_EQ(ex[0].type, jwt::ExportType::Service);
    EXPECT_TRUE(ex[0].tokenReq);
    ASSERT_EQ(ex[0].revocations.size(), 1u);
    EXPECT_EQ(ex[0].revocations.begin()->second, 1700000000);
    EXPECT_EQ(ex[0].responseType, "Singleton");
    EXPECT_EQ(ex[0].responseThresholdNanos, 2000000000LL);
    ASSERT_TRUE(ex[0].latency.has_value());
    EXPECT_EQ(ex[0].latency->sampling, 40);
    EXPECT_EQ(ex[0].latency->results, "billing.latency");
    EXPECT_TRUE(ex[0].allowTrace);

    EXPECT_EQ(ex[1].type, jwt::ExportType::Stream);
    EXPECT_TRUE(ex[1].advertise);
}

TEST(CrossAccountTest, DecodesGoImportsIntoTypedFields) {
    auto ac = jwt::decodeAccountClaims(readFixture2("acc-imports.jwt"));
    const auto& im = ac->imports();
    ASSERT_EQ(im.size(), 2u);
    EXPECT_EQ(im[0].subject, "billing.charge");
    EXPECT_EQ(im[0].account[0], 'A');
    EXPECT_FALSE(im[0].token.empty());
    EXPECT_EQ(im[0].localSubject, "acme.billing.charge");
    EXPECT_EQ(im[0].type, jwt::ExportType::Service);
    EXPECT_TRUE(im[0].share);
    EXPECT_EQ(im[1].type, jwt::ExportType::Stream);
    EXPECT_TRUE(im[1].allowTrace);

    // the embedded token is a REAL activation claim
    auto act = jwt::decodeActivationClaims(im[0].token);
    EXPECT_EQ(act->importSubject(), "billing.charge");
    EXPECT_EQ(act->issuer(), im[0].account);
}

TEST(CrossAccountTest, ExporterAndImporterWireEqualGo) {
    // decode→re-encode of both goldens must leave the nats objects EQUAL
    auto okp = nkeys::CreateOperator();
    for (const char* fixture : {"acc-exports.jwt", "acc-imports.jwt"}) {
        auto ac = jwt::decodeAccountClaims(readFixture2(fixture));
        EXPECT_EQ(natsObjectOf(ac->encode(okp->seedString())),
                  natsObjectOf(readFixture2(fixture)))
            << fixture;
    }
}

TEST(CrossAccountTest, ActivationClaimsRoundTrip) {
    auto golden = readFixture2("activation.jwt");
    auto act = jwt::decodeActivationClaims(golden);
    EXPECT_EQ(act->name().value_or(""), "billing-grant");
    EXPECT_EQ(act->importSubject(), "billing.charge");
    EXPECT_EQ(act->importType(), jwt::ExportType::Service);
    EXPECT_EQ(act->subject()[0], 'A');  // the grantee account

    // generic decode dispatches on nats.type == "activation"
    auto generic = jwt::decode(golden);
    EXPECT_NE(dynamic_cast<jwt::ActivationClaims*>(generic.get()), nullptr);
    EXPECT_TRUE(jwt::verify(golden));

    // C++-built activation: same nats object as the golden's
    jwt::ActivationClaims mine(act->subject());
    mine.setName("billing-grant");
    mine.setImportSubject("billing.charge");
    mine.setImportType(jwt::ExportType::Service);
    auto akp = nkeys::CreateAccount();
    EXPECT_EQ(natsObjectOf(mine.encode(akp->seedString())), natsObjectOf(golden));

    // decorateJWT armors by the new type
    EXPECT_EQ(jwt::decorateJWT(golden).rfind("-----BEGIN NATS ACTIVATION JWT-----\n", 0), 0u);
}

TEST(CrossAccountTest, ValidationRulesMatchGo) {
    auto akp = nkeys::CreateAccount();
    auto bkp = nkeys::CreateAccount();

    // stream exports can't carry response types or latency
    jwt::AccountClaims s1(akp->publicString());
    jwt::Export e1;
    e1.name = "t"; e1.subject = "t.>"; e1.type = jwt::ExportType::Stream;
    e1.responseType = "Singleton";
    s1.exports().push_back(e1);
    EXPECT_THROW((void)s1.encode(akp->seedString()), jwt::InvalidClaimsError);

    jwt::AccountClaims s2(akp->publicString());
    jwt::Export e2;
    e2.name = "t"; e2.subject = "t.>"; e2.type = jwt::ExportType::Stream;
    e2.latency = jwt::ServiceLatency{40, "lat"};
    s2.exports().push_back(e2);
    EXPECT_THROW((void)s2.encode(akp->seedString()), jwt::InvalidClaimsError);

    // latency sampling outside 1..100 (0 = "headers" is legal)
    jwt::AccountClaims s3(akp->publicString());
    jwt::Export e3;
    e3.name = "b"; e3.subject = "b.x"; e3.type = jwt::ExportType::Service;
    e3.latency = jwt::ServiceLatency{150, "lat"};
    s3.exports().push_back(e3);
    EXPECT_THROW((void)s3.encode(akp->seedString()), jwt::InvalidClaimsError);

    // share is service-only; allow_trace is stream-only (imports)
    jwt::AccountClaims s4(bkp->publicString());
    jwt::Import i4;
    i4.name = "t"; i4.subject = "t.>"; i4.account = akp->publicString();
    i4.type = jwt::ExportType::Stream; i4.share = true;
    s4.imports().push_back(i4);
    EXPECT_THROW((void)s4.encode(bkp->seedString()), jwt::InvalidClaimsError);

    // an import token must come from the account it names
    auto other = nkeys::CreateAccount();
    jwt::ActivationClaims grant(bkp->publicString());
    grant.setImportSubject("b.x");
    grant.setImportType(jwt::ExportType::Service);
    auto token = grant.encode(other->seedString());  // issued by the WRONG account
    jwt::AccountClaims s5(bkp->publicString());
    jwt::Import i5;
    i5.name = "b"; i5.subject = "b.x"; i5.account = akp->publicString();
    i5.token = token; i5.type = jwt::ExportType::Service;
    s5.imports().push_back(i5);
    EXPECT_THROW((void)s5.encode(bkp->seedString()), jwt::InvalidClaimsError);
}

TEST(CrossAccountTest, HeadersSamplingRoundTrips) {
    // Go marshals SamplingRate 0 as the string "headers"
    auto akp = nkeys::CreateAccount();
    jwt::AccountClaims ac(akp->publicString());
    jwt::Export eh;
    eh.name = "b"; eh.subject = "b.x"; eh.type = jwt::ExportType::Service;
    eh.latency = jwt::ServiceLatency{0, "lat"};
    ac.exports().push_back(eh);
    auto nats = natsObjectOf(ac.encode(akp->seedString()));
    EXPECT_EQ(nats.at("exports")[0].at("service_latency").at("sampling"), "headers");
    auto rt = jwt::decodeAccountClaims(ac.encode(akp->seedString()));
    EXPECT_EQ(rt->exports()[0].latency->sampling, 0);
}

// ============================================================================
// Operator/resolver wiring (fix-plan group 4) — measured from Go:
// account_server_url needs any scheme; operator_service_urls allow only
// nats/tls/ws/wss, no credentials, no path; system_account must be an account
// key; assert_server_version is <major>.<minor>.<update>, non-negative ints;
// signing keys are validated as operator keys at encode.
// ============================================================================

TEST(OperatorWiringTest, DecodesGoRichOperatorIntoTypedFields) {
    auto oc = jwt::decodeOperatorClaims(readFixture2("op-rich.jwt"));
    EXPECT_EQ(oc->accountServerURL(), "https://resolver.example.com:9090/jwt/v1");
    EXPECT_EQ(oc->operatorServiceURLs(),
              (std::vector<std::string>{"nats://n1.example.com:4222",
                                        "tls://n2.example.com:4222"}));
    EXPECT_EQ(oc->systemAccount()[0], 'A');
    EXPECT_EQ(oc->assertServerVersion(), "2.10.0");
    EXPECT_TRUE(oc->strictSigningKeyUsage());
    EXPECT_EQ(oc->signingKeys().size(), 1u);
}

TEST(OperatorWiringTest, RichOperatorWireEqualsGo) {
    // rebuild the golden's claims with the same keys → identical nats object
    auto golden = jwt::decodeOperatorClaims(readFixture2("op-rich.jwt"));
    jwt::OperatorClaims oc(golden->subject());
    oc.setName("rich-op");
    oc.addSigningKey(golden->signingKeys()[0]);
    oc.setAccountServerURL(golden->accountServerURL());
    for (const auto& u : golden->operatorServiceURLs()) oc.operatorServiceURLs().push_back(u);
    oc.setSystemAccount(golden->systemAccount());
    oc.setAssertServerVersion("2.10.0");
    oc.setStrictSigningKeyUsage(true);
    auto okp = nkeys::CreateOperator();
    EXPECT_EQ(natsObjectOf(oc.encode(okp->seedString())),
              natsObjectOf(readFixture2("op-rich.jwt")));

    // decode→re-encode of the golden itself survives equal
    EXPECT_EQ(natsObjectOf(golden->encode(okp->seedString())),
              natsObjectOf(readFixture2("op-rich.jwt")));
}

TEST(OperatorWiringTest, ValidationRulesMatchGo) {
    auto okp = nkeys::CreateOperator();
    auto ukp = nkeys::CreateUser();

    // service URLs: scheme whitelist, no credentials, no path
    for (const std::string bad :
         {"http://h:4222", "nats://user:pass@h:4222", "nats://h:4222/path"}) {
        jwt::OperatorClaims oc(okp->publicString());
        oc.operatorServiceURLs().push_back(bad);
        EXPECT_THROW((void)oc.encode(okp->seedString()), jwt::InvalidClaimsError) << bad;
    }
    for (const std::string good :
         {"nats://h:4222", "tls://h:4222", "ws://h:80", "wss://h:443"}) {
        jwt::OperatorClaims oc(okp->publicString());
        oc.operatorServiceURLs().push_back(good);
        EXPECT_NO_THROW((void)oc.encode(okp->seedString())) << good;
    }

    // account server URL requires a scheme (any)
    jwt::OperatorClaims noScheme(okp->publicString());
    noScheme.setAccountServerURL("resolver.example.com/jwt");
    EXPECT_THROW((void)noScheme.encode(okp->seedString()), jwt::InvalidClaimsError);

    // system account must be an account key
    jwt::OperatorClaims badSys(okp->publicString());
    badSys.setSystemAccount(ukp->publicString());
    EXPECT_THROW((void)badSys.encode(okp->seedString()), jwt::InvalidClaimsError);

    // version must be three non-negative ints
    for (const std::string bad : {"2.10", "2.x.1", "-1.2.3"}) {
        jwt::OperatorClaims oc(okp->publicString());
        oc.setAssertServerVersion(bad);
        EXPECT_THROW((void)oc.encode(okp->seedString()), jwt::InvalidClaimsError) << bad;
    }

    // signing keys must be operator keys
    jwt::OperatorClaims badSk(okp->publicString());
    badSk.addSigningKey(ukp->publicString());
    EXPECT_THROW((void)badSk.encode(okp->seedString()), jwt::InvalidClaimsError);
}
