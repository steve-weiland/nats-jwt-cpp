#include <gtest/gtest.h>
#include "jwt/claims.hpp"
#include "jwt/validation.hpp"
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
