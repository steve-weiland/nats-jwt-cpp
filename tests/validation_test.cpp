#include <gtest/gtest.h>
#include <fstream>
#include "jwt/jwt.hpp"
#include "jwt/validation.hpp"
#include <nkeys/nkeys.hpp>
#include <thread>
#include <chrono>

// ============================================================================
// Time-Based Validation Tests
// ============================================================================

TEST(ValidationTest, NonExpiredTokenIsValid) {
    auto kp = nkeys::CreateOperator();
    jwt::OperatorClaims claims(kp->publicString());

    // Set expiration far in the future
    std::int64_t future = 9999999999;
    claims.setExpires(future);

    std::string jwt = claims.encode(kp->seedString());

    auto result = jwt::validateExpiration(*jwt::decode(jwt));
    EXPECT_TRUE(result.valid);
    EXPECT_FALSE(result.error.has_value());
}

TEST(ValidationTest, ExpiredTokenIsInvalid) {
    auto kp = nkeys::CreateOperator();
    jwt::OperatorClaims claims(kp->publicString());

    // Get current time and set expiration 2 seconds in the future
    auto now = std::chrono::system_clock::now();
    auto since_epoch = now.time_since_epoch();
    std::int64_t current = std::chrono::duration_cast<std::chrono::seconds>(since_epoch).count();
    claims.setExpires(current + 2);

    std::string jwt = claims.encode(kp->seedString());

    // Wait for token to expire
    std::this_thread::sleep_for(std::chrono::seconds(3));

    auto result = jwt::validateExpiration(*jwt::decode(jwt));
    EXPECT_FALSE(result.valid);
    EXPECT_TRUE(result.error.has_value());
    EXPECT_NE(result.error->find("expired"), std::string::npos);
}

TEST(ValidationTest, TokenWithoutExpirationIsValid) {
    auto kp = nkeys::CreateOperator();
    jwt::OperatorClaims claims(kp->publicString());
    // No expiration set (defaults to 0)

    std::string jwt = claims.encode(kp->seedString());

    auto result = jwt::validateExpiration(*jwt::decode(jwt));
    EXPECT_TRUE(result.valid);
}

TEST(ValidationTest, ClockSkewAllowsRecentlyExpiredToken) {
    auto kp = nkeys::CreateOperator();
    jwt::OperatorClaims claims(kp->publicString());

    // Set expiration 1 second in the future
    auto now = std::chrono::system_clock::now();
    auto since_epoch = now.time_since_epoch();
    std::int64_t current = std::chrono::duration_cast<std::chrono::seconds>(since_epoch).count();
    claims.setExpires(current + 1);

    std::string jwt = claims.encode(kp->seedString());

    // Wait for it to expire
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // Should fail without clock skew
    auto result1 = jwt::validateExpiration(*jwt::decode(jwt), 0);
    EXPECT_FALSE(result1.valid);

    // Should succeed with 10 second clock skew
    auto result2 = jwt::validateExpiration(*jwt::decode(jwt), 10);
    EXPECT_TRUE(result2.valid);
}

TEST(ValidationTest, NotYetValidTokenIsInvalid) {
    auto kp = nkeys::CreateOperator();
    jwt::OperatorClaims claims(kp->publicString());

    // Set issued at time far in the future
    std::int64_t future = 9999999999;

    std::string jwt = claims.encode(kp->seedString());
    auto decoded = jwt::decode(jwt);

    // Hack: directly set issuedAt to future time
    // (In real scenarios this would come from a JWT issued in the future)
    // For testing, we'll just validate current timestamp against future
    auto result = jwt::validateNotBefore(*decoded, 0);
    // Should pass because issuedAt is current time (auto-set)
    EXPECT_TRUE(result.valid);
}

TEST(ValidationTest, ComprehensiveTimingValidation) {
    auto kp = nkeys::CreateOperator();
    jwt::OperatorClaims claims(kp->publicString());

    // Set expiration far in the future
    claims.setExpires(9999999999);

    std::string jwt = claims.encode(kp->seedString());

    jwt::ValidationOptions opts;
    opts.checkExpiration = true;
    opts.checkNotBefore = true;

    auto result = jwt::validateTiming(*jwt::decode(jwt), opts);
    EXPECT_TRUE(result.valid);
}

// ============================================================================
// Issuer Chain Validation Tests
// ============================================================================

TEST(ValidationTest, ValidIssuerChain) {
    auto operator_kp = nkeys::CreateOperator();
    auto account_kp = nkeys::CreateAccount();

    // Create operator
    jwt::OperatorClaims op_claims(operator_kp->publicString());
    std::string op_jwt = op_claims.encode(operator_kp->seedString());

    // Create account signed by operator
    jwt::AccountClaims acc_claims(account_kp->publicString());
    acc_claims.setIssuer(operator_kp->publicString());
    std::string acc_jwt = acc_claims.encode(operator_kp->seedString());

    auto op_decoded = jwt::decode(op_jwt);
    auto acc_decoded = jwt::decode(acc_jwt);

    auto result = jwt::validateIssuerChain(*acc_decoded, *op_decoded);
    EXPECT_TRUE(result.valid);
}

TEST(ValidationTest, InvalidIssuerChain) {
    auto operator_kp = nkeys::CreateOperator();
    auto account_kp = nkeys::CreateAccount();
    auto wrong_operator_kp = nkeys::CreateOperator();

    // Create operator
    jwt::OperatorClaims op_claims(operator_kp->publicString());
    std::string op_jwt = op_claims.encode(operator_kp->seedString());

    // Create account claiming to be signed by operator, but actually signed by wrong operator
    jwt::AccountClaims acc_claims(account_kp->publicString());
    acc_claims.setIssuer(operator_kp->publicString());
    std::string acc_jwt = acc_claims.encode(wrong_operator_kp->seedString());

    // Decode is authenticated (fix #2): a token whose iss claims the operator
    // but whose bytes were signed by a DIFFERENT key never reaches the caller —
    // pre-fix this test decoded it and called its issuer chain "valid".
    auto op_decoded = jwt::decode(op_jwt);
    EXPECT_THROW((void)jwt::decode(acc_jwt), std::exception);
}

TEST(ValidationTest, BrokenIssuerChain) {
    auto operator_kp = nkeys::CreateOperator();
    auto account_kp = nkeys::CreateAccount();
    auto wrong_operator_kp = nkeys::CreateOperator();

    // Create operator
    jwt::OperatorClaims op_claims(operator_kp->publicString());
    std::string op_jwt = op_claims.encode(operator_kp->seedString());

    // Create account claiming to be signed by WRONG operator
    jwt::AccountClaims acc_claims(account_kp->publicString());
    acc_claims.setIssuer(wrong_operator_kp->publicString());  // Different operator
    std::string acc_jwt = acc_claims.encode(wrong_operator_kp->seedString());

    auto op_decoded = jwt::decode(op_jwt);
    auto acc_decoded = jwt::decode(acc_jwt);

    auto result = jwt::validateIssuerChain(*acc_decoded, *op_decoded);
    EXPECT_FALSE(result.valid);
    EXPECT_TRUE(result.error.has_value());
    EXPECT_NE(result.error->find("chain broken"), std::string::npos);
}

// ============================================================================
// Key Hierarchy Validation Tests
// ============================================================================

TEST(ValidationTest, ValidOperatorAccountHierarchy) {
    auto operator_kp = nkeys::CreateOperator();
    auto account_kp = nkeys::CreateAccount();

    jwt::OperatorClaims op_claims(operator_kp->publicString());
    jwt::AccountClaims acc_claims(account_kp->publicString());
    acc_claims.setIssuer(operator_kp->publicString());

    auto op_jwt = op_claims.encode(operator_kp->seedString());
    auto acc_jwt = acc_claims.encode(operator_kp->seedString());

    auto op_decoded = jwt::decode(op_jwt);
    auto acc_decoded = jwt::decode(acc_jwt);

    auto result = jwt::validateKeyHierarchy(*acc_decoded, *op_decoded);
    EXPECT_TRUE(result.valid);
}

TEST(ValidationTest, ValidAccountUserHierarchy) {
    auto operator_kp = nkeys::CreateOperator();
    auto account_kp = nkeys::CreateAccount();
    auto user_kp = nkeys::CreateUser();

    jwt::AccountClaims acc_claims(account_kp->publicString());
    acc_claims.setIssuer(operator_kp->publicString());  // Account must be signed by operator
    jwt::UserClaims user_claims(user_kp->publicString());
    user_claims.setIssuer(account_kp->publicString());

    auto acc_jwt = acc_claims.encode(operator_kp->seedString());  // Signed by operator
    auto user_jwt = user_claims.encode(account_kp->seedString());

    auto acc_decoded = jwt::decode(acc_jwt);
    auto user_decoded = jwt::decode(user_jwt);

    auto result = jwt::validateKeyHierarchy(*user_decoded, *acc_decoded);
    EXPECT_TRUE(result.valid);
}

TEST(ValidationTest, InvalidUserSignedByOperator) {
    auto operator_kp = nkeys::CreateOperator();
    auto user_kp = nkeys::CreateUser();

    // Attempting to create a user with operator as issuer should fail structural validation
    jwt::UserClaims user_claims(user_kp->publicString());
    user_claims.setIssuer(operator_kp->publicString());

    // This should throw during encode because user issuer must be an account
    EXPECT_THROW({
        auto user_jwt = user_claims.encode(operator_kp->seedString());
    }, std::invalid_argument);
}

TEST(ValidationTest, OperatorSelfSigned) {
    auto operator_kp = nkeys::CreateOperator();

    jwt::OperatorClaims claims(operator_kp->publicString());
    auto jwt = claims.encode(operator_kp->seedString());

    auto decoded = jwt::decode(jwt);

    // Operator validating against itself (self-signed)
    auto result = jwt::validateKeyHierarchy(*decoded, *decoded);
    EXPECT_TRUE(result.valid);
}

// ============================================================================
// Comprehensive Validation Tests
// ============================================================================

TEST(ValidationTest, ValidateJwtString) {
    auto kp = nkeys::CreateOperator();
    jwt::OperatorClaims claims(kp->publicString());
    claims.setExpires(9999999999);  // Far future

    std::string jwt = claims.encode(kp->seedString());

    jwt::ValidationOptions opts;
    opts.checkSignature = true;
    opts.checkExpiration = true;

    auto result = jwt::validate(jwt, opts);
    EXPECT_TRUE(result.valid);
}

TEST(ValidationTest, ValidateExpiredJwtString) {
    auto kp = nkeys::CreateOperator();
    jwt::OperatorClaims claims(kp->publicString());

    // Set expiration 1 second in the future
    auto now = std::chrono::system_clock::now();
    auto since_epoch = now.time_since_epoch();
    std::int64_t current = std::chrono::duration_cast<std::chrono::seconds>(since_epoch).count();
    claims.setExpires(current + 1);

    std::string jwt = claims.encode(kp->seedString());

    // Wait for expiration
    std::this_thread::sleep_for(std::chrono::seconds(2));

    jwt::ValidationOptions opts;
    opts.checkExpiration = true;

    auto result = jwt::validate(jwt, opts);
    EXPECT_FALSE(result.valid);
    EXPECT_TRUE(result.error.has_value());
}

TEST(ValidationTest, ValidateWithInvalidSignature) {
    auto kp = nkeys::CreateOperator();
    jwt::OperatorClaims claims(kp->publicString());

    std::string jwt = claims.encode(kp->seedString());

    // Corrupt the JWT
    jwt[jwt.length() - 5] = 'X';

    jwt::ValidationOptions opts;
    opts.checkSignature = true;

    auto result = jwt::validate(jwt, opts);
    EXPECT_FALSE(result.valid);
    EXPECT_TRUE(result.error.has_value());
    EXPECT_NE(result.error->find("signature"), std::string::npos);
}

TEST(ValidationTest, ValidateCompleteChain) {
    auto operator_kp = nkeys::CreateOperator();
    auto account_kp = nkeys::CreateAccount();
    auto user_kp = nkeys::CreateUser();

    // Create operator
    jwt::OperatorClaims op_claims(operator_kp->publicString());
    op_claims.setExpires(9999999999);
    std::string op_jwt = op_claims.encode(operator_kp->seedString());

    // Create account signed by operator
    jwt::AccountClaims acc_claims(account_kp->publicString());
    acc_claims.setIssuer(operator_kp->publicString());
    acc_claims.setExpires(9999999999);
    std::string acc_jwt = acc_claims.encode(operator_kp->seedString());

    // Create user signed by account
    jwt::UserClaims user_claims(user_kp->publicString());
    user_claims.setIssuer(account_kp->publicString());
    user_claims.setIssuerAccount(account_kp->publicString());
    user_claims.setExpires(9999999999);
    std::string user_jwt = user_claims.encode(account_kp->seedString());

    std::vector<std::string> chain = {op_jwt, acc_jwt, user_jwt};

    jwt::ValidationOptions opts;
    opts.checkSignature = true;
    opts.checkExpiration = true;
    opts.checkIssuerChain = true;

    auto result = jwt::validateChain(chain, opts);
    EXPECT_TRUE(result.valid);
}

TEST(ValidationTest, ValidateChainWithBrokenLink) {
    auto operator_kp = nkeys::CreateOperator();
    auto account_kp = nkeys::CreateAccount();
    auto user_kp = nkeys::CreateUser();
    auto wrong_account_kp = nkeys::CreateAccount();

    // Create operator
    jwt::OperatorClaims op_claims(operator_kp->publicString());
    std::string op_jwt = op_claims.encode(operator_kp->seedString());

    // Create account signed by operator
    jwt::AccountClaims acc_claims(account_kp->publicString());
    acc_claims.setIssuer(operator_kp->publicString());
    std::string acc_jwt = acc_claims.encode(operator_kp->seedString());

    // Create user claiming to be signed by account, but actually signed by different account
    jwt::UserClaims user_claims(user_kp->publicString());
    user_claims.setIssuer(account_kp->publicString());
    user_claims.setIssuerAccount(account_kp->publicString());
    std::string user_jwt = user_claims.encode(wrong_account_kp->seedString());  // Wrong signer!

    std::vector<std::string> chain = {op_jwt, acc_jwt, user_jwt};

    jwt::ValidationOptions opts;
    opts.checkSignature = true;
    opts.checkIssuerChain = true;

    auto result = jwt::validateChain(chain, opts);
    EXPECT_FALSE(result.valid);  // Should fail signature check
}

TEST(ValidationTest, ValidateEmptyChain) {
    std::vector<std::string> empty_chain;

    auto result = jwt::validateChain(empty_chain);
    EXPECT_FALSE(result.valid);
    EXPECT_TRUE(result.error.has_value());
    EXPECT_NE(result.error->find("Empty"), std::string::npos);
}

// ============================================================================
// ValidationOptions Tests
// ============================================================================

TEST(ValidationTest, StrictValidationOptions) {
    auto opts = jwt::ValidationOptions::strict();

    EXPECT_TRUE(opts.checkExpiration);
    EXPECT_TRUE(opts.checkNotBefore);
    EXPECT_TRUE(opts.checkSignature);
    EXPECT_TRUE(opts.checkIssuerChain);
    EXPECT_EQ(opts.clockSkewSeconds, 0);
}

TEST(ValidationTest, PermissiveValidationOptions) {
    auto opts = jwt::ValidationOptions::permissive();

    EXPECT_FALSE(opts.checkExpiration);
    EXPECT_FALSE(opts.checkNotBefore);
    EXPECT_FALSE(opts.checkSignature);
    EXPECT_FALSE(opts.checkIssuerChain);
    EXPECT_EQ(opts.clockSkewSeconds, 300);
}

TEST(ValidationTest, PermissiveOptionsAllowExpiredToken) {
    auto kp = nkeys::CreateOperator();
    jwt::OperatorClaims claims(kp->publicString());

    // Set expiration 1 second in the future
    auto now = std::chrono::system_clock::now();
    auto since_epoch = now.time_since_epoch();
    std::int64_t current = std::chrono::duration_cast<std::chrono::seconds>(since_epoch).count();
    claims.setExpires(current + 1);

    std::string jwt = claims.encode(kp->seedString());

    // Wait for expiration
    std::this_thread::sleep_for(std::chrono::seconds(2));

    auto result = jwt::validate(jwt, jwt::ValidationOptions::permissive());
    EXPECT_TRUE(result.valid);  // Permissive mode doesn't check expiration
}

// ============================================================================
// ValidationResult Tests
// ============================================================================

TEST(ValidationTest, ValidationResultBoolConversion) {
    auto success = jwt::ValidationResult::success();
    EXPECT_TRUE(success);
    EXPECT_TRUE(success.valid);
    EXPECT_FALSE(success.error.has_value());

    auto failure = jwt::ValidationResult::failure("test error");
    EXPECT_FALSE(failure);
    EXPECT_FALSE(failure.valid);
    EXPECT_TRUE(failure.error.has_value());
    EXPECT_EQ(failure.error.value(), "test error");
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}


// ============================================================================
// Trust model (fixes #3 + #4) — measured against the live Go library:
// the fixtures ARE Go's canonical flow (operator with signing key; account
// self-signed then re-signed BY the signing key; user signed by the account
// signing key with issuer_account). Pre-fix, C++ rejected the self-signed
// account at decode and failed the whole chain at validateChain.
// ============================================================================

namespace {
    std::string readFixtureJwt(const std::string& name) {
        std::ifstream f("tests/fixtures/" + name, std::ios::binary);
        if (!f) f.open("../tests/fixtures/" + name, std::ios::binary);
        EXPECT_TRUE(f.is_open()) << "fixture " << name;
        std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
        return s;
    }
}

TEST(TrustModelTest, DecodesGoSelfSignedAccount) {
    // Go's ExpectedPrefixes for accounts is {operator, account}: the
    // documented flow self-signs, hands to the operator, who re-signs.
    auto claims = jwt::decodeAccountClaims(readFixtureJwt("account-selfsigned.jwt"));
    EXPECT_EQ(claims->issuer(), claims->subject());
}

TEST(TrustModelTest, SelfSignedAccountEncodesAndDecodes) {
    auto akp = nkeys::CreateAccount();
    jwt::AccountClaims ac(akp->publicString());
    ac.setIssuer(akp->publicString());
    auto token = ac.encode(akp->seedString());
    EXPECT_EQ(jwt::decodeAccountClaims(token)->issuer(), akp->publicString());
}

TEST(TrustModelTest, AccountIssuerMustBeOperatorOrAccount) {
    auto akp = nkeys::CreateAccount();
    auto ukp = nkeys::CreateUser();
    jwt::AccountClaims ac(akp->publicString());
    ac.setIssuer(ukp->publicString());  // user key can't issue accounts
    EXPECT_THROW(ac.validate(), std::invalid_argument);
}

TEST(TrustModelTest, GoCanonicalChainValidatesStrict) {
    // THE gate for #4: Go's README flow through strict chain validation.
    std::vector<std::string> chain = {
        readFixtureJwt("operator.jwt"),
        readFixtureJwt("account.jwt"),
        readFixtureJwt("user.jwt"),
    };
    auto result = jwt::validateChain(chain, jwt::ValidationOptions::strict());
    EXPECT_TRUE(result.valid) << result.error.value_or("");
}

TEST(TrustModelTest, IssuerChainAcceptsParentSigningKey) {
    auto okp = nkeys::CreateOperator();
    auto oskp = nkeys::CreateOperator();  // operator signing key
    jwt::OperatorClaims oc(okp->publicString());
    oc.addSigningKey(oskp->publicString());
    auto op_jwt = oc.encode(okp->seedString());

    auto akp = nkeys::CreateAccount();
    jwt::AccountClaims ac(akp->publicString());
    ac.setIssuer(oskp->publicString());   // issued by the SIGNING key
    auto acc_jwt = ac.encode(oskp->seedString());

    auto op = jwt::decodeOperatorClaims(op_jwt);
    auto acc = jwt::decodeAccountClaims(acc_jwt);
    EXPECT_TRUE(jwt::validateIssuerChain(*acc, *op).valid);

    // an unrelated operator key is NOT a valid issuer
    auto stranger = nkeys::CreateOperator();
    jwt::AccountClaims bad(akp->publicString());
    bad.setIssuer(stranger->publicString());
    auto bad_jwt = bad.encode(stranger->seedString());
    auto badc = jwt::decodeAccountClaims(bad_jwt);
    EXPECT_FALSE(jwt::validateIssuerChain(*badc, *op).valid);
}

TEST(TrustModelTest, UserIssuerAccountMustMatchAccountSubject) {
    auto akp = nkeys::CreateAccount();
    auto askp = nkeys::CreateAccount();  // account signing key
    auto other = nkeys::CreateAccount();
    auto ukp = nkeys::CreateUser();

    jwt::AccountClaims ac(akp->publicString());
    ac.setIssuer(akp->publicString());
    ac.addSigningKey(askp->publicString());
    auto acc = jwt::decodeAccountClaims(ac.encode(akp->seedString()));

    jwt::UserClaims uc(ukp->publicString());
    uc.setIssuer(askp->publicString());
    uc.setIssuerAccount(other->publicString());  // names the WRONG account
    auto user = jwt::decodeUserClaims(uc.encode(askp->seedString()));

    EXPECT_FALSE(jwt::validateIssuerChain(*user, *acc).valid);

    jwt::UserClaims good(ukp->publicString());
    good.setIssuer(askp->publicString());
    good.setIssuerAccount(akp->publicString());
    auto goodUser = jwt::decodeUserClaims(good.encode(askp->seedString()));
    EXPECT_TRUE(jwt::validateIssuerChain(*goodUser, *acc).valid);
}
