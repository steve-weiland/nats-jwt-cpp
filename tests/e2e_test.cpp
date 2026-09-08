#include <gtest/gtest.h>
#include "jwt/jwt.hpp"
#include <nkeys/nkeys.hpp>
#include <fstream>
#include <filesystem>
#include <chrono>
#include <thread>

namespace fs = std::filesystem;

// ============================================================================
// Test Fixture with Temporary Directory
// ============================================================================

class E2ETest : public ::testing::Test {
protected:
    fs::path temp_dir;

    void SetUp() override {
        // Create unique temporary directory
        temp_dir = fs::temp_directory_path() / ("jwt-e2e-test-" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()));
        fs::create_directories(temp_dir);
    }

    void TearDown() override {
        // Clean up temporary directory
        if (fs::exists(temp_dir)) {
            fs::remove_all(temp_dir);
        }
    }

    void writeFile(const fs::path& path, const std::string& content) {
        std::ofstream file(path);
        if (!file) {
            throw std::runtime_error("Failed to write file: " + path.string());
        }
        file << content;
    }

    std::string readFile(const fs::path& path) {
        std::ifstream file(path);
        if (!file) {
            throw std::runtime_error("Failed to read file: " + path.string());
        }
        std::stringstream buffer;
        buffer << file.rdbuf();
        return buffer.str();
    }
};

// ============================================================================
// Complete Trust Hierarchy Tests
// ============================================================================

TEST_F(E2ETest, CompleteTrustHierarchyCreation) {
    // Generate keys
    auto operator_kp = nkeys::CreateOperator();
    auto account_kp = nkeys::CreateAccount();
    auto user_kp = nkeys::CreateUser();

    // Save seeds to files
    writeFile(temp_dir / "operator.seed", operator_kp->seedString());
    writeFile(temp_dir / "account.seed", account_kp->seedString());
    writeFile(temp_dir / "user.seed", user_kp->seedString());

    // Create operator JWT (self-signed)
    jwt::OperatorClaims op_claims(operator_kp->publicString());
    op_claims.setName("E2E Test Operator");
    auto signing_key_pub = nkeys::CreateOperator()->publicString();
    op_claims.addSigningKey(signing_key_pub);
    std::string op_jwt = op_claims.encode(operator_kp->seedString());
    writeFile(temp_dir / "operator.jwt", op_jwt);

    // Verify operator JWT
    EXPECT_TRUE(jwt::verify(op_jwt));
    auto op_decoded = jwt::decodeOperatorClaims(op_jwt);
    EXPECT_EQ(op_decoded->name().value(), "E2E Test Operator");
    EXPECT_EQ(op_decoded->signingKeys().size(), 1);

    // Create account JWT (signed by operator)
    jwt::AccountClaims acc_claims(account_kp->publicString());
    acc_claims.setIssuer(operator_kp->publicString());
    acc_claims.setName("E2E Test Account");
    std::string acc_jwt = acc_claims.encode(operator_kp->seedString());
    writeFile(temp_dir / "account.jwt", acc_jwt);

    // Verify account JWT
    EXPECT_TRUE(jwt::verify(acc_jwt));
    auto acc_decoded = jwt::decodeAccountClaims(acc_jwt);
    EXPECT_EQ(acc_decoded->name().value(), "E2E Test Account");
    EXPECT_EQ(acc_decoded->issuer(), operator_kp->publicString());

    // Create user JWT (signed by account)
    jwt::UserClaims user_claims(user_kp->publicString());
    user_claims.setIssuer(account_kp->publicString());
    user_claims.setIssuerAccount(account_kp->publicString());
    user_claims.setName("E2E Test User");
    std::string user_jwt = user_claims.encode(account_kp->seedString());
    writeFile(temp_dir / "user.jwt", user_jwt);

    // Verify user JWT
    EXPECT_TRUE(jwt::verify(user_jwt));
    auto user_decoded = jwt::decodeUserClaims(user_jwt);
    EXPECT_EQ(user_decoded->name().value(), "E2E Test User");
    EXPECT_EQ(user_decoded->issuer(), account_kp->publicString());

    // Validate complete chain
    std::vector<std::string> chain = {op_jwt, acc_jwt, user_jwt};
    jwt::ValidationOptions opts = jwt::ValidationOptions::strict();
    auto chain_result = jwt::validateChain(chain, opts);
    EXPECT_TRUE(chain_result.valid) << "Chain validation failed: "
                                     << chain_result.error.value_or("unknown");
}

TEST_F(E2ETest, CredentialsFileWorkflow) {
    // Generate keys
    auto account_kp = nkeys::CreateAccount();
    auto user_kp = nkeys::CreateUser();

    // Create user JWT
    jwt::UserClaims user_claims(user_kp->publicString());
    user_claims.setIssuer(account_kp->publicString());
    user_claims.setIssuerAccount(account_kp->publicString());
    user_claims.setName("Creds Test User");
    std::string user_jwt = user_claims.encode(account_kp->seedString());

    // Generate credentials file
    std::string creds = jwt::formatUserConfig(user_jwt, user_kp->seedString());
    writeFile(temp_dir / "user.creds", creds);

    // Read credentials file
    std::string read_creds = readFile(temp_dir / "user.creds");
    EXPECT_EQ(creds, read_creds);

    // Verify credentials file structure
    EXPECT_NE(read_creds.find("-----BEGIN NATS USER JWT-----"), std::string::npos);
    EXPECT_NE(read_creds.find("------END NATS USER JWT------"), std::string::npos);
    EXPECT_NE(read_creds.find("-----BEGIN USER NKEY SEED-----"), std::string::npos);
    EXPECT_NE(read_creds.find("------END USER NKEY SEED------"), std::string::npos);
    EXPECT_NE(read_creds.find("IMPORTANT"), std::string::npos);

    // Extract JWT from creds file and verify
    size_t jwt_start = read_creds.find("-----BEGIN NATS USER JWT-----") + 29;
    size_t jwt_end = read_creds.find("------END NATS USER JWT------");
    std::string extracted_jwt = read_creds.substr(jwt_start, jwt_end - jwt_start);

    // Remove newlines
    extracted_jwt.erase(std::remove(extracted_jwt.begin(), extracted_jwt.end(), '\n'), extracted_jwt.end());
    extracted_jwt.erase(std::remove(extracted_jwt.begin(), extracted_jwt.end(), '\r'), extracted_jwt.end());

    EXPECT_TRUE(jwt::verify(extracted_jwt));
}

// ============================================================================
// Token Lifecycle Tests
// ============================================================================

TEST_F(E2ETest, TokenExpirationLifecycle) {
    auto kp = nkeys::CreateOperator();

    // Get current time
    auto now = std::chrono::system_clock::now();
    auto since_epoch = now.time_since_epoch();
    std::int64_t current = std::chrono::duration_cast<std::chrono::seconds>(since_epoch).count();

    // Create token expiring in 2 seconds
    jwt::OperatorClaims claims(kp->publicString());
    claims.setName("Short-lived Token");
    claims.setExpires(current + 2);
    std::string jwt_string = claims.encode(kp->seedString());

    // Token should be valid immediately
    jwt::ValidationOptions opts;
    opts.checkExpiration = true;
    auto result1 = jwt::validate(jwt_string, opts);
    EXPECT_TRUE(result1.valid);

    // Wait for expiration
    std::this_thread::sleep_for(std::chrono::seconds(3));

    // Token should be expired
    auto result2 = jwt::validate(jwt_string, opts);
    EXPECT_FALSE(result2.valid);
    EXPECT_TRUE(result2.error.has_value());
    EXPECT_NE(result2.error->find("expired"), std::string::npos);
}

TEST_F(E2ETest, TokenWithoutExpirationNeverExpires) {
    auto kp = nkeys::CreateOperator();

    // Create token without expiration
    jwt::OperatorClaims claims(kp->publicString());
    claims.setName("Eternal Token");
    // Don't set expiration
    std::string jwt_string = claims.encode(kp->seedString());

    // Validate with expiration check
    jwt::ValidationOptions opts;
    opts.checkExpiration = true;
    auto result = jwt::validate(jwt_string, opts);
    EXPECT_TRUE(result.valid);

    // Decode and verify no expiration
    auto decoded = jwt::decode(jwt_string);
    EXPECT_EQ(decoded->expires(), 0);
}

// ============================================================================
// Multi-Account Scenarios
// ============================================================================

TEST_F(E2ETest, OperatorWithMultipleAccounts) {
    auto operator_kp = nkeys::CreateOperator();

    // Create operator
    jwt::OperatorClaims op_claims(operator_kp->publicString());
    op_claims.setName("Multi-Account Operator");
    std::string op_jwt = op_claims.encode(operator_kp->seedString());

    // Create multiple accounts
    std::vector<std::string> account_jwts;
    for (int i = 0; i < 5; i++) {
        auto account_kp = nkeys::CreateAccount();
        jwt::AccountClaims acc_claims(account_kp->publicString());
        acc_claims.setIssuer(operator_kp->publicString());
        acc_claims.setName("Account-" + std::to_string(i));
        std::string acc_jwt = acc_claims.encode(operator_kp->seedString());

        // Verify each account
        EXPECT_TRUE(jwt::verify(acc_jwt));
        account_jwts.push_back(acc_jwt);

        // Save to file
        writeFile(temp_dir / ("account-" + std::to_string(i) + ".jwt"), acc_jwt);
    }

    // Verify all accounts are signed by the operator
    for (const auto& acc_jwt : account_jwts) {
        auto decoded = jwt::decodeAccountClaims(acc_jwt);
        EXPECT_EQ(decoded->issuer(), operator_kp->publicString());
    }

    // List all account files
    std::vector<fs::path> account_files;
    for (const auto& entry : fs::directory_iterator(temp_dir)) {
        if (entry.path().extension() == ".jwt" &&
            entry.path().filename().string().find("account-") == 0) {
            account_files.push_back(entry.path());
        }
    }
    EXPECT_EQ(account_files.size(), 5);
}

TEST_F(E2ETest, AccountWithMultipleUsers) {
    auto operator_kp = nkeys::CreateOperator();
    auto account_kp = nkeys::CreateAccount();

    // Create account
    jwt::AccountClaims acc_claims(account_kp->publicString());
    acc_claims.setIssuer(operator_kp->publicString());
    acc_claims.setName("Multi-User Account");
    std::string acc_jwt = acc_claims.encode(operator_kp->seedString());

    // Create multiple users
    std::vector<std::string> user_jwts;
    std::vector<std::string> user_seeds;

    for (int i = 0; i < 10; i++) {
        auto user_kp = nkeys::CreateUser();
        jwt::UserClaims user_claims(user_kp->publicString());
        user_claims.setIssuer(account_kp->publicString());
        user_claims.setIssuerAccount(account_kp->publicString());
        user_claims.setName("User-" + std::to_string(i));
        std::string user_jwt = user_claims.encode(account_kp->seedString());

        // Verify each user
        EXPECT_TRUE(jwt::verify(user_jwt));
        user_jwts.push_back(user_jwt);
        user_seeds.push_back(user_kp->seedString());

        // Create credentials file
        std::string creds = jwt::formatUserConfig(user_jwt, user_kp->seedString());
        writeFile(temp_dir / ("user-" + std::to_string(i) + ".creds"), creds);
    }

    // Verify all users are signed by the account
    for (const auto& user_jwt : user_jwts) {
        auto decoded = jwt::decodeUserClaims(user_jwt);
        EXPECT_EQ(decoded->issuer(), account_kp->publicString());
        EXPECT_EQ(decoded->issuerAccount().value(), account_kp->publicString());
    }

    // Count credentials files
    int creds_count = 0;
    for (const auto& entry : fs::directory_iterator(temp_dir)) {
        if (entry.path().extension() == ".creds") {
            creds_count++;
        }
    }
    EXPECT_EQ(creds_count, 10);
}

// ============================================================================
// Cross-Signing Scenarios
// ============================================================================

TEST_F(E2ETest, OperatorWithSigningKeys) {
    auto operator_kp = nkeys::CreateOperator();
    auto signing_key1_kp = nkeys::CreateOperator();
    auto signing_key2_kp = nkeys::CreateOperator();

    // Create operator with signing keys
    jwt::OperatorClaims op_claims(operator_kp->publicString());
    op_claims.setName("Operator with Signing Keys");
    op_claims.addSigningKey(signing_key1_kp->publicString());
    op_claims.addSigningKey(signing_key2_kp->publicString());
    std::string op_jwt = op_claims.encode(operator_kp->seedString());

    // Verify operator
    EXPECT_TRUE(jwt::verify(op_jwt));
    auto op_decoded = jwt::decodeOperatorClaims(op_jwt);
    EXPECT_EQ(op_decoded->signingKeys().size(), 2);

    // Create account signed by operator
    auto account_kp = nkeys::CreateAccount();
    jwt::AccountClaims acc_claims(account_kp->publicString());
    acc_claims.setIssuer(operator_kp->publicString());
    acc_claims.setName("Account signed by operator");
    std::string acc_jwt = acc_claims.encode(operator_kp->seedString());
    EXPECT_TRUE(jwt::verify(acc_jwt));

    // Create another account signed by signing key 1
    auto account2_kp = nkeys::CreateAccount();
    jwt::AccountClaims acc2_claims(account2_kp->publicString());
    acc2_claims.setIssuer(signing_key1_kp->publicString());
    acc2_claims.setName("Account signed by signing key");
    std::string acc2_jwt = acc2_claims.encode(signing_key1_kp->seedString());
    EXPECT_TRUE(jwt::verify(acc2_jwt));

    // Verify both accounts have different issuers but both valid
    auto acc1_decoded = jwt::decodeAccountClaims(acc_jwt);
    auto acc2_decoded = jwt::decodeAccountClaims(acc2_jwt);
    EXPECT_EQ(acc1_decoded->issuer(), operator_kp->publicString());
    EXPECT_EQ(acc2_decoded->issuer(), signing_key1_kp->publicString());
}

// ============================================================================
// Error Handling and Edge Cases
// ============================================================================

TEST_F(E2ETest, InvalidHierarchyRejected) {
    auto operator_kp = nkeys::CreateOperator();
    auto user_kp = nkeys::CreateUser();

    // Try to create user signed directly by operator (should fail)
    jwt::UserClaims user_claims(user_kp->publicString());
    user_claims.setIssuer(operator_kp->publicString());

    EXPECT_THROW({
        (void)user_claims.encode(operator_kp->seedString());
    }, std::invalid_argument);
}

TEST_F(E2ETest, BrokenChainDetected) {
    auto operator_kp = nkeys::CreateOperator();
    auto account_kp = nkeys::CreateAccount();
    auto wrong_account_kp = nkeys::CreateAccount();
    auto user_kp = nkeys::CreateUser();

    // Create valid operator
    jwt::OperatorClaims op_claims(operator_kp->publicString());
    std::string op_jwt = op_claims.encode(operator_kp->seedString());

    // Create valid account
    jwt::AccountClaims acc_claims(account_kp->publicString());
    acc_claims.setIssuer(operator_kp->publicString());
    std::string acc_jwt = acc_claims.encode(operator_kp->seedString());

    // Create user claiming to be signed by account, but with wrong issuer
    jwt::UserClaims user_claims(user_kp->publicString());
    user_claims.setIssuer(wrong_account_kp->publicString());  // Wrong account!
    std::string user_jwt = user_claims.encode(wrong_account_kp->seedString());

    // Individual JWTs verify (signatures are valid)
    EXPECT_TRUE(jwt::verify(op_jwt));
    EXPECT_TRUE(jwt::verify(acc_jwt));
    EXPECT_TRUE(jwt::verify(user_jwt));

    // But chain validation should fail
    std::vector<std::string> broken_chain = {op_jwt, acc_jwt, user_jwt};
    jwt::ValidationOptions opts;
    opts.checkIssuerChain = true;
    auto result = jwt::validateChain(broken_chain, opts);
    EXPECT_FALSE(result.valid);
    EXPECT_TRUE(result.error.has_value());
}

TEST_F(E2ETest, CorruptedJWTDetected) {
    auto kp = nkeys::CreateOperator();
    jwt::OperatorClaims claims(kp->publicString());
    std::string jwt_string = claims.encode(kp->seedString());

    // Original should verify
    EXPECT_TRUE(jwt::verify(jwt_string));

    // Save to file
    writeFile(temp_dir / "valid.jwt", jwt_string);

    // Corrupt JWT in middle of signature — swap to a guaranteed-different
    // char (a fixed = 'X' is a no-op 1 time in 64; same flake as
    // ValidationTest.ValidateWithInvalidSignature, fixed together)
    size_t second_dot = jwt_string.rfind('.');
    auto& sig_c = jwt_string[second_dot + 40];
    sig_c = (sig_c == 'X') ? 'Y' : 'X';
    writeFile(temp_dir / "corrupted.jwt", jwt_string);

    // Corrupted should not verify
    EXPECT_FALSE(jwt::verify(jwt_string));

    // Validation should fail
    jwt::ValidationOptions opts;
    opts.checkSignature = true;
    auto result = jwt::validate(jwt_string, opts);
    EXPECT_FALSE(result.valid);
}

// ============================================================================
// Real-World Simulation
// ============================================================================

TEST_F(E2ETest, CompleteNATSDeploymentSimulation) {
    // Simulate a complete NATS deployment:
    // 1 operator with 3 accounts, each account has 5 users

    auto operator_kp = nkeys::CreateOperator();

    // Create operator
    jwt::OperatorClaims op_claims(operator_kp->publicString());
    op_claims.setName("Production Operator");

    // Add signing keys for account management
    auto signing_key_kp = nkeys::CreateOperator();
    op_claims.addSigningKey(signing_key_kp->publicString());

    std::string op_jwt = op_claims.encode(operator_kp->seedString());
    writeFile(temp_dir / "operator.jwt", op_jwt);
    EXPECT_TRUE(jwt::verify(op_jwt));

    // Create 3 accounts
    std::vector<std::string> account_names = {"Dev", "Staging", "Production"};
    std::vector<std::unique_ptr<nkeys::KeyPair>> account_kps;
    std::vector<std::string> account_jwts;

    for (const auto& name : account_names) {
        auto acc_kp = nkeys::CreateAccount();
        jwt::AccountClaims acc_claims(acc_kp->publicString());
        acc_claims.setIssuer(operator_kp->publicString());
        acc_claims.setName(name + " Account");

        // Add account signing key
        auto acc_signing_kp = nkeys::CreateAccount();
        acc_claims.addSigningKey(acc_signing_kp->publicString());

        std::string acc_jwt = acc_claims.encode(operator_kp->seedString());
        writeFile(temp_dir / (name + "-account.jwt"), acc_jwt);
        EXPECT_TRUE(jwt::verify(acc_jwt));

        account_kps.push_back(std::move(acc_kp));
        account_jwts.push_back(acc_jwt);
    }

    // Create 5 users per account
    int total_users = 0;
    for (size_t i = 0; i < account_kps.size(); i++) {
        for (int j = 0; j < 5; j++) {
            auto user_kp = nkeys::CreateUser();
            jwt::UserClaims user_claims(user_kp->publicString());
            user_claims.setIssuer(account_kps[i]->publicString());
            user_claims.setIssuerAccount(account_kps[i]->publicString());
            user_claims.setName(account_names[i] + "-User-" + std::to_string(j));

            std::string user_jwt = user_claims.encode(account_kps[i]->seedString());
            EXPECT_TRUE(jwt::verify(user_jwt));

            // Create credentials file
            std::string creds = jwt::formatUserConfig(user_jwt, user_kp->seedString());
            writeFile(temp_dir / (account_names[i] + "-user-" + std::to_string(j) + ".creds"), creds);

            total_users++;
        }
    }

    EXPECT_EQ(total_users, 15);

    // Verify directory structure
    int jwt_count = 0;
    int creds_count = 0;
    for (const auto& entry : fs::directory_iterator(temp_dir)) {
        if (entry.path().extension() == ".jwt") jwt_count++;
        if (entry.path().extension() == ".creds") creds_count++;
    }

    EXPECT_EQ(jwt_count, 4);   // 1 operator + 3 accounts
    EXPECT_EQ(creds_count, 15); // 15 users

    // Validate a complete chain (operator -> account -> user)
    auto user_kp = nkeys::CreateUser();
    jwt::UserClaims final_user(user_kp->publicString());
    final_user.setIssuer(account_kps[0]->publicString());
    final_user.setIssuerAccount(account_kps[0]->publicString());
    final_user.setName("Final Test User");
    std::string final_user_jwt = final_user.encode(account_kps[0]->seedString());

    std::vector<std::string> complete_chain = {op_jwt, account_jwts[0], final_user_jwt};
    jwt::ValidationOptions chain_opts = jwt::ValidationOptions::strict();
    auto chain_result = jwt::validateChain(complete_chain, chain_opts);
    EXPECT_TRUE(chain_result.valid) << "Chain validation failed: "
                                     << chain_result.error.value_or("unknown");
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
