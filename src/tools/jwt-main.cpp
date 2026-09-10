#include "jwt/jwt.hpp"
#include "jwt/operator_claims.hpp"
#include "jwt/account_claims.hpp"
#include "jwt/user_claims.hpp"
#include "cmd_args.hpp"
#include <nkeys/nkeys.hpp>
#include <nlohmann/json.hpp>
#include <iostream>
#include <fstream>
#include <sstream>

std::string readFile(const std::string& path) {
    std::ifstream file(path);
    if (!file) {
        throw std::runtime_error("Cannot open file: " + path);
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

void writeFile(const std::string& path, const std::string& content) {
    std::ofstream file(path);
    if (!file) {
        throw std::runtime_error("Cannot write to file: " + path);
    }
    file << content;
}

void printUsage() {
    std::cerr << R"(jwt++ - NATS JWT utility

Usage: jwt++ [command] [options]

Commands:
    --encode              Mint a JWT from --type/--inkey/--sign-key/--name
    --decode              Decode and display JWT
    --verify              Verify JWT signature
    --generate-creds      Generate user credentials file

Options:
    --version, -v         Show version
    --help, -h            Show this help
    --type <type>         Claim type: operator, account, user (for encode)
    --inkey <file>        Input seed/key file (subject for encode)
    --sign-key <file>     Signing seed file; the JWT's issuer is DERIVED from
                          it (defaults to --inkey: self-signed)
    --name <name>         Claim name (for encode)
    --issuer-account <k>  issuer_account for users issued by a signing key
    --out <file>          Output file (default: stdout)
    --compact             Compact JSON output (for decode)

Examples:
    # Encode operator JWT (self-signed)
    jwt++ --encode --type operator --inkey operator.seed

    # Encode account JWT (signed by operator; issuer derived from sign-key)
    jwt++ --encode --type account --inkey account.seed --sign-key operator.seed

    # Encode user JWT (signed by account)
    jwt++ --encode --type user --inkey user.seed --sign-key account.seed

    # Decode JWT
    jwt++ --decode operator.jwt

    # Verify JWT signature
    jwt++ --verify operator.jwt

    # Generate user credentials file
    jwt++ --generate-creds --inkey user.seed user.jwt
)";
}

void encodeCommand(const cmd_args& args) {
    if (!args.positional.empty() && args.positional[0] == "encode") {
        throw std::runtime_error("Positional JSON input not yet supported. Use stdin or specify fields.");
    }

    auto type_opt = args.get("type");
    if (!type_opt) {
        throw std::runtime_error("--type required (operator, account, or user)");
    }
    std::string type = *type_opt;

    auto seed_file_opt = args.get("inkey");
    if (!seed_file_opt) {
        throw std::runtime_error("--inkey <seed_file> required");
    }
    std::string seed_file = *seed_file_opt;

    std::string seed = readFile(seed_file);
    // Trim whitespace
    seed.erase(0, seed.find_first_not_of(" \n\r\t"));
    seed.erase(seed.find_last_not_of(" \n\r\t") + 1);

    // Check if a separate signing key is provided (for account/user JWTs)
    std::string signing_seed = seed;  // Default to same seed (self-signed)
    auto sign_key_opt = args.get("sign-key");
    if (sign_key_opt) {
        std::string sign_key_file = *sign_key_opt;
        signing_seed = readFile(sign_key_file);
        signing_seed.erase(0, signing_seed.find_first_not_of(" \n\r\t"));
        signing_seed.erase(signing_seed.find_last_not_of(" \n\r\t") + 1);
    }

    std::string jwt_string;

    if (type == "operator") {
        auto kp = nkeys::FromSeed(seed);
        jwt::OperatorClaims claims(kp->publicString());

        // Set optional fields if provided
        if (auto name = args.get("name")) {
            claims.setName(*name);
        }

        jwt_string = claims.encode(signing_seed);

    } else if (type == "account") {
        auto kp = nkeys::FromSeed(seed);
        jwt::AccountClaims claims(kp->publicString());

        // The issuer is derived from --sign-key (or --inkey when self-signed);
        // there is nothing to pass.
        if (auto name = args.get("name")) {
            claims.setName(*name);
        }

        jwt_string = claims.encode(signing_seed);

    } else if (type == "user") {
        auto kp = nkeys::FromSeed(seed);
        jwt::UserClaims claims(kp->publicString());

        if (auto name = args.get("name")) {
            claims.setName(*name);
        }

        if (auto issuer_acct = args.get("issuer-account")) {
            claims.setIssuerAccount(*issuer_acct);
        }

        jwt_string = claims.encode(signing_seed);

    } else {
        throw std::runtime_error("Invalid type: " + type + " (must be operator, account, or user)");
    }

    // Output
    auto out_opt = args.get("out");
    if (!out_opt) {
        std::cout << jwt_string << "\n";
    } else {
        writeFile(*out_opt, jwt_string + "\n");
        std::cerr << "JWT written to: " << *out_opt << "\n";
    }
}

void decodeCommand(const cmd_args& args) {
    std::string jwt_string;

    // Check if JWT file was provided as value to --decode option
    auto decode_value = args.get("decode");
    std::string jwt_file_or_string;

    if (decode_value && *decode_value != "true") {
        // --decode <file> syntax
        jwt_file_or_string = *decode_value;
    } else if (!args.positional.empty()) {
        // Positional argument syntax
        jwt_file_or_string = args.positional[0];
    } else {
        throw std::runtime_error("JWT string or file required");
    }

    // Try as filename first
    try {
        jwt_string = readFile(jwt_file_or_string);
        // Trim whitespace
        jwt_string.erase(0, jwt_string.find_first_not_of(" \n\r\t"));
        jwt_string.erase(jwt_string.find_last_not_of(" \n\r\t") + 1);
    } catch (...) {
        // Treat as JWT string directly
        jwt_string = jwt_file_or_string;
    }

    auto claims = jwt::decode(jwt_string);

    auto compact_opt = args.get("compact");
    bool compact = compact_opt && (*compact_opt == "true");
    int indent = compact ? -1 : 2;

    nlohmann::json output;
    output["subject"] = claims->subject();
    output["issuer"] = claims->issuer();

    if (claims->name()) {
        output["name"] = *claims->name();
    }

    output["issuedAt"] = claims->issuedAt();

    if (claims->expires() > 0) {
        output["expires"] = claims->expires();
    }

    std::cout << output.dump(indent) << "\n";
}

void verifyCommand(const cmd_args& args) {
    std::string jwt_string;

    // Check if JWT file was provided as value to --verify option
    auto verify_value = args.get("verify");
    std::string jwt_file_or_string;

    if (verify_value && *verify_value != "true") {
        // --verify <file> syntax
        jwt_file_or_string = *verify_value;
    } else if (!args.positional.empty()) {
        // Positional argument syntax
        jwt_file_or_string = args.positional[0];
    } else {
        throw std::runtime_error("JWT string or file required");
    }

    // Try as filename first
    try {
        jwt_string = readFile(jwt_file_or_string);
        jwt_string.erase(0, jwt_string.find_first_not_of(" \n\r\t"));
        jwt_string.erase(jwt_string.find_last_not_of(" \n\r\t") + 1);
    } catch (...) {
        jwt_string = jwt_file_or_string;
    }

    bool valid = jwt::verify(jwt_string);

    if (valid) {
        std::cout << "✓ Signature valid\n";
        return;
    } else {
        std::cerr << "✗ Signature invalid\n";
        exit(1);
    }
}

void generateCredsCommand(const cmd_args& args) {
    if (args.positional.empty()) {
        throw std::runtime_error("JWT file required as positional argument");
    }

    std::string jwt_file = args.positional[0];
    std::string jwt_string = readFile(jwt_file);
    jwt_string.erase(0, jwt_string.find_first_not_of(" \n\r\t"));
    jwt_string.erase(jwt_string.find_last_not_of(" \n\r\t") + 1);

    auto seed_file_opt = args.get("inkey");
    if (!seed_file_opt) {
        throw std::runtime_error("--inkey <user_seed_file> required");
    }
    std::string seed_file = *seed_file_opt;

    std::string seed = readFile(seed_file);
    seed.erase(0, seed.find_first_not_of(" \n\r\t"));
    seed.erase(seed.find_last_not_of(" \n\r\t") + 1);

    std::string creds = jwt::formatUserConfig(jwt_string, seed);

    auto out_opt = args.get("out");
    if (!out_opt) {
        std::cout << creds;
    } else {
        writeFile(*out_opt, creds);
        std::cerr << "Credentials written to: " << *out_opt << "\n";
    }
}

int main(int argc, char* argv[]) {
    try {
        auto args = cmd_args::parse(argc, argv);

        if (args.get("version").has_value() || args.get("v").has_value()) {
            std::cout << "jwt++ version " JWTPP_VERSION "\n";
            return 0;
        }

        if (args.get("help").has_value() || args.get("h").has_value() || argc == 1) {
            printUsage();
            return 0;
        }

        // Dispatch commands
        if (args.get("encode").has_value()) {
            encodeCommand(args);
        } else if (args.get("decode").has_value()) {
            decodeCommand(args);
        } else if (args.get("verify").has_value()) {
            verifyCommand(args);
        } else if (args.get("generate-creds").has_value()) {
            generateCredsCommand(args);
        } else {
            std::cerr << "No command specified. Use --help for usage.\n";
            return 1;
        }

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
