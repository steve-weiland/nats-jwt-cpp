// cpp_driver — the C++ half of the live interop matrix (see run.sh).
// modes:
//   decode <type> <file>      authenticated decode; prints CPP-DECODE-OK + sub
//   verify <file>             signature check via the embedded issuer
//   chain <op> <acc> <user>   strict() chain validation
//   encode <dir>              writes op/acc/user.jwt + u.creds (direct issuance)
#include <jwt/jwt.hpp>
#include <nkeys/nkeys.hpp>
#include <fstream>
#include <iostream>
#include <sstream>

static std::string slurp(const char* p) {
    std::ifstream f(p);
    std::stringstream ss; ss << f.rdbuf();
    auto s = ss.str();
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
    return s;
}

int main(int argc, char** argv) try {
    std::string mode = argv[1];
    if (mode == "decode") {
        std::string type = argv[2], tok = slurp(argv[3]);
        if (type == "operator") { auto c = jwt::decodeOperatorClaims(tok); std::cout << "CPP-DECODE-OK sub=" << c->subject() << "\n"; }
        else if (type == "account") { auto c = jwt::decodeAccountClaims(tok); std::cout << "CPP-DECODE-OK sub=" << c->subject() << "\n"; }
        else { auto c = jwt::decodeUserClaims(tok); std::cout << "CPP-DECODE-OK sub=" << c->subject() << "\n"; }
    } else if (mode == "verify") {
        std::cout << (jwt::verify(slurp(argv[2])) ? "CPP-VERIFY-OK" : "CPP-VERIFY-FAIL") << "\n";
    } else if (mode == "chain") {
        std::vector<std::string> chain = {slurp(argv[2]), slurp(argv[3]), slurp(argv[4])};
        auto r = jwt::validateChain(chain, jwt::ValidationOptions::strict());
        std::cout << (r.valid ? "CPP-CHAIN-OK" : "CPP-CHAIN-FAIL: " + r.error.value_or("")) << "\n";
    } else if (mode == "encode") { // dir → write op/acc/user jwts + creds, README-style (direct issuance)
        std::string dir = argv[2];
        auto okp = nkeys::CreateOperator();
        jwt::OperatorClaims oc(okp->publicString());
        oc.setName("O");
        std::string opJwt = oc.encode(okp->seedString());
        auto akp = nkeys::CreateAccount();
        jwt::AccountClaims ac(akp->publicString());
        ac.setName("A");
        std::string accJwt = ac.encode(okp->seedString());
        auto ukp = nkeys::CreateUser();
        jwt::UserClaims u(ukp->publicString());
        std::string userJwt = u.encode(akp->seedString());
        std::string creds = jwt::formatUserConfig(userJwt, ukp->seedString());
        for (auto& [n, c] : std::vector<std::pair<std::string,std::string>>{
                {"op.jwt", opJwt}, {"acc.jwt", accJwt}, {"user.jwt", userJwt}, {"u.creds", creds}})
            std::ofstream(dir + "/" + n) << c;
        std::cout << "OK\n";
    }
    return 0;
} catch (const std::exception& e) {
    std::cerr << "ERR: " << e.what() << "\n";
    return 1;
}
