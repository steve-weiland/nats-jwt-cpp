// cpp_driver — the C++ half of the live interop matrix (see run.sh).
// modes:
//   decode <type> <file>      authenticated decode; prints CPP-DECODE-OK + sub
//   verify <file>             signature check via the embedded issuer
//   chain <op> <acc> <user>   strict() chain validation
//   encode <dir>              writes op/acc/user.jwt + u.creds (direct issuance)
//   richuser <dir>            user token exercising the full typed
//                             permissions/limits surface (fix-plan #1+#2)
//   bootstrap <dir>           the Go README flow, verbatim: operator with a
//                             signing key; account self-signed, then decoded
//                             and re-signed BY the operator signing key; user
//                             issued by an account signing key with
//                             issuer_account; u.creds; and resolver.conf for
//                             a memory-resolver nats-server
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

int main([[maybe_unused]] int argc, char** argv) try {
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
    } else if (mode == "bootstrap") {
        std::string dir = argv[2];

        // operator, plus a signing key that will issue accounts
        auto okp = nkeys::CreateOperator();
        auto oskp = nkeys::CreateOperator();
        jwt::OperatorClaims oc(okp->publicString());
        oc.setName("O");
        oc.addSigningKey(oskp->publicString());
        std::string opJwt = oc.encode(okp->seedString());

        // account: self-sign first (the README flow), hand to the operator,
        // who decodes and re-signs with the SIGNING key
        auto akp = nkeys::CreateAccount();
        auto askp = nkeys::CreateAccount();
        jwt::AccountClaims ac(akp->publicString());
        ac.setName("A");
        ac.addSigningKey(askp->publicString());
        std::string selfSigned = ac.encode(akp->seedString());
        auto received = jwt::decodeAccountClaims(selfSigned);
        std::string accJwt = received->encode(oskp->seedString());

        // user: issued by the account SIGNING key; issuer_account names the
        // account so the server knows where to look
        auto ukp = nkeys::CreateUser();
        jwt::UserClaims uc(ukp->publicString());
        uc.setIssuerAccount(akp->publicString());
        std::string userJwt = uc.encode(askp->seedString());
        std::string creds = jwt::formatUserConfig(userJwt, ukp->seedString());

        // a second, PERMISSION-RESTRICTED user: may only publish under
        // demo.> (plus subscribe to inbox replies) — the e2e gate proves the
        // server enforces these C++-minted permissions
        auto rkp = nkeys::CreateUser();
        jwt::UserClaims rc(rkp->publicString());
        rc.setName("restricted");
        rc.setIssuerAccount(akp->publicString());
        rc.permissions().pub.allow = {"demo.>"};
        rc.permissions().sub.allow = {"_INBOX.>"};
        std::string restrictedJwt = rc.encode(askp->seedString());
        std::string restrictedCreds = jwt::formatUserConfig(restrictedJwt, rkp->seedString());

        // memory-resolver config, the Go README's resolver.conf
        std::string resolver = "operator: " + opJwt + "\n\n" +
                               "resolver: MEMORY\n" +
                               "resolver_preload: {\n" +
                               "\t" + akp->publicString() + ": " + accJwt + "\n" +
                               "}\n";

        for (auto& [n, c] : std::vector<std::pair<std::string, std::string>>{
                 {"op.jwt", opJwt}, {"acc.jwt", accJwt}, {"user.jwt", userJwt},
                 {"u.creds", creds}, {"r.creds", restrictedCreds},
                 {"resolver.conf", resolver}})
            std::ofstream(dir + "/" + n) << c;
        std::cout << "OK\n";
    } else if (mode == "richuser") { // dir → user token with full perms/limits
        std::string dir = argv[2];
        auto akp = nkeys::CreateAccount();
        auto ukp = nkeys::CreateUser();
        jwt::UserClaims uc(ukp->publicString());
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
        std::ofstream(dir + "/rich-user.jwt") << uc.encode(akp->seedString());
        std::cout << "OK\n";
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
