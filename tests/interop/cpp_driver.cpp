// cpp_driver — the C++ half of the live interop matrix (see run.sh).
// modes:
//   decode <type> <file>      authenticated decode; prints CPP-DECODE-OK + sub
//   verify <file>             signature check via the embedded issuer
//   chain <op> <acc> <user>   strict() chain validation
//   encode <dir>              writes op/acc/user.jwt + u.creds (direct issuance)
//   encode-signer <dir>       the same files minted through encodeWithSigner —
//                             an external-signer callback holds the keys
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
#include <chrono>
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
        // the system account ($SYS): designated in the OPERATOR claims — the
        // e2e proves the server honors the C++-minted system_account field
        auto syskp = nkeys::CreateAccount();
        jwt::AccountClaims sysc(syskp->publicString());
        sysc.setName("SYS");

        jwt::OperatorClaims oc(okp->publicString());
        oc.setName("O");
        oc.addSigningKey(oskp->publicString());
        oc.setSystemAccount(syskp->publicString());
        std::string opJwt = oc.encode(okp->seedString());
        std::string sysAccJwt = sysc.encode(oskp->seedString());
        auto sysukp = nkeys::CreateUser();
        jwt::UserClaims sysuc(sysukp->publicString());
        std::string sysUserJwt = sysuc.encode(syskp->seedString());
        std::string sysCreds = jwt::formatUserConfig(sysUserJwt, sysukp->seedString());

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

        // a WEBSOCKET-ONLY user: allowed_connection_types gates the transport —
        // the e2e proves the server refuses it on a plain TCP connection
        auto wkp = nkeys::CreateUser();
        jwt::UserClaims wc(wkp->publicString());
        wc.setName("ws-only");
        wc.setIssuerAccount(akp->publicString());
        wc.allowedConnectionTypes() = {jwt::ConnectionType::Websocket};
        std::string wsOnlyJwt = wc.encode(askp->seedString());
        std::string wsOnlyCreds = jwt::formatUserConfig(wsOnlyJwt, wkp->seedString());

        // a SCOPED signing key on the account: its template (pub demo.> only)
        // governs users it issues — the scoped user's own JWT carries NO
        // permissions (issueUserJWT), the server applies the template
        auto scopedSK = nkeys::CreateAccount();
        jwt::UserScope scope;
        scope.key = scopedSK->publicString();
        scope.role = "demo-only";
        scope.permissions.pub.allow = {"demo.>"};
        scope.permissions.sub.allow = {"_INBOX.>"};
        received->setScope(scope);
        accJwt = received->encode(oskp->seedString());  // re-sign WITH the scope
        auto skp = nkeys::CreateUser();
        std::string scopedUserJwt = jwt::issueUserJWT(
            scopedSK->seedString(), akp->publicString(), skp->publicString(), "scoped");
        std::string scopedCreds = jwt::formatUserConfig(scopedUserJwt, skp->seedString());

        // a second, LIMITED account: conn=1 — the e2e proves the server
        // enforces C++-minted ACCOUNT limits (one connection lives, the
        // second dies with the very error that exposed the defaults bug)
        auto lkp = nkeys::CreateAccount();
        jwt::AccountClaims lc(lkp->publicString());
        lc.setName("L");
        lc.limits().conn = 1;
        std::string limitedAccJwt = lc.encode(oskp->seedString());
        auto lukp = nkeys::CreateUser();
        jwt::UserClaims luc(lukp->publicString());
        std::string limitedUserJwt = luc.encode(lkp->seedString());
        std::string limitedCreds = jwt::formatUserConfig(limitedUserJwt, lukp->seedString());

        // a cross-account PRIVATE export: account X exports billing.charge as
        // a token_req service; the main account imports it under
        // ext.billing.charge carrying X's activation grant — the e2e proves a
        // request crosses accounts through the C++-minted import chain
        auto xkp = nkeys::CreateAccount();
        jwt::AccountClaims xc(xkp->publicString());
        xc.setName("X");
        jwt::Export billing;
        billing.name = "billing";
        billing.subject = "billing.charge";
        billing.type = jwt::ExportType::Service;
        billing.tokenReq = true;
        xc.exports().push_back(billing);
        std::string exporterJwt = xc.encode(oskp->seedString());
        auto xukp = nkeys::CreateUser();
        jwt::UserClaims xuc(xukp->publicString());
        std::string exporterUserJwt = xuc.encode(xkp->seedString());
        std::string exporterCreds = jwt::formatUserConfig(exporterUserJwt, xukp->seedString());

        jwt::ActivationClaims grant(akp->publicString());  // grant to the main account
        grant.setName("billing-grant");
        grant.setImportSubject("billing.charge");
        grant.setImportType(jwt::ExportType::Service);
        std::string grantJwt = grant.encode(xkp->seedString());
        jwt::Import billingImport;
        billingImport.name = "billing";
        billingImport.subject = "billing.charge";
        billingImport.account = xkp->publicString();
        billingImport.token = grantJwt;
        billingImport.localSubject = "ext.billing.charge";
        billingImport.type = jwt::ExportType::Service;
        received->imports().push_back(billingImport);
        accJwt = received->encode(oskp->seedString());  // re-sign WITH the import

        // a REVOKED variant of the main account: the restricted user is
        // revoked as of now — the e2e boots a second server with this
        // resolver and proves the server refuses the revoked creds
        received->revokeAt(rkp->publicString(),
                           std::chrono::duration_cast<std::chrono::seconds>(
                               std::chrono::system_clock::now().time_since_epoch())
                                   .count() +
                               5);
        std::string revokedAccJwt = received->encode(oskp->seedString());
        received->clearRevocation(rkp->publicString());  // main conf stays clean

        // memory-resolver config, the Go README's resolver.conf
        std::string resolver = "operator: " + opJwt + "\n\n" +
                               "resolver: MEMORY\n" +
                               "resolver_preload: {\n" +
                               "\t" + akp->publicString() + ": " + accJwt + "\n" +
                               "\t" + lkp->publicString() + ": " + limitedAccJwt + "\n" +
                               "\t" + xkp->publicString() + ": " + exporterJwt + "\n" +
                               "\t" + syskp->publicString() + ": " + sysAccJwt + "\n" +
                               "}\n";

        std::string revokedResolver = "operator: " + opJwt + "\n\n" +
                                      "resolver: MEMORY\n" +
                                      "resolver_preload: {\n" +
                                      "\t" + akp->publicString() + ": " + revokedAccJwt + "\n" +
                                      "\t" + syskp->publicString() + ": " + sysAccJwt + "\n" +
                                      "}\n";

        for (auto& [n, c] : std::vector<std::pair<std::string, std::string>>{
                 {"op.jwt", opJwt}, {"acc.jwt", accJwt}, {"user.jwt", userJwt},
                 {"u.creds", creds}, {"r.creds", restrictedCreds},
                 {"s.creds", scopedCreds}, {"l.creds", limitedCreds},
                 {"x.creds", exporterCreds}, {"sys.creds", sysCreds},
                 {"w.creds", wsOnlyCreds},
                 {"resolver.conf", resolver},
                 {"resolver-revoked.conf", revokedResolver}})
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
        uc.setBearerToken(true);
        uc.setProxyRequired(true);
        uc.allowedConnectionTypes() = {jwt::ConnectionType::Websocket, jwt::ConnectionType::Mqtt};
        std::ofstream(dir + "/rich-user.jwt") << uc.encode(akp->seedString());
        std::cout << "OK\n";
    } else if (mode == "encode" || mode == "encode-signer") {
        // dir → write op/acc/user jwts + creds, README-style (direct issuance);
        // encode-signer mints the same through encodeWithSigner, the keys held
        // by a callback standing in for an HSM
        std::string dir = argv[2];
        const bool viaSigner = mode == "encode-signer";
        auto mint = [&](const jwt::Claims& c, const nkeys::KeyPair& kp) {
            if (!viaSigner) return c.encode(kp.seedString());
            return c.encodeWithSigner(kp.publicString(),
                [&kp](std::string_view, std::span<const std::uint8_t> d) { return kp.sign(d); });
        };
        auto okp = nkeys::CreateOperator();
        jwt::OperatorClaims oc(okp->publicString());
        oc.setName("O");
        std::string opJwt = mint(oc, *okp);
        auto akp = nkeys::CreateAccount();
        jwt::AccountClaims ac(akp->publicString());
        ac.setName("A");
        std::string accJwt = mint(ac, *okp);
        auto ukp = nkeys::CreateUser();
        jwt::UserClaims u(ukp->publicString());
        std::string userJwt = mint(u, *akp);
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
