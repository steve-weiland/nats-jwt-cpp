// cpp_driver — the C++ half of the live interop matrix (see run.sh).
// modes:
//   decode <type> <file>      authenticated decode; prints CPP-DECODE-OK + sub
//   verify <file>             signature check via the embedded issuer
//   validate <file>           authenticated decode (structure only), then the
//                             accumulated report: one sorted
//                             "blocking|timecheck|description" line per issue
//   chain <op> <acc> <user>   strict() chain validation
//   encode <dir>              writes op/acc/user.jwt + u.creds (direct issuance)
//   encode-signer <dir>       the same files minted through encodeWithSigner —
//                             an external-signer callback holds the keys
//   hashid <activation.jwt>   Go's HashID() of an activation (SHA-256, padded base32)
//   xkeys <dir>               writes a fresh curve pair: service-x.pub / service-x.seed
//   openreq <body> <serverXpub> <seedfile>   open + decode a sealed request; prints sub=
//   sealresp <dir> <serverXpub> <seedfile> <userpub> <serverpub>
//                             mint an error response and seal it → sealed-resp.bin
//   migrate <type> <in> <out> <seed>   decode (v1 or v2) and re-encode as v2 with seed
//   mintgeneric <dir>         a custom-type GenericClaims token
//   genfields <dir>           operator/account/user/activation carrying
//                             aud + nbf + tags (added Go-TagList-style)
//   genauth <dir>             auth-callout artifacts: account with
//                             authorization config, a server-signed request,
//                             responses (jwt via signing key / error)
//   authcallout <dir>         one callout decision from $NATS_REQUEST_BODY
//                             (kept for the plaintext relay path); prints ONLY
//                             the response JWT
//   callout-serve <url> <dir> <profile> [wrong-xkey]
//                             the e2e's callout SERVICE as a real NATS client
//                             (nats_min_client.hpp): profile "c" = plaintext
//                             account C, "cx" = account CX with an xkey —
//                             sealed requests are opened with service-x.seed,
//                             responses sealed back; "wrong-xkey" uses a fresh
//                             curve seed (negative control: nothing opens)
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
#include "nats_min_client.hpp"
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>

static std::vector<std::uint8_t> slurpBytes(const char* p) {
    std::ifstream f(p, std::ios::binary);
    return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

static std::string slurp(const char* p) {
    std::ifstream f(p);
    std::stringstream ss; ss << f.rdbuf();
    auto s = ss.str();
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
    return s;
}

// The callout DECISION (shared by the relay mode and the real client):
// admit sentinel "alice"/"alicex" into account A, refuse everyone else.
static std::string calloutDecision(const jwt::AuthorizationRequestClaims& rq, const std::string& dir,
                                   const std::string& accPubFile, const std::string& accSkFile,
                                   const std::string& admitName) {
    const std::string cPub = slurp((dir + "/" + accPubFile).c_str());
    const std::string aPub = slurp((dir + "/a.pub").c_str());
    auto cskp = nkeys::FromSeed(slurp((dir + "/" + accSkFile).c_str()));
    auto askp = nkeys::FromSeed(slurp((dir + "/a-sk.seed").c_str()));
    jwt::AuthorizationResponseClaims rs(rq.userNkey());
    rs.setAudience(rq.server().id);
    rs.setIssuerAccount(cPub);  // signed by the callout account's SIGNING key
    if (rq.audience() != jwt::AuthRequestAudience || rq.subject() != cPub) {
        rs.setError("request not addressed to this callout");
    } else if (rq.connectOptions().jwt.empty()) {
        rs.setError("no sentinel credential");
    } else {
        auto sentinel = jwt::decodeUserClaims(rq.connectOptions().jwt);  // authenticated
        const std::string who = sentinel->name().value_or("");
        if (sentinel->issuer() != cPub || who != admitName) {
            rs.setError("sentinel \"" + who + "\" is not authorized");
        } else {
            jwt::UserClaims uc(rq.userNkey());
            uc.setName(who);
            uc.setIssuerAccount(aPub);
            uc.permissions().pub.allow = {"demo.>"};
            uc.permissions().sub.allow = {"_INBOX.>"};
            uc.setExpires(rq.expires() + 3600);
            rs.setJwt(uc.encode(askp->seedString()));
        }
    }
    return rs.encode(cskp->seedString());
}

int main(int argc, char** argv) try {
    if (argc < 2) { std::cerr << "usage: cpp_driver <mode> [args]\n"; return 2; }
    std::string mode = argv[1];
    if (mode == "decode") {
        std::string type = argv[2], tok = slurp(argv[3]);
        if (type == "operator") { auto c = jwt::decodeOperatorClaims(tok); std::cout << "CPP-DECODE-OK sub=" << c->subject() << "\n"; }
        else if (type == "account") { auto c = jwt::decodeAccountClaims(tok); std::cout << "CPP-DECODE-OK sub=" << c->subject() << "\n"; }
        else if (type == "activation") { auto c = jwt::decodeActivationClaims(tok); std::cout << "CPP-DECODE-OK sub=" << c->subject() << "\n"; }
        else if (type == "authorization_request") { auto c = jwt::decodeAuthorizationRequestClaims(tok); std::cout << "CPP-DECODE-OK sub=" << c->subject() << "\n"; }
        else if (type == "authorization_response") { auto c = jwt::decodeAuthorizationResponseClaims(tok); std::cout << "CPP-DECODE-OK sub=" << c->subject() << "\n"; }
        else if (type == "user") { auto c = jwt::decodeUserClaims(tok); std::cout << "CPP-DECODE-OK sub=" << c->subject() << "\n"; }
        else if (type == "generic") {
            auto c = jwt::decodeGeneric(tok);
            // the driver has no JSON engine (public API is string-only): pull the
            // top-level keys with a small scan good enough for our flat fixtures
            std::vector<std::string> keys;
            std::string d = c->dataJson();
            int depth = 0;
            for (std::size_t i = 0; i < d.size(); ++i) {
                if (d[i] == '{' || d[i] == '[') ++depth;
                else if (d[i] == '}' || d[i] == ']') --depth;
                else if (d[i] == '"' && depth == 1) {
                    auto e = d.find('"', i + 1);
                    if (e != std::string::npos && e + 1 < d.size() && d[e + 1] == ':') keys.push_back(d.substr(i + 1, e - i - 1));
                    // skip the whole string (value or key)
                    i = e;
                }
            }
            std::sort(keys.begin(), keys.end());
            std::cout << "CPP-DECODE-OK claimtype=" << c->claimType() << " sub=" << c->subject() << " data=[";
            for (std::size_t i = 0; i < keys.size(); ++i) std::cout << (i ? " " : "") << keys[i];
            std::cout << "]\n";
        }
        else { std::cerr << "ERR: unknown claim type " << type << "\n"; return 2; }
    } else if (mode == "validate") {
        auto c = jwt::decode(slurp(argv[2]));
        jwt::ValidationResults vr;
        c->validate(vr);
        std::vector<std::string> lines;
        for (const auto& i : vr.issues())
            lines.push_back(std::string(i.blocking ? "true" : "false") + "|" +
                            (i.timeCheck ? "true" : "false") + "|" + i.description);
        std::sort(lines.begin(), lines.end());
        for (const auto& l : lines) std::cout << "ISSUE: " << l << "\n";
        std::cout << "CPP-VALIDATE-OK\n";
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

        // a NOT-YET-VALID user: nbf one hour out — nats-server runs Go's
        // Validate on user JWTs with time checks BLOCKING (auth.go:
        // IsBlocking(true)), so the e2e proves a future nbf is refused
        auto nkp = nkeys::CreateUser();
        jwt::UserClaims nbfc(nkp->publicString());
        nbfc.setName("not-yet");
        nbfc.setIssuerAccount(akp->publicString());
        nbfc.setNotBefore(std::chrono::duration_cast<std::chrono::seconds>(
                              std::chrono::system_clock::now().time_since_epoch()).count() + 3600);
        std::string nbfCreds = jwt::formatUserConfig(nbfc.encode(askp->seedString()), nkp->seedString());

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

        // AUTH CALLOUT: account C delegates authentication to a service that
        // connects as C's auth_user; it may place clients into A
        // (allowed_accounts). Clients present a SENTINEL credential — a user
        // of C — so the server routes them to C's callout (measured: operator
        // mode enters the callout only for clients carrying a user JWT of an
        // external-auth account). The service (cpp_driver authcallout) admits
        // sentinel "alice" into A and refuses "mallory".
        auto ckp = nkeys::CreateAccount();
        auto cskp = nkeys::CreateAccount();
        auto calloutUser = nkeys::CreateUser();
        jwt::AccountClaims cc(ckp->publicString());
        cc.setName("C");
        cc.addSigningKey(cskp->publicString());
        cc.enableExternalAuthorization({calloutUser->publicString()});
        cc.authorization().allowedAccounts = {akp->publicString()};
        std::string calloutAccJwt = cc.encode(oskp->seedString());
        jwt::UserClaims cuc(calloutUser->publicString());
        cuc.setName("callout-service");
        std::string calloutCreds =
            jwt::formatUserConfig(cuc.encode(ckp->seedString()), calloutUser->seedString());
        auto sentinel = [&](const std::string& name) {
            auto kp = nkeys::CreateUser();
            jwt::UserClaims su(kp->publicString());
            su.setName(name);
            su.permissions().pub.deny = {">"};  // the callout's grant replaces these anyway
            su.permissions().sub.deny = {">"};
            return jwt::formatUserConfig(su.encode(ckp->seedString()), kp->seedString());
        };
        std::string aliceCreds = sentinel("alice");
        std::string malloryCreds = sentinel("mallory");

        // ENCRYPTED callout: account CX carries the service's curve public key
        // (authorization.xkey) — the server seals requests to it and puts its
        // own curve key in the Nats-Server-Xkey header (measured); the service
        // answers sealed. Same target account A.
        auto serviceX = nkeys::CreateCurveKeys();
        auto cxkp = nkeys::CreateAccount();
        auto cxskp = nkeys::CreateAccount();
        auto calloutUserX = nkeys::CreateUser();
        jwt::AccountClaims cxc(cxkp->publicString());
        cxc.setName("CX");
        cxc.addSigningKey(cxskp->publicString());
        cxc.enableExternalAuthorization({calloutUserX->publicString()});
        cxc.authorization().allowedAccounts = {akp->publicString()};
        cxc.authorization().xkey = serviceX->publicString();
        std::string calloutXAccJwt = cxc.encode(oskp->seedString());
        jwt::UserClaims cxuc(calloutUserX->publicString());
        cxuc.setName("callout-service-x");
        std::string calloutXCreds =
            jwt::formatUserConfig(cxuc.encode(cxkp->seedString()), calloutUserX->seedString());
        auto sentinelX = [&](const std::string& name) {
            auto kp = nkeys::CreateUser();
            jwt::UserClaims su(kp->publicString());
            su.setName(name);
            su.permissions().pub.deny = {">"};
            su.permissions().sub.deny = {">"};
            return jwt::formatUserConfig(su.encode(cxkp->seedString()), kp->seedString());
        };
        std::string aliceXCreds = sentinelX("alicex");
        std::string malloryXCreds = sentinelX("malloryx");

        // memory-resolver config, the Go README's resolver.conf
        std::string resolver = "operator: " + opJwt + "\n\n" +
                               "resolver: MEMORY\n" +
                               "resolver_preload: {\n" +
                               "\t" + akp->publicString() + ": " + accJwt + "\n" +
                               "\t" + lkp->publicString() + ": " + limitedAccJwt + "\n" +
                               "\t" + xkp->publicString() + ": " + exporterJwt + "\n" +
                               "\t" + ckp->publicString() + ": " + calloutAccJwt + "\n" +
                               "\t" + cxkp->publicString() + ": " + calloutXAccJwt + "\n" +
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
                 {"w.creds", wsOnlyCreds}, {"n.creds", nbfCreds},
                 {"callout.creds", calloutCreds}, {"alice.creds", aliceCreds},
                 {"mallory.creds", malloryCreds},
                 // what the callout SERVICE needs: C's and A's signing seeds
                 {"c.pub", ckp->publicString()}, {"a.pub", akp->publicString()},
                 {"c-sk.seed", cskp->seedString()}, {"a-sk.seed", askp->seedString()},
                 {"calloutx.creds", calloutXCreds}, {"alicex.creds", aliceXCreds},
                 {"malloryx.creds", malloryXCreds},
                 {"cx.pub", cxkp->publicString()}, {"cx-sk.seed", cxskp->seedString()},
                 {"service-x.seed", serviceX->seedString()},
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
    } else if (mode == "xkeys") {
        std::string dir = argv[2];
        auto x = nkeys::CreateCurveKeys();
        std::ofstream(dir + "/service-x.pub") << x->publicString();
        std::ofstream(dir + "/service-x.seed") << x->seedString();
        std::cout << "OK\n";
    } else if (mode == "openreq") {
        auto body = slurpBytes(argv[2]);
        auto rq = jwt::decodeSealedAuthorizationRequest(body, slurp(argv[3]), slurp(argv[4]));
        std::cout << "SEALED-REQ-OK sub=" << rq->subject() << " user_nkey=" << rq->userNkey()
                  << " user=" << rq->connectOptions().username << "\n";
    } else if (mode == "sealresp") {
        std::string dir = argv[2], serverX = slurp(argv[3]), seed = slurp(argv[4]);
        auto ckp = nkeys::CreateAccount();
        jwt::AuthorizationResponseClaims rs(slurp(argv[5]));
        rs.setAudience(slurp(argv[6]));
        rs.setError("nope");
        auto sealed = jwt::sealAuthorizationResponse(rs.encode(ckp->seedString()), serverX, seed);
        std::ofstream(dir + "/sealed-resp.bin", std::ios::binary)
            .write(reinterpret_cast<const char*>(sealed.data()), static_cast<std::streamsize>(sealed.size()));
        std::cout << "OK\n";
    } else if (mode == "hashid") {
        std::cout << jwt::decodeActivationClaims(slurp(argv[2]))->hashID() << "\n";
    } else if (mode == "migrate") { // type in out seed → decode (v1 or v2), re-encode v2
        std::string type = argv[2], tok = slurp(argv[3]), out = argv[4], seed = slurp(argv[5]);
        auto c = jwt::decode(tok);
        std::ofstream(out) << c->encode(seed);
        std::cout << "OK\n";
    } else if (mode == "mintgeneric") { // dir → custom-type generic token
        std::string dir = argv[2];
        auto ukp = nkeys::CreateUser();
        jwt::GenericClaims gc(ukp->publicString());
        gc.setName("custom");
        gc.setAudience("aud-g");
        gc.setDataJson(R"({"type":"my-custom-claim","hello":"world","n":42})");
        std::ofstream(dir + "/generic.jwt") << gc.encode(ukp->seedString());
        std::cout << "OK\n";
    } else if (mode == "genfields") { // dir → the four legacy types with aud/nbf/tags
        std::string dir = argv[2];
        auto okp = nkeys::CreateOperator();
        auto akp = nkeys::CreateAccount();
        auto ukp = nkeys::CreateUser();
        jwt::OperatorClaims oc(okp->publicString());
        oc.setName("O"); oc.setAudience("aud-op"); oc.setNotBefore(1700000000);
        jwt::addTags(oc.tags(), {"East", " Prod ", "east", ""});
        jwt::AccountClaims ac(akp->publicString());
        ac.setName("A"); ac.setAudience("aud-acc"); ac.setNotBefore(1700000001);
        jwt::addTags(ac.tags(), {"Billing"});
        jwt::UserClaims uc(ukp->publicString());
        uc.setName("U"); uc.setAudience("aud-user"); uc.setNotBefore(1700000002);
        jwt::addTags(uc.tags(), {"Team:Blue", "ops"});
        jwt::ActivationClaims act(akp->publicString());
        act.setName("grant"); act.setAudience("aud-act"); act.setNotBefore(1700000003);
        jwt::addTags(act.tags(), {"X"});
        act.setImportSubject("billing.charge");
        act.setImportType(jwt::ExportType::Service);
        for (auto& [n, c] : std::vector<std::pair<std::string, std::string>>{
                 {"fields-operator.jwt", oc.encode(okp->seedString())},
                 {"fields-account.jwt", ac.encode(okp->seedString())},
                 {"fields-user.jwt", uc.encode(akp->seedString())},
                 {"fields-activation.jwt", act.encode(akp->seedString())}})
            std::ofstream(dir + "/" + n) << c;
        std::cout << "OK\n";
    } else if (mode == "genauth") { // dir → C++-minted auth-callout artifacts for Go to decode + Validate
        std::string dir = argv[2];
        auto okp = nkeys::CreateOperator();
        auto ckp = nkeys::CreateAccount();
        auto cskp = nkeys::CreateAccount();
        auto akp = nkeys::CreateAccount();
        auto skp = nkeys::CreateServer();
        auto ukp = nkeys::CreateUser();
        jwt::AccountClaims cc(ckp->publicString());
        cc.setName("C");
        cc.addSigningKey(cskp->publicString());
        cc.enableExternalAuthorization({nkeys::CreateUser()->publicString(),
                                        nkeys::CreateUser()->publicString()});
        cc.authorization().allowedAccounts = {akp->publicString()};
        cc.authorization().xkey = nkeys::CreateCurveKeys()->publicString();
        std::string accJwt = cc.encode(okp->seedString());

        jwt::AuthorizationRequestClaims rq(ckp->publicString());
        rq.setAudience(jwt::AuthRequestAudience);
        // far-future: Go's Validate flags expiry, and a 2 s window raced two
        // process starts on a slow runner (review T1)
        rq.setExpires(std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::system_clock::now().time_since_epoch()).count() + 3600);
        rq.server() = jwt::ServerID{"srv-1", "10.0.0.7", skp->publicString(), "2.10.29", "c1", {"east"}, ""};
        rq.setUserNkey(ukp->publicString());
        rq.clientInformation().host = "172.17.0.1";
        rq.clientInformation().id = 9;
        rq.clientInformation().user = "alice";
        rq.clientInformation().kind = "Client";
        rq.clientInformation().type = "nats";
        rq.connectOptions().username = "alice";
        rq.connectOptions().password = "secret";
        rq.connectOptions().lang = "cpp";
        rq.connectOptions().protocol = 1;
        rq.tls() = jwt::ClientTLS{"1.3", "TLS_AES_128_GCM_SHA256", {"cert1"}, {{"leaf", "root"}}};
        rq.setRequestNonce("nonce-1");
        std::string reqJwt = rq.encode(skp->seedString());

        jwt::UserClaims uc(ukp->publicString());
        uc.setName("alice");
        std::string userJwt = uc.encode(akp->seedString());
        jwt::AuthorizationResponseClaims rs(ukp->publicString());
        rs.setAudience(skp->publicString());
        rs.setJwt(userJwt);
        rs.setIssuerAccount(ckp->publicString());
        std::string respJwt = rs.encode(cskp->seedString());
        jwt::AuthorizationResponseClaims re(ukp->publicString());
        re.setAudience(skp->publicString());
        re.setError("bad credentials");
        std::string errJwt = re.encode(ckp->seedString());
        for (auto& [n, c] : std::vector<std::pair<std::string, std::string>>{
                 {"acc-auth.jwt", accJwt}, {"auth-request.jwt", reqJwt},
                 {"auth-response.jwt", respJwt}, {"auth-response-err.jwt", errJwt}})
            std::ofstream(dir + "/" + n) << c;
        std::cout << "OK\n";
    } else if (mode == "authcallout") { // dir → one decision from $NATS_REQUEST_BODY (plaintext relay path)
        std::string dir = argv[2];
        const char* body = std::getenv("NATS_REQUEST_BODY");
        if (!body || !*body) { std::cerr << "ERR: no NATS_REQUEST_BODY\n"; return 1; }
        auto rq = jwt::decodeAuthorizationRequestClaims(body);
        // ONLY the JWT, no newline, nothing on stderr: `nats reply --command`
        // replies with the command's COMBINED output
        std::cout << calloutDecision(*rq, dir, "c.pub", "c-sk.seed", "alice");
    } else if (mode == "callout-serve") { // url dir profile [wrong-xkey] → run the callout service
        std::string url = argv[2], dir = argv[3], profile = argv[4];
        const bool wrongKey = argc > 5 && std::string(argv[5]) == "wrong-xkey";
        const bool sealed = profile == "cx";
        const std::string creds = dir + (sealed ? "/calloutx.creds" : "/callout.creds");
        const std::string pubFile = sealed ? "cx.pub" : "c.pub", skFile = sealed ? "cx-sk.seed" : "c-sk.seed";
        const std::string admit = sealed ? "alicex" : "alice";
        std::string xseed;
        if (sealed) xseed = wrongKey ? nkeys::CreateCurveKeys()->seedString() : slurp((dir + "/service-x.seed").c_str());
        MinNatsClient nc;
        nc.connect(url, creds);
        nc.subscribe("$SYS.REQ.USER.AUTH", 1);
        std::cerr << "callout-serve: listening (" << profile << (wrongKey ? ", WRONG xkey" : "") << ")\n";
        nc.run([&](const MinNatsClient::Msg& m) {
            try {
                const bool isSealed = jwt::isSealedCalloutBody(m.payload);
                std::unique_ptr<jwt::AuthorizationRequestClaims> rq;
                std::string serverX;
                if (isSealed) {
                    auto it = m.headers.find("Nats-Server-Xkey");
                    if (it == m.headers.end()) throw std::runtime_error("sealed request without Nats-Server-Xkey");
                    serverX = it->second;
                    rq = jwt::decodeSealedAuthorizationRequest(m.payload, serverX, xseed);
                } else {
                    rq = jwt::decodeAuthorizationRequestClaims(std::string(m.payload.begin(), m.payload.end()));
                }
                const std::string respJwt = calloutDecision(*rq, dir, pubFile, skFile, admit);
                if (isSealed) {
                    auto box = jwt::sealAuthorizationResponse(respJwt, serverX, xseed);
                    nc.publish(m.reply, box);
                    std::cerr << "callout-serve: answered SEALED (" << box.size() << " bytes)\n";
                } else {
                    nc.publish(m.reply, std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t*>(respJwt.data()), respJwt.size()));
                    std::cerr << "callout-serve: answered plain\n";
                }
            } catch (const std::exception& e) {
                std::cerr << "callout-serve: could not answer: " << e.what() << "\n";  // no reply → the server times out → refused
            }
        });
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
    } else {
        std::cerr << "ERR: unknown mode " << mode << "\n";
        return 2;
    }
    return 0;
} catch (const std::exception& e) {
    std::cerr << "ERR: " << e.what() << "\n";
    return 1;
}
