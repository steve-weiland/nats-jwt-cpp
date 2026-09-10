package main

import (
	"sort"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nats-io/jwt/v2"
	v1 "github.com/nats-io/jwt/v2/v1compat"
	"github.com/nats-io/nkeys"
)

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERR:", err)
		os.Exit(1)
	}
}

func main() {
	switch os.Args[1] {
	case "gen": // dir → writes README-flow artifacts: op(+signing key), self-signed→re-signed account, user via signing key, creds
		dir := os.Args[2]
		okp, _ := nkeys.CreateOperator()
		opk, _ := okp.PublicKey()
		oskp, _ := nkeys.CreateOperator()
		ospk, _ := oskp.PublicKey()
		oc := jwt.NewOperatorClaims(opk)
		oc.Name = "O"
		oc.SigningKeys.Add(ospk)
		opJWT, err := oc.Encode(okp)
		must(err)

		akp, _ := nkeys.CreateAccount()
		apk, _ := akp.PublicKey()
		askp, _ := nkeys.CreateAccount()
		aspk, _ := askp.PublicKey()
		ac := jwt.NewAccountClaims(apk)
		ac.Name = "A"
		ac.SigningKeys.Add(aspk)
		// self-sign first (the README flow), then re-sign with the operator SIGNING key
		selfJWT, err := ac.Encode(akp)
		must(err)
		ac2, err := jwt.DecodeAccountClaims(selfJWT)
		must(err)
		accJWT, err := ac2.Encode(oskp)
		must(err)

		ukp, _ := nkeys.CreateUser()
		upk, _ := ukp.PublicKey()
		uc := jwt.NewUserClaims(upk)
		uc.IssuerAccount = apk
		userJWT, err := uc.Encode(askp)
		must(err)
		useed, _ := ukp.Seed()
		creds, err := jwt.FormatUserConfig(userJWT, useed)
		must(err)

		for name, content := range map[string]string{
			"op.jwt": opJWT, "acc-self.jwt": selfJWT, "acc.jwt": accJWT,
			"user.jwt": userJWT, "u.creds": string(creds),
		} {
			must(os.WriteFile(dir+"/"+name, []byte(content), 0600))
		}
		fmt.Println("OK")
	case "genrichuser": // dir → account + user with full permissions/limits
		dir := os.Args[2]
		akp, _ := nkeys.CreateAccount()
		apk, _ := akp.PublicKey()
		ukp, _ := nkeys.CreateUser()
		upk, _ := ukp.PublicKey()
		uc := jwt.NewUserClaims(upk)
		uc.Name = "rich"
		uc.Permissions.Pub.Allow.Add("demo.>", "orders.*.created")
		uc.Permissions.Pub.Deny.Add("demo.secret")
		uc.Permissions.Sub.Allow.Add("demo.>", "jobs.* workers")
		uc.Permissions.Sub.Deny.Add("demo.internal.>")
		uc.Permissions.Resp = &jwt.ResponsePermission{MaxMsgs: 5, Expires: 2 * time.Second}
		uc.Limits.Subs = 100
		uc.Limits.Data = 1 << 20
		uc.Limits.Payload = 4096
		uc.Limits.Src.Add("10.0.0.0/8", "192.168.1.0/24")
		uc.Limits.Times = []jwt.TimeRange{{Start: "08:00:00", End: "17:00:00"}}
		uc.Limits.Locale = "America/Los_Angeles"
		uc.BearerToken = true
		uc.ProxyRequired = true
		uc.AllowedConnectionTypes.Add(jwt.ConnectionTypeWebsocket, jwt.ConnectionTypeMqtt)
		token, err := uc.Encode(akp)
		must(err)
		must(os.WriteFile(dir+"/rich-user.jwt", []byte(token), 0600))
		must(os.WriteFile(dir+"/rich-user.apub", []byte(apk), 0600))
		fmt.Println("OK")
	case "userperms": // jwt file → typed permission/limit fields, one per line
		data, err := os.ReadFile(os.Args[2])
		must(err)
		uc, err := jwt.DecodeUserClaims(strings.TrimSpace(string(data)))
		must(err)
		fmt.Printf("pub.allow=%v\n", uc.Permissions.Pub.Allow)
		fmt.Printf("pub.deny=%v\n", uc.Permissions.Pub.Deny)
		fmt.Printf("sub.allow=%v\n", uc.Permissions.Sub.Allow)
		fmt.Printf("sub.deny=%v\n", uc.Permissions.Sub.Deny)
		if uc.Permissions.Resp != nil {
			fmt.Printf("resp=%d,%v\n", uc.Permissions.Resp.MaxMsgs, uc.Permissions.Resp.Expires)
		} else {
			fmt.Println("resp=nil")
		}
		fmt.Printf("subs=%d data=%d payload=%d\n", uc.Limits.Subs, uc.Limits.Data, uc.Limits.Payload)
		fmt.Printf("src=%v times=%v locale=%s\n", uc.Limits.Src, uc.Limits.Times, uc.Limits.Locale)
		fmt.Printf("bearer=%v proxy=%v conn_types=%v\n", uc.BearerToken, uc.ProxyRequired, uc.AllowedConnectionTypes)
	case "genrichoperator": // dir → operator with all resolver-wiring fields
		dir := os.Args[2]
		okp, _ := nkeys.CreateOperator()
		opk, _ := okp.PublicKey()
		oskp, _ := nkeys.CreateOperator()
		ospk, _ := oskp.PublicKey()
		sakp, _ := nkeys.CreateAccount()
		sapk, _ := sakp.PublicKey()
		oc := jwt.NewOperatorClaims(opk)
		oc.Name = "rich-op"
		oc.SigningKeys.Add(ospk)
		oc.AccountServerURL = "https://resolver.example.com:9090/jwt/v1"
		oc.OperatorServiceURLs.Add("nats://n1.example.com:4222", "tls://n2.example.com:4222")
		oc.SystemAccount = sapk
		oc.AssertServerVersion = "2.10.0"
		oc.StrictSigningKeyUsage = true
		token, err := oc.Encode(okp)
		must(err)
		must(os.WriteFile(dir+"/op-rich.jwt", []byte(token), 0600))
		fmt.Println("OK")
	case "genxaccount": // dir → exporter + importer accounts + activation claim
		dir := os.Args[2]
		akp, _ := nkeys.CreateAccount() // exporter A
		apk, _ := akp.PublicKey()
		bkp, _ := nkeys.CreateAccount() // importer B
		bpk, _ := bkp.PublicKey()
		ukp, _ := nkeys.CreateUser()
		upk, _ := ukp.PublicKey()

		ea := jwt.NewAccountClaims(apk)
		ea.Name = "exporter"
		ea.Exports = jwt.Exports{
			&jwt.Export{
				Name: "billing", Subject: "billing.charge", Type: jwt.Service,
				TokenReq: true, ResponseType: jwt.ResponseTypeSingleton,
				ResponseThreshold: 2 * time.Second,
				Latency: &jwt.ServiceLatency{Sampling: 40, Results: "billing.latency"},
				AccountTokenPosition: 0, AllowTrace: true,
			},
			&jwt.Export{
				Name: "ticker", Subject: "ticks.>", Type: jwt.Stream,
				Advertise: true,
			},
		}
		ea.Exports[0].Revocations = jwt.RevocationList{upk: 1700000000}
		exporterJWT, err := ea.Encode(akp)
		must(err)

		act := jwt.NewActivationClaims(bpk) // grant TO account B
		act.Name = "billing-grant"
		act.ImportSubject = "billing.charge"
		act.ImportType = jwt.Service
		actJWT, err := act.Encode(akp) // issued by exporter A
		must(err)

		ib := jwt.NewAccountClaims(bpk)
		ib.Name = "importer"
		ib.Imports = jwt.Imports{
			&jwt.Import{
				Name: "billing", Subject: "billing.charge", Account: apk,
				Token: actJWT, LocalSubject: "acme.billing.charge",
				Type: jwt.Service, Share: true,
			},
			&jwt.Import{
				Name: "ticker", Subject: "ticks.>", Account: apk,
				Type: jwt.Stream, AllowTrace: true,
			},
		}
		importerJWT, err := ib.Encode(bkp)
		must(err)

		must(os.WriteFile(dir+"/acc-exports.jwt", []byte(exporterJWT), 0600))
		must(os.WriteFile(dir+"/acc-imports.jwt", []byte(importerJWT), 0600))
		must(os.WriteFile(dir+"/activation.jwt", []byte(actJWT), 0600))
		fmt.Println("OK")
	case "genrevaccount": // dir → account with a revocation list (fixed timestamps)
		dir := os.Args[2]
		akp, _ := nkeys.CreateAccount()
		apk, _ := akp.PublicKey()
		ukp, _ := nkeys.CreateUser()
		upk, _ := ukp.PublicKey()
		ac := jwt.NewAccountClaims(apk)
		ac.Name = "rev"
		ac.RevokeAt(upk, time.Unix(1700000000, 0))
		ac.RevokeAt(jwt.All, time.Unix(1600000000, 0))
		token, err := ac.Encode(akp)
		must(err)
		must(os.WriteFile(dir+"/acc-revoked.jwt", []byte(token), 0600))
		must(os.WriteFile(dir+"/acc-revoked.upub", []byte(upk), 0600))
		fmt.Println("OK")
	case "genrichaccount": // dir → account with custom limits/JS/mappings/info + a tiered variant
		dir := os.Args[2]
		akp, _ := nkeys.CreateAccount()
		apk, _ := akp.PublicKey()
		ac := jwt.NewAccountClaims(apk)
		ac.Name = "rich-account"
		ac.Description = "tenant with quotas"
		ac.InfoURL = "https://example.com/tenant"
		ac.Limits.Subs = 500
		ac.Limits.Data = 1 << 30
		ac.Limits.Payload = 65536
		ac.Limits.Imports = 4
		ac.Limits.Exports = 2
		ac.Limits.WildcardExports = false
		ac.Limits.DisallowBearer = true
		ac.Limits.Conn = 10
		ac.Limits.LeafNodeConn = 2
		ac.Limits.JetStreamLimits = jwt.JetStreamLimits{
			MemoryStorage: 1 << 20, DiskStorage: 1 << 30, Streams: 10,
			Consumer: 100, MaxAckPending: 1000, MemoryMaxStreamBytes: 1 << 19,
			DiskMaxStreamBytes: 1 << 29, MaxBytesRequired: true,
		}
		ac.DefaultPermissions.Pub.Allow.Add("app.>")
		ac.DefaultPermissions.Sub.Deny.Add("app.internal.>")
		ac.AddMapping("orders.v1.*",
			jwt.WeightedMapping{Subject: "orders.v2.*", Weight: 80},
			jwt.WeightedMapping{Subject: "orders.v1shadow.*", Weight: 20})
		token, err := ac.Encode(akp)
		must(err)
		must(os.WriteFile(dir+"/acc-rich.jwt", []byte(token), 0600))

		ac2 := jwt.NewAccountClaims(apk)
		ac2.Name = "tiered"
		ac2.Limits.JetStreamTieredLimits = jwt.JetStreamTieredLimits{
			"R1": {MemoryStorage: 1 << 20, DiskStorage: 1 << 30, Streams: 5},
			"R3": {DiskStorage: 1 << 28, Consumer: 10},
		}
		token2, err := ac2.Encode(akp)
		must(err)
		must(os.WriteFile(dir+"/acc-tiered.jwt", []byte(token2), 0600))
		fmt.Println("OK")
	case "genscopedaccount": // dir → account with plain + SCOPED signing key, and an IssueUserJWT user
		dir := os.Args[2]
		akp, _ := nkeys.CreateAccount()
		apk, _ := akp.PublicKey()
		plainSK, _ := nkeys.CreateAccount()
		plainPK, _ := plainSK.PublicKey()
		scopedSK, _ := nkeys.CreateAccount()
		scopedPK, _ := scopedSK.PublicKey()

		ac := jwt.NewAccountClaims(apk)
		ac.Name = "SA"
		ac.SigningKeys.Add(plainPK)
		scope := jwt.NewUserScope()
		scope.Key = scopedPK
		scope.Role = "demo-only"
		scope.Description = "may only touch demo.>"
		scope.Template.Permissions.Pub.Allow.Add("demo.>")
		scope.Template.Permissions.Sub.Allow.Add("demo.>", "_INBOX.>")
		scope.Template.Limits.Payload = 4096
		ac.SigningKeys.AddScopedSigner(scope)
		accJWT, err := ac.Encode(akp)
		must(err)

		ukp, _ := nkeys.CreateUser()
		upk, _ := ukp.PublicKey()
		userJWT, err := jwt.IssueUserJWT(scopedSK, apk, upk, "scoped-user", 0)
		must(err)

		must(os.WriteFile(dir+"/acc-scoped.jwt", []byte(accJWT), 0600))
		must(os.WriteFile(dir+"/scoped-user.jwt", []byte(userJWT), 0600))
		must(os.WriteFile(dir+"/scoped-user.apub", []byte(apk), 0600))
		fmt.Println("OK")
	case "seeds": // opfile accfile → fresh operator + account seeds (for the migrate check)
		okp, _ := nkeys.CreateOperator()
		os_, _ := okp.Seed()
		akp, _ := nkeys.CreateAccount()
		as_, _ := akp.Seed()
		must(os.WriteFile(os.Args[2], os_, 0600))
		must(os.WriteFile(os.Args[3], as_, 0600))
		fmt.Println("OK")
	case "genv1": // dir → V1 tokens (alg ed25519, payload-only signature, type/tags/issuer_account at top level) via v1compat
		dir := os.Args[2]
		okp, _ := nkeys.CreateOperator()
		opk, _ := okp.PublicKey()
		oskp, _ := nkeys.CreateOperator()
		ospk, _ := oskp.PublicKey()
		akp, _ := nkeys.CreateAccount()
		apk, _ := akp.PublicKey()
		askp, _ := nkeys.CreateAccount()
		aspk, _ := askp.PublicKey()
		ukp, _ := nkeys.CreateUser()
		upk, _ := ukp.PublicKey()
		oc := v1.NewOperatorClaims(opk)
		oc.Name = "O1"
		oc.Tags.Add("Legacy", "east")
		oc.SigningKeys.Add(ospk)
		oc.AccountServerURL = "https://as.example.com/jwt/v1"
		opJWT, err := oc.Encode(okp)
		must(err)
		ac := v1.NewAccountClaims(apk)
		ac.Name = "A1"
		ac.Tags.Add("billing")
		ac.SigningKeys.Add(aspk)
		ac.Limits.Conn = 10
		ac.Limits.Payload = 4096
		accJWT, err := ac.Encode(okp)
		must(err)
		uc := v1.NewUserClaims(upk)
		uc.Name = "U1"
		uc.Tags.Add("ops")
		uc.IssuerAccount = apk // top-level in v1
		uc.Permissions.Pub.Allow.Add("demo.>")
		uc.Permissions.Sub.Allow.Add("_INBOX.>", "jobs.* workers")
		uc.Limits.Max = 1000 // deprecated in v2 — dropped by migration
		uc.Limits.Payload = 2048
		uc.Limits.Src = "10.0.0.0/8,192.168.1.0/24" // v1: comma string
		uc.BearerToken = true
		userJWT, err := uc.Encode(askp)
		must(err)
		act := v1.NewActivationClaims(apk)
		act.Name = "grant1"
		act.Tags.Add("x")
		act.ImportSubject = "billing.charge"
		act.ImportType = v1.Service // v1 wire key is "type" (v2: "kind")
		act.Limits.Max = 5
		actJWT, err := act.Encode(akp)
		must(err)
		for name, content := range map[string]string{"v1-operator.jwt": opJWT, "v1-account.jwt": accJWT,
			"v1-user.jwt": userJWT, "v1-activation.jwt": actJWT} {
			must(os.WriteFile(dir+"/"+name, []byte(content), 0600))
		}
		fmt.Println("OK")
	case "gengeneric": // dir → a custom-type generic claim (Go: GenericClaims), signed by a user key (no prefix rule)
		dir := os.Args[2]
		ukp, _ := nkeys.CreateUser()
		upk, _ := ukp.PublicKey()
		gc := jwt.NewGenericClaims(upk)
		gc.Name = "custom"
		gc.Audience = "aud-g"
		gc.Data["type"] = "my-custom-claim"
		gc.Data["hello"] = "world"
		gc.Data["n"] = 42
		gc.Data["nested"] = map[string]interface{}{"k": []string{"a", "b"}}
		token, err := gc.Encode(ukp)
		must(err)
		must(os.WriteFile(dir+"/generic.jwt", []byte(token), 0600))
		fmt.Println("OK")
	case "generic": // jwt file → DecodeGeneric: type= and the data keys (sorted)
		data, err := os.ReadFile(os.Args[2])
		must(err)
		gc, err := jwt.DecodeGeneric(strings.TrimSpace(string(data)))
		must(err)
		var keys []string
		for k := range gc.Data {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Printf("claimtype=%s sub=%s data=%v\n", gc.ClaimType(), gc.Subject, keys)
	case "genfields": // dir → operator/account/user/activation carrying aud + nbf + tags (group 6a)
		dir := os.Args[2]
		okp, _ := nkeys.CreateOperator()
		opk, _ := okp.PublicKey()
		akp, _ := nkeys.CreateAccount()
		apk, _ := akp.PublicKey()
		ukp, _ := nkeys.CreateUser()
		upk, _ := ukp.PublicKey()
		oc := jwt.NewOperatorClaims(opk)
		oc.Name = "O"
		oc.Audience = "aud-op"
		oc.NotBefore = 1700000000
		oc.Tags.Add("East", " Prod ", "east", "")
		opJWT, err := oc.Encode(okp)
		must(err)
		ac := jwt.NewAccountClaims(apk)
		ac.Name = "A"
		ac.Audience = "aud-acc"
		ac.NotBefore = 1700000001
		ac.Tags.Add("Billing")
		accJWT, err := ac.Encode(okp)
		must(err)
		uc := jwt.NewUserClaims(upk)
		uc.Name = "U"
		uc.Audience = "aud-user"
		uc.NotBefore = 1700000002
		uc.Tags.Add("Team:Blue", "ops")
		userJWT, err := uc.Encode(akp)
		must(err)
		act := jwt.NewActivationClaims(apk)
		act.Name = "grant"
		act.Audience = "aud-act"
		act.NotBefore = 1700000003
		act.Tags.Add("X")
		act.ImportSubject = "billing.charge"
		act.ImportType = jwt.Service
		actJWT, err := act.Encode(akp)
		must(err)
		for name, content := range map[string]string{"fields-operator.jwt": opJWT, "fields-account.jwt": accJWT,
			"fields-user.jwt": userJWT, "fields-activation.jwt": actJWT} {
			must(os.WriteFile(dir+"/"+name, []byte(content), 0600))
		}
		fmt.Println("OK")
	case "fields": // jwt file → aud/nbf/tags as Go's typed parse sees them
		data, err := os.ReadFile(os.Args[2])
		must(err)
		c, err := jwt.Decode(strings.TrimSpace(string(data)))
		must(err)
		var tags jwt.TagList
		switch t := c.(type) {
		case *jwt.OperatorClaims:
			tags = t.Tags
		case *jwt.AccountClaims:
			tags = t.Tags
		case *jwt.UserClaims:
			tags = t.Tags
		case *jwt.ActivationClaims:
			tags = t.Tags
		}
		fmt.Printf("aud=%s nbf=%d tags=%v\n", c.Claims().Audience, c.Claims().NotBefore, tags)
	case "genauth": // dir → auth-callout goldens: account with authorization, a rich request, responses (jwt / error)
		dir := os.Args[2]
		okp, _ := nkeys.CreateOperator()
		ckp, _ := nkeys.CreateAccount()
		cpk, _ := ckp.PublicKey()
		cskp, _ := nkeys.CreateAccount()
		cspk, _ := cskp.PublicKey()
		u1, _ := nkeys.CreateUser()
		u1pk, _ := u1.PublicKey()
		u2, _ := nkeys.CreateUser()
		u2pk, _ := u2.PublicKey()
		a1, _ := nkeys.CreateAccount()
		a1pk, _ := a1.PublicKey()
		xkp, _ := nkeys.CreateCurveKeys()
		xpk, _ := xkp.PublicKey()
		cc := jwt.NewAccountClaims(cpk)
		cc.Name = "C"
		cc.SigningKeys.Add(cspk)
		cc.Authorization.AuthUsers.Add(u1pk, u2pk)
		cc.Authorization.AllowedAccounts.Add(a1pk)
		cc.Authorization.XKey = xpk
		accJWT, err := cc.Encode(okp)
		must(err)

		skp, _ := nkeys.CreateServer()
		spk, _ := skp.PublicKey()
		ukp, _ := nkeys.CreateUser()
		upk, _ := ukp.PublicKey()
		rq := jwt.NewAuthorizationRequestClaims(cpk)
		rq.Name = "req"
		rq.Audience = "nats-authorization-request"
		rq.Expires = 1800000000
		rq.Server = jwt.ServerID{Name: "srv-1", Host: "10.0.0.7", ID: spk, Version: "2.10.29", Cluster: "c1",
			Tags: jwt.TagList{"east", "prod"}, XKey: xpk}
		rq.UserNkey = upk
		rq.ClientInformation = jwt.ClientInformation{Host: "172.17.0.1", ID: 9, User: "alice", Name: "cli",
			Tags: jwt.TagList{"t1"}, NameTag: "sentinel", Kind: "Client", Type: "nats", MQTT: "m1", Nonce: "abc"}
		rq.ConnectOptions = jwt.ConnectOptions{JWT: "eyJ.x.y", Nkey: upk, SignedNonce: "sig", Token: "tok",
			Username: "alice", Password: "secret", Name: "cli", Lang: "go", Version: "1.45.0", Protocol: 1}
		rq.TLS = &jwt.ClientTLS{Version: "1.3", Cipher: "TLS_AES_128_GCM_SHA256", Certs: jwt.StringList{"cert1"},
			VerifiedChains: []jwt.StringList{{"leaf", "root"}}}
		rq.RequestNonce = "nonce-1"
		reqJWT, err := rq.Encode(skp)
		must(err)

		uc := jwt.NewUserClaims(upk)
		uc.Name = "alice"
		userJWT, err := uc.Encode(a1)
		must(err)
		rs := jwt.NewAuthorizationResponseClaims(upk)
		rs.Audience = spk
		rs.Jwt = userJWT
		rs.IssuerAccount = cpk
		respJWT, err := rs.Encode(cskp)
		must(err)
		re := jwt.NewAuthorizationResponseClaims(upk)
		re.Audience = spk
		re.Error = "bad credentials"
		errJWT, err := re.Encode(ckp)
		must(err)
		for name, content := range map[string]string{"acc-auth.jwt": accJWT, "auth-request.jwt": reqJWT,
			"auth-response.jwt": respJWT, "auth-response-err.jwt": errJWT} {
			must(os.WriteFile(dir+"/"+name, []byte(content), 0600))
		}
		fmt.Println("OK")
	case "validate": // jwt file → Decode + Validate; one "blocking|timecheck|description" line per issue (sorted), then type=
		data, err := os.ReadFile(os.Args[2])
		must(err)
		c, err := jwt.Decode(strings.TrimSpace(string(data)))
		must(err)
		vr := jwt.CreateValidationResults()
		c.Validate(vr)
		var lines []string
		for _, i := range vr.Issues {
			lines = append(lines, fmt.Sprintf("%t|%t|%s", i.Blocking, i.TimeCheck, i.Description))
		}
		sort.Strings(lines)
		for _, l := range lines {
			fmt.Println("ISSUE:", l)
		}
		fmt.Println("type=" + string(c.ClaimType()))
	case "genflawed": // dir → tokens Go can MINT but its own Validate flags (Encode does not validate)
		dir := os.Args[2]
		okp, _ := nkeys.CreateOperator()
		opk, _ := okp.PublicKey()
		akp, _ := nkeys.CreateAccount()
		apk, _ := akp.PublicKey()
		ukp, _ := nkeys.CreateUser()
		upk, _ := ukp.PublicKey()
		// expired operator (time check)
		oc := jwt.NewOperatorClaims(opk)
		oc.Expires = 1700000000
		expired, err := oc.Encode(okp)
		must(err)
		// user not yet valid (time check)
		uc := jwt.NewUserClaims(upk)
		uc.NotBefore = 4102444800
		notyet, err := uc.Encode(akp)
		must(err)
		// self-signed account with the default limits (warning)
		sc := jwt.NewAccountClaims(apk)
		selfsigned, err := sc.Encode(akp)
		must(err)
		// operator-signed account importing with the deprecated `to` (warning)
		ic := jwt.NewAccountClaims(apk)
		other, _ := nkeys.CreateAccount()
		otherpk, _ := other.PublicKey()
		ic.Imports.Add(&jwt.Import{Name: "old", Subject: "legacy.>", Account: otherpk, Type: jwt.Stream, To: "local.>"})
		deprecatedTo, err := ic.Encode(okp)
		must(err)
		// operator-signed account with a 150-weight mapping (error)
		mc := jwt.NewAccountClaims(apk)
		mc.Mappings = jwt.Mapping{"orders.>": []jwt.WeightedMapping{{Subject: "orders.v2.>", Weight: 150}}}
		badMapping, err := mc.Encode(okp)
		must(err)
		// user with a queue in pub + a bad cidr (two errors)
		qc := jwt.NewUserClaims(upk)
		qc.Permissions.Pub.Allow.Add("jobs.* workers")
		qc.Limits.Src.Add("not-a-cidr")
		badUser, err := qc.Encode(akp)
		must(err)
		// exports: overlap, bad subjects, token position, latency, info url, default perms, signing key
		xkp, _ := nkeys.CreateAccount()
		ec := jwt.NewAccountClaims(apk)
		ec.Exports.Add(
			&jwt.Export{Name: "a", Subject: "svc.>", Type: jwt.Service},
			&jwt.Export{Name: "b", Subject: "svc.one", Type: jwt.Service, ResponseType: "Weird"},
			&jwt.Export{Name: "c", Subject: ".bad..subj.", Type: jwt.Stream, ResponseType: "Singleton", AllowTrace: true},
			&jwt.Export{Name: "d", Subject: "acc.*.data", Type: jwt.Service, AccountTokenPosition: 3},
			&jwt.Export{Name: "e", Subject: "plain.data", Type: jwt.Service, AccountTokenPosition: 1},
			&jwt.Export{Name: "f", Subject: "s.*", Type: jwt.Service, AccountTokenPosition: 9},
			&jwt.Export{Name: "g", Subject: "lat.svc", Type: jwt.Stream, Latency: &jwt.ServiceLatency{Sampling: 50, Results: "lat.>"},
				ResponseThreshold: 5 * time.Second, Info: jwt.Info{InfoURL: "nohost"}},
			&jwt.Export{Name: "h", Subject: "str.>", Type: jwt.Stream},
			&jwt.Export{Name: "i", Subject: "str.x.y", Type: jwt.Stream},
		)
		ec.DefaultPermissions.Pub.Allow.Add("a..b", "jobs.* q")
		ec.DefaultPermissions.Sub.Deny.Add(".lead")
		ec.SigningKeys.Add("bogus-signing-key")
		ec.Info = jwt.Info{Description: "ok", InfoURL: "ftp:noslashes"}
		flawedExports, err := ec.Encode(okp)
		must(err)
		// imports: per-account service overlap, deprecated `to`, renaming refs, token cross-checks
		zkp, _ := nkeys.CreateAccount()
		zpk, _ := zkp.PublicKey()
		act2 := jwt.NewActivationClaims(zpk) // grantee is NOT this account
		act2.ImportSubject = "other.>"
		act2.ImportType = jwt.Stream
		act2.Expires = 1700000000 // expired: a time check the import cross-check must NOT copy
		actTok, err := act2.Encode(xkp)
		must(err)
		xpk, _ := xkp.PublicKey()
		ic2 := jwt.NewAccountClaims(apk)
		ic2.Imports.Add(
			&jwt.Import{Name: "s1", Subject: "svc.a", Account: otherpk, Type: jwt.Service},
			&jwt.Import{Name: "s2", Subject: "svc.>", Account: otherpk, Type: jwt.Service},
			&jwt.Import{Name: "s3", Subject: "svc.a", Account: otherpk, Type: jwt.Service},
			&jwt.Import{Name: "t", Subject: "legacy.>", Account: otherpk, Type: jwt.Stream, To: "local.>", LocalSubject: "l.>"},
			&jwt.Import{Name: "r", Subject: "i.one.*", Account: otherpk, Type: jwt.Stream, LocalSubject: "l.$3.x"},
			&jwt.Import{Name: "k", Subject: "tok.data", Account: xpk, Type: jwt.Service, Token: actTok, Share: false},
			&jwt.Import{Name: "sh", Subject: "shared.>", Account: otherpk, Type: jwt.Stream, Share: true},
			&jwt.Import{Name: "bt", Subject: "bad.tok", Account: otherpk, Type: jwt.Stream, Token: "not-a-jwt"},
		)
		flawedImports, err := ic2.Encode(okp)
		must(err)
		// limits vs counts, wildcard exports forbidden
		lc := jwt.NewAccountClaims(apk)
		lc.Limits.Imports = 0
		lc.Limits.Exports = 1
		lc.Limits.WildcardExports = false
		lc.Exports.Add(&jwt.Export{Name: "w1", Subject: "w.>", Type: jwt.Stream}, &jwt.Export{Name: "w2", Subject: "w.x", Type: jwt.Stream})
		lc.Imports.Add(&jwt.Import{Name: "one", Subject: "one", Account: otherpk, Type: jwt.Stream})
		flawedLimits, err := lc.Encode(okp)
		must(err)
		for name, content := range map[string]string{"flawed-expired.jwt": expired, "flawed-notyet.jwt": notyet,
			"flawed-selfsigned.jwt": selfsigned, "flawed-to.jwt": deprecatedTo, "flawed-mapping.jwt": badMapping,
			"flawed-user.jwt": badUser, "flawed-exports.jwt": flawedExports, "flawed-imports.jwt": flawedImports,
			"flawed-limits.jwt": flawedLimits} {
			must(os.WriteFile(dir+"/"+name, []byte(content), 0600))
		}
		fmt.Println("OK")
	case "sealreq": // dir serviceXpub → a server-signed request SEALED (Go nkeys) to the service's curve key, like nats-server
		dir, servicePub := os.Args[2], os.Args[3]
		skp, _ := nkeys.CreateServer()
		spk, _ := skp.PublicKey()
		sxkp, _ := nkeys.CreateCurveKeys()
		sxpub, _ := sxkp.PublicKey()
		sxseed, _ := sxkp.Seed()
		akp, _ := nkeys.CreateAccount()
		apk, _ := akp.PublicKey()
		ukp, _ := nkeys.CreateUser()
		upk, _ := ukp.PublicKey()
		rq := jwt.NewAuthorizationRequestClaims(apk)
		rq.Audience = "nats-authorization-request"
		rq.UserNkey = upk
		rq.Server = jwt.ServerID{Name: "srv", Host: "0.0.0.0", ID: spk, Version: "2.10.29", XKey: sxpub}
		rq.ConnectOptions = jwt.ConnectOptions{Username: "alice", Password: "secret", Protocol: 1}
		reqJWT, err := rq.Encode(skp)
		must(err)
		sealed, err := sxkp.Seal([]byte(reqJWT), servicePub)
		must(err)
		must(os.WriteFile(dir+"/sealed-req.bin", sealed, 0600))
		must(os.WriteFile(dir+"/server-x.pub", []byte(sxpub), 0600))
		must(os.WriteFile(dir+"/server-x.seed", sxseed, 0600))
		must(os.WriteFile(dir+"/server.pub", []byte(spk), 0600))
		must(os.WriteFile(dir+"/user.pub", []byte(upk), 0600))
		fmt.Println("OK")
	case "openresp": // bodyfile senderXpub serverXseedfile → open a sealed response like nats-server, Decode it, print sub= and error=
		body, err := os.ReadFile(os.Args[2])
		must(err)
		seed, err := os.ReadFile(os.Args[4])
		must(err)
		sxkp, err := nkeys.FromCurveSeed(seed)
		must(err)
		plain, err := sxkp.Open(body, os.Args[3])
		must(err)
		rc, err := jwt.DecodeAuthorizationResponseClaims(string(plain))
		must(err)
		fmt.Printf("sub=%s error=%s\n", rc.Subject, rc.Error)
	case "hashid": // activation jwt file → Go's HashID()
		data, err := os.ReadFile(os.Args[2])
		must(err)
		ac, err := jwt.DecodeActivationClaims(strings.TrimSpace(string(data)))
		must(err)
		h, err := ac.HashID()
		must(err)
		fmt.Println(h)
	case "djwt": // jwt file → DecorateJWT output (armored by claim type)
		data, err := os.ReadFile(os.Args[2])
		must(err)
		out, err := jwt.DecorateJWT(strings.TrimSpace(string(data)))
		must(err)
		os.Stdout.Write(out)
	case "dseed": // seed file → DecorateSeed output
		data, err := os.ReadFile(os.Args[2])
		must(err)
		out, err := jwt.DecorateSeed([]byte(strings.TrimSpace(string(data))))
		must(err)
		os.Stdout.Write(out)
	case "pdjwt": // creds file → ParseDecoratedJWT result
		data, err := os.ReadFile(os.Args[2])
		must(err)
		token, err := jwt.ParseDecoratedJWT(data)
		must(err)
		fmt.Println(token)
	case "decode": // jwt file → type + iss + sub (Decode = authenticated)
		data, err := os.ReadFile(os.Args[2])
		must(err)
		c, err := jwt.Decode(strings.TrimSpace(string(data)))
		must(err)
		fmt.Printf("GO-DECODE-OK type=%v iss=%s sub=%s\n", c.ClaimType(), c.Claims().Issuer, c.Claims().Subject)
	case "creds": // creds file → parse jwt out and Decode it
		data, err := os.ReadFile(os.Args[2])
		must(err)
		token, err := jwt.ParseDecoratedJWT(data)
		must(err)
		_, err = jwt.Decode(token)
		must(err)
		fmt.Println("GO-CREDS-OK")
	case "expired": // opseed → operator jwt with exp in the past (exp < iat)
		seed, err := os.ReadFile(os.Args[2])
		must(err)
		okp, err := nkeys.FromSeed([]byte(strings.TrimSpace(string(seed))))
		must(err)
		opk, _ := okp.PublicKey()
		oc := jwt.NewOperatorClaims(opk)
		oc.Expires = 1000000000 // 2001 — long past
		s, err := oc.Encode(okp)
		must(err)
		fmt.Println(s)
	}
}
