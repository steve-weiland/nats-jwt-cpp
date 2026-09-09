package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nats-io/jwt/v2"
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
