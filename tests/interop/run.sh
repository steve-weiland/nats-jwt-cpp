#!/usr/bin/env sh
# run.sh — the live Go↔C++ interop matrix (the gate CI runs; also runnable
# locally). Pairs this library against the reference Go nats-io/jwt through
# two CLIs: cpp_driver (built by CMake with tests) and the Go probe here.
#
#   usage: tests/interop/run.sh <cmake-build-dir>
#
# Fourteen checks:
#   1. C++-minted operator/account/user JWTs pass Go's authenticated Decode —
#      minted both from seeds and through encodeWithSigner (external signer)
#   2. C++-generated .creds parses via Go ParseDecoratedJWT (the armor regex
#      every NATS client uses) and its JWT decodes
#   3. Go's canonical artifacts decode in C++ — including the SELF-SIGNED
#      account (Go's documented flow) and the signing-key-issued user
#   4. Go's README-flow chain passes C++ strict() chain validation
#      (operator signing key issues the account; account signing key + issuer_account
#      issue the user)
#   5. a payload-tampered token is rejected by BOTH sides
#   6. Go-minted already-expired token decodes in C++ (expiry is validity,
#      not structure)
#   7. typed permissions/limits: a C++-minted rich user parses into Go's
#      TYPED fields with the intended values (fix-plan #1+#2), including the
#      bearer/proxy/connection-type flags (group 5c)
#   8. round-trip: Go decodes a C++ user token, C++ decodes it back
#   9. auth callout: C++-minted account-with-authorization, server-signed
#      request and responses pass Go Decode + Validate with no issues, and
#      Go's goldens (incl. a REAL nats-server request) decode in C++
#  10. aud / nbf / tags: C++-minted tokens of all four legacy types show the
#      intended values in Go's typed parse (tags normalized Go-TagList-style);
#      Go's goldens decode in C++
#  11. validation report: tokens Go can MINT but its own Validate flags
#      (Go's Encode does not validate) decode in C++ WITHOUT throwing, and the
#      C++ report equals Go's issue list line-for-line (blocking/time flags +
#      description)
#  12. v1 + generic: Go's v1compat-minted tokens (alg ed25519, payload-only
#      signature, top-level type/tags/issuer_account) decode in C++ and
#      re-encode as v2 tokens Go decodes; generic claims cross both ways
#  13. activation hashID: C++ equals Go's HashID() on Go-minted activations,
#      wildcard and plain subjects alike
#  14. xkey-sealed callout: Go (nkeys Seal, as nats-server does) seals a
#      server-signed request to a C++ curve key → C++ opens, decodes and
#      cross-checks server_id.xkey; C++ seals a response → Go opens + Decodes
set -eu

BUILD_DIR=${1:?usage: run.sh <cmake-build-dir>}
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=$(CDPATH= cd -- "$HERE/../.." && pwd)
CPP="$BUILD_DIR/cpp_driver"
[ -x "$CPP" ] || CPP="$BUILD_DIR/tests/interop/cpp_driver"
[ -x "$CPP" ] || { echo "cpp_driver not found under $BUILD_DIR (build with tests on)" >&2; exit 1; }

echo "interop: building Go probe"
( cd "$HERE/probe" && go build -o "$HERE/probe/probe" . )
GO="$HERE/probe/probe"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

pass=0
check() { pass=$((pass+1)); echo "  ok $pass: $1"; }
fail() { echo "  FAIL: $1" >&2; exit 1; }

# 1 ── C++-minted → Go authenticated Decode
mkdir -p "$TMP/cpp"
"$CPP" encode "$TMP/cpp" >/dev/null
for f in op acc user; do
    "$GO" decode "$TMP/cpp/$f.jwt" >/dev/null || fail "Go rejected C++-minted $f.jwt"
done
mkdir -p "$TMP/cpp-signer"
"$CPP" encode-signer "$TMP/cpp-signer" >/dev/null
for f in op acc user; do
    "$GO" decode "$TMP/cpp-signer/$f.jwt" >/dev/null || fail "Go rejected C++ signer-minted $f.jwt"
done
"$GO" creds "$TMP/cpp-signer/u.creds" >/dev/null || fail "Go could not parse signer-minted creds"
check "C++-minted operator/account/user pass Go's authenticated Decode (seed AND external-signer paths)"

# 2 ── C++ creds through the armor regex real clients use
"$GO" creds "$TMP/cpp/u.creds" >/dev/null || fail "Go could not parse C++-generated creds"
check "C++ .creds parses via Go ParseDecoratedJWT and decodes"

# 3 ── Go's canonical artifacts → C++ (self-signed account included)
mkdir -p "$TMP/go"
"$GO" gen "$TMP/go" >/dev/null
"$CPP" decode operator "$TMP/go/op.jwt" >/dev/null || fail "C++ rejected Go operator"
"$CPP" decode account "$TMP/go/acc.jwt" >/dev/null || fail "C++ rejected Go account (signing-key issued)"
"$CPP" decode account "$TMP/go/acc-self.jwt" >/dev/null || fail "C++ rejected Go SELF-SIGNED account"
"$CPP" decode user "$TMP/go/user.jwt" >/dev/null || fail "C++ rejected Go user (signing-key issued)"
check "Go-minted artifacts decode in C++ (incl. self-signed account)"

# 4 ── Go README flow through strict chain validation
out=$("$CPP" chain "$TMP/go/op.jwt" "$TMP/go/acc.jwt" "$TMP/go/user.jwt")
[ "$out" = "CPP-CHAIN-OK" ] || fail "Go canonical chain failed C++ strict validation: $out"
check "Go's canonical chain passes strict() (signing keys + issuer_account)"

# 5 ── tampered payload rejected by both sides. Flip one payload char,
# swapping between two base64url alphabet members so it stays decodable.
token=$(cat "$TMP/go/user.jwt")
payload=${token#*.}; payload=${payload%.*}
case $payload in
    *A*) tampered_payload=$(printf '%s' "$payload" | sed 's/A/B/') ;;
    *)   tampered_payload=$(printf '%s' "$payload" | sed 's/[a-z]/A/') ;;
esac
tampered="${token%%.*}.${tampered_payload}.${token##*.}"
printf '%s' "$tampered" > "$TMP/tampered.jwt"
if "$GO" decode "$TMP/tampered.jwt" >/dev/null 2>&1; then fail "Go accepted a tampered token"; fi
if "$CPP" decode user "$TMP/tampered.jwt" >/dev/null 2>&1; then fail "C++ accepted a tampered token"; fi
check "payload-tampered token rejected by BOTH sides"

# 6 ── Go-legal expired token decodes in C++
"$CPP" decode operator "$REPO/tests/fixtures/operator-expired.jwt" >/dev/null \
    || fail "C++ could not decode a Go-minted expired token"
check "Go-minted expired token decodes (expiry is validity, not structure)"

# 7 ── typed permissions/limits round trip: C++ mints the rich user, Go's
# TYPED parser must see every field with the intended values
mkdir -p "$TMP/rich"
"$CPP" richuser "$TMP/rich" >/dev/null
perms=$("$GO" userperms "$TMP/rich/rich-user.jwt")
for expect in \
    'pub.allow=[demo.> orders.*.created]' \
    'pub.deny=[demo.secret]' \
    'sub.allow=[demo.> jobs.* workers]' \
    'resp=5,2s' \
    'subs=100 data=1048576 payload=4096' \
    'src=[10.0.0.0/8 192.168.1.0/24] times=[{08:00:00 17:00:00}] locale=America/Los_Angeles' \
    'bearer=true proxy=true conn_types=[WEBSOCKET MQTT]'
do
    printf '%s\n' "$perms" | grep -qF "$expect" \
        || fail "Go's typed parse missing: $expect (got: $perms)"
done
check "C++ typed permissions/limits parse into Go's types with intended values"

# 8 ── round-trip sanity
"$GO" decode "$TMP/cpp/user.jwt" >/dev/null && "$CPP" decode user "$TMP/cpp/user.jwt" >/dev/null \
    || fail "round-trip decode failed"
check "round-trip: both sides decode the same C++ user token"

# 9 ── auth callout, both directions
mkdir -p "$TMP/auth-cpp" "$TMP/auth-go"
"$CPP" genauth "$TMP/auth-cpp" >/dev/null
for f in acc-auth auth-request auth-response auth-response-err; do
    out=$("$GO" validate "$TMP/auth-cpp/$f.jwt") || fail "Go rejected C++-minted $f.jwt"
    printf '%s' "$out" | grep -q "ISSUE:" && fail "Go Validate found issues in C++-minted $f.jwt: $out"
done
"$GO" genauth "$TMP/auth-go" >/dev/null
for f in acc-auth:account auth-request:authorization_request auth-response:authorization_response \
         auth-response-err:authorization_response; do
    name=${f%%:*}; type=${f##*:}
    out=$("$CPP" decode "$type" "$TMP/auth-go/$name.jwt") || fail "C++ rejected Go-minted $name.jwt"
done
"$CPP" decode authorization_request "$REPO/tests/fixtures/auth-request-server.jwt" >/dev/null \
    || fail "C++ rejected the REAL nats-server authorization request fixture"
check "auth callout: C++ artifacts pass Go Decode+Validate; Go's (and nats-server's) decode in C++"

# 10 ── aud / nbf / tags, both directions
mkdir -p "$TMP/fields-cpp" "$TMP/fields-go"
"$CPP" genfields "$TMP/fields-cpp" >/dev/null
for pair in 'operator:aud=aud-op nbf=1700000000 tags=[east prod]' \
            'account:aud=aud-acc nbf=1700000001 tags=[billing]' \
            'user:aud=aud-user nbf=1700000002 tags=[team:blue ops]' \
            'activation:aud=aud-act nbf=1700000003 tags=[x]'; do
    t=${pair%%:*}; expect=${pair#*:}
    got=$("$GO" fields "$TMP/fields-cpp/fields-$t.jwt") || fail "Go rejected C++-minted fields-$t.jwt"
    [ "$got" = "$expect" ] || fail "Go's typed parse of C++ fields-$t.jwt: expected '$expect', got '$got'"
done
"$GO" genfields "$TMP/fields-go" >/dev/null
for t in operator account user activation; do
    "$CPP" decode "$t" "$TMP/fields-go/fields-$t.jwt" >/dev/null || fail "C++ rejected Go-minted fields-$t.jwt"
done
check "aud/nbf/tags: C++ values land in Go's typed parse; Go's goldens decode in C++"

# 11 ── validation report parity on Go-mintable-but-flawed tokens
mkdir -p "$TMP/flawed"
"$GO" genflawed "$TMP/flawed" >/dev/null
for f in expired notyet selfsigned to mapping user exports imports limits; do
    want=$("$GO" validate "$TMP/flawed/flawed-$f.jwt" | grep "^ISSUE:") || true
    # capture the driver's status itself (a pipeline would report grep's)
    cppout=$("$CPP" validate "$TMP/flawed/flawed-$f.jwt") || fail "C++ could not decode Go's flawed-$f.jwt (advisory failures must stay inspectable)"
    got=$(printf '%s\n' "$cppout" | grep "^ISSUE:" || true)
    [ -n "$want" ] || fail "Go reported no issues for flawed-$f.jwt — the golden lost its flaw"
    [ "$got" = "$want" ] || fail "report mismatch on flawed-$f.jwt
--- Go:
$want
--- C++:
$got"
done
check "validation report: C++ decodes Go's flawed tokens and reports Go's issues verbatim"

# 12 ── v1 reading + generic claims, both directions
mkdir -p "$TMP/v1" "$TMP/gen-cpp"
"$GO" genv1 "$TMP/v1" >/dev/null
"$GO" gengeneric "$TMP/v1" >/dev/null
okseed=$TMP/op.seed; acseed=$TMP/acc.seed  # inside $TMP so the EXIT trap removes them on any path
"$GO" seeds "$okseed" "$acseed" >/dev/null || fail "probe seeds failed"
for t in operator:"$okseed" account:"$okseed" user:"$acseed" activation:"$acseed"; do
    name=${t%%:*}; seed=${t##*:}
    "$CPP" decode "$name" "$TMP/v1/v1-$name.jwt" >/dev/null || fail "C++ rejected Go's v1 $name token"
    "$CPP" migrate "$name" "$TMP/v1/v1-$name.jwt" "$TMP/v1/v2-$name.jwt" "$seed" >/dev/null || fail "C++ could not re-encode v1 $name"
    out=$("$GO" validate "$TMP/v1/v2-$name.jwt") || fail "Go rejected the C++ v2 re-encode of v1 $name"
    printf '%s' "$out" | grep -q "type=$name" || fail "re-encoded $name has the wrong type: $out"
done
out=$("$CPP" decode generic "$TMP/v1/generic.jwt") || fail "C++ rejected Go's generic token"
[ "$out" = "CPP-DECODE-OK claimtype=generic sub=$(printf '%s' "$out" | sed 's/.* sub=\([A-Z0-9]*\).*/\1/') data=[hello n nested type version]" ] \
    || fail "C++ generic decode unexpected: $out"
"$CPP" mintgeneric "$TMP/gen-cpp" >/dev/null
out=$("$GO" generic "$TMP/gen-cpp/generic.jwt") || fail "Go DecodeGeneric rejected the C++ generic token"
printf '%s' "$out" | grep -q "claimtype=generic .* data=\[hello n type version\]" || fail "Go's view of the C++ generic: $out"
# (measured: Go's own Decode fails on Go's own v2 generics — its unknown-type
# branch returns version -1 and applies the v1 signature rule — so Go's
# working path, DecodeGeneric, is the one gated here)
check "v1 tokens decode + re-encode as v2 Go accepts; generic claims cross both ways"

# 13 ── activation hashID parity
mkdir -p "$TMP/x"
"$GO" genxaccount "$TMP/x" >/dev/null
for f in "$TMP/x"/*activation*.jwt "$TMP/v1/v1-activation.jwt" "$REPO/tests/fixtures/activation.jwt"; do
    [ -f "$f" ] || continue
    want=$("$GO" hashid "$f") || fail "Go could not hash $f"
    got=$("$CPP" hashid "$f") || fail "C++ could not hash $f"
    [ "$got" = "$want" ] || fail "hashID mismatch on $f: Go $want, C++ $got"
done
check "activation hashID equals Go's HashID() on Go-minted activations"

# 14 ── xkey-sealed callout bodies, both directions
mkdir -p "$TMP/xk"
"$CPP" xkeys "$TMP/xk" >/dev/null
"$GO" sealreq "$TMP/xk" "$(cat "$TMP/xk/service-x.pub")" >/dev/null
out=$("$CPP" openreq "$TMP/xk/sealed-req.bin" "$TMP/xk/server-x.pub" "$TMP/xk/service-x.seed") \
    || fail "C++ could not open/decode the Go-sealed request"
printf '%s' "$out" | grep -q "SEALED-REQ-OK .* user=alice" || fail "C++ opened the request but saw: $out"
"$CPP" sealresp "$TMP/xk" "$TMP/xk/server-x.pub" "$TMP/xk/service-x.seed" "$TMP/xk/user.pub" "$TMP/xk/server.pub" >/dev/null
out=$("$GO" openresp "$TMP/xk/sealed-resp.bin" "$(cat "$TMP/xk/service-x.pub")" "$TMP/xk/server-x.seed") \
    || fail "Go could not open the C++-sealed response"
[ "$out" = "sub=$(cat "$TMP/xk/user.pub") error=nope" ] || fail "Go's view of the C++ sealed response: $out"
check "xkey-sealed callout: Go-sealed request opens in C++ (xkey cross-checked); C++-sealed response opens in Go"

echo
echo "INTEROP PASS ($pass checks)"
