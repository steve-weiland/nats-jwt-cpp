#!/usr/bin/env sh
# run.sh — the live Go↔C++ interop matrix (the gate CI runs; also runnable
# locally). Pairs this library against the reference Go nats-io/jwt through
# two CLIs: cpp_driver (built by CMake with tests) and the Go probe here.
#
#   usage: tests/interop/run.sh <cmake-build-dir>
#
# Seven checks:
#   1. C++-minted operator/account/user JWTs pass Go's authenticated Decode
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
#   7. round-trip: Go decodes a C++ user token, C++ decodes it back
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
check "C++-minted operator/account/user pass Go's authenticated Decode"

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

# 7 ── round-trip sanity
"$GO" decode "$TMP/cpp/user.jwt" >/dev/null && "$CPP" decode user "$TMP/cpp/user.jwt" >/dev/null \
    || fail "round-trip decode failed"
check "round-trip: both sides decode the same C++ user token"

echo
echo "INTEROP PASS ($pass checks)"
