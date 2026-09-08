#!/usr/bin/env sh
# run.sh — the Go README's ending, made a gate: prove that a trust chain
# minted ENTIRELY by this library authenticates against a real nats-server.
#
# cpp_driver bootstrap emits the README flow verbatim (operator with signing
# key; account self-signed then re-signed by the operator signing key; user
# issued by an account signing key with issuer_account; u.creds; and a
# memory-resolver resolver.conf). This script then:
#
#   1. starts nats-server (docker, pinned) with that resolver.conf
#   2. positive: a request/reply round trip authenticated by u.creds
#   3. negative control: the same connection WITHOUT creds is refused
#      (proves the server is actually enforcing the operator-mode auth our
#      chain is supposed to satisfy — without this, check 2 could pass
#      against an open server)
#
# usage: tests/e2e-server/run.sh <cmake-build-dir>   (requires docker)
set -eu

BUILD_DIR=${1:?usage: run.sh <cmake-build-dir>}
CPP="$BUILD_DIR/cpp_driver"
[ -x "$CPP" ] || CPP="$BUILD_DIR/tests/e2e-server/../interop/cpp_driver"
[ -x "$CPP" ] || { echo "cpp_driver not found under $BUILD_DIR" >&2; exit 1; }

NATS_IMG=nats:2.10-alpine
BOX_IMG=natsio/nats-box:0.14.5
NET="natsjwt-e2e-$$"
SRV="natsjwt-server-$$"

WORK=$(mktemp -d)
cleanup() {
    docker rm -f "$SRV" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

pass=0
check() { pass=$((pass+1)); echo "  ok $pass: $1"; }
fail() { echo "  FAIL: $1" >&2; exit 1; }

echo "e2e-server: minting the README trust chain"
"$CPP" bootstrap "$WORK" >/dev/null
chmod 644 "$WORK"/u.creds "$WORK"/resolver.conf

docker network create "$NET" >/dev/null
docker run -d --name "$SRV" --network "$NET" \
    -v "$WORK":/conf:ro "$NATS_IMG" -c /conf/resolver.conf >/dev/null

# readiness: rtt needs auth in operator mode, so poll with the creds
i=0
until docker run --rm --network "$NET" -v "$WORK":/w:ro "$BOX_IMG" \
        nats --server nats://"$SRV":4222 --creds /w/u.creds rtt >/dev/null 2>&1; do
    i=$((i+1))
    [ "$i" -le 15 ] || { docker logs "$SRV" 2>&1 | tail -5 >&2; fail "server did not become ready / creds rejected"; }
    sleep 1
done
check "nats-server up with the C++-minted resolver.conf; creds accepted (rtt)"

# 2 ── authenticated request/reply round trip
out=$(docker run --rm --network "$NET" -v "$WORK":/w:ro "$BOX_IMG" sh -c "
    nats --server nats://$SRV:4222 --creds /w/u.creds reply demo.svc pong --count 1 >/dev/null 2>&1 &
    sleep 1
    nats --server nats://$SRV:4222 --creds /w/u.creds request demo.svc ping 2>/dev/null")
printf '%s' "$out" | grep -q "pong" || fail "request/reply round trip failed: $out"
check "authenticated request/reply round trip (pub + sub permissions live)"

# 3 ── negative control: no creds → refused
if docker run --rm --network "$NET" "$BOX_IMG" \
        nats --server nats://"$SRV":4222 rtt >/dev/null 2>&1; then
    fail "server accepted a connection WITHOUT credentials — auth not enforced"
fi
check "negative control: connection without creds is refused"

echo
echo "E2E-SERVER PASS ($pass checks) — this library's chain authenticates against a real nats-server"
