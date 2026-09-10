// Exercises one call from each API family so the gate proves linkage and
// behavior, not just that headers were found. nkeys is used directly too, so
// the consumer proves nkeys::nkeys resolves in the consumer's scope.
#include <jwt/jwt.hpp>
#include <nkeys/nkeys.hpp>
#include <cstdio>

int main() {
    auto okp = nkeys::CreateOperator();
    jwt::OperatorClaims oc(okp->publicString());
    oc.setName("pkg");
    auto op_jwt = oc.encode(okp->seedString());
    if (!jwt::verify(op_jwt)) return 1;

    auto decoded = jwt::decodeOperatorClaims(op_jwt);
    if (decoded->name().value_or("") != "pkg") return 1;

    try {
        (void)jwt::decode("garbage");
        return 1;
    } catch (const jwt::Error&) {
    }

    if (!jwt::validate(op_jwt)) return 1;

    std::puts("CONSUMER-OK");
    return 0;
}
