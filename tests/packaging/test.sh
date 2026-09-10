#!/usr/bin/env sh
# test.sh — the packaging gate (CI runs it; also runnable locally).
# Proves the library is consumable every way the README advertises:
#
#   1. install → find_package(natsjwt) consumer builds, links natsjwt::jwt, runs
#   2. same, with BUILD_SHARED_LIBS=ON
#   3. pkg-config: compile the consumer with `pkg-config --cflags --libs natsjwt`
#   4. add_subdirectory embed: natsjwt::jwt resolves; no test/CLI targets leak
#
# Installing requires a system-installed nkeys-cpp (a FetchContent-built nkeys
# cannot be exported), so the gate first installs nkeys-cpp v1.1.0 from GitHub
# into the same prefix — which also exercises the JWT_USE_SYSTEM_NKEYS path.
#
# usage: tests/packaging/test.sh
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=$(CDPATH= cd -- "$HERE/../.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

pass=0
check() { pass=$((pass+1)); echo "  ok $pass: $1"; }
fail() { echo "  FAIL: $1" >&2; exit 1; }

PREFIX="$WORK/prefix"

echo "packaging: installing nkeys-cpp v1.1.0 into the test prefix"
git clone -q -c advice.detachedHead=false --depth 1 --branch v1.1.0 https://github.com/steve-weiland/nkeys-cpp.git "$WORK/nkeys"
cmake -S "$WORK/nkeys" -B "$WORK/nkeys-b" -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX="$PREFIX" -DNKEYS_BUILD_TESTS=OFF -DNKEYS_BUILD_CLI=OFF >/dev/null
cmake --build "$WORK/nkeys-b" -j >/dev/null
cmake --install "$WORK/nkeys-b" >/dev/null

# 1 ── static install → find_package consumer (system-nkeys path exercised)
cmake -S "$REPO" -B "$WORK/b-static" -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX="$PREFIX" -DCMAKE_PREFIX_PATH="$PREFIX" \
      -DJWT_BUILD_TESTS=OFF >/dev/null
cmake --build "$WORK/b-static" -j >/dev/null
cmake --install "$WORK/b-static" >/dev/null
cmake -S "$HERE/consumer" -B "$WORK/c-static" -DCMAKE_PREFIX_PATH="$PREFIX" >/dev/null
cmake --build "$WORK/c-static" -j >/dev/null
[ "$("$WORK/c-static/consumer")" = "CONSUMER-OK" ] || fail "static find_package consumer did not run"
check "find_package consumer builds and runs (static, system nkeys)"

# 2 ── shared install → find_package consumer
PREFIX2="$WORK/prefix-shared"
cmake -S "$WORK/nkeys" -B "$WORK/nkeys-b2" -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX="$PREFIX2" -DNKEYS_BUILD_TESTS=OFF -DNKEYS_BUILD_CLI=OFF >/dev/null
cmake --build "$WORK/nkeys-b2" -j >/dev/null
cmake --install "$WORK/nkeys-b2" >/dev/null
cmake -S "$REPO" -B "$WORK/b-shared" -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX="$PREFIX2" -DCMAKE_PREFIX_PATH="$PREFIX2" \
      -DBUILD_SHARED_LIBS=ON -DJWT_BUILD_TESTS=OFF >/dev/null
cmake --build "$WORK/b-shared" -j >/dev/null
cmake --install "$WORK/b-shared" >/dev/null
{ ls "$PREFIX2"/lib*/libnatsjwt.so* >/dev/null 2>&1 || ls "$PREFIX2"/lib*/libnatsjwt.*dylib >/dev/null 2>&1; } \
    || fail "BUILD_SHARED_LIBS=ON did not install a shared libnatsjwt"
cmake -S "$HERE/consumer" -B "$WORK/c-shared" -DCMAKE_PREFIX_PATH="$PREFIX2" >/dev/null
cmake --build "$WORK/c-shared" -j >/dev/null
[ "$("$WORK/c-shared/consumer")" = "CONSUMER-OK" ] || fail "shared find_package consumer did not run"
check "find_package consumer builds and runs (BUILD_SHARED_LIBS=ON)"

# 3 ── pkg-config consumer (against the static install)
if command -v pkg-config >/dev/null 2>&1; then
    PC_DIR=$(dirname "$(find "$PREFIX" -name natsjwt.pc)")
    # shellcheck disable=SC2046
    c++ -std=c++20 "$HERE/consumer/main.cpp" \
        $(PKG_CONFIG_PATH="$PC_DIR" pkg-config --cflags --libs natsjwt) -o "$WORK/pc-consumer"
    [ "$("$WORK/pc-consumer")" = "CONSUMER-OK" ] || fail "pkg-config consumer did not run"
    check "pkg-config consumer builds and runs"
elif [ -n "${CI:-}" ]; then
    fail "pkg-config is not installed on this CI runner — the natsjwt.pc check cannot run"
else
    echo "  -- pkg-config not present: check skipped (not counted; CI requires it)"
fi

# 4 ── add_subdirectory embed: alias works, top-level-only targets stay out
mkdir -p "$WORK/embed"
cp "$HERE/consumer/main.cpp" "$WORK/embed/main.cpp"
cat > "$WORK/embed/CMakeLists.txt" <<EMBED
cmake_minimum_required(VERSION 3.21)
project(embed CXX)
add_subdirectory("$REPO" natsjwt)
add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE natsjwt::jwt nkeys::nkeys)
foreach(_t jwt_test claims_test cmd_args_test validation_test e2e_test cpp_driver jwt++)
    if (TARGET \${_t})
        message(FATAL_ERROR "top-level-only target \${_t} leaked into the embed")
    endif()
endforeach()
EMBED
cmake -S "$WORK/embed" -B "$WORK/embed-b" >/dev/null
cmake --build "$WORK/embed-b" -j >/dev/null
[ "$("$WORK/embed-b/consumer")" = "CONSUMER-OK" ] || fail "embedded consumer did not run"
check "add_subdirectory embed: alias resolves, no test/CLI targets leak"

echo
echo "PACKAGING PASS ($pass checks)"
