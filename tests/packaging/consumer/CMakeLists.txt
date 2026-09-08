# Consumer project for the packaging gate: exactly what the README tells a
# user to write — find_package + the namespaced target, nothing else.
cmake_minimum_required(VERSION 3.21)
project(natsjwt_consumer CXX)

find_package(natsjwt 1.0 CONFIG REQUIRED)

add_executable(consumer main.cpp)
# The consumer calls nkeys APIs directly (key generation), so it declares
# that dependency itself — natsjwt's nkeys linkage is PRIVATE (no natsjwt
# public header exposes nkeys types). find_package(natsjwt) already pulled
# nkeys in via find_dependency.
target_link_libraries(consumer PRIVATE natsjwt::jwt nkeys::nkeys)
