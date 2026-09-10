cmake_minimum_required(VERSION 3.21)  # PROJECT_IS_TOP_LEVEL

# Project
# The VERSION is the single source of truth: package config version file,
# pkg-config, and jwt++ --version all derive from it.
project(nats-jwt-cpp VERSION 1.10.0 LANGUAGES CXX)

# --- Options ---------------------------------------------------------------
option(JWT_WARNINGS_AS_ERRORS "Treat warnings as errors" OFF)
option(JWT_USE_SYSTEM_GTEST "Prefer system-installed GTest if available" ON)
option(JWT_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(JWT_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(JWT_ENABLE_HARDENING "Enable security hardening flags" ON)
option(JWT_USE_SYSTEM_NKEYS "Prefer system-installed nkeys-cpp if available" ON)
option(JWT_BUILD_TESTS "Build the test suite" ${PROJECT_IS_TOP_LEVEL})
option(JWT_BUILD_DRIVER "Build the interop/e2e driver (cpp_driver); needs no GoogleTest" ${JWT_BUILD_TESTS})
option(JWT_BUILD_CLI "Build the jwt++ CLI tool" ${PROJECT_IS_TOP_LEVEL})
option(JWT_INSTALL "Generate install and package-config rules" ${PROJECT_IS_TOP_LEVEL})

# --- Global settings -------------------------------------------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
include(GNUInstallDirs)

# Helpful warnings (compiler-specific) — applied per-target to OUR code only.
# The nkeys-cpp lesson, measured on a CI runner: a global add_compile_options
# also compiles fetched third-party sources (GoogleTest, the fetched nkeys)
# with -Werror, and a newer compiler's new warnings then break the build
# inside code we don't own.
if (MSVC)
    set(JWT_WARNING_FLAGS /W4)
    if (JWT_WARNINGS_AS_ERRORS)
        list(APPEND JWT_WARNING_FLAGS /WX)
    endif()
else()
    set(JWT_WARNING_FLAGS -Wall -Wextra -Wpedantic)
    if (JWT_WARNINGS_AS_ERRORS)
        list(APPEND JWT_WARNING_FLAGS -Werror)
    endif()
endif()

# --- Sanitizers ------------------------------------------------------------
if (JWT_ENABLE_ASAN)
    if (MSVC)
        add_compile_options(/fsanitize=address)
        add_link_options(/fsanitize=address)
    else()
        add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address)
    endif()
    message(STATUS "AddressSanitizer enabled")
endif()

if (JWT_ENABLE_UBSAN)
    if (NOT MSVC)
        add_compile_options(-fsanitize=undefined -fno-omit-frame-pointer)
        add_link_options(-fsanitize=undefined)
        message(STATUS "UndefinedBehaviorSanitizer enabled")
    else()
        message(WARNING "UndefinedBehaviorSanitizer not supported on MSVC")
    endif()
endif()

# --- Security Hardening Flags ----------------------------------------------
if (JWT_ENABLE_HARDENING AND NOT MSVC)
    # Stack protection
    add_compile_options(-fstack-protector-strong)

    # Fortify source (requires -O1 or higher)
    if (CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
        add_compile_definitions(_FORTIFY_SOURCE=2)
    endif()

    # RELRO + BIND_NOW (read-only GOT after startup) - Linux only; PIC itself
    # comes from CMAKE_POSITION_INDEPENDENT_CODE above
    if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_link_options(-Wl,-z,relro,-z,now)
    endif()

    message(STATUS "Security hardening flags enabled")
endif()

# --- Dependencies ----------------------------------------------------------

# Find nkeys-cpp (required) - try system install, fallback to FetchContent
set(_have_nkeys FALSE)
if (JWT_USE_SYSTEM_NKEYS)
    find_package(nkeys QUIET)
    if (nkeys_FOUND)
        message(STATUS "Using system-installed nkeys-cpp")
        set(_have_nkeys TRUE)
        # An IMPORTED target is directory-scoped: when this project is
        # add_subdirectory'd, the embedder could not resolve nkeys::nkeys (nor
        # the $<LINK_ONLY:nkeys::nkeys> our static export carries) — measured
        # by the packaging gate's embed check on a host with nkeys installed.
        # The FetchContent path's alias is global already; match it.
        set_target_properties(nkeys::nkeys PROPERTIES IMPORTED_GLOBAL TRUE)
    endif()
endif()

if (NOT _have_nkeys)
    message(STATUS "System nkeys-cpp not found, using FetchContent to build from source")
    include(FetchContent)
    # Pinned: GIT_TAG main made every build non-reproducible and let breaking
    # upstream changes land silently. v1.1.0+ is also embed-clean (its tests,
    # CLI, and install rules are PROJECT_IS_TOP_LEVEL-gated), which is what
    # made the old BUILD_TESTING save/restore dance here removable — that
    # dance captured BUILD_TESTING BEFORE include(CTest) defined it and
    # force-restored the empty value, silently disabling THIS repo's entire
    # test suite on every fresh clone ("No tests were found!!!").
    FetchContent_Declare(
        nkeys-cpp
        GIT_REPOSITORY https://github.com/steve-weiland/nkeys-cpp.git
        GIT_TAG v1.1.0
        GIT_SHALLOW TRUE
    )
    set(NKEYS_WARNINGS_AS_ERRORS ${JWT_WARNINGS_AS_ERRORS} CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(nkeys-cpp)
    message(STATUS "Built nkeys-cpp from source via FetchContent")
endif()

# Fetch nlohmann/json (header-only) - always use FetchContent
if (NOT TARGET nlohmann_json)
    include(FetchContent)
    FetchContent_Declare(
        nlohmann_json
        URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
        URL_HASH SHA256=d6c65aca6b1ed68e7a182f4757257b107ae403032760ed6ef121c9d55e81757d
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    FetchContent_MakeAvailable(nlohmann_json)
endif()

# --- Sources ---------------------------------------------------------------
set(JWT_SOURCES
    src/jwt.cpp
    src/claims.cpp
    src/operator_claims.cpp
    src/account_claims.cpp
    src/activation_claims.cpp
    src/authorization_claims.cpp
    src/generic_claims.cpp
    src/user_claims.cpp
    src/creds.cpp
    src/base64url.cpp
    src/jwt_utils.cpp
    src/validation.cpp
)

# --- Library: jwt ----------------------------------------------------------
# Static by default; honors BUILD_SHARED_LIBS=ON. Installed as libnatsjwt —
# "libjwt" is as collision-prone as the old repo name was.
add_library(jwt
    ${JWT_SOURCES}
)
add_library(natsjwt::jwt ALIAS jwt)
set_target_properties(jwt PROPERTIES
    OUTPUT_NAME natsjwt
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)
target_compile_features(jwt PUBLIC cxx_std_20)

target_include_directories(jwt PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_include_directories(jwt PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_options(jwt PRIVATE ${JWT_WARNING_FLAGS})
# nkeys::nkeys — the namespaced name exists on BOTH paths (find_package's
# imported target, and the alias the FetchContent'd nkeys-cpp defines); the
# bare `nkeys` linked before only existed on the FetchContent path, so the
# system-nkeys configuration had never compiled (measured by the packaging
# gate). No public header includes nkeys or nlohmann (pimpl), so both are
# PRIVATE: nkeys propagates to static consumers as link-only via the export
# + find_dependency; header-only nlohmann is build-time only.
target_link_libraries(jwt PRIVATE
    nkeys::nkeys
    $<BUILD_INTERFACE:nlohmann_json::nlohmann_json>
)

# --- Executable: jwt++ -----------------------------------------------------
if (JWT_BUILD_CLI)
    add_executable(jwt++ src/tools/jwt-main.cpp)
    target_compile_options(jwt++ PRIVATE ${JWT_WARNING_FLAGS})
    target_compile_definitions(jwt++ PRIVATE JWTPP_VERSION="${PROJECT_VERSION}")
    target_link_libraries(jwt++ PRIVATE jwt nkeys::nkeys nlohmann_json::nlohmann_json)
    target_include_directories(jwt++ PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/tools
    )
endif()

# --- Tests: jwt_test (GoogleTest) ------------------------------------------
if (JWT_BUILD_TESTS)
    include(CTest)
endif()
if (JWT_BUILD_TESTS AND BUILD_TESTING)
    # Threads are needed by GTest on POSIX
    find_package(Threads REQUIRED)

    set(_have_gtest FALSE)
    # Sanitizer builds must NOT link a system (uninstrumented) GTest — libc++'s
    # ASAN container annotations disagree with uninstrumented code and GTest's
    # own argv setup reports a bogus container-overflow before any test runs
    # (measured in nkeys-cpp). Fetch and instrument it alongside the code.
    if (JWT_USE_SYSTEM_GTEST AND NOT (JWT_ENABLE_ASAN OR JWT_ENABLE_UBSAN))
        find_package(GTest QUIET)
        if (GTest_FOUND)
            set(_have_gtest TRUE)
        endif()
    endif()

    if (NOT _have_gtest)
        include(FetchContent)
        FetchContent_Declare(
            googletest
            URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
            URL_HASH SHA256=1f357c27ca988c3f7c6b4bf68a9395005ac6761f034046e9dde0896e3aba00e4
            DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        )
        # For MSVC: don't override runtime flags in gtest
        set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
        FetchContent_MakeAvailable(googletest)
        set(GTEST_LIBS GTest::gtest GTest::gtest_main)
        # Fetched GTest headers as system includes in OUR TUs, so our -Werror
        # can't fail on warnings inside gtest's inline functions.
        foreach(_gt gtest gtest_main gmock gmock_main)
            if (TARGET ${_gt})
                get_target_property(_gt_inc ${_gt} INTERFACE_INCLUDE_DIRECTORIES)
                if (_gt_inc)
                    set_target_properties(${_gt} PROPERTIES
                            INTERFACE_SYSTEM_INCLUDE_DIRECTORIES "${_gt_inc}")
                endif()
            endif()
        endforeach()
    else()
        set(GTEST_LIBS GTest::GTest GTest::Main)
    endif()

    # Absolute fixtures path so out-of-tree builds (CI, /tmp dirs) find them —
    # the nkeys-cpp lesson: CWD-relative lookup only worked for in-tree builds.
    set(JWT_FIXTURES_DEF
        JWT_TEST_FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures")

    add_executable(jwt_test tests/jwt_test.cpp)
    target_compile_options(jwt_test PRIVATE ${JWT_WARNING_FLAGS})
    target_compile_definitions(jwt_test PRIVATE ${JWT_FIXTURES_DEF})
    target_link_libraries(jwt_test PRIVATE jwt nkeys::nkeys nlohmann_json::nlohmann_json ${GTEST_LIBS} Threads::Threads)
    target_include_directories(jwt_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

    add_executable(claims_test tests/claims_test.cpp)
    target_compile_options(claims_test PRIVATE ${JWT_WARNING_FLAGS})
    target_compile_definitions(claims_test PRIVATE ${JWT_FIXTURES_DEF})
    target_link_libraries(claims_test PRIVATE jwt nkeys::nkeys nlohmann_json::nlohmann_json ${GTEST_LIBS} Threads::Threads)
    target_include_directories(claims_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

    add_executable(cmd_args_test tests/cmd_args_test.cpp)
    target_compile_options(cmd_args_test PRIVATE ${JWT_WARNING_FLAGS})
    target_link_libraries(cmd_args_test PRIVATE ${GTEST_LIBS} Threads::Threads)
    target_include_directories(cmd_args_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/tools
        ${CMAKE_CURRENT_SOURCE_DIR}/tests
    )

    add_executable(validation_test tests/validation_test.cpp)
    target_compile_options(validation_test PRIVATE ${JWT_WARNING_FLAGS})
    target_compile_definitions(validation_test PRIVATE ${JWT_FIXTURES_DEF})
    target_link_libraries(validation_test PRIVATE jwt nkeys::nkeys nlohmann_json::nlohmann_json ${GTEST_LIBS} Threads::Threads)
    target_include_directories(validation_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

    add_executable(e2e_test tests/e2e_test.cpp)
    target_compile_options(e2e_test PRIVATE ${JWT_WARNING_FLAGS})
    target_link_libraries(e2e_test PRIVATE jwt nkeys::nkeys nlohmann_json::nlohmann_json ${GTEST_LIBS} Threads::Threads)
    target_include_directories(e2e_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

    include(GoogleTest)
    gtest_discover_tests(jwt_test)
    gtest_discover_tests(claims_test)
    gtest_discover_tests(cmd_args_test)
    gtest_discover_tests(validation_test)
    gtest_discover_tests(e2e_test)
endif()

# Interop/e2e driver: the C++ half of tests/interop/run.sh and the body of
# the e2e callout service. Separate from the tests so the e2e toolbox image
# can build it WITHOUT fetching GoogleTest (JWT_BUILD_TESTS=OFF).
if (JWT_BUILD_DRIVER)
    add_executable(cpp_driver tests/interop/cpp_driver.cpp)
    target_compile_options(cpp_driver PRIVATE ${JWT_WARNING_FLAGS})
    target_link_libraries(cpp_driver PRIVATE jwt nkeys::nkeys nlohmann_json::nlohmann_json)
endif()

# --- Install + package config ----------------------------------------------
if (JWT_INSTALL)
    # Exporting requires the namespaced nkeys to be an IMPORTED (installed)
    # target — a FetchContent-built nkeys is a real target outside any export
    # set and install(EXPORT) would refuse it with a worse message.
    if (NOT nkeys_FOUND)
        message(WARNING
            "Install rules disabled: exporting natsjwt requires a "
            "system-installed nkeys-cpp (find_package(nkeys)) — a "
            "FetchContent-built nkeys cannot be exported. Building works "
            "normally; to install, install nkeys-cpp first.")
        set(JWT_INSTALL OFF)
    endif()
endif()
if (JWT_INSTALL)

    include(CMakePackageConfigHelpers)

    install(TARGETS jwt
        EXPORT natsjwtTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )

    # Public headers - preserve include/jwt/ directory structure
    install(FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/include/jwt/jwt.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/jwt/jwt_constants.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/jwt/jwt_errors.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/jwt/claims.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/jwt/operator_claims.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/jwt/account_claims.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/jwt/authorization_claims.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/jwt/validation_results.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/jwt/generic_claims.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/jwt/activation_claims.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/jwt/permissions.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/jwt/user_claims.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/jwt/creds.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/jwt/validation.hpp
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/jwt
    )

    # find_package(natsjwt): namespaced target + config + version files
    install(EXPORT natsjwtTargets
        FILE natsjwtTargets.cmake
        NAMESPACE natsjwt::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/natsjwt
    )
    configure_package_config_file(
        cmake/natsjwtConfig.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/natsjwtConfig.cmake
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/natsjwt
    )
    write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/natsjwtConfigVersion.cmake
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion
    )
    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/natsjwtConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/natsjwtConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/natsjwt
    )

    # pkg-config for non-CMake consumers
    if (IS_ABSOLUTE "${CMAKE_INSTALL_LIBDIR}")
        set(PKGCONFIG_LIBDIR "${CMAKE_INSTALL_LIBDIR}")
    else()
        set(PKGCONFIG_LIBDIR "\${prefix}/${CMAKE_INSTALL_LIBDIR}")
    endif()
    if (IS_ABSOLUTE "${CMAKE_INSTALL_INCLUDEDIR}")
        set(PKGCONFIG_INCLUDEDIR "${CMAKE_INSTALL_INCLUDEDIR}")
    else()
        set(PKGCONFIG_INCLUDEDIR "\${prefix}/${CMAKE_INSTALL_INCLUDEDIR}")
    endif()
    configure_file(cmake/natsjwt.pc.in ${CMAKE_CURRENT_BINARY_DIR}/natsjwt.pc @ONLY)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/natsjwt.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
    )

    if (JWT_BUILD_CLI)
        install(TARGETS jwt++
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        )
    endif()
endif()
