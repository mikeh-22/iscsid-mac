cmake_minimum_required(VERSION 3.20)

project(iscsid-mac
    VERSION     0.1.0
    DESCRIPTION "Open-source iSCSI initiator daemon for macOS"
    LANGUAGES   C
)

# ---------------------------------------------------------------------------
# Compiler requirements
# ---------------------------------------------------------------------------

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)   # Stick to C17 strictly (-std=c17)

# We target macOS 12+ (Monterey and later have full DriverKit support)
set(MACOSX_DEPLOYMENT_TARGET "12.0")
set(CMAKE_OSX_DEPLOYMENT_TARGET "${MACOSX_DEPLOYMENT_TARGET}")

# ARM64 native build (Apple Silicon)
if(NOT CMAKE_OSX_ARCHITECTURES)
    set(CMAKE_OSX_ARCHITECTURES "arm64")
endif()

# ---------------------------------------------------------------------------
# Build flags
# ---------------------------------------------------------------------------

add_compile_options(
    -Wall
    -Wextra
    -Wshadow
    -Wpointer-arith
    -Wcast-qual
    -Wstrict-prototypes
    -Wmissing-prototypes
    -Wformat=2
    -Wno-unused-parameter      # tolerate unused params in stubs
    -fstack-protector-strong
)

# Hardening
add_compile_definitions(
    MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET}"
)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-g -O0 -fsanitize=address,undefined)
    add_link_options(-fsanitize=address,undefined)
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-O2 -DNDEBUG)
endif()

# ---------------------------------------------------------------------------
# Shared include path
# ---------------------------------------------------------------------------

include_directories(${CMAKE_SOURCE_DIR}/src/shared)

# ---------------------------------------------------------------------------
# libiscsid: protocol library (shared between daemon, CLI, tests)
# ---------------------------------------------------------------------------

set(LIB_SOURCES
    src/daemon/pdu.c
    src/daemon/digest.c
    src/daemon/auth.c
    src/daemon/connection.c
    src/daemon/session.c
    src/daemon/login.c
    src/daemon/discovery.c
    src/daemon/config.c
    src/daemon/ipc.c
)

add_library(iscsid_lib STATIC ${LIB_SOURCES})
target_include_directories(iscsid_lib PUBLIC src/daemon src/shared)

# Link with CommonCrypto (built into macOS, no extra -l needed)
# and with pthread
target_link_libraries(iscsid_lib PUBLIC pthread)

# ---------------------------------------------------------------------------
# iscsid daemon executable
# ---------------------------------------------------------------------------

add_executable(iscsid src/daemon/main.c)
target_link_libraries(iscsid PRIVATE iscsid_lib)

# ---------------------------------------------------------------------------
# iscsictl CLI executable
# ---------------------------------------------------------------------------

add_executable(iscsictl src/cli/main.c)
target_link_libraries(iscsictl PRIVATE iscsid_lib)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

enable_testing()

add_executable(test_pdu tests/test_pdu.c)
target_link_libraries(test_pdu PRIVATE iscsid_lib)
add_test(NAME test_pdu COMMAND test_pdu)

add_executable(test_auth tests/test_auth.c)
target_link_libraries(test_auth PRIVATE iscsid_lib)
add_test(NAME test_auth COMMAND test_auth)

add_executable(test_digest tests/test_digest.c)
target_link_libraries(test_digest PRIVATE iscsid_lib)
add_test(NAME test_digest COMMAND test_digest)

# ---------------------------------------------------------------------------
# Installation
# ---------------------------------------------------------------------------

install(TARGETS iscsid  RUNTIME DESTINATION /usr/local/sbin)
install(TARGETS iscsictl RUNTIME DESTINATION /usr/local/bin)

install(FILES etc/iscsid.conf.sample
        DESTINATION /usr/local/etc
        RENAME iscsid.conf.sample)

install(FILES etc/io.iscsid-mac.plist
        DESTINATION /Library/LaunchDaemons)

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

message(STATUS "")
message(STATUS "iscsid-mac ${PROJECT_VERSION}")
message(STATUS "  Build type : ${CMAKE_BUILD_TYPE}")
message(STATUS "  Arch       : ${CMAKE_OSX_ARCHITECTURES}")
message(STATUS "  Deployment : macOS ${MACOSX_DEPLOYMENT_TARGET}")
message(STATUS "  Compiler   : ${CMAKE_C_COMPILER}")
message(STATUS "")
