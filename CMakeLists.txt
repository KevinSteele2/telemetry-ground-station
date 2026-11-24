cmake_minimum_required(VERSION 3.20)
project(telemetry_ground_station LANGUAGES CXX)

# C++20 for std::span (a view of bytes without copying them).
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Strict warnings on our own code only (not on GoogleTest's). -Wconversion
# flags silent narrowing, like an int quietly cut down to a byte: exactly the
# kind of bug bit-packing code invites.
set(TLM_WARNINGS -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)

# The packet library: everything the simulator and ground station share.
add_library(tlm
    src/crc16.cpp
    src/space_packet.cpp
)
target_include_directories(tlm PUBLIC include)
target_compile_options(tlm PRIVATE ${TLM_WARNINGS})

# ---------- Tests ----------
# GoogleTest is downloaded at configure time, pinned to one release, so every
# machine (and CI) builds against the same version.
include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)  # needed on Windows/MSVC, harmless elsewhere
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()
add_executable(tlm_tests
    tests/test_crc16.cpp
    tests/test_space_packet.cpp
)
target_link_libraries(tlm_tests PRIVATE tlm GTest::gtest_main)
target_compile_options(tlm_tests PRIVATE -Wall -Wextra)

include(GoogleTest)
gtest_discover_tests(tlm_tests)  # each TEST becomes its own ctest entry
