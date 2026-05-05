cmake_minimum_required(VERSION 3.20)
project(JustServer VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Enforce Clang 22+ compiler (Zero Policy Warning: -Werror)
if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "JustServer requires Clang 22+. Current compiler: ${CMAKE_CXX_COMPILER_ID}. "
                        "Use: cmake -DCMAKE_CXX_COMPILER=clang++ ..")
endif()
if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "22.0")
    message(FATAL_ERROR "JustServer requires Clang 22+. Found: ${CMAKE_CXX_COMPILER_VERSION}. "
                        "Get LLVM 22.1.4 from https://github.com/llvm/llvm-project/releases")
endif()

# Strict warnings
add_compile_options(-Wall -Wextra -Wpedantic -Werror)

# Use mold or lld linker if available
find_program(MOLD_LINKER "mold")
find_program(LLD_LINKER "ld.lld")
if(MOLD_LINKER)
    add_link_options("-fuse-ld=mold")
    message(STATUS "Using mold linker")
elseif(LLD_LINKER)
    add_link_options("-fuse-ld=lld")
    message(STATUS "Using lld linker")
endif()

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Find RE2
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(RE2 QUIET re2)
endif()
if(NOT RE2_FOUND)
    find_library(RE2_LIBRARIES NAMES re2)
    find_path(RE2_INCLUDE_DIRS NAMES re2/re2.h)
    if(RE2_LIBRARIES AND RE2_INCLUDE_DIRS)
        set(RE2_FOUND TRUE)
    else()
        message(FATAL_ERROR "RE2 library not found. Install re2-devel / libre2-dev.")
    endif()
endif()
message(STATUS "RE2 found: ${RE2_LIBRARIES}")

# Source files
set(JS_SOURCES
    src/main.cpp
    src/server.cpp
    src/worker.cpp
    src/tls_context.cpp
    src/http_parser.cpp
    src/waf.cpp
    src/ddos_guard.cpp
    src/file_handler.cpp
    src/fastcgi_client.cpp
    src/config.cpp
    src/logger.cpp
    src/metrics.cpp
    src/unicode.cpp
    src/http2.cpp
    src/websocket.cpp
    src/grpc_handler.cpp
)

add_executable(justserver ${JS_SOURCES})

target_include_directories(justserver PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
    ${RE2_INCLUDE_DIRS}
)

target_link_libraries(justserver PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    ${RE2_LIBRARIES}
    pthread
)

# Install target
install(TARGETS justserver DESTINATION bin)
install(DIRECTORY www/ DESTINATION share/justserver/www)
install(FILES config/justserver.conf DESTINATION etc/justserver)

# ===== Tests =====
option(BUILD_TESTS "Build unit tests" ON)
if(BUILD_TESTS)
    enable_testing()

    add_executable(justserver_tests
        tests/test_main.cpp
        tests/test_http_parser.cpp
        tests/test_waf.cpp
        tests/test_http2.cpp
        tests/test_unicode.cpp
        tests/test_websocket.cpp
        tests/test_grpc.cpp
        src/http_parser.cpp
        src/waf.cpp
        src/http2.cpp
        src/unicode.cpp
        src/websocket.cpp
        src/grpc_handler.cpp
        src/logger.cpp
        src/config.cpp
        src/metrics.cpp
    )

    target_include_directories(justserver_tests PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${OPENSSL_INCLUDE_DIR}
        ${RE2_INCLUDE_DIRS}
    )

    target_link_libraries(justserver_tests PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        ${RE2_LIBRARIES}
        pthread
    )

    add_test(NAME unit_tests COMMAND justserver_tests)
endif()

# ===== Fuzz targets =====
option(BUILD_FUZZ "Build fuzz testing targets (requires Clang with libFuzzer)" OFF)
if(BUILD_FUZZ)
    add_compile_options(-fsanitize=fuzzer-no-link,address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=fuzzer,address)

    add_executable(fuzz_http_parser
        fuzz/fuzz_http_parser.cpp
        src/http_parser.cpp
        src/logger.cpp
    )
    target_include_directories(fuzz_http_parser PRIVATE ${CMAKE_SOURCE_DIR}/include ${OPENSSL_INCLUDE_DIR} ${RE2_INCLUDE_DIRS})
    target_link_libraries(fuzz_http_parser PRIVATE ${RE2_LIBRARIES} pthread)

    add_executable(fuzz_http2
        fuzz/fuzz_http2.cpp
        src/http2.cpp
        src/http_parser.cpp
        src/logger.cpp
        src/metrics.cpp
    )
    target_include_directories(fuzz_http2 PRIVATE ${CMAKE_SOURCE_DIR}/include ${OPENSSL_INCLUDE_DIR} ${RE2_INCLUDE_DIRS})
    target_link_libraries(fuzz_http2 PRIVATE OpenSSL::SSL OpenSSL::Crypto ${RE2_LIBRARIES} pthread)

    add_executable(fuzz_waf
        fuzz/fuzz_waf.cpp
        src/waf.cpp
        src/unicode.cpp
        src/http_parser.cpp
        src/logger.cpp
    )
    target_include_directories(fuzz_waf PRIVATE ${CMAKE_SOURCE_DIR}/include ${OPENSSL_INCLUDE_DIR} ${RE2_INCLUDE_DIRS})
    target_link_libraries(fuzz_waf PRIVATE ${RE2_LIBRARIES} pthread)
endif()

# ===== Sanitizer build =====
option(SANITIZE "Enable AddressSanitizer + UBSan" OFF)
if(SANITIZE)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address,undefined)
    message(STATUS "AddressSanitizer + UBSan enabled")
endif()
