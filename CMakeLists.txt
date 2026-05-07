cmake_minimum_required(VERSION 3.20)
project(JustServer VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Enforce Clang 18+ compiler (Zero Policy Warning: -Werror)
if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "JustServer requires Clang 22+. Current compiler: ${CMAKE_CXX_COMPILER_ID}. "
                        "Use: cmake -DCMAKE_CXX_COMPILER=clang++ ..")
endif()
if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "18.0")
    message(FATAL_ERROR "JustServer requires Clang 22+. Found: ${CMAKE_CXX_COMPILER_VERSION}. "
                        "Get LLVM from https://github.com/llvm/llvm-project/releases")
endif()

# Strict warnings
add_compile_options(-Wall -Wextra -Wpedantic -Werror -Wno-error=unused-parameter)

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

# Find liburing (io_uring)
if(PkgConfig_FOUND)
    pkg_check_modules(URING QUIET liburing)
endif()
if(NOT URING_FOUND)
    find_library(URING_LIBRARIES NAMES uring)
    find_path(URING_INCLUDE_DIRS NAMES liburing.h)
    if(URING_LIBRARIES AND URING_INCLUDE_DIRS)
        set(URING_FOUND TRUE)
    else()
        message(FATAL_ERROR "liburing not found. Install liburing-devel / liburing-dev.")
    endif()
endif()
message(STATUS "liburing found: ${URING_LIBRARIES}")

# Find Brotli
find_library(BROTLI_ENC_LIBRARY NAMES brotlienc)
find_library(BROTLI_DEC_LIBRARY NAMES brotlidec)
find_path(BROTLI_INCLUDE_DIRS NAMES brotli/encode.h)
if(BROTLI_ENC_LIBRARY AND BROTLI_DEC_LIBRARY AND BROTLI_INCLUDE_DIRS)
    set(BROTLI_FOUND TRUE)
    set(BROTLI_LIBRARIES ${BROTLI_ENC_LIBRARY} ${BROTLI_DEC_LIBRARY})
    message(STATUS "Brotli found: ${BROTLI_LIBRARIES}")
else()
    message(FATAL_ERROR "Brotli not found. Install brotli-devel / libbrotli-dev.")
endif()

# Find Zstd
find_library(ZSTD_LIBRARIES NAMES zstd)
find_path(ZSTD_INCLUDE_DIRS NAMES zstd.h)
if(ZSTD_LIBRARIES AND ZSTD_INCLUDE_DIRS)
    set(ZSTD_FOUND TRUE)
    message(STATUS "Zstd found: ${ZSTD_LIBRARIES}")
else()
    message(FATAL_ERROR "Zstd not found. Install libzstd-devel / libzstd-dev.")
endif()

# Find ngtcp2 (QUIC)
find_library(NGTCP2_LIBRARIES NAMES ngtcp2 HINTS /usr/local/lib64 /usr/local/lib)
find_path(NGTCP2_INCLUDE_DIRS NAMES ngtcp2/ngtcp2.h HINTS /usr/local/include)
if(NGTCP2_LIBRARIES AND NGTCP2_INCLUDE_DIRS)
    set(NGTCP2_FOUND TRUE)
    message(STATUS "ngtcp2 found: ${NGTCP2_LIBRARIES}")
else()
    message(FATAL_ERROR "ngtcp2 not found. Build from https://github.com/ngtcp2/ngtcp2")
endif()

# Find nghttp3 (HTTP/3)
find_library(NGHTTP3_LIBRARIES NAMES nghttp3 HINTS /usr/local/lib64 /usr/local/lib)
find_path(NGHTTP3_INCLUDE_DIRS NAMES nghttp3/nghttp3.h HINTS /usr/local/include)
if(NGHTTP3_LIBRARIES AND NGHTTP3_INCLUDE_DIRS)
    set(NGHTTP3_FOUND TRUE)
    message(STATUS "nghttp3 found: ${NGHTTP3_LIBRARIES}")
else()
    message(FATAL_ERROR "nghttp3 not found. Build from https://github.com/ngtcp2/nghttp3")
endif()

# Source files
set(JS_SOURCES
    # Original sources
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

    # Stage 1: Core & I/O
    src/stream.cpp
    src/io_uring_loop.cpp

    # Stage 2: Transport & Crypto
    src/compression.cpp
    src/acme_client.cpp

    # Stage 3: Gateway & Balancer
    src/load_balancer.cpp
    src/cache.cpp
    src/proxy.cpp
    src/tracing.cpp

    # Stage 4: WAF 2.0 / Zero Trust
    src/jwt_validator.cpp

    # Stage 5: Anti-Bot
    src/anti_bot.cpp

    # HTTP/3 & QUIC
    src/http3.cpp

    # Stage 6: WASM Plugins
    src/wasm_plugin.cpp
)

add_executable(justserver ${JS_SOURCES})

target_include_directories(justserver PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
    ${RE2_INCLUDE_DIRS}
    ${URING_INCLUDE_DIRS}
    ${BROTLI_INCLUDE_DIRS}
    ${ZSTD_INCLUDE_DIRS}
    ${NGTCP2_INCLUDE_DIRS}
    ${NGHTTP3_INCLUDE_DIRS}
)

target_link_libraries(justserver PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    ${RE2_LIBRARIES}
    ${URING_LIBRARIES}
    ${BROTLI_LIBRARIES}
    ${ZSTD_LIBRARIES}
    ${NGTCP2_LIBRARIES}
    ${NGHTTP3_LIBRARIES}
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
        tests/test_arena.cpp
        tests/test_compression.cpp
        tests/test_cache.cpp
        tests/test_load_balancer.cpp
        tests/test_jwt.cpp
        tests/test_anti_bot.cpp
        tests/test_tracing.cpp
        # Source files needed by tests
        src/http_parser.cpp
        src/waf.cpp
        src/http2.cpp
        src/unicode.cpp
        src/websocket.cpp
        src/grpc_handler.cpp
        src/logger.cpp
        src/config.cpp
        src/metrics.cpp
        src/compression.cpp
        src/cache.cpp
        src/load_balancer.cpp
        src/jwt_validator.cpp
        src/anti_bot.cpp
        src/tracing.cpp
        src/stream.cpp
        src/wasm_plugin.cpp
    )

    # Tests use assert() which is no-op in Release, causing unused variable warnings
    target_compile_options(justserver_tests PRIVATE -Wno-unused-variable -Wno-unused-but-set-variable)

    target_include_directories(justserver_tests PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${OPENSSL_INCLUDE_DIR}
        ${RE2_INCLUDE_DIRS}
        ${URING_INCLUDE_DIRS}
        ${BROTLI_INCLUDE_DIRS}
        ${ZSTD_INCLUDE_DIRS}
    )

    target_link_libraries(justserver_tests PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        ${RE2_LIBRARIES}
        ${BROTLI_LIBRARIES}
        ${ZSTD_LIBRARIES}
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

    # JWT validator fuzzer -- tests the state-machine JSON parser
    add_executable(fuzz_jwt
        fuzz/fuzz_jwt.cpp
        src/jwt_validator.cpp
        src/logger.cpp
    )
    target_include_directories(fuzz_jwt PRIVATE ${CMAKE_SOURCE_DIR}/include ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(fuzz_jwt PRIVATE OpenSSL::SSL OpenSSL::Crypto pthread)

    # FastCGI protocol fuzzer -- tests response parsing robustness
    add_executable(fuzz_fastcgi
        fuzz/fuzz_fastcgi.cpp
        src/fastcgi_client.cpp
        src/http_parser.cpp
        src/logger.cpp
    )
    target_include_directories(fuzz_fastcgi PRIVATE ${CMAKE_SOURCE_DIR}/include ${OPENSSL_INCLUDE_DIR} ${RE2_INCLUDE_DIRS})
    target_link_libraries(fuzz_fastcgi PRIVATE ${RE2_LIBRARIES} pthread)

    # HTTP/3 QUIC fuzzer -- tests QUIC frame/stream parsing
    add_executable(fuzz_http3
        fuzz/fuzz_http3.cpp
        src/http3.cpp
        src/http_parser.cpp
        src/stream.cpp
        src/logger.cpp
        src/metrics.cpp
    )
    target_include_directories(fuzz_http3 PRIVATE
        ${CMAKE_SOURCE_DIR}/include ${OPENSSL_INCLUDE_DIR} ${RE2_INCLUDE_DIRS}
        ${NGTCP2_INCLUDE_DIRS} ${NGHTTP3_INCLUDE_DIRS}
    )
    target_link_libraries(fuzz_http3 PRIVATE
        OpenSSL::SSL OpenSSL::Crypto
        ${NGTCP2_LIBRARIES} ${NGHTTP3_LIBRARIES}
        ${RE2_LIBRARIES} pthread
    )
endif()

# ===== Sanitizer build =====
option(SANITIZE "Enable AddressSanitizer + UBSan" OFF)
if(SANITIZE)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address,undefined)
    message(STATUS "AddressSanitizer + UBSan enabled")
endif()
