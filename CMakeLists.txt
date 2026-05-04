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
)

add_executable(justserver ${JS_SOURCES})

target_include_directories(justserver PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(justserver PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    pthread
)

# Install target
install(TARGETS justserver DESTINATION bin)
install(DIRECTORY www/ DESTINATION share/justserver/www)
install(FILES config/justserver.conf DESTINATION etc/justserver)
