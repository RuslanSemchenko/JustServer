// Fuzz target for HTTP/1.1 parser
// Build with: cmake -DBUILD_FUZZ=ON -DCMAKE_CXX_COMPILER=clang++ ..
// Run: ./fuzz_http_parser -max_len=8192

#include "http_parser.hpp"
#include <cstdint>
#include <cstddef>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    js::HttpParser parser;

    // Feed the entire input at once
    auto state = parser.feed(std::span<const char>(
        reinterpret_cast<const char*>(data), size));

    // Also test incremental feeding (split at midpoint)
    if (size > 2) {
        js::HttpParser parser2;
        size_t mid = size / 2;
        parser2.feed(std::span<const char>(
            reinterpret_cast<const char*>(data), mid));
        parser2.feed(std::span<const char>(
            reinterpret_cast<const char*>(data + mid), size - mid));
    }

    // Test reset + re-feed
    parser.reset();
    parser.feed(std::span<const char>(
        reinterpret_cast<const char*>(data), size));

    (void)state;
    return 0;
}
