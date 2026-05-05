// Fuzz target for WAF engine (RE2 patterns + normalizer)
// Build with: cmake -DBUILD_FUZZ=ON -DCMAKE_CXX_COMPILER=clang++ ..
// Run: ./fuzz_waf -max_len=4096

#include "waf.hpp"
#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static js::WAF waf; // Reuse across calls (RE2 compilation is expensive)

    std::string_view input(reinterpret_cast<const char*>(data), size);

    // Test normalizer pipeline
    {
        auto normalized = js::PayloadNormalizer::normalize(input);
        (void)normalized;
    }

    // Test individual normalizer steps
    {
        auto decoded = js::PayloadNormalizer::recursive_url_decode(input);
        (void)decoded;
    }

    // Test WAF inspection with fuzz data as URI
    {
        js::HttpRequest req;
        req.method = js::HttpMethod::GET;
        req.method_str = "GET";
        req.uri = std::string(input.substr(0, std::min(size, size_t(2048))));
        req.path = req.uri;
        req.version = "HTTP/1.1";

        auto verdict = waf.inspect(req);
        (void)verdict;
    }

    // Test WAF inspection with fuzz data as POST body
    {
        js::HttpRequest req;
        req.method = js::HttpMethod::POST;
        req.method_str = "POST";
        req.uri = "/api";
        req.path = "/api";
        req.version = "HTTP/1.1";
        req.body = std::string(input);

        auto verdict = waf.inspect(req);
        (void)verdict;
    }

    return 0;
}
