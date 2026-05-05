// Fuzz target for HTTP/2 frame parser + HPACK decoder
// Build with: cmake -DBUILD_FUZZ=ON -DCMAKE_CXX_COMPILER=clang++ ..
// Run: ./fuzz_http2 -max_len=16384

#include "http2.hpp"
#include <cstdint>
#include <cstddef>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Test HPACK decoder directly
    {
        js::HPACKDecoder decoder;
        decoder.decode(std::span<const uint8_t>(data, size));
    }

    // Test Http2Connection with fabricated preface + data
    {
        js::Http2Connection conn([](const js::HttpRequest&) -> js::HttpResponse {
            js::HttpResponse resp;
            resp.status_code = 200;
            resp.body = "OK";
            return resp;
        });

        // Prepend valid client preface to fuzz data
        std::string input(js::Http2Connection::CLIENT_PREFACE);
        input.append(reinterpret_cast<const char*>(data), size);

        conn.process_input(std::span<const char>(input.data(), input.size()));
    }

    return 0;
}
