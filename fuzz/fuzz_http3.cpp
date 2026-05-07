// HTTP/3 (QUIC) Fuzzer (libFuzzer)
// Fuzzes the HTTP/3 connection by feeding malformed QUIC UDP packets.
// Tests resilience against corrupted QUIC frames and HTTP/3 streams.

#include "http3.hpp"
#include "http_parser.hpp"
#include "logger.hpp"

#include <cstdint>
#include <cstring>
#include <span>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    if (size > 65536) return 0; // Limit input size

    // Create an HTTP/3 connection with a dummy request handler
    js::QuicTransportParams params;
    js::Http3Connection conn(
        [](const js::HttpRequest& req) -> js::HttpResponse {
            return js::HttpResponse::make_error(200, "OK");
        },
        params
    );

    // Feed fuzzed data as incoming UDP QUIC packets
    auto packets = conn.process_input(
        std::span<const uint8_t>(data, size),
        "127.0.0.1:1234"
    );

    // Exercise the output
    for (const auto& pkt : packets) {
        (void)pkt.data.size();
    }

    // Exercise timer path
    auto timeout = conn.next_timeout();
    (void)timeout;
    (void)conn.is_alive();
    (void)conn.is_handshake_complete();

    return 0;
}
