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
#include <netinet/in.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    if (size > 65536) return 0; // Limit input size

    auto packet = js::QuicDispatcher::decode_packet(
        std::span<const uint8_t>(data, size));
    if (packet) {
        (void)packet->dcid.to_hex();
        (void)packet->scid.to_hex();
        (void)js::QuicConnectionIdHash{}(packet->dcid);
        (void)packet->initial;
    }

    // Create an HTTP/3 connection with a dummy request handler
    js::QuicTransportParams params;
    js::Http3Connection conn(
        [](const js::HttpRequest&, const std::string&) -> js::HttpResponse {
            return js::HttpResponse::make_error(200, "OK");
        },
        params, "127.0.0.1"
    );

    // Feed fuzzed data as incoming UDP QUIC packets
    sockaddr_in local_addr{};
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(443);
    sockaddr_in remote_addr{};
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(1234);
    auto packets = conn.process_input(
        std::span<const uint8_t>(data, size),
        reinterpret_cast<const sockaddr*>(&local_addr), sizeof(local_addr),
        reinterpret_cast<const sockaddr*>(&remote_addr), sizeof(remote_addr)
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
