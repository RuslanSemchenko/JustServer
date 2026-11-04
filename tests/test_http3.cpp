#include "http3.hpp"

#include <cassert>
#include <iostream>

void run_http3_tests() {
    auto cid = js::QuicConnectionId::generate();
    assert(cid.len == 16);
    assert(cid == cid);
    assert(cid.to_hex().size() == cid.len * 2);

    auto bounded_cid = js::QuicConnectionId::generate(1000);
    assert(bounded_cid.len == bounded_cid.data.size());
    assert(bounded_cid.to_hex().size() == bounded_cid.len * 2);

    js::QuicConnectionId invalid;
    invalid.len = invalid.data.size() + 1;
    assert(invalid.to_hex().empty());
    assert(!(invalid == invalid));
    assert(js::QuicConnectionIdHash{}(invalid) ==
           js::QuicConnectionIdHash{}(js::QuicConnectionId{}));

    assert(!js::QuicDispatcher::decode_packet({}));
    const std::array<uint8_t, 1> truncated_packet{0xc0};
    assert(!js::QuicDispatcher::decode_packet(truncated_packet));
    std::cout << "  [PASS] HTTP/3 connection ID bounds and packet decoding\n";
}
