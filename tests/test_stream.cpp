#include "stream.hpp"

#include <array>
#include <cassert>
#include <cerrno>
#include <iostream>
#include <string>

void run_stream_tests() {
    std::string written;
    uint64_t written_stream = 0;
    int shutdown_count = 0;
    js::QuicStream stream(
        7,
        [&](uint64_t id, const void* data, size_t length) {
            written_stream = id;
            written.append(static_cast<const char*>(data), length);
            return true;
        },
        [&](uint64_t id) {
            assert(id == 7);
            ++shutdown_count;
        },
        5);

    constexpr std::string_view input = "hello";
    assert(stream.feed_data(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(input.data()), input.size())));
    constexpr std::string_view too_much = "!";
    assert(!stream.feed_data(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(too_much.data()), too_much.size())));
    assert(errno == ENOBUFS);

    std::array<char, 3> buffer{};
    assert(stream.read(buffer.data(), buffer.size()) == 3);
    assert(std::string(buffer.data(), buffer.size()) == "hel");
    assert(stream.read(buffer.data(), buffer.size()) == 2);
    assert(std::string(buffer.data(), 2) == "lo");
    assert(stream.read(buffer.data(), buffer.size()) == -1);
    assert(errno == EAGAIN);

    assert(stream.write("response", 8) == 8);
    assert(written_stream == 7);
    assert(written == "response");
    stream.shutdown();
    assert(shutdown_count == 1);
    assert(stream.write("x", 1) == -1);
    assert(errno == EPIPE);

    stream.finish_read();
    assert(!stream.is_open());
    assert(stream.read(buffer.data(), buffer.size()) == -1);
    assert(errno == EBADF);
    std::cout << "  [PASS] QUIC stream buffering and half-close behavior\n";
}
