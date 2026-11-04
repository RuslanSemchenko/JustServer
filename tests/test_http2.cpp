#include "http2.hpp"
#include <iostream>
#include <functional>
#include <cstring>

bool register_test(const char* name, std::function<bool()> func);

#define TEST(name) \
    static bool test_##name(); \
    static bool _reg_##name = register_test(#name, test_##name); \
    static bool test_##name()

#define ASSERT_TRUE(expr) \
    do { if (!(expr)) { std::cerr << "  FAIL: " << #expr << " at " << __FILE__ << ":" << __LINE__ << "\n"; return false; } } while(0)
#define ASSERT_FALSE(expr) ASSERT_TRUE(!(expr))
#define ASSERT_EQ(a, b) \
    do { if ((a) != (b)) { std::cerr << "  FAIL: " << #a << " != " << #b << " at " << __FILE__ << ":" << __LINE__ << "\n"; return false; } } while(0)

using namespace js;

TEST(hpack_decode_indexed_header) {
    HPACKDecoder decoder;
    // Indexed header field: index 2 = :method GET
    uint8_t data[] = {0x82}; // 1000 0010 = indexed, index 2
    auto result = decoder.decode(std::span<const uint8_t>(data, 1));
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->size(), 1u);
    ASSERT_EQ((*result)[0].first, ":method");
    ASSERT_EQ((*result)[0].second, "GET");
    return true;
}

TEST(hpack_decode_multiple_indexed) {
    HPACKDecoder decoder;
    // :method GET (82), :path / (84), :scheme https (87)
    uint8_t data[] = {0x82, 0x84, 0x87};
    auto result = decoder.decode(std::span<const uint8_t>(data, 3));
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->size(), 3u);
    ASSERT_EQ((*result)[0].first, ":method");
    ASSERT_EQ((*result)[0].second, "GET");
    ASSERT_EQ((*result)[1].first, ":path");
    ASSERT_EQ((*result)[1].second, "/");
    ASSERT_EQ((*result)[2].first, ":scheme");
    ASSERT_EQ((*result)[2].second, "https");
    return true;
}

TEST(hpack_decode_literal_with_indexing) {
    HPACKDecoder decoder;
    // Literal with incremental indexing, new name
    // 0x40, name="x-custom", value="test"
    uint8_t data[] = {
        0x40,                                  // Literal with indexing, new name
        0x08,                                  // Name length = 8
        'x', '-', 'c', 'u', 's', 't', 'o', 'm',
        0x04,                                  // Value length = 4
        't', 'e', 's', 't'
    };
    auto result = decoder.decode(std::span<const uint8_t>(data, sizeof(data)));
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->size(), 1u);
    ASSERT_EQ((*result)[0].first, "x-custom");
    ASSERT_EQ((*result)[0].second, "test");
    return true;
}

TEST(hpack_decode_literal_indexed_name) {
    HPACKDecoder decoder;
    // Literal without indexing, indexed name
    // Name index 1 = ":authority", value = "example.com"
    uint8_t data[] = {
        0x01,                                  // Without indexing, name index 1
        0x0b,                                  // Value length = 11
        'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'
    };
    auto result = decoder.decode(std::span<const uint8_t>(data, sizeof(data)));
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->size(), 1u);
    ASSERT_EQ((*result)[0].first, ":authority");
    ASSERT_EQ((*result)[0].second, "example.com");
    return true;
}

TEST(hpack_encoder_indexed) {
    HPACKEncoder encoder;
    // Encode :method GET - should be fully indexed (index 2)
    std::vector<std::pair<std::string, std::string>> headers = {
        {":method", "GET"}
    };
    auto encoded = encoder.encode(headers);
    ASSERT_TRUE(!encoded.empty());
    ASSERT_EQ(static_cast<uint8_t>(encoded[0]), 0x82u); // Indexed, index 2
    return true;
}

TEST(hpack_roundtrip) {
    HPACKEncoder encoder;
    HPACKDecoder decoder;

    std::vector<std::pair<std::string, std::string>> headers = {
        {":method", "GET"},
        {":path", "/"},
        {":scheme", "https"},
    };

    auto encoded = encoder.encode(headers);
    auto decoded = decoder.decode(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(encoded.data()), encoded.size()));

    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded->size(), 3u);
    ASSERT_EQ((*decoded)[0].first, ":method");
    ASSERT_EQ((*decoded)[0].second, "GET");
    ASSERT_EQ((*decoded)[1].first, ":path");
    ASSERT_EQ((*decoded)[1].second, "/");
    ASSERT_EQ((*decoded)[2].first, ":scheme");
    ASSERT_EQ((*decoded)[2].second, "https");
    return true;
}

TEST(h2_connection_invalid_preface) {
    bool request_called = false;
    Http2Connection conn([&](const HttpRequest&) -> HttpResponse {
        request_called = true;
        return HttpResponse::make_error(200, "OK");
    });

    std::string garbage = "NOT A VALID PREFACE DATA HERE!!";
    auto output = conn.process_input(std::span<const char>(garbage.data(), garbage.size()));
    ASSERT_FALSE(conn.is_alive());
    ASSERT_FALSE(request_called);
    return true;
}

TEST(h2_connection_valid_preface_and_settings) {
    Http2Connection conn([](const HttpRequest&) -> HttpResponse {
        HttpResponse resp;
        resp.status_code = 200;
        resp.body = "OK";
        return resp;
    });

    // Send client preface
    std::string preface(Http2Connection::CLIENT_PREFACE);

    // Add empty SETTINGS frame
    char settings_frame[9] = {};
    settings_frame[3] = 0x04; // SETTINGS type
    // length = 0, flags = 0, stream_id = 0
    preface.append(settings_frame, 9);

    auto output = conn.process_input(std::span<const char>(preface.data(), preface.size()));
    ASSERT_TRUE(conn.is_alive());
    // Server should have sent its own SETTINGS + SETTINGS ACK
    ASSERT_TRUE(output.size() > 9);
    return true;
}

TEST(h2_frame_ping) {
    Http2Connection conn([](const HttpRequest&) -> HttpResponse {
        return HttpResponse::make_error(200, "OK");
    });

    // Send preface + empty settings
    std::string data(Http2Connection::CLIENT_PREFACE);
    char settings[9] = {};
    settings[3] = 0x04;
    data.append(settings, 9);

    auto output = conn.process_input(std::span<const char>(data.data(), data.size()));
    ASSERT_TRUE(conn.is_alive());

    // Now send a PING frame
    char ping[9 + 8] = {};
    ping[2] = 8;          // Length = 8
    ping[3] = 0x06;       // Type = PING
    // 8 bytes of opaque data
    for (int i = 0; i < 8; ++i) ping[9 + i] = static_cast<char>(i + 1);

    std::string ping_data(ping, sizeof(ping));
    auto ping_output = conn.process_input(std::span<const char>(ping_data.data(), ping_data.size()));
    // Should get a PING ACK back
    ASSERT_TRUE(ping_output.size() >= 17); // 9 header + 8 payload
    return true;
}

// ===== Connection-level helpers: build client frames, parse server frames =====

namespace {

struct TestFrame {
    uint8_t type = 0;
    uint8_t flags = 0;
    uint32_t stream_id = 0;
    std::string payload;
};

std::string make_frame(uint8_t type, uint8_t flags, uint32_t stream_id, std::string_view payload) {
    std::string f(9, '\0');
    f[0] = static_cast<char>((payload.size() >> 16) & 0xFF);
    f[1] = static_cast<char>((payload.size() >> 8) & 0xFF);
    f[2] = static_cast<char>(payload.size() & 0xFF);
    f[3] = static_cast<char>(type);
    f[4] = static_cast<char>(flags);
    f[5] = static_cast<char>((stream_id >> 24) & 0x7F);
    f[6] = static_cast<char>((stream_id >> 16) & 0xFF);
    f[7] = static_cast<char>((stream_id >> 8) & 0xFF);
    f[8] = static_cast<char>(stream_id & 0xFF);
    f.append(payload);
    return f;
}

std::vector<TestFrame> parse_frames(std::string_view data) {
    std::vector<TestFrame> frames;
    while (data.size() >= 9) {
        size_t len = (static_cast<size_t>(static_cast<uint8_t>(data[0])) << 16) |
                     (static_cast<size_t>(static_cast<uint8_t>(data[1])) << 8) |
                     static_cast<size_t>(static_cast<uint8_t>(data[2]));
        if (data.size() < 9 + len) break;
        TestFrame f;
        f.type = static_cast<uint8_t>(data[3]);
        f.flags = static_cast<uint8_t>(data[4]);
        f.stream_id = (static_cast<uint32_t>(static_cast<uint8_t>(data[5]) & 0x7F) << 24) |
                      (static_cast<uint32_t>(static_cast<uint8_t>(data[6])) << 16) |
                      (static_cast<uint32_t>(static_cast<uint8_t>(data[7])) << 8) |
                      static_cast<uint32_t>(static_cast<uint8_t>(data[8]));
        f.payload = std::string(data.substr(9, len));
        frames.push_back(std::move(f));
        data.remove_prefix(9 + len);
    }
    return frames;
}

std::string feed(Http2Connection& conn, const std::string& data) {
    return conn.process_input(std::span<const char>(data.data(), data.size()));
}

std::string handshake_bytes() {
    std::string data(Http2Connection::CLIENT_PREFACE);
    data += make_frame(0x4, 0, 0, "");
    return data;
}

std::string request_headers_block(HPACKEncoder& enc, const std::string& method, const std::string& path,
                                  std::vector<std::pair<std::string, std::string>> extra = {}) {
    std::vector<std::pair<std::string, std::string>> h = {
        {":method", method}, {":scheme", "https"}, {":path", path}, {":authority", "localhost"}};
    for (auto& kv : extra) h.push_back(std::move(kv));
    return enc.encode(h);
}

std::string window_update(uint32_t stream_id, uint32_t inc) {
    std::string p(4, '\0');
    p[0] = static_cast<char>((inc >> 24) & 0x7F);
    p[1] = static_cast<char>((inc >> 16) & 0xFF);
    p[2] = static_cast<char>((inc >> 8) & 0xFF);
    p[3] = static_cast<char>(inc & 0xFF);
    return make_frame(0x8, 0, stream_id, p);
}

size_t data_bytes_for(const std::vector<TestFrame>& frames, uint32_t stream_id, bool* end_stream = nullptr) {
    size_t total = 0;
    for (const auto& f : frames) {
        if (f.type == 0x0 && f.stream_id == stream_id) {
            total += f.payload.size();
            if (end_stream && (f.flags & 0x1)) *end_stream = true;
        }
    }
    return total;
}

} // namespace

TEST(h2_get_request_roundtrip) {
    std::string seen_cookie;
    Http2Connection conn([&](const HttpRequest& req) -> HttpResponse {
        seen_cookie = std::string(req.get_header("cookie"));
        HttpResponse resp;
        resp.body = "hello h2";
        resp.headers["Content-Type"] = "text/plain";
        resp.headers["Connection"] = "close"; // must be stripped for HTTP/2
        return resp;
    });

    HPACKEncoder enc;
    auto block = request_headers_block(enc, "GET", "/index.html", {{"cookie", "a=1"}, {"cookie", "b=2"}});
    auto out = feed(conn, handshake_bytes() + make_frame(0x1, 0x4 | 0x1, 1, block));
    auto frames = parse_frames(out);

    bool got_headers = false;
    for (const auto& f : frames) {
        if (f.type == 0x1 && f.stream_id == 1) {
            got_headers = true;
            HPACKDecoder dec;
            auto decoded = dec.decode(std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(f.payload.data()), f.payload.size()));
            ASSERT_TRUE(decoded.has_value());
            ASSERT_EQ((*decoded)[0].first, ":status");
            ASSERT_EQ((*decoded)[0].second, "200");
            for (const auto& [n, v] : *decoded) {
                ASSERT_TRUE(n != "connection");
                ASSERT_TRUE(n != "server"); // no hardcoded Server header
            }
        }
    }
    ASSERT_TRUE(got_headers);
    bool end = false;
    ASSERT_EQ(data_bytes_for(frames, 1, &end), 8u);
    ASSERT_TRUE(end);
    ASSERT_EQ(seen_cookie, "a=1; b=2");
    ASSERT_EQ(conn.active_streams(), 0u); // finished streams are released
    return true;
}

TEST(h2_flow_control_large_response) {
    const size_t body_size = 200 * 1024; // > 65535 initial window
    Http2Connection conn([&](const HttpRequest&) -> HttpResponse {
        HttpResponse resp;
        resp.body = std::string(body_size, 'x');
        return resp;
    });

    HPACKEncoder enc;
    auto out = feed(conn, handshake_bytes() +
                    make_frame(0x1, 0x5, 1, request_headers_block(enc, "GET", "/big")));
    auto frames = parse_frames(out);
    bool end = false;
    size_t sent = data_bytes_for(frames, 1, &end);
    ASSERT_EQ(sent, 65535u); // Exactly the initial window
    ASSERT_FALSE(end);
    ASSERT_TRUE(conn.has_pending_output());

    // Grant more credit on both levels until everything arrives
    size_t total = sent;
    for (int i = 0; i < 10 && !end; ++i) {
        auto more = feed(conn, window_update(0, 65535) + window_update(1, 65535));
        total += data_bytes_for(parse_frames(more), 1, &end);
    }
    ASSERT_EQ(total, body_size);
    ASSERT_TRUE(end);
    ASSERT_FALSE(conn.has_pending_output());
    return true;
}

TEST(h2_continuation_and_trailers) {
    Http2Connection conn([&](const HttpRequest& req) -> HttpResponse {
        HttpResponse resp;
        resp.body = std::string(req.get_header("x-long"));
        resp.trailers.emplace_back("grpc-status", "0");
        return resp;
    });

    HPACKEncoder enc;
    std::string long_value(3000, 'v');
    auto block = request_headers_block(enc, "POST", "/svc", {{"x-long", long_value}});
    // Split the header block across HEADERS + CONTINUATION
    std::string first = block.substr(0, 100);
    std::string rest = block.substr(100);
    std::string data = handshake_bytes() +
                       make_frame(0x1, 0x0, 1, first) +           // HEADERS, no END_HEADERS
                       make_frame(0x9, 0x4, 1, rest) +            // CONTINUATION + END_HEADERS
                       make_frame(0x0, 0x1, 1, "body");           // DATA + END_STREAM
    auto frames = parse_frames(feed(conn, data));

    int header_frames = 0;
    bool trailer_end_stream = false;
    for (const auto& f : frames) {
        if (f.type == 0x1 && f.stream_id == 1) {
            ++header_frames;
            if (header_frames == 2) trailer_end_stream = (f.flags & 0x1) != 0;
        }
    }
    ASSERT_EQ(header_frames, 2); // response headers + trailers
    ASSERT_TRUE(trailer_end_stream);
    ASSERT_EQ(data_bytes_for(frames, 1), long_value.size());
    return true;
}

TEST(h2_protocol_errors) {
    // Oversized frame -> GOAWAY(FRAME_SIZE_ERROR)
    {
        Http2Connection conn([](const HttpRequest&) { return HttpResponse{}; });
        std::string big(20000, 'a');
        auto out = feed(conn, handshake_bytes() + make_frame(0x0, 0, 1, big));
        auto frames = parse_frames(out);
        ASSERT_FALSE(conn.is_alive());
        ASSERT_EQ(frames.back().type, 0x7);
        ASSERT_EQ(static_cast<uint8_t>(frames.back().payload[7]), 0x6);
    }
    // Interleaving another frame inside a header block -> GOAWAY(PROTOCOL_ERROR)
    {
        Http2Connection conn([](const HttpRequest&) { return HttpResponse{}; });
        HPACKEncoder enc;
        auto block = request_headers_block(enc, "GET", "/");
        auto out = feed(conn, handshake_bytes() + make_frame(0x1, 0x0, 1, block) +
                        make_frame(0x6, 0, 0, std::string(8, '\0')));
        ASSERT_FALSE(conn.is_alive());
    }
    // Missing :path -> stream reset, connection survives
    {
        bool called = false;
        Http2Connection conn([&](const HttpRequest&) { called = true; return HttpResponse{}; });
        HPACKEncoder enc;
        auto block = enc.encode({{":method", "GET"}, {":scheme", "https"}});
        auto frames = parse_frames(feed(conn, handshake_bytes() + make_frame(0x1, 0x5, 1, block)));
        ASSERT_FALSE(called);
        ASSERT_TRUE(conn.is_alive());
        ASSERT_EQ(frames.back().type, 0x3); // RST_STREAM
    }
    return true;
}

TEST(h2_request_body_limit) {
    bool called = false;
    Http2Connection conn([&](const HttpRequest&) { called = true; return HttpResponse{}; });
    conn.set_max_request_body(1000);

    HPACKEncoder enc;
    auto data = handshake_bytes() +
                make_frame(0x1, 0x4, 1, request_headers_block(enc, "POST", "/upload")) +
                make_frame(0x0, 0x0, 1, std::string(1500, 'b'));
    auto frames = parse_frames(feed(conn, data));
    ASSERT_FALSE(called);

    bool saw_413 = false;
    for (const auto& f : frames) {
        if (f.type == 0x1 && f.stream_id == 1) {
            HPACKDecoder dec;
            auto decoded = dec.decode(std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(f.payload.data()), f.payload.size()));
            ASSERT_TRUE(decoded.has_value());
            saw_413 = ((*decoded)[0].second == "413");
        }
    }
    ASSERT_TRUE(saw_413);
    ASSERT_TRUE(conn.is_alive());
    return true;
}

TEST(h2_head_request_has_no_body) {
    Http2Connection conn([](const HttpRequest&) {
        HttpResponse resp;
        resp.body = "not sent for HEAD";
        return resp;
    });
    HPACKEncoder enc;
    auto frames = parse_frames(feed(conn, handshake_bytes() +
                                    make_frame(0x1, 0x5, 1, request_headers_block(enc, "HEAD", "/"))));
    ASSERT_EQ(data_bytes_for(frames, 1), 0u);
    bool end_on_headers = false;
    for (const auto& f : frames) {
        if (f.type == 0x1 && f.stream_id == 1) end_on_headers = (f.flags & 0x1) != 0;
    }
    ASSERT_TRUE(end_on_headers);
    return true;
}
