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
