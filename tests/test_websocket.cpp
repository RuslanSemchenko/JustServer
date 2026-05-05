#include "websocket.hpp"
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

TEST(ws_handshake_detect_upgrade) {
    HttpRequest req;
    req.method = HttpMethod::GET;
    req.method_str = "GET";
    req.uri = "/ws";
    req.path = "/ws";
    req.version = "HTTP/1.1";
    req.headers["Upgrade"] = "websocket";
    req.headers["Connection"] = "Upgrade";
    req.headers["Sec-WebSocket-Key"] = "dGhlIHNhbXBsZSBub25jZQ==";
    req.headers["Sec-WebSocket-Version"] = "13";

    ASSERT_TRUE(WsHandshake::is_upgrade_request(req));
    return true;
}

TEST(ws_handshake_reject_non_upgrade) {
    HttpRequest req;
    req.method = HttpMethod::GET;
    req.uri = "/index.html";
    req.path = "/index.html";
    req.version = "HTTP/1.1";
    req.headers["Host"] = "example.com";

    ASSERT_FALSE(WsHandshake::is_upgrade_request(req));
    return true;
}

TEST(ws_handshake_reject_post) {
    HttpRequest req;
    req.method = HttpMethod::POST;
    req.method_str = "POST";
    req.uri = "/ws";
    req.headers["Upgrade"] = "websocket";
    req.headers["Connection"] = "Upgrade";
    req.headers["Sec-WebSocket-Key"] = "dGhlIHNhbXBsZSBub25jZQ==";
    req.headers["Sec-WebSocket-Version"] = "13";

    ASSERT_FALSE(WsHandshake::is_upgrade_request(req));
    return true;
}

TEST(ws_handshake_accept_key) {
    // RFC 6455 Section 4.2.2 example
    auto accept = WsHandshake::compute_accept_key("dGhlIHNhbXBsZSBub25jZQ==");
    ASSERT_EQ(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    return true;
}

TEST(ws_handshake_response) {
    HttpRequest req;
    req.method = HttpMethod::GET;
    req.uri = "/ws";
    req.headers["Sec-WebSocket-Key"] = "dGhlIHNhbXBsZSBub25jZQ==";

    auto resp = WsHandshake::build_accept_response(req);
    ASSERT_EQ(resp.status_code, 101);
    ASSERT_EQ(resp.headers["Upgrade"], "websocket");
    ASSERT_EQ(resp.headers["Connection"], "Upgrade");
    ASSERT_EQ(resp.headers["Sec-WebSocket-Accept"], "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    return true;
}

// Helper: build a masked client frame
static std::string build_client_frame(WsOpcode opcode, std::string_view payload,
                                       bool fin = true, uint8_t mask_key[4] = nullptr) {
    std::string frame;
    uint8_t byte0 = static_cast<uint8_t>(opcode);
    if (fin) byte0 |= 0x80;
    frame += static_cast<char>(byte0);

    // Mask bit = 1 (client -> server must be masked)
    uint8_t mask_flag = 0x80;
    if (payload.size() <= 125) {
        frame += static_cast<char>(mask_flag | payload.size());
    } else if (payload.size() <= 65535) {
        frame += static_cast<char>(mask_flag | 126);
        frame += static_cast<char>((payload.size() >> 8) & 0xFF);
        frame += static_cast<char>(payload.size() & 0xFF);
    } else {
        frame += static_cast<char>(mask_flag | 127);
        uint64_t len = payload.size();
        for (int i = 7; i >= 0; --i) {
            frame += static_cast<char>((len >> (i * 8)) & 0xFF);
        }
    }

    // Mask key
    uint8_t default_mask[4] = {0x37, 0xfa, 0x21, 0x3d};
    uint8_t* mk = mask_key ? mask_key : default_mask;
    frame.append(reinterpret_cast<const char*>(mk), 4);

    // Masked payload
    for (size_t i = 0; i < payload.size(); ++i) {
        frame += static_cast<char>(payload[i] ^ static_cast<char>(mk[i % 4]));
    }

    return frame;
}

TEST(ws_text_message_echo) {
    WsConnection ws;
    std::string received_msg;
    WsOpcode received_opcode = WsOpcode::CLOSE;

    ws.set_on_message([&](WsOpcode op, std::string_view data) {
        received_opcode = op;
        received_msg = std::string(data);
    });

    auto frame = build_client_frame(WsOpcode::TEXT, "Hello, WebSocket!");
    ws.process_input(std::span<const char>(frame.data(), frame.size()));

    ASSERT_EQ(received_opcode, WsOpcode::TEXT);
    ASSERT_EQ(received_msg, "Hello, WebSocket!");
    ASSERT_TRUE(ws.is_alive());
    return true;
}

TEST(ws_binary_message) {
    WsConnection ws;
    std::string received_msg;

    ws.set_on_message([&](WsOpcode, std::string_view data) {
        received_msg = std::string(data);
    });

    std::string binary_data = "\x00\x01\x02\x03\xFF";
    auto frame = build_client_frame(WsOpcode::BINARY, binary_data);
    ws.process_input(std::span<const char>(frame.data(), frame.size()));

    ASSERT_EQ(received_msg, binary_data);
    return true;
}

TEST(ws_ping_pong) {
    WsConnection ws;
    bool ping_received = false;

    ws.set_on_ping([&](std::string_view) {
        ping_received = true;
    });

    auto frame = build_client_frame(WsOpcode::PING, "ping!");
    auto response = ws.process_input(std::span<const char>(frame.data(), frame.size()));

    ASSERT_TRUE(ping_received);
    // Response should be a PONG frame
    ASSERT_TRUE(response.size() > 0);
    // First byte should be 0x8A (FIN + PONG)
    ASSERT_EQ(static_cast<uint8_t>(response[0]), 0x8Au);
    ASSERT_TRUE(ws.is_alive());
    return true;
}

TEST(ws_close_handshake) {
    WsConnection ws;
    uint16_t close_code = 0;
    std::string close_reason;

    ws.set_on_close([&](uint16_t code, std::string_view reason) {
        close_code = code;
        close_reason = std::string(reason);
    });

    // Build close frame with code 1000 and reason "bye"
    std::string close_payload;
    close_payload += static_cast<char>((WsClose::NORMAL >> 8) & 0xFF);
    close_payload += static_cast<char>(WsClose::NORMAL & 0xFF);
    close_payload += "bye";

    auto frame = build_client_frame(WsOpcode::CLOSE, close_payload);
    auto response = ws.process_input(std::span<const char>(frame.data(), frame.size()));

    ASSERT_EQ(close_code, WsClose::NORMAL);
    ASSERT_EQ(close_reason, "bye");
    ASSERT_FALSE(ws.is_alive());
    // Response should be a close frame echo
    ASSERT_TRUE(response.size() > 0);
    return true;
}

TEST(ws_build_frame_small) {
    auto frame = WsConnection::build_frame(WsOpcode::TEXT, "Hello");
    ASSERT_TRUE(frame.size() == 7); // 2 header + 5 payload
    ASSERT_EQ(static_cast<uint8_t>(frame[0]), 0x81u); // FIN + TEXT
    ASSERT_EQ(static_cast<uint8_t>(frame[1]), 5u);    // Length 5, no mask
    ASSERT_EQ(frame.substr(2), "Hello");
    return true;
}

TEST(ws_build_frame_medium) {
    std::string payload(200, 'A');
    auto frame = WsConnection::build_frame(WsOpcode::BINARY, payload);
    ASSERT_TRUE(frame.size() == 4 + 200); // 2 + 2 (extended) + 200
    ASSERT_EQ(static_cast<uint8_t>(frame[0]), 0x82u); // FIN + BINARY
    ASSERT_EQ(static_cast<uint8_t>(frame[1]), 126u);  // Extended 16-bit length
    return true;
}

TEST(ws_reject_unmasked_client_frame) {
    // RFC 6455 Section 5.1: server MUST close on unmasked client frame
    WsConnection ws;
    bool message_received = false;

    ws.set_on_message([&](WsOpcode, std::string_view) {
        message_received = true;
    });

    // Build an unmasked frame (mask bit = 0)
    std::string frame;
    frame += static_cast<char>(0x81); // FIN + TEXT
    frame += static_cast<char>(0x05); // Length 5, mask bit NOT set
    frame += "Hello";

    ws.process_input(std::span<const char>(frame.data(), frame.size()));

    ASSERT_FALSE(message_received); // Message should NOT be delivered
    ASSERT_FALSE(ws.is_alive());    // Connection should be closed
    return true;
}

TEST(ws_fragmented_message) {
    WsConnection ws;
    std::string received_msg;

    ws.set_on_message([&](WsOpcode, std::string_view data) {
        received_msg = std::string(data);
    });

    // First fragment (TEXT, not FIN)
    auto frag1 = build_client_frame(WsOpcode::TEXT, "Hello, ", false);
    ws.process_input(std::span<const char>(frag1.data(), frag1.size()));
    ASSERT_TRUE(received_msg.empty()); // Not delivered yet

    // Continuation (FIN)
    auto frag2 = build_client_frame(WsOpcode::CONTINUATION, "World!");
    ws.process_input(std::span<const char>(frag2.data(), frag2.size()));
    ASSERT_EQ(received_msg, "Hello, World!");
    return true;
}
