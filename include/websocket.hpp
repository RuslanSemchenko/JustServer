#pragma once

#include "http_parser.hpp"
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <functional>
#include <span>

namespace js {

// WebSocket opcodes (RFC 6455 Section 5.2)
enum class WsOpcode : uint8_t {
    CONTINUATION = 0x0,
    TEXT         = 0x1,
    BINARY       = 0x2,
    // 0x3-0x7 reserved for non-control frames
    CLOSE        = 0x8,
    PING         = 0x9,
    PONG         = 0xA,
    // 0xB-0xF reserved for control frames
};

// WebSocket close status codes (RFC 6455 Section 7.4.1)
namespace WsClose {
    constexpr uint16_t NORMAL          = 1000;
    constexpr uint16_t GOING_AWAY      = 1001;
    constexpr uint16_t PROTOCOL_ERROR  = 1002;
    constexpr uint16_t UNSUPPORTED     = 1003;
    constexpr uint16_t NO_STATUS       = 1005;
    constexpr uint16_t ABNORMAL        = 1006;
    constexpr uint16_t INVALID_PAYLOAD = 1007;
    constexpr uint16_t POLICY_VIOLATION= 1008;
    constexpr uint16_t TOO_BIG         = 1009;
    constexpr uint16_t EXTENSION_NEEDED= 1010;
    constexpr uint16_t INTERNAL_ERROR  = 1011;
}

// Parsed WebSocket frame
struct WsFrame {
    bool fin = false;
    WsOpcode opcode = WsOpcode::TEXT;
    bool masked = false;
    uint64_t payload_length = 0;
    uint8_t mask_key[4] = {};
    std::string payload;
};

// WebSocket handshake utilities
class WsHandshake {
public:
    // Check if an HTTP request is a WebSocket upgrade request
    static bool is_upgrade_request(const HttpRequest& req);

    // Build the WebSocket handshake response (101 Switching Protocols)
    static HttpResponse build_accept_response(const HttpRequest& req);

    // Compute the Sec-WebSocket-Accept value from Sec-WebSocket-Key
    static std::string compute_accept_key(std::string_view client_key);
};

// WebSocket connection handler
class WsConnection {
public:
    // Callbacks for received messages
    using OnMessage = std::function<void(WsOpcode opcode, std::string_view data)>;
    using OnClose = std::function<void(uint16_t code, std::string_view reason)>;
    using OnPing = std::function<void(std::string_view data)>;

    WsConnection();

    void set_on_message(OnMessage cb) { on_message_ = std::move(cb); }
    void set_on_close(OnClose cb) { on_close_ = std::move(cb); }
    void set_on_ping(OnPing cb) { on_ping_ = std::move(cb); }

    // Feed raw data from the socket, returns frames to send back (pong, close ack)
    std::string process_input(std::span<const char> data);

    // Build an outgoing frame (server -> client, unmasked)
    static std::string build_frame(WsOpcode opcode, std::string_view payload, bool fin = true);

    // Build a close frame
    static std::string build_close(uint16_t code, std::string_view reason = "");

    // Check if connection is still alive
    bool is_alive() const { return !closed_; }

    // Get accumulated message for fragmented frames
    const std::string& accumulated_message() const { return message_buffer_; }

private:
    // Parse a single frame from the buffer
    std::optional<WsFrame> parse_frame();

    // Handle a complete frame
    std::string handle_frame(const WsFrame& frame);

    // Unmask payload data in-place
    static void unmask(std::string& data, const uint8_t mask[4]);

    std::string buffer_;
    std::string message_buffer_;  // For fragmented messages
    WsOpcode fragment_opcode_ = WsOpcode::TEXT;
    bool in_fragment_ = false;
    bool closed_ = false;
    bool close_sent_ = false;

    OnMessage on_message_;
    OnClose on_close_;
    OnPing on_ping_;

    // Limits
    static constexpr size_t MAX_FRAME_SIZE = 16 * 1024 * 1024; // 16 MB
    static constexpr size_t MAX_MESSAGE_SIZE = 64 * 1024 * 1024; // 64 MB
};

} // namespace js
