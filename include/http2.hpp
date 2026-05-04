#pragma once

#include "http_parser.hpp"
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <functional>
#include <optional>
#include <span>

namespace js {

// HTTP/2 Frame Types (RFC 7540 Section 6)
enum class H2FrameType : uint8_t {
    DATA          = 0x0,
    HEADERS       = 0x1,
    PRIORITY      = 0x2,
    RST_STREAM    = 0x3,
    SETTINGS      = 0x4,
    PUSH_PROMISE  = 0x5,
    PING          = 0x6,
    GOAWAY        = 0x7,
    WINDOW_UPDATE = 0x8,
    CONTINUATION  = 0x9,
};

// HTTP/2 Error Codes
enum class H2Error : uint32_t {
    NO_ERROR            = 0x0,
    PROTOCOL_ERROR      = 0x1,
    INTERNAL_ERROR      = 0x2,
    FLOW_CONTROL_ERROR  = 0x3,
    SETTINGS_TIMEOUT    = 0x4,
    STREAM_CLOSED       = 0x5,
    FRAME_SIZE_ERROR    = 0x6,
    REFUSED_STREAM      = 0x7,
    CANCEL              = 0x8,
    COMPRESSION_ERROR   = 0x9,
    CONNECT_ERROR       = 0xa,
    ENHANCE_YOUR_CALM   = 0xb,
    INADEQUATE_SECURITY = 0xc,
    HTTP_1_1_REQUIRED   = 0xd,
};

// HTTP/2 Frame Flags
namespace H2Flags {
    constexpr uint8_t END_STREAM  = 0x1;
    constexpr uint8_t END_HEADERS = 0x4;
    constexpr uint8_t PADDED      = 0x8;
    constexpr uint8_t PRIORITY    = 0x20;
}

// HTTP/2 Settings Parameters
enum class H2Setting : uint16_t {
    HEADER_TABLE_SIZE      = 0x1,
    ENABLE_PUSH            = 0x2,
    MAX_CONCURRENT_STREAMS = 0x3,
    INITIAL_WINDOW_SIZE    = 0x4,
    MAX_FRAME_SIZE         = 0x5,
    MAX_HEADER_LIST_SIZE   = 0x6,
};

// Parsed HTTP/2 frame
struct H2Frame {
    uint32_t length = 0;         // 24-bit payload length
    H2FrameType type = H2FrameType::DATA;
    uint8_t flags = 0;
    uint32_t stream_id = 0;      // 31-bit stream identifier
    std::string payload;

    bool has_flag(uint8_t flag) const { return (flags & flag) != 0; }
};

// HPACK - Header Compression for HTTP/2 (RFC 7541)
class HPACKDecoder {
public:
    HPACKDecoder();

    // Decode a header block
    std::optional<std::vector<std::pair<std::string, std::string>>>
    decode(std::span<const uint8_t> data);

    // Set dynamic table size
    void set_max_table_size(size_t size);

private:
    // Decode an integer with prefix bits
    static std::optional<uint64_t> decode_integer(
        std::span<const uint8_t>& data, uint8_t prefix_bits);

    // Decode a string (Huffman or literal)
    static std::optional<std::string> decode_string(std::span<const uint8_t>& data);

    // Static table lookup (RFC 7541 Appendix A)
    static std::pair<std::string_view, std::string_view> static_table_entry(size_t index);
    static size_t static_table_size();

    // Dynamic table
    struct TableEntry {
        std::string name;
        std::string value;
        size_t size() const { return name.size() + value.size() + 32; }
    };

    std::vector<TableEntry> dynamic_table_;
    size_t dynamic_table_size_ = 0;
    size_t max_dynamic_table_size_ = 4096;

    void add_to_dynamic_table(std::string name, std::string value);
    std::optional<std::pair<std::string, std::string>> lookup(size_t index) const;
    void evict_dynamic_table();
};

class HPACKEncoder {
public:
    // Encode headers into HPACK format
    std::string encode(const std::vector<std::pair<std::string, std::string>>& headers);

private:
    static void encode_integer(std::string& out, uint64_t value, uint8_t prefix_bits, uint8_t pattern);
    static void encode_string(std::string& out, std::string_view str);
};

// HTTP/2 Stream State Machine
enum class H2StreamState {
    IDLE,
    RESERVED_LOCAL,
    RESERVED_REMOTE,
    OPEN,
    HALF_CLOSED_LOCAL,
    HALF_CLOSED_REMOTE,
    CLOSED,
};

struct H2Stream {
    uint32_t id = 0;
    H2StreamState state = H2StreamState::IDLE;
    int32_t window_size = 65535;
    std::string header_block;    // Accumulated header fragments
    HttpRequest request;         // Decoded request
    bool headers_complete = false;
};

// HTTP/2 Connection Handler
class Http2Connection {
public:
    using RequestHandler = std::function<HttpResponse(const HttpRequest&)>;

    explicit Http2Connection(RequestHandler handler);

    // Process incoming data, returns frames to send back
    std::string process_input(std::span<const char> data);

    // Check if connection is still alive
    bool is_alive() const { return !goaway_sent_; }

    // Get the connection preface to verify
    static constexpr std::string_view CLIENT_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

private:
    // Parse a frame from buffer
    std::optional<H2Frame> parse_frame();

    // Handle individual frame types
    std::string handle_frame(const H2Frame& frame);
    std::string handle_settings(const H2Frame& frame);
    std::string handle_headers(const H2Frame& frame);
    std::string handle_data(const H2Frame& frame);
    std::string handle_window_update(const H2Frame& frame);
    std::string handle_ping(const H2Frame& frame);
    std::string handle_goaway(const H2Frame& frame);

    // Build frames
    static std::string build_frame(H2FrameType type, uint8_t flags, uint32_t stream_id,
                                   std::string_view payload);
    std::string build_settings_frame(bool ack = false);
    std::string build_headers_response(uint32_t stream_id, const HttpResponse& resp);
    std::string build_data_frame(uint32_t stream_id, std::string_view data, bool end_stream);
    std::string build_goaway(H2Error error, std::string_view debug = "");

    // Stream management
    H2Stream& get_or_create_stream(uint32_t stream_id);

    RequestHandler handler_;
    HPACKDecoder decoder_;
    HPACKEncoder encoder_;

    std::string buffer_;
    std::unordered_map<uint32_t, H2Stream> streams_;
    bool preface_received_ = false;
    bool settings_sent_ = false;
    bool goaway_sent_ = false;
    uint32_t last_stream_id_ = 0;
    int32_t connection_window_ = 65535;

    // Connection settings
    uint32_t max_frame_size_ = 16384;
    uint32_t max_concurrent_streams_ = 100;
    uint32_t header_table_size_ = 4096;
    uint32_t initial_window_size_ = 65535;
};

} // namespace js
