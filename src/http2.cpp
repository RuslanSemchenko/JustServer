#include "http2.hpp"
#include "logger.hpp"
#include <cstring>
#include <algorithm>
#include <arpa/inet.h>

namespace js {

// ===== HPACK Static Table (RFC 7541, Appendix A) =====

static const std::pair<std::string_view, std::string_view> STATIC_TABLE[] = {
    {"", ""},                              // 0 (unused)
    {":authority", ""},                    // 1
    {":method", "GET"},                    // 2
    {":method", "POST"},                   // 3
    {":path", "/"},                        // 4
    {":path", "/index.html"},              // 5
    {":scheme", "http"},                   // 6
    {":scheme", "https"},                  // 7
    {":status", "200"},                    // 8
    {":status", "204"},                    // 9
    {":status", "206"},                    // 10
    {":status", "304"},                    // 11
    {":status", "400"},                    // 12
    {":status", "404"},                    // 13
    {":status", "500"},                    // 14
    {"accept-charset", ""},                // 15
    {"accept-encoding", "gzip, deflate"},  // 16
    {"accept-language", ""},               // 17
    {"accept-ranges", ""},                 // 18
    {"accept", ""},                        // 19
    {"access-control-allow-origin", ""},   // 20
    {"age", ""},                           // 21
    {"allow", ""},                         // 22
    {"authorization", ""},                 // 23
    {"cache-control", ""},                 // 24
    {"content-disposition", ""},           // 25
    {"content-encoding", ""},              // 26
    {"content-language", ""},              // 27
    {"content-length", ""},                // 28
    {"content-location", ""},              // 29
    {"content-range", ""},                 // 30
    {"content-type", ""},                  // 31
    {"cookie", ""},                        // 32
    {"date", ""},                          // 33
    {"etag", ""},                          // 34
    {"expect", ""},                        // 35
    {"expires", ""},                       // 36
    {"from", ""},                          // 37
    {"host", ""},                          // 38
    {"if-match", ""},                      // 39
    {"if-modified-since", ""},             // 40
    {"if-none-match", ""},                 // 41
    {"if-range", ""},                      // 42
    {"if-unmodified-since", ""},           // 43
    {"last-modified", ""},                 // 44
    {"link", ""},                          // 45
    {"location", ""},                      // 46
    {"max-forwards", ""},                  // 47
    {"proxy-authenticate", ""},            // 48
    {"proxy-authorization", ""},           // 49
    {"range", ""},                         // 50
    {"referer", ""},                       // 51
    {"refresh", ""},                       // 52
    {"retry-after", ""},                   // 53
    {"server", ""},                        // 54
    {"set-cookie", ""},                    // 55
    {"strict-transport-security", ""},     // 56
    {"transfer-encoding", ""},             // 57
    {"user-agent", ""},                    // 58
    {"vary", ""},                          // 59
    {"via", ""},                           // 60
    {"www-authenticate", ""},              // 61
};
static constexpr size_t STATIC_TABLE_SIZE = sizeof(STATIC_TABLE) / sizeof(STATIC_TABLE[0]) - 1;

// ===== HPACKDecoder =====

HPACKDecoder::HPACKDecoder() = default;

std::pair<std::string_view, std::string_view> HPACKDecoder::static_table_entry(size_t index) {
    if (index > 0 && index <= STATIC_TABLE_SIZE) {
        return STATIC_TABLE[index];
    }
    return {"", ""};
}

size_t HPACKDecoder::static_table_size() {
    return STATIC_TABLE_SIZE;
}

void HPACKDecoder::set_max_table_size(size_t size) {
    max_dynamic_table_size_ = size;
    evict_dynamic_table();
}

void HPACKDecoder::add_to_dynamic_table(std::string name, std::string value) {
    size_t entry_size = name.size() + value.size() + 32;

    // Evict entries if needed
    while (dynamic_table_size_ + entry_size > max_dynamic_table_size_ && !dynamic_table_.empty()) {
        auto& last = dynamic_table_.back();
        dynamic_table_size_ -= last.size();
        dynamic_table_.pop_back();
    }

    if (entry_size <= max_dynamic_table_size_) {
        dynamic_table_.insert(dynamic_table_.begin(), {std::move(name), std::move(value)});
        dynamic_table_size_ += entry_size;
    }
}

void HPACKDecoder::evict_dynamic_table() {
    while (dynamic_table_size_ > max_dynamic_table_size_ && !dynamic_table_.empty()) {
        dynamic_table_size_ -= dynamic_table_.back().size();
        dynamic_table_.pop_back();
    }
}

std::optional<std::pair<std::string, std::string>> HPACKDecoder::lookup(size_t index) const {
    if (index == 0) return std::nullopt;

    if (index <= STATIC_TABLE_SIZE) {
        auto [n, v] = STATIC_TABLE[index];
        return std::pair{std::string(n), std::string(v)};
    }

    size_t dyn_index = index - STATIC_TABLE_SIZE - 1;
    if (dyn_index < dynamic_table_.size()) {
        auto& entry = dynamic_table_[dyn_index];
        return std::pair{entry.name, entry.value};
    }

    return std::nullopt;
}

std::optional<uint64_t> HPACKDecoder::decode_integer(
    std::span<const uint8_t>& data, uint8_t prefix_bits) {
    if (data.empty()) return std::nullopt;

    uint8_t max_prefix = static_cast<uint8_t>((1u << prefix_bits) - 1);
    uint64_t value = data[0] & max_prefix;
    data = data.subspan(1);

    if (value < max_prefix) return value;

    uint64_t m = 0;
    do {
        if (data.empty()) return std::nullopt;
        uint8_t b = data[0];
        data = data.subspan(1);
        value += static_cast<uint64_t>(b & 0x7F) << m;
        m += 7;
        if ((b & 0x80) == 0) break;
        if (m > 63) return std::nullopt; // Overflow protection
    } while (true);

    return value;
}

std::optional<std::string> HPACKDecoder::decode_string(std::span<const uint8_t>& data) {
    if (data.empty()) return std::nullopt;

    bool huffman = (data[0] & 0x80) != 0;
    auto length = decode_integer(data, 7);
    if (!length || *length > data.size()) return std::nullopt;

    if (huffman) {
        // For simplicity, we don't implement Huffman decoding here
        // In production, you'd implement the full Huffman table from RFC 7541
        // For now, treat as raw bytes (works for non-Huffman encoded headers)
        std::string result(reinterpret_cast<const char*>(data.data()),
                          static_cast<size_t>(*length));
        data = data.subspan(static_cast<size_t>(*length));
        return result;
    }

    std::string result(reinterpret_cast<const char*>(data.data()),
                      static_cast<size_t>(*length));
    data = data.subspan(static_cast<size_t>(*length));
    return result;
}

std::optional<std::vector<std::pair<std::string, std::string>>>
HPACKDecoder::decode(std::span<const uint8_t> data) {
    std::vector<std::pair<std::string, std::string>> headers;

    while (!data.empty()) {
        uint8_t byte = data[0];

        if (byte & 0x80) {
            // Indexed Header Field (Section 6.1)
            auto index = decode_integer(data, 7);
            if (!index) return std::nullopt;

            auto entry = lookup(static_cast<size_t>(*index));
            if (!entry) return std::nullopt;
            headers.push_back(*entry);

        } else if (byte & 0x40) {
            // Literal Header Field with Incremental Indexing (Section 6.2.1)
            auto index = decode_integer(data, 6);
            if (!index) return std::nullopt;

            std::string name, value;
            if (*index > 0) {
                auto entry = lookup(static_cast<size_t>(*index));
                if (!entry) return std::nullopt;
                name = entry->first;
            } else {
                auto n = decode_string(data);
                if (!n) return std::nullopt;
                name = std::move(*n);
            }

            auto v = decode_string(data);
            if (!v) return std::nullopt;
            value = std::move(*v);

            add_to_dynamic_table(name, value);
            headers.emplace_back(std::move(name), std::move(value));

        } else if (byte & 0x20) {
            // Dynamic Table Size Update (Section 6.3)
            auto size = decode_integer(data, 5);
            if (!size) return std::nullopt;
            set_max_table_size(static_cast<size_t>(*size));

        } else {
            // Literal Header Field without Indexing / Never Indexed
            uint8_t prefix = (byte & 0x10) ? 4 : 4;
            auto index = decode_integer(data, prefix);
            if (!index) return std::nullopt;

            std::string name, value;
            if (*index > 0) {
                auto entry = lookup(static_cast<size_t>(*index));
                if (!entry) return std::nullopt;
                name = entry->first;
            } else {
                auto n = decode_string(data);
                if (!n) return std::nullopt;
                name = std::move(*n);
            }

            auto v = decode_string(data);
            if (!v) return std::nullopt;
            value = std::move(*v);

            headers.emplace_back(std::move(name), std::move(value));
        }
    }

    return headers;
}

// ===== HPACKEncoder =====

void HPACKEncoder::encode_integer(std::string& out, uint64_t value, uint8_t prefix_bits, uint8_t pattern) {
    uint8_t max_prefix = static_cast<uint8_t>((1u << prefix_bits) - 1);

    if (value < max_prefix) {
        out += static_cast<char>(pattern | static_cast<uint8_t>(value));
    } else {
        out += static_cast<char>(pattern | max_prefix);
        value -= max_prefix;
        while (value >= 128) {
            out += static_cast<char>((value & 0x7F) | 0x80);
            value >>= 7;
        }
        out += static_cast<char>(value);
    }
}

void HPACKEncoder::encode_string(std::string& out, std::string_view str) {
    // Without Huffman encoding for simplicity
    encode_integer(out, str.size(), 7, 0x00);
    out.append(str);
}

std::string HPACKEncoder::encode(const std::vector<std::pair<std::string, std::string>>& headers) {
    std::string result;

    for (const auto& [name, value] : headers) {
        // Check static table for indexed name
        bool found = false;
        for (size_t i = 1; i <= STATIC_TABLE_SIZE; ++i) {
            if (STATIC_TABLE[i].first == name) {
                if (STATIC_TABLE[i].second == value) {
                    // Fully indexed
                    encode_integer(result, i, 7, 0x80);
                    found = true;
                    break;
                }
                // Name indexed, literal value (without indexing)
                encode_integer(result, i, 4, 0x00);
                encode_string(result, value);
                found = true;
                break;
            }
        }

        if (!found) {
            // Literal without indexing, new name
            result += '\x00';
            encode_string(result, name);
            encode_string(result, value);
        }
    }

    return result;
}

// ===== Http2Connection =====

Http2Connection::Http2Connection(RequestHandler handler)
    : handler_(std::move(handler)) {}

std::string Http2Connection::process_input(std::span<const char> data) {
    buffer_.append(data.data(), data.size());
    std::string output;

    // Check for client preface
    if (!preface_received_) {
        if (buffer_.size() < CLIENT_PREFACE.size()) {
            return output; // Need more data
        }

        if (buffer_.substr(0, CLIENT_PREFACE.size()) != CLIENT_PREFACE) {
            LOG_WARN("HTTP/2: Invalid client connection preface");
            output += build_goaway(H2Error::PROTOCOL_ERROR, "Invalid preface");
            goaway_sent_ = true;
            return output;
        }

        buffer_.erase(0, CLIENT_PREFACE.size());
        preface_received_ = true;

        // Send server settings
        output += build_settings_frame();
        settings_sent_ = true;
    }

    // Process frames
    while (true) {
        auto frame = parse_frame();
        if (!frame) break;

        output += handle_frame(*frame);

        if (goaway_sent_) break;
    }

    return output;
}

std::optional<H2Frame> Http2Connection::parse_frame() {
    // Frame header is 9 bytes
    if (buffer_.size() < 9) return std::nullopt;

    H2Frame frame;

    // Length (24 bits)
    frame.length = (static_cast<uint32_t>(static_cast<uint8_t>(buffer_[0])) << 16) |
                   (static_cast<uint32_t>(static_cast<uint8_t>(buffer_[1])) << 8) |
                   static_cast<uint32_t>(static_cast<uint8_t>(buffer_[2]));

    // Type (8 bits)
    frame.type = static_cast<H2FrameType>(buffer_[3]);

    // Flags (8 bits)
    frame.flags = static_cast<uint8_t>(buffer_[4]);

    // Stream ID (31 bits, MSB reserved)
    frame.stream_id = (static_cast<uint32_t>(static_cast<uint8_t>(buffer_[5]) & 0x7F) << 24) |
                      (static_cast<uint32_t>(static_cast<uint8_t>(buffer_[6])) << 16) |
                      (static_cast<uint32_t>(static_cast<uint8_t>(buffer_[7])) << 8) |
                      static_cast<uint32_t>(static_cast<uint8_t>(buffer_[8]));

    // Check frame size
    if (frame.length > max_frame_size_) {
        return std::nullopt;
    }

    // Check we have full payload
    if (buffer_.size() < 9 + frame.length) return std::nullopt;

    frame.payload = buffer_.substr(9, frame.length);
    buffer_.erase(0, 9 + frame.length);

    return frame;
}

std::string Http2Connection::handle_frame(const H2Frame& frame) {
    switch (frame.type) {
        case H2FrameType::SETTINGS:    return handle_settings(frame);
        case H2FrameType::HEADERS:     return handle_headers(frame);
        case H2FrameType::DATA:        return handle_data(frame);
        case H2FrameType::WINDOW_UPDATE: return handle_window_update(frame);
        case H2FrameType::PING:        return handle_ping(frame);
        case H2FrameType::GOAWAY:      return handle_goaway(frame);
        case H2FrameType::RST_STREAM:  return {}; // Acknowledged
        case H2FrameType::PRIORITY:    return {}; // Advisory only
        default:
            // Unknown frame types are ignored per spec
            return {};
    }
}

std::string Http2Connection::handle_settings(const H2Frame& frame) {
    if (frame.has_flag(0x1)) {
        // Settings ACK - no payload
        return {};
    }

    // Parse settings
    if (frame.payload.size() % 6 != 0) {
        return build_goaway(H2Error::FRAME_SIZE_ERROR, "Invalid SETTINGS frame size");
    }

    for (size_t i = 0; i < frame.payload.size(); i += 6) {
        uint16_t id = (static_cast<uint16_t>(static_cast<uint8_t>(frame.payload[i])) << 8) |
                      static_cast<uint16_t>(static_cast<uint8_t>(frame.payload[i + 1]));
        uint32_t value = (static_cast<uint32_t>(static_cast<uint8_t>(frame.payload[i + 2])) << 24) |
                         (static_cast<uint32_t>(static_cast<uint8_t>(frame.payload[i + 3])) << 16) |
                         (static_cast<uint32_t>(static_cast<uint8_t>(frame.payload[i + 4])) << 8) |
                         static_cast<uint32_t>(static_cast<uint8_t>(frame.payload[i + 5]));

        switch (static_cast<H2Setting>(id)) {
            case H2Setting::HEADER_TABLE_SIZE:
                header_table_size_ = value;
                decoder_.set_max_table_size(value);
                break;
            case H2Setting::MAX_CONCURRENT_STREAMS:
                max_concurrent_streams_ = value;
                break;
            case H2Setting::INITIAL_WINDOW_SIZE:
                if (value > 0x7FFFFFFF) {
                    return build_goaway(H2Error::FLOW_CONTROL_ERROR);
                }
                initial_window_size_ = value;
                break;
            case H2Setting::MAX_FRAME_SIZE:
                if (value < 16384 || value > 16777215) {
                    return build_goaway(H2Error::PROTOCOL_ERROR);
                }
                max_frame_size_ = value;
                break;
            default:
                break; // Unknown settings are ignored
        }
    }

    // Send SETTINGS ACK
    return build_settings_frame(true);
}

std::string Http2Connection::handle_headers(const H2Frame& frame) {
    if (frame.stream_id == 0) {
        return build_goaway(H2Error::PROTOCOL_ERROR, "HEADERS on stream 0");
    }

    auto& stream = get_or_create_stream(frame.stream_id);

    std::string_view payload(frame.payload);

    // Handle padding
    size_t pad_length = 0;
    size_t offset = 0;
    if (frame.has_flag(H2Flags::PADDED)) {
        if (payload.empty()) return build_goaway(H2Error::PROTOCOL_ERROR);
        pad_length = static_cast<uint8_t>(payload[0]);
        offset = 1;
    }

    // Handle priority
    if (frame.has_flag(H2Flags::PRIORITY)) {
        offset += 5; // Stream dependency (4) + Weight (1)
    }

    if (offset + pad_length > payload.size()) {
        return build_goaway(H2Error::PROTOCOL_ERROR);
    }

    auto header_data = payload.substr(offset, payload.size() - offset - pad_length);
    stream.header_block.append(header_data);

    if (frame.has_flag(H2Flags::END_HEADERS)) {
        // Decode headers
        auto header_bytes = std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(stream.header_block.data()),
            stream.header_block.size()
        );

        auto decoded = decoder_.decode(header_bytes);
        if (!decoded) {
            return build_goaway(H2Error::COMPRESSION_ERROR);
        }

        // Build HttpRequest from decoded headers
        for (const auto& [name, value] : *decoded) {
            if (name == ":method") stream.request.method_str = value;
            else if (name == ":path") {
                stream.request.uri = value;
                stream.request.path = value;
                auto qmark = value.find('?');
                if (qmark != std::string::npos) {
                    stream.request.path = value.substr(0, qmark);
                    stream.request.query_string = value.substr(qmark + 1);
                }
            }
            else if (name == ":authority") stream.request.headers["Host"] = value;
            else if (name == ":scheme") {} // Not needed for routing
            else if (!name.empty() && name[0] != ':') {
                stream.request.headers[name] = value;
            }
        }

        // Parse method
        if (stream.request.method_str == "GET") stream.request.method = HttpMethod::GET;
        else if (stream.request.method_str == "POST") stream.request.method = HttpMethod::POST;
        else if (stream.request.method_str == "HEAD") stream.request.method = HttpMethod::HEAD;
        else if (stream.request.method_str == "PUT") stream.request.method = HttpMethod::PUT;
        else if (stream.request.method_str == "DELETE") stream.request.method = HttpMethod::DELETE_;
        else if (stream.request.method_str == "OPTIONS") stream.request.method = HttpMethod::OPTIONS;
        else stream.request.method = HttpMethod::UNKNOWN;

        stream.request.version = "HTTP/2";
        stream.headers_complete = true;
        stream.header_block.clear();

        // If END_STREAM, process request immediately
        if (frame.has_flag(H2Flags::END_STREAM)) {
            stream.state = H2StreamState::HALF_CLOSED_REMOTE;

            // Handle request
            auto response = handler_(stream.request);
            LOG_INFO("HTTP/2 stream " + std::to_string(frame.stream_id) + " " +
                     stream.request.method_str + " " + stream.request.uri +
                     " -> " + std::to_string(response.status_code));

            return build_headers_response(frame.stream_id, response);
        } else {
            stream.state = H2StreamState::OPEN;
        }
    }

    return {};
}

std::string Http2Connection::handle_data(const H2Frame& frame) {
    if (frame.stream_id == 0) {
        return build_goaway(H2Error::PROTOCOL_ERROR);
    }

    auto it = streams_.find(frame.stream_id);
    if (it == streams_.end()) {
        return build_goaway(H2Error::PROTOCOL_ERROR);
    }

    auto& stream = it->second;
    stream.request.body.append(frame.payload);

    if (frame.has_flag(H2Flags::END_STREAM)) {
        stream.state = H2StreamState::HALF_CLOSED_REMOTE;

        if (stream.headers_complete) {
            auto response = handler_(stream.request);
            return build_headers_response(frame.stream_id, response);
        }
    }

    // Send WINDOW_UPDATE for connection and stream
    std::string output;
    if (frame.length > 0) {
        uint32_t increment = frame.length;
        // Connection-level window update
        char buf[4];
        uint32_t net_inc = htonl(increment);
        std::memcpy(buf, &net_inc, 4);
        output += build_frame(H2FrameType::WINDOW_UPDATE, 0, 0, std::string_view(buf, 4));
        // Stream-level window update
        output += build_frame(H2FrameType::WINDOW_UPDATE, 0, frame.stream_id, std::string_view(buf, 4));
    }

    return output;
}

std::string Http2Connection::handle_window_update(const H2Frame& frame) {
    if (frame.payload.size() != 4) {
        return build_goaway(H2Error::FRAME_SIZE_ERROR);
    }

    uint32_t increment = (static_cast<uint32_t>(static_cast<uint8_t>(frame.payload[0]) & 0x7F) << 24) |
                         (static_cast<uint32_t>(static_cast<uint8_t>(frame.payload[1])) << 16) |
                         (static_cast<uint32_t>(static_cast<uint8_t>(frame.payload[2])) << 8) |
                         static_cast<uint32_t>(static_cast<uint8_t>(frame.payload[3]));

    if (increment == 0) {
        return build_goaway(H2Error::PROTOCOL_ERROR);
    }

    if (frame.stream_id == 0) {
        connection_window_ += static_cast<int32_t>(increment);
    } else {
        auto it = streams_.find(frame.stream_id);
        if (it != streams_.end()) {
            it->second.window_size += static_cast<int32_t>(increment);
        }
    }

    return {};
}

std::string Http2Connection::handle_ping(const H2Frame& frame) {
    if (frame.payload.size() != 8) {
        return build_goaway(H2Error::FRAME_SIZE_ERROR);
    }
    if (frame.has_flag(0x1)) {
        return {}; // ACK, ignore
    }
    // Echo back with ACK flag
    return build_frame(H2FrameType::PING, 0x1, 0, frame.payload);
}

std::string Http2Connection::handle_goaway([[maybe_unused]] const H2Frame& frame) {
    goaway_sent_ = true;
    return {};
}

// ===== Frame building =====

std::string Http2Connection::build_frame(H2FrameType type, uint8_t flags,
                                          uint32_t stream_id, std::string_view payload) {
    std::string frame;
    frame.resize(9 + payload.size());

    uint32_t len = static_cast<uint32_t>(payload.size());
    frame[0] = static_cast<char>((len >> 16) & 0xFF);
    frame[1] = static_cast<char>((len >> 8) & 0xFF);
    frame[2] = static_cast<char>(len & 0xFF);
    frame[3] = static_cast<char>(type);
    frame[4] = static_cast<char>(flags);
    frame[5] = static_cast<char>((stream_id >> 24) & 0x7F);
    frame[6] = static_cast<char>((stream_id >> 16) & 0xFF);
    frame[7] = static_cast<char>((stream_id >> 8) & 0xFF);
    frame[8] = static_cast<char>(stream_id & 0xFF);

    if (!payload.empty()) {
        std::memcpy(frame.data() + 9, payload.data(), payload.size());
    }

    return frame;
}

std::string Http2Connection::build_settings_frame(bool ack) {
    if (ack) {
        return build_frame(H2FrameType::SETTINGS, 0x1, 0, "");
    }

    // Send our settings
    std::string payload;
    auto add_setting = [&payload](H2Setting id, uint32_t value) {
        uint16_t net_id = htons(static_cast<uint16_t>(id));
        uint32_t net_val = htonl(value);
        payload.append(reinterpret_cast<const char*>(&net_id), 2);
        payload.append(reinterpret_cast<const char*>(&net_val), 4);
    };

    add_setting(H2Setting::MAX_CONCURRENT_STREAMS, 100);
    add_setting(H2Setting::INITIAL_WINDOW_SIZE, 65535);
    add_setting(H2Setting::MAX_FRAME_SIZE, 16384);

    return build_frame(H2FrameType::SETTINGS, 0, 0, payload);
}

std::string Http2Connection::build_headers_response(uint32_t stream_id, const HttpResponse& resp) {
    std::string output;

    // Encode response headers
    std::vector<std::pair<std::string, std::string>> headers;
    headers.emplace_back(":status", std::to_string(resp.status_code));

    for (const auto& [name, value] : resp.headers) {
        std::string lower_name(name);
        std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        headers.emplace_back(std::move(lower_name), value);
    }

    if (!resp.body.empty()) {
        bool has_cl = false;
        for (const auto& [n, v] : headers) {
            if (n == "content-length") { has_cl = true; break; }
        }
        if (!has_cl) {
            headers.emplace_back("content-length", std::to_string(resp.body.size()));
        }
    }

    headers.emplace_back("server", "JustServer/1.0");

    auto encoded = encoder_.encode(headers);

    uint8_t flags = H2Flags::END_HEADERS;
    if (resp.body.empty()) {
        flags |= H2Flags::END_STREAM;
    }

    output += build_frame(H2FrameType::HEADERS, flags, stream_id, encoded);

    // Send body as DATA frames
    if (!resp.body.empty()) {
        size_t offset = 0;
        while (offset < resp.body.size()) {
            size_t chunk = std::min(resp.body.size() - offset, static_cast<size_t>(max_frame_size_));
            bool last = (offset + chunk >= resp.body.size());
            uint8_t data_flags = last ? H2Flags::END_STREAM : 0;
            output += build_frame(H2FrameType::DATA, data_flags, stream_id,
                                  std::string_view(resp.body.data() + offset, chunk));
            offset += chunk;
        }
    }

    return output;
}

std::string Http2Connection::build_goaway(H2Error error, std::string_view debug) {
    goaway_sent_ = true;

    std::string payload;
    payload.resize(8 + debug.size());

    uint32_t last_id = htonl(last_stream_id_);
    uint32_t err_code = htonl(static_cast<uint32_t>(error));
    std::memcpy(payload.data(), &last_id, 4);
    std::memcpy(payload.data() + 4, &err_code, 4);
    if (!debug.empty()) {
        std::memcpy(payload.data() + 8, debug.data(), debug.size());
    }

    return build_frame(H2FrameType::GOAWAY, 0, 0, payload);
}

H2Stream& Http2Connection::get_or_create_stream(uint32_t stream_id) {
    auto it = streams_.find(stream_id);
    if (it == streams_.end()) {
        auto [new_it, _] = streams_.emplace(stream_id, H2Stream{});
        new_it->second.id = stream_id;
        new_it->second.state = H2StreamState::IDLE;
        new_it->second.window_size = static_cast<int32_t>(initial_window_size_);
        if (stream_id > last_stream_id_) {
            last_stream_id_ = stream_id;
        }
        return new_it->second;
    }
    return it->second;
}

} // namespace js
