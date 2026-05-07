#include "websocket.hpp"
#include "logger.hpp"

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <cstring>
#include <algorithm>
#include <arpa/inet.h>

namespace js {

// ===== WsHandshake =====

static const std::string WS_MAGIC_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

bool WsHandshake::is_upgrade_request(const HttpRequest& req) {
    // RFC 6455 Section 4.2.1: Opening Handshake requirements
    if (req.method != HttpMethod::GET) return false;

    auto upgrade = req.get_header("Upgrade");
    if (upgrade.empty()) return false;
    std::string lower_upgrade(upgrade);
    std::transform(lower_upgrade.begin(), lower_upgrade.end(), lower_upgrade.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (lower_upgrade != "websocket") return false;

    auto connection = req.get_header("Connection");
    std::string lower_conn(connection);
    std::transform(lower_conn.begin(), lower_conn.end(), lower_conn.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (lower_conn.find("upgrade") == std::string::npos) return false;

    auto key = req.get_header("Sec-WebSocket-Key");
    if (key.empty()) return false;

    auto version = req.get_header("Sec-WebSocket-Version");
    if (version != "13") return false;

    return true;
}

std::string WsHandshake::compute_accept_key(std::string_view client_key) {
    // SHA-1 of (client_key + magic GUID), then base64 encode
    std::string combined(client_key);
    combined += WS_MAGIC_GUID;

    unsigned char sha1_hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(combined.data()),
         combined.size(), sha1_hash);

    // Base64 encode
    // Output length for SHA1 (20 bytes) is ceil(20/3)*4 = 28 chars + null
    char b64[64] = {};
    EVP_EncodeBlock(reinterpret_cast<unsigned char*>(b64), sha1_hash, SHA_DIGEST_LENGTH);

    return std::string(b64);
}

HttpResponse WsHandshake::build_accept_response(const HttpRequest& req) {
    HttpResponse resp;
    resp.status_code = 101;
    resp.status_text = "Switching Protocols";
    resp.headers["Upgrade"] = "websocket";
    resp.headers["Connection"] = "Upgrade";

    auto key = req.get_header("Sec-WebSocket-Key");
    resp.headers["Sec-WebSocket-Accept"] = compute_accept_key(key);

    return resp;
}

// ===== WsConnection =====

WsConnection::WsConnection() = default;

std::string WsConnection::process_input(std::span<const char> data) {
    buffer_.append(data.data(), data.size());
    std::string output;

    while (!closed_) {
        auto frame = parse_frame();
        if (!frame) break;

        output += handle_frame(*frame);
    }

    return output;
}

std::optional<WsFrame> WsConnection::parse_frame() {
    // Minimum frame is 2 bytes (no mask, payload <= 125)
    if (buffer_.size() < 2) return std::nullopt;

    size_t pos = 0;
    WsFrame frame;

    uint8_t byte0 = static_cast<uint8_t>(buffer_[0]);
    uint8_t byte1 = static_cast<uint8_t>(buffer_[1]);

    frame.fin = (byte0 & 0x80) != 0;
    uint8_t rsv = (byte0 >> 4) & 0x07;
    if (rsv != 0) {
        // RSV bits must be 0 unless extensions are negotiated
        closed_ = true;
        return std::nullopt;
    }
    frame.opcode = static_cast<WsOpcode>(byte0 & 0x0F);
    frame.masked = (byte1 & 0x80) != 0;

    uint64_t payload_len = byte1 & 0x7F;
    pos = 2;

    if (payload_len == 126) {
        if (buffer_.size() < pos + 2) return std::nullopt;
        payload_len = (static_cast<uint64_t>(static_cast<uint8_t>(buffer_[pos])) << 8) |
                      static_cast<uint64_t>(static_cast<uint8_t>(buffer_[pos + 1]));
        pos += 2;
    } else if (payload_len == 127) {
        if (buffer_.size() < pos + 8) return std::nullopt;
        payload_len = 0;
        for (int i = 0; i < 8; ++i) {
            payload_len = (payload_len << 8) | static_cast<uint64_t>(static_cast<uint8_t>(buffer_[pos + static_cast<size_t>(i)]));
        }
        pos += 8;
        // Most significant bit must be 0 per RFC 6455
        if (payload_len & (1ULL << 63)) {
            closed_ = true;
            return std::nullopt;
        }
    }

    if (payload_len > MAX_FRAME_SIZE) {
        closed_ = true;
        return std::nullopt;
    }

    frame.payload_length = payload_len;

    // Read mask key if present (client -> server frames MUST be masked)
    if (!frame.masked) {
        // RFC 6455 Section 5.1: server MUST close connection on unmasked frame
        closed_ = true;
        return std::nullopt;
    }
    if (buffer_.size() < pos + 4) return std::nullopt;
    std::memcpy(frame.mask_key, buffer_.data() + pos, 4);
    pos += 4;

    // Read payload
    if (buffer_.size() < pos + payload_len) return std::nullopt;

    frame.payload.assign(buffer_.data() + pos, static_cast<size_t>(payload_len));
    pos += static_cast<size_t>(payload_len);

    // Unmask payload
    if (frame.masked) {
        unmask(frame.payload, frame.mask_key);
    }

    // Remove consumed data from buffer
    buffer_.erase(0, pos);

    return frame;
}

std::string WsConnection::handle_frame(const WsFrame& frame) {
    std::string output;

    switch (frame.opcode) {
        case WsOpcode::TEXT:
        case WsOpcode::BINARY:
            if (in_fragment_) {
                // Protocol error: new message while fragmentation in progress
                output += build_close(WsClose::PROTOCOL_ERROR, "Expected continuation frame");
                closed_ = true;
                return output;
            }
            if (frame.fin) {
                // Complete single-frame message
                if (on_message_) {
                    on_message_(frame.opcode, frame.payload);
                }
            } else {
                // Start of fragmented message
                in_fragment_ = true;
                fragment_opcode_ = frame.opcode;
                message_buffer_ = frame.payload;
                if (message_buffer_.size() > MAX_MESSAGE_SIZE) {
                    output += build_close(WsClose::TOO_BIG, "Message too large");
                    closed_ = true;
                }
            }
            break;

        case WsOpcode::CONTINUATION:
            if (!in_fragment_) {
                output += build_close(WsClose::PROTOCOL_ERROR, "Unexpected continuation");
                closed_ = true;
                return output;
            }
            message_buffer_ += frame.payload;
            if (message_buffer_.size() > MAX_MESSAGE_SIZE) {
                output += build_close(WsClose::TOO_BIG, "Message too large");
                closed_ = true;
                return output;
            }
            if (frame.fin) {
                in_fragment_ = false;
                if (on_message_) {
                    on_message_(fragment_opcode_, message_buffer_);
                }
                message_buffer_.clear();
            }
            break;

        case WsOpcode::CLOSE: {
            uint16_t code = WsClose::NO_STATUS;
            std::string_view reason;
            if (frame.payload.size() >= 2) {
                code = (static_cast<uint16_t>(static_cast<uint8_t>(frame.payload[0])) << 8) |
                       static_cast<uint16_t>(static_cast<uint8_t>(frame.payload[1]));
                if (frame.payload.size() > 2) {
                    reason = std::string_view(frame.payload.data() + 2, frame.payload.size() - 2);
                }
            }
            if (on_close_) {
                on_close_(code, reason);
            }
            if (!close_sent_) {
                output += build_close(code, reason);
                close_sent_ = true;
            }
            closed_ = true;
            break;
        }

        case WsOpcode::PING:
            if (frame.payload.size() > 125) {
                output += build_close(WsClose::PROTOCOL_ERROR, "Ping payload too large");
                closed_ = true;
                return output;
            }
            if (on_ping_) {
                on_ping_(frame.payload);
            }
            // Send pong with same payload
            output += build_frame(WsOpcode::PONG, frame.payload);
            break;

        case WsOpcode::PONG:
            // Unsolicited pongs are ignored per RFC 6455
            break;

        default:
            // Unknown opcode
            output += build_close(WsClose::PROTOCOL_ERROR, "Unknown opcode");
            closed_ = true;
            break;
    }

    return output;
}

void WsConnection::unmask(std::string& data, const uint8_t mask[4]) {
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] ^= static_cast<char>(mask[i % 4]);
    }
}

std::string WsConnection::build_frame(WsOpcode opcode, std::string_view payload, bool fin) {
    std::string frame;

    // Byte 0: FIN + opcode
    uint8_t byte0 = static_cast<uint8_t>(opcode);
    if (fin) byte0 |= 0x80;
    frame += static_cast<char>(byte0);

    // Byte 1: mask bit (0 for server) + payload length
    if (payload.size() <= 125) {
        frame += static_cast<char>(payload.size());
    } else if (payload.size() <= 65535) {
        frame += static_cast<char>(126);
        frame += static_cast<char>((payload.size() >> 8) & 0xFF);
        frame += static_cast<char>(payload.size() & 0xFF);
    } else {
        frame += static_cast<char>(127);
        uint64_t len = payload.size();
        for (int i = 7; i >= 0; --i) {
            frame += static_cast<char>((len >> (i * 8)) & 0xFF);
        }
    }

    // No mask key for server -> client
    frame.append(payload);
    return frame;
}

std::string WsConnection::build_close(uint16_t code, std::string_view reason) {
    std::string payload;
    payload += static_cast<char>((code >> 8) & 0xFF);
    payload += static_cast<char>(code & 0xFF);
    payload.append(reason);
    return build_frame(WsOpcode::CLOSE, payload);
}

} // namespace js
