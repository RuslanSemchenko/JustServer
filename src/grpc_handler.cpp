#include "grpc_handler.hpp"
#include "compression.hpp"
#include "logger.hpp"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <exception>

namespace js {

namespace {

constexpr std::string_view HEALTH_CHECK_METHOD = "/grpc.health.v1.Health/Check";
constexpr std::string_view HEALTH_SERVICE = "grpc.health.v1.Health";

std::string to_lower_copy(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

std::string trim_copy(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
    return std::string(s);
}

// Does a comma-separated header list (e.g. grpc-accept-encoding) contain a token?
bool list_contains(std::string_view list, std::string_view token) {
    size_t pos = 0;
    while (pos <= list.size()) {
        auto comma = list.find(',', pos);
        auto item = list.substr(pos, comma == std::string_view::npos ? std::string_view::npos : comma - pos);
        if (to_lower_copy(trim_copy(item)) == token) return true;
        if (comma == std::string_view::npos) break;
        pos = comma + 1;
    }
    return false;
}

// "package.Service/Method" -> "package.Service"
std::string service_of(std::string_view full_method) {
    if (!full_method.empty() && full_method.front() == '/') full_method.remove_prefix(1);
    auto slash = full_method.find('/');
    return std::string(full_method.substr(0, slash));
}

// Minimal protobuf reader for the health check request (field 1: string service)
bool read_varint(std::string_view data, size_t& pos, uint64_t& value) {
    value = 0;
    for (int shift = 0; shift < 64; shift += 7) {
        if (pos >= data.size()) return false;
        auto byte = static_cast<uint8_t>(data[pos++]);
        value |= static_cast<uint64_t>(byte & 0x7F) << shift;
        if ((byte & 0x80) == 0) return true;
    }
    return false; // Varint longer than 10 bytes
}

std::optional<std::string> parse_health_request(std::string_view data) {
    std::string service;
    size_t pos = 0;
    while (pos < data.size()) {
        uint64_t key = 0;
        if (!read_varint(data, pos, key)) return std::nullopt;
        uint64_t field = key >> 3;
        uint64_t wire_type = key & 0x7;
        switch (wire_type) {
            case 0: { // varint
                uint64_t ignored = 0;
                if (!read_varint(data, pos, ignored)) return std::nullopt;
                break;
            }
            case 1: // fixed64
                if (data.size() - pos < 8) return std::nullopt;
                pos += 8;
                break;
            case 2: { // length-delimited
                uint64_t len = 0;
                if (!read_varint(data, pos, len) || len > data.size() - pos) return std::nullopt;
                if (field == 1) service.assign(data.substr(pos, static_cast<size_t>(len)));
                pos += static_cast<size_t>(len);
                break;
            }
            case 5: // fixed32
                if (data.size() - pos < 4) return std::nullopt;
                pos += 4;
                break;
            default:
                return std::nullopt; // Groups / invalid wire types
        }
    }
    return service;
}

std::string encode_health_response(GrpcServingStatus status) {
    // HealthCheckResponse { ServingStatus status = 1; } -- proto3 omits the default (0)
    std::string out;
    auto value = static_cast<uint8_t>(status);
    if (value != 0) {
        out += '\x08'; // field 1, wire type 0 (varint)
        out += static_cast<char>(value);
    }
    return out;
}

} // namespace

GrpcHandler::GrpcHandler() {
    // Overall server health and the health service itself are SERVING by default
    health_status_[""] = GrpcServingStatus::SERVING;
    health_status_[std::string(HEALTH_SERVICE)] = GrpcServingStatus::SERVING;
}

void GrpcHandler::register_method(const std::string& full_method, GrpcMethodHandler handler) {
    methods_[full_method] = std::move(handler);

    auto service = service_of(full_method);
    if (!service.empty()) {
        std::lock_guard lock(health_mutex_);
        health_status_.try_emplace(service, GrpcServingStatus::SERVING);
    }
}

void GrpcHandler::set_serving_status(const std::string& service, GrpcServingStatus status) {
    std::lock_guard lock(health_mutex_);
    health_status_[service] = status;
}

bool GrpcHandler::is_grpc_request(const HttpRequest& req) {
    auto ct = req.get_header("Content-Type");
    if (ct.empty()) return false;

    auto lower_ct = to_lower_copy(ct);
    // application/grpc, application/grpc+proto, application/grpc;charset=...
    // (gRPC-Web uses a different framing and is not handled here)
    return lower_ct == "application/grpc" ||
           lower_ct.starts_with("application/grpc+") ||
           lower_ct.starts_with("application/grpc;");
}

std::optional<GrpcMessage> GrpcHandler::parse_message(std::string_view body) {
    // gRPC length-prefixed message format:
    // 1 byte: compressed flag
    // 4 bytes: message length (big-endian uint32)
    // N bytes: message data

    if (body.size() < 5) return std::nullopt;

    GrpcMessage msg;
    msg.compressed = (body[0] != 0);

    uint32_t length = (static_cast<uint32_t>(static_cast<uint8_t>(body[1])) << 24) |
                      (static_cast<uint32_t>(static_cast<uint8_t>(body[2])) << 16) |
                      (static_cast<uint32_t>(static_cast<uint8_t>(body[3])) << 8) |
                      static_cast<uint32_t>(static_cast<uint8_t>(body[4]));

    if (body.size() - 5 < length) return std::nullopt;

    msg.data = std::string(body.substr(5, length));
    return msg;
}

std::optional<std::vector<GrpcMessage>> GrpcHandler::parse_messages(std::string_view body,
                                                                    size_t max_message_size) {
    std::vector<GrpcMessage> messages;
    while (!body.empty()) {
        if (body.size() < 5) return std::nullopt;
        uint8_t flag = static_cast<uint8_t>(body[0]);
        if (flag > 1) return std::nullopt; // Only 0/1 are defined

        uint32_t length = (static_cast<uint32_t>(static_cast<uint8_t>(body[1])) << 24) |
                          (static_cast<uint32_t>(static_cast<uint8_t>(body[2])) << 16) |
                          (static_cast<uint32_t>(static_cast<uint8_t>(body[3])) << 8) |
                          static_cast<uint32_t>(static_cast<uint8_t>(body[4]));
        if (length > max_message_size || body.size() - 5 < length) return std::nullopt;

        GrpcMessage msg;
        msg.compressed = (flag == 1);
        msg.data = std::string(body.substr(5, length));
        messages.push_back(std::move(msg));
        body.remove_prefix(5 + static_cast<size_t>(length));
    }
    return messages;
}

std::string GrpcHandler::encode_message(std::string_view data, bool compressed) {
    // Bounds check: gRPC wire format uses a 4-byte length prefix (uint32)
    if (data.size() > UINT32_MAX) {
        return {};  // Message too large for gRPC wire format
    }

    std::string result;
    result.reserve(5 + data.size());

    // Compression flag
    result += compressed ? '\x01' : '\x00';

    // Message length (big-endian uint32)
    uint32_t len = static_cast<uint32_t>(data.size());
    result += static_cast<char>((len >> 24) & 0xFF);
    result += static_cast<char>((len >> 16) & 0xFF);
    result += static_cast<char>((len >> 8) & 0xFF);
    result += static_cast<char>(len & 0xFF);

    // Message data
    result.append(data);
    return result;
}

std::string GrpcHandler::percent_encode_message(std::string_view message) {
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(message.size());
    for (char ch : message) {
        auto c = static_cast<unsigned char>(ch);
        if (c >= 0x20 && c <= 0x7E && c != '%') {
            out += ch;
        } else {
            out += '%';
            out += hex[c >> 4];
            out += hex[c & 0x0F];
        }
    }
    return out;
}

void GrpcHandler::set_grpc_trailers(HttpResponse& resp, GrpcStatus status,
                                     std::string_view message) {
    auto status_str = std::to_string(static_cast<int>(status));
    auto encoded_msg = percent_encode_message(message);

    if (resp.body.empty()) {
        // Trailers-Only response: status travels in the (only) HEADERS frame
        resp.headers["grpc-status"] = status_str;
        if (!message.empty()) resp.headers["grpc-message"] = encoded_msg;
        else resp.headers.erase("grpc-message");
        return;
    }

    std::erase_if(resp.trailers, [](const auto& kv) {
        return kv.first == "grpc-status" || kv.first == "grpc-message";
    });
    resp.trailers.emplace_back("grpc-status", status_str);
    if (!message.empty()) resp.trailers.emplace_back("grpc-message", encoded_msg);
}

std::optional<int> GrpcHandler::response_status(const HttpResponse& resp) {
    auto parse = [](const std::string& v) -> std::optional<int> {
        if (v.empty() || v.size() > 3) return std::nullopt;
        int out = 0;
        for (char c : v) {
            if (c < '0' || c > '9') return std::nullopt;
            out = out * 10 + (c - '0');
        }
        return out;
    };
    for (const auto& [name, value] : resp.trailers) {
        if (to_lower_copy(name) == "grpc-status") return parse(value);
    }
    for (const auto& [name, value] : resp.headers) {
        if (to_lower_copy(name) == "grpc-status") return parse(value);
    }
    return std::nullopt;
}

HttpResponse GrpcHandler::handle(const HttpRequest& req) const {
    // gRPC method is the request path: /package.Service/Method
    auto method_it = methods_.find(req.path);
    const bool builtin_health = (method_it == methods_.end() && req.path == HEALTH_CHECK_METHOD);

    if (method_it == methods_.end() && !builtin_health) {
        LOG_WARN("gRPC: unimplemented method " + req.path);
        return make_grpc_error(GrpcStatus::UNIMPLEMENTED, "Method not found: " + req.path);
    }

    if (!req.method_str.empty() && req.method_str != "POST") {
        return make_grpc_error(GrpcStatus::UNIMPLEMENTED, "gRPC requires POST");
    }

    // Parse the incoming gRPC message(s) from the request body
    auto messages = parse_messages(req.body);
    if (!messages) {
        LOG_WARN("gRPC: failed to parse message for " + req.path);
        return make_grpc_error(GrpcStatus::INTERNAL, "Failed to parse gRPC message");
    }
    // Unary methods take exactly one request message
    if (messages->size() != 1) {
        return make_grpc_error(GrpcStatus::INTERNAL,
                               messages->empty() ? "Missing request message"
                                                 : "Too many request messages for a unary method");
    }

    auto& msg = messages->front();
    if (msg.compressed) {
        auto encoding = to_lower_copy(trim_copy(req.get_header("grpc-encoding")));
        if (encoding.empty() || encoding == "identity") {
            return make_grpc_error(GrpcStatus::INTERNAL,
                                   "Compressed flag set with identity encoding");
        }
        if (encoding != "gzip" && encoding != "deflate") {
            auto resp = make_grpc_error(GrpcStatus::UNIMPLEMENTED,
                                        "Unsupported grpc-encoding: " + encoding);
            return resp;
        }
        // zlib's auto-detection handles both gzip (RFC 1952) and deflate/zlib (RFC 1950)
        auto plain = Compressor::gzip_decompress(msg.data, DEFAULT_MAX_MESSAGE_SIZE);
        if (!plain) {
            return make_grpc_error(GrpcStatus::INTERNAL, "Failed to decompress gRPC message");
        }
        msg.data = std::move(*plain);
        msg.compressed = false;
    }

    if (builtin_health) {
        return handle_health_check(req, msg.data);
    }

    // Call the handler
    std::pair<GrpcStatus, std::string> result;
    try {
        result = method_it->second(msg.data);
    } catch (const std::exception& e) {
        LOG_ERROR("gRPC: handler for " + req.path + " threw: " + e.what());
        return make_grpc_error(GrpcStatus::INTERNAL, "Handler error");
    } catch (...) {
        LOG_ERROR("gRPC: handler for " + req.path + " threw an unknown exception");
        return make_grpc_error(GrpcStatus::INTERNAL, "Handler error");
    }

    auto& [status, response_data] = result;
    LOG_DEBUG("gRPC: " + req.path + " -> status " + std::to_string(static_cast<int>(status)));

    if (status != GrpcStatus::OK) {
        // Non-OK handlers may return a human-readable error message as payload
        return make_grpc_error(status, response_data);
    }

    return make_ok_response(req, response_data);
}

HttpResponse GrpcHandler::handle_health_check(const HttpRequest& req,
                                              std::string_view request_data) const {
    auto service = parse_health_request(request_data);
    if (!service) {
        return make_grpc_error(GrpcStatus::INVALID_ARGUMENT, "Malformed HealthCheckRequest");
    }

    GrpcServingStatus status;
    {
        std::lock_guard lock(health_mutex_);
        auto it = health_status_.find(*service);
        if (it == health_status_.end()) {
            return make_grpc_error(GrpcStatus::NOT_FOUND, "Unknown service: " + *service);
        }
        status = it->second;
    }

    return make_ok_response(req, encode_health_response(status));
}

HttpResponse GrpcHandler::make_ok_response(const HttpRequest& req,
                                           const std::string& response_data) const {
    HttpResponse resp;
    resp.status_code = 200;
    resp.status_text = "OK";

    // Mirror the request's content subtype (application/grpc+proto, +json, ...)
    auto req_ct = to_lower_copy(req.get_header("Content-Type"));
    resp.headers["content-type"] = req_ct.starts_with("application/grpc+") ? req_ct : "application/grpc";
    resp.headers["grpc-accept-encoding"] = std::string(ACCEPT_ENCODING);

    // Compress large responses when the client accepts gzip
    bool compress = response_data.size() >= COMPRESS_MIN_SIZE &&
                    list_contains(req.get_header("grpc-accept-encoding"), "gzip");
    if (compress) {
        auto compressed = Compressor::gzip_compress(response_data);
        if (compressed.size() < response_data.size()) {
            resp.headers["grpc-encoding"] = "gzip";
            resp.body = encode_message(compressed, true);
        } else {
            compress = false;
        }
    }
    if (!compress) {
        resp.body = encode_message(response_data);
    }

    set_grpc_trailers(resp, GrpcStatus::OK);
    return resp;
}

HttpResponse GrpcHandler::make_grpc_error(GrpcStatus status, std::string_view message) const {
    HttpResponse resp;
    resp.status_code = 200; // gRPC always uses HTTP 200, errors in trailers
    resp.status_text = "OK";
    resp.headers["content-type"] = "application/grpc";
    resp.headers["grpc-accept-encoding"] = std::string(ACCEPT_ENCODING);
    set_grpc_trailers(resp, status, message); // No body: Trailers-Only form
    return resp;
}

} // namespace js
