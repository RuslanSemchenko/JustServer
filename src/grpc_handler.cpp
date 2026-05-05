#include "grpc_handler.hpp"
#include "logger.hpp"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <arpa/inet.h>

namespace js {

GrpcHandler::GrpcHandler() {
    // Register built-in gRPC health check (grpc.health.v1.Health/Check)
    register_method("/grpc.health.v1.Health/Check",
        [](std::string_view /*request_data*/) -> std::pair<GrpcStatus, std::string> {
            // Return a simple HealthCheckResponse with SERVING status
            // This is a minimal protobuf encoding: field 1 (status), varint = 1 (SERVING)
            std::string response;
            response += '\x08'; // field 1, wire type 0 (varint)
            response += '\x01'; // value 1 = SERVING
            return {GrpcStatus::OK, response};
        });
}

void GrpcHandler::register_method(const std::string& full_method, GrpcMethodHandler handler) {
    methods_[full_method] = std::move(handler);
}

bool GrpcHandler::is_grpc_request(const HttpRequest& req) {
    auto ct = req.get_header("Content-Type");
    if (ct.empty()) return false;

    std::string lower_ct(ct);
    std::transform(lower_ct.begin(), lower_ct.end(), lower_ct.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    return lower_ct.starts_with("application/grpc");
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

    if (body.size() < 5 + length) return std::nullopt;

    msg.data = std::string(body.substr(5, length));
    return msg;
}

std::string GrpcHandler::encode_message(std::string_view data, bool compressed) {
    std::string result;
    result.reserve(5 + data.size());

    // Bounds check: gRPC wire format uses a 4-byte length prefix (uint32)
    if (data.size() > UINT32_MAX) {
        return {};  // Message too large for gRPC wire format
    }

    // Compression flag
    result += compressed ? '\x01' : '\x00';

    // Message length (big-endian uint32)
    if (data.size() > UINT32_MAX) {
        return {};  // Message too large for gRPC wire format
    }
    if (data.size() > UINT32_MAX) {
        return {};  // Message too large for gRPC wire format
    }
    uint32_t len = static_cast<uint32_t>(data.size());
    result += static_cast<char>((len >> 24) & 0xFF);
    result += static_cast<char>((len >> 16) & 0xFF);
    result += static_cast<char>((len >> 8) & 0xFF);
    result += static_cast<char>(len & 0xFF);

    // Message data
    result.append(data);
    return result;
}

void GrpcHandler::set_grpc_trailers(HttpResponse& resp, GrpcStatus status,
                                     std::string_view message) {
    resp.headers["grpc-status"] = std::to_string(static_cast<int>(status));
    if (!message.empty()) {
        resp.headers["grpc-message"] = std::string(message);
    }
}

HttpResponse GrpcHandler::handle(const HttpRequest& req) const {
    // gRPC method is the request path: /package.Service/Method
    auto method_it = methods_.find(req.path);

    if (method_it == methods_.end()) {
        LOG_WARN("gRPC: unimplemented method " + req.path);
        return make_grpc_error(GrpcStatus::UNIMPLEMENTED,
                               "Method not found: " + req.path);
    }

    // Parse the incoming gRPC message from the request body
    auto msg = parse_message(req.body);
    if (!msg) {
        LOG_WARN("gRPC: failed to parse message for " + req.path);
        return make_grpc_error(GrpcStatus::INTERNAL, "Failed to parse gRPC message");
    }

    if (msg->compressed) {
        return make_grpc_error(GrpcStatus::UNIMPLEMENTED,
                               "Compressed messages not supported");
    }

    // Call the handler
    auto [status, response_data] = method_it->second(msg->data);

    // Build response
    HttpResponse resp;
    resp.status_code = 200;
    resp.status_text = "OK";
    resp.headers["content-type"] = "application/grpc";

    if (status == GrpcStatus::OK) {
        resp.body = encode_message(response_data);
    }

    set_grpc_trailers(resp, status);

    LOG_INFO("gRPC: " + req.path + " -> status " + std::to_string(static_cast<int>(status)));
    return resp;
}

HttpResponse GrpcHandler::make_grpc_error(GrpcStatus status, std::string_view message) const {
    HttpResponse resp;
    resp.status_code = 200; // gRPC always uses HTTP 200, errors in trailers
    resp.status_text = "OK";
    resp.headers["content-type"] = "application/grpc";
    set_grpc_trailers(resp, status, message);
    return resp;
}

} // namespace js
