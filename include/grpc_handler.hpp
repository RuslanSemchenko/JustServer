#pragma once

#include "http_parser.hpp"
#include <string>
#include <string_view>
#include <unordered_map>
#include <functional>
#include <optional>

namespace js {

// gRPC status codes (subset from grpc/status.h)
enum class GrpcStatus : int {
    OK                  = 0,
    CANCELLED           = 1,
    UNKNOWN             = 2,
    INVALID_ARGUMENT    = 3,
    DEADLINE_EXCEEDED   = 4,
    NOT_FOUND           = 5,
    ALREADY_EXISTS      = 6,
    PERMISSION_DENIED   = 7,
    RESOURCE_EXHAUSTED  = 8,
    FAILED_PRECONDITION = 9,
    ABORTED             = 10,
    OUT_OF_RANGE        = 11,
    UNIMPLEMENTED       = 12,
    INTERNAL            = 13,
    UNAVAILABLE         = 14,
    DATA_LOSS           = 15,
    UNAUTHENTICATED     = 16,
};

// gRPC message (length-prefixed frame)
struct GrpcMessage {
    bool compressed = false;   // Compression flag (first byte)
    std::string data;          // Raw message bytes (protobuf-encoded)
};

// gRPC service handler - processes raw bytes (protobuf serialization is caller's job)
// Takes raw request bytes, returns raw response bytes
using GrpcMethodHandler = std::function<std::pair<GrpcStatus, std::string>(std::string_view request_data)>;

// gRPC handler that integrates with HTTP/2
class GrpcHandler {
public:
    GrpcHandler();

    // Register a method handler: /package.ServiceName/MethodName
    void register_method(const std::string& full_method, GrpcMethodHandler handler);

    // Check if an HTTP/2 request is a gRPC request
    static bool is_grpc_request(const HttpRequest& req);

    // Handle a gRPC request over HTTP/2, return the HTTP response
    HttpResponse handle(const HttpRequest& req) const;

    // Parse a gRPC length-prefixed message from the body
    static std::optional<GrpcMessage> parse_message(std::string_view body);

    // Encode a gRPC length-prefixed message
    static std::string encode_message(std::string_view data, bool compressed = false);

    // Build gRPC trailers (grpc-status + grpc-message)
    static void set_grpc_trailers(HttpResponse& resp, GrpcStatus status,
                                   std::string_view message = "");

private:
    std::unordered_map<std::string, GrpcMethodHandler> methods_;

    // Built-in reflection/health handlers
    HttpResponse handle_health_check(const HttpRequest& req) const;
    HttpResponse make_grpc_error(GrpcStatus status, std::string_view message) const;
};

} // namespace js
