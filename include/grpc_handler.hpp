#pragma once

#include "http_parser.hpp"
#include <string>
#include <string_view>
#include <unordered_map>
#include <functional>
#include <optional>
#include <vector>
#include <mutex>

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

// Serving status of the standard health service (grpc.health.v1.HealthCheckResponse.ServingStatus)
enum class GrpcServingStatus : int {
    UNKNOWN         = 0,
    SERVING         = 1,
    NOT_SERVING     = 2,
    SERVICE_UNKNOWN = 3,
};

// gRPC handler that integrates with HTTP/2
class GrpcHandler {
public:
    GrpcHandler();

    // Register a method handler: /package.ServiceName/MethodName
    // The service ("package.ServiceName") is automatically reported as SERVING by the health service.
    void register_method(const std::string& full_method, GrpcMethodHandler handler);

    // Override the health status reported for a service ("" = the whole server)
    void set_serving_status(const std::string& service, GrpcServingStatus status);

    // Check if an HTTP/2 request is a gRPC request
    static bool is_grpc_request(const HttpRequest& req);

    // Handle a gRPC request over HTTP/2, return the HTTP response
    // (grpc-status/grpc-message are delivered as trailers, or as headers for Trailers-Only errors)
    HttpResponse handle(const HttpRequest& req) const;

    // Parse a gRPC length-prefixed message from the body
    static std::optional<GrpcMessage> parse_message(std::string_view body);

    // Parse every length-prefixed message of a body. Returns std::nullopt if the body is
    // truncated/malformed or a message exceeds max_message_size.
    static std::optional<std::vector<GrpcMessage>> parse_messages(
        std::string_view body, size_t max_message_size = DEFAULT_MAX_MESSAGE_SIZE);

    // Encode a gRPC length-prefixed message
    static std::string encode_message(std::string_view data, bool compressed = false);

    // Set grpc-status (+ grpc-message). Call after the body is set: responses with a body get
    // the status as trailers, body-less responses use the Trailers-Only form (status in headers).
    static void set_grpc_trailers(HttpResponse& resp, GrpcStatus status,
                                   std::string_view message = "");

    // Percent-encode a grpc-message value as required by the gRPC HTTP/2 protocol spec
    static std::string percent_encode_message(std::string_view message);

    // Read grpc-status from a response (trailers first, then Trailers-Only headers)
    static std::optional<int> response_status(const HttpResponse& resp);

    // Message encodings we accept (grpc-encoding) and advertise (grpc-accept-encoding)
    static constexpr std::string_view ACCEPT_ENCODING = "identity,gzip,deflate";

    // Default maximum message size (same as the reference gRPC implementations)
    static constexpr size_t DEFAULT_MAX_MESSAGE_SIZE = 4 * 1024 * 1024;

    // Responses at least this large are compressed when the client accepts gzip
    static constexpr size_t COMPRESS_MIN_SIZE = 1024;

private:
    std::unordered_map<std::string, GrpcMethodHandler> methods_;

    // Health status per service ("" = overall server health)
    mutable std::mutex health_mutex_;
    std::unordered_map<std::string, GrpcServingStatus> health_status_;

    // Built-in reflection/health handlers
    HttpResponse handle_health_check(const HttpRequest& req, std::string_view request_data) const;
    HttpResponse make_grpc_error(GrpcStatus status, std::string_view message) const;
    HttpResponse make_ok_response(const HttpRequest& req, const std::string& response_data) const;
};

} // namespace js
