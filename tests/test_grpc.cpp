#include "grpc_handler.hpp"
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

TEST(grpc_detect_request) {
    HttpRequest req;
    req.method = HttpMethod::POST;
    req.headers["Content-Type"] = "application/grpc";
    ASSERT_TRUE(GrpcHandler::is_grpc_request(req));
    return true;
}

TEST(grpc_detect_request_with_proto) {
    HttpRequest req;
    req.method = HttpMethod::POST;
    req.headers["content-type"] = "application/grpc+proto";
    ASSERT_TRUE(GrpcHandler::is_grpc_request(req));
    return true;
}

TEST(grpc_not_detected_for_json) {
    HttpRequest req;
    req.method = HttpMethod::POST;
    req.headers["Content-Type"] = "application/json";
    ASSERT_FALSE(GrpcHandler::is_grpc_request(req));
    return true;
}

TEST(grpc_encode_decode_message) {
    std::string original = "Hello, gRPC!";
    auto encoded = GrpcHandler::encode_message(original);

    ASSERT_EQ(encoded.size(), 5 + original.size());
    ASSERT_EQ(encoded[0], '\0'); // Not compressed

    auto decoded = GrpcHandler::parse_message(encoded);
    ASSERT_TRUE(decoded.has_value());
    ASSERT_FALSE(decoded->compressed);
    ASSERT_EQ(decoded->data, original);
    return true;
}

TEST(grpc_encode_empty_message) {
    auto encoded = GrpcHandler::encode_message("");
    ASSERT_EQ(encoded.size(), 5u);

    auto decoded = GrpcHandler::parse_message(encoded);
    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded->data, "");
    return true;
}

TEST(grpc_parse_invalid_message) {
    // Too short
    auto decoded = GrpcHandler::parse_message("abc");
    ASSERT_FALSE(decoded.has_value());
    return true;
}

TEST(grpc_parse_truncated_message) {
    // Header says 100 bytes but only 3 available
    std::string truncated;
    truncated += '\0';           // Not compressed
    truncated += '\0';
    truncated += '\0';
    truncated += '\0';
    truncated += '\x64';         // Length = 100
    truncated += "abc";          // Only 3 bytes
    auto decoded = GrpcHandler::parse_message(truncated);
    ASSERT_FALSE(decoded.has_value());
    return true;
}

TEST(grpc_health_check) {
    GrpcHandler handler;

    HttpRequest req;
    req.method = HttpMethod::POST;
    req.method_str = "POST";
    req.path = "/grpc.health.v1.Health/Check";
    req.uri = "/grpc.health.v1.Health/Check";
    req.headers["content-type"] = "application/grpc";

    // Send empty health check request (empty protobuf)
    req.body = GrpcHandler::encode_message("");

    auto resp = handler.handle(req);
    ASSERT_EQ(resp.status_code, 200);
    ASSERT_EQ(resp.headers["grpc-status"], "0"); // OK

    // Response body should contain the encoded health response
    auto msg = GrpcHandler::parse_message(resp.body);
    ASSERT_TRUE(msg.has_value());
    // The response should have protobuf data (field 1 = SERVING)
    ASSERT_TRUE(msg->data.size() >= 2);
    return true;
}

TEST(grpc_unimplemented_method) {
    GrpcHandler handler;

    HttpRequest req;
    req.method = HttpMethod::POST;
    req.method_str = "POST";
    req.path = "/foo.Bar/NonExistent";
    req.uri = "/foo.Bar/NonExistent";
    req.headers["content-type"] = "application/grpc";
    req.body = GrpcHandler::encode_message("");

    auto resp = handler.handle(req);
    ASSERT_EQ(resp.status_code, 200); // gRPC uses 200 even for errors
    ASSERT_EQ(resp.headers["grpc-status"], "12"); // UNIMPLEMENTED
    return true;
}

TEST(grpc_custom_method_handler) {
    GrpcHandler handler;

    handler.register_method("/test.Echo/Echo",
        [](std::string_view request_data) -> std::pair<GrpcStatus, std::string> {
            // Simple echo: return the same data
            return {GrpcStatus::OK, std::string(request_data)};
        });

    HttpRequest req;
    req.method = HttpMethod::POST;
    req.method_str = "POST";
    req.path = "/test.Echo/Echo";
    req.uri = "/test.Echo/Echo";
    req.headers["content-type"] = "application/grpc";

    std::string test_data = "echo me!";
    req.body = GrpcHandler::encode_message(test_data);

    auto resp = handler.handle(req);
    ASSERT_EQ(resp.headers["grpc-status"], "0"); // OK

    auto msg = GrpcHandler::parse_message(resp.body);
    ASSERT_TRUE(msg.has_value());
    ASSERT_EQ(msg->data, test_data);
    return true;
}
