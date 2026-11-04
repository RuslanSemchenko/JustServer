#include "grpc_handler.hpp"
#include "compression.hpp"
#include <iostream>
#include <functional>
#include <cstring>
#include <stdexcept>

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

namespace {

HttpRequest make_grpc_request(const std::string& path, const std::string& body) {
    HttpRequest req;
    req.method = HttpMethod::POST;
    req.method_str = "POST";
    req.path = path;
    req.uri = path;
    req.headers["content-type"] = "application/grpc";
    req.body = body;
    return req;
}

int grpc_status(const HttpResponse& resp) {
    auto st = GrpcHandler::response_status(resp);
    return st ? *st : -1;
}

// Protobuf: HealthCheckRequest { string service = 1; }
std::string health_request(const std::string& service) {
    std::string pb;
    if (!service.empty()) {
        pb += '\x0a';
        pb += static_cast<char>(service.size());
        pb += service;
    }
    return pb;
}

} // namespace

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
    ASSERT_EQ(grpc_status(resp), 0); // OK (sent as trailer after the body)
    ASSERT_TRUE(resp.headers.find("grpc-status") == resp.headers.end());

    // Response body should contain the encoded health response
    auto msg = GrpcHandler::parse_message(resp.body);
    ASSERT_TRUE(msg.has_value());
    // The response should have protobuf data (field 1 = SERVING)
    ASSERT_TRUE(msg->data.size() >= 2);
    ASSERT_EQ(msg->data, std::string("\x08\x01", 2));
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
    ASSERT_EQ(grpc_status(resp), 0); // OK

    auto msg = GrpcHandler::parse_message(resp.body);
    ASSERT_TRUE(msg.has_value());
    ASSERT_EQ(msg->data, test_data);
    return true;
}

TEST(grpc_gzip_compressed_request) {
    GrpcHandler handler;
    handler.register_method("/test.Echo/Echo",
        [](std::string_view data) -> std::pair<GrpcStatus, std::string> {
            return {GrpcStatus::OK, std::string(data)};
        });

    std::string payload = "compressed gRPC payload compressed gRPC payload";
    auto req = make_grpc_request("/test.Echo/Echo",
        GrpcHandler::encode_message(Compressor::gzip_compress(payload), true));
    req.headers["grpc-encoding"] = "gzip";

    auto resp = handler.handle(req);
    ASSERT_EQ(grpc_status(resp), 0);
    auto msg = GrpcHandler::parse_message(resp.body);
    ASSERT_TRUE(msg.has_value());
    ASSERT_FALSE(msg->compressed);
    ASSERT_EQ(msg->data, payload);
    return true;
}

TEST(grpc_compression_errors) {
    GrpcHandler handler;
    handler.register_method("/test.Echo/Echo",
        [](std::string_view data) -> std::pair<GrpcStatus, std::string> {
            return {GrpcStatus::OK, std::string(data)};
        });

    // Compressed flag without grpc-encoding -> INTERNAL
    auto req = make_grpc_request("/test.Echo/Echo", GrpcHandler::encode_message("x", true));
    ASSERT_EQ(grpc_status(handler.handle(req)), 13);

    // Unsupported encoding -> UNIMPLEMENTED
    req.headers["grpc-encoding"] = "snappy";
    ASSERT_EQ(grpc_status(handler.handle(req)), 12);

    // Corrupt gzip data -> INTERNAL
    req.headers["grpc-encoding"] = "gzip";
    ASSERT_EQ(grpc_status(handler.handle(req)), 13);
    return true;
}

TEST(grpc_response_compression_when_accepted) {
    GrpcHandler handler;
    std::string big(8192, 'z');
    handler.register_method("/test.Big/Get",
        [&big](std::string_view) -> std::pair<GrpcStatus, std::string> {
            return {GrpcStatus::OK, big};
        });

    auto req = make_grpc_request("/test.Big/Get", GrpcHandler::encode_message(""));
    req.headers["grpc-accept-encoding"] = "identity, gzip";
    auto resp = handler.handle(req);
    ASSERT_EQ(grpc_status(resp), 0);
    ASSERT_EQ(resp.headers["grpc-encoding"], "gzip");
    auto msg = GrpcHandler::parse_message(resp.body);
    ASSERT_TRUE(msg.has_value());
    ASSERT_TRUE(msg->compressed);
    auto plain = Compressor::gzip_decompress(msg->data);
    ASSERT_TRUE(plain.has_value());
    ASSERT_EQ(*plain, big);

    // Without grpc-accept-encoding the response stays uncompressed
    auto req2 = make_grpc_request("/test.Big/Get", GrpcHandler::encode_message(""));
    auto resp2 = handler.handle(req2);
    auto msg2 = GrpcHandler::parse_message(resp2.body);
    ASSERT_TRUE(msg2.has_value());
    ASSERT_FALSE(msg2->compressed);
    ASSERT_EQ(msg2->data, big);
    return true;
}

TEST(grpc_health_per_service) {
    GrpcHandler handler;
    handler.register_method("/shop.Cart/Add",
        [](std::string_view) -> std::pair<GrpcStatus, std::string> { return {GrpcStatus::OK, ""}; });

    // Registered service is SERVING
    auto resp = handler.handle(make_grpc_request("/grpc.health.v1.Health/Check",
        GrpcHandler::encode_message(health_request("shop.Cart"))));
    ASSERT_EQ(grpc_status(resp), 0);
    auto msg = GrpcHandler::parse_message(resp.body);
    ASSERT_TRUE(msg.has_value());
    ASSERT_EQ(msg->data, std::string("\x08\x01", 2));

    // Status can be changed
    handler.set_serving_status("shop.Cart", GrpcServingStatus::NOT_SERVING);
    resp = handler.handle(make_grpc_request("/grpc.health.v1.Health/Check",
        GrpcHandler::encode_message(health_request("shop.Cart"))));
    msg = GrpcHandler::parse_message(resp.body);
    ASSERT_TRUE(msg.has_value());
    ASSERT_EQ(msg->data, std::string("\x08\x02", 2));

    // Unknown service -> NOT_FOUND
    resp = handler.handle(make_grpc_request("/grpc.health.v1.Health/Check",
        GrpcHandler::encode_message(health_request("no.Such"))));
    ASSERT_EQ(grpc_status(resp), 5);

    // Malformed protobuf -> INVALID_ARGUMENT
    resp = handler.handle(make_grpc_request("/grpc.health.v1.Health/Check",
        GrpcHandler::encode_message(std::string("\x0a\x7f", 2))));
    ASSERT_EQ(grpc_status(resp), 3);
    return true;
}

TEST(grpc_message_framing_errors) {
    GrpcHandler handler;
    handler.register_method("/test.Echo/Echo",
        [](std::string_view data) -> std::pair<GrpcStatus, std::string> {
            return {GrpcStatus::OK, std::string(data)};
        });

    // Two messages for a unary method
    auto two = GrpcHandler::encode_message("a") + GrpcHandler::encode_message("b");
    ASSERT_EQ(grpc_status(handler.handle(make_grpc_request("/test.Echo/Echo", two))), 13);

    // Missing message
    ASSERT_EQ(grpc_status(handler.handle(make_grpc_request("/test.Echo/Echo", ""))), 13);

    // parse_messages enforces the size limit and rejects bad flags
    ASSERT_FALSE(GrpcHandler::parse_messages(GrpcHandler::encode_message("hello"), 4).has_value());
    std::string bad_flag = GrpcHandler::encode_message("x");
    bad_flag[0] = '\x07';
    ASSERT_FALSE(GrpcHandler::parse_messages(bad_flag).has_value());
    auto parsed = GrpcHandler::parse_messages(two);
    ASSERT_TRUE(parsed.has_value());
    ASSERT_EQ(parsed->size(), 2u);
    return true;
}

TEST(grpc_handler_errors_and_messages) {
    GrpcHandler handler;
    handler.register_method("/test.Fail/Denied",
        [](std::string_view) -> std::pair<GrpcStatus, std::string> {
            return {GrpcStatus::PERMISSION_DENIED, "no access: 100%"};
        });
    handler.register_method("/test.Fail/Throw",
        [](std::string_view) -> std::pair<GrpcStatus, std::string> {
            throw std::runtime_error("boom");
        });

    auto resp = handler.handle(make_grpc_request("/test.Fail/Denied", GrpcHandler::encode_message("")));
    ASSERT_EQ(grpc_status(resp), 7);
    ASSERT_TRUE(resp.body.empty()); // Trailers-Only
    ASSERT_EQ(resp.headers["grpc-message"], "no access: 100%25");

    resp = handler.handle(make_grpc_request("/test.Fail/Throw", GrpcHandler::encode_message("")));
    ASSERT_EQ(grpc_status(resp), 13);

    ASSERT_EQ(GrpcHandler::percent_encode_message("caf\xc3\xa9\n"), "caf%C3%A9%0A");
    return true;
}

TEST(grpc_web_not_treated_as_grpc) {
    HttpRequest req;
    req.headers["content-type"] = "application/grpc-web+proto";
    ASSERT_FALSE(GrpcHandler::is_grpc_request(req));
    req.headers["content-type"] = "application/grpc; charset=utf-8";
    ASSERT_TRUE(GrpcHandler::is_grpc_request(req));
    return true;
}
