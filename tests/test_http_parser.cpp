#include "http_parser.hpp"
#include <iostream>
#include <functional>
#include <string>
#include <cstring>

// Defined in test_main.cpp
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

TEST(http_parser_basic_get) {
    HttpParser parser;
    std::string raw = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    auto state = parser.feed(std::span<const char>(raw.data(), raw.size()));
    ASSERT_EQ(state, HttpParser::State::COMPLETE);
    ASSERT_EQ(parser.request().method, HttpMethod::GET);
    ASSERT_EQ(parser.request().path, "/index.html");
    ASSERT_EQ(parser.request().version, "HTTP/1.1");
    return true;
}

TEST(http_parser_post_with_body) {
    HttpParser parser;
    std::string raw = "POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 13\r\n\r\nHello, World!";
    auto state = parser.feed(std::span<const char>(raw.data(), raw.size()));
    ASSERT_EQ(state, HttpParser::State::COMPLETE);
    ASSERT_EQ(parser.request().method, HttpMethod::POST);
    ASSERT_EQ(parser.request().body, "Hello, World!");
    return true;
}

TEST(http_parser_query_string) {
    HttpParser parser;
    std::string raw = "GET /search?q=test&page=1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
    auto state = parser.feed(std::span<const char>(raw.data(), raw.size()));
    ASSERT_EQ(state, HttpParser::State::COMPLETE);
    ASSERT_EQ(parser.request().path, "/search");
    ASSERT_EQ(parser.request().query_string, "q=test&page=1");
    return true;
}

TEST(http_parser_duplicate_content_length_rejected) {
    HttpParser parser;
    std::string raw = "POST /api HTTP/1.1\r\nHost: example.com\r\n"
                      "Content-Length: 5\r\nContent-Length: 10\r\n\r\nHello";
    auto state = parser.feed(std::span<const char>(raw.data(), raw.size()));
    ASSERT_EQ(state, HttpParser::State::ERROR);
    // Should mention duplicate Content-Length
    std::string err(parser.error());
    ASSERT_TRUE(err.find("Duplicate") != std::string::npos || err.find("duplicate") != std::string::npos);
    return true;
}

TEST(http_parser_te_chunked_overrides_cl) {
    HttpParser parser;
    // When both Transfer-Encoding: chunked and Content-Length are present,
    // chunked takes priority (request smuggling protection)
    std::string raw = "POST /api HTTP/1.1\r\nHost: example.com\r\n"
                      "Content-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\n"
                      "5\r\nHello\r\n0\r\n\r\n";
    auto state = parser.feed(std::span<const char>(raw.data(), raw.size()));
    ASSERT_EQ(state, HttpParser::State::COMPLETE);
    ASSERT_EQ(parser.request().body, "Hello");
    return true;
}

TEST(http_parser_chunked_encoding) {
    HttpParser parser;
    std::string raw = "POST /data HTTP/1.1\r\nHost: example.com\r\n"
                      "Transfer-Encoding: chunked\r\n\r\n"
                      "5\r\nHello\r\n6\r\n World\r\n0\r\n\r\n";
    auto state = parser.feed(std::span<const char>(raw.data(), raw.size()));
    ASSERT_EQ(state, HttpParser::State::COMPLETE);
    ASSERT_EQ(parser.request().body, "Hello World");
    return true;
}

TEST(http_parser_null_byte_in_request_line) {
    HttpParser parser;
    std::string raw = "GET /index\0.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    // Manually construct with null byte
    std::string real_raw = "GET /index";
    real_raw += '\0';
    real_raw += ".html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    auto state = parser.feed(std::span<const char>(real_raw.data(), real_raw.size()));
    ASSERT_EQ(state, HttpParser::State::ERROR);
    return true;
}

TEST(http_parser_space_in_header_name_rejected) {
    HttpParser parser;
    std::string raw = "GET / HTTP/1.1\r\nHost: example.com\r\nX Bad Header: value\r\n\r\n";
    auto state = parser.feed(std::span<const char>(raw.data(), raw.size()));
    ASSERT_EQ(state, HttpParser::State::ERROR);
    return true;
}

TEST(http_parser_headers_too_large) {
    HttpParser parser;
    std::string raw = "GET / HTTP/1.1\r\nHost: example.com\r\nX-Big: ";
    raw += std::string(17000, 'A'); // Exceed 16KB header limit
    // Don't close headers yet
    auto state = parser.feed(std::span<const char>(raw.data(), raw.size()));
    ASSERT_EQ(state, HttpParser::State::ERROR);
    return true;
}

TEST(http_parser_incremental_feed) {
    HttpParser parser;
    std::string part1 = "GET /index.html HT";
    std::string part2 = "TP/1.1\r\nHost: example.com\r\n\r\n";

    auto state = parser.feed(std::span<const char>(part1.data(), part1.size()));
    ASSERT_EQ(state, HttpParser::State::INCOMPLETE);

    state = parser.feed(std::span<const char>(part2.data(), part2.size()));
    ASSERT_EQ(state, HttpParser::State::COMPLETE);
    ASSERT_EQ(parser.request().path, "/index.html");
    return true;
}

TEST(http_parser_reset) {
    HttpParser parser;
    std::string raw = "GET / HTTP/1.1\r\nHost: a.com\r\n\r\n";
    parser.feed(std::span<const char>(raw.data(), raw.size()));
    parser.reset();

    std::string raw2 = "POST /api HTTP/1.1\r\nHost: b.com\r\nContent-Length: 3\r\n\r\nfoo";
    auto state = parser.feed(std::span<const char>(raw2.data(), raw2.size()));
    ASSERT_EQ(state, HttpParser::State::COMPLETE);
    ASSERT_EQ(parser.request().method, HttpMethod::POST);
    ASSERT_EQ(parser.request().body, "foo");
    return true;
}

TEST(http_response_serialize) {
    HttpResponse resp;
    resp.status_code = 200;
    resp.status_text = "OK";
    resp.headers["Content-Type"] = "text/plain";
    resp.body = "Hello";

    auto data = resp.serialize();
    ASSERT_TRUE(data.find("HTTP/1.1 200 OK") != std::string::npos);
    ASSERT_TRUE(data.find("Content-Type: text/plain") != std::string::npos);
    ASSERT_TRUE(data.find("Hello") != std::string::npos);
    return true;
}

TEST(http_response_make_error) {
    auto resp = HttpResponse::make_error(404, "Page not found");
    ASSERT_EQ(resp.status_code, 404);
    ASSERT_EQ(resp.status_text, "Not Found");
    ASSERT_TRUE(resp.body.find("Page not found") != std::string::npos);
    return true;
}
