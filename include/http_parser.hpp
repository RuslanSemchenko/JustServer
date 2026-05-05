#pragma once

#include <string>
#include <string_view>
#include <unordered_map>
#include <optional>
#include <span>

namespace js {

enum class HttpMethod {
    GET,
    POST,
    PUT,
    DELETE_,
    HEAD,
    OPTIONS,
    PATCH,
    UNKNOWN,
};

struct HttpRequest {
    HttpMethod method = HttpMethod::UNKNOWN;
    std::string method_str;
    std::string uri;
    std::string path;
    std::string query_string;
    std::string version;
    std::unordered_map<std::string, std::string> headers;
    std::string body;

    std::string_view get_header(std::string_view name) const;
    bool has_header(std::string_view name) const;
};

struct HttpResponse {
    int status_code = 200;
    std::string status_text = "OK";
    std::unordered_map<std::string, std::string> headers;
    std::string body;

    std::string serialize() const;

    static HttpResponse make_error(int code, std::string_view message);
    static HttpResponse make_redirect(std::string_view location, int code = 301);
};

class HttpParser {
public:
    enum class State {
        INCOMPLETE,
        COMPLETE,
        ERROR,
    };

    // Feed data into parser, returns state
    State feed(std::span<const char> data);

    // Get parsed request (only valid when state == COMPLETE)
    const HttpRequest& request() const { return request_; }

    // Reset for next request
    void reset();

    // Get error message
    std::string_view error() const { return error_; }

private:
    bool parse_request_line(std::string_view line);
    bool parse_header_line(std::string_view line);
    bool validate_headers();
    void parse_uri();

    HttpRequest request_;
    std::string buffer_;
    std::string error_;
    bool headers_done_ = false;
    size_t content_length_ = 0;
    bool has_content_length_ = false;
    bool has_transfer_encoding_chunked_ = false;
    bool use_chunked_ = false;
    size_t body_received_ = 0;
    size_t body_start_offset_ = 0;

    // Duplicate Content-Length detection
    int content_length_count_ = 0;

    // Chunked transfer encoding state
    bool chunk_done_ = false;
    size_t current_chunk_remaining_ = 0;
    bool reading_chunk_size_ = true;
};

} // namespace js
