#pragma once

#include "http_parser.hpp"
#include <string>
#include <string_view>
#include <unordered_map>
#include <optional>

namespace js {

class FastCGIClient {
public:
    explicit FastCGIClient(std::string_view socket_path);

    // Send a request to FastCGI backend and get response
    std::optional<HttpResponse> send_request(
        const HttpRequest& req,
        std::string_view script_filename,
        std::string_view document_root
    );

private:
    // FastCGI record types
    static constexpr uint8_t FCGI_BEGIN_REQUEST = 1;
    static constexpr uint8_t FCGI_ABORT_REQUEST = 2;
    static constexpr uint8_t FCGI_END_REQUEST = 3;
    static constexpr uint8_t FCGI_PARAMS = 4;
    static constexpr uint8_t FCGI_STDIN = 5;
    static constexpr uint8_t FCGI_STDOUT = 6;
    static constexpr uint8_t FCGI_STDERR = 7;

    static constexpr uint16_t FCGI_RESPONDER = 1;
    static constexpr uint8_t FCGI_KEEP_CONN = 0;

    struct Header {
        uint8_t version;
        uint8_t type;
        uint16_t request_id;
        uint16_t content_length;
        uint8_t padding_length;
        uint8_t reserved;
    } __attribute__((packed));

    std::string build_header(uint8_t type, uint16_t request_id, uint16_t content_length);
    std::string build_begin_request(uint16_t request_id);
    std::string encode_params(const std::unordered_map<std::string, std::string>& params);
    std::string encode_name_value(std::string_view name, std::string_view value);

    int connect_to_socket();
    std::optional<std::string> read_response(int fd);
    HttpResponse parse_fcgi_response(std::string_view raw);

    std::string socket_path_;
};

} // namespace js
