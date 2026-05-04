#include "fastcgi_client.hpp"
#include "logger.hpp"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <cstring>
#include <algorithm>
#include <arpa/inet.h>

namespace js {

FastCGIClient::FastCGIClient(std::string_view socket_path)
    : socket_path_(socket_path) {}

int FastCGIClient::connect_to_socket() {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        LOG_ERROR("FastCGI: failed to create socket");
        return -1;
    }

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

    if (connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        LOG_ERROR("FastCGI: failed to connect to " + socket_path_);
        close(fd);
        return -1;
    }

    return fd;
}

std::string FastCGIClient::build_header(uint8_t type, uint16_t request_id, uint16_t content_length) {
    Header hdr{};
    hdr.version = 1;
    hdr.type = type;
    hdr.request_id = htons(request_id);
    hdr.content_length = htons(content_length);
    hdr.padding_length = 0;
    hdr.reserved = 0;

    return std::string(reinterpret_cast<const char*>(&hdr), sizeof(hdr));
}

std::string FastCGIClient::build_begin_request(uint16_t request_id) {
    auto header = build_header(FCGI_BEGIN_REQUEST, request_id, 8);

    // Begin request body: role (2 bytes) + flags (1 byte) + reserved (5 bytes)
    char body[8] = {};
    uint16_t role = htons(FCGI_RESPONDER);
    std::memcpy(body, &role, 2);
    body[2] = FCGI_KEEP_CONN;

    return header + std::string(body, 8);
}

std::string FastCGIClient::encode_name_value(std::string_view name, std::string_view value) {
    std::string result;

    auto encode_length = [&result](size_t len) {
        if (len < 128) {
            result += static_cast<char>(len);
        } else {
            uint32_t nl = htonl(static_cast<uint32_t>(len) | 0x80000000u);
            result.append(reinterpret_cast<const char*>(&nl), 4);
        }
    };

    encode_length(name.size());
    encode_length(value.size());
    result.append(name.data(), name.size());
    result.append(value.data(), value.size());

    return result;
}

std::string FastCGIClient::encode_params(const std::unordered_map<std::string, std::string>& params) {
    std::string all_params;
    for (const auto& [name, value] : params) {
        all_params += encode_name_value(name, value);
    }
    return all_params;
}

std::optional<HttpResponse> FastCGIClient::send_request(
    const HttpRequest& req,
    std::string_view script_filename,
    std::string_view document_root
) {
    int fd = connect_to_socket();
    if (fd < 0) return std::nullopt;

    uint16_t request_id = 1;
    std::string packet;

    // 1. Begin request
    packet += build_begin_request(request_id);

    // 2. Params
    std::unordered_map<std::string, std::string> params = {
        {"REQUEST_METHOD", req.method_str},
        {"REQUEST_URI", req.uri},
        {"SCRIPT_NAME", req.path},
        {"SCRIPT_FILENAME", std::string(script_filename)},
        {"QUERY_STRING", req.query_string},
        {"DOCUMENT_ROOT", std::string(document_root)},
        {"SERVER_SOFTWARE", "JustServer/1.0"},
        {"SERVER_PROTOCOL", req.version},
        {"GATEWAY_INTERFACE", "CGI/1.1"},
        {"CONTENT_LENGTH", std::to_string(req.body.size())},
    };

    // Forward relevant HTTP headers
    for (const auto& [name, value] : req.headers) {
        std::string env_name = "HTTP_";
        for (char c : name) {
            env_name += (c == '-') ? '_' : static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        }
        params[env_name] = value;
    }

    auto ct = req.get_header("Content-Type");
    if (!ct.empty()) {
        params["CONTENT_TYPE"] = std::string(ct);
    }

    auto encoded_params = encode_params(params);

    // Send params in chunks if needed
    size_t offset = 0;
    while (offset < encoded_params.size()) {
        size_t chunk = std::min(encoded_params.size() - offset, size_t(65535));
        packet += build_header(FCGI_PARAMS, request_id, static_cast<uint16_t>(chunk));
        packet += encoded_params.substr(offset, chunk);
        offset += chunk;
    }
    // Empty PARAMS record to signal end
    packet += build_header(FCGI_PARAMS, request_id, 0);

    // 3. STDIN (request body)
    if (!req.body.empty()) {
        size_t body_offset = 0;
        while (body_offset < req.body.size()) {
            size_t chunk = std::min(req.body.size() - body_offset, size_t(65535));
            packet += build_header(FCGI_STDIN, request_id, static_cast<uint16_t>(chunk));
            packet += req.body.substr(body_offset, chunk);
            body_offset += chunk;
        }
    }
    // Empty STDIN to signal end
    packet += build_header(FCGI_STDIN, request_id, 0);

    // Send all at once
    auto total = packet.size();
    size_t sent = 0;
    while (sent < total) {
        auto n = write(fd, packet.data() + sent, total - sent);
        if (n <= 0) {
            LOG_ERROR("FastCGI: write failed");
            close(fd);
            return std::nullopt;
        }
        sent += static_cast<size_t>(n);
    }

    // Read response
    auto raw_response = read_response(fd);
    close(fd);

    if (!raw_response) return std::nullopt;

    return parse_fcgi_response(*raw_response);
}

std::optional<std::string> FastCGIClient::read_response(int fd) {
    std::string stdout_data;
    std::string stderr_data;

    while (true) {
        Header hdr{};
        auto n = read(fd, &hdr, sizeof(hdr));
        if (n <= 0) break;
        if (n != sizeof(hdr)) {
            LOG_ERROR("FastCGI: incomplete header");
            return std::nullopt;
        }

        uint16_t content_length = ntohs(hdr.content_length);
        uint8_t padding_length = hdr.padding_length;

        std::string content(content_length, '\0');
        size_t total_read = 0;
        while (total_read < content_length) {
            n = read(fd, content.data() + total_read, content_length - total_read);
            if (n <= 0) {
                LOG_ERROR("FastCGI: read content failed");
                return std::nullopt;
            }
            total_read += static_cast<size_t>(n);
        }

        // Skip padding
        if (padding_length > 0) {
            char pad[256];
            size_t pad_read = 0;
            while (pad_read < padding_length) {
                n = read(fd, pad, std::min(static_cast<size_t>(padding_length) - pad_read, sizeof(pad)));
                if (n <= 0) break;
                pad_read += static_cast<size_t>(n);
            }
        }

        switch (hdr.type) {
            case FCGI_STDOUT:
                stdout_data += content;
                break;
            case FCGI_STDERR:
                stderr_data += content;
                if (!stderr_data.empty()) {
                    LOG_WARN("FastCGI stderr: " + stderr_data);
                }
                break;
            case FCGI_END_REQUEST:
                return stdout_data;
            default:
                break;
        }
    }

    return stdout_data.empty() ? std::nullopt : std::optional(stdout_data);
}

HttpResponse FastCGIClient::parse_fcgi_response(std::string_view raw) {
    HttpResponse resp;
    resp.status_code = 200;
    resp.status_text = "OK";

    // FastCGI response has headers followed by \r\n\r\n then body
    auto header_end = raw.find("\r\n\r\n");
    if (header_end == std::string_view::npos) {
        // No headers, treat entire output as body
        resp.body = std::string(raw);
        resp.headers["Content-Type"] = "text/html; charset=utf-8";
        return resp;
    }

    // Parse CGI headers
    auto header_section = raw.substr(0, header_end);
    while (!header_section.empty()) {
        auto line_end = header_section.find("\r\n");
        std::string_view line;
        if (line_end == std::string_view::npos) {
            line = header_section;
            header_section = {};
        } else {
            line = header_section.substr(0, line_end);
            header_section = header_section.substr(line_end + 2);
        }

        auto colon = line.find(':');
        if (colon == std::string_view::npos) continue;

        auto name = line.substr(0, colon);
        auto value = line.substr(colon + 1);
        auto vstart = value.find_first_not_of(" \t");
        if (vstart != std::string_view::npos) value = value.substr(vstart);

        if (name == "Status") {
            // Parse status code
            auto sp = value.find(' ');
            if (sp != std::string_view::npos) {
                resp.status_code = std::stoi(std::string(value.substr(0, sp)));
                resp.status_text = std::string(value.substr(sp + 1));
            }
        } else {
            resp.headers[std::string(name)] = std::string(value);
        }
    }

    resp.body = std::string(raw.substr(header_end + 4));
    resp.headers["Connection"] = "close";

    return resp;
}

} // namespace js
