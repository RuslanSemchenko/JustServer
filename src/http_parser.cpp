#include "http_parser.hpp"
#include <algorithm>
#include <charconv>
#include <cstring>

namespace js {

std::string_view HttpRequest::get_header(std::string_view name) const {
    // Case-insensitive header lookup
    std::string lower_name(name);
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    for (const auto& [key, val] : headers) {
        std::string lower_key(key);
        std::transform(lower_key.begin(), lower_key.end(), lower_key.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        if (lower_key == lower_name) {
            return val;
        }
    }
    return {};
}

bool HttpRequest::has_header(std::string_view name) const {
    return !get_header(name).empty();
}

std::string HttpResponse::serialize() const {
    std::string result;
    result.reserve(512 + body.size());

    result += "HTTP/1.1 ";
    result += std::to_string(status_code);
    result += " ";
    result += status_text;
    result += "\r\n";

    for (const auto& [key, val] : headers) {
        result += key;
        result += ": ";
        result += val;
        result += "\r\n";
    }

    // Always include Content-Length
    bool has_cl = false;
    for (const auto& [key, val] : headers) {
        std::string lower_key(key);
        std::transform(lower_key.begin(), lower_key.end(), lower_key.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        if (lower_key == "content-length") { has_cl = true; break; }
    }
    if (!has_cl) {
        result += "Content-Length: ";
        result += std::to_string(body.size());
        result += "\r\n";
    }

    result += "\r\n";
    result += body;
    return result;
}

HttpResponse HttpResponse::make_error(int code, std::string_view message) {
    HttpResponse resp;
    resp.status_code = code;

    switch (code) {
        case 400: resp.status_text = "Bad Request"; break;
        case 403: resp.status_text = "Forbidden"; break;
        case 404: resp.status_text = "Not Found"; break;
        case 405: resp.status_text = "Method Not Allowed"; break;
        case 408: resp.status_text = "Request Timeout"; break;
        case 413: resp.status_text = "Payload Too Large"; break;
        case 429: resp.status_text = "Too Many Requests"; break;
        case 500: resp.status_text = "Internal Server Error"; break;
        case 502: resp.status_text = "Bad Gateway"; break;
        default: resp.status_text = "Error"; break;
    }

    resp.headers["Content-Type"] = "text/html; charset=utf-8";
    resp.headers["Connection"] = "close";

    resp.body = "<!DOCTYPE html><html><head><title>";
    resp.body += std::to_string(code);
    resp.body += " ";
    resp.body += resp.status_text;
    resp.body += "</title></head><body><h1>";
    resp.body += std::to_string(code);
    resp.body += " ";
    resp.body += resp.status_text;
    resp.body += "</h1><p>";
    resp.body += message;
    resp.body += "</p><hr><p>JustServer/1.0</p></body></html>";

    return resp;
}

HttpResponse HttpResponse::make_redirect(std::string_view location, int code) {
    HttpResponse resp;
    resp.status_code = code;
    resp.status_text = (code == 301) ? "Moved Permanently" : "Found";
    resp.headers["Location"] = std::string(location);
    resp.headers["Connection"] = "close";
    resp.body = "";
    return resp;
}

HttpParser::State HttpParser::feed(std::span<const char> data) {
    buffer_.append(data.data(), data.size());

    if (!headers_done_) {
        // Look for end of headers
        auto header_end = buffer_.find("\r\n\r\n");
        if (header_end == std::string::npos) {
            // Check if buffer is too large (possible attack)
            if (buffer_.size() > 16 * 1024) {
                error_ = "Headers too large";
                return State::ERROR;
            }
            return State::INCOMPLETE;
        }

        // Parse headers
        std::string_view header_section(buffer_.data(), header_end);

        // Parse request line
        auto first_line_end = header_section.find("\r\n");
        if (first_line_end == std::string_view::npos) {
            error_ = "Invalid request line";
            return State::ERROR;
        }

        if (!parse_request_line(header_section.substr(0, first_line_end))) {
            return State::ERROR;
        }

        // Parse header lines
        auto remaining = header_section.substr(first_line_end + 2);
        while (!remaining.empty()) {
            auto line_end = remaining.find("\r\n");
            std::string_view line;
            if (line_end == std::string_view::npos) {
                line = remaining;
                remaining = {};
            } else {
                line = remaining.substr(0, line_end);
                remaining = remaining.substr(line_end + 2);
            }

            if (!line.empty()) {
                if (!parse_header_line(line)) {
                    return State::ERROR;
                }
            }
        }

        headers_done_ = true;

        // Check for Content-Length
        auto cl = request_.get_header("Content-Length");
        if (!cl.empty()) {
            auto result = std::from_chars(cl.data(), cl.data() + cl.size(), content_length_);
            if (result.ec != std::errc()) {
                error_ = "Invalid Content-Length";
                return State::ERROR;
            }
        }

        // Record where the body starts in the buffer
        body_start_offset_ = header_end + 4;

        parse_uri();
    }

    if (headers_done_) {
        // Update body tracking from the growing buffer on every feed() call
        if (body_start_offset_ < buffer_.size()) {
            body_received_ = buffer_.size() - body_start_offset_;
            request_.body = buffer_.substr(body_start_offset_);
        }

        if (body_received_ >= content_length_) {
            // Trim body to content_length
            if (request_.body.size() > content_length_) {
                request_.body.resize(content_length_);
            }
            return State::COMPLETE;
        }
        return State::INCOMPLETE;
    }

    return State::INCOMPLETE;
}

void HttpParser::reset() {
    request_ = HttpRequest{};
    buffer_.clear();
    error_.clear();
    headers_done_ = false;
    content_length_ = 0;
    body_received_ = 0;
    body_start_offset_ = 0;
}

bool HttpParser::parse_request_line(std::string_view line) {
    // METHOD SP URI SP VERSION
    auto sp1 = line.find(' ');
    if (sp1 == std::string_view::npos) {
        error_ = "Invalid request line: no method";
        return false;
    }

    auto method = line.substr(0, sp1);
    request_.method_str = std::string(method);

    if (method == "GET") request_.method = HttpMethod::GET;
    else if (method == "POST") request_.method = HttpMethod::POST;
    else if (method == "PUT") request_.method = HttpMethod::PUT;
    else if (method == "DELETE") request_.method = HttpMethod::DELETE_;
    else if (method == "HEAD") request_.method = HttpMethod::HEAD;
    else if (method == "OPTIONS") request_.method = HttpMethod::OPTIONS;
    else if (method == "PATCH") request_.method = HttpMethod::PATCH;
    else request_.method = HttpMethod::UNKNOWN;

    auto rest = line.substr(sp1 + 1);
    auto sp2 = rest.find(' ');
    if (sp2 == std::string_view::npos) {
        error_ = "Invalid request line: no URI";
        return false;
    }

    request_.uri = std::string(rest.substr(0, sp2));
    request_.version = std::string(rest.substr(sp2 + 1));

    return true;
}

bool HttpParser::parse_header_line(std::string_view line) {
    auto colon = line.find(':');
    if (colon == std::string_view::npos) {
        error_ = "Invalid header line";
        return false;
    }

    auto name = line.substr(0, colon);
    auto value = line.substr(colon + 1);

    // Trim whitespace from value
    auto vstart = value.find_first_not_of(" \t");
    if (vstart != std::string_view::npos) {
        value = value.substr(vstart);
    }

    request_.headers[std::string(name)] = std::string(value);
    return true;
}

void HttpParser::parse_uri() {
    auto qmark = request_.uri.find('?');
    if (qmark != std::string::npos) {
        request_.path = request_.uri.substr(0, qmark);
        request_.query_string = request_.uri.substr(qmark + 1);
    } else {
        request_.path = request_.uri;
    }
}

} // namespace js
