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

        // Validate headers for request smuggling protection
        if (!validate_headers()) {
            return State::ERROR;
        }

        headers_done_ = true;

        // Record where the body starts in the buffer
        body_start_offset_ = header_end + 4;

        parse_uri();
    }

    if (headers_done_) {
        if (use_chunked_) {
            // Chunked transfer encoding: parse chunks
            // We accumulate body from chunks until we see a 0-length chunk
            size_t pos = body_start_offset_;
            while (pos < buffer_.size() && !chunk_done_) {
                if (reading_chunk_size_) {
                    // Look for chunk size line
                    auto crlf = buffer_.find("\r\n", pos);
                    if (crlf == std::string::npos) {
                        return State::INCOMPLETE;
                    }
                    std::string_view size_str(buffer_.data() + pos, crlf - pos);
                    // Parse hex chunk size (ignore extensions after semicolon)
                    auto semi = size_str.find(';');
                    if (semi != std::string_view::npos) {
                        size_str = size_str.substr(0, semi);
                    }
                    size_t chunk_size = 0;
                    auto result = std::from_chars(size_str.data(), size_str.data() + size_str.size(),
                                                  chunk_size, 16);
                    if (result.ec != std::errc()) {
                        error_ = "Invalid chunk size";
                        return State::ERROR;
                    }
                    if (chunk_size == 0) {
                        chunk_done_ = true;
                        // Look for trailing \r\n after the 0 chunk
                        if (crlf + 2 + 2 <= buffer_.size()) {
                            return State::COMPLETE;
                        }
                        return State::INCOMPLETE;
                    }
                    current_chunk_remaining_ = chunk_size;
                    reading_chunk_size_ = false;
                    pos = crlf + 2;
                } else {
                    // Read chunk data
                    size_t available = buffer_.size() - pos;
                    size_t to_read = std::min(available, current_chunk_remaining_);
                    request_.body.append(buffer_.data() + pos, to_read);
                    current_chunk_remaining_ -= to_read;
                    pos += to_read;
                    if (current_chunk_remaining_ == 0) {
                        // Skip trailing \r\n after chunk data
                        if (pos + 2 > buffer_.size()) {
                            return State::INCOMPLETE;
                        }
                        pos += 2;
                        reading_chunk_size_ = true;
                    }
                }
            }
            // Update body_start_offset_ to track our position
            body_start_offset_ = pos;
            if (chunk_done_) return State::COMPLETE;
            return State::INCOMPLETE;
        }

        // Content-Length based body reading
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
    has_content_length_ = false;
    has_transfer_encoding_chunked_ = false;
    use_chunked_ = false;
    body_received_ = 0;
    body_start_offset_ = 0;
    content_length_count_ = 0;
    chunk_done_ = false;
    current_chunk_remaining_ = 0;
    reading_chunk_size_ = true;
}

bool HttpParser::parse_request_line(std::string_view line) {
    // Reject lines with null bytes
    if (line.find('\0') != std::string_view::npos) {
        error_ = "Null byte in request line";
        return false;
    }

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

    // Validate HTTP version
    if (request_.version != "HTTP/1.0" && request_.version != "HTTP/1.1") {
        error_ = "Unsupported HTTP version: " + request_.version;
        return false;
    }

    return true;
}

bool HttpParser::parse_header_line(std::string_view line) {
    // Reject lines with null bytes
    if (line.find('\0') != std::string_view::npos) {
        error_ = "Null byte in header";
        return false;
    }

    auto colon = line.find(':');
    if (colon == std::string_view::npos) {
        error_ = "Invalid header line";
        return false;
    }

    auto name = line.substr(0, colon);
    auto value = line.substr(colon + 1);

    // Reject header names with spaces (HTTP desync vector)
    if (name.find(' ') != std::string_view::npos || name.find('\t') != std::string_view::npos) {
        error_ = "Space in header name (request smuggling vector)";
        return false;
    }

    // Trim whitespace from value
    auto vstart = value.find_first_not_of(" \t");
    if (vstart != std::string_view::npos) {
        value = value.substr(vstart);
    }
    auto vend = value.find_last_not_of(" \t");
    if (vend != std::string_view::npos) {
        value = value.substr(0, vend + 1);
    }

    // Lowercase name for comparison
    std::string lower_name(name);
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    // Track Content-Length for smuggling protection
    if (lower_name == "content-length") {
        content_length_count_++;
        if (content_length_count_ > 1) {
            error_ = "Duplicate Content-Length header (request smuggling attempt)";
            return false;
        }
        has_content_length_ = true;
        auto result = std::from_chars(value.data(), value.data() + value.size(), content_length_);
        if (result.ec != std::errc()) {
            error_ = "Invalid Content-Length value";
            return false;
        }
    }

    // Track Transfer-Encoding
    if (lower_name == "transfer-encoding") {
        std::string lower_val(value);
        std::transform(lower_val.begin(), lower_val.end(), lower_val.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        if (lower_val.find("chunked") != std::string::npos) {
            has_transfer_encoding_chunked_ = true;
        }
    }

    request_.headers[std::string(name)] = std::string(value);
    return true;
}

bool HttpParser::validate_headers() {
    // Request Smuggling Protection (RFC 7230 Section 3.3.3):
    // If both Transfer-Encoding and Content-Length are present,
    // Transfer-Encoding takes priority and Content-Length MUST be ignored.
    if (has_transfer_encoding_chunked_ && has_content_length_) {
        // Per RFC 7230: TE takes priority, CL is ignored
        use_chunked_ = true;
        content_length_ = 0;
        has_content_length_ = false;
    } else if (has_transfer_encoding_chunked_) {
        use_chunked_ = true;
    }
    // If only Content-Length, content_length_ is already set from parse_header_line

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
