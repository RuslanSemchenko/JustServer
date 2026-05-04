#pragma once

#include "http_parser.hpp"
#include "config.hpp"
#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_map>
#include <optional>

namespace js {

class FileHandler {
public:
    explicit FileHandler(const Config& config);

    // Resolve and serve a file, returns response
    HttpResponse serve(const HttpRequest& req) const;

private:
    // Safely resolve a request path to a filesystem path
    // Returns std::nullopt if path traversal is detected
    std::optional<std::filesystem::path> resolve_path(std::string_view uri_path) const;

    // Get MIME type for a file extension
    std::string_view mime_type(std::string_view extension) const;

    // Read file content
    std::optional<std::string> read_file(const std::filesystem::path& path) const;

    std::filesystem::path doc_root_;
    std::string index_file_;
    std::unordered_map<std::string, std::string> mime_types_;

public:
    // Sendfile support: resolve path and return fd + size for zero-copy transfer
    struct SendfileInfo {
        int fd = -1;
        size_t file_size = 0;
        std::string mime;
        std::string headers; // Pre-built HTTP headers
    };

    // Resolve file for sendfile(2) zero-copy. Returns nullopt if not suitable.
    std::optional<SendfileInfo> resolve_for_sendfile(const HttpRequest& req) const;
};

} // namespace js
