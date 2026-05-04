#include "file_handler.hpp"
#include "logger.hpp"
#include <fstream>
#include <sstream>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace js {

FileHandler::FileHandler(const Config& config)
    : doc_root_(config.document_root)
    , index_file_(config.index_file) {

    // Initialize MIME types
    mime_types_ = {
        {".html", "text/html; charset=utf-8"},
        {".htm",  "text/html; charset=utf-8"},
        {".css",  "text/css; charset=utf-8"},
        {".js",   "application/javascript; charset=utf-8"},
        {".mjs",  "application/javascript; charset=utf-8"},
        {".json", "application/json; charset=utf-8"},
        {".xml",  "application/xml; charset=utf-8"},
        {".txt",  "text/plain; charset=utf-8"},
        {".csv",  "text/csv; charset=utf-8"},
        {".svg",  "image/svg+xml"},
        {".png",  "image/png"},
        {".jpg",  "image/jpeg"},
        {".jpeg", "image/jpeg"},
        {".gif",  "image/gif"},
        {".ico",  "image/x-icon"},
        {".webp", "image/webp"},
        {".avif", "image/avif"},
        {".woff", "font/woff"},
        {".woff2","font/woff2"},
        {".ttf",  "font/ttf"},
        {".otf",  "font/otf"},
        {".eot",  "application/vnd.ms-fontobject"},
        {".pdf",  "application/pdf"},
        {".zip",  "application/zip"},
        {".gz",   "application/gzip"},
        {".mp4",  "video/mp4"},
        {".webm", "video/webm"},
        {".mp3",  "audio/mpeg"},
        {".ogg",  "audio/ogg"},
        {".wasm", "application/wasm"},
    };
}

HttpResponse FileHandler::serve(const HttpRequest& req) const {
    // Only GET and HEAD
    if (req.method != HttpMethod::GET && req.method != HttpMethod::HEAD) {
        return HttpResponse::make_error(405, "Method not allowed for static files");
    }

    auto resolved = resolve_path(req.path);
    if (!resolved) {
        LOG_WARN("Path traversal attempt blocked: " + req.path);
        return HttpResponse::make_error(403, "Access denied");
    }

    auto& file_path = *resolved;

    // Check if path is a directory, serve index file
    std::error_code ec;
    if (std::filesystem::is_directory(file_path, ec)) {
        file_path = file_path / index_file_;
    }

    // Check file exists
    if (!std::filesystem::exists(file_path, ec) || !std::filesystem::is_regular_file(file_path, ec)) {
        return HttpResponse::make_error(404, "File not found");
    }

    // Read file
    auto content = read_file(file_path);
    if (!content) {
        return HttpResponse::make_error(500, "Failed to read file");
    }

    // Build response
    HttpResponse resp;
    resp.status_code = 200;
    resp.status_text = "OK";

    auto ext = file_path.extension().string();
    resp.headers["Content-Type"] = std::string(mime_type(ext));
    resp.headers["Content-Length"] = std::to_string(content->size());
    resp.headers["X-Content-Type-Options"] = "nosniff";
    resp.headers["X-Frame-Options"] = "SAMEORIGIN";
    resp.headers["Cache-Control"] = "public, max-age=3600";
    resp.headers["Connection"] = "close";

    if (req.method == HttpMethod::HEAD) {
        resp.body.clear();
    } else {
        resp.body = std::move(*content);
    }

    return resp;
}

std::optional<std::filesystem::path> FileHandler::resolve_path(std::string_view uri_path) const {
    // Decode URI - basic percent decoding
    std::string decoded;
    decoded.reserve(uri_path.size());

    for (size_t i = 0; i < uri_path.size(); ++i) {
        if (uri_path[i] == '%' && i + 2 < uri_path.size()) {
            char hex[3] = {uri_path[i + 1], uri_path[i + 2], '\0'};
            char* end = nullptr;
            auto val = std::strtol(hex, &end, 16);
            if (end == hex + 2) {
                decoded += static_cast<char>(val);
                i += 2;
                continue;
            }
        }
        decoded += uri_path[i];
    }

    // Reject paths with null bytes
    if (decoded.find('\0') != std::string::npos) {
        return std::nullopt;
    }

    // Reject obvious traversal
    if (decoded.find("..") != std::string::npos) {
        return std::nullopt;
    }

    // Construct full path
    auto full_path = doc_root_ / decoded.substr(1); // Remove leading '/'

    // Use canonical to resolve symlinks and normalize
    std::error_code ec;
    auto canonical = std::filesystem::canonical(full_path, ec);
    if (ec) {
        // File may not exist yet - try weakly_canonical
        canonical = std::filesystem::weakly_canonical(full_path, ec);
        if (ec) {
            return std::nullopt;
        }
    }

    // Verify the resolved path is within document root
    auto canonical_root = std::filesystem::canonical(doc_root_, ec);
    if (ec) {
        canonical_root = std::filesystem::weakly_canonical(doc_root_, ec);
        if (ec) return std::nullopt;
    }

    auto root_str = canonical_root.string();
    auto path_str = canonical.string();

    if (path_str != root_str && path_str.substr(0, root_str.size() + 1) != root_str + "/") {
        LOG_WARN("Path traversal blocked: " + path_str + " outside " + root_str);
        return std::nullopt;
    }

    return canonical;
}

std::string_view FileHandler::mime_type(std::string_view extension) const {
    std::string ext_lower(extension);
    std::transform(ext_lower.begin(), ext_lower.end(), ext_lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    auto it = mime_types_.find(ext_lower);
    if (it != mime_types_.end()) {
        return it->second;
    }
    return "application/octet-stream";
}

std::optional<std::string> FileHandler::read_file(const std::filesystem::path& path) const {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return std::nullopt;
    }

    std::ostringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

std::optional<FileHandler::SendfileInfo> FileHandler::resolve_for_sendfile(const HttpRequest& req) const {
    if (req.method != HttpMethod::GET) return std::nullopt;

    auto resolved = resolve_path(req.path);
    if (!resolved) return std::nullopt;

    auto file_path = *resolved;

    std::error_code ec;
    if (std::filesystem::is_directory(file_path, ec)) {
        file_path = file_path / index_file_;
    }

    if (!std::filesystem::exists(file_path, ec) || !std::filesystem::is_regular_file(file_path, ec)) {
        return std::nullopt;
    }

    int fd = open(file_path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return std::nullopt;

    struct stat st{};
    if (fstat(fd, &st) < 0) {
        close(fd);
        return std::nullopt;
    }

    auto ext = file_path.extension().string();
    auto mt = std::string(mime_type(ext));

    // Build HTTP response headers
    std::string headers;
    headers += "HTTP/1.1 200 OK\r\n";
    headers += "Content-Type: ";
    headers += mt;
    headers += "\r\n";
    headers += "Content-Length: ";
    headers += std::to_string(st.st_size);
    headers += "\r\n";
    headers += "X-Content-Type-Options: nosniff\r\n";
    headers += "X-Frame-Options: SAMEORIGIN\r\n";
    headers += "Cache-Control: public, max-age=3600\r\n";
    headers += "X-Sendfile: true\r\n";
    headers += "Connection: close\r\n";
    headers += "\r\n";

    return SendfileInfo{fd, static_cast<size_t>(st.st_size), std::move(mt), std::move(headers)};
}

} // namespace js
