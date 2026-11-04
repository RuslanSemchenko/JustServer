#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// Forward declaration (avoids pulling OpenSSL headers into every user)
typedef struct ssl_ctx_st SSL_CTX;

namespace js {

// Minimal blocking HTTP/1.1 + HTTPS client (used by the ACME client).
// One request per connection ("Connection: close"), no redirects, no proxies.

// Absolute http:// or https:// URL split into its components
struct ParsedUrl {
    std::string scheme;     // "http" or "https" (lower-case)
    std::string host;       // Host name (lower-case) or IP literal (IPv6 without brackets)
    uint16_t port = 0;      // Explicit port or the scheme's default port
    std::string target;     // Path + query ("/" when empty), fragment removed
    bool ipv6_literal = false;

    bool is_https() const { return scheme == "https"; }
    bool is_ip_literal() const;
    // Value for the Host header: [v6]/host plus ":port" when not the default port
    std::string host_header() const;
};

struct HttpClientResponse {
    int status = 0;
    std::string reason;
    std::vector<std::pair<std::string, std::string>> headers;   // In wire order, repeats kept
    std::string body;

    // First value of a header (case-insensitive name), empty string if absent
    std::string header(std::string_view name) const;
    // All values of a header in wire order (case-insensitive name)
    std::vector<std::string> header_values(std::string_view name) const;
    bool has_header(std::string_view name) const;
};

struct HttpClientOptions {
    std::chrono::milliseconds timeout{30000};           // Per connect attempt / read / write wait
    std::chrono::milliseconds total_timeout{120000};    // Whole request (excluding DNS), 0 = unlimited
    std::string ca_bundle_path;                         // Extra trusted CAs (PEM file), empty = none
    bool use_system_ca_store = true;                    // Trust the system CA store as well
    bool verify_tls = true;                             // Disable only for tests
    size_t max_response_size = 16 * 1024 * 1024;        // Cap for headers + decoded body
    std::string user_agent = "JustServer-ACME/2.0";
};

// Thread-safe: one instance may serve concurrent requests (the TLS context is shared).
// last_error() reports the most recent failure of any thread and is meant for logging.
class HttpClient {
public:
    using HeaderList = std::vector<std::pair<std::string, std::string>>;

    explicit HttpClient(HttpClientOptions options = {});
    ~HttpClient();

    HttpClient(const HttpClient&) = delete;
    HttpClient& operator=(const HttpClient&) = delete;

    // Performs one request. Host, Content-Length and Connection are managed by the
    // client (caller-supplied values for them are ignored); User-Agent and Accept
    // defaults can be overridden. Returns std::nullopt on transport/protocol errors
    // (any HTTP status, including 4xx/5xx, is a successful exchange).
    std::optional<HttpClientResponse> request(std::string_view method, const std::string& url,
                                              const HeaderList& headers = {},
                                              std::string_view body = {});

    std::optional<HttpClientResponse> get(const std::string& url);
    std::optional<HttpClientResponse> head(const std::string& url);
    std::optional<HttpClientResponse> post(const std::string& url, std::string_view body,
                                           const std::string& content_type);

    std::string last_error() const;
    const HttpClientOptions& options() const { return options_; }

    // URL parser (public for reuse and tests). Rejects user-info, unsupported
    // schemes, invalid ports and characters that could break the request line.
    static std::optional<ParsedUrl> parse_url(std::string_view url);

private:
    SSL_CTX* tls_context(std::string& error);
    void set_error(std::string error);

    HttpClientOptions options_;

    std::mutex ctx_mutex_;
    SSL_CTX* ssl_ctx_ = nullptr;     // Created lazily on the first HTTPS request

    mutable std::mutex error_mutex_;
    std::string last_error_;
};

} // namespace js
