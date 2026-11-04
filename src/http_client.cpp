#include "http_client.hpp"

#include "logger.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <cerrno>
#include <charconv>
#include <cctype>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <netdb.h>
#include <poll.h>
#include <sstream>
#include <sys/socket.h>
#include <unistd.h>

namespace js {
namespace {

bool is_token_char(unsigned char c) {
    if (std::isalnum(c)) return true;
    constexpr std::string_view punctuation = "!#$%&'*+-.^_`|~";
    return punctuation.find(static_cast<char>(c)) != std::string_view::npos;
}

std::string lower(std::string_view value) {
    std::string result(value);
    for (char& ch : result) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return result;
}

std::string_view trim_ows(std::string_view value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
        value.remove_prefix(1);
    }
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
        value.remove_suffix(1);
    }
    return value;
}

bool has_ctl(std::string_view value, bool allow_tab = false) {
    for (unsigned char ch : value) {
        if ((ch < 0x20 && !(allow_tab && ch == '\t')) || ch == 0x7f) return true;
    }
    return false;
}

std::optional<uint16_t> parse_port(std::string_view value) {
    if (value.empty()) return std::nullopt;
    unsigned port = 0;
    auto [end, ec] = std::from_chars(value.data(), value.data() + value.size(), port);
    if (ec != std::errc{} || end != value.data() + value.size() ||
        port == 0 || port > std::numeric_limits<uint16_t>::max()) {
        return std::nullopt;
    }
    return static_cast<uint16_t>(port);
}

std::string openssl_error() {
    unsigned long code = ERR_get_error();
    if (code == 0) return "TLS operation failed";
    char buffer[256]{};
    ERR_error_string_n(code, buffer, sizeof(buffer));
    return buffer;
}

class Connection {
public:
    explicit Connection(int fd) : fd_(fd) {}
    ~Connection() {
        if (ssl_) {
            SSL_shutdown(ssl_);
            SSL_free(ssl_);
        }
        if (fd_ >= 0) close(fd_);
    }

    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    int fd() const { return fd_; }
    SSL* ssl() const { return ssl_; }
    void set_ssl(SSL* ssl) { ssl_ = ssl; }

private:
    int fd_;
    SSL* ssl_ = nullptr;
};

int poll_timeout(std::chrono::steady_clock::time_point deadline,
                 std::chrono::steady_clock::time_point total_deadline) {
    auto effective = std::min(deadline, total_deadline);
    auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        effective - std::chrono::steady_clock::now());
    if (remaining.count() <= 0) return 0;
    return static_cast<int>(std::min<int64_t>(remaining.count(), INT_MAX));
}

bool wait_fd(int fd, short events, std::chrono::milliseconds timeout,
             std::chrono::steady_clock::time_point total_deadline,
             std::string& error) {
    auto deadline = timeout.count() > 0
        ? std::chrono::steady_clock::now() + timeout
        : std::chrono::steady_clock::time_point::max();
    while (true) {
        int ms = poll_timeout(deadline, total_deadline);
        if (ms == 0) {
            error = "HTTP request timed out";
            return false;
        }
        struct pollfd descriptor{fd, events, 0};
        int result = poll(&descriptor, 1, ms);
        if (result > 0) {
            if (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                if (!(descriptor.revents & events)) {
                    error = "socket closed while waiting for I/O";
                    return false;
                }
            }
            if (descriptor.revents & events) return true;
            continue;
        }
        if (result == 0) {
            error = "HTTP request timed out";
            return false;
        }
        if (errno == EINTR) continue;
        error = "poll failed: " + std::string(std::strerror(errno));
        return false;
    }
}

bool parse_chunked(std::string_view encoded, std::string& body, size_t max_size,
                   std::string& error) {
    size_t pos = 0;
    body.clear();
    while (true) {
        size_t line_end = encoded.find("\r\n", pos);
        if (line_end == std::string_view::npos) {
            error = "incomplete chunk-size line";
            return false;
        }
        auto line = encoded.substr(pos, line_end - pos);
        auto extension = line.find(';');
        auto size_token = line.substr(0, extension);
        if (size_token.empty() || size_token.size() > 16) {
            error = "invalid chunk size";
            return false;
        }
        uint64_t chunk_size = 0;
        for (char ch : size_token) {
            unsigned digit;
            if (ch >= '0' && ch <= '9') digit = static_cast<unsigned>(ch - '0');
            else if (ch >= 'a' && ch <= 'f') digit = static_cast<unsigned>(ch - 'a' + 10);
            else if (ch >= 'A' && ch <= 'F') digit = static_cast<unsigned>(ch - 'A' + 10);
            else {
                error = "invalid hexadecimal chunk size";
                return false;
            }
            if (chunk_size > (std::numeric_limits<uint64_t>::max() - digit) / 16) {
                error = "chunk size overflow";
                return false;
            }
            chunk_size = chunk_size * 16 + digit;
        }
        pos = line_end + 2;
        if (chunk_size == 0) {
            if (encoded.substr(pos, 2) == "\r\n") return true;
            size_t trailer_end = encoded.find("\r\n\r\n", pos);
            if (trailer_end == std::string_view::npos) {
                if (encoded.substr(pos).ends_with("\r\n")) return true;
                error = "incomplete chunk trailers";
                return false;
            }
            auto trailers = encoded.substr(pos, trailer_end - pos);
            while (!trailers.empty()) {
                size_t line_break = trailers.find("\r\n");
                auto trailer = trailers.substr(0, line_break);
                size_t colon = trailer.find(':');
                if (colon == std::string_view::npos || colon == 0 ||
                    has_ctl(trailer, true)) {
                    error = "malformed chunk trailer";
                    return false;
                }
                for (unsigned char ch : trailer.substr(0, colon)) {
                    if (!is_token_char(ch)) {
                        error = "invalid chunk trailer name";
                        return false;
                    }
                }
                if (line_break == std::string_view::npos) break;
                trailers.remove_prefix(line_break + 2);
            }
            return true;
        }
        if (chunk_size > max_size - body.size() ||
            chunk_size > encoded.size() - pos ||
            encoded.size() - pos - static_cast<size_t>(chunk_size) < 2) {
            error = "chunked response is incomplete or exceeds the size limit";
            return false;
        }
        body.append(encoded.substr(pos, static_cast<size_t>(chunk_size)));
        pos += static_cast<size_t>(chunk_size);
        if (encoded.substr(pos, 2) != "\r\n") {
            error = "chunk data is not terminated";
            return false;
        }
        pos += 2;
    }
}

struct ParsedResponseHead {
    HttpClientResponse response;
    size_t body_offset = 0;
    std::optional<size_t> content_length;
    bool chunked = false;
};

std::optional<ParsedResponseHead> parse_response_head(std::string_view raw,
                                                      std::string& error) {
    size_t header_end = raw.find("\r\n\r\n");
    if (header_end == std::string_view::npos) {
        error = "incomplete HTTP response headers";
        return std::nullopt;
    }
    size_t line_end = raw.find("\r\n");
    if (line_end == std::string_view::npos || line_end > header_end) {
        error = "malformed HTTP status line";
        return std::nullopt;
    }
    auto status_line = raw.substr(0, line_end);
    if (!status_line.starts_with("HTTP/1.0 ") && !status_line.starts_with("HTTP/1.1 ")) {
        error = "unsupported HTTP response version";
        return std::nullopt;
    }
    if (status_line.size() < 12 || status_line[9] < '1' || status_line[9] > '5' ||
        status_line[10] < '0' || status_line[10] > '9' ||
        status_line[11] < '0' || status_line[11] > '9' ||
        (status_line.size() > 12 && status_line[12] != ' ')) {
        error = "invalid HTTP status code";
        return std::nullopt;
    }
    ParsedResponseHead parsed;
    parsed.response.status = (status_line[9] - '0') * 100 +
                             (status_line[10] - '0') * 10 +
                             (status_line[11] - '0');
    if (status_line.size() > 13) parsed.response.reason = std::string(status_line.substr(13));
    if (has_ctl(parsed.response.reason, true)) {
        error = "control character in HTTP reason phrase";
        return std::nullopt;
    }
    size_t position = line_end + 2;
    while (position < header_end) {
        line_end = raw.find("\r\n", position);
        if (line_end == std::string_view::npos || line_end > header_end) {
            error = "malformed HTTP header line";
            return std::nullopt;
        }
        auto line = raw.substr(position, line_end - position);
        size_t colon = line.find(':');
        if (colon == std::string_view::npos || colon == 0 || line.front() == ' ' ||
            line.front() == '\t' || has_ctl(line, true)) {
            error = "invalid HTTP header";
            return std::nullopt;
        }
        for (unsigned char ch : line.substr(0, colon)) {
            if (!is_token_char(ch)) {
                error = "invalid HTTP header name";
                return std::nullopt;
            }
        }
        auto value = trim_ows(line.substr(colon + 1));
        parsed.response.headers.emplace_back(std::string(line.substr(0, colon)),
                                             std::string(value));
        auto name = lower(line.substr(0, colon));
        if (name == "content-length") {
            size_t length = 0;
            auto [end, ec] = std::from_chars(value.data(), value.data() + value.size(), length);
            if (value.empty() || ec != std::errc{} || end != value.data() + value.size() ||
                (parsed.content_length && *parsed.content_length != length)) {
                error = "invalid or conflicting Content-Length";
                return std::nullopt;
            }
            parsed.content_length = length;
        } else if (name == "transfer-encoding") {
            auto encoding = lower(value);
            if (encoding != "chunked") {
                error = "unsupported Transfer-Encoding";
                return std::nullopt;
            }
            parsed.chunked = true;
        }
        position = line_end + 2;
    }
    if (parsed.chunked && parsed.content_length) {
        error = "response contains both Transfer-Encoding and Content-Length";
        return std::nullopt;
    }
    parsed.body_offset = header_end + 4;
    return parsed;
}

} // namespace

bool ParsedUrl::is_ip_literal() const {
    std::array<unsigned char, 16> address{};
    return inet_pton(AF_INET, host.c_str(), address.data()) == 1 ||
           inet_pton(AF_INET6, host.c_str(), address.data()) == 1;
}

std::string ParsedUrl::host_header() const {
    std::string result = ipv6_literal ? "[" + host + "]" : host;
    uint16_t default_port = scheme == "https" ? 443 : 80;
    if (port != default_port) result += ":" + std::to_string(port);
    return result;
}

std::string HttpClientResponse::header(std::string_view name) const {
    auto wanted = lower(name);
    for (const auto& [key, value] : headers) {
        if (lower(key) == wanted) return value;
    }
    return {};
}

std::vector<std::string> HttpClientResponse::header_values(std::string_view name) const {
    auto wanted = lower(name);
    std::vector<std::string> result;
    for (const auto& [key, value] : headers) {
        if (lower(key) == wanted) result.push_back(value);
    }
    return result;
}

bool HttpClientResponse::has_header(std::string_view name) const {
    auto wanted = lower(name);
    for (const auto& [key, value] : headers) {
        (void)value;
        if (lower(key) == wanted) return true;
    }
    return false;
}

HttpClient::HttpClient(HttpClientOptions options) : options_(std::move(options)) {
    if (options_.timeout.count() <= 0) options_.timeout = std::chrono::milliseconds{1};
    if (options_.max_response_size == 0) options_.max_response_size = 1;
}

HttpClient::~HttpClient() {
    if (ssl_ctx_) SSL_CTX_free(ssl_ctx_);
}

std::optional<ParsedUrl> HttpClient::parse_url(std::string_view url) {
    if (url.empty() || has_ctl(url) || url.find(' ') != std::string_view::npos) {
        return std::nullopt;
    }
    size_t scheme_end = url.find("://");
    if (scheme_end == std::string_view::npos) return std::nullopt;
    ParsedUrl result;
    result.scheme = lower(url.substr(0, scheme_end));
    if (result.scheme != "http" && result.scheme != "https") return std::nullopt;
    auto remainder = url.substr(scheme_end + 3);
    auto authority_end = remainder.find_first_of("/?#");
    auto authority = remainder.substr(0, authority_end);
    if (authority.empty() || authority.find('@') != std::string_view::npos ||
        authority.find('\\') != std::string_view::npos) {
        return std::nullopt;
    }
    auto suffix = authority_end == std::string_view::npos
        ? std::string_view{} : remainder.substr(authority_end);
    auto fragment = suffix.find('#');
    if (fragment != std::string_view::npos) suffix = suffix.substr(0, fragment);
    auto query = suffix.find('?');
    if (query == 0) {
        result.target = "/" + std::string(suffix);
    } else {
        result.target = suffix.empty() ? "/" : std::string(suffix);
    }
    if (result.target.empty() || result.target.front() != '/') return std::nullopt;
    for (unsigned char ch : result.target) {
        if (ch <= 0x20 || ch == 0x7f || ch == '#') return std::nullopt;
    }

    std::string_view port_text;
    if (authority.front() == '[') {
        size_t close = authority.find(']');
        if (close == std::string_view::npos || close == 1) return std::nullopt;
        result.host = lower(authority.substr(1, close - 1));
        result.ipv6_literal = true;
        std::array<unsigned char, 16> address{};
        if (inet_pton(AF_INET6, result.host.c_str(), address.data()) != 1) return std::nullopt;
        if (close + 1 < authority.size()) {
            if (authority[close + 1] != ':') return std::nullopt;
            port_text = authority.substr(close + 2);
        }
    } else {
        size_t colon = authority.rfind(':');
        if (colon != std::string_view::npos) {
            if (authority.find(':') != colon) return std::nullopt;
            result.host = lower(authority.substr(0, colon));
            port_text = authority.substr(colon + 1);
        } else {
            result.host = lower(authority);
        }
        if (result.host.empty()) return std::nullopt;
        for (unsigned char ch : result.host) {
            if (!(std::isalnum(ch) || ch == '.' || ch == '-')) return std::nullopt;
        }
    }
    result.port = result.scheme == "https" ? 443 : 80;
    if (!port_text.empty()) {
        auto port = parse_port(port_text);
        if (!port) return std::nullopt;
        result.port = *port;
    } else if (!authority.empty() && authority.back() == ':') {
        return std::nullopt;
    }
    return result;
}

SSL_CTX* HttpClient::tls_context(std::string& error) {
    std::lock_guard lock(ctx_mutex_);
    if (ssl_ctx_) return ssl_ctx_;

    SSL_CTX* context = SSL_CTX_new(TLS_client_method());
    if (!context) {
        error = openssl_error();
        return nullptr;
    }
    SSL_CTX_set_min_proto_version(context, TLS1_2_VERSION);
    SSL_CTX_set_options(context, SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_verify(context, options_.verify_tls ? SSL_VERIFY_PEER : SSL_VERIFY_NONE,
                       nullptr);
    if (options_.verify_tls && options_.use_system_ca_store &&
        SSL_CTX_set_default_verify_paths(context) != 1) {
        error = "failed to load system trust store: " + openssl_error();
        SSL_CTX_free(context);
        return nullptr;
    }
    if (options_.verify_tls && !options_.ca_bundle_path.empty() &&
        SSL_CTX_load_verify_locations(context, options_.ca_bundle_path.c_str(), nullptr) != 1) {
        error = "failed to load CA bundle: " + openssl_error();
        SSL_CTX_free(context);
        return nullptr;
    }
    ssl_ctx_ = context;
    return ssl_ctx_;
}

void HttpClient::set_error(std::string error) {
    std::lock_guard lock(error_mutex_);
    last_error_ = std::move(error);
}

std::string HttpClient::last_error() const {
    std::lock_guard lock(error_mutex_);
    return last_error_;
}

std::optional<HttpClientResponse> HttpClient::request(std::string_view method,
                                                       const std::string& url,
                                                       const HeaderList& headers,
                                                       std::string_view body) {
    auto parsed_url = parse_url(url);
    if (!parsed_url) {
        set_error("invalid or unsupported URL");
        return std::nullopt;
    }
    if (method.empty() || !std::all_of(method.begin(), method.end(),
            [](unsigned char ch) { return is_token_char(ch); })) {
        set_error("invalid HTTP method");
        return std::nullopt;
    }
    for (const auto& [name, value] : headers) {
        if (name.empty() || has_ctl(name) || has_ctl(value, true) ||
            !std::all_of(name.begin(), name.end(),
                         [](unsigned char ch) { return is_token_char(ch); })) {
            set_error("invalid HTTP request header");
            return std::nullopt;
        }
    }

    auto total_deadline = options_.total_timeout.count() > 0
        ? std::chrono::steady_clock::now() + options_.total_timeout
        : std::chrono::steady_clock::time_point::max();
    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    addrinfo* addresses = nullptr;
    std::string port = std::to_string(parsed_url->port);
    int gai_result = getaddrinfo(parsed_url->host.c_str(), port.c_str(), &hints, &addresses);
    if (gai_result != 0) {
        set_error("DNS lookup failed: " + std::string(gai_strerror(gai_result)));
        return std::nullopt;
    }
    struct AddrInfoGuard {
        addrinfo* value;
        ~AddrInfoGuard() { if (value) freeaddrinfo(value); }
    } address_guard{addresses};

    std::unique_ptr<Connection> connection;
    std::string connect_error = "unable to connect to host";
    for (addrinfo* address = addresses; address; address = address->ai_next) {
        int fd = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (fd < 0) {
            connect_error = "socket failed: " + std::string(std::strerror(errno));
            continue;
        }
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            connect_error = "failed to set nonblocking mode: " + std::string(std::strerror(errno));
            close(fd);
            continue;
        }
        connection = std::make_unique<Connection>(fd);
        int result = connect(fd, address->ai_addr, address->ai_addrlen);
        if (result != 0 && errno != EINPROGRESS) {
            connect_error = "connect failed: " + std::string(std::strerror(errno));
            connection.reset();
            continue;
        }
        if (result != 0) {
            if (!wait_fd(fd, POLLOUT, options_.timeout, total_deadline, connect_error)) {
                connection.reset();
                continue;
            }
            int socket_error = 0;
            socklen_t error_len = sizeof(socket_error);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &error_len) != 0 ||
                socket_error != 0) {
                connect_error = "connect failed: " +
                    std::string(std::strerror(socket_error != 0 ? socket_error : errno));
                connection.reset();
                continue;
            }
        }
        break;
    }
    if (!connection) {
        set_error(std::move(connect_error));
        return std::nullopt;
    }

    SSL* ssl = nullptr;
    if (parsed_url->is_https()) {
        std::string tls_error;
        SSL_CTX* context = tls_context(tls_error);
        if (!context) {
            set_error(std::move(tls_error));
            return std::nullopt;
        }
        ssl = SSL_new(context);
        if (!ssl) {
            set_error(openssl_error());
            return std::nullopt;
        }
        connection->set_ssl(ssl);
        if (SSL_set_fd(ssl, connection->fd()) != 1) {
            set_error("SSL_set_fd failed: " + openssl_error());
            return std::nullopt;
        }
        if (!parsed_url->is_ip_literal() &&
            SSL_set_tlsext_host_name(ssl, parsed_url->host.c_str()) != 1) {
            set_error("failed to set TLS SNI: " + openssl_error());
            return std::nullopt;
        }
        if (options_.verify_tls) {
            X509_VERIFY_PARAM* verify = SSL_get0_param(ssl);
            int configured = parsed_url->is_ip_literal()
                ? X509_VERIFY_PARAM_set1_ip_asc(verify, parsed_url->host.c_str())
                : X509_VERIFY_PARAM_set1_host(verify, parsed_url->host.c_str(), 0);
            if (configured != 1) {
                set_error("failed to configure TLS peer name verification");
                return std::nullopt;
            }
        }
        auto tls_deadline = std::chrono::steady_clock::now() + options_.timeout;
        while (true) {
            int result = SSL_connect(ssl);
            if (result == 1) break;
            int ssl_error = SSL_get_error(ssl, result);
            short events = ssl_error == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN;
            if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE) {
                set_error("TLS handshake failed: " + openssl_error());
                return std::nullopt;
            }
            std::string wait_error;
            if (!wait_fd(connection->fd(), events, options_.timeout, total_deadline, wait_error) ||
                std::chrono::steady_clock::now() > tls_deadline) {
                set_error(wait_error.empty() ? "TLS handshake timed out" : wait_error);
                return std::nullopt;
            }
        }
        if (options_.verify_tls && SSL_get_verify_result(ssl) != X509_V_OK) {
            set_error("TLS certificate verification failed: " +
                      std::string(X509_verify_cert_error_string(SSL_get_verify_result(ssl))));
            return std::nullopt;
        }
    }

    std::ostringstream request_stream;
    request_stream << method << ' ' << parsed_url->target << " HTTP/1.1\r\n"
                   << "Host: " << parsed_url->host_header() << "\r\n"
                   << "Connection: close\r\n";
    if (!options_.user_agent.empty()) request_stream << "User-Agent: " << options_.user_agent << "\r\n";
    bool has_accept = false;
    for (const auto& [name, value] : headers) {
        auto normalized = lower(name);
        if (normalized == "host" || normalized == "connection" ||
            normalized == "content-length") continue;
        if (normalized == "user-agent") {
            request_stream << name << ": " << value << "\r\n";
        } else if (normalized == "accept") {
            has_accept = true;
            request_stream << name << ": " << value << "\r\n";
        } else {
            request_stream << name << ": " << value << "\r\n";
        }
    }
    if (!has_accept) request_stream << "Accept: */*\r\n";
    if (!body.empty() || lower(method) == "post" || lower(method) == "put" ||
        lower(method) == "patch") {
        request_stream << "Content-Length: " << body.size() << "\r\n";
    }
    request_stream << "\r\n";
    std::string request_bytes = request_stream.str();
    request_bytes.append(body);
    size_t written = 0;
    while (written < request_bytes.size()) {
        int result;
        if (ssl) {
            size_t count = 0;
            int ssl_result = SSL_write_ex(ssl, request_bytes.data() + written,
                                          request_bytes.size() - written, &count);
            if (ssl_result == 1) {
                written += count;
                continue;
            }
            int ssl_error = SSL_get_error(ssl, ssl_result);
            short events = ssl_error == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN;
            if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE) {
                set_error("TLS write failed: " + openssl_error());
                return std::nullopt;
            }
            std::string wait_error;
            if (!wait_fd(connection->fd(), events, options_.timeout, total_deadline, wait_error)) {
                set_error(std::move(wait_error));
                return std::nullopt;
            }
        } else {
            result = static_cast<int>(send(connection->fd(), request_bytes.data() + written,
                                           request_bytes.size() - written, MSG_NOSIGNAL));
            if (result > 0) {
                written += static_cast<size_t>(result);
            } else if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
                std::string wait_error;
                if (!wait_fd(connection->fd(), POLLOUT, options_.timeout,
                             total_deadline, wait_error)) {
                    set_error(std::move(wait_error));
                    return std::nullopt;
                }
            } else {
                set_error("socket write failed: " + std::string(std::strerror(errno)));
                return std::nullopt;
            }
        }
    }

    std::string raw;
    raw.reserve(std::min<size_t>(options_.max_response_size, 8192));
    std::array<char, 8192> buffer{};
    size_t header_end = std::string::npos;
    std::optional<ParsedResponseHead> parsed_head;
    while (raw.size() <= options_.max_response_size) {
        if (ssl) {
            size_t count = 0;
            int result = SSL_read_ex(ssl, buffer.data(), buffer.size(), &count);
            if (result == 1) {
                if (count > options_.max_response_size - raw.size()) {
                    set_error("HTTP response exceeds configured size limit");
                    return std::nullopt;
                }
                raw.append(buffer.data(), count);
            } else {
                int ssl_error = SSL_get_error(ssl, result);
                if (ssl_error == SSL_ERROR_ZERO_RETURN) break;
                if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE) {
                    set_error("TLS read failed: " + openssl_error());
                    return std::nullopt;
                }
                std::string wait_error;
                short events = ssl_error == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN;
                if (!wait_fd(connection->fd(), events, options_.timeout,
                             total_deadline, wait_error)) {
                    set_error(std::move(wait_error));
                    return std::nullopt;
                }
                continue;
            }
        } else {
            ssize_t result = recv(connection->fd(), buffer.data(), buffer.size(), 0);
            if (result > 0) {
                if (static_cast<size_t>(result) > options_.max_response_size - raw.size()) {
                    set_error("HTTP response exceeds configured size limit");
                    return std::nullopt;
                }
                raw.append(buffer.data(), static_cast<size_t>(result));
            } else if (result == 0) {
                break;
            } else if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                std::string wait_error;
                if (!wait_fd(connection->fd(), POLLIN, options_.timeout,
                             total_deadline, wait_error)) {
                    set_error(std::move(wait_error));
                    return std::nullopt;
                }
                continue;
            } else {
                set_error("socket read failed: " + std::string(std::strerror(errno)));
                return std::nullopt;
            }
        }

        if (!parsed_head) {
            header_end = raw.find("\r\n\r\n");
            if (header_end != std::string::npos) {
                std::string parse_error;
                parsed_head = parse_response_head(raw, parse_error);
                if (!parsed_head) {
                    set_error(std::move(parse_error));
                    return std::nullopt;
                }
                if (parsed_head->body_offset > options_.max_response_size) {
                    set_error("HTTP response headers exceed configured size limit");
                    return std::nullopt;
                }
                int status = parsed_head->response.status;
                if (status == 204 || status == 304 || lower(method) == "head") break;
                if (parsed_head->content_length &&
                    *parsed_head->content_length > options_.max_response_size -
                                                       parsed_head->body_offset) {
                    set_error("HTTP response body exceeds configured size limit");
                    return std::nullopt;
                }
            }
        }
        if (parsed_head) {
            size_t body_length = raw.size() - parsed_head->body_offset;
            if (parsed_head->content_length &&
                body_length >= *parsed_head->content_length) break;
            if (!parsed_head->chunked && !parsed_head->content_length &&
                (parsed_head->response.status == 204 || parsed_head->response.status == 304)) break;
        }
    }
    if (!parsed_head) {
        set_error("incomplete HTTP response");
        return std::nullopt;
    }

    size_t body_offset = parsed_head->body_offset;
    std::string_view encoded_body(raw.data() + body_offset, raw.size() - body_offset);
    if (lower(method) == "head" || parsed_head->response.status == 204 ||
        parsed_head->response.status == 304) {
        parsed_head->response.body.clear();
    } else if (parsed_head->chunked) {
        std::string parse_error;
        if (!parse_chunked(encoded_body, parsed_head->response.body,
                           options_.max_response_size, parse_error)) {
            set_error(std::move(parse_error));
            return std::nullopt;
        }
    } else if (parsed_head->content_length) {
        if (encoded_body.size() < *parsed_head->content_length) {
            set_error("response ended before Content-Length bytes arrived");
            return std::nullopt;
        }
        parsed_head->response.body.assign(encoded_body.substr(0, *parsed_head->content_length));
    } else {
        parsed_head->response.body.assign(encoded_body);
    }

    set_error({});
    return std::move(parsed_head->response);
}

std::optional<HttpClientResponse> HttpClient::get(const std::string& url) {
    return request("GET", url);
}

std::optional<HttpClientResponse> HttpClient::head(const std::string& url) {
    return request("HEAD", url);
}

std::optional<HttpClientResponse> HttpClient::post(const std::string& url,
                                                    std::string_view body,
                                                    const std::string& content_type) {
    return request("POST", url, {{"Content-Type", content_type}}, body);
}

} // namespace js
