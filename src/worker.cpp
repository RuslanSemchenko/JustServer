#include "worker.hpp"
#include "logger.hpp"
#include "metrics.hpp"

#include <sys/socket.h>
#include <sys/sendfile.h>
#include <sys/time.h>
#include <unistd.h>
#include <cstring>
#include <array>
#include <chrono>

namespace js {

Worker::Worker(const Config& config, TLSContext* tls, WAF* waf,
               DDoSGuard* ddos, FileHandler* file_handler, FastCGIClient* fcgi)
    : config_(config), tls_(tls), waf_(waf), ddos_(ddos),
      file_handler_(file_handler), fcgi_(fcgi) {}

void Worker::handle_connection(int client_fd, const std::string& client_ip) {
    Metrics::instance().record_connection();
    Metrics::instance().record_worker_busy();

    auto start_time = std::chrono::steady_clock::now();
    SSL* ssl = nullptr;

    // Set read timeout for header phase (DDoS protection)
    struct timeval tv{};
    tv.tv_sec = config_.header_read_timeout_ms / 1000;
    tv.tv_usec = (config_.header_read_timeout_ms % 1000) * 1000;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // TLS handshake
    if (config_.tls_enabled && tls_ && tls_->native()) {
        ssl = tls_->wrap_socket(client_fd);
        if (!ssl) {
            LOG_WARN("TLS handshake failed for " + client_ip);
            close(client_fd);
            ddos_->release_connection(client_ip);
            Metrics::instance().record_disconnection();
            Metrics::instance().record_worker_idle();
            return;
        }
    }

    // Parse HTTP request
    HttpParser parser;
    bool success = false;

    if (ssl) {
        success = read_request(ssl, client_fd, parser);
    } else {
        success = read_request_plain(client_fd, parser);
    }

    if (!success) {
        auto resp = HttpResponse::make_error(408, "Request timeout or parse error");
        if (ssl) {
            send_response(ssl, client_fd, resp);
            SSL_shutdown(ssl);
            SSL_free(ssl);
        } else {
            send_response_plain(client_fd, resp);
        }
        close(client_fd);
        ddos_->release_connection(client_ip);

        auto elapsed = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - start_time).count();
        Metrics::instance().record_request(408, elapsed);
        Metrics::instance().record_disconnection();
        Metrics::instance().record_worker_idle();
        return;
    }

    const auto& req = parser.request();

    // WAF inspection
    if (config_.waf_enabled && waf_) {
        auto verdict = waf_->inspect(req);
        if (verdict.blocked) {
            Metrics::instance().record_waf_block();
            auto resp = HttpResponse::make_error(verdict.status_code, verdict.reason);
            if (ssl) {
                send_response(ssl, client_fd, resp);
            } else {
                send_response_plain(client_fd, resp);
            }

            auto elapsed = std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - start_time).count();
            Metrics::instance().record_request(verdict.status_code, elapsed);

            if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
            close(client_fd);
            ddos_->release_connection(client_ip);
            Metrics::instance().record_disconnection();
            Metrics::instance().record_worker_idle();
            return;
        }
    }

    // Try zero-copy sendfile for plain (non-TLS) static file requests
    if (!ssl && !is_php_request(req.path) && req.path != "/metrics") {
        if (try_sendfile(client_fd, req)) {
            auto elapsed = std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - start_time).count();
            LOG_INFO(client_ip + " " + req.method_str + " " + req.uri + " -> 200 (sendfile)");
            Metrics::instance().record_request(200, elapsed);
            close(client_fd);
            ddos_->release_connection(client_ip);
            Metrics::instance().record_disconnection();
            Metrics::instance().record_worker_idle();
            return;
        }
    }

    // Route and handle request
    auto resp = route_request(req);

    auto elapsed = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - start_time).count();
    Metrics::instance().record_request(resp.status_code, elapsed);

    // Log the request
    LOG_INFO(client_ip + " " + req.method_str + " " + req.uri +
             " -> " + std::to_string(resp.status_code));

    // Send response
    if (ssl) {
        send_response(ssl, client_fd, resp);
        Metrics::instance().record_bytes_sent(resp.body.size());
        SSL_shutdown(ssl);
        SSL_free(ssl);
    } else {
        send_response_plain(client_fd, resp);
        Metrics::instance().record_bytes_sent(resp.body.size());
    }

    close(client_fd);
    ddos_->release_connection(client_ip);
    Metrics::instance().record_disconnection();
    Metrics::instance().record_worker_idle();
}

bool Worker::try_sendfile(int client_fd, const HttpRequest& req) {
    auto info = file_handler_->resolve_for_sendfile(req);
    if (!info) return false;

    // Send headers first
    size_t sent = 0;
    while (sent < info->headers.size()) {
        auto n = send(client_fd, info->headers.data() + sent,
                      info->headers.size() - sent, MSG_NOSIGNAL);
        if (n <= 0) {
            close(info->fd);
            return false;
        }
        sent += static_cast<size_t>(n);
    }

    // Zero-copy sendfile(2) - data goes directly from page cache to NIC
    off_t offset = 0;
    size_t remaining = info->file_size;
    while (remaining > 0) {
        auto n = sendfile(client_fd, info->fd, &offset, remaining);
        if (n <= 0) break;
        remaining -= static_cast<size_t>(n);
    }

    Metrics::instance().record_bytes_sent(info->file_size);
    close(info->fd);
    return true;
}

bool Worker::read_request(SSL* ssl, [[maybe_unused]] int fd, HttpParser& parser) {
    std::array<char, 8192> buf{};
    size_t total_read = 0;

    while (true) {
        int n = SSL_read(ssl, buf.data(), static_cast<int>(buf.size()));
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
            return false;
        }

        total_read += static_cast<size_t>(n);
        Metrics::instance().record_bytes_received(static_cast<size_t>(n));

        if (total_read > static_cast<size_t>(config_.max_request_size)) {
            return false; // Request too large
        }

        auto state = parser.feed(std::span<const char>(buf.data(), static_cast<size_t>(n)));
        if (state == HttpParser::State::COMPLETE) return true;
        if (state == HttpParser::State::ERROR) return false;
    }
}

bool Worker::read_request_plain(int fd, HttpParser& parser) {
    std::array<char, 8192> buf{};
    size_t total_read = 0;

    while (true) {
        auto n = recv(fd, buf.data(), buf.size(), 0);
        if (n <= 0) return false;

        total_read += static_cast<size_t>(n);
        Metrics::instance().record_bytes_received(static_cast<size_t>(n));

        if (total_read > static_cast<size_t>(config_.max_request_size)) {
            return false;
        }

        auto state = parser.feed(std::span<const char>(buf.data(), static_cast<size_t>(n)));
        if (state == HttpParser::State::COMPLETE) return true;
        if (state == HttpParser::State::ERROR) return false;
    }
}

void Worker::send_response(SSL* ssl, [[maybe_unused]] int fd, const HttpResponse& resp) {
    auto data = resp.serialize();
    size_t sent = 0;
    while (sent < data.size()) {
        int n = SSL_write(ssl, data.data() + sent, static_cast<int>(data.size() - sent));
        if (n <= 0) break;
        sent += static_cast<size_t>(n);
    }
}

void Worker::send_response_plain(int fd, const HttpResponse& resp) {
    auto data = resp.serialize();
    size_t sent = 0;
    while (sent < data.size()) {
        auto n = send(fd, data.data() + sent, data.size() - sent, MSG_NOSIGNAL);
        if (n <= 0) break;
        sent += static_cast<size_t>(n);
    }
}

HttpResponse Worker::route_request(const HttpRequest& req) {
    // Prometheus metrics endpoint
    if (req.path == "/metrics") {
        return Metrics::instance().serve_metrics();
    }

    // PHP files go through FastCGI
    if (is_php_request(req.path) && config_.fastcgi_enabled && fcgi_) {
        auto script_path = config_.document_root / req.path.substr(1);

        auto result = fcgi_->send_request(
            req,
            script_path.string(),
            config_.document_root.string()
        );

        if (result) return *result;
        return HttpResponse::make_error(502, "FastCGI backend unavailable");
    }

    // Static files
    return file_handler_->serve(req);
}

bool Worker::is_php_request(std::string_view path) const {
    if (path.size() >= 4) {
        auto ext = path.substr(path.size() - 4);
        return ext == ".php";
    }
    return false;
}

} // namespace js
