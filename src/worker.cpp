#include "worker.hpp"
#include "logger.hpp"
#include "metrics.hpp"
#include "websocket.hpp"
#include "grpc_handler.hpp"

#include <sys/socket.h>
#include <sys/sendfile.h>
#include <sys/time.h>
#include <unistd.h>
#include <cstring>
#include <array>
#include <chrono>
#include <poll.h>

namespace js {

Worker::Worker(const Config& config, TLSContext* tls, WAF* waf,
               DDoSGuard* ddos, FileHandler* file_handler, FastCGIClient* fcgi)
    : config_(config), tls_(tls), waf_(waf), ddos_(ddos),
      file_handler_(file_handler), fcgi_(fcgi) {}

void Worker::apply_security_headers(HttpResponse& resp) const {
    const auto& sh = config_.security_headers;
    if (!sh.enabled) return;

    if (sh.csp_enabled) {
        resp.headers["Content-Security-Policy"] = sh.csp_value;
    }
    if (sh.hsts_enabled && config_.tls_enabled) {
        resp.headers["Strict-Transport-Security"] = sh.hsts_value;
    }
    if (sh.xcto_enabled) {
        resp.headers["X-Content-Type-Options"] = "nosniff";
    }
    if (sh.xxss_enabled) {
        resp.headers["X-XSS-Protection"] = sh.xxss_value;
    }
    if (sh.xfo_enabled) {
        resp.headers["X-Frame-Options"] = sh.xfo_value;
    }
    if (sh.referrer_policy_enabled) {
        resp.headers["Referrer-Policy"] = sh.referrer_policy_value;
    }

    // Server header: configurable or omitted entirely to prevent fingerprinting
    if (!config_.server_header.empty()) {
        resp.headers["Server"] = config_.server_header;
    } else {
        // Remove any Server header that may have been set by sub-handlers
        resp.headers.erase("Server");
    }
}

void Worker::handle_h2_connection(SSL* ssl, int client_fd, const std::string& client_ip) {
    LOG_INFO("HTTP/2 connection from " + client_ip);

    // gRPC handler for this connection
    GrpcHandler grpc;

    Http2Connection h2_conn([this, &grpc, &client_ip](const HttpRequest& req) -> HttpResponse {
        // WAF inspection for HTTP/2 requests
        if (config_.waf_enabled && waf_) {
            auto verdict = waf_->inspect(req, config_.waf_body_inspection_limit);
            if (verdict.blocked) {
                Metrics::instance().record_waf_block();
                return HttpResponse::make_error(verdict.status_code, verdict.reason);
            }
        }

        // Rate limit check for HTTP/2 requests
        if (ddos_ && !ddos_->allow_request(client_ip)) {
            return HttpResponse::make_error(429, "Too Many Requests");
        }

        // Route gRPC requests through the gRPC handler
        if (GrpcHandler::is_grpc_request(req)) {
            auto resp = grpc.handle(req);
            apply_security_headers(resp);
            return resp;
        }

        auto resp = route_request(req, client_ip);
        apply_security_headers(resp);
        return resp;
    });

    std::array<char, 16384> buf{};

    // Set a generous timeout for HTTP/2 (longer-lived connections)
    struct timeval tv{};
    tv.tv_sec = 30;
    tv.tv_usec = 0;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (h2_conn.is_alive()) {
        int n = SSL_read(ssl, buf.data(), static_cast<int>(buf.size()));
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
            break; // Connection closed or error
        }

        Metrics::instance().record_bytes_received(static_cast<size_t>(n));

        auto response_data = h2_conn.process_input(
            std::span<const char>(buf.data(), static_cast<size_t>(n)));

        if (!response_data.empty()) {
            size_t sent = 0;
            while (sent < response_data.size()) {
                int w = SSL_write(ssl, response_data.data() + sent,
                                  static_cast<int>(response_data.size() - sent));
                if (w <= 0) goto done;
                sent += static_cast<size_t>(w);
                Metrics::instance().record_bytes_sent(static_cast<size_t>(w));
            }
        }
    }

done:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_fd);
    ddos_->release_connection(client_ip);
    Metrics::instance().record_disconnection();
    Metrics::instance().record_worker_idle();
}

void Worker::handle_connection(int client_fd, const std::string& client_ip) {
    Metrics::instance().record_connection();
    Metrics::instance().record_worker_busy();

    auto start_time = std::chrono::steady_clock::now();
    SSL* ssl = nullptr;

    // Set hard header read timeout (Anti-Slowloris protection)
    // This is the maximum time allowed to receive all headers
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

        // Check ALPN negotiation result - route to HTTP/2 if negotiated
        auto proto = TLSContext::get_negotiated_protocol(ssl);
        if (proto == NegotiatedProtocol::HTTP_2) {
            handle_h2_connection(ssl, client_fd, client_ip);
            return;
        }
    }

    // HTTP/1.1 path
    HttpParser parser;
    bool success = false;

    // Track header read deadline (hard timeout for anti-Slowloris)
    auto header_deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(config_.header_read_timeout_ms);

    if (ssl) {
        success = read_request(ssl, client_fd, parser);
    } else {
        success = read_request_plain(client_fd, parser);
    }

    // Check if we exceeded the header deadline
    if (success && std::chrono::steady_clock::now() > header_deadline) {
        success = false; // Treat as timeout
    }

    if (!success) {
        auto resp = HttpResponse::make_error(408, "Request timeout or parse error");
        apply_security_headers(resp);
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
        auto verdict = waf_->inspect(req, config_.waf_body_inspection_limit);
        if (verdict.blocked) {
            Metrics::instance().record_waf_block();
            auto resp = HttpResponse::make_error(verdict.status_code, verdict.reason);
            apply_security_headers(resp);
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

    // Rate limit check -- must happen before any early-return path
    // (sendfile, WebSocket upgrade, etc.) so every request consumes a token.
    if (ddos_ && !ddos_->allow_request(client_ip)) {
        auto resp = HttpResponse::make_error(429, "Too Many Requests");
        apply_security_headers(resp);
        if (ssl) {
            send_response(ssl, client_fd, resp);
            SSL_shutdown(ssl);
            SSL_free(ssl);
        } else {
            send_response_plain(client_fd, resp);
        }

        auto elapsed = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - start_time).count();
        Metrics::instance().record_request(429, elapsed);

        close(client_fd);
        ddos_->release_connection(client_ip);
        Metrics::instance().record_disconnection();
        Metrics::instance().record_worker_idle();
        return;
    }

    // Check for WebSocket upgrade request
    if (WsHandshake::is_upgrade_request(req)) {
        handle_websocket(ssl, client_fd, client_ip, req);
        return; // WebSocket handler manages its own cleanup
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
    auto resp = route_request(req, client_ip);
    apply_security_headers(resp);

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

    // Inject configurable security headers into the sendfile response.
    // resolve_for_sendfile() returns headers WITHOUT the final \r\n terminator
    // so we can append security headers here before closing the header block.
    const auto& sh = config_.security_headers;
    if (sh.enabled) {
        if (sh.csp_enabled) {
            info->headers += "Content-Security-Policy: " + sh.csp_value + "\r\n";
        }
        if (sh.hsts_enabled && config_.tls_enabled) {
            info->headers += "Strict-Transport-Security: " + sh.hsts_value + "\r\n";
        }
        if (sh.xcto_enabled) {
            info->headers += "X-Content-Type-Options: nosniff\r\n";
        }
        if (sh.xxss_enabled) {
            info->headers += "X-XSS-Protection: " + sh.xxss_value + "\r\n";
        }
        if (sh.xfo_enabled) {
            info->headers += "X-Frame-Options: " + sh.xfo_value + "\r\n";
        }
        if (sh.referrer_policy_enabled) {
            info->headers += "Referrer-Policy: " + sh.referrer_policy_value + "\r\n";
        }
    }
    info->headers += "\r\n"; // Terminate header block

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

    // Hard deadline for header reading (anti-Slowloris)
    auto deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(config_.header_read_timeout_ms);

    while (true) {
        // Check deadline
        if (std::chrono::steady_clock::now() > deadline) {
            return false; // Hard timeout exceeded
        }

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

    // Hard deadline for header reading (anti-Slowloris)
    auto deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(config_.header_read_timeout_ms);

    while (true) {
        // Check deadline
        auto now = std::chrono::steady_clock::now();
        if (now > deadline) {
            return false; // Hard timeout exceeded
        }

        // Use poll() with remaining timeout
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        struct pollfd pfd{};
        pfd.fd = fd;
        pfd.events = POLLIN;
        int poll_ret = poll(&pfd, 1, static_cast<int>(remaining.count()));
        if (poll_ret <= 0) return false; // Timeout or error

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

HttpResponse Worker::route_request(const HttpRequest& req, const std::string& client_ip) {
    // Prometheus metrics endpoint -- restricted to localhost if configured
    if (req.path == "/metrics") {
        if (config_.metrics_localhost_only &&
            client_ip != "127.0.0.1" && client_ip != "::1" && !client_ip.empty()) {
            return HttpResponse::make_error(403, "Metrics access denied");
        }
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

void Worker::handle_websocket(SSL* ssl, int client_fd, const std::string& client_ip,
                               const HttpRequest& req) {
    LOG_INFO("WebSocket upgrade from " + client_ip + " for " + req.uri);

    // Send 101 Switching Protocols
    auto ws_resp = WsHandshake::build_accept_response(req);
    if (ssl) {
        send_response(ssl, client_fd, ws_resp);
    } else {
        send_response_plain(client_fd, ws_resp);
    }

    // Create WebSocket connection handler
    WsConnection ws;

    ws.set_on_message([&](WsOpcode opcode, std::string_view data) {
        LOG_DEBUG("WebSocket message (" +
                  std::string(opcode == WsOpcode::TEXT ? "text" : "binary") +
                  "): " + std::to_string(data.size()) + " bytes");

        // Echo back by default (applications can override via custom routing)
        auto frame = WsConnection::build_frame(opcode, data);
        if (ssl) {
            int written = SSL_write(ssl, frame.data(), static_cast<int>(frame.size()));
            (void)written;
        } else {
            auto sent_result = send(client_fd, frame.data(), frame.size(), MSG_NOSIGNAL);
            (void)sent_result;
        }
    });

    ws.set_on_close([&](uint16_t code, std::string_view reason) {
        LOG_INFO("WebSocket close from " + client_ip +
                 " code=" + std::to_string(code) +
                 " reason=" + std::string(reason));
    });

    ws.set_on_ping([&]([[maybe_unused]] std::string_view data) {
        LOG_DEBUG("WebSocket ping from " + client_ip);
    });

    // Set longer timeout for WebSocket connections
    struct timeval tv{};
    tv.tv_sec = 300; // 5 minute idle timeout
    tv.tv_usec = 0;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    std::array<char, 8192> buf{};

    while (ws.is_alive()) {
        int n;
        if (ssl) {
            n = SSL_read(ssl, buf.data(), static_cast<int>(buf.size()));
            if (n <= 0) {
                int err = SSL_get_error(ssl, n);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
                break;
            }
        } else {
            auto recv_n = recv(client_fd, buf.data(), buf.size(), 0);
            if (recv_n <= 0) break;
            n = static_cast<int>(recv_n);
        }

        Metrics::instance().record_bytes_received(static_cast<size_t>(n));

        auto response_data = ws.process_input(
            std::span<const char>(buf.data(), static_cast<size_t>(n)));

        if (!response_data.empty()) {
            if (ssl) {
                size_t sent = 0;
                while (sent < response_data.size()) {
                    int w = SSL_write(ssl, response_data.data() + sent,
                                      static_cast<int>(response_data.size() - sent));
                    if (w <= 0) goto ws_done;
                    sent += static_cast<size_t>(w);
                }
            } else {
                size_t sent = 0;
                while (sent < response_data.size()) {
                    auto w = send(client_fd, response_data.data() + sent,
                                  response_data.size() - sent, MSG_NOSIGNAL);
                    if (w <= 0) goto ws_done;
                    sent += static_cast<size_t>(w);
                }
            }
            Metrics::instance().record_bytes_sent(response_data.size());
        }
    }

ws_done:
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    close(client_fd);
    ddos_->release_connection(client_ip);
    Metrics::instance().record_disconnection();
    Metrics::instance().record_worker_idle();
}

bool Worker::is_php_request(std::string_view path) const {
    if (path.size() >= 4) {
        auto ext = path.substr(path.size() - 4);
        return ext == ".php";
    }
    return false;
}

} // namespace js
