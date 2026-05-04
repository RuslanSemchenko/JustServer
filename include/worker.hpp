#pragma once

#include "config.hpp"
#include "tls_context.hpp"
#include "http_parser.hpp"
#include "waf.hpp"
#include "ddos_guard.hpp"
#include "file_handler.hpp"
#include "fastcgi_client.hpp"
#include "metrics.hpp"

#include <functional>
#include <string>
#include <openssl/ssl.h>

namespace js {

class Worker {
public:
    Worker(const Config& config, TLSContext* tls, WAF* waf,
           DDoSGuard* ddos, FileHandler* file_handler, FastCGIClient* fcgi);

    // Handle an accepted connection
    void handle_connection(int client_fd, const std::string& client_ip);

private:
    // Read full request with timeout
    bool read_request(SSL* ssl, int fd, HttpParser& parser);
    bool read_request_plain(int fd, HttpParser& parser);

    // Send response
    void send_response(SSL* ssl, int fd, const HttpResponse& resp);
    void send_response_plain(int fd, const HttpResponse& resp);

    // Zero-copy sendfile for plain connections
    bool try_sendfile(int client_fd, const HttpRequest& req);

    // Route request to appropriate handler
    HttpResponse route_request(const HttpRequest& req);

    // Check if request is for a PHP file
    bool is_php_request(std::string_view path) const;

    const Config& config_;
    TLSContext* tls_;
    WAF* waf_;
    DDoSGuard* ddos_;
    FileHandler* file_handler_;
    FastCGIClient* fcgi_;
};

} // namespace js
