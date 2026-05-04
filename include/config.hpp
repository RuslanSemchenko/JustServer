#pragma once

#include <cstdint>
#include <string>
#include <filesystem>

namespace js {

struct Config {
    // Network
    std::string bind_address = "0.0.0.0";
    uint16_t port = 8443;
    int backlog = 512;
    int worker_threads = 4;

    // TLS
    std::string tls_cert_path = "/etc/justserver/cert.pem";
    std::string tls_key_path = "/etc/justserver/key.pem";
    bool tls_enabled = true;

    // DDoS protection
    int max_connections_per_ip = 50;
    int header_read_timeout_ms = 3000;
    int request_body_timeout_ms = 10000;
    int max_request_size = 8 * 1024 * 1024; // 8 MB

    // File serving
    std::filesystem::path document_root = "/var/www/html";
    std::string index_file = "index.html";
    bool chroot_enabled = false;

    // FastCGI
    std::string fastcgi_socket = "/run/php/php-fpm.sock";
    bool fastcgi_enabled = true;

    // WAF
    bool waf_enabled = true;

    // Logging
    std::string log_level = "info";

    static Config load_from_file(const std::string& path);
    static Config defaults();
};

} // namespace js
