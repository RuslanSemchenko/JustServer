#pragma once

#include <cstdint>
#include <string>
#include <filesystem>

namespace js {

struct SecurityHeadersConfig {
    bool enabled = true;

    // Content-Security-Policy
    bool csp_enabled = true;
    std::string csp_value = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'";

    // Strict-Transport-Security (HSTS)
    bool hsts_enabled = true;
    std::string hsts_value = "max-age=31536000; includeSubDomains; preload";

    // X-Content-Type-Options
    bool xcto_enabled = true;
    // Always "nosniff"

    // X-XSS-Protection (legacy, for older browsers)
    bool xxss_enabled = true;
    std::string xxss_value = "1; mode=block";

    // X-Frame-Options
    bool xfo_enabled = true;
    std::string xfo_value = "DENY";

    // Referrer-Policy
    bool referrer_policy_enabled = true;
    std::string referrer_policy_value = "strict-origin-when-cross-origin";
};

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
    int header_read_timeout_ms = 5000;
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
    size_t waf_body_inspection_limit = 131072; // 128 KB max body inspection

    // Security headers
    SecurityHeadersConfig security_headers;

    // Logging
    std::string log_level = "info";

    static Config load_from_file(const std::string& path);
    static Config defaults();
};

} // namespace js
