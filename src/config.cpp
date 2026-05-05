#include "config.hpp"
#include "logger.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>

namespace js {

static std::string trim(std::string_view sv) {
    auto start = sv.find_first_not_of(" \t\r\n");
    if (start == std::string_view::npos) return {};
    auto end = sv.find_last_not_of(" \t\r\n");
    return std::string(sv.substr(start, end - start + 1));
}

Config Config::defaults() {
    return Config{};
}

Config Config::load_from_file(const std::string& path) {
    Config config = defaults();

    std::ifstream file(path);
    if (!file.is_open()) {
        LOG_WARN("Config file not found, using defaults: " + path);
        return config;
    }

    std::string line;
    while (std::getline(file, line)) {
        // Skip comments and empty lines
        auto trimmed = trim(line);
        if (trimmed.empty() || trimmed[0] == '#') continue;

        auto eq_pos = trimmed.find('=');
        if (eq_pos == std::string::npos) continue;

        auto key = trim(std::string_view(trimmed).substr(0, eq_pos));
        auto value = trim(std::string_view(trimmed).substr(eq_pos + 1));

        if (key == "bind_address") config.bind_address = value;
        else if (key == "port") config.port = static_cast<uint16_t>(std::stoi(value));
        else if (key == "backlog") config.backlog = std::stoi(value);
        else if (key == "worker_threads") config.worker_threads = std::stoi(value);
        else if (key == "tls_cert") config.tls_cert_path = value;
        else if (key == "tls_key") config.tls_key_path = value;
        else if (key == "tls_enabled") config.tls_enabled = (value == "true" || value == "1");
        else if (key == "max_connections_per_ip") config.max_connections_per_ip = std::stoi(value);
        else if (key == "header_read_timeout_ms") config.header_read_timeout_ms = std::stoi(value);
        else if (key == "request_body_timeout_ms") config.request_body_timeout_ms = std::stoi(value);
        else if (key == "max_request_size") config.max_request_size = std::stoi(value);
        else if (key == "document_root") config.document_root = value;
        else if (key == "index_file") config.index_file = value;
        else if (key == "chroot_enabled") config.chroot_enabled = (value == "true" || value == "1");
        else if (key == "fastcgi_socket") config.fastcgi_socket = value;
        else if (key == "fastcgi_enabled") config.fastcgi_enabled = (value == "true" || value == "1");
        else if (key == "waf_enabled") config.waf_enabled = (value == "true" || value == "1");
        else if (key == "waf_body_inspection_limit") config.waf_body_inspection_limit = static_cast<size_t>(std::stoi(value));
        else if (key == "log_level") config.log_level = value;
        // Security headers
        else if (key == "security_headers_enabled") config.security_headers.enabled = (value == "true" || value == "1");
        else if (key == "csp_enabled") config.security_headers.csp_enabled = (value == "true" || value == "1");
        else if (key == "csp_value") config.security_headers.csp_value = value;
        else if (key == "hsts_enabled") config.security_headers.hsts_enabled = (value == "true" || value == "1");
        else if (key == "hsts_value") config.security_headers.hsts_value = value;
        else if (key == "xcto_enabled") config.security_headers.xcto_enabled = (value == "true" || value == "1");
        else if (key == "xxss_enabled") config.security_headers.xxss_enabled = (value == "true" || value == "1");
        else if (key == "xfo_enabled") config.security_headers.xfo_enabled = (value == "true" || value == "1");
        else if (key == "xfo_value") config.security_headers.xfo_value = value;
        else if (key == "referrer_policy_enabled") config.security_headers.referrer_policy_enabled = (value == "true" || value == "1");
        else if (key == "referrer_policy_value") config.security_headers.referrer_policy_value = value;
    }

    return config;
}

} // namespace js
