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

static std::vector<std::string> split_list(std::string_view value) {
    std::vector<std::string> items;
    size_t pos = 0;
    while (pos <= value.size()) {
        auto comma = value.find(',', pos);
        auto item = trim(value.substr(pos, comma == std::string_view::npos
                                              ? std::string_view::npos
                                              : comma - pos));
        if (!item.empty()) items.push_back(std::move(item));
        if (comma == std::string_view::npos) break;
        pos = comma + 1;
    }
    return items;
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
        else if (key == "http3_enabled") config.http3_enabled = (value == "true" || value == "1");
        else if (key == "http3_port") config.http3_port = static_cast<uint16_t>(std::stoi(value));
        else if (key == "acme_enabled") config.acme_enabled = (value == "true" || value == "1");
        else if (key == "acme_email") config.acme_email = value;
        else if (key == "acme_domains") config.acme_domains = split_list(value);
        else if (key == "acme_storage") config.acme_storage_path = value;
        else if (key == "acme_use_staging") config.acme_use_staging = (value == "true" || value == "1");
        else if (key == "acme_directory_url") config.acme_directory_url = value;
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
        else if (key == "antibot_geoip_enabled") config.geoip_enabled = (value == "true" || value == "1");
        else if (key == "antibot_geoip_database") config.geoip_database_path = value;
        else if (key == "antibot_blocked_countries") config.geoip_blocked_countries = split_list(value);
        else if (key == "wasm_enabled") config.wasm_enabled = (value == "true" || value == "1");
        else if (key == "wasm_plugin_dir") config.wasm_plugin_dir = value;
        else if (key == "wasm_max_memory_mb")
            config.wasm_max_memory_bytes = static_cast<size_t>(std::stoull(value)) * 1024 * 1024;
        else if (key == "wasm_timeout_ms") config.wasm_execution_timeout_ms = std::stoi(value);
        else if (key == "log_level") config.log_level = value;
        // Rate limiting
        else if (key == "rate_limit_rps") config.rate_limit_rps = std::stod(value);
        else if (key == "rate_limit_burst") config.rate_limit_burst = std::stod(value);
        // Global limits
        else if (key == "max_total_connections") config.max_total_connections = std::stoi(value);
        else if (key == "max_memory_bytes") config.max_memory_bytes = static_cast<size_t>(std::stoll(value));
        else if (key == "max_open_files") config.max_open_files = std::stoi(value);
        // Privilege dropping
        else if (key == "drop_uid") config.drop_uid = std::stoi(value);
        else if (key == "drop_gid") config.drop_gid = std::stoi(value);
        // Metrics access
        else if (key == "metrics_localhost_only") config.metrics_localhost_only = (value == "true" || value == "1");
        // Server header
        else if (key == "server_header") config.server_header = value;
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
