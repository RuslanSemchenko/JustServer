#include "waf.hpp"
#include "unicode.hpp"
#include "logger.hpp"
#include <algorithm>

namespace js {

WAF::WAF() {
    // Blocked User-Agent strings (known attack tools)
    blocked_user_agents_ = {
        "sqlmap",
        "commix",
        "nikto",
        "nmap",
        "masscan",
        "dirbuster",
        "gobuster",
        "wfuzz",
        "hydra",
        "metasploit",
        "nessus",
        "openvas",
        "burpsuite",
        "zap",
        "havij",
        "acunetix",
    };

    // Blocked URI patterns (path traversal, injection, etc.)
    blocked_uri_patterns_ = {
        "../",
        "..\\",
        "%2e%2e",
        "%2e%2e%2f",
        "%252e%252e",
        "/etc/passwd",
        "/etc/shadow",
        "/proc/self",
        "cmd.exe",
        "powershell",
        "<script",
        "javascript:",
        "vbscript:",
        "onload=",
        "onerror=",
        "eval(",
        "exec(",
        "system(",
        "passthru(",
        "shell_exec(",
        "base64_decode(",
        "union+select",
        "union%20select",
        "select+from",
        "insert+into",
        "drop+table",
        "delete+from",
        "1=1",
        "1'='1",
        "or+1=1",
        "' or '",
        "'; drop",
    };
}

WAF::Verdict WAF::inspect(const HttpRequest& req) const {
    Verdict v;

    // Unicode normalization and multi-byte bypass detection
    // Decode percent-encoded URI and check for encoding attacks
    auto decoded_uri = Unicode::decode_percent_utf8(req.uri);

    if (Unicode::detect_multibyte_bypass(decoded_uri)) {
        v.blocked = true;
        v.reason = "Multi-byte encoding bypass detected";
        v.status_code = 403;
        LOG_WARN("WAF blocked: " + v.reason + " (URI: " + req.uri + ")");
        return v;
    }

    if (Unicode::has_overlong_encoding(decoded_uri)) {
        v.blocked = true;
        v.reason = "Overlong UTF-8 encoding detected (attack vector)";
        v.status_code = 403;
        LOG_WARN("WAF blocked: " + v.reason + " (URI: " + req.uri + ")");
        return v;
    }

    if (Unicode::detect_shiftjis_bypass(decoded_uri)) {
        v.blocked = true;
        v.reason = "Shift-JIS encoding bypass detected";
        v.status_code = 403;
        LOG_WARN("WAF blocked: " + v.reason + " (URI: " + req.uri + ")");
        return v;
    }

    // Normalize the URI for further checks
    auto normalized_uri = Unicode::normalize_utf8(decoded_uri);

    // Check User-Agent
    auto ua = req.get_header("User-Agent");
    if (check_user_agent(ua)) {
        v.blocked = true;
        v.reason = "Blocked User-Agent detected";
        v.status_code = 403;
        LOG_WARN("WAF blocked request: " + v.reason + " (UA: " + std::string(ua) + ")");
        return v;
    }

    // Check URI (both original and normalized)
    if (check_uri(req.uri) || check_uri(normalized_uri)) {
        v.blocked = true;
        v.reason = "Malicious URI pattern detected";
        v.status_code = 403;
        LOG_WARN("WAF blocked request: " + v.reason + " (URI: " + req.uri + ")");
        return v;
    }

    // Check headers for injection
    if (check_headers(req)) {
        v.blocked = true;
        v.reason = "Malicious header content detected";
        v.status_code = 403;
        LOG_WARN("WAF blocked request: " + v.reason);
        return v;
    }

    // Check body for injection patterns (including unicode bypass)
    if (!req.body.empty()) {
        if (check_body(req.body)) {
            v.blocked = true;
            v.reason = "Malicious body content detected";
            v.status_code = 403;
            LOG_WARN("WAF blocked request: " + v.reason);
            return v;
        }

        // Check body for multi-byte bypasses too
        if (Unicode::detect_multibyte_bypass(req.body)) {
            v.blocked = true;
            v.reason = "Multi-byte encoding bypass in request body";
            v.status_code = 403;
            LOG_WARN("WAF blocked: " + v.reason);
            return v;
        }
    }

    return v;
}

bool WAF::check_user_agent(std::string_view ua) const {
    if (ua.empty()) return false;

    std::string lower_ua(ua);
    std::transform(lower_ua.begin(), lower_ua.end(), lower_ua.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    for (const auto& blocked : blocked_user_agents_) {
        if (lower_ua.find(blocked) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool WAF::check_uri(std::string_view uri) const {
    std::string lower_uri(uri);
    std::transform(lower_uri.begin(), lower_uri.end(), lower_uri.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    for (const auto& pattern : blocked_uri_patterns_) {
        if (lower_uri.find(pattern) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool WAF::check_headers(const HttpRequest& req) const {
    // Check for oversized headers
    for (const auto& [name, value] : req.headers) {
        if (value.size() > 8192) return true;

        // Check header values for injection patterns
        std::string lower_val(value);
        std::transform(lower_val.begin(), lower_val.end(), lower_val.begin(),
                       [](unsigned char c) { return std::tolower(c); });

        // CRLF injection check
        if (lower_val.find("\r\n") != std::string::npos) return true;
        if (lower_val.find('\0') != std::string::npos) return true;

        // Check headers for multi-byte encoding attacks
        if (Unicode::detect_multibyte_bypass(value)) return true;
    }
    return false;
}

bool WAF::check_body(std::string_view body) const {
    // Basic XSS/injection checks on POST body
    std::string lower_body(body.substr(0, std::min(body.size(), size_t(65536))));
    std::transform(lower_body.begin(), lower_body.end(), lower_body.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    static const std::vector<std::string> body_patterns = {
        "<script",
        "javascript:",
        "eval(",
        "exec(",
        "system(",
    };

    for (const auto& pattern : body_patterns) {
        if (lower_body.find(pattern) != std::string::npos) {
            return true;
        }
    }
    return false;
}

} // namespace js
