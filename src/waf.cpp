#include "waf.hpp"
#include "unicode.hpp"
#include "logger.hpp"
#include <algorithm>
#include <re2/re2.h>
#include <cstring>

namespace js {

// ===== PayloadNormalizer =====

std::string PayloadNormalizer::recursive_url_decode(std::string_view input, int max_iterations) {
    std::string current(input);
    for (int i = 0; i < max_iterations; ++i) {
        std::string decoded;
        decoded.reserve(current.size());
        bool changed = false;

        for (size_t j = 0; j < current.size(); ++j) {
            if (current[j] == '%' && j + 2 < current.size()) {
                char h1 = current[j + 1];
                char h2 = current[j + 2];
                auto hex_val = [](char c) -> int {
                    if (c >= '0' && c <= '9') return c - '0';
                    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
                    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
                    return -1;
                };
                int v1 = hex_val(h1);
                int v2 = hex_val(h2);
                if (v1 >= 0 && v2 >= 0) {
                    decoded += static_cast<char>((v1 << 4) | v2);
                    j += 2;
                    changed = true;
                    continue;
                }
            }
            decoded += current[j];
        }

        if (!changed) break;
        current = std::move(decoded);
    }
    return current;
}

std::string PayloadNormalizer::strip_null_bytes(std::string_view input) {
    std::string result;
    result.reserve(input.size());
    for (char c : input) {
        if (c != '\0') {
            result += c;
        }
    }
    return result;
}

std::string PayloadNormalizer::decode_html_entities(std::string_view input) {
    std::string result;
    result.reserve(input.size());

    for (size_t i = 0; i < input.size(); ++i) {
        if (input[i] == '&' && i + 1 < input.size()) {
            // Named entities
            auto remaining = input.substr(i);
            if (remaining.starts_with("&lt;")) { result += '<'; i += 3; continue; }
            if (remaining.starts_with("&gt;")) { result += '>'; i += 3; continue; }
            if (remaining.starts_with("&amp;")) { result += '&'; i += 4; continue; }
            if (remaining.starts_with("&quot;")) { result += '"'; i += 5; continue; }
            if (remaining.starts_with("&apos;")) { result += '\''; i += 5; continue; }
            if (remaining.starts_with("&#x") || remaining.starts_with("&#X")) {
                // Hex numeric entity: &#xHH;
                size_t end = remaining.find(';', 3);
                if (end != std::string_view::npos && end <= 10) {
                    auto hex_str = remaining.substr(3, end - 3);
                    unsigned long val = 0;
                    bool valid = true;
                    for (char c : hex_str) {
                        val <<= 4;
                        if (c >= '0' && c <= '9') val |= static_cast<unsigned long>(c - '0');
                        else if (c >= 'a' && c <= 'f') val |= static_cast<unsigned long>(10 + c - 'a');
                        else if (c >= 'A' && c <= 'F') val |= static_cast<unsigned long>(10 + c - 'A');
                        else { valid = false; break; }
                    }
                    if (valid && val < 128) {
                        result += static_cast<char>(val);
                        i += end;
                        continue;
                    }
                }
            }
            if (remaining.starts_with("&#")) {
                // Decimal numeric entity: &#DD;
                size_t end = remaining.find(';', 2);
                if (end != std::string_view::npos && end <= 10) {
                    auto num_str = remaining.substr(2, end - 2);
                    unsigned long val = 0;
                    bool valid = true;
                    for (char c : num_str) {
                        if (c >= '0' && c <= '9') val = val * 10 + static_cast<unsigned long>(c - '0');
                        else { valid = false; break; }
                    }
                    if (valid && val < 128) {
                        result += static_cast<char>(val);
                        i += end;
                        continue;
                    }
                }
            }
        }
        result += input[i];
    }
    return result;
}

std::string PayloadNormalizer::strip_html_comments(std::string_view input) {
    std::string result;
    result.reserve(input.size());

    size_t i = 0;
    while (i < input.size()) {
        if (i + 3 < input.size() && input[i] == '<' && input[i + 1] == '!' &&
            input[i + 2] == '-' && input[i + 3] == '-') {
            // Skip until -->
            auto end = input.find("-->", i + 4);
            if (end != std::string_view::npos) {
                i = end + 3;
                continue;
            }
        }
        result += input[i];
        ++i;
    }
    return result;
}

std::string PayloadNormalizer::collapse_whitespace(std::string_view input) {
    std::string result;
    result.reserve(input.size());
    bool in_tag = false;
    bool last_was_space = false;

    for (char c : input) {
        if (c == '<') in_tag = true;
        if (c == '>') in_tag = false;

        if (in_tag && (c == ' ' || c == '\t' || c == '\n' || c == '\r')) {
            if (!last_was_space) {
                result += ' ';
                last_was_space = true;
            }
            continue;
        }
        last_was_space = false;
        result += c;
    }
    return result;
}

std::string PayloadNormalizer::normalize(std::string_view input) {
    // Full normalization pipeline for WAF bypass prevention:
    // 1. Recursive URL decoding (handles %253c double encoding)
    auto step1 = recursive_url_decode(input);
    // 2. Strip null bytes
    auto step2 = strip_null_bytes(step1);
    // 3. Decode HTML entities
    auto step3 = decode_html_entities(step2);
    // 4. Strip HTML comments (e.g., <scr<!-- -->ipt>)
    auto step4 = strip_html_comments(step3);
    // 5. Collapse whitespace in tags
    auto step5 = collapse_whitespace(step4);
    // 6. Lowercase for pattern matching
    std::transform(step5.begin(), step5.end(), step5.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return step5;
}

// ===== WAF =====

WAF::WAF() {
    re2::RE2::Options opts;
    opts.set_case_sensitive(false);
    opts.set_log_errors(false);
    opts.set_max_mem(1 << 20); // 1 MB per pattern

    // XSS: HTML event handlers (covers all on* attributes)
    // Matches: onerror="...", onload = '...', onmouseover=alert(1), etc.
    re_xss_event_handlers_ = std::make_unique<re2::RE2>(
        R"((?i)\bon[a-z]{2,20}\s*=\s*["']?[^"'>]*)", opts);

    // XSS: Dangerous URI schemes
    re_xss_script_uri_ = std::make_unique<re2::RE2>(
        R"((?i)(?:javascript|vbscript|data\s*:\s*text/html)\s*:)", opts);

    // XSS: Dangerous HTML tags (script, svg, iframe, embed, object, etc.)
    re_xss_tags_ = std::make_unique<re2::RE2>(
        R"((?i)<\s*/?(?:script|svg|iframe|embed|object|applet|form|input|textarea|button|select|link|style|base|meta|foreignobject|animate|set|use|image|math)\b)",
        opts);

    // SQLi: UNION-based injection
    re_sqli_union_ = std::make_unique<re2::RE2>(
        R"((?i)(?:union\s+(?:all\s+)?select|select\s+.*\s+from|insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s+(?:table|database|column)))",
        opts);

    // SQLi: Boolean-based / authentication bypass
    re_sqli_boolean_ = std::make_unique<re2::RE2>(
        R"((?i)(?:(?:^|\s|=)(?:or|and)\s+[\d'"].*?=.*?[\d'"]|'\s*(?:or|and)\s*'|(?:--|#|/\*)\s*$|;\s*(?:drop|alter|create|truncate)\b))",
        opts);

    // SQLi: Stacked queries and comment-based attacks
    re_sqli_stacked_ = std::make_unique<re2::RE2>(
        R"((?i)(?:;\s*(?:select|insert|update|delete|drop|alter|create|exec|execute)\b|/\*!?\d*\s*\w))",
        opts);

    // SQLi: System table access
    re_sqli_sysinfo_ = std::make_unique<re2::RE2>(
        R"((?i)(?:information_schema|mysql\.user|sys\.objects|sysobjects|pg_catalog|sqlite_master|master\.\.sysdatabases))",
        opts);

    // RCE: Dangerous function calls
    re_rce_functions_ = std::make_unique<re2::RE2>(
        R"((?i)(?:(?:system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec|eval|assert|preg_replace|create_function|call_user_func|base64_decode|gzinflate|str_rot13)\s*\())",
        opts);

    // RCE: OS command injection patterns and sensitive file access
    re_rce_commands_ = std::make_unique<re2::RE2>(
        R"((?i)(?:/etc/(?:passwd|shadow|hosts)|/proc/self/|cmd\.exe|powershell|/bin/(?:bash|sh|zsh|csh)|`[^`]+`|\$\([^)]+\)|\bwget\s|curl\s.*-[oO]|nc\s+-[el]))",
        opts);

    // Path traversal
    re_path_traversal_ = std::make_unique<re2::RE2>(
        R"((?:\.\.[\\/]|\.\.%2[fF]|%2[eE]%2[eE]|%252[eE]%252[eE]))", opts);

    // Protocol attacks (CRLF injection) - matches both decoded CRLF and literal \r\n sequences
    re_protocol_attack_ = std::make_unique<re2::RE2>(
        R"(\r\n|\n|%0[dD]%0[aA]|%0[aA])", opts);

    // Blocked user agents (attack tools)
    re_blocked_ua_ = std::make_unique<re2::RE2>(
        R"((?i)(?:sqlmap|commix|nikto|nmap|masscan|dirbuster|gobuster|wfuzz|hydra|metasploit|nessus|openvas|burpsuite|zap|havij|acunetix|w3af|skipfish|arachni))",
        opts);
}

WAF::~WAF() = default;

WAF::Verdict WAF::inspect(const HttpRequest& req, size_t body_inspection_limit) const {
    Verdict v;
    if (body_inspection_limit == 0) {
        body_inspection_limit = DEFAULT_BODY_INSPECTION_LIMIT;
    }

    // --- Unicode-level checks (pre-normalization) ---
    auto decoded_uri = Unicode::decode_percent_utf8(req.uri);

    if (Unicode::detect_multibyte_bypass(decoded_uri)) {
        v.blocked = true;
        v.reason = "Multi-byte encoding bypass detected";
        v.status_code = 403;
        v.score = BLOCK_THRESHOLD;
        v.tags.push_back("unicode-bypass");
        LOG_WARN("WAF blocked: " + v.reason + " (URI: " + req.uri + ")");
        return v;
    }

    if (Unicode::has_overlong_encoding(decoded_uri)) {
        v.blocked = true;
        v.reason = "Overlong UTF-8 encoding detected (attack vector)";
        v.status_code = 403;
        v.score = BLOCK_THRESHOLD;
        v.tags.push_back("overlong-utf8");
        LOG_WARN("WAF blocked: " + v.reason + " (URI: " + req.uri + ")");
        return v;
    }

    if (Unicode::detect_shiftjis_bypass(decoded_uri)) {
        v.blocked = true;
        v.reason = "Shift-JIS encoding bypass detected";
        v.status_code = 403;
        v.score = BLOCK_THRESHOLD;
        v.tags.push_back("shiftjis-bypass");
        LOG_WARN("WAF blocked: " + v.reason + " (URI: " + req.uri + ")");
        return v;
    }

    // --- Check User-Agent ---
    auto ua = req.get_header("User-Agent");
    v.score += check_user_agent(ua, v);
    if (v.score >= BLOCK_THRESHOLD) {
        v.blocked = true;
        v.status_code = 403;
        LOG_WARN("WAF blocked request: " + v.reason + " (UA: " + std::string(ua) + ")");
        return v;
    }

    // --- Check headers ---
    v.score += check_headers(req, v);
    if (v.score >= BLOCK_THRESHOLD) {
        v.blocked = true;
        v.status_code = 403;
        LOG_WARN("WAF blocked request: " + v.reason);
        return v;
    }

    // --- Normalize and scan path and query string separately ---
    // Note: req.uri contains the full URI including the query string (e.g.
    // "/search?q=<script>"), so scanning req.uri AND req.query_string would
    // double-count any attack patterns in the query string. Instead we scan
    // req.path and req.query_string independently.
    auto normalized_path = PayloadNormalizer::normalize(req.path);
    v.score += scan_payload(normalized_path, v);
    if (v.score >= BLOCK_THRESHOLD) {
        v.blocked = true;
        v.status_code = 403;
        LOG_WARN("WAF blocked request: " + v.reason + " (path: " + req.path + ")");
        return v;
    }

    if (!req.query_string.empty()) {
        auto normalized_qs = PayloadNormalizer::normalize(req.query_string);
        v.score += scan_payload(normalized_qs, v);
        if (v.score >= BLOCK_THRESHOLD) {
            v.blocked = true;
            v.status_code = 403;
            LOG_WARN("WAF blocked request: " + v.reason + " (QS: " + req.query_string + ")");
            return v;
        }
    }

    // --- POST body deep inspection ---
    if (!req.body.empty()) {
        // Limit inspection size to prevent worker stalls on large uploads
        auto body_to_scan = req.body.substr(0, std::min(req.body.size(), body_inspection_limit));

        // Check for multi-byte bypasses in body
        if (Unicode::detect_multibyte_bypass(body_to_scan)) {
            v.blocked = true;
            v.reason = "Multi-byte encoding bypass in request body";
            v.status_code = 403;
            v.score = BLOCK_THRESHOLD;
            v.tags.push_back("body-unicode-bypass");
            LOG_WARN("WAF blocked: " + v.reason);
            return v;
        }

        // Normalize and scan body
        auto normalized_body = PayloadNormalizer::normalize(body_to_scan);
        v.score += scan_payload(normalized_body, v);
        if (v.score >= BLOCK_THRESHOLD) {
            v.blocked = true;
            v.status_code = 403;
            LOG_WARN("WAF blocked request: " + v.reason + " (body inspection)");
            return v;
        }

        // Content-Type aware scanning: check JSON values, form field values
        auto ct = req.get_header("Content-Type");
        std::string lower_ct(ct);
        std::transform(lower_ct.begin(), lower_ct.end(), lower_ct.begin(),
                       [](unsigned char c) { return std::tolower(c); });

        // For JSON/form data, the normalized body scan above already catches
        // dangerous patterns in values. This is sufficient because our
        // normalization pipeline handles URL encoding, HTML entities, etc.
    }

    return v;
}

int WAF::check_user_agent(std::string_view ua, Verdict& v) const {
    if (ua.empty()) return 0;

    if (re_blocked_ua_ && re2::RE2::PartialMatch(
            re2::StringPiece(ua.data(), ua.size()), *re_blocked_ua_)) {
        v.reason = "Blocked User-Agent detected";
        v.tags.push_back("blocked-ua");
        return BLOCK_THRESHOLD; // Instant block for known attack tools
    }
    return 0;
}

int WAF::scan_payload(std::string_view data, Verdict& v) const {
    int score = 0;
    score += check_xss(data, v);
    score += check_sqli(data, v);
    score += check_rce(data, v);
    score += check_path_traversal(data, v);
    score += check_protocol_attack(data, v);
    return score;
}

int WAF::check_xss(std::string_view data, Verdict& v) const {
    int score = 0;
    auto sp = re2::StringPiece(data.data(), data.size());

    // Event handlers: on*= (high confidence XSS)
    if (re_xss_event_handlers_ && re2::RE2::PartialMatch(sp, *re_xss_event_handlers_)) {
        score += 5;
        v.reason = "XSS: HTML event handler detected";
        v.tags.push_back("xss-event-handler");
    }

    // Script URIs: javascript:, data:text/html, vbscript:
    if (re_xss_script_uri_ && re2::RE2::PartialMatch(sp, *re_xss_script_uri_)) {
        score += 5;
        v.reason = "XSS: Dangerous URI scheme detected";
        v.tags.push_back("xss-script-uri");
    }

    // Dangerous HTML tags (script, svg, iframe, etc.)
    if (re_xss_tags_ && re2::RE2::PartialMatch(sp, *re_xss_tags_)) {
        score += 5;
        if (v.reason.empty()) v.reason = "XSS: Dangerous HTML tag detected";
        v.tags.push_back("xss-dangerous-tag");
    }

    return score;
}

int WAF::check_sqli(std::string_view data, Verdict& v) const {
    int score = 0;
    auto sp = re2::StringPiece(data.data(), data.size());

    if (re_sqli_union_ && re2::RE2::PartialMatch(sp, *re_sqli_union_)) {
        score += 5;
        v.reason = "SQLi: UNION/DDL injection detected";
        v.tags.push_back("sqli-union");
    }

    if (re_sqli_boolean_ && re2::RE2::PartialMatch(sp, *re_sqli_boolean_)) {
        score += 3;
        if (v.reason.empty()) v.reason = "SQLi: Boolean injection detected";
        v.tags.push_back("sqli-boolean");
    }

    if (re_sqli_stacked_ && re2::RE2::PartialMatch(sp, *re_sqli_stacked_)) {
        score += 4;
        if (v.reason.empty()) v.reason = "SQLi: Stacked query detected";
        v.tags.push_back("sqli-stacked");
    }

    if (re_sqli_sysinfo_ && re2::RE2::PartialMatch(sp, *re_sqli_sysinfo_)) {
        score += 5;
        if (v.reason.empty()) v.reason = "SQLi: System table access detected";
        v.tags.push_back("sqli-sysinfo");
    }

    return score;
}

int WAF::check_rce(std::string_view data, Verdict& v) const {
    int score = 0;
    auto sp = re2::StringPiece(data.data(), data.size());

    if (re_rce_functions_ && re2::RE2::PartialMatch(sp, *re_rce_functions_)) {
        score += 5;
        v.reason = "RCE: Dangerous function call detected";
        v.tags.push_back("rce-function");
    }

    if (re_rce_commands_ && re2::RE2::PartialMatch(sp, *re_rce_commands_)) {
        score += 5;
        if (v.reason.empty()) v.reason = "RCE: OS command/file access detected";
        v.tags.push_back("rce-command");
    }

    return score;
}

int WAF::check_path_traversal(std::string_view data, Verdict& v) const {
    auto sp = re2::StringPiece(data.data(), data.size());
    if (re_path_traversal_ && re2::RE2::PartialMatch(sp, *re_path_traversal_)) {
        v.reason = "Path traversal detected";
        v.tags.push_back("path-traversal");
        return 5;
    }
    return 0;
}

int WAF::check_protocol_attack(std::string_view data, Verdict& v) const {
    auto sp = re2::StringPiece(data.data(), data.size());
    if (re_protocol_attack_ && re2::RE2::PartialMatch(sp, *re_protocol_attack_)) {
        v.reason = "Protocol attack (CRLF injection) detected";
        v.tags.push_back("crlf-injection");
        return 5;
    }
    return 0;
}

int WAF::check_headers(const HttpRequest& req, Verdict& v) const {
    int score = 0;
    for (const auto& [name, value] : req.headers) {
        if (value.size() > 8192) {
            score += 3;
            v.reason = "Oversized header value";
            v.tags.push_back("oversized-header");
        }

        // CRLF injection in headers
        if (value.find("\r\n") != std::string::npos) {
            score += 5;
            v.reason = "CRLF injection in header";
            v.tags.push_back("crlf-header");
        }
        if (value.find('\0') != std::string::npos) {
            score += 5;
            v.reason = "Null byte in header";
            v.tags.push_back("null-header");
        }

        // Multi-byte encoding attacks in headers
        if (Unicode::detect_multibyte_bypass(value)) {
            score += 5;
            v.reason = "Multi-byte encoding bypass in header";
            v.tags.push_back("header-unicode-bypass");
        }

        if (score >= BLOCK_THRESHOLD) break;
    }
    return score;
}

} // namespace js
