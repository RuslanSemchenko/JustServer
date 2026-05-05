#pragma once

#include "http_parser.hpp"
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <memory>

// Forward-declare RE2 to avoid header pollution
namespace re2 {
class RE2;
}

namespace js {

// Payload normalization utilities for WAF bypass prevention
class PayloadNormalizer {
public:
    // Recursive URL decoding (handles double/triple encoding like %253c -> %3c -> <)
    static std::string recursive_url_decode(std::string_view input, int max_iterations = 10);

    // Strip null bytes from payload
    static std::string strip_null_bytes(std::string_view input);

    // Decode HTML entities (&lt; -> <, &#60; -> <, &#x3c; -> <)
    static std::string decode_html_entities(std::string_view input);

    // Strip HTML comments that could break up tags
    static std::string strip_html_comments(std::string_view input);

    // Strip excess whitespace inside tags
    static std::string collapse_whitespace(std::string_view input);

    // Full normalization pipeline
    static std::string normalize(std::string_view input);
};

class WAF {
public:
    WAF();
    ~WAF();

    // Non-copyable (RE2 pointers)
    WAF(const WAF&) = delete;
    WAF& operator=(const WAF&) = delete;

    struct Verdict {
        bool blocked = false;
        std::string reason;
        int status_code = 403;
        int score = 0;                  // Anomaly score
        std::vector<std::string> tags;  // Matched rule tags
    };

    // Inspect a parsed HTTP request, return block verdict
    // body_inspection_limit: max bytes of body to scan (0 = default 128KB)
    Verdict inspect(const HttpRequest& req, size_t body_inspection_limit = 0) const;

private:
    // Scoring thresholds
    static constexpr int BLOCK_THRESHOLD = 5;

    // Individual check functions that return scores
    int check_user_agent(std::string_view ua, Verdict& v) const;
    int check_xss(std::string_view data, Verdict& v) const;
    int check_sqli(std::string_view data, Verdict& v) const;
    int check_rce(std::string_view data, Verdict& v) const;
    int check_path_traversal(std::string_view data, Verdict& v) const;
    int check_protocol_attack(std::string_view data, Verdict& v) const;
    int check_headers(const HttpRequest& req, Verdict& v) const;

    // Scan a normalized payload through all attack patterns
    int scan_payload(std::string_view data, Verdict& v) const;

    // RE2 compiled patterns (owned pointers)
    std::unique_ptr<re2::RE2> re_xss_event_handlers_;    // on* event handlers
    std::unique_ptr<re2::RE2> re_xss_script_uri_;        // javascript:, data:, vbscript:
    std::unique_ptr<re2::RE2> re_xss_tags_;              // <script>, <svg>, <iframe>, etc.
    std::unique_ptr<re2::RE2> re_sqli_union_;             // UNION SELECT patterns
    std::unique_ptr<re2::RE2> re_sqli_boolean_;           // OR 1=1, AND 1=1 patterns
    std::unique_ptr<re2::RE2> re_sqli_stacked_;           // Stacked queries, comments
    std::unique_ptr<re2::RE2> re_sqli_sysinfo_;           // information_schema, sys tables
    std::unique_ptr<re2::RE2> re_rce_functions_;          // system(), exec(), etc.
    std::unique_ptr<re2::RE2> re_rce_commands_;           // /etc/passwd, cmd.exe, etc.
    std::unique_ptr<re2::RE2> re_path_traversal_;         // ../, ..\ patterns
    std::unique_ptr<re2::RE2> re_protocol_attack_;        // CRLF injection, null bytes

    // Blocked user agents (compiled RE2)
    std::unique_ptr<re2::RE2> re_blocked_ua_;

    static constexpr size_t DEFAULT_BODY_INSPECTION_LIMIT = 131072; // 128 KB
};

} // namespace js
