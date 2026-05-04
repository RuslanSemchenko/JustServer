#pragma once

#include "http_parser.hpp"
#include <string>
#include <string_view>
#include <vector>
#include <optional>

namespace js {

class WAF {
public:
    WAF();

    struct Verdict {
        bool blocked = false;
        std::string reason;
        int status_code = 403;
    };

    // Inspect a parsed HTTP request, return block verdict
    Verdict inspect(const HttpRequest& req) const;

private:
    bool check_user_agent(std::string_view ua) const;
    bool check_uri(std::string_view uri) const;
    bool check_headers(const HttpRequest& req) const;
    bool check_body(std::string_view body) const;

    std::vector<std::string> blocked_user_agents_;
    std::vector<std::string> blocked_uri_patterns_;
};

} // namespace js
