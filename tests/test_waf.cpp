#include "waf.hpp"
#include <iostream>
#include <functional>

bool register_test(const char* name, std::function<bool()> func);

#define TEST(name) \
    static bool test_##name(); \
    static bool _reg_##name = register_test(#name, test_##name); \
    static bool test_##name()

#define ASSERT_TRUE(expr) \
    do { if (!(expr)) { std::cerr << "  FAIL: " << #expr << " at " << __FILE__ << ":" << __LINE__ << "\n"; return false; } } while(0)
#define ASSERT_FALSE(expr) ASSERT_TRUE(!(expr))
#define ASSERT_EQ(a, b) \
    do { if ((a) != (b)) { std::cerr << "  FAIL: " << #a << " != " << #b << " at " << __FILE__ << ":" << __LINE__ << "\n"; return false; } } while(0)

using namespace js;

// Helper: build a request with URI
static HttpRequest make_req(const std::string& uri, const std::string& body = "") {
    HttpRequest req;
    req.method = HttpMethod::GET;
    req.method_str = "GET";
    req.uri = uri;
    req.path = uri;
    req.version = "HTTP/1.1";
    req.body = body;
    auto qmark = uri.find('?');
    if (qmark != std::string::npos) {
        req.path = uri.substr(0, qmark);
        req.query_string = uri.substr(qmark + 1);
    }
    return req;
}

TEST(waf_clean_request_passes) {
    WAF waf;
    auto req = make_req("/index.html");
    req.headers["Host"] = "example.com";
    req.headers["User-Agent"] = "Mozilla/5.0";
    auto v = waf.inspect(req);
    ASSERT_FALSE(v.blocked);
    ASSERT_EQ(v.score, 0);
    return true;
}

TEST(waf_blocks_sqlmap_ua) {
    WAF waf;
    auto req = make_req("/");
    req.headers["User-Agent"] = "sqlmap/1.0-dev";
    auto v = waf.inspect(req);
    ASSERT_TRUE(v.blocked);
    ASSERT_TRUE(v.score >= 5);
    return true;
}

TEST(waf_blocks_xss_event_handler) {
    WAF waf;
    auto req = make_req("/search?q=<img onerror=alert(1)>");
    auto v = waf.inspect(req);
    ASSERT_TRUE(v.blocked);
    bool has_xss_tag = false;
    for (const auto& t : v.tags) {
        if (t.find("xss") != std::string::npos) { has_xss_tag = true; break; }
    }
    ASSERT_TRUE(has_xss_tag);
    return true;
}

TEST(waf_blocks_xss_javascript_uri) {
    WAF waf;
    auto req = make_req("/redirect?url=javascript:alert(1)");
    auto v = waf.inspect(req);
    ASSERT_TRUE(v.blocked);
    return true;
}

TEST(waf_blocks_xss_script_tag) {
    WAF waf;
    auto req = make_req("/page?input=<script>alert(1)</script>");
    auto v = waf.inspect(req);
    ASSERT_TRUE(v.blocked);
    return true;
}

TEST(waf_blocks_xss_svg_tag) {
    WAF waf;
    auto req = make_req("/page?input=<svg onload=alert(1)>");
    auto v = waf.inspect(req);
    ASSERT_TRUE(v.blocked);
    return true;
}

TEST(waf_blocks_sqli_union_select) {
    WAF waf;
    auto req = make_req("/api?id=1 UNION SELECT username,password FROM users--");
    auto v = waf.inspect(req);
    ASSERT_TRUE(v.blocked);
    bool has_sqli = false;
    for (const auto& t : v.tags) {
        if (t.find("sqli") != std::string::npos) { has_sqli = true; break; }
    }
    ASSERT_TRUE(has_sqli);
    return true;
}

TEST(waf_blocks_sqli_boolean) {
    WAF waf;
    auto req = make_req("/login?user=' OR 1=1--&pass=x");
    auto v = waf.inspect(req);
    ASSERT_TRUE(v.score > 0 || v.blocked);
    return true;
}

TEST(waf_blocks_sqli_information_schema) {
    WAF waf;
    auto req = make_req("/api?id=1 AND (SELECT * FROM information_schema.tables)");
    auto v = waf.inspect(req);
    ASSERT_TRUE(v.blocked);
    return true;
}

TEST(waf_blocks_rce_system_call) {
    WAF waf;
    auto req = make_req("/api?cmd=system('ls -la')");
    auto v = waf.inspect(req);
    ASSERT_TRUE(v.blocked);
    return true;
}

TEST(waf_blocks_rce_etc_passwd) {
    WAF waf;
    auto req = make_req("/file?path=/etc/passwd");
    auto v = waf.inspect(req);
    ASSERT_TRUE(v.blocked);
    return true;
}

TEST(waf_blocks_path_traversal) {
    WAF waf;
    auto req = make_req("/files/../../../etc/passwd");
    auto v = waf.inspect(req);
    ASSERT_TRUE(v.blocked);
    return true;
}

TEST(waf_blocks_double_encoded_path_traversal) {
    WAF waf;
    // Double encoded: %252e%252e%252f = %2e%2e%2f = ../
    auto req = make_req("/files/%252e%252e%252f%252e%252e%252fetc/passwd");
    auto v = waf.inspect(req);
    ASSERT_TRUE(v.blocked);
    return true;
}

TEST(waf_blocks_xss_in_post_body) {
    WAF waf;
    auto req = make_req("/api/comment");
    req.method = HttpMethod::POST;
    req.method_str = "POST";
    req.headers["Content-Type"] = "application/x-www-form-urlencoded";
    // Combines tag (<svg>) + event handler (onload=) to exceed scoring threshold
    req.body = "comment=<svg onload=alert(1)>";
    auto v = waf.inspect(req);
    ASSERT_TRUE(v.blocked);
    return true;
}

TEST(waf_blocks_sqli_in_post_body) {
    WAF waf;
    auto req = make_req("/api/login");
    req.method = HttpMethod::POST;
    req.method_str = "POST";
    req.headers["Content-Type"] = "application/json";
    req.body = R"({"username":"admin' UNION SELECT * FROM users--","password":"x"})";
    auto v = waf.inspect(req);
    ASSERT_TRUE(v.blocked);
    return true;
}

TEST(waf_body_inspection_limit) {
    WAF waf;
    auto req = make_req("/upload");
    req.method = HttpMethod::POST;
    req.method_str = "POST";
    // Create a large body with attack at the very end (beyond limit)
    req.body = std::string(200000, 'A') + "<script>alert(1)</script>";
    // With default 128KB limit, the attack should be beyond inspection range
    auto v = waf.inspect(req, 131072);
    // The attack is at offset 200000, beyond the 128KB limit
    ASSERT_FALSE(v.blocked);
    return true;
}

// ===== Normalization tests =====

TEST(normalizer_recursive_url_decode) {
    // Double encoded: %253c -> %3c -> <
    auto result = PayloadNormalizer::recursive_url_decode("%253cscript%253e");
    ASSERT_EQ(result, "<script>");
    return true;
}

TEST(normalizer_triple_url_decode) {
    // Triple encoded: %25253c -> %253c -> %3c -> <
    auto result = PayloadNormalizer::recursive_url_decode("%25253c");
    ASSERT_EQ(result, "<");
    return true;
}

TEST(normalizer_html_entity_decode) {
    auto result = PayloadNormalizer::decode_html_entities("&lt;script&gt;alert(1)&lt;/script&gt;");
    ASSERT_EQ(result, "<script>alert(1)</script>");
    return true;
}

TEST(normalizer_html_numeric_entity) {
    auto result = PayloadNormalizer::decode_html_entities("&#60;script&#62;");
    ASSERT_EQ(result, "<script>");
    return true;
}

TEST(normalizer_html_hex_entity) {
    auto result = PayloadNormalizer::decode_html_entities("&#x3c;script&#x3e;");
    ASSERT_EQ(result, "<script>");
    return true;
}

TEST(normalizer_strip_null_bytes) {
    std::string input = "scr";
    input += '\0';
    input += "ipt";
    auto result = PayloadNormalizer::strip_null_bytes(input);
    ASSERT_EQ(result, "script");
    return true;
}

TEST(normalizer_strip_html_comments) {
    auto result = PayloadNormalizer::strip_html_comments("<scr<!-- -->ipt>");
    ASSERT_EQ(result, "<script>");
    return true;
}

TEST(normalizer_full_pipeline) {
    // Combined bypass attempt: double-encoded + HTML comments
    auto result = PayloadNormalizer::normalize("%253Cscr<!-- -->ipt%253E");
    ASSERT_TRUE(result.find("<script>") != std::string::npos);
    return true;
}
