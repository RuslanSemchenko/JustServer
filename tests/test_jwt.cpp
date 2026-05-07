#include "jwt_validator.hpp"
#include <cassert>
#include <iostream>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <cstring>

namespace {

// Helper: base64url encode
static std::string b64url_encode(std::string_view data) {
    static constexpr char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string result;
    result.reserve((data.size() + 2) / 3 * 4);
    size_t i = 0;
    for (; i + 2 < data.size(); i += 3) {
        uint32_t n = (static_cast<uint8_t>(data[i]) << 16) |
                     (static_cast<uint8_t>(data[i+1]) << 8) |
                     static_cast<uint8_t>(data[i+2]);
        result += table[(n >> 18) & 0x3F];
        result += table[(n >> 12) & 0x3F];
        result += table[(n >> 6) & 0x3F];
        result += table[n & 0x3F];
    }
    if (i + 1 == data.size()) {
        uint32_t n = static_cast<uint8_t>(data[i]) << 16;
        result += table[(n >> 18) & 0x3F];
        result += table[(n >> 12) & 0x3F];
    } else if (i + 2 == data.size()) {
        uint32_t n = (static_cast<uint8_t>(data[i]) << 16) |
                     (static_cast<uint8_t>(data[i+1]) << 8);
        result += table[(n >> 18) & 0x3F];
        result += table[(n >> 12) & 0x3F];
        result += table[(n >> 6) & 0x3F];
    }
    return result;
}

// Helper: create a simple HS256 JWT for testing
static std::string create_test_jwt(const std::string& payload_json, const std::string& secret) {
    std::string header = R"({"alg":"HS256","typ":"JWT"})";
    auto header_b64 = b64url_encode(header);
    auto payload_b64 = b64url_encode(payload_json);

    std::string signing_input = header_b64 + "." + payload_b64;

    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len = 0;
    HMAC(EVP_sha256(),
         secret.data(), static_cast<int>(secret.size()),
         reinterpret_cast<const unsigned char*>(signing_input.data()),
         signing_input.size(), mac, &mac_len);

    auto sig_b64 = b64url_encode(std::string_view(reinterpret_cast<char*>(mac), mac_len));
    return signing_input + "." + sig_b64;
}

void test_jwt_valid_hs256() {
    std::string secret = "test-secret-key-for-jwt-validation";

    // Create a token that expires far in the future
    std::string payload = R"({"sub":"user123","iss":"test","exp":9999999999,"iat":1000000000})";
    auto token = create_test_jwt(payload, secret);

    js::JwtValidator::Config config;
    config.hmac_secret = secret;
    js::JwtValidator validator(config);

    auto result = validator.validate(token);
    assert(result.valid);
    assert(result.claims.subject == "user123");
    assert(result.claims.issuer == "test");

    std::cout << "  [PASS] jwt_valid_hs256\n";
}

void test_jwt_expired() {
    std::string secret = "test-secret";

    // Create token that's already expired
    std::string payload = R"({"sub":"user","exp":1000000000,"iat":999999999})";
    auto token = create_test_jwt(payload, secret);

    js::JwtValidator::Config config;
    config.hmac_secret = secret;
    js::JwtValidator validator(config);

    auto result = validator.validate(token);
    assert(!result.valid);
    assert(result.error.find("expired") != std::string::npos);

    std::cout << "  [PASS] jwt_expired\n";
}

void test_jwt_invalid_signature() {
    auto token = create_test_jwt(R"({"sub":"user","exp":9999999999})", "correct-secret");

    js::JwtValidator::Config config;
    config.hmac_secret = "wrong-secret";
    js::JwtValidator validator(config);

    auto result = validator.validate(token);
    assert(!result.valid);
    assert(result.error.find("signature") != std::string::npos);

    std::cout << "  [PASS] jwt_invalid_signature\n";
}

void test_jwt_wrong_issuer() {
    std::string secret = "test-secret";
    auto token = create_test_jwt(R"({"sub":"user","iss":"wrong","exp":9999999999})", secret);

    js::JwtValidator::Config config;
    config.hmac_secret = secret;
    config.required_issuer = "expected-issuer";
    js::JwtValidator validator(config);

    auto result = validator.validate(token);
    assert(!result.valid);
    assert(result.error.find("issuer") != std::string::npos);

    std::cout << "  [PASS] jwt_wrong_issuer\n";
}

void test_jwt_wrong_audience() {
    std::string secret = "test-secret";
    auto token = create_test_jwt(R"({"sub":"user","aud":"wrong-aud","exp":9999999999})", secret);

    js::JwtValidator::Config config;
    config.hmac_secret = secret;
    config.required_audience = "expected-audience";
    js::JwtValidator validator(config);

    auto result = validator.validate(token);
    assert(!result.valid);
    assert(result.error.find("audience") != std::string::npos);

    std::cout << "  [PASS] jwt_wrong_audience\n";
}

void test_jwt_nbf_not_yet_valid() {
    std::string secret = "test-secret";
    // nbf far in the future
    auto token = create_test_jwt(R"({"sub":"user","nbf":9999999999,"exp":9999999999})", secret);

    js::JwtValidator::Config config;
    config.hmac_secret = secret;
    js::JwtValidator validator(config);

    auto result = validator.validate(token);
    assert(!result.valid);
    assert(result.error.find("not yet valid") != std::string::npos);

    std::cout << "  [PASS] jwt_nbf_not_yet_valid\n";
}

void test_jwt_extract_bearer() {
    auto token = js::JwtValidator::extract_bearer_token("Bearer eyJ0eXAi.eyJzdWIi.signature");
    assert(token.has_value());
    assert(token->starts_with("eyJ0eXAi"));

    auto no_token = js::JwtValidator::extract_bearer_token("Basic dXNlcjpwYXNz");
    assert(!no_token.has_value());

    std::cout << "  [PASS] jwt_extract_bearer\n";
}

void test_jwt_malformed() {
    js::JwtValidator::Config config;
    config.hmac_secret = "secret";
    js::JwtValidator validator(config);

    // No dots
    auto r1 = validator.validate("nodots");
    assert(!r1.valid);

    // Only one dot
    auto r2 = validator.validate("one.dot");
    assert(!r2.valid);

    // Empty sections
    auto r3 = validator.validate("...");
    assert(!r3.valid);

    std::cout << "  [PASS] jwt_malformed\n";
}

// === New tests for hardened JSON parser ===

void test_jwt_json_escaped_quotes() {
    // Test that escaped quotes in values don't break parsing
    // The old find()-based parser would break on escaped quotes
    std::string secret = "test-secret";
    std::string payload = R"({"sub":"user\"admin","exp":9999999999})";
    auto token = create_test_jwt(payload, secret);

    js::JwtValidator::Config config;
    config.hmac_secret = secret;
    js::JwtValidator validator(config);

    auto result = validator.validate(token);
    assert(result.valid);
    assert(result.claims.subject == "user\"admin");

    std::cout << "  [PASS] jwt_json_escaped_quotes\n";
}

void test_jwt_json_key_in_value_bypass() {
    // Attack: embed "sub" as part of another value to confuse find()-based parser
    // The old parser would match the "sub" inside the value of "description",
    // returning "attacker" instead of "real-user"
    std::string secret = "test-secret";
    std::string payload = R"({"description":"has sub inside","sub":"real-user","exp":9999999999})";
    auto token = create_test_jwt(payload, secret);

    js::JwtValidator::Config config;
    config.hmac_secret = secret;
    js::JwtValidator validator(config);

    auto result = validator.validate(token);
    assert(result.valid);
    assert(result.claims.subject == "real-user");

    std::cout << "  [PASS] jwt_json_key_in_value_bypass\n";
}

void test_jwt_json_nested_objects() {
    // Test that nested objects are skipped correctly
    std::string secret = "test-secret";
    std::string payload = R"({"metadata":{"sub":"nested-value","inner":true},"sub":"top-level-user","exp":9999999999})";
    auto token = create_test_jwt(payload, secret);

    js::JwtValidator::Config config;
    config.hmac_secret = secret;
    js::JwtValidator validator(config);

    auto result = validator.validate(token);
    assert(result.valid);
    // The parser should find the TOP-LEVEL "sub", not the one inside "metadata"
    assert(result.claims.subject == "top-level-user");

    std::cout << "  [PASS] jwt_json_nested_objects\n";
}

void test_jwt_json_unicode_escape() {
    // Test that \uXXXX escapes are handled
    std::string secret = "test-secret";
    // \u0041 = 'A'
    std::string payload = R"({"sub":"\u0041dmin","exp":9999999999})";
    auto token = create_test_jwt(payload, secret);

    js::JwtValidator::Config config;
    config.hmac_secret = secret;
    js::JwtValidator validator(config);

    auto result = validator.validate(token);
    assert(result.valid);
    assert(result.claims.subject == "Admin");

    std::cout << "  [PASS] jwt_json_unicode_escape\n";
}

void test_jwt_json_arrays_in_payload() {
    // Test that arrays are skipped correctly
    std::string secret = "test-secret";
    std::string payload = R"({"roles":["admin","user"],"sub":"array-test","exp":9999999999})";
    auto token = create_test_jwt(payload, secret);

    js::JwtValidator::Config config;
    config.hmac_secret = secret;
    js::JwtValidator validator(config);

    auto result = validator.validate(token);
    assert(result.valid);
    assert(result.claims.subject == "array-test");

    std::cout << "  [PASS] jwt_json_arrays_in_payload\n";
}

void test_jwt_json_boolean_null_values() {
    // Test that boolean and null values are handled
    std::string secret = "test-secret";
    std::string payload = R"({"active":true,"deleted":false,"extra":null,"sub":"bool-test","exp":9999999999})";
    auto token = create_test_jwt(payload, secret);

    js::JwtValidator::Config config;
    config.hmac_secret = secret;
    js::JwtValidator validator(config);

    auto result = validator.validate(token);
    assert(result.valid);
    assert(result.claims.subject == "bool-test");

    std::cout << "  [PASS] jwt_json_boolean_null_values\n";
}

} // namespace

void run_jwt_tests() {
    std::cout << "=== JWT Validator Tests ===\n";
    test_jwt_valid_hs256();
    test_jwt_expired();
    test_jwt_invalid_signature();
    test_jwt_wrong_issuer();
    test_jwt_wrong_audience();
    test_jwt_nbf_not_yet_valid();
    test_jwt_extract_bearer();
    test_jwt_malformed();
    // Hardened JSON parser tests
    test_jwt_json_escaped_quotes();
    test_jwt_json_key_in_value_bypass();
    test_jwt_json_nested_objects();
    test_jwt_json_unicode_escape();
    test_jwt_json_arrays_in_payload();
    test_jwt_json_boolean_null_values();
    std::cout << "=== All JWT tests passed ===\n\n";
}
