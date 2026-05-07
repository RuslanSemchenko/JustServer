// JWT Validator Fuzzer (libFuzzer)
// Fuzzes the JWT JSON parser, base64url decoder, and token validation pipeline.
// Targets the state-machine JSON parser to find crashes, hangs, or memory issues.

#include "jwt_validator.hpp"

#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0) return 0;

    // Limit input size to prevent OOM
    if (size > 16384) return 0;

    std::string_view input(reinterpret_cast<const char*>(data), size);

    // --- Fuzz 1: Full JWT validation pipeline ---
    {
        js::JwtValidator::Config config;
        config.hmac_secret = "fuzz-secret-key-for-testing-1234";
        config.allowed_algorithms = {"HS256", "RS256", "ES256"};
        config.clock_skew = std::chrono::seconds(9999999); // Don't reject on time
        js::JwtValidator validator(config);

        // Try to validate the fuzzed input as a JWT token
        auto result = validator.validate(input);
        // Just exercise the result -- we're looking for crashes, not correctness
        (void)result.valid;
        (void)result.error;
        (void)result.claims.subject;
        (void)result.claims.issuer;
        (void)result.claims.audience;
        (void)result.claims.expires_at;
    }

    // --- Fuzz 2: Bearer token extraction ---
    {
        auto token = js::JwtValidator::extract_bearer_token(input);
        (void)token;
    }

    // --- Fuzz 3: Direct JSON parser exercising ---
    // Feed raw bytes as if they were a decoded JWT payload JSON
    // This directly tests the state-machine parser
    {
        // Try to extract various keys from fuzzed JSON
        auto sub = js::JwtValidator::json_get_string(input, "sub");
        (void)sub;
        auto iss = js::JwtValidator::json_get_string(input, "iss");
        (void)iss;
        auto exp_val = js::JwtValidator::json_get_number(input, "exp");
        (void)exp_val;
        auto nbf_val = js::JwtValidator::json_get_number(input, "nbf");
        (void)nbf_val;
    }

    return 0;
}
