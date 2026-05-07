#pragma once

#include <string>
#include <string_view>
#include <optional>
#include <unordered_map>
#include <vector>
#include <chrono>

namespace js {

// JWT (JSON Web Token) validator for Zero Trust edge authentication.
// Validates tokens at the edge (JustServer) so invalid requests
// never reach the backend, saving backend resources.
class JwtValidator {
public:
    struct Claims {
        std::string subject;      // "sub"
        std::string issuer;       // "iss"
        std::string audience;     // "aud"
        int64_t issued_at = 0;    // "iat" (Unix timestamp)
        int64_t expires_at = 0;   // "exp" (Unix timestamp)
        int64_t not_before = 0;   // "nbf" (Unix timestamp)
        std::string jti;          // JWT ID
        std::unordered_map<std::string, std::string> custom; // Additional claims
    };

    struct ValidationResult {
        bool valid = false;
        std::string error;
        Claims claims;
    };

    struct Config {
        // HMAC secret for HS256/HS384/HS512
        std::string hmac_secret;

        // RSA/EC public key (PEM) for RS256/ES256 verification
        std::string public_key_pem;

        // Expected issuer (optional, if set, must match)
        std::string required_issuer;

        // Expected audience (optional)
        std::string required_audience;

        // Clock skew tolerance
        std::chrono::seconds clock_skew{60};

        // Allowed algorithms (e.g., {"HS256", "RS256"})
        std::vector<std::string> allowed_algorithms = {"HS256", "RS256", "ES256"};
    };

    explicit JwtValidator(Config config);

    // Validate a JWT token string
    ValidationResult validate(std::string_view token) const;

    // Extract the Authorization: Bearer <token> from a request header
    static std::optional<std::string_view> extract_bearer_token(std::string_view auth_header);

    // State-machine JSON parser (handles escapes, nesting, key vs value)
    // Public so fuzzers and tests can exercise them directly.
    static std::optional<std::string> json_get_string(std::string_view json, std::string_view key);
    static std::optional<int64_t> json_get_number(std::string_view json, std::string_view key);

private:
    // JWT parts
    struct JwtParts {
        std::string_view header_b64;
        std::string_view payload_b64;
        std::string_view signature_b64;
    };

    // Split token into header.payload.signature
    static std::optional<JwtParts> split_token(std::string_view token);

    // Base64url decode
    static std::optional<std::string> base64url_decode(std::string_view input);

    // Internal: parse a JSON string token starting at pos (pos points to opening '"')
    // Returns the unescaped string content and advances pos past the closing '"'.
    // Returns std::nullopt on malformed input.
    static std::optional<std::string> parse_json_string(std::string_view json, size_t& pos);

    // Internal: skip a JSON value (string, number, object, array, bool, null)
    // starting at pos.  Returns false on malformed input.
    static bool skip_json_value(std::string_view json, size_t& pos);

    // Verify HMAC-SHA256 signature
    bool verify_hs256(std::string_view signing_input, std::string_view signature) const;

    // Verify RSA-SHA256 signature
    bool verify_rs256(std::string_view signing_input, std::string_view signature) const;

    // Verify ECDSA-SHA256 signature
    bool verify_es256(std::string_view signing_input, std::string_view signature) const;

    Config config_;
};

} // namespace js
