#include "jwt_validator.hpp"
#include "logger.hpp"

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/err.h>

#include <cstring>
#include <ctime>

namespace js {

JwtValidator::JwtValidator(Config config) : config_(std::move(config)) {}

std::optional<std::string_view> JwtValidator::extract_bearer_token(std::string_view auth_header) {
    constexpr std::string_view prefix = "Bearer ";
    if (auth_header.size() > prefix.size() &&
        auth_header.substr(0, prefix.size()) == prefix) {
        return auth_header.substr(prefix.size());
    }
    return std::nullopt;
}

std::optional<JwtValidator::JwtParts> JwtValidator::split_token(std::string_view token) {
    auto dot1 = token.find('.');
    if (dot1 == std::string_view::npos) return std::nullopt;

    auto dot2 = token.find('.', dot1 + 1);
    if (dot2 == std::string_view::npos) return std::nullopt;

    // Ensure no more dots
    if (token.find('.', dot2 + 1) != std::string_view::npos) return std::nullopt;

    return JwtParts{
        token.substr(0, dot1),
        token.substr(dot1 + 1, dot2 - dot1 - 1),
        token.substr(dot2 + 1)
    };
}

std::optional<std::string> JwtValidator::base64url_decode(std::string_view input) {
    // Base64url to standard base64
    std::string b64;
    b64.reserve(input.size() + 4);
    for (char c : input) {
        switch (c) {
            case '-': b64 += '+'; break;
            case '_': b64 += '/'; break;
            default: b64 += c; break;
        }
    }
    // Add padding
    while (b64.size() % 4 != 0) b64 += '=';

    // Decode
    std::string output(b64.size() * 3 / 4 + 1, '\0');
    int len = EVP_DecodeBlock(
        reinterpret_cast<unsigned char*>(output.data()),
        reinterpret_cast<const unsigned char*>(b64.data()),
        static_cast<int>(b64.size()));

    if (len < 0) return std::nullopt;

    // Adjust for padding
    size_t pad = 0;
    if (b64.size() >= 2 && b64[b64.size() - 1] == '=') ++pad;
    if (b64.size() >= 2 && b64[b64.size() - 2] == '=') ++pad;

    output.resize(static_cast<size_t>(len) - pad);
    return output;
}

// Parse a JSON string token starting at pos (must point to opening '"').
// Returns the unescaped string and advances pos past the closing '"'.
std::optional<std::string> JwtValidator::parse_json_string(std::string_view json, size_t& pos) {
    if (pos >= json.size() || json[pos] != '"') return std::nullopt;
    ++pos; // skip opening quote

    std::string result;
    result.reserve(32);

    while (pos < json.size()) {
        char c = json[pos];
        if (c == '"') {
            ++pos; // skip closing quote
            return result;
        }
        if (c == '\\') {
            ++pos;
            if (pos >= json.size()) return std::nullopt;
            char esc = json[pos];
            switch (esc) {
                case '"':  result += '"'; break;
                case '\\': result += '\\'; break;
                case '/':  result += '/'; break;
                case 'b':  result += '\b'; break;
                case 'f':  result += '\f'; break;
                case 'n':  result += '\n'; break;
                case 'r':  result += '\r'; break;
                case 't':  result += '\t'; break;
                case 'u': {
                    // \uXXXX unicode escape
                    if (pos + 4 >= json.size()) return std::nullopt;
                    uint32_t cp = 0;
                    for (int i = 1; i <= 4; ++i) {
                        char h = json[pos + i];
                        cp <<= 4;
                        if (h >= '0' && h <= '9') cp |= (h - '0');
                        else if (h >= 'a' && h <= 'f') cp |= (h - 'a' + 10);
                        else if (h >= 'A' && h <= 'F') cp |= (h - 'A' + 10);
                        else return std::nullopt;
                    }
                    pos += 4;
                    // Encode as UTF-8
                    if (cp < 0x80) {
                        result += static_cast<char>(cp);
                    } else if (cp < 0x800) {
                        result += static_cast<char>(0xC0 | (cp >> 6));
                        result += static_cast<char>(0x80 | (cp & 0x3F));
                    } else {
                        result += static_cast<char>(0xE0 | (cp >> 12));
                        result += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                        result += static_cast<char>(0x80 | (cp & 0x3F));
                    }
                    break;
                }
                default: return std::nullopt; // Invalid escape
            }
        } else if (static_cast<unsigned char>(c) < 0x20) {
            return std::nullopt; // Control characters not allowed in JSON strings
        } else {
            result += c;
        }
        ++pos;
    }
    return std::nullopt; // Unterminated string
}

// Skip a JSON value starting at pos (string, number, object, array, bool, null).
bool JwtValidator::skip_json_value(std::string_view json, size_t& pos) {
    // Skip whitespace
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' ||
           json[pos] == '\n' || json[pos] == '\r')) ++pos;
    if (pos >= json.size()) return false;

    char c = json[pos];
    if (c == '"') {
        // String
        auto s = parse_json_string(json, pos);
        return s.has_value();
    } else if (c == '{') {
        // Object -- track nesting depth
        int depth = 1;
        ++pos;
        while (pos < json.size() && depth > 0) {
            if (json[pos] == '"') {
                auto s = parse_json_string(json, pos);
                if (!s) return false;
                continue; // pos already advanced
            }
            if (json[pos] == '{') ++depth;
            else if (json[pos] == '}') --depth;
            ++pos;
        }
        return depth == 0;
    } else if (c == '[') {
        // Array -- track nesting depth
        int depth = 1;
        ++pos;
        while (pos < json.size() && depth > 0) {
            if (json[pos] == '"') {
                auto s = parse_json_string(json, pos);
                if (!s) return false;
                continue;
            }
            if (json[pos] == '[') ++depth;
            else if (json[pos] == ']') --depth;
            ++pos;
        }
        return depth == 0;
    } else if (c == '-' || (c >= '0' && c <= '9')) {
        // Number
        if (c == '-') ++pos;
        if (pos >= json.size()) return false;
        while (pos < json.size() && json[pos] >= '0' && json[pos] <= '9') ++pos;
        if (pos < json.size() && json[pos] == '.') {
            ++pos;
            while (pos < json.size() && json[pos] >= '0' && json[pos] <= '9') ++pos;
        }
        if (pos < json.size() && (json[pos] == 'e' || json[pos] == 'E')) {
            ++pos;
            if (pos < json.size() && (json[pos] == '+' || json[pos] == '-')) ++pos;
            while (pos < json.size() && json[pos] >= '0' && json[pos] <= '9') ++pos;
        }
        return true;
    } else if (json.substr(pos).starts_with("true")) {
        pos += 4; return true;
    } else if (json.substr(pos).starts_with("false")) {
        pos += 5; return true;
    } else if (json.substr(pos).starts_with("null")) {
        pos += 4; return true;
    }
    return false;
}

// Skip whitespace helper
static void skip_ws(std::string_view json, size_t& pos) {
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' ||
           json[pos] == '\n' || json[pos] == '\r')) ++pos;
}

// State-machine JSON parser: find a top-level key in a JSON object and return
// its value as a string.  For string values, returns the unescaped content.
// For numbers/bools/null, returns the raw text representation.
// Correctly handles escaped quotes, nested objects/arrays, and distinguishes
// keys from values -- fixing the old find()-based bypass vulnerability.
std::optional<std::string> JwtValidator::json_get_string(std::string_view json, std::string_view key) {
    size_t pos = 0;
    skip_ws(json, pos);

    // Expect opening '{'
    if (pos >= json.size() || json[pos] != '{') return std::nullopt;
    ++pos;

    while (pos < json.size()) {
        skip_ws(json, pos);
        if (pos >= json.size()) return std::nullopt;
        if (json[pos] == '}') return std::nullopt; // key not found

        // Parse key (must be a string)
        auto parsed_key = parse_json_string(json, pos);
        if (!parsed_key) return std::nullopt;

        // Expect ':'
        skip_ws(json, pos);
        if (pos >= json.size() || json[pos] != ':') return std::nullopt;
        ++pos;
        skip_ws(json, pos);

        if (*parsed_key == key) {
            // This is the key we want -- extract the value
            if (pos >= json.size()) return std::nullopt;

            if (json[pos] == '"') {
                // String value
                return parse_json_string(json, pos);
            }

            // Non-string value: capture the raw text
            size_t val_start = pos;
            if (!skip_json_value(json, pos)) return std::nullopt;
            return std::string(json.substr(val_start, pos - val_start));
        }

        // Not the key we want -- skip the value
        if (!skip_json_value(json, pos)) return std::nullopt;

        // Expect ',' or '}'
        skip_ws(json, pos);
        if (pos >= json.size()) return std::nullopt;
        if (json[pos] == ',') { ++pos; continue; }
        if (json[pos] == '}') return std::nullopt; // key not found
        return std::nullopt; // malformed JSON
    }
    return std::nullopt;
}

std::optional<int64_t> JwtValidator::json_get_number(std::string_view json, std::string_view key) {
    auto str = json_get_string(json, key);
    if (!str) return std::nullopt;

    // Trim whitespace from raw number text
    std::string_view sv = *str;
    while (!sv.empty() && sv.front() == ' ') sv.remove_prefix(1);
    while (!sv.empty() && sv.back() == ' ') sv.remove_suffix(1);

    try {
        size_t consumed = 0;
        int64_t val = std::stoll(std::string(sv), &consumed);
        if (consumed == 0) return std::nullopt;
        return val;
    } catch (...) {
        return std::nullopt;
    }
}

bool JwtValidator::verify_hs256(std::string_view signing_input, std::string_view signature) const {
    if (config_.hmac_secret.empty()) return false;

    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len = 0;

    HMAC(EVP_sha256(),
         config_.hmac_secret.data(), static_cast<int>(config_.hmac_secret.size()),
         reinterpret_cast<const unsigned char*>(signing_input.data()),
         signing_input.size(),
         mac, &mac_len);

    auto decoded_sig = base64url_decode(signature);
    if (!decoded_sig) return false;

    if (decoded_sig->size() != mac_len) return false;
    return CRYPTO_memcmp(mac, decoded_sig->data(), mac_len) == 0;
}

bool JwtValidator::verify_rs256(std::string_view signing_input, std::string_view signature) const {
    if (config_.public_key_pem.empty()) return false;

    auto decoded_sig = base64url_decode(signature);
    if (!decoded_sig) return false;

    BIO* bio = BIO_new_mem_buf(config_.public_key_pem.data(),
                                static_cast<int>(config_.public_key_pem.size()));
    if (!bio) return false;

    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool valid = false;

    if (ctx) {
        if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) == 1 &&
            EVP_DigestVerifyUpdate(ctx, signing_input.data(), signing_input.size()) == 1) {
            valid = (EVP_DigestVerifyFinal(
                ctx,
                reinterpret_cast<const unsigned char*>(decoded_sig->data()),
                decoded_sig->size()) == 1);
        }
        EVP_MD_CTX_free(ctx);
    }

    EVP_PKEY_free(pkey);
    return valid;
}

bool JwtValidator::verify_es256(std::string_view signing_input, std::string_view signature) const {
    if (config_.public_key_pem.empty()) return false;

    auto decoded_sig = base64url_decode(signature);
    if (!decoded_sig || decoded_sig->size() != 64) return false;

    BIO* bio = BIO_new_mem_buf(config_.public_key_pem.data(),
                                static_cast<int>(config_.public_key_pem.size()));
    if (!bio) return false;

    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) return false;

    // Convert raw R||S signature to DER format for OpenSSL
    // ES256 produces 32 bytes R + 32 bytes S
    ECDSA_SIG* ec_sig = ECDSA_SIG_new();
    BIGNUM* r = BN_bin2bn(reinterpret_cast<const unsigned char*>(decoded_sig->data()), 32, nullptr);
    BIGNUM* s = BN_bin2bn(reinterpret_cast<const unsigned char*>(decoded_sig->data() + 32), 32, nullptr);
    ECDSA_SIG_set0(ec_sig, r, s);

    unsigned char* der_sig = nullptr;
    int der_len = i2d_ECDSA_SIG(ec_sig, &der_sig);
    ECDSA_SIG_free(ec_sig);

    if (der_len <= 0 || !der_sig) {
        EVP_PKEY_free(pkey);
        return false;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool valid = false;

    if (ctx) {
        if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) == 1 &&
            EVP_DigestVerifyUpdate(ctx, signing_input.data(), signing_input.size()) == 1) {
            valid = (EVP_DigestVerifyFinal(ctx, der_sig, static_cast<size_t>(der_len)) == 1);
        }
        EVP_MD_CTX_free(ctx);
    }

    OPENSSL_free(der_sig);
    EVP_PKEY_free(pkey);
    return valid;
}

JwtValidator::ValidationResult JwtValidator::validate(std::string_view token) const {
    ValidationResult result;

    // Split token
    auto parts = split_token(token);
    if (!parts) {
        result.error = "Invalid token format";
        return result;
    }

    // Decode header
    auto header_json = base64url_decode(parts->header_b64);
    if (!header_json) {
        result.error = "Invalid header encoding";
        return result;
    }

    // Check algorithm
    auto alg = json_get_string(*header_json, "alg");
    if (!alg) {
        result.error = "Missing algorithm";
        return result;
    }

    bool alg_allowed = false;
    for (const auto& a : config_.allowed_algorithms) {
        if (a == *alg) { alg_allowed = true; break; }
    }
    if (!alg_allowed) {
        result.error = "Algorithm not allowed: " + *alg;
        return result;
    }

    // Verify signature
    std::string signing_input = std::string(parts->header_b64) + "." + std::string(parts->payload_b64);
    bool sig_valid = false;

    if (*alg == "HS256") sig_valid = verify_hs256(signing_input, parts->signature_b64);
    else if (*alg == "RS256") sig_valid = verify_rs256(signing_input, parts->signature_b64);
    else if (*alg == "ES256") sig_valid = verify_es256(signing_input, parts->signature_b64);

    if (!sig_valid) {
        result.error = "Invalid signature";
        return result;
    }

    // Decode payload
    auto payload_json = base64url_decode(parts->payload_b64);
    if (!payload_json) {
        result.error = "Invalid payload encoding";
        return result;
    }

    // Parse claims
    auto sub = json_get_string(*payload_json, "sub");
    if (sub) result.claims.subject = *sub;

    auto iss = json_get_string(*payload_json, "iss");
    if (iss) result.claims.issuer = *iss;

    auto aud = json_get_string(*payload_json, "aud");
    if (aud) result.claims.audience = *aud;

    auto iat = json_get_number(*payload_json, "iat");
    if (iat) result.claims.issued_at = *iat;

    auto exp = json_get_number(*payload_json, "exp");
    if (exp) result.claims.expires_at = *exp;

    auto nbf = json_get_number(*payload_json, "nbf");
    if (nbf) result.claims.not_before = *nbf;

    auto jti = json_get_string(*payload_json, "jti");
    if (jti) result.claims.jti = *jti;

    // Validate time-based claims
    auto now = std::chrono::system_clock::now();
    auto now_ts = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    auto skew = config_.clock_skew.count();

    if (result.claims.expires_at > 0 && now_ts > result.claims.expires_at + skew) {
        result.error = "Token expired";
        return result;
    }

    if (result.claims.not_before > 0 && now_ts < result.claims.not_before - skew) {
        result.error = "Token not yet valid";
        return result;
    }

    // Validate issuer
    if (!config_.required_issuer.empty() && result.claims.issuer != config_.required_issuer) {
        result.error = "Invalid issuer: " + result.claims.issuer;
        return result;
    }

    // Validate audience
    if (!config_.required_audience.empty() && result.claims.audience != config_.required_audience) {
        result.error = "Invalid audience: " + result.claims.audience;
        return result;
    }

    result.valid = true;
    return result;
}

} // namespace js
