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

std::optional<std::string> JwtValidator::json_get_string(std::string_view json, std::string_view key) {
    // Simple JSON string extraction (no nested objects)
    std::string search = "\"" + std::string(key) + "\"";
    auto pos = json.find(search);
    if (pos == std::string_view::npos) return std::nullopt;

    pos += search.size();
    // Skip whitespace and colon
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':')) ++pos;
    if (pos >= json.size()) return std::nullopt;

    if (json[pos] == '"') {
        // String value
        ++pos;
        auto end = json.find('"', pos);
        if (end == std::string_view::npos) return std::nullopt;
        return std::string(json.substr(pos, end - pos));
    }

    // Number as string
    auto end = pos;
    while (end < json.size() && json[end] != ',' && json[end] != '}' && json[end] != ' ') ++end;
    return std::string(json.substr(pos, end - pos));
}

std::optional<int64_t> JwtValidator::json_get_number(std::string_view json, std::string_view key) {
    auto str = json_get_string(json, key);
    if (!str) return std::nullopt;

    try {
        return std::stoll(*str);
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
