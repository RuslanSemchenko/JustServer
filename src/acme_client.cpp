#include "acme_client.hpp"
#include "logger.hpp"

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>

#include <fstream>
#include <filesystem>
#include <sstream>
#include <cstring>
#include <array>

namespace js {

AcmeClient::AcmeClient(Config config) : config_(std::move(config)) {}

AcmeClient::~AcmeClient() = default;

bool AcmeClient::initialize() {
    // Create storage directory
    std::error_code ec;
    std::filesystem::create_directories(config_.storage_path, ec);
    if (ec) {
        LOG_ERROR("ACME: Failed to create storage dir: " + config_.storage_path);
        return false;
    }

    // Load or generate account key
    auto key = load_account_key();
    if (key) {
        account_key_pem_ = *key;
        LOG_INFO("ACME: Loaded existing account key");
    } else {
        account_key_pem_ = generate_ec_key();
        if (account_key_pem_.empty()) {
            LOG_ERROR("ACME: Failed to generate account key");
            return false;
        }
        save_account_key(account_key_pem_);
        LOG_INFO("ACME: Generated new EC P-256 account key");
    }

    // Load existing certificates
    for (const auto& domain : config_.domains) {
        auto cert = load_cert(domain);
        if (cert && cert->valid) {
            std::lock_guard lock(certs_mutex_);
            certificates_[domain] = *cert;
            LOG_INFO("ACME: Loaded certificate for " + domain);
        }
    }

    return true;
}

bool AcmeClient::obtain_certificates() {
    for (const auto& domain : config_.domains) {
        // Check if we already have a valid cert
        {
            std::lock_guard lock(certs_mutex_);
            auto it = certificates_.find(domain);
            if (it != certificates_.end() && it->second.valid) {
                auto now = std::chrono::system_clock::now();
                auto days_until_expiry = std::chrono::duration_cast<std::chrono::hours>(
                    it->second.not_after - now).count() / 24;
                if (days_until_expiry > config_.renew_before_days) {
                    LOG_INFO("ACME: Certificate for " + domain + " still valid (" +
                             std::to_string(days_until_expiry) + " days)");
                    continue;
                }
            }
        }

        LOG_INFO("ACME: Obtaining certificate for " + domain);

        // ACME flow: newOrder -> authorization -> HTTP-01 challenge -> finalize -> download
        if (!create_order(domain)) {
            LOG_ERROR("ACME: Failed to create order for " + domain);
            return false;
        }
    }

    return true;
}

bool AcmeClient::check_and_renew() {
    auto now = std::chrono::system_clock::now();

    std::lock_guard lock(certs_mutex_);
    for (auto& [domain, cert] : certificates_) {
        auto days_until_expiry = std::chrono::duration_cast<std::chrono::hours>(
            cert.not_after - now).count() / 24;

        if (days_until_expiry <= config_.renew_before_days) {
            LOG_INFO("ACME: Certificate for " + domain + " expires in " +
                     std::to_string(days_until_expiry) + " days, renewing...");

            // Trigger renewal (release lock temporarily)
            // In production, this would run the full ACME flow
        }
    }

    return true;
}

std::optional<AcmeClient::CertInfo> AcmeClient::get_certificate(std::string_view domain) const {
    std::lock_guard lock(certs_mutex_);
    auto it = certificates_.find(std::string(domain));
    if (it != certificates_.end()) return it->second;
    return std::nullopt;
}

std::optional<std::string> AcmeClient::handle_challenge(std::string_view token) const {
    std::lock_guard lock(challenges_mutex_);
    auto it = active_challenges_.find(std::string(token));
    if (it != active_challenges_.end()) return it->second;
    return std::nullopt;
}

// === Crypto helpers ===

std::string AcmeClient::generate_ec_key() {
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!ctx) return {};

    std::string result;

    if (EVP_PKEY_keygen_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); return {}; }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) { EVP_PKEY_CTX_free(ctx); return {}; }

    BIO* bio = BIO_new(BIO_s_mem());
    if (bio && PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
        char* data = nullptr;
        long len = BIO_get_mem_data(bio, &data);
        result.assign(data, static_cast<size_t>(len));
    }

    BIO_free(bio);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return result;
}

std::string AcmeClient::create_csr(const std::string& domain, const std::string& key_pem) {
    BIO* key_bio = BIO_new_mem_buf(key_pem.data(), static_cast<int>(key_pem.size()));
    if (!key_bio) return {};

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr);
    BIO_free(key_bio);
    if (!pkey) return {};

    X509_REQ* req = X509_REQ_new();
    if (!req) { EVP_PKEY_free(pkey); return {}; }

    X509_REQ_set_version(req, 0);

    X509_NAME* name = X509_REQ_get_subject_name(req);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>(domain.c_str()), -1, -1, 0);

    X509_REQ_set_pubkey(req, pkey);
    X509_REQ_sign(req, pkey, EVP_sha256());

    BIO* bio = BIO_new(BIO_s_mem());
    std::string result;
    if (bio && i2d_X509_REQ_bio(bio, req)) {
        char* data = nullptr;
        long len = BIO_get_mem_data(bio, &data);
        result.assign(data, static_cast<size_t>(len));
    }

    BIO_free(bio);
    X509_REQ_free(req);
    EVP_PKEY_free(pkey);

    return result;
}

std::string AcmeClient::base64url_encode(std::string_view data) {
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

    return result; // No padding in base64url
}

// === Storage helpers ===

bool AcmeClient::save_cert(const std::string& domain, const CertInfo& cert) {
    auto dir = std::filesystem::path(config_.storage_path) / domain;
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec) return false;

    {
        std::ofstream f(dir / "cert.pem");
        if (!f) return false;
        f << cert.cert_pem;
    }
    {
        std::ofstream f(dir / "key.pem");
        if (!f) return false;
        f << cert.key_pem;
    }

    return true;
}

std::optional<AcmeClient::CertInfo> AcmeClient::load_cert(const std::string& domain) const {
    auto dir = std::filesystem::path(config_.storage_path) / domain;
    auto cert_path = dir / "cert.pem";
    auto key_path = dir / "key.pem";

    if (!std::filesystem::exists(cert_path) || !std::filesystem::exists(key_path))
        return std::nullopt;

    CertInfo info;
    info.domain = domain;

    {
        std::ifstream f(cert_path);
        if (!f) return std::nullopt;
        std::ostringstream ss;
        ss << f.rdbuf();
        info.cert_pem = ss.str();
    }
    {
        std::ifstream f(key_path);
        if (!f) return std::nullopt;
        std::ostringstream ss;
        ss << f.rdbuf();
        info.key_pem = ss.str();
    }

    // Parse certificate to get expiry
    BIO* bio = BIO_new_mem_buf(info.cert_pem.data(), static_cast<int>(info.cert_pem.size()));
    if (bio) {
        X509* x509 = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        if (x509) {
            const ASN1_TIME* not_after = X509_get0_notAfter(x509);
            struct tm tm_val{};
            ASN1_TIME_to_tm(not_after, &tm_val);
            info.not_after = std::chrono::system_clock::from_time_t(mktime(&tm_val));
            info.valid = (std::chrono::system_clock::now() < info.not_after);
            X509_free(x509);
        }
        BIO_free(bio);
    }

    return info;
}

bool AcmeClient::save_account_key(const std::string& key_pem) {
    auto path = std::filesystem::path(config_.storage_path) / "account_key.pem";
    std::ofstream f(path);
    if (!f) return false;
    f << key_pem;
    return true;
}

std::optional<std::string> AcmeClient::load_account_key() const {
    auto path = std::filesystem::path(config_.storage_path) / "account_key.pem";
    if (!std::filesystem::exists(path)) return std::nullopt;

    std::ifstream f(path);
    if (!f) return std::nullopt;
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// === ACME protocol stubs (full HTTP integration requires async HTTP client) ===

bool AcmeClient::register_account() {
    LOG_INFO("ACME: Account registration (requires network access to " + config_.directory_url + ")");
    // Full implementation would:
    // 1. GET directory URL to discover endpoints
    // 2. POST newAccount with JWS-signed payload
    // 3. Store account_kid_ from Location header
    return false; // Stub - needs HTTP client integration
}

bool AcmeClient::create_order(const std::string& domain) {
    LOG_INFO("ACME: Creating order for " + domain);
    // Full implementation would:
    // 1. POST newOrder with domain identifiers
    // 2. Process authorization URLs
    // 3. Solve HTTP-01 challenge
    // 4. Finalize with CSR
    // 5. Download certificate
    return false; // Stub
}

bool AcmeClient::solve_http01_challenge(const std::string& domain, const std::string& token,
                                          const std::string& key_authorization) {
    LOG_INFO("ACME: Solving HTTP-01 challenge for " + domain);

    // Register the challenge response so the HTTP handler can serve it
    {
        std::lock_guard lock(challenges_mutex_);
        active_challenges_[token] = key_authorization;
    }

    // In full implementation: POST to challenge URL to signal readiness
    // Then wait for validation
    return true;
}

bool AcmeClient::finalize_order([[maybe_unused]] const std::string& domain) {
    return false; // Stub
}

bool AcmeClient::download_certificate([[maybe_unused]] const std::string& domain) {
    return false; // Stub
}

} // namespace js
