#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <functional>
#include <chrono>
#include <mutex>

namespace js {

// ACME (Automatic Certificate Management Environment) client
// Automatically obtains and renews TLS certificates from Let's Encrypt.
// Users just configure domain names -- JustServer handles the rest.
class AcmeClient {
public:
    struct CertInfo {
        std::string cert_pem;       // Full certificate chain (PEM)
        std::string key_pem;        // Private key (PEM)
        std::string domain;
        std::chrono::system_clock::time_point not_after;  // Expiry
        bool valid = false;
    };

    struct Config {
        std::string directory_url = "https://acme-v02.api.letsencrypt.org/directory";
        std::string email;                    // Contact email for ACME account
        std::vector<std::string> domains;     // Domains to obtain certs for
        std::string storage_path = "/etc/justserver/acme"; // Where to store certs/keys
        int renew_before_days = 30;           // Renew this many days before expiry
        bool use_staging = false;             // Use Let's Encrypt staging for testing
    };

    explicit AcmeClient(Config config);
    ~AcmeClient();

    // Non-copyable
    AcmeClient(const AcmeClient&) = delete;
    AcmeClient& operator=(const AcmeClient&) = delete;

    // Initialize: create/load ACME account, check existing certs
    bool initialize();

    // Obtain certificates for all configured domains
    // Returns true if all certs are valid (either existing or newly obtained)
    bool obtain_certificates();

    // Check if any certificates need renewal and renew them
    bool check_and_renew();

    // Get the certificate for a specific domain
    std::optional<CertInfo> get_certificate(std::string_view domain) const;

    // HTTP-01 challenge handler: returns the response for /.well-known/acme-challenge/<token>
    // This should be called from the HTTP request router
    std::optional<std::string> handle_challenge(std::string_view token) const;

    // Set callback for when certificates are updated (for hot-reloading TLS context)
    using CertUpdatedCallback = std::function<void(const std::string& domain, const CertInfo& cert)>;
    void set_cert_updated_callback(CertUpdatedCallback cb) { cert_updated_cb_ = std::move(cb); }

private:
    // ACME protocol steps
    bool register_account();
    bool create_order(const std::string& domain);
    bool solve_http01_challenge(const std::string& domain, const std::string& token,
                                 const std::string& key_authorization);
    bool finalize_order(const std::string& domain);
    bool download_certificate(const std::string& domain);

    // Crypto helpers
    static std::string generate_ec_key();    // Generate EC P-256 private key
    static std::string create_csr(const std::string& domain, const std::string& key_pem);
    static std::string base64url_encode(std::string_view data);
    static std::string create_jws(const std::string& payload, const std::string& url,
                                   const std::string& account_key, const std::string& kid,
                                   const std::string& nonce);

    // HTTP helpers
    static std::optional<std::string> http_get(const std::string& url);
    static std::optional<std::string> http_post(const std::string& url,
                                                  const std::string& body,
                                                  const std::string& content_type);

    // Storage helpers
    bool save_cert(const std::string& domain, const CertInfo& cert);
    std::optional<CertInfo> load_cert(const std::string& domain) const;
    bool save_account_key(const std::string& key_pem);
    std::optional<std::string> load_account_key() const;

    Config config_;
    std::string account_key_pem_;
    std::string account_kid_;   // ACME account key ID (URL)

    // Active challenges for HTTP-01 validation
    mutable std::mutex challenges_mutex_;
    std::unordered_map<std::string, std::string> active_challenges_; // token -> key_authorization

    // Cached certificates
    mutable std::mutex certs_mutex_;
    std::unordered_map<std::string, CertInfo> certificates_;

    CertUpdatedCallback cert_updated_cb_;
};

} // namespace js
