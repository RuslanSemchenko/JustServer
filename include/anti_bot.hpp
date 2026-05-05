#pragma once

#include "http_parser.hpp"
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <atomic>
#include <chrono>
#include <optional>
#include <vector>
#include <cstdint>
#include <functional>

// Forward declare SSL types
struct ssl_st;

namespace js {

// === JA3/JA4 TLS Fingerprinting ===
// Passive fingerprinting of TLS ClientHello to detect bots.
// Python requests, Go http, curl all have distinct JA3 hashes
// even when they set "Chrome" User-Agent.
class TlsFingerprinter {
public:
    struct Fingerprint {
        std::string ja3_hash;         // MD5 of JA3 string
        std::string ja3_raw;          // Raw JA3 string (for debugging)
        std::string client_ip;
        std::string user_agent;
        bool is_known_bot = false;    // Matches known bot fingerprint
    };

    // Extract JA3 fingerprint from an SSL connection (call after handshake)
    static Fingerprint extract_ja3(ssl_st* ssl, const std::string& client_ip);

    // Check if a JA3 hash matches known bot/scanner fingerprints
    static bool is_known_bot_fingerprint(std::string_view ja3_hash);

    // Add a JA3 hash to the blocklist
    void block_fingerprint(std::string_view ja3_hash);

    // Check if a fingerprint is blocked
    bool is_blocked(std::string_view ja3_hash) const;

private:
    mutable std::mutex mutex_;
    std::unordered_set<std::string> blocked_fingerprints_;

    // Known bot JA3 hashes (Python requests, Go stdlib, curl, etc.)
    static const std::unordered_set<std::string>& known_bot_hashes();
};

// === Token Bucket Rate Limiter ===
// Adaptive rate limiting by IP, session, subnet, or JA3 fingerprint.
class TokenBucketLimiter {
public:
    struct Config {
        double rate = 10.0;           // Tokens per second
        double burst = 50.0;          // Maximum bucket capacity
        std::chrono::seconds window{60}; // Cleanup window for idle buckets
    };

    TokenBucketLimiter();
    explicit TokenBucketLimiter(Config config);

    // Check if a request is allowed (consumes one token)
    // key: IP, session ID, JA3 hash, or compound key
    bool allow(const std::string& key);

    // Check without consuming
    bool check(const std::string& key) const;

    // Get remaining tokens for a key
    double remaining(const std::string& key) const;

    // Update rate for a specific key (adaptive)
    void set_rate(const std::string& key, double rate, double burst);

    // Cleanup expired buckets
    void cleanup();

    // Stats
    uint64_t total_allowed() const { return total_allowed_.load(); }
    uint64_t total_rejected() const { return total_rejected_.load(); }

private:
    struct Bucket {
        double tokens;
        double rate;
        double burst;
        std::chrono::steady_clock::time_point last_refill;
    };

    void refill(Bucket& bucket) const;

    Config config_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, Bucket> buckets_;
    std::atomic<uint64_t> total_allowed_{0};
    std::atomic<uint64_t> total_rejected_{0};
};

// === JS Challenge ===
// Serves a hidden JavaScript challenge that real browsers execute
// to obtain a session cookie. Blocks 99% of dumb parsers/scrapers.
class JsChallenge {
public:
    struct Config {
        std::string cookie_name = "__js_verify";
        std::chrono::seconds cookie_ttl{3600};      // 1 hour
        std::string challenge_page_title = "Checking your browser...";
    };

    JsChallenge();
    explicit JsChallenge(Config config);

    // Check if a request has a valid challenge cookie
    bool is_verified(const HttpRequest& req, const std::string& client_ip) const;

    // Generate a challenge response (HTML page with JS)
    HttpResponse generate_challenge(const std::string& client_ip) const;

    // Validate a challenge response (cookie value)
    bool validate_response(std::string_view cookie_value, const std::string& client_ip) const;

private:
    // Generate HMAC-based challenge token
    std::string generate_token(const std::string& client_ip,
                                std::chrono::system_clock::time_point ts) const;

    Config config_;
    std::string secret_key_; // Random secret for HMAC
};

// === Proof-of-Work Challenge ===
// Under L7 DDoS suspicion, issues a compute-intensive challenge
// that the client must solve before their request is processed.
class PowChallenge {
public:
    struct Config {
        int difficulty = 18;          // Number of leading zero bits required
        std::chrono::seconds challenge_ttl{300}; // 5 minute challenge validity
    };

    PowChallenge();
    explicit PowChallenge(Config config);

    // Generate a PoW challenge
    struct Challenge {
        std::string nonce;           // Server-generated random nonce
        int difficulty;
        std::string challenge_id;
    };
    Challenge generate_challenge(const std::string& client_ip);

    // Verify a PoW solution (non-const: consumes the challenge to prevent replay)
    bool verify_solution(const std::string& challenge_id,
                          const std::string& solution);

    // Generate the challenge HTML page
    HttpResponse generate_challenge_page(const Challenge& challenge) const;

private:
    Config config_;
    std::string secret_;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, Challenge> active_challenges_;
};

// === Tarpit (Tar Pit / Teergrube) ===
// Sends responses at 1 byte/second to waste scanner resources.
// Ties up their connection pool threads.
class Tarpit {
public:
    struct Config {
        int bytes_per_second = 1;         // Response drip rate
        std::chrono::seconds max_duration{300}; // Max tarpit duration (5 min)
        std::string response_body;        // Fake response to drip-feed
    };

    Tarpit();
    explicit Tarpit(Config config);

    // Generate a tarpit response (the caller drip-feeds it)
    HttpResponse generate_response() const;

    // Drip-feed the response on a socket (blocking, intentionally slow)
    void drip_feed(int fd, const std::string& data) const;

    Config& config() { return config_; }

private:
    Config config_;
};

// === GeoIP Filter ===
// In-memory lookup for IP geolocation (MaxMind GeoLite2 compatible).
// O(1) radix trie lookup for country/ASN blocking.
class GeoIPFilter {
public:
    struct Config {
        std::string database_path;        // Path to GeoLite2 database
        std::vector<std::string> blocked_countries;  // ISO 3166-1 alpha-2 codes
        bool block_tor = false;
        bool block_known_proxies = false;
        bool block_known_vpns = false;
    };

    GeoIPFilter();
    explicit GeoIPFilter(Config config);

    // Lookup country code for an IP address
    std::optional<std::string> lookup_country(std::string_view ip) const;

    // Check if an IP should be blocked
    bool is_blocked(std::string_view ip) const;

    // Load or reload the GeoIP database
    bool load_database();

private:
    Config config_;
    // In-memory IP range -> country code mapping
    // Simplified structure (full implementation would use a radix trie)
    struct IpRange {
        uint32_t start;
        uint32_t end;
        std::string country;
    };
    std::vector<IpRange> ranges_;
    mutable std::mutex mutex_;
};

// === Unified Anti-Bot Engine ===
// Combines all anti-bot features into a single inspection pipeline.
class AntiBotEngine {
public:
    struct Config {
        bool enabled = true;
        bool ja3_enabled = true;
        bool rate_limit_enabled = true;
        bool js_challenge_enabled = false;  // Off by default (breaks APIs)
        bool pow_enabled = false;           // Only under attack
        bool tarpit_enabled = true;
        bool geoip_enabled = false;         // Needs database

        TokenBucketLimiter::Config rate_limit;
        JsChallenge::Config js_challenge;
        PowChallenge::Config pow;
        Tarpit::Config tarpit;
        GeoIPFilter::Config geoip;
    };

    struct Verdict {
        bool allowed = true;
        bool tarpit = false;              // Should tarpit this connection
        bool challenge = false;           // Should send challenge
        std::string reason;
        HttpResponse response;            // Challenge/block response (if not allowed)
    };

    AntiBotEngine();
    explicit AntiBotEngine(Config config);

    // Full anti-bot inspection pipeline
    Verdict inspect(const HttpRequest& req, const std::string& client_ip,
                     ssl_st* ssl = nullptr);

    // Access sub-components for direct use
    TlsFingerprinter& fingerprinter() { return fingerprinter_; }
    TokenBucketLimiter& rate_limiter() { return rate_limiter_; }
    JsChallenge& js_challenge() { return js_challenge_; }
    PowChallenge& pow_challenge() { return pow_challenge_; }
    Tarpit& tarpit() { return tarpit_; }
    GeoIPFilter& geoip() { return geoip_; }

private:
    Config config_;
    TlsFingerprinter fingerprinter_;
    TokenBucketLimiter rate_limiter_;
    JsChallenge js_challenge_;
    PowChallenge pow_challenge_;
    Tarpit tarpit_;
    GeoIPFilter geoip_;
};

} // namespace js
