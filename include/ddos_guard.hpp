#pragma once

#include <string>
#include <string_view>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <cstdint>
#include <atomic>

namespace js {

class DDoSGuard {
public:
    struct Config {
        int max_connections_per_ip = 50;
        int max_total_connections = 10000;
        double rate_limit_rps = 10.0;   // Requests per second per IP
        double rate_limit_burst = 50.0; // Burst capacity
    };

    explicit DDoSGuard(int max_connections_per_ip);
    explicit DDoSGuard(Config config);

    // Returns true if connection is allowed (checks per-IP and global limits)
    bool allow_connection(std::string_view ip);

    // Returns true if request is allowed by rate limiter (token bucket)
    bool allow_request(std::string_view ip);

    // Call when a connection closes
    void release_connection(std::string_view ip);

    // Periodic cleanup of stale entries
    void cleanup();

    // Update max connections limit (for hot reload)
    void set_max_per_ip(int max);

    // Current total connections
    int total_connections() const { return total_connections_.load(std::memory_order_relaxed); }

private:
    struct IpEntry {
        int active_connections = 0;
        std::chrono::steady_clock::time_point last_seen;
        // Token bucket for rate limiting
        double tokens = 0.0;
        double rate = 0.0;
        double burst = 0.0;
        std::chrono::steady_clock::time_point last_refill;
    };

    void refill_tokens(IpEntry& entry) const;

    Config config_;
    int max_per_ip_; // kept for backward compat with set_max_per_ip()
    std::unordered_map<std::string, IpEntry> connections_;
    std::mutex mutex_;
    std::atomic<int> total_connections_{0};
};

} // namespace js
