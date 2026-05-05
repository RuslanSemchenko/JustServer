#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <mutex>
#include <atomic>
#include <cstdint>
#include <chrono>
#include <unordered_map>
#include <functional>
#include <optional>
#include <cmath>

namespace js {

// Backend server descriptor
struct Backend {
    std::string address;       // host:port
    std::string host;
    uint16_t port = 0;
    int weight = 1;            // For weighted algorithms
    bool healthy = true;
    std::atomic<int> active_connections{0};

    // EWMA metrics
    std::atomic<double> ewma_latency_ns{0.0};
    std::chrono::steady_clock::time_point last_response_time;
};

// Load balancing algorithms
enum class LBAlgorithm {
    ROUND_ROBIN,
    LEAST_CONNECTIONS,
    EWMA,                // Exponentially Weighted Moving Average
    CONSISTENT_HASH,     // Consistent hashing (session affinity)
    RANDOM,
};

// Base load balancer interface
class LoadBalancer {
public:
    virtual ~LoadBalancer() = default;

    // Select a backend for a request
    // key: used by consistent hashing (IP, cookie, etc.)
    virtual Backend* select(std::string_view key = "") = 0;

    // Notify that a request to a backend completed
    virtual void report_result(Backend* backend, std::chrono::nanoseconds latency, bool success) = 0;

    // Get all backends
    virtual const std::vector<Backend*>& backends() const = 0;

    // Factory
    static std::unique_ptr<LoadBalancer> create(LBAlgorithm algo, std::vector<Backend>& backends);
};

// Round-Robin: simple sequential rotation through backends
class RoundRobinLB : public LoadBalancer {
public:
    explicit RoundRobinLB(std::vector<Backend>& backends);

    Backend* select(std::string_view key = "") override;
    void report_result(Backend* backend, std::chrono::nanoseconds latency, bool success) override;
    const std::vector<Backend*>& backends() const override { return ptrs_; }

private:
    std::vector<Backend*> ptrs_;
    std::atomic<uint64_t> counter_{0};
};

// Least Connections: route to the backend with fewest active connections
class LeastConnectionsLB : public LoadBalancer {
public:
    explicit LeastConnectionsLB(std::vector<Backend>& backends);

    Backend* select(std::string_view key = "") override;
    void report_result(Backend* backend, std::chrono::nanoseconds latency, bool success) override;
    const std::vector<Backend*>& backends() const override { return ptrs_; }

private:
    std::vector<Backend*> ptrs_;
};

// EWMA: route to the backend with the lowest exponentially weighted moving average latency
// The EWMA decays old measurements so the LB always adapts to the "right now" fastest backend.
class EwmaLB : public LoadBalancer {
public:
    explicit EwmaLB(std::vector<Backend>& backends, double decay_ns = 10e9); // 10s decay

    Backend* select(std::string_view key = "") override;
    void report_result(Backend* backend, std::chrono::nanoseconds latency, bool success) override;
    const std::vector<Backend*>& backends() const override { return ptrs_; }

private:
    std::vector<Backend*> ptrs_;
    double decay_ns_;
};

// Consistent Hashing: maps keys to a hash ring for session affinity.
// Used for sticky sessions by IP, cookie, or custom key.
class ConsistentHashLB : public LoadBalancer {
public:
    explicit ConsistentHashLB(std::vector<Backend>& backends, int vnodes_per_backend = 150);

    Backend* select(std::string_view key = "") override;
    void report_result(Backend* backend, std::chrono::nanoseconds latency, bool success) override;
    const std::vector<Backend*>& backends() const override { return ptrs_; }

private:
    // Hash function: xxHash-style for speed
    static uint64_t hash(std::string_view data);

    struct RingNode {
        uint64_t hash;
        Backend* backend;
    };

    std::vector<Backend*> ptrs_;
    std::vector<RingNode> ring_;  // Sorted by hash
};

// Backend health checker (active probes)
class HealthChecker {
public:
    struct Config {
        std::chrono::seconds interval{10};
        std::chrono::seconds timeout{5};
        int unhealthy_threshold = 3;
        int healthy_threshold = 2;
        std::string check_path = "/health";
    };

    HealthChecker(std::vector<Backend>& backends, Config config);

    // Run one round of health checks (call periodically)
    void check_all();

private:
    bool probe_backend(Backend& backend);

    std::vector<Backend*> backends_;
    Config config_;
    std::unordered_map<std::string, int> failure_counts_;
    std::unordered_map<std::string, int> success_counts_;
};

} // namespace js
