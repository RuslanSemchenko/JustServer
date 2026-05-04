#pragma once

#include "http_parser.hpp"
#include <atomic>
#include <chrono>
#include <string>
#include <mutex>
#include <array>

namespace js {

class Metrics {
public:
    static Metrics& instance();

    // Connection tracking
    void record_connection();
    void record_disconnection();
    void record_request(int status_code, double latency_ms);
    void record_blocked_ip();
    void record_waf_block();
    void record_bytes_sent(size_t bytes);
    void record_bytes_received(size_t bytes);

    // Worker tracking
    void record_worker_busy();
    void record_worker_idle();

    // Generate Prometheus-format metrics
    HttpResponse serve_metrics() const;

    // Get current values
    uint64_t total_requests() const { return total_requests_.load(); }
    uint64_t active_connections() const { return active_connections_.load(); }

private:
    Metrics();

    // Counters
    std::atomic<uint64_t> total_requests_{0};
    std::atomic<uint64_t> total_connections_{0};
    std::atomic<uint64_t> active_connections_{0};
    std::atomic<uint64_t> blocked_ips_{0};
    std::atomic<uint64_t> waf_blocks_{0};
    std::atomic<uint64_t> bytes_sent_{0};
    std::atomic<uint64_t> bytes_received_{0};
    std::atomic<uint64_t> active_workers_{0};

    // Status code buckets
    std::atomic<uint64_t> status_2xx_{0};
    std::atomic<uint64_t> status_3xx_{0};
    std::atomic<uint64_t> status_4xx_{0};
    std::atomic<uint64_t> status_5xx_{0};

    // Latency histogram buckets (ms): 1, 5, 10, 25, 50, 100, 250, 500, 1000, +Inf
    static constexpr size_t LATENCY_BUCKETS = 10;
    static constexpr std::array<double, LATENCY_BUCKETS> bucket_bounds_ = {
        1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 1e18
    };
    std::array<std::atomic<uint64_t>, LATENCY_BUCKETS> latency_buckets_{};
    std::atomic<uint64_t> latency_count_{0};
    std::atomic<double> latency_sum_{0.0};

    std::chrono::steady_clock::time_point start_time_;
};

} // namespace js
