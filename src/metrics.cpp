#include "metrics.hpp"
#include <sstream>
#include <iomanip>

namespace js {

Metrics::Metrics()
    : start_time_(std::chrono::steady_clock::now()) {
    for (auto& b : latency_buckets_) {
        b.store(0);
    }
}

Metrics& Metrics::instance() {
    static Metrics m;
    return m;
}

void Metrics::record_connection() {
    total_connections_.fetch_add(1, std::memory_order_relaxed);
    active_connections_.fetch_add(1, std::memory_order_relaxed);
}

void Metrics::record_disconnection() {
    active_connections_.fetch_sub(1, std::memory_order_relaxed);
}

void Metrics::record_request(int status_code, double latency_ms) {
    total_requests_.fetch_add(1, std::memory_order_relaxed);

    if (status_code >= 200 && status_code < 300) status_2xx_.fetch_add(1, std::memory_order_relaxed);
    else if (status_code >= 300 && status_code < 400) status_3xx_.fetch_add(1, std::memory_order_relaxed);
    else if (status_code >= 400 && status_code < 500) status_4xx_.fetch_add(1, std::memory_order_relaxed);
    else if (status_code >= 500) status_5xx_.fetch_add(1, std::memory_order_relaxed);

    // Latency histogram
    for (size_t i = 0; i < LATENCY_BUCKETS; ++i) {
        if (latency_ms <= bucket_bounds_[i]) {
            latency_buckets_[i].fetch_add(1, std::memory_order_relaxed);
        }
    }
    latency_count_.fetch_add(1, std::memory_order_relaxed);

    // Atomic double add via CAS loop
    double old_sum = latency_sum_.load(std::memory_order_relaxed);
    while (!latency_sum_.compare_exchange_weak(old_sum, old_sum + latency_ms,
                                                std::memory_order_relaxed)) {}
}

void Metrics::record_blocked_ip() {
    blocked_ips_.fetch_add(1, std::memory_order_relaxed);
}

void Metrics::record_waf_block() {
    waf_blocks_.fetch_add(1, std::memory_order_relaxed);
}

void Metrics::record_bytes_sent(size_t bytes) {
    bytes_sent_.fetch_add(bytes, std::memory_order_relaxed);
}

void Metrics::record_bytes_received(size_t bytes) {
    bytes_received_.fetch_add(bytes, std::memory_order_relaxed);
}

void Metrics::record_worker_busy() {
    active_workers_.fetch_add(1, std::memory_order_relaxed);
}

void Metrics::record_worker_idle() {
    active_workers_.fetch_sub(1, std::memory_order_relaxed);
}

HttpResponse Metrics::serve_metrics() const {
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - start_time_).count();

    std::ostringstream out;

    // Server info
    out << "# HELP justserver_info Server information\n";
    out << "# TYPE justserver_info gauge\n";
    out << "justserver_info{version=\"1.0\"} 1\n\n";

    // Uptime
    out << "# HELP justserver_uptime_seconds Server uptime in seconds\n";
    out << "# TYPE justserver_uptime_seconds counter\n";
    out << "justserver_uptime_seconds " << uptime << "\n\n";

    // Connections
    out << "# HELP justserver_connections_total Total connections accepted\n";
    out << "# TYPE justserver_connections_total counter\n";
    out << "justserver_connections_total " << total_connections_.load() << "\n\n";

    out << "# HELP justserver_connections_active Current active connections\n";
    out << "# TYPE justserver_connections_active gauge\n";
    out << "justserver_connections_active " << active_connections_.load() << "\n\n";

    // Requests
    out << "# HELP justserver_requests_total Total HTTP requests processed\n";
    out << "# TYPE justserver_requests_total counter\n";
    out << "justserver_requests_total " << total_requests_.load() << "\n\n";

    // Status codes
    out << "# HELP justserver_responses_total Total responses by status class\n";
    out << "# TYPE justserver_responses_total counter\n";
    out << "justserver_responses_total{code=\"2xx\"} " << status_2xx_.load() << "\n";
    out << "justserver_responses_total{code=\"3xx\"} " << status_3xx_.load() << "\n";
    out << "justserver_responses_total{code=\"4xx\"} " << status_4xx_.load() << "\n";
    out << "justserver_responses_total{code=\"5xx\"} " << status_5xx_.load() << "\n\n";

    // Security
    out << "# HELP justserver_blocked_ips_total IPs blocked by DDoS guard\n";
    out << "# TYPE justserver_blocked_ips_total counter\n";
    out << "justserver_blocked_ips_total " << blocked_ips_.load() << "\n\n";

    out << "# HELP justserver_waf_blocks_total Requests blocked by WAF\n";
    out << "# TYPE justserver_waf_blocks_total counter\n";
    out << "justserver_waf_blocks_total " << waf_blocks_.load() << "\n\n";

    // Bytes
    out << "# HELP justserver_bytes_sent_total Total bytes sent\n";
    out << "# TYPE justserver_bytes_sent_total counter\n";
    out << "justserver_bytes_sent_total " << bytes_sent_.load() << "\n\n";

    out << "# HELP justserver_bytes_received_total Total bytes received\n";
    out << "# TYPE justserver_bytes_received_total counter\n";
    out << "justserver_bytes_received_total " << bytes_received_.load() << "\n\n";

    // Workers
    out << "# HELP justserver_workers_active Currently busy workers\n";
    out << "# TYPE justserver_workers_active gauge\n";
    out << "justserver_workers_active " << active_workers_.load() << "\n\n";

    // Latency histogram
    out << "# HELP justserver_request_duration_ms Request latency in milliseconds\n";
    out << "# TYPE justserver_request_duration_ms histogram\n";

    static const char* bucket_labels[] = {
        "1", "5", "10", "25", "50", "100", "250", "500", "1000", "+Inf"
    };
    uint64_t cumulative = 0;
    for (size_t i = 0; i < LATENCY_BUCKETS; ++i) {
        cumulative += latency_buckets_[i].load();
        out << "justserver_request_duration_ms_bucket{le=\"" << bucket_labels[i] << "\"} "
            << cumulative << "\n";
    }
    out << "justserver_request_duration_ms_sum " << std::fixed << std::setprecision(2)
        << latency_sum_.load() << "\n";
    out << "justserver_request_duration_ms_count " << latency_count_.load() << "\n";

    HttpResponse resp;
    resp.status_code = 200;
    resp.status_text = "OK";
    resp.headers["Content-Type"] = "text/plain; version=0.0.4; charset=utf-8";
    resp.headers["Connection"] = "close";
    resp.body = out.str();
    return resp;
}

} // namespace js
