#include "load_balancer.hpp"
#include "logger.hpp"

#include <algorithm>
#include <limits>
#include <cstring>
#include <random>
#include <numeric>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

namespace js {

// === Factory ===

std::unique_ptr<LoadBalancer> LoadBalancer::create(LBAlgorithm algo, std::vector<Backend>& backends) {
    switch (algo) {
        case LBAlgorithm::ROUND_ROBIN:
            return std::make_unique<RoundRobinLB>(backends);
        case LBAlgorithm::LEAST_CONNECTIONS:
            return std::make_unique<LeastConnectionsLB>(backends);
        case LBAlgorithm::EWMA:
            return std::make_unique<EwmaLB>(backends);
        case LBAlgorithm::CONSISTENT_HASH:
            return std::make_unique<ConsistentHashLB>(backends);
        default:
            return std::make_unique<RoundRobinLB>(backends);
    }
}

// === Round-Robin ===

RoundRobinLB::RoundRobinLB(std::vector<Backend>& backends) {
    ptrs_.reserve(backends.size());
    for (auto& b : backends) ptrs_.push_back(&b);
}

Backend* RoundRobinLB::select([[maybe_unused]] std::string_view key) {
    if (ptrs_.empty()) return nullptr;

    // Find next healthy backend
    size_t n = ptrs_.size();
    for (size_t i = 0; i < n; ++i) {
        auto idx = counter_.fetch_add(1, std::memory_order_relaxed) % n;
        if (ptrs_[idx]->healthy) {
            ptrs_[idx]->active_connections.fetch_add(1, std::memory_order_relaxed);
            return ptrs_[idx];
        }
    }
    return nullptr; // All backends down
}

void RoundRobinLB::report_result(Backend* backend,
                                  [[maybe_unused]] std::chrono::nanoseconds latency,
                                  [[maybe_unused]] bool success) {
    if (backend) {
        backend->active_connections.fetch_sub(1, std::memory_order_relaxed);
    }
}

// === Least Connections ===

LeastConnectionsLB::LeastConnectionsLB(std::vector<Backend>& backends) {
    ptrs_.reserve(backends.size());
    for (auto& b : backends) ptrs_.push_back(&b);
}

Backend* LeastConnectionsLB::select([[maybe_unused]] std::string_view key) {
    Backend* best = nullptr;
    int min_conns = std::numeric_limits<int>::max();

    for (auto* b : ptrs_) {
        if (!b->healthy) continue;
        int conns = b->active_connections.load(std::memory_order_relaxed);
        if (conns < min_conns) {
            min_conns = conns;
            best = b;
        }
    }

    if (best) {
        best->active_connections.fetch_add(1, std::memory_order_relaxed);
    }
    return best;
}

void LeastConnectionsLB::report_result(Backend* backend,
                                        [[maybe_unused]] std::chrono::nanoseconds latency,
                                        [[maybe_unused]] bool success) {
    if (backend) {
        backend->active_connections.fetch_sub(1, std::memory_order_relaxed);
    }
}

// === EWMA (Exponentially Weighted Moving Average) ===

EwmaLB::EwmaLB(std::vector<Backend>& backends, double decay_ns) : decay_ns_(decay_ns) {
    ptrs_.reserve(backends.size());
    for (auto& b : backends) ptrs_.push_back(&b);
}

Backend* EwmaLB::select([[maybe_unused]] std::string_view key) {
    Backend* best = nullptr;
    double best_score = std::numeric_limits<double>::max();
    auto now = std::chrono::steady_clock::now();

    for (auto* b : ptrs_) {
        if (!b->healthy) continue;

        double latency = b->ewma_latency_ns.load(std::memory_order_relaxed);

        // Apply time decay: older measurements fade
        auto elapsed = std::chrono::duration<double, std::nano>(now - b->last_response_time).count();
        double decay_factor = std::exp(-elapsed / decay_ns_);
        double score = latency * decay_factor;

        // Factor in active connections (penalize busy backends)
        int conns = b->active_connections.load(std::memory_order_relaxed);
        score *= (1.0 + static_cast<double>(conns) * 0.1);

        if (score < best_score) {
            best_score = score;
            best = b;
        }
    }

    if (best) {
        best->active_connections.fetch_add(1, std::memory_order_relaxed);
    }
    return best;
}

void EwmaLB::report_result(Backend* backend, std::chrono::nanoseconds latency, bool success) {
    if (!backend) return;

    backend->active_connections.fetch_sub(1, std::memory_order_relaxed);
    backend->last_response_time = std::chrono::steady_clock::now();

    if (!success) {
        // Penalize failed requests heavily
        backend->ewma_latency_ns.store(1e9, std::memory_order_relaxed); // 1 second penalty
        return;
    }

    // EWMA update: new_avg = alpha * sample + (1 - alpha) * old_avg
    constexpr double alpha = 0.4; // Responsiveness factor (higher = more responsive)
    double sample = static_cast<double>(latency.count());
    double old_val = backend->ewma_latency_ns.load(std::memory_order_relaxed);
    double new_val = alpha * sample + (1.0 - alpha) * old_val;
    backend->ewma_latency_ns.store(new_val, std::memory_order_relaxed);
}

// === Consistent Hashing ===

ConsistentHashLB::ConsistentHashLB(std::vector<Backend>& backends, int vnodes_per_backend) {
    ptrs_.reserve(backends.size());
    for (auto& b : backends) ptrs_.push_back(&b);

    // Build the hash ring with virtual nodes
    ring_.reserve(backends.size() * static_cast<size_t>(vnodes_per_backend));
    for (auto* b : ptrs_) {
        for (int i = 0; i < vnodes_per_backend; ++i) {
            std::string vnode_key = b->address + "#" + std::to_string(i);
            ring_.push_back({hash(vnode_key), b});
        }
    }

    // Sort ring by hash
    std::sort(ring_.begin(), ring_.end(), [](const RingNode& a, const RingNode& b) {
        return a.hash < b.hash;
    });

    LOG_INFO("Consistent hash ring built: " + std::to_string(ring_.size()) +
             " vnodes for " + std::to_string(backends.size()) + " backends");
}

Backend* ConsistentHashLB::select(std::string_view key) {
    if (ring_.empty()) return nullptr;

    // Hash the key and find the next node on the ring
    uint64_t h = hash(key);

    // Binary search for the first ring node >= h
    auto it = std::lower_bound(ring_.begin(), ring_.end(), h,
        [](const RingNode& node, uint64_t val) { return node.hash < val; });

    // Wrap around
    if (it == ring_.end()) it = ring_.begin();

    // Find a healthy backend starting from this position
    auto start = it;
    do {
        if (it->backend->healthy) {
            it->backend->active_connections.fetch_add(1, std::memory_order_relaxed);
            return it->backend;
        }
        ++it;
        if (it == ring_.end()) it = ring_.begin();
    } while (it != start);

    return nullptr; // All backends down
}

void ConsistentHashLB::report_result(Backend* backend,
                                      [[maybe_unused]] std::chrono::nanoseconds latency,
                                      [[maybe_unused]] bool success) {
    if (backend) {
        backend->active_connections.fetch_sub(1, std::memory_order_relaxed);
    }
}

uint64_t ConsistentHashLB::hash(std::string_view data) {
    // FNV-1a 64-bit hash (fast, good distribution)
    uint64_t h = 14695981039346656037ULL;
    for (char c : data) {
        h ^= static_cast<uint64_t>(static_cast<uint8_t>(c));
        h *= 1099511628211ULL;
    }
    return h;
}

// === Health Checker ===

HealthChecker::HealthChecker(std::vector<Backend>& backends, Config config)
    : config_(std::move(config)) {
    for (auto& b : backends) backends_.push_back(&b);
}

void HealthChecker::check_all() {
    for (auto* backend : backends_) {
        bool ok = probe_backend(*backend);

        if (ok) {
            failure_counts_[backend->address] = 0;
            int& sc = success_counts_[backend->address];
            ++sc;
            if (!backend->healthy && sc >= config_.healthy_threshold) {
                backend->healthy = true;
                LOG_INFO("Backend " + backend->address + " is now HEALTHY");
            }
        } else {
            success_counts_[backend->address] = 0;
            int& fc = failure_counts_[backend->address];
            ++fc;
            if (backend->healthy && fc >= config_.unhealthy_threshold) {
                backend->healthy = false;
                LOG_WARN("Backend " + backend->address + " is now UNHEALTHY");
            }
        }
    }
}

bool HealthChecker::probe_backend(Backend& backend) {
    // TCP connect probe with timeout
    int sockfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (sockfd < 0) return false;

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(backend.port);
    inet_pton(AF_INET, backend.host.c_str(), &addr.sin_addr);

    int ret = connect(sockfd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
    if (ret < 0 && errno != EINPROGRESS) {
        close(sockfd);
        return false;
    }

    // Wait for connection with timeout
    struct pollfd pfd{};
    pfd.fd = sockfd;
    pfd.events = POLLOUT;
    int timeout_ms = static_cast<int>(config_.timeout.count() * 1000);
    ret = poll(&pfd, 1, timeout_ms);

    bool connected = (ret > 0 && (pfd.revents & POLLOUT));

    if (connected) {
        // Send a minimal HTTP health check request
        std::string req = "GET " + config_.check_path + " HTTP/1.1\r\nHost: " +
                         backend.host + "\r\nConnection: close\r\n\r\n";
        auto sent = send(sockfd, req.data(), req.size(), MSG_NOSIGNAL);
        if (sent > 0) {
            char buf[256];
            struct pollfd rpfd{};
            rpfd.fd = sockfd;
            rpfd.events = POLLIN;
            if (poll(&rpfd, 1, timeout_ms) > 0) {
                auto n = recv(sockfd, buf, sizeof(buf) - 1, 0);
                if (n > 0) {
                    buf[n] = '\0';
                    // Check for 2xx status code
                    std::string_view response(buf, static_cast<size_t>(n));
                    auto space = response.find(' ');
                    if (space != std::string_view::npos) {
                        auto code = response.substr(space + 1, 3);
                        connected = (code[0] == '2'); // 2xx = healthy
                    }
                }
            }
        }
    }

    close(sockfd);
    return connected;
}

} // namespace js
