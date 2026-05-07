#include "ddos_guard.hpp"
#include "logger.hpp"

#include <algorithm>

namespace js {

DDoSGuard::DDoSGuard(int max_connections_per_ip)
    : max_per_ip_(max_connections_per_ip) {
    config_.max_connections_per_ip = max_connections_per_ip;
}

DDoSGuard::DDoSGuard(Config config)
    : config_(config)
    , max_per_ip_(config.max_connections_per_ip) {}

void DDoSGuard::refill_tokens(IpEntry& entry) const {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration<double>(now - entry.last_refill).count();
    entry.tokens = std::min(entry.burst, entry.tokens + elapsed * entry.rate);
    entry.last_refill = now;
}

bool DDoSGuard::allow_connection(std::string_view ip) {
    // Check global connection limit first
    if (total_connections_.load(std::memory_order_relaxed) >= config_.max_total_connections) {
        LOG_WARN("DDoS guard: global connection limit reached (" +
                 std::to_string(config_.max_total_connections) + ")");
        return false;
    }

    std::lock_guard lock(mutex_);
    auto key = std::string(ip);
    auto& entry = connections_[key];
    entry.last_seen = std::chrono::steady_clock::now();

    if (entry.active_connections >= max_per_ip_) {
        LOG_WARN("DDoS guard: blocked IP " + key +
                 " (active: " + std::to_string(entry.active_connections) + ")");
        return false;
    }

    // Initialize token bucket if new entry
    if (entry.rate == 0.0) {
        entry.tokens = config_.rate_limit_burst;
        entry.rate = config_.rate_limit_rps;
        entry.burst = config_.rate_limit_burst;
        entry.last_refill = std::chrono::steady_clock::now();
    }

    entry.active_connections++;
    total_connections_.fetch_add(1, std::memory_order_relaxed);
    return true;
}

bool DDoSGuard::allow_request(std::string_view ip) {
    std::lock_guard lock(mutex_);
    auto it = connections_.find(std::string(ip));
    if (it == connections_.end()) {
        // No connection entry -- shouldn't happen in normal flow, allow it
        return true;
    }

    auto& entry = it->second;
    refill_tokens(entry);

    if (entry.tokens >= 1.0) {
        entry.tokens -= 1.0;
        return true;
    }

    LOG_WARN("DDoS guard: rate limit exceeded for " + std::string(ip));
    return false;
}

void DDoSGuard::release_connection(std::string_view ip) {
    std::lock_guard lock(mutex_);
    auto it = connections_.find(std::string(ip));
    if (it != connections_.end()) {
        it->second.active_connections--;
        total_connections_.fetch_sub(1, std::memory_order_relaxed);
        if (it->second.active_connections <= 0) {
            connections_.erase(it);
        }
    }
}

void DDoSGuard::set_max_per_ip(int max) {
    std::lock_guard lock(mutex_);
    max_per_ip_ = max;
    config_.max_connections_per_ip = max;
}

void DDoSGuard::cleanup() {
    std::lock_guard lock(mutex_);
    auto now = std::chrono::steady_clock::now();
    auto threshold = std::chrono::minutes(5);

    for (auto it = connections_.begin(); it != connections_.end();) {
        if (it->second.active_connections <= 0 &&
            (now - it->second.last_seen) > threshold) {
            it = connections_.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace js
