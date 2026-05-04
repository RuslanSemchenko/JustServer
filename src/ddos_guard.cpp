#include "ddos_guard.hpp"
#include "logger.hpp"

namespace js {

DDoSGuard::DDoSGuard(int max_connections_per_ip)
    : max_per_ip_(max_connections_per_ip) {}

bool DDoSGuard::allow_connection(std::string_view ip) {
    std::lock_guard lock(mutex_);
    auto key = std::string(ip);
    auto& entry = connections_[key];
    entry.last_seen = std::chrono::steady_clock::now();

    if (entry.active_connections >= max_per_ip_) {
        LOG_WARN("DDoS guard: blocked IP " + key +
                 " (active: " + std::to_string(entry.active_connections) + ")");
        return false;
    }

    entry.active_connections++;
    return true;
}

void DDoSGuard::release_connection(std::string_view ip) {
    std::lock_guard lock(mutex_);
    auto it = connections_.find(std::string(ip));
    if (it != connections_.end()) {
        it->second.active_connections--;
        if (it->second.active_connections <= 0) {
            connections_.erase(it);
        }
    }
}

void DDoSGuard::set_max_per_ip(int max) {
    std::lock_guard lock(mutex_);
    max_per_ip_ = max;
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
