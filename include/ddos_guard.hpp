#pragma once

#include <string>
#include <string_view>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <cstdint>

namespace js {

class DDoSGuard {
public:
    explicit DDoSGuard(int max_connections_per_ip);

    // Returns true if connection is allowed
    bool allow_connection(std::string_view ip);

    // Call when a connection closes
    void release_connection(std::string_view ip);

    // Periodic cleanup of stale entries
    void cleanup();

    // Update max connections limit (for hot reload)
    void set_max_per_ip(int max);

private:
    struct IpEntry {
        int active_connections = 0;
        std::chrono::steady_clock::time_point last_seen;
    };

    int max_per_ip_;
    std::unordered_map<std::string, IpEntry> connections_;
    std::mutex mutex_;
};

} // namespace js
