#pragma once

#include "http_parser.hpp"
#include <string>
#include <string_view>
#include <unordered_map>
#include <list>
#include <mutex>
#include <chrono>
#include <optional>
#include <atomic>
#include <functional>

namespace js {

// LRU/LFU hybrid cache with stale-while-revalidate support.
// Used for in-memory microcaching of static files and API responses.
class HttpCache {
public:
    struct CacheEntry {
        std::string key;
        HttpResponse response;
        std::chrono::steady_clock::time_point created;
        std::chrono::steady_clock::time_point expires;
        std::chrono::steady_clock::time_point stale_expires; // stale-while-revalidate window
        uint64_t access_count = 0;
        bool revalidating = false; // Currently being revalidated in background
    };

    struct Config {
        size_t max_entries = 10000;
        size_t max_memory_bytes = 256 * 1024 * 1024; // 256 MB
        std::chrono::seconds default_ttl{60};
        std::chrono::seconds stale_while_revalidate{30}; // Serve stale for 30s while refreshing
        bool enabled = true;
    };

    struct Stats {
        std::atomic<uint64_t> hits{0};
        std::atomic<uint64_t> misses{0};
        std::atomic<uint64_t> stale_hits{0};
        std::atomic<uint64_t> evictions{0};
        std::atomic<uint64_t> current_entries{0};
        std::atomic<uint64_t> current_bytes{0};
    };

    HttpCache();
    explicit HttpCache(Config config);

    // Lookup a cached response by cache key (method + url + vary headers)
    std::optional<HttpResponse> get(const std::string& key);

    // Store a response in the cache
    void put(const std::string& key, const HttpResponse& response,
             std::chrono::seconds ttl = std::chrono::seconds{0});

    // Remove a specific entry
    void invalidate(const std::string& key);

    // Clear all entries
    void clear();

    // Build a cache key from an HTTP request
    static std::string build_key(const HttpRequest& req);

    // Check if a response is cacheable based on headers
    static bool is_cacheable(const HttpRequest& req, const HttpResponse& resp);

    // Parse Cache-Control header for max-age, stale-while-revalidate, etc.
    struct CacheControl {
        int max_age = -1;
        int s_maxage = -1;
        int stale_while_revalidate = -1;
        bool no_cache = false;
        bool no_store = false;
        bool private_ = false;
        bool must_revalidate = false;
    };
    static CacheControl parse_cache_control(std::string_view header);

    // Stats
    const Stats& stats() const { return stats_; }
    double hit_rate() const;

    // Set revalidation callback (called when serving stale content)
    using RevalidateCallback = std::function<void(const std::string& key)>;
    void set_revalidate_callback(RevalidateCallback cb) { revalidate_cb_ = std::move(cb); }

private:
    // Evict entries to make room (LRU eviction)
    void evict_lru();

    // Estimate memory usage of an entry
    static size_t entry_size(const CacheEntry& entry);

    Config config_;
    Stats stats_;

    // LRU list (most recently used at front)
    std::list<CacheEntry> lru_list_;
    // Map from key to LRU list iterator
    std::unordered_map<std::string, std::list<CacheEntry>::iterator> index_;

    mutable std::mutex mutex_;
    size_t current_memory_ = 0;

    RevalidateCallback revalidate_cb_;
};

} // namespace js
