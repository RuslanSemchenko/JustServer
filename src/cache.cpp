#include "cache.hpp"
#include "logger.hpp"

#include <algorithm>
#include <sstream>

namespace js {

HttpCache::HttpCache() : config_{} {}

HttpCache::HttpCache(Config config) : config_(std::move(config)) {}

std::optional<HttpResponse> HttpCache::get(const std::string& key) {
    if (!config_.enabled) {
        stats_.misses.fetch_add(1, std::memory_order_relaxed);
        return std::nullopt;
    }

    std::lock_guard lock(mutex_);

    auto it = index_.find(key);
    if (it == index_.end()) {
        stats_.misses.fetch_add(1, std::memory_order_relaxed);
        return std::nullopt;
    }

    auto& entry = *it->second;
    auto now = std::chrono::steady_clock::now();

    // Check if still fresh
    if (now < entry.expires) {
        // Move to front of LRU
        lru_list_.splice(lru_list_.begin(), lru_list_, it->second);
        ++entry.access_count;
        stats_.hits.fetch_add(1, std::memory_order_relaxed);
        return entry.response;
    }

    // Check stale-while-revalidate window
    if (now < entry.stale_expires) {
        // Serve stale content, trigger revalidation in background
        lru_list_.splice(lru_list_.begin(), lru_list_, it->second);
        ++entry.access_count;
        stats_.stale_hits.fetch_add(1, std::memory_order_relaxed);

        if (!entry.revalidating && revalidate_cb_) {
            entry.revalidating = true;
            // Fire-and-forget revalidation
            revalidate_cb_(key);
        }

        return entry.response;
    }

    // Entry is fully expired -- remove it
    current_memory_ -= entry_size(entry);
    lru_list_.erase(it->second);
    index_.erase(it);
    stats_.evictions.fetch_add(1, std::memory_order_relaxed);
    stats_.current_entries.store(index_.size(), std::memory_order_relaxed);
    stats_.current_bytes.store(current_memory_, std::memory_order_relaxed);
    stats_.misses.fetch_add(1, std::memory_order_relaxed);

    return std::nullopt;
}

void HttpCache::put(const std::string& key, const HttpResponse& response,
                     std::chrono::seconds ttl) {
    if (!config_.enabled) return;

    // Parse Cache-Control to determine TTL
    auto cc_it = response.headers.find("Cache-Control");
    if (cc_it != response.headers.end()) {
        auto cc = parse_cache_control(cc_it->second);
        if (cc.no_store) return; // Don't cache
        if (cc.s_maxage >= 0) ttl = std::chrono::seconds(cc.s_maxage);
        else if (cc.max_age >= 0) ttl = std::chrono::seconds(cc.max_age);
    }

    if (ttl.count() == 0) ttl = config_.default_ttl;

    auto now = std::chrono::steady_clock::now();

    CacheEntry entry;
    entry.key = key;
    entry.response = response;
    entry.created = now;
    entry.expires = now + ttl;
    entry.stale_expires = entry.expires + config_.stale_while_revalidate;

    std::lock_guard lock(mutex_);

    // Remove existing entry if present
    auto existing = index_.find(key);
    if (existing != index_.end()) {
        current_memory_ -= entry_size(*existing->second);
        lru_list_.erase(existing->second);
        index_.erase(existing);
    }

    size_t new_size = entry_size(entry);

    // Evict if needed
    while ((index_.size() >= config_.max_entries ||
            current_memory_ + new_size > config_.max_memory_bytes) &&
           !lru_list_.empty()) {
        evict_lru();
    }

    // Insert at front (most recently used)
    lru_list_.push_front(std::move(entry));
    index_[key] = lru_list_.begin();
    current_memory_ += new_size;

    stats_.current_entries.store(index_.size(), std::memory_order_relaxed);
    stats_.current_bytes.store(current_memory_, std::memory_order_relaxed);
}

void HttpCache::invalidate(const std::string& key) {
    std::lock_guard lock(mutex_);
    auto it = index_.find(key);
    if (it != index_.end()) {
        current_memory_ -= entry_size(*it->second);
        lru_list_.erase(it->second);
        index_.erase(it);
        stats_.current_entries.store(index_.size(), std::memory_order_relaxed);
        stats_.current_bytes.store(current_memory_, std::memory_order_relaxed);
    }
}

void HttpCache::clear() {
    std::lock_guard lock(mutex_);
    lru_list_.clear();
    index_.clear();
    current_memory_ = 0;
    stats_.current_entries.store(0, std::memory_order_relaxed);
    stats_.current_bytes.store(0, std::memory_order_relaxed);
}

std::string HttpCache::build_key(const HttpRequest& req) {
    // Key: METHOD:scheme:host:path?query
    std::string key = req.method_str + ":" + req.uri;

    // Include Vary headers if present
    auto host = req.get_header("Host");
    if (!host.empty()) {
        key += "|h:" + std::string(host);
    }
    auto accept_enc = req.get_header("Accept-Encoding");
    if (!accept_enc.empty()) {
        key += "|ae:" + std::string(accept_enc);
    }

    return key;
}

bool HttpCache::is_cacheable(const HttpRequest& req, const HttpResponse& resp) {
    // Only cache GET and HEAD
    if (req.method != HttpMethod::GET && req.method != HttpMethod::HEAD) return false;

    // Don't cache error responses (except 301, 404)
    if (resp.status_code >= 400 && resp.status_code != 404) return false;
    if (resp.status_code >= 500) return false;

    // Check Cache-Control
    auto cc_it = resp.headers.find("Cache-Control");
    if (cc_it != resp.headers.end()) {
        auto cc = parse_cache_control(cc_it->second);
        if (cc.no_store || cc.private_) return false;
    }

    return true;
}

HttpCache::CacheControl HttpCache::parse_cache_control(std::string_view header) {
    CacheControl cc;

    size_t pos = 0;
    while (pos < header.size()) {
        while (pos < header.size() && (header[pos] == ' ' || header[pos] == ',')) ++pos;
        if (pos >= header.size()) break;

        auto end = header.find(',', pos);
        auto directive = header.substr(pos, end == std::string_view::npos ? end : end - pos);
        pos = (end == std::string_view::npos) ? header.size() : end + 1;

        // Trim
        while (!directive.empty() && directive.back() == ' ') directive.remove_suffix(1);
        while (!directive.empty() && directive.front() == ' ') directive.remove_prefix(1);

        auto eq = directive.find('=');
        auto name = directive.substr(0, eq);
        while (!name.empty() && name.back() == ' ') name.remove_suffix(1);

        if (name == "no-cache") cc.no_cache = true;
        else if (name == "no-store") cc.no_store = true;
        else if (name == "private") cc.private_ = true;
        else if (name == "must-revalidate") cc.must_revalidate = true;
        else if (eq != std::string_view::npos) {
            auto val = directive.substr(eq + 1);
            while (!val.empty() && val.front() == ' ') val.remove_prefix(1);
            int num = 0;
            for (char c : val) {
                if (c >= '0' && c <= '9') num = num * 10 + (c - '0');
                else break;
            }
            if (name == "max-age") cc.max_age = num;
            else if (name == "s-maxage") cc.s_maxage = num;
            else if (name == "stale-while-revalidate") cc.stale_while_revalidate = num;
        }
    }

    return cc;
}

double HttpCache::hit_rate() const {
    auto hits = stats_.hits.load() + stats_.stale_hits.load();
    auto total = hits + stats_.misses.load();
    if (total == 0) return 0.0;
    return static_cast<double>(hits) / static_cast<double>(total);
}

void HttpCache::evict_lru() {
    if (lru_list_.empty()) return;

    // Evict from back (least recently used)
    auto& victim = lru_list_.back();
    current_memory_ -= entry_size(victim);
    index_.erase(victim.key);
    lru_list_.pop_back();
    stats_.evictions.fetch_add(1, std::memory_order_relaxed);
}

size_t HttpCache::entry_size(const CacheEntry& entry) {
    return sizeof(CacheEntry) +
           entry.key.capacity() +
           entry.response.body.capacity() +
           entry.response.status_text.capacity();
}

} // namespace js
