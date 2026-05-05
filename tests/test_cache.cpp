#include "cache.hpp"
#include <cassert>
#include <iostream>
#include <thread>

namespace {

void test_cache_put_get() {
    js::HttpCache cache;

    js::HttpResponse resp;
    resp.status_code = 200;
    resp.body = "Hello, cached world!";
    resp.headers["Content-Type"] = "text/plain";

    cache.put("GET:/test", resp);

    auto cached = cache.get("GET:/test");
    assert(cached.has_value());
    assert(cached->status_code == 200);
    assert(cached->body == "Hello, cached world!");

    std::cout << "  [PASS] cache_put_get\n";
}

void test_cache_miss() {
    js::HttpCache cache;
    auto result = cache.get("nonexistent");
    assert(!result.has_value());
    std::cout << "  [PASS] cache_miss\n";
}

void test_cache_invalidate() {
    js::HttpCache cache;

    js::HttpResponse resp;
    resp.status_code = 200;
    resp.body = "data";

    cache.put("key1", resp);
    assert(cache.get("key1").has_value());

    cache.invalidate("key1");
    assert(!cache.get("key1").has_value());

    std::cout << "  [PASS] cache_invalidate\n";
}

void test_cache_eviction() {
    js::HttpCache::Config config;
    config.max_entries = 3;
    js::HttpCache cache(config);

    js::HttpResponse resp;
    resp.status_code = 200;

    cache.put("k1", resp);
    cache.put("k2", resp);
    cache.put("k3", resp);
    cache.put("k4", resp); // Should evict k1

    assert(!cache.get("k1").has_value()); // Evicted
    assert(cache.get("k2").has_value());
    assert(cache.get("k3").has_value());
    assert(cache.get("k4").has_value());

    std::cout << "  [PASS] cache_eviction\n";
}

void test_cache_control_parsing() {
    auto cc = js::HttpCache::parse_cache_control("max-age=300, stale-while-revalidate=60, public");
    assert(cc.max_age == 300);
    assert(cc.stale_while_revalidate == 60);
    assert(!cc.no_cache);
    assert(!cc.no_store);

    auto cc2 = js::HttpCache::parse_cache_control("no-store, no-cache");
    assert(cc2.no_store);
    assert(cc2.no_cache);

    std::cout << "  [PASS] cache_control_parsing\n";
}

void test_cache_build_key() {
    js::HttpRequest req;
    req.method_str = "GET";
    req.uri = "/api/data?page=1";
    req.headers["Host"] = "example.com";

    auto key = js::HttpCache::build_key(req);
    assert(!key.empty());
    assert(key.find("GET") != std::string::npos);
    assert(key.find("/api/data") != std::string::npos);

    std::cout << "  [PASS] cache_build_key\n";
}

void test_cache_stats() {
    js::HttpCache cache;

    js::HttpResponse resp;
    resp.status_code = 200;
    resp.body = "data";
    cache.put("k1", resp);

    cache.get("k1"); // Hit
    cache.get("k1"); // Hit
    cache.get("k2"); // Miss

    assert(cache.stats().hits.load() == 2);
    assert(cache.stats().misses.load() == 1);

    std::cout << "  [PASS] cache_stats\n";
}

} // namespace

void run_cache_tests() {
    std::cout << "=== Cache Tests ===\n";
    test_cache_put_get();
    test_cache_miss();
    test_cache_invalidate();
    test_cache_eviction();
    test_cache_control_parsing();
    test_cache_build_key();
    test_cache_stats();
    std::cout << "=== All cache tests passed ===\n\n";
}
