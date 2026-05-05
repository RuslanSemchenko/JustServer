#include "anti_bot.hpp"
#include <cassert>
#include <iostream>
#include <thread>

namespace {

void test_token_bucket_basic() {
    js::TokenBucketLimiter::Config config;
    config.rate = 5.0;   // 5 tokens/sec
    config.burst = 5.0;  // 5 max burst

    js::TokenBucketLimiter limiter(config);

    // Should allow burst of 5
    for (int i = 0; i < 5; ++i) {
        assert(limiter.allow("test-ip"));
    }

    // 6th should be rejected (no time to refill)
    assert(!limiter.allow("test-ip"));

    std::cout << "  [PASS] token_bucket_basic\n";
}

void test_token_bucket_refill() {
    js::TokenBucketLimiter::Config config;
    config.rate = 100.0;  // Fast refill for testing
    config.burst = 5.0;

    js::TokenBucketLimiter limiter(config);

    // Exhaust tokens
    for (int i = 0; i < 5; ++i) limiter.allow("ip1");
    assert(!limiter.allow("ip1"));

    // Wait for refill
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Should have some tokens again
    assert(limiter.allow("ip1"));

    std::cout << "  [PASS] token_bucket_refill\n";
}

void test_token_bucket_separate_keys() {
    js::TokenBucketLimiter::Config config;
    config.rate = 5.0;
    config.burst = 2.0;

    js::TokenBucketLimiter limiter(config);

    // Different keys have separate buckets
    assert(limiter.allow("ip1"));
    assert(limiter.allow("ip1"));
    assert(!limiter.allow("ip1")); // ip1 exhausted

    assert(limiter.allow("ip2")); // ip2 still has tokens
    assert(limiter.allow("ip2"));
    assert(!limiter.allow("ip2"));

    std::cout << "  [PASS] token_bucket_separate_keys\n";
}

void test_token_bucket_stats() {
    js::TokenBucketLimiter limiter;

    limiter.allow("k1");
    limiter.allow("k2");

    assert(limiter.total_allowed() >= 2);

    std::cout << "  [PASS] token_bucket_stats\n";
}

void test_js_challenge_generation() {
    js::JsChallenge challenge;

    auto response = challenge.generate_challenge("192.168.1.1");
    assert(response.status_code == 503);
    assert(response.body.find("__js_verify") != std::string::npos);
    assert(response.body.find("script") != std::string::npos);
    assert(response.headers.count("Content-Type") > 0);

    std::cout << "  [PASS] js_challenge_generation\n";
}

void test_pow_challenge_generation() {
    js::PowChallenge::Config config;
    config.difficulty = 8; // Easy difficulty for testing
    js::PowChallenge pow(config);

    auto challenge = pow.generate_challenge("192.168.1.1");
    assert(!challenge.nonce.empty());
    assert(!challenge.challenge_id.empty());
    assert(challenge.difficulty == 8);

    auto page = pow.generate_challenge_page(challenge);
    assert(page.status_code == 503);
    assert(page.body.find("crypto.subtle.digest") != std::string::npos);

    std::cout << "  [PASS] pow_challenge_generation\n";
}

void test_fingerprinter_known_bots() {
    // Known bot hashes should be detected
    assert(js::TlsFingerprinter::is_known_bot_fingerprint("e7d705a3286e19ea42f587b344ee6865"));

    // Random hash should not be a known bot
    assert(!js::TlsFingerprinter::is_known_bot_fingerprint("0000000000000000000000000000000"));

    std::cout << "  [PASS] fingerprinter_known_bots\n";
}

void test_fingerprinter_blocklist() {
    js::TlsFingerprinter fp;

    assert(!fp.is_blocked("custom_hash_123"));
    fp.block_fingerprint("custom_hash_123");
    assert(fp.is_blocked("custom_hash_123"));

    std::cout << "  [PASS] fingerprinter_blocklist\n";
}

void test_antibot_engine_rate_limit() {
    js::AntiBotEngine::Config config;
    config.enabled = true;
    config.ja3_enabled = false;
    config.rate_limit_enabled = true;
    config.js_challenge_enabled = false;
    config.pow_enabled = false;
    config.rate_limit.rate = 2.0;
    config.rate_limit.burst = 2.0;

    js::AntiBotEngine engine(config);

    js::HttpRequest req;
    req.method = js::HttpMethod::GET;
    req.method_str = "GET";
    req.uri = "/test";

    // First 2 should pass
    auto v1 = engine.inspect(req, "1.2.3.4");
    assert(v1.allowed);

    auto v2 = engine.inspect(req, "1.2.3.4");
    assert(v2.allowed);

    // Third should be rate limited
    auto v3 = engine.inspect(req, "1.2.3.4");
    assert(!v3.allowed);
    assert(v3.response.status_code == 429);

    std::cout << "  [PASS] antibot_engine_rate_limit\n";
}

} // namespace

void run_anti_bot_tests() {
    std::cout << "=== Anti-Bot Tests ===\n";
    test_token_bucket_basic();
    test_token_bucket_refill();
    test_token_bucket_separate_keys();
    test_token_bucket_stats();
    test_js_challenge_generation();
    test_pow_challenge_generation();
    test_fingerprinter_known_bots();
    test_fingerprinter_blocklist();
    test_antibot_engine_rate_limit();
    std::cout << "=== All anti-bot tests passed ===\n\n";
}
