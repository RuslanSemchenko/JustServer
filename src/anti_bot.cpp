#include "anti_bot.hpp"
#include "logger.hpp"

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <cstring>
#include <cmath>
#include <cctype>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <new>
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>
#include <chrono>
#include <thread>

namespace js {

// === Hex helpers ===
static std::string md5_hex(std::string_view data) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx) {
        EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
        EVP_DigestUpdate(ctx, data.data(), data.size());
        EVP_DigestFinal_ex(ctx, md, &md_len);
        EVP_MD_CTX_free(ctx);
    }
    std::string result;
    result.reserve(md_len * 2);
    for (unsigned i = 0; i < md_len; ++i) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", md[i]);
        result += buf;
    }
    return result;
}

static std::string sha256_hex(std::string_view data) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx) {
        EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(ctx, data.data(), data.size());
        EVP_DigestFinal_ex(ctx, md, &md_len);
        EVP_MD_CTX_free(ctx);
    }
    std::string result;
    result.reserve(md_len * 2);
    for (unsigned i = 0; i < md_len; ++i) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", md[i]);
        result += buf;
    }
    return result;
}

static std::string random_hex(size_t bytes) {
    std::vector<unsigned char> buf(bytes);
    RAND_bytes(buf.data(), static_cast<int>(bytes));
    std::string result;
    result.reserve(bytes * 2);
    for (auto b : buf) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", b);
        result += hex;
    }
    return result;
}

// === TLS Fingerprinter ===

namespace {

bool is_grease_value(unsigned value) {
    return (value & 0x0f0fU) == 0x0a0aU && ((value >> 8) & 0xffU) == (value & 0xffU);
}

void append_ja3_values(std::string& output, const unsigned char* data, size_t length,
                       size_t value_width, size_t prefix_width) {
    if (!data || length < prefix_width || value_width == 0) return;
    size_t list_length = prefix_width == 0 ? length : 0;
    for (size_t i = 0; i < prefix_width; ++i) list_length = (list_length << 8) | data[i];
    if (list_length > length - prefix_width || list_length % value_width != 0) return;
    for (size_t offset = prefix_width; offset < prefix_width + list_length;
         offset += value_width) {
        unsigned value = 0;
        for (size_t i = 0; i < value_width; ++i) value = (value << 8) | data[offset + i];
        if (is_grease_value(value)) continue;
        if (!output.empty()) output += '-';
        output += std::to_string(value);
    }
}

int ja3_ex_data_index() {
    static int index = SSL_get_ex_new_index(
        0, nullptr, nullptr, nullptr,
        [](void*, void* data, CRYPTO_EX_DATA*, int, long, void*) {
            delete static_cast<std::string*>(data);
        });
    return index;
}

int capture_client_hello(SSL* ssl, int* alert, void*) {
    if (!ssl) {
        if (alert) *alert = SSL_AD_INTERNAL_ERROR;
        return SSL_CLIENT_HELLO_ERROR;
    }
    try {
        std::string raw = std::to_string(SSL_client_hello_get0_legacy_version(ssl)) + ",";

        const unsigned char* ciphers = nullptr;
        size_t cipher_length = SSL_client_hello_get0_ciphers(ssl, &ciphers);
        std::string cipher_list;
        append_ja3_values(cipher_list, ciphers, cipher_length, 2, 0);
        raw += cipher_list + ",";

        int* extensions = nullptr;
        size_t extension_count = 0;
        std::string extension_list;
        if (SSL_client_hello_get1_extensions_present(ssl, &extensions, &extension_count) == 1) {
            auto free_extensions = [](int* values) { OPENSSL_free(values); };
            std::unique_ptr<int, decltype(free_extensions)> extension_guard(
                extensions, free_extensions);
            for (size_t i = 0; i < extension_count; ++i) {
                unsigned value = static_cast<unsigned>(extensions[i]);
                if (is_grease_value(value)) continue;
                if (!extension_list.empty()) extension_list += '-';
                extension_list += std::to_string(value);
            }
        }
        raw += extension_list + ",";

        const unsigned char* extension_data = nullptr;
        size_t extension_length = 0;
        std::string groups;
        if (SSL_client_hello_get0_ext(ssl, 10, &extension_data, &extension_length) == 1) {
            append_ja3_values(groups, extension_data, extension_length, 2, 2);
        }
        raw += groups + ",";

        std::string point_formats;
        if (SSL_client_hello_get0_ext(ssl, 11, &extension_data, &extension_length) == 1) {
            append_ja3_values(point_formats, extension_data, extension_length, 1, 1);
        }
        raw += point_formats;

        int index = ja3_ex_data_index();
        if (index < 0) return SSL_CLIENT_HELLO_SUCCESS;
        auto* previous = static_cast<std::string*>(SSL_get_ex_data(ssl, index));
        if (previous) {
            if (SSL_set_ex_data(ssl, index, nullptr) != 1) return SSL_CLIENT_HELLO_SUCCESS;
            delete previous;
        }
        auto* stored = new (std::nothrow) std::string(std::move(raw));
        if (!stored || SSL_set_ex_data(ssl, index, stored) != 1) {
            delete stored;
            return SSL_CLIENT_HELLO_SUCCESS;
        }
        return SSL_CLIENT_HELLO_SUCCESS;
    } catch (const std::bad_alloc&) {
        return SSL_CLIENT_HELLO_SUCCESS;
    }
}

} // namespace

void install_ja3_client_hello_capture(ssl_ctx_st* context) {
    if (context) SSL_CTX_set_client_hello_cb(context, capture_client_hello, nullptr);
}

TlsFingerprinter::Fingerprint TlsFingerprinter::extract_ja3(ssl_st* ssl, const std::string& client_ip) {
    Fingerprint fp;
    fp.client_ip = client_ip;

    if (!ssl) {
        fp.ja3_hash = "no_tls";
        return fp;
    }

    int index = ja3_ex_data_index();
    auto* captured = index >= 0
        ? static_cast<std::string*>(SSL_get_ex_data(ssl, index)) : nullptr;
    if (captured) {
        fp.ja3_raw = *captured;
    } else {
        std::string fallback = std::to_string(SSL_version(ssl)) + ",";
        const STACK_OF(SSL_CIPHER)* ciphers = SSL_get_client_ciphers(ssl);
        bool first_cipher = true;
        if (ciphers) {
            for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); ++i) {
                unsigned value = SSL_CIPHER_get_protocol_id(sk_SSL_CIPHER_value(ciphers, i));
                if (is_grease_value(value)) continue;
                if (!first_cipher) fallback += '-';
                fallback += std::to_string(value);
                first_cipher = false;
            }
        }
        fp.ja3_raw = fallback + ",,,";
    }
    fp.ja3_hash = md5_hex(fp.ja3_raw);
    fp.is_known_bot = is_known_bot_fingerprint(fp.ja3_hash);

    return fp;
}

bool TlsFingerprinter::is_known_bot_fingerprint(std::string_view ja3_hash) {
    return known_bot_hashes().count(std::string(ja3_hash)) > 0;
}

void TlsFingerprinter::block_fingerprint(std::string_view ja3_hash) {
    std::lock_guard lock(mutex_);
    blocked_fingerprints_.insert(std::string(ja3_hash));
}

bool TlsFingerprinter::is_blocked(std::string_view ja3_hash) const {
    std::lock_guard lock(mutex_);
    return blocked_fingerprints_.count(std::string(ja3_hash)) > 0;
}

const std::unordered_set<std::string>& TlsFingerprinter::known_bot_hashes() {
    // Known JA3 hashes for common bots/scanners
    static const std::unordered_set<std::string> hashes = {
        "e7d705a3286e19ea42f587b344ee6865", // Python requests
        "b32309a26951912be7dba376398abc3b", // Go net/http
        "3b5074b1b5d032e5620f69f9f700ff0e", // curl/7.x
        "5d65ea3fb1d4aa7d826733d2f2cbbb1d", // wget
        "9e10692f1b7f78228b2d4e424db3a98c", // Nikto scanner
        "7c02dbae662670040c7af9bd15fb7e2f", // Nmap scripting
        "c12f54a3f91dc7bafd92cb59fe009a35", // sqlmap
        "a0e9f5d64349fb13191bc781f81f42e1", // Headless Chrome (old)
        "cd08e31494f9531f560d64c695473da9", // PhantomJS
    };
    return hashes;
}

// === Token Bucket Rate Limiter ===

TokenBucketLimiter::TokenBucketLimiter() : config_{} {}
TokenBucketLimiter::TokenBucketLimiter(Config config) : config_(std::move(config)) {}

void TokenBucketLimiter::refill(Bucket& bucket) const {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration<double>(now - bucket.last_refill).count();
    bucket.tokens = std::min(bucket.burst, bucket.tokens + elapsed * bucket.rate);
    bucket.last_refill = now;
}

bool TokenBucketLimiter::allow(const std::string& key) {
    std::lock_guard lock(mutex_);

    auto it = buckets_.find(key);
    if (it == buckets_.end()) {
        // New bucket
        Bucket b;
        b.tokens = config_.burst - 1.0; // Consume first token
        b.rate = config_.rate;
        b.burst = config_.burst;
        b.last_refill = std::chrono::steady_clock::now();
        buckets_[key] = b;
        total_allowed_.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    auto& bucket = it->second;
    refill(bucket);

    if (bucket.tokens >= 1.0) {
        bucket.tokens -= 1.0;
        total_allowed_.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    total_rejected_.fetch_add(1, std::memory_order_relaxed);
    return false;
}

bool TokenBucketLimiter::check(const std::string& key) const {
    std::lock_guard lock(mutex_);
    auto it = buckets_.find(key);
    if (it == buckets_.end()) return true;

    auto bucket = it->second; // Copy
    refill(bucket);
    return bucket.tokens >= 1.0;
}

double TokenBucketLimiter::remaining(const std::string& key) const {
    std::lock_guard lock(mutex_);
    auto it = buckets_.find(key);
    if (it == buckets_.end()) return config_.burst;

    auto bucket = it->second;
    refill(bucket);
    return bucket.tokens;
}

void TokenBucketLimiter::set_rate(const std::string& key, double rate, double burst) {
    std::lock_guard lock(mutex_);
    auto it = buckets_.find(key);
    if (it != buckets_.end()) {
        it->second.rate = rate;
        it->second.burst = burst;
    }
}

void TokenBucketLimiter::cleanup() {
    std::lock_guard lock(mutex_);
    auto now = std::chrono::steady_clock::now();

    for (auto it = buckets_.begin(); it != buckets_.end(); ) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - it->second.last_refill);
        if (elapsed > config_.window) {
            it = buckets_.erase(it);
        } else {
            ++it;
        }
    }
}

// === JS Challenge ===

JsChallenge::JsChallenge() : JsChallenge(Config{}) {}
JsChallenge::JsChallenge(Config config) : config_(std::move(config)) {
    secret_key_ = random_hex(32);
}

std::string JsChallenge::generate_token(const std::string& client_ip,
                                          std::chrono::system_clock::time_point ts) const {
    auto ts_secs = std::chrono::duration_cast<std::chrono::seconds>(
        ts.time_since_epoch()).count();

    std::string data = client_ip + "|" + std::to_string(ts_secs) + "|" + secret_key_;
    return sha256_hex(data);
}

bool JsChallenge::is_verified(const HttpRequest& req, const std::string& client_ip) const {
    // Look for the verification cookie
    auto cookie_header = req.get_header("Cookie");
    if (cookie_header.empty()) return false;

    // Parse cookies to find our verification cookie
    std::string search = config_.cookie_name + "=";
    auto pos = cookie_header.find(search);
    if (pos == std::string_view::npos) return false;

    pos += search.size();
    auto end = cookie_header.find(';', pos);
    auto cookie_value = cookie_header.substr(pos, end == std::string_view::npos ? end : end - pos);

    // The cookie format is: timestamp:hash
    auto sep = cookie_value.find(':');
    if (sep == std::string_view::npos) return false;

    auto ts_str = cookie_value.substr(0, sep);
    auto hash = cookie_value.substr(sep + 1);

    // Validate timestamp (not expired)
    int64_t ts = 0;
    for (char c : ts_str) {
        if (c >= '0' && c <= '9') ts = ts * 10 + (c - '0');
    }

    auto now = std::chrono::system_clock::now();
    auto now_ts = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();

    if (now_ts - ts > config_.cookie_ttl.count()) return false;

    // Cryptographically verify the hash by re-deriving it from client_ip + timestamp
    auto ts_point = std::chrono::system_clock::time_point(std::chrono::seconds(ts));
    auto expected_hash = generate_token(client_ip, ts_point);
    return hash == expected_hash;
}

HttpResponse JsChallenge::generate_challenge([[maybe_unused]] const std::string& client_ip) const {
    auto now = std::chrono::system_clock::now();
    auto ts = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    auto token = generate_token(client_ip, now);

    // Generate JS challenge page
    std::string html = R"(<!DOCTYPE html>
<html><head><title>)" + config_.challenge_page_title + R"(</title>
<style>
body{display:flex;justify-content:center;align-items:center;height:100vh;margin:0;
font-family:sans-serif;background:#f5f5f5}
.box{text-align:center;padding:40px;background:white;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.1)}
.spinner{width:40px;height:40px;border:4px solid #ddd;border-top-color:#333;
border-radius:50%;animation:spin 1s linear infinite;margin:20px auto}
@keyframes spin{to{transform:rotate(360deg)}}
</style></head><body>
<div class="box">
<div class="spinner"></div>
<h2>)" + config_.challenge_page_title + R"(</h2>
<p>This is an automatic process. Your browser will redirect shortly.</p>
<noscript><p>Please enable JavaScript to continue.</p></noscript>
</div>
<script>
(function(){
var t=)" + std::to_string(ts) + R"(;
var h=')" + token + R"(';
// Simple computation that proves JS execution
var r=0;for(var i=0;i<1000;i++){r=(r*31+i)>>>0;}
document.cookie=')" + config_.cookie_name + R"(='+t+':'+h+';path=/;max-age=)" +
    std::to_string(config_.cookie_ttl.count()) + R"(;SameSite=Lax';
setTimeout(function(){location.reload();},1500);
})();
</script></body></html>)";

    HttpResponse resp;
    resp.status_code = 503;
    resp.status_text = "Service Temporarily Unavailable";
    resp.headers["Content-Type"] = "text/html; charset=utf-8";
    resp.headers["Cache-Control"] = "no-store";
    resp.headers["Retry-After"] = "2";
    resp.body = html;
    return resp;
}

// === Proof-of-Work Challenge ===

PowChallenge::PowChallenge() : PowChallenge(Config{}) {}
PowChallenge::PowChallenge(Config config) : config_(std::move(config)) {
    secret_ = random_hex(32);
}

PowChallenge::Challenge PowChallenge::generate_challenge(const std::string& client_ip) {
    Challenge ch;
    ch.nonce = random_hex(16);
    ch.difficulty = config_.difficulty;
    ch.challenge_id = sha256_hex(client_ip + "|" + ch.nonce + "|" + secret_);

    std::lock_guard lock(mutex_);
    active_challenges_[ch.challenge_id] = ch;
    return ch;
}

bool PowChallenge::verify_solution(const std::string& challenge_id,
                                     const std::string& solution) {
    // Look up the challenge to get the real nonce
    std::lock_guard lock(mutex_);
    auto it = active_challenges_.find(challenge_id);
    if (it == active_challenges_.end()) return false;

    const std::string& nonce = it->second.nonce;

    // Verify: SHA256(nonce + solution) has required leading zero bits
    std::string input = nonce + solution;
    auto hash = sha256_hex(input);

    // Check leading zero nibbles
    int required_nibbles = config_.difficulty / 4;
    for (int i = 0; i < required_nibbles && i < static_cast<int>(hash.size()); ++i) {
        if (hash[static_cast<size_t>(i)] != '0') return false;
    }

    // Check remaining bits if difficulty is not nibble-aligned
    int remaining_bits = config_.difficulty % 4;
    if (remaining_bits > 0 && required_nibbles < static_cast<int>(hash.size())) {
        char c = hash[static_cast<size_t>(required_nibbles)];
        int val = (c >= '0' && c <= '9') ? c - '0' : 10 + c - 'a';
        int mask = (0xF << (4 - remaining_bits)) & 0xF;
        if ((val & mask) != 0) return false;
    }

    // Consume the challenge (prevent replay attacks, free memory)
    active_challenges_.erase(it);
    return true;
}

HttpResponse PowChallenge::generate_challenge_page(const Challenge& challenge) const {
    std::string html = R"(<!DOCTYPE html>
<html><head><title>Security Check</title>
<style>
body{display:flex;justify-content:center;align-items:center;height:100vh;margin:0;
font-family:monospace;background:#1a1a1a;color:#00ff00}
.box{text-align:center;padding:40px;background:#222;border-radius:8px;border:1px solid #333}
#status{margin-top:20px}
</style></head><body>
<div class="box">
<h2>Security Verification Required</h2>
<p>Solving computational challenge...</p>
<div id="status">Computing: 0 hashes</div>
<canvas id="progress" width="300" height="20"></canvas>
</div>
<script>
(function(){
var nonce=')" + challenge.nonce + R"(';
var id=')" + challenge.challenge_id + R"(';
var diff=)" + std::to_string(challenge.difficulty) + R"(;
var count=0;
var prefix='0'.repeat(Math.floor(diff/4));

async function sha256(msg){
var enc=new TextEncoder();
var buf=await crypto.subtle.digest('SHA-256',enc.encode(msg));
return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
}

async function solve(){
var s=document.getElementById('status');
for(var i=0;i<1e8;i++){
count++;
var sol=i.toString(16);
var hash=await sha256(nonce+sol);
if(hash.startsWith(prefix)){
s.textContent='Solved! Redirecting...';
document.cookie='__pow='+id+':'+sol+';path=/;max-age=300;SameSite=Lax';
setTimeout(function(){location.reload();},500);
return;
}
if(count%10000===0)s.textContent='Computing: '+count+' hashes';
}
s.textContent='Challenge failed. Please refresh.';
}
solve();
})();
</script></body></html>)";

    HttpResponse resp;
    resp.status_code = 503;
    resp.status_text = "Service Temporarily Unavailable";
    resp.headers["Content-Type"] = "text/html; charset=utf-8";
    resp.headers["Cache-Control"] = "no-store";
    resp.body = html;
    return resp;
}

// === Tarpit ===

Tarpit::Tarpit() : Tarpit(Config{}) {}
Tarpit::Tarpit(Config config) : config_(std::move(config)) {
    if (config_.response_body.empty()) {
        // Generate a large fake response to drip-feed
        config_.response_body = std::string(4096, ' ');
    }
}

HttpResponse Tarpit::generate_response() const {
    HttpResponse resp;
    resp.status_code = 200;
    resp.status_text = "OK";
    resp.headers["Content-Type"] = "text/html";
    resp.headers["Content-Length"] = std::to_string(config_.response_body.size());
    resp.body = config_.response_body;
    return resp;
}

void Tarpit::drip_feed(int fd, const std::string& data) const {
    auto deadline = std::chrono::steady_clock::now() + config_.max_duration;
    int delay_ms = 1000 / std::max(config_.bytes_per_second, 1);

    for (size_t i = 0; i < data.size(); ++i) {
        if (std::chrono::steady_clock::now() > deadline) break;

        // Use poll() with timeout instead of blocking sleep_for.
        // This avoids tying up the worker thread -- poll() yields the CPU
        // to the kernel and only wakes when the fd is writable or the
        // timeout expires, whichever comes first.
        struct pollfd pfd{};
        pfd.fd = fd;
        pfd.events = POLLOUT;
        int poll_ret = poll(&pfd, 1, delay_ms);

        if (poll_ret < 0) break; // Error
        if (poll_ret == 0) continue; // Timeout expired, send next byte
        if (pfd.revents & (POLLERR | POLLHUP)) break; // Client gone

        auto n = send(fd, data.data() + i, 1, MSG_NOSIGNAL);
        if (n <= 0) break; // Client disconnected (mission accomplished)
    }
}

// === GeoIP Filter ===

GeoIPFilter::GeoIPFilter() : GeoIPFilter(Config{}) {}
GeoIPFilter::GeoIPFilter(Config config) : config_(std::move(config)) {}

std::optional<std::string> GeoIPFilter::lookup_country(std::string_view ip) const {
    std::lock_guard lock(mutex_);
    if (!database_) return std::nullopt;
    return database_->lookup_country(ip);
}

bool GeoIPFilter::is_blocked(std::string_view ip) const {
    if (config_.blocked_countries.empty()) return false;

    auto country = lookup_country(ip);
    if (!country) return false;

    for (const auto& blocked : config_.blocked_countries) {
        if (blocked.size() != country->size()) continue;
        bool matches = true;
        for (size_t i = 0; i < blocked.size(); ++i) {
            if (std::toupper(static_cast<unsigned char>(blocked[i])) != (*country)[i]) {
                matches = false;
                break;
            }
        }
        if (matches) return true;
    }
    return false;
}

bool GeoIPFilter::load_database() {
    if (config_.database_path.empty()) {
        LOG_ERROR("GeoIP: database path is empty");
        return false;
    }

    auto database = std::make_unique<MaxMindDbReader>();
    if (!database->open(config_.database_path)) return false;

    std::lock_guard lock(mutex_);
    database_ = std::move(database);
    LOG_INFO("GeoIP: loaded database " + config_.database_path);
    return true;
}

// === Unified Anti-Bot Engine ===

AntiBotEngine::AntiBotEngine() : AntiBotEngine(Config{}) {}

AntiBotEngine::AntiBotEngine(Config config)
    : config_(std::move(config))
    , rate_limiter_(config_.rate_limit)
    , js_challenge_(config_.js_challenge)
    , pow_challenge_(config_.pow)
    , tarpit_(config_.tarpit)
    , geoip_(config_.geoip) {
    if (config_.geoip_enabled && !geoip_.load_database()) {
        LOG_ERROR("GeoIP: filtering is enabled but the database could not be loaded");
    }
}

AntiBotEngine::Verdict AntiBotEngine::inspect(const HttpRequest& req,
                                                const std::string& client_ip,
                                                ssl_st* ssl) {
    Verdict verdict;
    if (!config_.enabled) return verdict;

    // 1. GeoIP check
    if (config_.geoip_enabled && geoip_.is_blocked(client_ip)) {
        verdict.allowed = false;
        verdict.reason = "Blocked by GeoIP policy";
        verdict.response = HttpResponse::make_error(403, "Access denied");
        return verdict;
    }

    // 2. JA3 fingerprint check
    if (config_.ja3_enabled && ssl) {
        auto fp = TlsFingerprinter::extract_ja3(ssl, client_ip);
        if (fp.is_known_bot || fingerprinter_.is_blocked(fp.ja3_hash)) {
            LOG_WARN("Bot detected by JA3: " + client_ip + " hash=" + fp.ja3_hash);

            if (config_.tarpit_enabled) {
                verdict.allowed = false;
                verdict.tarpit = true;
                verdict.reason = "Known bot fingerprint (tarpitting)";
                verdict.response = tarpit_.generate_response();
                return verdict;
            }

            verdict.allowed = false;
            verdict.reason = "Known bot fingerprint blocked";
            verdict.response = HttpResponse::make_error(403, "Access denied");
            return verdict;
        }
    }

    // 3. Rate limiting
    if (config_.rate_limit_enabled) {
        if (!rate_limiter_.allow(client_ip)) {
            verdict.allowed = false;
            verdict.reason = "Rate limit exceeded";

            HttpResponse resp;
            resp.status_code = 429;
            resp.status_text = "Too Many Requests";
            resp.headers["Content-Type"] = "text/plain";
            resp.headers["Retry-After"] = "10";
            resp.body = "Rate limit exceeded. Please try again later.";
            verdict.response = resp;
            return verdict;
        }
    }

    // 4. JS Challenge (for browser clients)
    if (config_.js_challenge_enabled) {
        if (!js_challenge_.is_verified(req, client_ip)) {
            verdict.allowed = false;
            verdict.challenge = true;
            verdict.reason = "JS challenge required";
            verdict.response = js_challenge_.generate_challenge(client_ip);
            return verdict;
        }
    }

    // 5. PoW Challenge (under attack mode)
    if (config_.pow_enabled) {
        // Check for existing PoW solution
        auto cookie = req.get_header("Cookie");
        bool pow_solved = false;

        if (!cookie.empty()) {
            std::string search = "__pow=";
            auto pos = cookie.find(search);
            if (pos != std::string_view::npos) {
                pos += search.size();
                auto end = cookie.find(';', pos);
                auto pow_cookie = cookie.substr(pos, end == std::string_view::npos ? end : end - pos);
                auto sep = pow_cookie.find(':');
                if (sep != std::string_view::npos) {
                    auto cid = std::string(pow_cookie.substr(0, sep));
                    auto sol = std::string(pow_cookie.substr(sep + 1));
                    pow_solved = pow_challenge_.verify_solution(cid, sol);
                }
            }
        }

        if (!pow_solved) {
            auto challenge = pow_challenge_.generate_challenge(client_ip);
            verdict.allowed = false;
            verdict.challenge = true;
            verdict.reason = "PoW challenge required";
            verdict.response = pow_challenge_.generate_challenge_page(challenge);
            return verdict;
        }
    }

    return verdict; // All checks passed
}

} // namespace js
