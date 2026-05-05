#include "anti_bot.hpp"
#include "logger.hpp"

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <cstring>
#include <cmath>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <sys/socket.h>
#include <unistd.h>
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

TlsFingerprinter::Fingerprint TlsFingerprinter::extract_ja3(ssl_st* ssl, const std::string& client_ip) {
    Fingerprint fp;
    fp.client_ip = client_ip;

    if (!ssl) {
        fp.ja3_hash = "no_tls";
        return fp;
    }

    // Build JA3 string from SSL connection info
    // JA3 = SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
    std::string ja3;

    // TLS version
    int version = SSL_version(ssl);
    ja3 += std::to_string(version);
    ja3 += ',';

    // Cipher suite (the negotiated one -- in a real implementation we'd capture
    // the full ClientHello cipher list via an info callback)
    const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl);
    if (cipher) {
        ja3 += std::to_string(SSL_CIPHER_get_protocol_id(cipher));
    }
    ja3 += ',';

    // Extensions, curves, point formats would be captured from ClientHello
    // via SSL_CTX_set_info_callback or custom extension callbacks.
    // For now, use what's available from the session.
    ja3 += "0"; // placeholder extensions
    ja3 += ',';
    ja3 += "0"; // placeholder curves
    ja3 += ',';
    ja3 += "0"; // placeholder point formats

    fp.ja3_raw = ja3;
    fp.ja3_hash = md5_hex(ja3);
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

    for (size_t i = 0; i < data.size(); ++i) {
        if (std::chrono::steady_clock::now() > deadline) break;

        auto n = send(fd, data.data() + i, 1, MSG_NOSIGNAL);
        if (n <= 0) break; // Client disconnected (mission accomplished)

        // Sleep to achieve target bytes/sec
        std::this_thread::sleep_for(
            std::chrono::milliseconds(1000 / config_.bytes_per_second));
    }
}

// === GeoIP Filter ===

GeoIPFilter::GeoIPFilter() : config_{} {}
GeoIPFilter::GeoIPFilter(Config config) : config_(std::move(config)) {}

std::optional<std::string> GeoIPFilter::lookup_country([[maybe_unused]] std::string_view ip) const {
    // Full implementation would use a radix trie over MaxMind GeoLite2 data.
    // This is a structural placeholder that shows the correct interface.
    std::lock_guard lock(mutex_);

    // Parse IP to uint32
    uint32_t ip_num = 0;
    int octet = 0;
    int shift = 24;
    for (char c : ip) {
        if (c == '.') {
            ip_num |= (static_cast<uint32_t>(octet) << shift);
            octet = 0;
            shift -= 8;
        } else if (c >= '0' && c <= '9') {
            octet = octet * 10 + (c - '0');
        }
    }
    ip_num |= static_cast<uint32_t>(octet);

    // Binary search in sorted ranges
    for (const auto& range : ranges_) {
        if (ip_num >= range.start && ip_num <= range.end) {
            return range.country;
        }
    }
    return std::nullopt;
}

bool GeoIPFilter::is_blocked(std::string_view ip) const {
    if (config_.blocked_countries.empty()) return false;

    auto country = lookup_country(ip);
    if (!country) return false;

    for (const auto& blocked : config_.blocked_countries) {
        if (*country == blocked) return true;
    }
    return false;
}

bool GeoIPFilter::load_database() {
    // TODO: Parse MaxMind GeoLite2 CSV/MMDB into ranges_
    LOG_INFO("GeoIP: Database loading from " + config_.database_path +
             " (not implemented -- needs MaxMind integration)");
    return false;
}

// === Unified Anti-Bot Engine ===

AntiBotEngine::AntiBotEngine() : AntiBotEngine(Config{}) {}

AntiBotEngine::AntiBotEngine(Config config)
    : config_(std::move(config))
    , rate_limiter_(config_.rate_limit)
    , js_challenge_(config_.js_challenge)
    , pow_challenge_(config_.pow)
    , tarpit_(config_.tarpit)
    , geoip_(config_.geoip) {}

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
