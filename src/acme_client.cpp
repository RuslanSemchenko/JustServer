#include "acme_client.hpp"
#include "logger.hpp"

#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <cerrno>
#include <ctime>
#include <fstream>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <thread>
#include <variant>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace js {
namespace {

struct Json {
    using Object = std::unordered_map<std::string, Json>;
    using Array = std::vector<Json>;
    std::variant<std::nullptr_t, bool, int64_t, std::string, Array, Object> value = nullptr;

    const Json* get(std::string_view key) const {
        const auto* object = std::get_if<Object>(&value);
        if (!object) return nullptr;
        auto it = object->find(std::string(key));
        return it == object->end() ? nullptr : &it->second;
    }

    std::string string() const {
        if (const auto* result = std::get_if<std::string>(&value)) return *result;
        return {};
    }

    const Array* array() const { return std::get_if<Array>(&value); }
};

class JsonParser {
public:
    explicit JsonParser(std::string_view input) : input_(input) {}

    std::optional<Json> parse() {
        skip_space();
        auto result = parse_value(0);
        skip_space();
        if (!result || position_ != input_.size()) return std::nullopt;
        return result;
    }

private:
    void skip_space() {
        while (position_ < input_.size() &&
               (input_[position_] == ' ' || input_[position_] == '\t' ||
                input_[position_] == '\r' || input_[position_] == '\n')) {
            ++position_;
        }
    }

    bool consume(std::string_view token) {
        if (input_.substr(position_, token.size()) != token) return false;
        position_ += token.size();
        return true;
    }

    static void append_utf8(std::string& out, uint32_t cp) {
        if (cp <= 0x7f) out += static_cast<char>(cp);
        else if (cp <= 0x7ff) {
            out += static_cast<char>(0xc0 | (cp >> 6));
            out += static_cast<char>(0x80 | (cp & 0x3f));
        } else if (cp <= 0xffff) {
            out += static_cast<char>(0xe0 | (cp >> 12));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3f));
            out += static_cast<char>(0x80 | (cp & 0x3f));
        } else {
            out += static_cast<char>(0xf0 | (cp >> 18));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3f));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3f));
            out += static_cast<char>(0x80 | (cp & 0x3f));
        }
    }

    bool hex4(uint32_t& result) {
        if (input_.size() - position_ < 4) return false;
        result = 0;
        for (size_t i = 0; i < 4; ++i) {
            char ch = input_[position_++];
            unsigned value;
            if (ch >= '0' && ch <= '9') value = static_cast<unsigned>(ch - '0');
            else if (ch >= 'a' && ch <= 'f') value = static_cast<unsigned>(ch - 'a' + 10);
            else if (ch >= 'A' && ch <= 'F') value = static_cast<unsigned>(ch - 'A' + 10);
            else return false;
            result = (result << 4) | value;
        }
        return true;
    }

    std::optional<std::string> parse_string() {
        if (position_ >= input_.size() || input_[position_++] != '"') return std::nullopt;
        std::string result;
        while (position_ < input_.size()) {
            unsigned char ch = static_cast<unsigned char>(input_[position_++]);
            if (ch == '"') return result;
            if (ch < 0x20) return std::nullopt;
            if (ch != '\\') {
                result += static_cast<char>(ch);
                continue;
            }
            if (position_ >= input_.size()) return std::nullopt;
            char escape = input_[position_++];
            switch (escape) {
                case '"': result += '"'; break;
                case '\\': result += '\\'; break;
                case '/': result += '/'; break;
                case 'b': result += '\b'; break;
                case 'f': result += '\f'; break;
                case 'n': result += '\n'; break;
                case 'r': result += '\r'; break;
                case 't': result += '\t'; break;
                case 'u': {
                    uint32_t cp = 0;
                    if (!hex4(cp)) return std::nullopt;
                    if (cp >= 0xd800 && cp <= 0xdbff) {
                        if (!consume("\\u")) return std::nullopt;
                        uint32_t low = 0;
                        if (!hex4(low) || low < 0xdc00 || low > 0xdfff) return std::nullopt;
                        cp = 0x10000 + ((cp - 0xd800) << 10) + (low - 0xdc00);
                    } else if (cp >= 0xdc00 && cp <= 0xdfff) {
                        return std::nullopt;
                    }
                    append_utf8(result, cp);
                    break;
                }
                default: return std::nullopt;
            }
        }
        return std::nullopt;
    }

    std::optional<Json> parse_value(size_t depth) {
        if (depth > 64 || position_ >= input_.size()) return std::nullopt;
        skip_space();
        if (position_ >= input_.size()) return std::nullopt;
        char ch = input_[position_];
        if (ch == '"') {
            auto string = parse_string();
            if (!string) return std::nullopt;
            Json result;
            result.value = std::move(*string);
            return result;
        }
        if (consume("true")) { Json result; result.value = true; return result; }
        if (consume("false")) { Json result; result.value = false; return result; }
        if (consume("null")) return Json{};
        if (ch == '[') {
            ++position_;
            Json::Array array;
            skip_space();
            if (position_ < input_.size() && input_[position_] == ']') {
                ++position_;
                Json result;
                result.value = std::move(array);
                return result;
            }
            while (array.size() < 10000) {
                auto item = parse_value(depth + 1);
                if (!item) return std::nullopt;
                array.push_back(std::move(*item));
                skip_space();
                if (position_ < input_.size() && input_[position_] == ']') {
                    ++position_;
                    Json result;
                    result.value = std::move(array);
                    return result;
                }
                if (position_ >= input_.size() || input_[position_++] != ',') return std::nullopt;
            }
            return std::nullopt;
        }
        if (ch == '{') {
            ++position_;
            Json::Object object;
            skip_space();
            if (position_ < input_.size() && input_[position_] == '}') {
                ++position_;
                Json result;
                result.value = std::move(object);
                return result;
            }
            while (object.size() < 10000) {
                auto key = parse_string();
                if (!key) return std::nullopt;
                skip_space();
                if (position_ >= input_.size() || input_[position_++] != ':') return std::nullopt;
                auto value = parse_value(depth + 1);
                if (!value || !object.emplace(std::move(*key), std::move(*value)).second)
                    return std::nullopt;
                skip_space();
                if (position_ < input_.size() && input_[position_] == '}') {
                    ++position_;
                    Json result;
                    result.value = std::move(object);
                    return result;
                }
                if (position_ >= input_.size() || input_[position_++] != ',') return std::nullopt;
                skip_space();
            }
            return std::nullopt;
        }
        size_t start = position_;
        if (ch == '-') ++position_;
        if (position_ >= input_.size() || !std::isdigit(static_cast<unsigned char>(input_[position_])))
            return std::nullopt;
        if (input_[position_] == '0') ++position_;
        else {
            while (position_ < input_.size() &&
                   std::isdigit(static_cast<unsigned char>(input_[position_]))) ++position_;
        }
        if (position_ < input_.size() &&
            (input_[position_] == '.' || input_[position_] == 'e' || input_[position_] == 'E')) {
            return std::nullopt;
        }
        int64_t number = 0;
        auto [end, ec] = std::from_chars(input_.data() + start, input_.data() + position_, number);
        if (ec != std::errc{} || end != input_.data() + position_) return std::nullopt;
        Json result;
        result.value = number;
        return result;
    }

    std::string_view input_;
    size_t position_ = 0;
};

std::string json_string(std::string_view value) {
    std::string result = "\"";
    for (unsigned char ch : value) {
        switch (ch) {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\b': result += "\\b"; break;
            case '\f': result += "\\f"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default:
                if (ch < 0x20) {
                    static constexpr char hex[] = "0123456789abcdef";
                    result += "\\u00";
                    result += hex[ch >> 4];
                    result += hex[ch & 0x0f];
                } else {
                    result += static_cast<char>(ch);
                }
        }
    }
    result += '"';
    return result;
}

bool successful_status(const HttpClientResponse& response) {
    return response.status >= 200 && response.status < 300;
}

std::string encode_base64url(std::string_view data) {
    static constexpr char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string result;
    result.reserve((data.size() + 2) / 3 * 4);
    size_t i = 0;
    for (; i + 2 < data.size(); i += 3) {
        uint32_t n = (static_cast<uint8_t>(data[i]) << 16) |
                     (static_cast<uint8_t>(data[i + 1]) << 8) |
                     static_cast<uint8_t>(data[i + 2]);
        result += table[(n >> 18) & 0x3f];
        result += table[(n >> 12) & 0x3f];
        result += table[(n >> 6) & 0x3f];
        result += table[n & 0x3f];
    }
    if (i + 1 == data.size()) {
        uint32_t n = static_cast<uint8_t>(data[i]) << 16;
        result += table[(n >> 18) & 0x3f];
        result += table[(n >> 12) & 0x3f];
    } else if (i + 2 == data.size()) {
        uint32_t n = (static_cast<uint8_t>(data[i]) << 16) |
                     (static_cast<uint8_t>(data[i + 1]) << 8);
        result += table[(n >> 18) & 0x3f];
        result += table[(n >> 12) & 0x3f];
        result += table[(n >> 6) & 0x3f];
    }
    return result;
}

std::string acme_error(const HttpClientResponse& response) {
    auto parsed = JsonParser(response.body).parse();
    if (parsed) {
        std::string type, detail;
        if (const auto* value = parsed->get("type")) type = value->string();
        if (const auto* value = parsed->get("detail")) detail = value->string();
        if (!type.empty() || !detail.empty()) return type + ": " + detail;
    }
    return "HTTP " + std::to_string(response.status) + " " + response.reason +
           (response.body.empty() ? "" : ": " + response.body.substr(0, 512));
}

std::chrono::seconds retry_after(const HttpClientResponse& response,
                                 std::chrono::seconds fallback) {
    auto value = response.header("Retry-After");
    if (value.empty()) return fallback;
    int64_t seconds = 0;
    auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), seconds);
    if (error == std::errc{} && end == value.data() + value.size() && seconds >= 0) {
        return std::max(fallback, std::chrono::seconds(seconds));
    }

    std::tm retry_time{};
    std::istringstream input(value);
    input >> std::get_time(&retry_time, "%a, %d %b %Y %H:%M:%S GMT");
    if (input.fail()) return fallback;
    input >> std::ws;
    if (!input.eof()) return fallback;
    auto retry_point = std::chrono::system_clock::from_time_t(timegm(&retry_time));
    auto delay = std::chrono::duration_cast<std::chrono::seconds>(
        retry_point - std::chrono::system_clock::now());
    return std::max(fallback, std::max(delay, std::chrono::seconds::zero()));
}

void sleep_before_poll(const HttpClientResponse& response,
                       std::chrono::seconds fallback,
                       std::chrono::steady_clock::time_point deadline) {
    auto remaining = std::chrono::duration_cast<std::chrono::seconds>(
        deadline - std::chrono::steady_clock::now());
    if (remaining <= std::chrono::seconds::zero()) return;
    std::this_thread::sleep_for(std::min(retry_after(response, fallback), remaining));
}

std::optional<std::string> absolute_url(std::string_view base, std::string_view reference) {
    if (reference.starts_with("https://") || reference.starts_with("http://"))
        return std::string(reference);
    auto parsed = HttpClient::parse_url(base);
    if (!parsed) return std::nullopt;
    auto origin = parsed->scheme + "://" + parsed->host_header();
    if (reference.empty()) return std::string(base);
    if (reference.front() == '/') return origin + std::string(reference);
    auto slash = parsed->target.rfind('/');
    std::string path = slash == std::string::npos ? "/" : parsed->target.substr(0, slash + 1);
    return origin + path + std::string(reference);
}

std::optional<std::string> base64url_digest(std::string_view data) {
    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
    if (!EVP_Digest(data.data(), data.size(), digest.data(), nullptr, EVP_sha256(), nullptr))
        return std::nullopt;
    return encode_base64url(std::string_view(
        reinterpret_cast<const char*>(digest.data()), digest.size()));
}

bool write_private_file(const std::filesystem::path& path, std::string_view contents) {
    auto temporary = path.string() + ".tmp.XXXXXX";
    std::vector<char> template_path(temporary.begin(), temporary.end());
    template_path.push_back('\0');
    int fd = mkstemp(template_path.data());
    if (fd < 0) return false;
    bool ok = fchmod(fd, 0600) == 0;
    if (ok && fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) ok = false;
    size_t written = 0;
    while (ok && written < contents.size()) {
        ssize_t count = write(fd, contents.data() + written, contents.size() - written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            ok = false;
            break;
        }
        written += static_cast<size_t>(count);
    }
    if (ok && fsync(fd) != 0) ok = false;
    if (close(fd) != 0) ok = false;
    if (ok && rename(template_path.data(), path.c_str()) == 0) return true;
    unlink(template_path.data());
    return false;
}

} // namespace

AcmeClient::AcmeClient(Config config)
    : config_(std::move(config)), http_client_(config_.http) {
    if (config_.use_staging &&
        config_.directory_url == "https://acme-v02.api.letsencrypt.org/directory") {
        config_.directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory";
    }
}

AcmeClient::~AcmeClient() = default;

bool AcmeClient::initialize() {
    if (config_.directory_url.empty() || config_.domains.empty() ||
        config_.authorization_timeout.count() <= 0 ||
        config_.poll_interval.count() <= 0) {
        LOG_ERROR("ACME: invalid directory, domain list, or polling timeout");
        return false;
    }
    for (const auto& domain : config_.domains) {
        if (!valid_domain(domain)) {
            LOG_ERROR("ACME: invalid DNS domain: " + domain);
            return false;
        }
    }

    // Create storage directory
    std::error_code ec;
    std::filesystem::create_directories(config_.storage_path, ec);
    if (ec) {
        LOG_ERROR("ACME: Failed to create storage dir: " + config_.storage_path +
                  ": " + ec.message());
        return false;
    }
    std::filesystem::permissions(config_.storage_path, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace, ec);
    if (ec) {
        LOG_ERROR("ACME: failed to restrict storage directory permissions: " + ec.message());
        return false;
    }

    // Load or generate account key
    auto key = load_account_key();
    if (key) {
        account_key_pem_ = *key;
        LOG_INFO("ACME: Loaded existing account key");
    } else {
        account_key_pem_ = generate_ec_key();
        if (account_key_pem_.empty()) {
            LOG_ERROR("ACME: Failed to generate account key");
            return false;
        }
        if (!save_account_key(account_key_pem_)) {
            LOG_ERROR("ACME: failed to persist account private key");
            return false;
        }
        LOG_INFO("ACME: Generated new EC P-256 account key");
    }

    // Load existing certificates
    for (const auto& domain : config_.domains) {
        auto cert = load_cert(domain);
        if (cert && cert->valid) {
            std::lock_guard lock(certs_mutex_);
            certificates_[domain] = *cert;
            LOG_INFO("ACME: Loaded certificate for " + domain);
        }
    }

    return register_account();
}

bool AcmeClient::obtain_certificates() {
    if (account_key_pem_.empty() || account_kid_.empty()) {
        LOG_ERROR("ACME: initialize must succeed before obtaining certificates");
        return false;
    }
    bool needs_order = false;
    auto now = std::chrono::system_clock::now();
    {
        std::lock_guard lock(certs_mutex_);
        for (const auto& domain : config_.domains) {
            auto it = certificates_.find(domain);
            if (it == certificates_.end() || !it->second.valid) {
                needs_order = true;
                break;
            }
            auto days_until_expiry = std::chrono::duration_cast<std::chrono::hours>(
                it->second.not_after - now).count() / 24;
            if (days_until_expiry <= config_.renew_before_days) {
                needs_order = true;
                break;
            }
        }
    }
    if (!needs_order) return true;
    LOG_INFO("ACME: obtaining a certificate covering all configured domains");
    return create_order(config_.domains.front());
}

bool AcmeClient::check_and_renew() {
    auto now = std::chrono::system_clock::now();
    bool needs_renewal = false;
    {
        std::lock_guard lock(certs_mutex_);
        for (const auto& domain : config_.domains) {
            auto it = certificates_.find(domain);
            if (it == certificates_.end() || !it->second.valid) {
                LOG_INFO("ACME: no valid cached certificate for " + domain + ", obtaining one");
                needs_renewal = true;
                continue;
            }
            auto days_until_expiry = std::chrono::duration_cast<std::chrono::hours>(
                it->second.not_after - now).count() / 24;
            if (days_until_expiry <= config_.renew_before_days) {
                LOG_INFO("ACME: Certificate for " + domain + " expires in " +
                         std::to_string(days_until_expiry) + " days, renewing...");
                needs_renewal = true;
            }
        }
    }
    if (needs_renewal && !create_order(config_.domains.front())) {
        LOG_ERROR("ACME: renewal failed");
        return false;
    }
    return true;
}

std::optional<AcmeClient::CertInfo> AcmeClient::get_certificate(std::string_view domain) const {
    std::lock_guard lock(certs_mutex_);
    auto it = certificates_.find(std::string(domain));
    if (it != certificates_.end()) return it->second;
    return std::nullopt;
}

std::optional<std::string> AcmeClient::handle_challenge(std::string_view token) const {
    std::lock_guard lock(challenges_mutex_);
    auto it = active_challenges_.find(std::string(token));
    if (it != active_challenges_.end()) return it->second;
    return std::nullopt;
}

// === Crypto helpers ===

std::string AcmeClient::generate_ec_key() {
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!ctx) return {};

    std::string result;

    if (EVP_PKEY_keygen_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); return {}; }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) { EVP_PKEY_CTX_free(ctx); return {}; }

    BIO* bio = BIO_new(BIO_s_mem());
    if (bio && PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
        char* data = nullptr;
        long len = BIO_get_mem_data(bio, &data);
        result.assign(data, static_cast<size_t>(len));
    }

    BIO_free(bio);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return result;
}

std::string AcmeClient::create_csr(const std::vector<std::string>& domains,
                                    const std::string& key_pem) {
    if (domains.empty()) return {};
    BIO* key_bio = BIO_new_mem_buf(key_pem.data(), static_cast<int>(key_pem.size()));
    if (!key_bio) return {};

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr);
    BIO_free(key_bio);
    if (!pkey) return {};

    X509_REQ* req = X509_REQ_new();
    if (!req) { EVP_PKEY_free(pkey); return {}; }

    X509_REQ_set_version(req, 0);

    X509_NAME* name = X509_REQ_get_subject_name(req);
    bool ok = X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>(domains.front().c_str()), -1, -1, 0) == 1;
    ok = ok && X509_REQ_set_pubkey(req, pkey) == 1;
    std::string san_names;
    for (const auto& domain : domains) {
        if (!valid_domain(domain)) {
            ok = false;
            break;
        }
        if (!san_names.empty()) san_names += ",";
        san_names += "DNS:" + domain;
    }
    X509_EXTENSION* san = X509V3_EXT_conf_nid(
        nullptr, nullptr, NID_subject_alt_name,
        san_names.data());
    if (san) {
        STACK_OF(X509_EXTENSION)* extensions = sk_X509_EXTENSION_new_null();
        if (extensions && sk_X509_EXTENSION_push(extensions, san) == 1) {
            ok = ok && X509_REQ_add_extensions(req, extensions) == 1;
            sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
        } else {
            X509_EXTENSION_free(san);
            sk_X509_EXTENSION_free(extensions);
            ok = false;
        }
    } else {
        ok = false;
    }
    ok = ok && X509_REQ_sign(req, pkey, EVP_sha256()) > 0;

    BIO* bio = BIO_new(BIO_s_mem());
    std::string result;
    if (ok && bio && i2d_X509_REQ_bio(bio, req)) {
        char* data = nullptr;
        long len = BIO_get_mem_data(bio, &data);
        result.assign(data, static_cast<size_t>(len));
    }

    BIO_free(bio);
    X509_REQ_free(req);
    EVP_PKEY_free(pkey);

    return result;
}

std::string AcmeClient::base64url_encode(std::string_view data) {
    return encode_base64url(data);
}

// === Storage helpers ===

bool AcmeClient::save_cert(const std::string& domain, const CertInfo& cert) {
    if (!valid_domain(domain)) return false;
    auto dir = std::filesystem::path(config_.storage_path) / domain;
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec) return false;
    std::filesystem::permissions(dir, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace, ec);
    if (ec) return false;

    {
        std::ofstream f(dir / "cert.pem", std::ios::binary | std::ios::trunc);
        if (!f) return false;
        f << cert.cert_pem;
        if (!f) return false;
    }
    return write_private_file(dir / "key.pem", cert.key_pem);
}

std::optional<AcmeClient::CertInfo> AcmeClient::load_cert(const std::string& domain) const {
    if (!valid_domain(domain)) return std::nullopt;
    auto dir = std::filesystem::path(config_.storage_path) / domain;
    auto cert_path = dir / "cert.pem";
    auto key_path = dir / "key.pem";

    if (!std::filesystem::exists(cert_path) || !std::filesystem::exists(key_path))
        return std::nullopt;

    CertInfo info;
    info.domain = domain;

    {
        std::ifstream f(cert_path);
        if (!f) return std::nullopt;
        std::ostringstream ss;
        ss << f.rdbuf();
        info.cert_pem = ss.str();
        if (f.bad()) return std::nullopt;
    }
    {
        std::ifstream f(key_path);
        if (!f) return std::nullopt;
        std::ostringstream ss;
        ss << f.rdbuf();
        info.key_pem = ss.str();
        if (f.bad()) return std::nullopt;
    }

    BIO* cert_bio = BIO_new_mem_buf(info.cert_pem.data(), static_cast<int>(info.cert_pem.size()));
    BIO* key_bio = BIO_new_mem_buf(info.key_pem.data(), static_cast<int>(info.key_pem.size()));
    X509* certificate = cert_bio ? PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr) : nullptr;
    EVP_PKEY* private_key = key_bio ? PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr)
                                    : nullptr;
    EVP_PKEY* certificate_key = certificate ? X509_get_pubkey(certificate) : nullptr;
    struct tm expiry_tm{};
    const ASN1_TIME* expiry = certificate ? X509_get0_notAfter(certificate) : nullptr;
    bool parsed = certificate && private_key && certificate_key && expiry &&
                  X509_check_host(certificate, domain.c_str(), domain.size(), 0, nullptr) == 1 &&
                  EVP_PKEY_eq(private_key, certificate_key) == 1 &&
                  ASN1_TIME_to_tm(expiry, &expiry_tm) == 1;
    if (parsed) {
        info.not_after = std::chrono::system_clock::from_time_t(timegm(&expiry_tm));
        info.valid = std::chrono::system_clock::now() < info.not_after;
    }
    EVP_PKEY_free(certificate_key);
    EVP_PKEY_free(private_key);
    X509_free(certificate);
    BIO_free(key_bio);
    BIO_free(cert_bio);

    return info;
}

bool AcmeClient::save_account_key(const std::string& key_pem) {
    auto path = std::filesystem::path(config_.storage_path) / "account_key.pem";
    return write_private_file(path, key_pem);
}

std::optional<std::string> AcmeClient::load_account_key() const {
    auto path = std::filesystem::path(config_.storage_path) / "account_key.pem";
    if (!std::filesystem::exists(path)) return std::nullopt;

    std::ifstream f(path);
    if (!f) return std::nullopt;
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

std::string AcmeClient::account_jwk(const std::string& account_key) {
    BIO* bio = BIO_new_mem_buf(account_key.data(), static_cast<int>(account_key.size()));
    if (!bio) return {};
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) return {};

    std::array<char, 80> group_name{};
    size_t group_name_length = 0;
    bool ok = EVP_PKEY_is_a(pkey, "EC") == 1 && EVP_PKEY_get_bits(pkey) == 256 &&
              EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
                                             group_name.data(), group_name.size(),
                                             &group_name_length) == 1 &&
              (std::string_view(group_name.data()) == "prime256v1" ||
               std::string_view(group_name.data()) == "secp256r1");
    BIGNUM* x = nullptr;
    BIGNUM* y = nullptr;
    ok = ok && EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &x) == 1 &&
         EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &y) == 1;
    std::array<unsigned char, 32> x_bytes{}, y_bytes{};
    ok = ok && BN_bn2binpad(x, x_bytes.data(), static_cast<int>(x_bytes.size())) ==
                   static_cast<int>(x_bytes.size()) &&
         BN_bn2binpad(y, y_bytes.data(), static_cast<int>(y_bytes.size())) ==
                   static_cast<int>(y_bytes.size());
    std::string result;
    if (ok) {
        result = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" +
                 base64url_encode(std::string_view(
                     reinterpret_cast<const char*>(x_bytes.data()), x_bytes.size())) +
                 "\",\"y\":\"" +
                 base64url_encode(std::string_view(
                     reinterpret_cast<const char*>(y_bytes.data()), y_bytes.size())) +
                 "\"}";
    }
    BN_free(x);
    BN_free(y);
    EVP_PKEY_free(pkey);
    return result;
}

std::string AcmeClient::account_thumbprint(const std::string& account_key) {
    auto jwk = account_jwk(account_key);
    if (jwk.empty()) return {};
    return base64url_digest(jwk).value_or("");
}

std::string AcmeClient::create_jws(const std::string& payload, const std::string& url,
                                    const std::string& account_key, const std::string& kid,
                                    const std::string& nonce) {
    if (nonce.empty() || url.empty()) return {};
    std::string protected_json = "{\"alg\":\"ES256\",\"nonce\":" + json_string(nonce) +
                                 ",\"url\":" + json_string(url);
    if (kid.empty()) {
        auto jwk = account_jwk(account_key);
        if (jwk.empty()) return {};
        protected_json += ",\"jwk\":" + jwk;
    } else {
        protected_json += ",\"kid\":" + json_string(kid);
    }
    protected_json += "}";
    auto protected64 = base64url_encode(protected_json);
    auto payload64 = base64url_encode(payload);
    std::string signing_input = protected64 + "." + payload64;

    BIO* bio = BIO_new_mem_buf(account_key.data(), static_cast<int>(account_key.size()));
    if (!bio) return {};
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) return {};
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    size_t signature_size = 0;
    bool ok = context && EVP_DigestSignInit(context, nullptr, EVP_sha256(), nullptr, pkey) == 1 &&
              EVP_DigestSignUpdate(context, signing_input.data(), signing_input.size()) == 1 &&
              EVP_DigestSignFinal(context, nullptr, &signature_size) == 1;
    std::vector<unsigned char> der(signature_size);
    ok = ok && EVP_DigestSignFinal(context, der.data(), &signature_size) == 1;
    der.resize(signature_size);
    const unsigned char* der_cursor = der.data();
    ECDSA_SIG* ecdsa_sig = ok ? d2i_ECDSA_SIG(nullptr, &der_cursor,
                                               static_cast<long>(der.size())) : nullptr;
    std::array<unsigned char, 64> raw_signature{};
    if (!ecdsa_sig) {
        ok = false;
    } else {
        const BIGNUM* r = nullptr;
        const BIGNUM* s = nullptr;
        ECDSA_SIG_get0(ecdsa_sig, &r, &s);
        ok = BN_bn2binpad(r, raw_signature.data(), 32) == 32 &&
             BN_bn2binpad(s, raw_signature.data() + 32, 32) == 32;
    }
    std::string result;
    if (ok) {
        result = "{\"protected\":" + json_string(protected64) +
                 ",\"payload\":" + json_string(payload64) +
                 ",\"signature\":\"" +
                 base64url_encode(std::string_view(
                     reinterpret_cast<const char*>(raw_signature.data()), raw_signature.size())) +
                 "\"}";
    }
    ECDSA_SIG_free(ecdsa_sig);
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(pkey);
    return result;
}

bool AcmeClient::refresh_nonce() {
    if (new_nonce_url_.empty()) {
        LOG_ERROR("ACME: directory did not provide newNonce");
        return false;
    }
    auto response = http_client_.head(new_nonce_url_);
    if (!response) {
        LOG_ERROR("ACME: nonce request failed: " + http_client_.last_error());
        return false;
    }
    if (response->status < 200 || response->status >= 400) {
        LOG_ERROR("ACME: nonce request failed: " + acme_error(*response));
        return false;
    }
    nonce_ = response->header("Replay-Nonce");
    if (nonce_.empty()) {
        LOG_ERROR("ACME: nonce response is missing Replay-Nonce");
        return false;
    }
    return true;
}

std::optional<HttpClientResponse> AcmeClient::signed_post(const std::string& url,
                                                           std::string_view payload) {
    if (nonce_.empty() && !refresh_nonce()) return std::nullopt;
    auto jws = create_jws(std::string(payload), url, account_key_pem_, account_kid_, nonce_);
    if (jws.empty()) {
        LOG_ERROR("ACME: failed to sign request for " + url);
        return std::nullopt;
    }
    nonce_.clear();
    auto response = http_client_.request("POST", url,
        {{"Content-Type", "application/jose+json"}}, jws);
    if (!response) {
        LOG_ERROR("ACME: POST " + url + " failed: " + http_client_.last_error());
        return std::nullopt;
    }
    nonce_ = response->header("Replay-Nonce");
    return response;
}

bool AcmeClient::register_account() {
    auto directory_response = http_client_.get(config_.directory_url);
    if (!directory_response || !successful_status(*directory_response)) {
        LOG_ERROR("ACME: directory fetch failed: " +
                  (directory_response ? acme_error(*directory_response)
                                      : http_client_.last_error()));
        return false;
    }
    auto directory = JsonParser(directory_response->body).parse();
    if (!directory) {
        LOG_ERROR("ACME: directory response is invalid JSON");
        return false;
    }
    auto endpoint = [&](std::string_view key) -> std::string {
        const auto* value = directory->get(key);
        if (!value) return {};
        auto ref = value->string();
        auto resolved = absolute_url(config_.directory_url, ref);
        return resolved.value_or("");
    };
    new_nonce_url_ = endpoint("newNonce");
    new_account_url_ = endpoint("newAccount");
    new_order_url_ = endpoint("newOrder");
    if (new_nonce_url_.empty() || new_account_url_.empty() || new_order_url_.empty()) {
        LOG_ERROR("ACME: directory is missing required endpoints");
        return false;
    }
    nonce_ = directory_response->header("Replay-Nonce");
    if (nonce_.empty() && !refresh_nonce()) return false;

    std::string payload = "{\"termsOfServiceAgreed\":true";
    if (!config_.email.empty()) {
        payload += ",\"contact\":[" + json_string("mailto:" + config_.email) + "]";
    }
    payload += "}";
    auto response = signed_post(new_account_url_, payload);
    if (!response || (response->status != 200 && response->status != 201)) {
        LOG_ERROR("ACME: account registration failed: " +
                  (response ? acme_error(*response) : http_client_.last_error()));
        return false;
    }
    account_kid_ = response->header("Location");
    if (account_kid_.empty()) {
        LOG_ERROR("ACME: account response is missing Location");
        return false;
    }
    if (auto resolved = absolute_url(new_account_url_, account_kid_)) account_kid_ = *resolved;
    LOG_INFO("ACME: registered account " + account_kid_);
    return true;
}

bool AcmeClient::valid_domain(std::string_view domain) {
    if (domain.empty() || domain.size() > 253 || domain.front() == '.' ||
        domain.back() == '.' || domain.find("..") != std::string_view::npos ||
        domain.find('*') != std::string_view::npos) return false;
    size_t start = 0;
    while (start < domain.size()) {
        size_t end = domain.find('.', start);
        if (end == std::string_view::npos) end = domain.size();
        auto label = domain.substr(start, end - start);
        if (label.empty() || label.size() > 63 || label.front() == '-' || label.back() == '-')
            return false;
        for (unsigned char ch : label) {
            if (!(std::isalnum(ch) || ch == '-')) return false;
        }
        start = end + 1;
    }
    return true;
}

bool AcmeClient::create_order(const std::string& domain) {
    if (!valid_domain(domain)) {
        LOG_ERROR("ACME: invalid domain " + domain);
        return false;
    }
    LOG_INFO("ACME: creating order for " + domain);
    current_domain_key_pem_ = generate_ec_key();
    if (current_domain_key_pem_.empty()) {
        LOG_ERROR("ACME: failed to generate certificate private key");
        return false;
    }
    current_order_url_.clear();
    current_finalize_url_.clear();
    current_certificate_url_.clear();

    std::string payload = "{\"identifiers\":[";
    for (size_t i = 0; i < config_.domains.size(); ++i) {
        if (i) payload += ",";
        payload += "{\"type\":\"dns\",\"value\":" + json_string(config_.domains[i]) + "}";
    }
    payload += "]}";
    auto response = signed_post(new_order_url_, payload);
    if (!response || (response->status != 200 && response->status != 201)) {
        LOG_ERROR("ACME: order creation failed: " +
                  (response ? acme_error(*response) : http_client_.last_error()));
        return false;
    }
    auto order = JsonParser(response->body).parse();
    if (!order) {
        LOG_ERROR("ACME: invalid order JSON");
        return false;
    }
    auto order_location = response->header("Location");
    if (!order_location.empty()) {
        auto resolved = absolute_url(new_order_url_, order_location);
        current_order_url_ = resolved.value_or("");
    }
    const auto* finalize = order->get("finalize");
    const auto* authorizations = order->get("authorizations");
    if (finalize) current_finalize_url_ = absolute_url(new_order_url_, finalize->string()).value_or("");
    if (current_order_url_.empty() || current_finalize_url_.empty() || !authorizations ||
        !authorizations->array()) {
        LOG_ERROR("ACME: order response is missing its location, finalize URL, or authorizations");
        return false;
    }

    auto thumbprint = account_thumbprint(account_key_pem_);
    if (thumbprint.empty()) {
        LOG_ERROR("ACME: failed to calculate account key thumbprint");
        return false;
    }
    for (const auto& authorization_ref : *authorizations->array()) {
        auto authorization_url = absolute_url(new_order_url_, authorization_ref.string());
        if (!authorization_url) {
            LOG_ERROR("ACME: invalid authorization URL");
            return false;
        }
        auto auth_response = signed_post(*authorization_url, "");
        if (!auth_response || !successful_status(*auth_response)) {
            LOG_ERROR("ACME: authorization fetch failed: " +
                      (auth_response ? acme_error(*auth_response) : http_client_.last_error()));
            return false;
        }
        auto authorization = JsonParser(auth_response->body).parse();
        if (!authorization) {
            LOG_ERROR("ACME: invalid authorization JSON");
            return false;
        }
        const auto* status = authorization->get("status");
        if (status && status->string() == "valid") continue;
        if (status && (status->string() == "invalid" || status->string() == "deactivated" ||
                       status->string() == "revoked" || status->string() == "expired")) {
            LOG_ERROR("ACME: authorization is " + status->string() + " for " + domain);
            return false;
        }
        const auto* identifier = authorization->get("identifier");
        const auto* identifier_value = identifier ? identifier->get("value") : nullptr;
        auto authorization_domain = identifier_value ? identifier_value->string() : std::string{};
        if (!valid_domain(authorization_domain) ||
            std::find(config_.domains.begin(), config_.domains.end(), authorization_domain) ==
                config_.domains.end()) {
            LOG_ERROR("ACME: authorization returned an unexpected domain");
            return false;
        }
        const auto* challenges = authorization->get("challenges");
        if (!challenges || !challenges->array()) {
            LOG_ERROR("ACME: authorization has no challenges");
            return false;
        }
        bool solved = false;
        for (const auto& challenge : *challenges->array()) {
            const auto* type = challenge.get("type");
            if (!type || type->string() != "http-01") continue;
            const auto* token_value = challenge.get("token");
            const auto* url_value = challenge.get("url");
            if (!token_value || !url_value) continue;
            auto token = token_value->string();
            if (token.empty() || token.size() > 256 ||
                !std::all_of(token.begin(), token.end(), [](unsigned char ch) {
                    return std::isalnum(ch) || ch == '-' || ch == '_';
                })) {
                LOG_ERROR("ACME: challenge has an invalid token");
                return false;
            }
            auto challenge_url = absolute_url(*authorization_url, url_value->string());
            if (!challenge_url) return false;
            if (!solve_http01_challenge(authorization_domain, token, token + "." + thumbprint,
                                        *challenge_url, *authorization_url)) {
                return false;
            }
            solved = true;
            break;
        }
        if (!solved) {
            LOG_ERROR("ACME: authorization does not offer HTTP-01");
            return false;
        }
    }
    if (!finalize_order(domain)) return false;
    return download_certificate(domain);
}

bool AcmeClient::solve_http01_challenge(const std::string& domain, const std::string& token,
                                         const std::string& key_authorization,
                                         const std::string& challenge_url,
                                         const std::string& authorization_url) {
    LOG_INFO("ACME: publishing HTTP-01 challenge for " + domain);
    {
        std::lock_guard lock(challenges_mutex_);
        active_challenges_[token] = key_authorization;
    }
    auto response = signed_post(challenge_url, "{}");
    if (!response || (response->status != 200 && response->status != 202)) {
        std::lock_guard lock(challenges_mutex_);
        active_challenges_.erase(token);
        LOG_ERROR("ACME: challenge acknowledgement failed: " +
                  (response ? acme_error(*response) : http_client_.last_error()));
        return false;
    }
    bool valid = wait_for_authorization(domain, authorization_url);
    {
        std::lock_guard lock(challenges_mutex_);
        active_challenges_.erase(token);
    }
    return valid;
}

bool AcmeClient::wait_for_authorization(const std::string& domain,
                                         const std::string& authorization_url) {
    auto deadline = std::chrono::steady_clock::now() + config_.authorization_timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        auto response = signed_post(authorization_url, "");
        if (!response || !successful_status(*response)) {
            LOG_ERROR("ACME: authorization polling failed for " + domain + ": " +
                      (response ? acme_error(*response) : http_client_.last_error()));
            return false;
        }
        auto authorization = JsonParser(response->body).parse();
        if (!authorization) {
            LOG_ERROR("ACME: invalid authorization response while polling");
            return false;
        }
        const auto* status = authorization->get("status");
        if (status && status->string() == "valid") return true;
        if (status && (status->string() == "invalid" || status->string() == "deactivated" ||
                       status->string() == "revoked" || status->string() == "expired")) {
            LOG_ERROR("ACME: authorization became " + status->string() + " for " + domain);
            return false;
        }
        sleep_before_poll(*response, config_.poll_interval, deadline);
    }
    LOG_ERROR("ACME: authorization timed out for " + domain);
    return false;
}

bool AcmeClient::finalize_order(const std::string& domain) {
    std::string csr = create_csr(config_.domains, current_domain_key_pem_);
    if (csr.empty()) {
        LOG_ERROR("ACME: failed to create CSR for " + domain);
        return false;
    }
    auto payload = "{\"csr\":\"" + base64url_encode(csr) + "\"}";
    auto response = signed_post(current_finalize_url_, payload);
    if (!response || !successful_status(*response)) {
        LOG_ERROR("ACME: order finalization failed for " + domain + ": " +
                  (response ? acme_error(*response) : http_client_.last_error()));
        return false;
    }
    auto order = JsonParser(response->body).parse();
    if (order) {
        if (const auto* cert = order->get("certificate")) {
            current_certificate_url_ = absolute_url(current_order_url_, cert->string()).value_or("");
        }
    }
    if (!wait_for_order(domain, "valid")) return false;
    return !current_certificate_url_.empty();
}

bool AcmeClient::wait_for_order(const std::string& domain, std::string_view expected_status) {
    auto deadline = std::chrono::steady_clock::now() + config_.authorization_timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        auto response = signed_post(current_order_url_, "");
        if (!response || !successful_status(*response)) {
            LOG_ERROR("ACME: order polling failed for " + domain + ": " +
                      (response ? acme_error(*response) : http_client_.last_error()));
            return false;
        }
        auto order = JsonParser(response->body).parse();
        if (!order) {
            LOG_ERROR("ACME: invalid order response while polling");
            return false;
        }
        const auto* status = order->get("status");
        if (status && status->string() == expected_status) {
            const auto* certificate = order->get("certificate");
            if (certificate) {
                current_certificate_url_ =
                    absolute_url(current_order_url_, certificate->string()).value_or("");
            }
            return true;
        }
        if (status && (status->string() == "invalid" || status->string() == "expired" ||
                       status->string() == "deactivated")) {
            LOG_ERROR("ACME: order became " + status->string() + " for " + domain);
            return false;
        }
        sleep_before_poll(*response, config_.poll_interval, deadline);
    }
    LOG_ERROR("ACME: order timed out for " + domain);
    return false;
}

bool AcmeClient::download_certificate(const std::string& domain) {
    if (current_certificate_url_.empty()) {
        LOG_ERROR("ACME: certificate URL is missing for " + domain);
        return false;
    }
    auto response = signed_post(current_certificate_url_, "");
    if (!response || !successful_status(*response)) {
        LOG_ERROR("ACME: certificate download failed for " + domain + ": " +
                  (response ? acme_error(*response) : http_client_.last_error()));
        return false;
    }
    BIO* cert_bio = BIO_new_mem_buf(response->body.data(),
                                    static_cast<int>(response->body.size()));
    BIO* key_bio = BIO_new_mem_buf(current_domain_key_pem_.data(),
                                   static_cast<int>(current_domain_key_pem_.size()));
    X509* certificate = cert_bio ? PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr) : nullptr;
    EVP_PKEY* private_key = key_bio ? PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr) : nullptr;
    bool valid = certificate && private_key;
    for (const auto& configured_domain : config_.domains) {
        valid = valid && X509_check_host(certificate, configured_domain.c_str(),
                                         configured_domain.size(), 0, nullptr) == 1;
    }
    EVP_PKEY* certificate_key = certificate ? X509_get_pubkey(certificate) : nullptr;
    valid = valid && certificate_key && EVP_PKEY_eq(private_key, certificate_key) == 1;
    struct tm expiry_tm{};
    const ASN1_TIME* expiry = certificate ? X509_get0_notAfter(certificate) : nullptr;
    valid = valid && expiry && ASN1_TIME_to_tm(expiry, &expiry_tm) == 1;
    if (!valid) {
        LOG_ERROR("ACME: downloaded certificate is invalid or does not match " + domain);
        EVP_PKEY_free(certificate_key);
        EVP_PKEY_free(private_key);
        X509_free(certificate);
        BIO_free(key_bio);
        BIO_free(cert_bio);
        return false;
    }

    CertInfo info;
    info.cert_pem = response->body;
    info.key_pem = current_domain_key_pem_;
    info.not_after = std::chrono::system_clock::from_time_t(timegm(&expiry_tm));
    info.valid = info.not_after > std::chrono::system_clock::now();
    EVP_PKEY_free(certificate_key);
    EVP_PKEY_free(private_key);
    X509_free(certificate);
    BIO_free(key_bio);
    BIO_free(cert_bio);
    if (!info.valid) {
        LOG_ERROR("ACME: certificate expired or could not be stored for " + domain);
        return false;
    }
    for (const auto& configured_domain : config_.domains) {
        info.domain = configured_domain;
        if (!save_cert(configured_domain, info)) {
            LOG_ERROR("ACME: failed to store certificate for " + configured_domain);
            return false;
        }
        {
            std::lock_guard lock(certs_mutex_);
            certificates_[configured_domain] = info;
        }
        if (cert_updated_cb_) cert_updated_cb_(configured_domain, info);
        LOG_INFO("ACME: certificate installed for " + configured_domain);
    }
    return true;
}

} // namespace js
