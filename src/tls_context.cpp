#include "tls_context.hpp"
#include "anti_bot.hpp"
#include "logger.hpp"

#include <poll.h>
#include <ctime>
#include <cstring>

namespace js {

TLSContext::TLSContext() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}

TLSContext::~TLSContext() {
    std::lock_guard lock(ctx_mutex_);
    SSL_CTX_free(ctx_);
}

int TLSContext::alpn_select_callback(
    [[maybe_unused]] SSL* ssl,
    const unsigned char** out, unsigned char* outlen,
    const unsigned char* in, unsigned int inlen,
    [[maybe_unused]] void* arg)
{
    // Prefer h2, fallback to http/1.1
    // ALPN wire format: length-prefixed strings
    static const unsigned char h2[] = {2, 'h', '2'};
    static const unsigned char h1[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};

    // First pass: look for "h2"
    for (unsigned int i = 0; i < inlen; ) {
        unsigned int proto_len = in[i];
        if (i + 1 + proto_len > inlen) break;
        if (proto_len == 2 && std::memcmp(&in[i + 1], "h2", 2) == 0) {
            *out = &in[i + 1];
            *outlen = static_cast<unsigned char>(proto_len);
            return SSL_TLSEXT_ERR_OK;
        }
        i += 1 + proto_len;
    }

    // Second pass: look for "http/1.1"
    for (unsigned int i = 0; i < inlen; ) {
        unsigned int proto_len = in[i];
        if (i + 1 + proto_len > inlen) break;
        if (proto_len == 8 && std::memcmp(&in[i + 1], "http/1.1", 8) == 0) {
            *out = &in[i + 1];
            *outlen = static_cast<unsigned char>(proto_len);
            return SSL_TLSEXT_ERR_OK;
        }
        i += 1 + proto_len;
    }

    // Suppress unused variable warnings for the wire-format constants
    (void)h2;
    (void)h1;

    // No matching protocol - fall back to HTTP/1.1 behavior
    return SSL_TLSEXT_ERR_NOACK;
}

NegotiatedProtocol TLSContext::get_negotiated_protocol(SSL* ssl) {
    if (!ssl) return NegotiatedProtocol::HTTP_1_1;

    const unsigned char* proto = nullptr;
    unsigned int proto_len = 0;
    SSL_get0_alpn_selected(ssl, &proto, &proto_len);

    if (proto && proto_len == 2 && std::memcmp(proto, "h2", 2) == 0) {
        return NegotiatedProtocol::HTTP_2;
    }
    return NegotiatedProtocol::HTTP_1_1;
}

bool TLSContext::init(const std::string& cert_path, const std::string& key_path) {
    SSL_CTX* new_ctx = SSL_CTX_new(TLS_server_method());
    if (!new_ctx) {
        LOG_ERROR("Failed to create SSL context");
        return false;
    }

    // Enforce TLS 1.3+ (ALPN h2 negotiation works fine with TLS 1.3)
    if (SSL_CTX_set_min_proto_version(new_ctx, TLS1_3_VERSION) != 1) {
        LOG_ERROR("Failed to set minimum TLS protocol version");
        SSL_CTX_free(new_ctx);
        return false;
    }

    // Disable weak ciphers - TLS 1.3 ciphersuites only
    if (SSL_CTX_set_ciphersuites(new_ctx,
            "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256") != 1) {
        LOG_ERROR("Failed to set TLS 1.3 ciphersuites");
        SSL_CTX_free(new_ctx);
        return false;
    }

    // Setup ALPN callback for h2 / http/1.1 negotiation
    SSL_CTX_set_alpn_select_cb(new_ctx, alpn_select_callback, nullptr);
    install_ja3_client_hello_capture(new_ctx);

    // Load certificate
    if (SSL_CTX_use_certificate_file(new_ctx, cert_path.c_str(), SSL_FILETYPE_PEM) != 1) {
        LOG_ERROR("Failed to load certificate: " + cert_path);
        SSL_CTX_free(new_ctx);
        return false;
    }

    // Load private key
    if (SSL_CTX_use_PrivateKey_file(new_ctx, key_path.c_str(), SSL_FILETYPE_PEM) != 1) {
        LOG_ERROR("Failed to load private key: " + key_path);
        SSL_CTX_free(new_ctx);
        return false;
    }

    // Verify key matches certificate
    if (SSL_CTX_check_private_key(new_ctx) != 1) {
        LOG_ERROR("Certificate and private key do not match");
        SSL_CTX_free(new_ctx);
        return false;
    }

    SSL_CTX* old_ctx = nullptr;
    {
        std::lock_guard lock(ctx_mutex_);
        old_ctx = ctx_;
        ctx_ = new_ctx;
    }
    SSL_CTX_free(old_ctx);
    LOG_INFO("TLS context initialized (TLS 1.3 only) with ALPN (h2, http/1.1)");
    return true;
}

SSL_CTX* TLSContext::native() const {
    std::lock_guard lock(ctx_mutex_);
    return ctx_;
}

SSL* TLSContext::wrap_socket(int fd) {
    SSL* ssl = nullptr;
    {
        std::lock_guard lock(ctx_mutex_);
        if (ctx_) ssl = SSL_new(ctx_);
    }
    if (!ssl) return nullptr;

    SSL_set_fd(ssl, fd);

    // Retry loop: SSL_accept may return WANT_READ/WANT_WRITE on non-blocking fds.
    // Track elapsed time cumulatively so a slow-loris client cannot reset the
    // timeout by trickling just enough data to trigger WANT_READ each iteration.
    constexpr int handshake_timeout_ms = 5000;

    struct timespec deadline_ts{};
    clock_gettime(CLOCK_MONOTONIC, &deadline_ts);
    const auto deadline_ms = static_cast<long long>(deadline_ts.tv_sec) * 1000
                           + deadline_ts.tv_nsec / 1000000
                           + handshake_timeout_ms;

    while (true) {
        int ret = SSL_accept(ssl);
        if (ret == 1) {
            return ssl; // Handshake completed successfully
        }

        int ssl_err = SSL_get_error(ssl, ret);
        if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
            struct timespec now_ts{};
            clock_gettime(CLOCK_MONOTONIC, &now_ts);
            const auto now_ms = static_cast<long long>(now_ts.tv_sec) * 1000
                              + now_ts.tv_nsec / 1000000;
            int remaining_ms = static_cast<int>(deadline_ms - now_ms);
            if (remaining_ms <= 0) {
                LOG_WARN("TLS handshake timed out (cumulative deadline exceeded)");
                SSL_free(ssl);
                return nullptr;
            }

            struct pollfd pfd{};
            pfd.fd = fd;
            pfd.events = (ssl_err == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;

            int poll_ret = poll(&pfd, 1, remaining_ms);
            if (poll_ret <= 0) {
                LOG_WARN("TLS handshake timed out or poll error");
                SSL_free(ssl);
                return nullptr;
            }
            continue;
        }

        // Any other error is a real failure
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        LOG_WARN(std::string("TLS handshake failed: ") + err_buf);
        SSL_free(ssl);
        return nullptr;
    }
}

} // namespace js
