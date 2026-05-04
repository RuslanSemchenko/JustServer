#include "tls_context.hpp"
#include "logger.hpp"

#include <poll.h>
#include <ctime>

namespace js {

TLSContext::TLSContext() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}

TLSContext::~TLSContext() {
    if (ctx_) {
        SSL_CTX_free(ctx_);
    }
}

bool TLSContext::init(const std::string& cert_path, const std::string& key_path) {
    ctx_ = SSL_CTX_new(TLS_server_method());
    if (!ctx_) {
        LOG_ERROR("Failed to create SSL context");
        return false;
    }

    // Enforce TLS 1.3 only
    SSL_CTX_set_min_proto_version(ctx_, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx_, TLS1_3_VERSION);

    // Disable weak ciphers - TLS 1.3 ciphersuites only
    if (SSL_CTX_set_ciphersuites(ctx_,
            "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256") != 1) {
        LOG_ERROR("Failed to set TLS 1.3 ciphersuites");
        return false;
    }

    // Load certificate
    if (SSL_CTX_use_certificate_file(ctx_, cert_path.c_str(), SSL_FILETYPE_PEM) != 1) {
        LOG_ERROR("Failed to load certificate: " + cert_path);
        return false;
    }

    // Load private key
    if (SSL_CTX_use_PrivateKey_file(ctx_, key_path.c_str(), SSL_FILETYPE_PEM) != 1) {
        LOG_ERROR("Failed to load private key: " + key_path);
        return false;
    }

    // Verify key matches certificate
    if (SSL_CTX_check_private_key(ctx_) != 1) {
        LOG_ERROR("Certificate and private key do not match");
        return false;
    }

    LOG_INFO("TLS context initialized (TLS 1.3 only)");
    return true;
}

SSL* TLSContext::wrap_socket(int fd) {
    if (!ctx_) return nullptr;

    SSL* ssl = SSL_new(ctx_);
    if (!ssl) return nullptr;

    SSL_set_fd(ssl, fd);

    // Retry loop: SSL_accept may return WANT_READ/WANT_WRITE on non-blocking fds
    // (accepted via accept4 on a non-blocking listener). Use poll() to wait for
    // the fd to become ready before retrying.
    //
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
                // Timeout or error -- give up
                LOG_WARN("TLS handshake timed out or poll error");
                SSL_free(ssl);
                return nullptr;
            }
            // fd is ready, retry SSL_accept
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
