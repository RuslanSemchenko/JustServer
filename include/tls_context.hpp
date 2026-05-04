#pragma once

#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>

namespace js {

class TLSContext {
public:
    TLSContext();
    ~TLSContext();

    // Non-copyable
    TLSContext(const TLSContext&) = delete;
    TLSContext& operator=(const TLSContext&) = delete;

    // Initialize with cert and key files
    bool init(const std::string& cert_path, const std::string& key_path);

    // Wrap a raw socket fd into an SSL connection
    SSL* wrap_socket(int fd);

    // Get the raw SSL_CTX
    SSL_CTX* native() const { return ctx_; }

private:
    SSL_CTX* ctx_ = nullptr;
};

} // namespace js
