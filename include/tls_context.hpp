#pragma once

#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>

namespace js {

enum class NegotiatedProtocol {
    HTTP_1_1,
    HTTP_2,
    UNKNOWN,
};

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

    // Get the negotiated ALPN protocol after handshake
    static NegotiatedProtocol get_negotiated_protocol(SSL* ssl);

    // Get the raw SSL_CTX
    SSL_CTX* native() const { return ctx_; }

private:
    // ALPN selection callback
    static int alpn_select_callback(SSL* ssl, const unsigned char** out,
                                    unsigned char* outlen,
                                    const unsigned char* in, unsigned int inlen,
                                    void* arg);

    SSL_CTX* ctx_ = nullptr;
};

} // namespace js
