#include "stream.hpp"

#include <sys/socket.h>
#include <unistd.h>
#include <cstring>

// OpenSSL functions for TlsStream -- we use the real SSL type via cast
#include <openssl/ssl.h>

namespace js {

// === TcpStream ===

ssize_t TcpStream::read(void* buf, size_t max_bytes) {
    if (fd_ < 0) return -1;
    return ::recv(fd_, buf, max_bytes, 0);
}

ssize_t TcpStream::write(const void* buf, size_t len) {
    if (fd_ < 0) return -1;
    return ::send(fd_, buf, len, MSG_NOSIGNAL);
}

void TcpStream::shutdown() {
    if (fd_ >= 0) {
        ::shutdown(fd_, SHUT_RDWR);
    }
}

void TcpStream::close() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

// === TlsStream ===

ssize_t TlsStream::read(void* buf, size_t max_bytes) {
    if (!ssl_) return -1;
    auto* s = static_cast<SSL*>(ssl_);
    int n = SSL_read(s, buf, static_cast<int>(max_bytes));
    if (n <= 0) {
        int err = SSL_get_error(s, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            return 0; // Would block
        return -1;
    }
    return n;
}

ssize_t TlsStream::write(const void* buf, size_t len) {
    if (!ssl_) return -1;
    auto* s = static_cast<SSL*>(ssl_);
    int n = SSL_write(s, buf, static_cast<int>(len));
    if (n <= 0) {
        int err = SSL_get_error(s, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            return 0;
        return -1;
    }
    return n;
}

void TlsStream::shutdown() {
    if (ssl_) {
        SSL_shutdown(static_cast<SSL*>(ssl_));
    }
}

void TlsStream::close() {
    if (ssl_) {
        SSL_shutdown(static_cast<SSL*>(ssl_));
        SSL_free(static_cast<SSL*>(ssl_));
        ssl_ = nullptr;
    }
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

// === H2VirtualStream ===

ssize_t H2VirtualStream::read(void* buf, size_t max_bytes) {
    if (!open_ || read_offset_ >= read_buffer_.size()) return 0;

    size_t available = read_buffer_.size() - read_offset_;
    size_t to_copy = (max_bytes < available) ? max_bytes : available;
    std::memcpy(buf, read_buffer_.data() + read_offset_, to_copy);
    read_offset_ += to_copy;

    // Compact if we've consumed everything
    if (read_offset_ == read_buffer_.size()) {
        read_buffer_.clear();
        read_offset_ = 0;
    }

    return static_cast<ssize_t>(to_copy);
}

ssize_t H2VirtualStream::write(const void* buf, size_t len) {
    if (!open_ || !write_fn_) return -1;
    bool ok = write_fn_(stream_id_, buf, len);
    return ok ? static_cast<ssize_t>(len) : -1;
}

void H2VirtualStream::feed_data(std::span<const uint8_t> data) {
    read_buffer_.append(reinterpret_cast<const char*>(data.data()), data.size());
}

// === QuicStream (stub -- real implementation requires ngtcp2/nghttp3) ===

ssize_t QuicStream::read([[maybe_unused]] void* buf, [[maybe_unused]] size_t max_bytes) {
    // TODO: Implement with ngtcp2 when QUIC transport is integrated
    return -1;
}

ssize_t QuicStream::write([[maybe_unused]] const void* buf, [[maybe_unused]] size_t len) {
    // TODO: Implement with ngtcp2
    return -1;
}

void QuicStream::shutdown() {
    open_ = false;
}

void QuicStream::close() {
    open_ = false;
    quic_conn_ = nullptr;
}

} // namespace js
