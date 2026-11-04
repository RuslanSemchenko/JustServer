#include "stream.hpp"

#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <cerrno>
#include <algorithm>
#include <limits>

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

// === QuicStream ===

ssize_t QuicStream::read(void* buf, size_t max_bytes) {
    if (!open_) {
        errno = EBADF;
        return -1;
    }
    if (!buf && max_bytes > 0) {
        errno = EINVAL;
        return -1;
    }
    if (max_bytes == 0) return 0;
    if (read_offset_ == read_buffer_.size()) {
        read_buffer_.clear();
        read_offset_ = 0;
        if (read_finished_) return 0;
        errno = EAGAIN;
        return -1;
    }
    size_t count = std::min(max_bytes, read_buffer_.size() - read_offset_);
    std::memcpy(buf, read_buffer_.data() + read_offset_, count);
    read_offset_ += count;
    if (read_offset_ == read_buffer_.size()) {
        read_buffer_.clear();
        read_offset_ = 0;
    }
    return static_cast<ssize_t>(count);
}

ssize_t QuicStream::write(const void* buf, size_t len) {
    if (!open_ || write_shutdown_ || !write_fn_) {
        errno = EPIPE;
        return -1;
    }
    if (len == 0) return 0;
    if (!buf || len > static_cast<size_t>(std::numeric_limits<ssize_t>::max())) {
        errno = EINVAL;
        return -1;
    }
    if (!write_fn_(stream_id_, buf, len)) {
        if (errno == 0) errno = EAGAIN;
        return -1;
    }
    return static_cast<ssize_t>(len);
}

void QuicStream::shutdown() {
    if (write_shutdown_) return;
    write_shutdown_ = true;
    if (shutdown_fn_) shutdown_fn_(stream_id_);
    if (read_finished_) open_ = false;
}

void QuicStream::close() {
    shutdown();
    open_ = false;
    read_finished_ = true;
    write_shutdown_ = true;
    read_buffer_.clear();
    read_offset_ = 0;
}

bool QuicStream::feed_data(std::span<const uint8_t> data) {
    if (!open_ || read_finished_) return false;
    if (data.empty()) return true;
    size_t buffered = read_buffer_.size() - read_offset_;
    if (data.size() > max_buffer_bytes_ - std::min(max_buffer_bytes_, buffered)) {
        errno = ENOBUFS;
        return false;
    }
    if (read_offset_ > 0) {
        read_buffer_.erase(0, read_offset_);
        read_offset_ = 0;
    }
    read_buffer_.append(reinterpret_cast<const char*>(data.data()), data.size());
    return true;
}

void QuicStream::finish_read() {
    read_finished_ = true;
    if (write_shutdown_) open_ = false;
}

} // namespace js
