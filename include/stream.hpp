#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <functional>
#include <memory>

namespace js {

// Universal Stream Interface (IStream)
// Decouples request processing logic from the underlying transport.
// HTTP/1.1 sockets, HTTP/2 streams, and QUIC streams all implement this.
class IStream {
public:
    virtual ~IStream() = default;

    // Read up to max_bytes into buf. Returns bytes read, 0 on EOF, -1 on error.
    virtual ssize_t read(void* buf, size_t max_bytes) = 0;

    // Write data. Returns bytes written, -1 on error.
    virtual ssize_t write(const void* buf, size_t len) = 0;

    // Write entire buffer (loop internally). Returns true on success.
    virtual bool write_all(const void* buf, size_t len) {
        auto* p = static_cast<const uint8_t*>(buf);
        size_t sent = 0;
        while (sent < len) {
            auto n = write(p + sent, len - sent);
            if (n <= 0) return false;
            sent += static_cast<size_t>(n);
        }
        return true;
    }

    bool write_all(std::string_view sv) {
        return write_all(sv.data(), sv.size());
    }

    // Shutdown the stream (graceful close)
    virtual void shutdown() = 0;

    // Close the stream (immediate)
    virtual void close() = 0;

    // Is the stream still open for reading/writing?
    virtual bool is_open() const = 0;

    // Get the underlying file descriptor (if applicable, -1 otherwise)
    virtual int fd() const { return -1; }

    // Get the peer address as a string (IP:port or similar)
    virtual std::string peer_address() const { return "unknown"; }

    // Get the stream type for logging/debugging
    virtual std::string_view stream_type() const = 0;
};

// Plain TCP stream wrapping a raw socket fd
class TcpStream : public IStream {
public:
    explicit TcpStream(int socket_fd, std::string peer_addr = "")
        : fd_(socket_fd), peer_addr_(std::move(peer_addr)) {}

    ~TcpStream() override { close(); }

    // Non-copyable
    TcpStream(const TcpStream&) = delete;
    TcpStream& operator=(const TcpStream&) = delete;

    // Movable
    TcpStream(TcpStream&& other) noexcept
        : fd_(other.fd_), peer_addr_(std::move(other.peer_addr_)) {
        other.fd_ = -1;
    }

    ssize_t read(void* buf, size_t max_bytes) override;
    ssize_t write(const void* buf, size_t len) override;
    void shutdown() override;
    void close() override;
    bool is_open() const override { return fd_ >= 0; }
    int fd() const override { return fd_; }
    std::string peer_address() const override { return peer_addr_; }
    std::string_view stream_type() const override { return "tcp"; }

private:
    int fd_ = -1;
    std::string peer_addr_;
};

// TLS stream wrapping an SSL* connection
// Note: We use void* to avoid pulling in OpenSSL headers here.
// The implementation casts to SSL* internally.
class TlsStream : public IStream {
public:
    TlsStream(void* ssl_handle, int socket_fd, std::string peer_addr = "")
        : ssl_(ssl_handle), fd_(socket_fd), peer_addr_(std::move(peer_addr)) {}

    ~TlsStream() override { close(); }

    TlsStream(const TlsStream&) = delete;
    TlsStream& operator=(const TlsStream&) = delete;

    ssize_t read(void* buf, size_t max_bytes) override;
    ssize_t write(const void* buf, size_t len) override;
    void shutdown() override;
    void close() override;
    bool is_open() const override { return ssl_ != nullptr; }
    int fd() const override { return fd_; }
    std::string peer_address() const override { return peer_addr_; }
    std::string_view stream_type() const override { return "tls"; }

    void* native_ssl() const { return ssl_; }

private:
    void* ssl_ = nullptr;
    int fd_ = -1;
    std::string peer_addr_;
};

// HTTP/2 virtual stream (multiplexed over a single connection)
class H2VirtualStream : public IStream {
public:
    using WriteFn = std::function<bool(uint32_t stream_id, const void* data, size_t len)>;

    H2VirtualStream(uint32_t stream_id, WriteFn write_fn)
        : stream_id_(stream_id), write_fn_(std::move(write_fn)) {}

    ssize_t read(void* buf, size_t max_bytes) override;
    ssize_t write(const void* buf, size_t len) override;
    void shutdown() override { open_ = false; }
    void close() override { open_ = false; }
    bool is_open() const override { return open_; }
    std::string_view stream_type() const override { return "h2"; }

    // Feed data into the virtual stream's read buffer (called by the H2 connection)
    void feed_data(std::span<const uint8_t> data);

    uint32_t stream_id() const { return stream_id_; }

private:
    uint32_t stream_id_;
    WriteFn write_fn_;
    std::string read_buffer_;
    size_t read_offset_ = 0;
    bool open_ = true;
};

// QUIC stream (placeholder for HTTP/3 transport)
class QuicStream : public IStream {
public:
    QuicStream(uint64_t stream_id, void* quic_conn)
        : stream_id_(stream_id), quic_conn_(quic_conn) {}

    ssize_t read(void* buf, size_t max_bytes) override;
    ssize_t write(const void* buf, size_t len) override;
    void shutdown() override;
    void close() override;
    bool is_open() const override { return open_; }
    std::string_view stream_type() const override { return "quic"; }

    uint64_t quic_stream_id() const { return stream_id_; }

private:
    uint64_t stream_id_;
    void* quic_conn_;
    bool open_ = true;
};

} // namespace js
