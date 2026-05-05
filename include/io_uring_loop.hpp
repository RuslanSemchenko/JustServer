#pragma once

#include <cstdint>
#include <cstddef>
#include <functional>
#include <string>
#include <vector>
#include <unordered_map>
#include <atomic>
#include <chrono>

// Forward declare liburing types
struct io_uring;
struct io_uring_cqe;

namespace js {

// Completion callback: (result, flags) from the kernel
using IoCallback = std::function<void(int32_t result, uint32_t flags)>;

// Operation types for tracking
enum class IoOp : uint8_t {
    ACCEPT,
    READ,
    WRITE,
    SEND,
    RECV,
    SENDMSG,
    RECVMSG,
    TIMEOUT,
    CANCEL,
    CLOSE,
    SPLICE,
    PROVIDE_BUFFERS,
    POLL_ADD,
    CONNECT,
    SHUTDOWN,
    NOP,
};

// io_uring event loop: replaces epoll with zero-copy, batched syscall I/O.
// Supports multishot accept, provided buffers, and linked operations.
class IoUringLoop {
public:
    // queue_depth: number of SQE slots in the submission ring
    // flags: IORING_SETUP_* flags (e.g., IORING_SETUP_SQPOLL for kernel-side polling)
    explicit IoUringLoop(uint32_t queue_depth = 4096, uint32_t flags = 0);
    ~IoUringLoop();

    // Non-copyable
    IoUringLoop(const IoUringLoop&) = delete;
    IoUringLoop& operator=(const IoUringLoop&) = delete;

    // === Async operations (submit to SQ, callback on CQ) ===

    // Accept a new connection (multishot: keeps accepting until cancelled)
    void async_accept(int listen_fd, IoCallback cb, bool multishot = true);

    // Read from fd into buffer
    void async_read(int fd, void* buf, size_t len, uint64_t offset, IoCallback cb);

    // Write to fd from buffer
    void async_write(int fd, const void* buf, size_t len, uint64_t offset, IoCallback cb);

    // Send on socket (MSG_NOSIGNAL etc)
    void async_send(int fd, const void* buf, size_t len, int flags, IoCallback cb);

    // Recv on socket
    void async_recv(int fd, void* buf, size_t len, int flags, IoCallback cb);

    // Zero-copy send (uses IORING_OP_SEND_ZC when available)
    void async_send_zc(int fd, const void* buf, size_t len, int flags, IoCallback cb);

    // Splice for zero-copy file -> socket transfer (replaces sendfile)
    void async_splice(int fd_in, int64_t off_in, int fd_out, int64_t off_out,
                      size_t len, unsigned int splice_flags, IoCallback cb);

    // Add a timeout
    void async_timeout(std::chrono::milliseconds ms, IoCallback cb);

    // Cancel a pending operation by user_data
    void async_cancel(uint64_t user_data, IoCallback cb);

    // Close a file descriptor asynchronously
    void async_close(int fd, IoCallback cb);

    // Poll for readability/writability (one-shot)
    void async_poll_add(int fd, uint32_t poll_mask, IoCallback cb);

    // Connect to a remote address
    void async_connect(int fd, const struct sockaddr* addr, socklen_t addrlen, IoCallback cb);

    // Shutdown a socket
    void async_shutdown(int fd, int how, IoCallback cb);

    // === Provided buffer pool (zero-copy receive) ===

    // Register a pool of buffers that the kernel can use directly
    bool register_buffer_pool(uint16_t group_id, size_t buffer_size, size_t buffer_count);

    // Receive with provided buffers (kernel picks the buffer, zero-copy)
    void async_recv_provided(int fd, uint16_t group_id, IoCallback cb);

    // Get a provided buffer by index after a successful recv
    void* get_provided_buffer(uint16_t group_id, uint32_t buffer_id);

    // Return a provided buffer to the pool
    void return_provided_buffer(uint16_t group_id, uint32_t buffer_id);

    // === Event loop control ===

    // Run the event loop (blocks until stop() is called)
    void run();

    // Run one iteration (non-blocking, process available completions)
    int run_once(int timeout_ms = 0);

    // Submit pending entries and wait for at least min_complete completions
    int submit_and_wait(int min_complete = 0);

    // Stop the event loop
    void stop();

    // Is the loop running?
    bool running() const { return running_.load(std::memory_order_relaxed); }

    // === Stats ===
    uint64_t total_submissions() const { return total_submissions_; }
    uint64_t total_completions() const { return total_completions_; }
    uint64_t pending_operations() const { return pending_ops_; }

private:
    // Internal callback tracking
    struct PendingOp {
        IoCallback callback;
        IoOp type;
        bool multishot = false;
    };

    // Get the next user_data identifier
    uint64_t next_user_data();

    // Process a single completion
    void handle_completion(io_uring_cqe* cqe);

    // Process all available completions
    int process_completions();

    io_uring* ring_ = nullptr;
    std::unordered_map<uint64_t, PendingOp> pending_;
    std::atomic<bool> running_{false};
    uint64_t next_id_ = 1;

    // Provided buffer pools
    struct BufferPool {
        std::vector<uint8_t> storage;    // Contiguous buffer memory
        size_t buffer_size = 0;
        size_t buffer_count = 0;
    };
    std::unordered_map<uint16_t, BufferPool> buffer_pools_;

    // Stats
    uint64_t total_submissions_ = 0;
    uint64_t total_completions_ = 0;
    uint64_t pending_ops_ = 0;
};

} // namespace js
