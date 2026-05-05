#include "io_uring_loop.hpp"
#include "logger.hpp"

#include <liburing.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <cerrno>
#include <stdexcept>

namespace js {

IoUringLoop::IoUringLoop(uint32_t queue_depth, uint32_t flags) {
    ring_ = new io_uring{};
    struct io_uring_params params{};
    params.flags = flags;

    int ret = io_uring_queue_init_params(queue_depth, ring_, &params);
    if (ret < 0) {
        delete ring_;
        ring_ = nullptr;
        throw std::runtime_error(
            std::string("io_uring_queue_init failed: ") + strerror(-ret));
    }

    LOG_INFO("io_uring initialized: queue_depth=" + std::to_string(queue_depth) +
             " features=0x" + std::to_string(params.features));
}

IoUringLoop::~IoUringLoop() {
    if (ring_) {
        io_uring_queue_exit(ring_);
        delete ring_;
    }
}

uint64_t IoUringLoop::next_user_data() {
    return next_id_++;
}

// === Async operations ===

void IoUringLoop::async_accept(int listen_fd, IoCallback cb, bool multishot) {
    auto* sqe = io_uring_get_sqe(ring_);
    if (!sqe) {
        submit_and_wait(0);
        sqe = io_uring_get_sqe(ring_);
        if (!sqe) {
            cb(-ENOMEM, 0);
            return;
        }
    }

    if (multishot) {
        io_uring_prep_multishot_accept(sqe, listen_fd, nullptr, nullptr, 0);
    } else {
        io_uring_prep_accept(sqe, listen_fd, nullptr, nullptr, 0);
    }

    uint64_t id = next_user_data();
    io_uring_sqe_set_data64(sqe, id);
    pending_[id] = {std::move(cb), IoOp::ACCEPT, multishot};
    ++pending_ops_;
    ++total_submissions_;
}

void IoUringLoop::async_read(int fd, void* buf, size_t len, uint64_t offset, IoCallback cb) {
    auto* sqe = io_uring_get_sqe(ring_);
    if (!sqe) {
        submit_and_wait(0);
        sqe = io_uring_get_sqe(ring_);
        if (!sqe) { cb(-ENOMEM, 0); return; }
    }

    io_uring_prep_read(sqe, fd, buf, static_cast<unsigned>(len), offset);
    uint64_t id = next_user_data();
    io_uring_sqe_set_data64(sqe, id);
    pending_[id] = {std::move(cb), IoOp::READ, false};
    ++pending_ops_;
    ++total_submissions_;
}

void IoUringLoop::async_write(int fd, const void* buf, size_t len, uint64_t offset, IoCallback cb) {
    auto* sqe = io_uring_get_sqe(ring_);
    if (!sqe) {
        submit_and_wait(0);
        sqe = io_uring_get_sqe(ring_);
        if (!sqe) { cb(-ENOMEM, 0); return; }
    }

    io_uring_prep_write(sqe, fd, buf, static_cast<unsigned>(len), offset);
    uint64_t id = next_user_data();
    io_uring_sqe_set_data64(sqe, id);
    pending_[id] = {std::move(cb), IoOp::WRITE, false};
    ++pending_ops_;
    ++total_submissions_;
}

void IoUringLoop::async_send(int fd, const void* buf, size_t len, int flags, IoCallback cb) {
    auto* sqe = io_uring_get_sqe(ring_);
    if (!sqe) {
        submit_and_wait(0);
        sqe = io_uring_get_sqe(ring_);
        if (!sqe) { cb(-ENOMEM, 0); return; }
    }

    io_uring_prep_send(sqe, fd, buf, len, flags);
    uint64_t id = next_user_data();
    io_uring_sqe_set_data64(sqe, id);
    pending_[id] = {std::move(cb), IoOp::SEND, false};
    ++pending_ops_;
    ++total_submissions_;
}

void IoUringLoop::async_recv(int fd, void* buf, size_t len, int flags, IoCallback cb) {
    auto* sqe = io_uring_get_sqe(ring_);
    if (!sqe) {
        submit_and_wait(0);
        sqe = io_uring_get_sqe(ring_);
        if (!sqe) { cb(-ENOMEM, 0); return; }
    }

    io_uring_prep_recv(sqe, fd, buf, len, flags);
    uint64_t id = next_user_data();
    io_uring_sqe_set_data64(sqe, id);
    pending_[id] = {std::move(cb), IoOp::RECV, false};
    ++pending_ops_;
    ++total_submissions_;
}

void IoUringLoop::async_send_zc(int fd, const void* buf, size_t len, int flags, IoCallback cb) {
    auto* sqe = io_uring_get_sqe(ring_);
    if (!sqe) {
        submit_and_wait(0);
        sqe = io_uring_get_sqe(ring_);
        if (!sqe) { cb(-ENOMEM, 0); return; }
    }

    // Use zero-copy send if available (kernel 6.0+), fallback to regular send
    io_uring_prep_send_zc(sqe, fd, buf, len, flags, 0);
    uint64_t id = next_user_data();
    io_uring_sqe_set_data64(sqe, id);
    pending_[id] = {std::move(cb), IoOp::SEND, false};
    ++pending_ops_;
    ++total_submissions_;
}

void IoUringLoop::async_splice(int fd_in, int64_t off_in, int fd_out, int64_t off_out,
                                size_t len, unsigned int splice_flags, IoCallback cb) {
    auto* sqe = io_uring_get_sqe(ring_);
    if (!sqe) {
        submit_and_wait(0);
        sqe = io_uring_get_sqe(ring_);
        if (!sqe) { cb(-ENOMEM, 0); return; }
    }

    io_uring_prep_splice(sqe, fd_in, off_in, fd_out, off_out,
                         static_cast<unsigned int>(len), splice_flags);
    uint64_t id = next_user_data();
    io_uring_sqe_set_data64(sqe, id);
    pending_[id] = {std::move(cb), IoOp::SPLICE, false};
    ++pending_ops_;
    ++total_submissions_;
}

void IoUringLoop::async_timeout(std::chrono::milliseconds ms, IoCallback cb) {
    auto* sqe = io_uring_get_sqe(ring_);
    if (!sqe) {
        submit_and_wait(0);
        sqe = io_uring_get_sqe(ring_);
        if (!sqe) { cb(-ENOMEM, 0); return; }
    }

    // Store timeout spec - we need it to outlive the SQE submission
    // Use a heap-allocated timespec that gets cleaned up on completion
    auto* ts = new __kernel_timespec{};
    ts->tv_sec = static_cast<long long>(ms.count() / 1000);
    ts->tv_nsec = static_cast<long long>((ms.count() % 1000) * 1000000);

    io_uring_prep_timeout(sqe, ts, 0, 0);
    uint64_t id = next_user_data();
    io_uring_sqe_set_data64(sqe, id);

    // Wrap callback to also free the timespec
    pending_[id] = {[cb = std::move(cb), ts](int32_t res, uint32_t flags) {
        delete ts;
        cb(res, flags);
    }, IoOp::TIMEOUT, false};
    ++pending_ops_;
    ++total_submissions_;
}

void IoUringLoop::async_cancel(uint64_t user_data, IoCallback cb) {
    auto* sqe = io_uring_get_sqe(ring_);
    if (!sqe) {
        submit_and_wait(0);
        sqe = io_uring_get_sqe(ring_);
        if (!sqe) { cb(-ENOMEM, 0); return; }
    }

    io_uring_prep_cancel64(sqe, user_data, 0);
    uint64_t id = next_user_data();
    io_uring_sqe_set_data64(sqe, id);
    pending_[id] = {std::move(cb), IoOp::CANCEL, false};
    ++pending_ops_;
    ++total_submissions_;
}

void IoUringLoop::async_close(int fd, IoCallback cb) {
    auto* sqe = io_uring_get_sqe(ring_);
    if (!sqe) {
        submit_and_wait(0);
        sqe = io_uring_get_sqe(ring_);
        if (!sqe) { cb(-ENOMEM, 0); return; }
    }

    io_uring_prep_close(sqe, fd);
    uint64_t id = next_user_data();
    io_uring_sqe_set_data64(sqe, id);
    pending_[id] = {std::move(cb), IoOp::CLOSE, false};
    ++pending_ops_;
    ++total_submissions_;
}

void IoUringLoop::async_poll_add(int fd, uint32_t poll_mask, IoCallback cb) {
    auto* sqe = io_uring_get_sqe(ring_);
    if (!sqe) {
        submit_and_wait(0);
        sqe = io_uring_get_sqe(ring_);
        if (!sqe) { cb(-ENOMEM, 0); return; }
    }

    io_uring_prep_poll_add(sqe, fd, poll_mask);
    uint64_t id = next_user_data();
    io_uring_sqe_set_data64(sqe, id);
    pending_[id] = {std::move(cb), IoOp::POLL_ADD, false};
    ++pending_ops_;
    ++total_submissions_;
}

void IoUringLoop::async_connect(int fd, const struct sockaddr* addr,
                                 socklen_t addrlen, IoCallback cb) {
    auto* sqe = io_uring_get_sqe(ring_);
    if (!sqe) {
        submit_and_wait(0);
        sqe = io_uring_get_sqe(ring_);
        if (!sqe) { cb(-ENOMEM, 0); return; }
    }

    // io_uring_prep_connect may not be available in all liburing versions
    // Manually prepare the SQE for IORING_OP_CONNECT
    io_uring_prep_rw(IORING_OP_CONNECT, sqe, fd, addr, 0, addrlen);
    uint64_t id = next_user_data();
    io_uring_sqe_set_data64(sqe, id);
    pending_[id] = {std::move(cb), IoOp::CONNECT, false};
    ++pending_ops_;
    ++total_submissions_;
}

void IoUringLoop::async_shutdown(int fd, int how, IoCallback cb) {
    auto* sqe = io_uring_get_sqe(ring_);
    if (!sqe) {
        submit_and_wait(0);
        sqe = io_uring_get_sqe(ring_);
        if (!sqe) { cb(-ENOMEM, 0); return; }
    }

    io_uring_prep_shutdown(sqe, fd, how);
    uint64_t id = next_user_data();
    io_uring_sqe_set_data64(sqe, id);
    pending_[id] = {std::move(cb), IoOp::SHUTDOWN, false};
    ++pending_ops_;
    ++total_submissions_;
}

// === Provided buffer pool ===

bool IoUringLoop::register_buffer_pool(uint16_t group_id, size_t buffer_size, size_t buffer_count) {
    BufferPool pool;
    pool.buffer_size = buffer_size;
    pool.buffer_count = buffer_count;
    pool.storage.resize(buffer_size * buffer_count);

    // Register buffers with the kernel via provide_buffers
    auto* sqe = io_uring_get_sqe(ring_);
    if (!sqe) return false;

    io_uring_prep_provide_buffers(sqe, pool.storage.data(),
                                  static_cast<int>(buffer_size),
                                  static_cast<int>(buffer_count),
                                  group_id, 0);

    uint64_t id = next_user_data();
    io_uring_sqe_set_data64(sqe, id);
    pending_[id] = {[](int32_t, uint32_t){}, IoOp::PROVIDE_BUFFERS, false};
    ++pending_ops_;

    io_uring_submit(ring_);

    // Wait for completion
    struct io_uring_cqe* cqe = nullptr;
    io_uring_wait_cqe(ring_, &cqe);
    bool success = (cqe->res >= 0);
    io_uring_cqe_seen(ring_, cqe);

    if (success) {
        buffer_pools_[group_id] = std::move(pool);
        LOG_INFO("Registered buffer pool: group=" + std::to_string(group_id) +
                 " buffers=" + std::to_string(buffer_count) +
                 " size=" + std::to_string(buffer_size));
    }

    return success;
}

void IoUringLoop::async_recv_provided(int fd, uint16_t group_id, IoCallback cb) {
    auto* sqe = io_uring_get_sqe(ring_);
    if (!sqe) {
        submit_and_wait(0);
        sqe = io_uring_get_sqe(ring_);
        if (!sqe) { cb(-ENOMEM, 0); return; }
    }

    auto it = buffer_pools_.find(group_id);
    if (it == buffer_pools_.end()) { cb(-EINVAL, 0); return; }

    io_uring_prep_recv(sqe, fd, nullptr, it->second.buffer_size, 0);
    sqe->flags |= IOSQE_BUFFER_SELECT;
    sqe->buf_group = group_id;

    uint64_t id = next_user_data();
    io_uring_sqe_set_data64(sqe, id);
    pending_[id] = {std::move(cb), IoOp::RECV, false};
    ++pending_ops_;
    ++total_submissions_;
}

void* IoUringLoop::get_provided_buffer(uint16_t group_id, uint32_t buffer_id) {
    auto it = buffer_pools_.find(group_id);
    if (it == buffer_pools_.end()) return nullptr;
    if (buffer_id >= it->second.buffer_count) return nullptr;
    return it->second.storage.data() + (buffer_id * it->second.buffer_size);
}

void IoUringLoop::return_provided_buffer(uint16_t group_id, uint32_t buffer_id) {
    auto it = buffer_pools_.find(group_id);
    if (it == buffer_pools_.end()) return;

    auto* sqe = io_uring_get_sqe(ring_);
    if (!sqe) return;

    void* buf = it->second.storage.data() + (buffer_id * it->second.buffer_size);
    io_uring_prep_provide_buffers(sqe, buf,
                                  static_cast<int>(it->second.buffer_size),
                                  1, group_id, static_cast<int>(buffer_id));

    uint64_t id = next_user_data();
    io_uring_sqe_set_data64(sqe, id);
    pending_[id] = {[](int32_t, uint32_t){}, IoOp::PROVIDE_BUFFERS, false};
    ++pending_ops_;
}

// === Event loop ===

void IoUringLoop::handle_completion(io_uring_cqe* cqe) {
    uint64_t id = io_uring_cqe_get_data64(cqe);
    auto it = pending_.find(id);
    if (it == pending_.end()) return;

    auto& op = it->second;
    bool is_multishot = op.multishot;

    // Call the user callback
    if (op.callback) {
        op.callback(cqe->res, cqe->flags);
    }

    // For multishot operations, only remove if the operation is done
    // (IORING_CQE_F_MORE flag means more completions will come)
    if (!is_multishot || !(cqe->flags & IORING_CQE_F_MORE)) {
        pending_.erase(it);
        --pending_ops_;
    }

    ++total_completions_;
}

int IoUringLoop::process_completions() {
    struct io_uring_cqe* cqe = nullptr;
    unsigned head = 0;
    int count = 0;

    io_uring_for_each_cqe(ring_, head, cqe) {
        handle_completion(cqe);
        ++count;
    }

    if (count > 0) {
        io_uring_cq_advance(ring_, static_cast<unsigned>(count));
    }

    return count;
}

int IoUringLoop::submit_and_wait(int min_complete) {
    return io_uring_submit_and_wait(ring_, min_complete);
}

int IoUringLoop::run_once(int timeout_ms) {
    io_uring_submit(ring_);

    if (timeout_ms == 0) {
        // Non-blocking: peek at completions
        struct io_uring_cqe* cqe = nullptr;
        int ret = io_uring_peek_cqe(ring_, &cqe);
        if (ret < 0) return 0;
    } else {
        // Wait with timeout
        struct __kernel_timespec ts{};
        ts.tv_sec = timeout_ms / 1000;
        ts.tv_nsec = static_cast<long long>(timeout_ms % 1000) * 1000000;

        struct io_uring_cqe* cqe = nullptr;
        io_uring_wait_cqe_timeout(ring_, &cqe, &ts);
    }

    return process_completions();
}

void IoUringLoop::run() {
    running_ = true;

    while (running_.load(std::memory_order_relaxed)) {
        io_uring_submit(ring_);

        struct io_uring_cqe* cqe = nullptr;
        struct __kernel_timespec ts{};
        ts.tv_sec = 0;
        ts.tv_nsec = 100000000; // 100ms timeout

        int ret = io_uring_wait_cqe_timeout(ring_, &cqe, &ts);
        if (ret == -ETIME) continue;
        if (ret < 0) {
            if (ret == -EINTR) continue;
            LOG_ERROR("io_uring_wait_cqe error: " + std::string(strerror(-ret)));
            break;
        }

        process_completions();
    }
}

void IoUringLoop::stop() {
    running_ = false;
}

} // namespace js
