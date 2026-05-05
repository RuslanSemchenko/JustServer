#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <new>
#include <vector>
#include <mutex>
#include <memory>

namespace js {

// Arena allocator: allocates memory in large contiguous blocks.
// All allocations are freed at once via reset() in O(1).
// Perfect for per-request memory where all data shares the same lifetime.
class ArenaAllocator {
public:
    static constexpr size_t DEFAULT_BLOCK_SIZE = 64 * 1024; // 64 KB blocks

    explicit ArenaAllocator(size_t block_size = DEFAULT_BLOCK_SIZE)
        : block_size_(block_size) {
        allocate_block(block_size_);
    }

    ~ArenaAllocator() {
        for (auto* block : blocks_) {
            std::free(block);
        }
    }

    // Non-copyable, movable
    ArenaAllocator(const ArenaAllocator&) = delete;
    ArenaAllocator& operator=(const ArenaAllocator&) = delete;
    ArenaAllocator(ArenaAllocator&& other) noexcept
        : blocks_(std::move(other.blocks_))
        , current_(other.current_)
        , end_(other.end_)
        , block_size_(other.block_size_)
        , total_allocated_(other.total_allocated_) {
        other.current_ = nullptr;
        other.end_ = nullptr;
        other.total_allocated_ = 0;
    }

    // Allocate aligned memory from the arena
    [[nodiscard]] void* allocate(size_t size, size_t alignment = alignof(std::max_align_t)) {
        // Align current pointer
        auto* aligned = reinterpret_cast<uint8_t*>(
            (reinterpret_cast<uintptr_t>(current_) + alignment - 1) & ~(alignment - 1));

        if (aligned + size > end_) {
            // Need a new block
            size_t alloc_size = (size + alignment > block_size_) ? size + alignment : block_size_;
            allocate_block(alloc_size);
            aligned = reinterpret_cast<uint8_t*>(
                (reinterpret_cast<uintptr_t>(current_) + alignment - 1) & ~(alignment - 1));
        }

        current_ = aligned + size;
        return aligned;
    }

    // Typed allocation
    template<typename T, typename... Args>
    [[nodiscard]] T* construct(Args&&... args) {
        void* ptr = allocate(sizeof(T), alignof(T));
        return new (ptr) T(std::forward<Args>(args)...);
    }

    // Allocate array
    template<typename T>
    [[nodiscard]] T* allocate_array(size_t count) {
        void* ptr = allocate(sizeof(T) * count, alignof(T));
        return static_cast<T*>(ptr);
    }

    // Duplicate a string into the arena
    [[nodiscard]] char* strdup(const char* str, size_t len) {
        char* dst = allocate_array<char>(len + 1);
        std::memcpy(dst, str, len);
        dst[len] = '\0';
        return dst;
    }

    // Reset all allocations in O(1) -- keeps the first block for reuse
    void reset() {
        if (blocks_.empty()) return;

        // Free all blocks except the first
        for (size_t i = 1; i < blocks_.size(); ++i) {
            std::free(blocks_[i]);
        }

        auto* first_block = blocks_[0];
        blocks_.resize(1);
        current_ = first_block;
        end_ = first_block + block_size_;
        total_allocated_ = block_size_;
    }

    // Stats
    size_t total_allocated() const { return total_allocated_; }
    size_t bytes_used() const {
        if (blocks_.empty()) return 0;
        // Approximate: sum of full blocks + used portion of current block
        size_t used = 0;
        for (size_t i = 0; i + 1 < blocks_.size(); ++i) {
            used += block_size_; // Approximate
        }
        if (current_ && !blocks_.empty()) {
            used += static_cast<size_t>(current_ - blocks_.back());
        }
        return used;
    }

private:
    void allocate_block(size_t size) {
        auto* block = static_cast<uint8_t*>(std::malloc(size));
        if (!block) throw std::bad_alloc();
        blocks_.push_back(block);
        current_ = block;
        end_ = block + size;
        total_allocated_ += size;
    }

    std::vector<uint8_t*> blocks_;
    uint8_t* current_ = nullptr;
    uint8_t* end_ = nullptr;
    size_t block_size_;
    size_t total_allocated_ = 0;
};

// Slab allocator: pre-allocated fixed-size object pool.
// Zero fragmentation, O(1) alloc/free via free-list.
// Ideal for connection objects, request contexts, etc.
template<typename T, size_t SlabCapacity = 256>
class SlabAllocator {
public:
    SlabAllocator() {
        grow();
    }

    ~SlabAllocator() {
        for (auto* slab : slabs_) {
            std::free(slab);
        }
    }

    // Non-copyable
    SlabAllocator(const SlabAllocator&) = delete;
    SlabAllocator& operator=(const SlabAllocator&) = delete;

    // Allocate one object slot (O(1) from free list)
    [[nodiscard]] T* allocate() {
        std::lock_guard lock(mutex_);
        if (!free_head_) {
            grow();
        }
        auto* node = free_head_;
        free_head_ = node->next;
        ++allocated_count_;
        return reinterpret_cast<T*>(node);
    }

    // Return one object slot to the free list (O(1))
    void deallocate(T* ptr) {
        if (!ptr) return;
        std::lock_guard lock(mutex_);
        auto* node = reinterpret_cast<FreeNode*>(ptr);
        node->next = free_head_;
        free_head_ = node;
        --allocated_count_;
    }

    // Construct in-place
    template<typename... Args>
    [[nodiscard]] T* construct(Args&&... args) {
        T* ptr = allocate();
        return new (ptr) T(std::forward<Args>(args)...);
    }

    // Destroy and deallocate
    void destroy(T* ptr) {
        if (!ptr) return;
        ptr->~T();
        deallocate(ptr);
    }

    size_t allocated_count() const { return allocated_count_; }
    size_t capacity() const { return slabs_.size() * SlabCapacity; }

private:
    union FreeNode {
        FreeNode* next;
        alignas(T) char storage[sizeof(T)];
    };
    static_assert(sizeof(FreeNode) >= sizeof(T));

    void grow() {
        // Allocate a new slab of SlabCapacity nodes
        auto* slab = static_cast<FreeNode*>(
            std::malloc(sizeof(FreeNode) * SlabCapacity));
        if (!slab) throw std::bad_alloc();
        slabs_.push_back(slab);

        // Chain all nodes into the free list
        for (size_t i = 0; i < SlabCapacity - 1; ++i) {
            slab[i].next = &slab[i + 1];
        }
        slab[SlabCapacity - 1].next = free_head_;
        free_head_ = slab;
    }

    std::vector<FreeNode*> slabs_;
    FreeNode* free_head_ = nullptr;
    size_t allocated_count_ = 0;
    std::mutex mutex_;
};

// Per-request context with arena allocator for zero-cost cleanup
struct RequestArena {
    ArenaAllocator arena;

    // Convenience allocation
    template<typename T, typename... Args>
    T* alloc(Args&&... args) {
        return arena.construct<T>(std::forward<Args>(args)...);
    }

    char* dup(std::string_view sv) {
        return arena.strdup(sv.data(), sv.size());
    }
};

} // namespace js
