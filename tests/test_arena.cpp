#include "arena_allocator.hpp"
#include <cassert>
#include <cstring>
#include <iostream>

namespace {

void test_arena_basic_allocation() {
    js::ArenaAllocator arena(1024);

    auto* p1 = arena.allocate(64);
    assert(p1 != nullptr);

    auto* p2 = arena.allocate(128);
    assert(p2 != nullptr);
    assert(p2 != p1);

    // Allocations should not overlap
    auto diff = static_cast<uint8_t*>(p2) - static_cast<uint8_t*>(p1);
    assert(diff >= 64);

    std::cout << "  [PASS] arena_basic_allocation\n";
}

void test_arena_construct() {
    js::ArenaAllocator arena;

    struct TestObj {
        int x;
        double y;
        TestObj(int a, double b) : x(a), y(b) {}
    };

    auto* obj = arena.construct<TestObj>(42, 3.14);
    assert(obj != nullptr);
    assert(obj->x == 42);
    assert(obj->y == 3.14);

    std::cout << "  [PASS] arena_construct\n";
}

void test_arena_strdup() {
    js::ArenaAllocator arena;

    const char* original = "Hello, Arena!";
    auto* copy = arena.strdup(original, strlen(original));
    assert(copy != nullptr);
    assert(strcmp(copy, original) == 0);
    assert(copy != original); // Different pointer

    std::cout << "  [PASS] arena_strdup\n";
}

void test_arena_reset() {
    js::ArenaAllocator arena(1024);

    // Allocate some memory
    (void)arena.allocate(256);
    (void)arena.allocate(256);
    (void)arena.allocate(256);

    auto before = arena.total_allocated();
    arena.reset();

    // After reset, should be able to allocate again within the first block
    auto* p = arena.allocate(512);
    assert(p != nullptr);

    // Total allocated should not increase much (reuses first block)
    assert(arena.total_allocated() <= before);

    std::cout << "  [PASS] arena_reset\n";
}

void test_arena_large_allocation() {
    js::ArenaAllocator arena(256); // Small block size

    // Allocate more than block size
    auto* p = arena.allocate(1024);
    assert(p != nullptr);

    std::cout << "  [PASS] arena_large_allocation\n";
}

void test_slab_allocator() {
    js::SlabAllocator<int, 16> slab;

    // Allocate several objects
    std::vector<int*> ptrs;
    for (int i = 0; i < 32; ++i) {
        auto* p = slab.construct(i);
        assert(p != nullptr);
        assert(*p == i);
        ptrs.push_back(p);
    }

    assert(slab.allocated_count() == 32);

    // Free half
    for (size_t i = 0; i < 16; ++i) {
        slab.destroy(ptrs[i]);
    }

    assert(slab.allocated_count() == 16);

    // Reallocate (should reuse freed slots)
    for (int i = 0; i < 16; ++i) {
        auto* p = slab.construct(100 + i);
        assert(p != nullptr);
        assert(*p == 100 + i);
    }

    assert(slab.allocated_count() == 32);

    std::cout << "  [PASS] slab_allocator\n";
}

void test_request_arena() {
    js::RequestArena ra;

    auto* val = ra.alloc<int>(42);
    assert(val != nullptr);
    assert(*val == 42);

    auto* str = ra.dup("test string");
    assert(str != nullptr);
    assert(strcmp(str, "test string") == 0);

    std::cout << "  [PASS] request_arena\n";
}

} // namespace

void run_arena_tests() {
    std::cout << "=== Arena Allocator Tests ===\n";
    test_arena_basic_allocation();
    test_arena_construct();
    test_arena_strdup();
    test_arena_reset();
    test_arena_large_allocation();
    test_slab_allocator();
    test_request_arena();
    std::cout << "=== All arena tests passed ===\n\n";
}
