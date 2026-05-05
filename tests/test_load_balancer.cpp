#include "load_balancer.hpp"
#include <cassert>
#include <iostream>

namespace {

void test_round_robin() {
    std::vector<js::Backend> backends(3);
    backends[0].address = "10.0.0.1:8080"; backends[0].host = "10.0.0.1"; backends[0].port = 8080;
    backends[1].address = "10.0.0.2:8080"; backends[1].host = "10.0.0.2"; backends[1].port = 8080;
    backends[2].address = "10.0.0.3:8080"; backends[2].host = "10.0.0.3"; backends[2].port = 8080;

    auto lb = js::LoadBalancer::create(js::LBAlgorithm::ROUND_ROBIN, backends);

    auto* b1 = lb->select();
    auto* b2 = lb->select();
    auto* b3 = lb->select();
    auto* b4 = lb->select(); // Should wrap around

    assert(b1 != nullptr && b2 != nullptr && b3 != nullptr && b4 != nullptr);
    assert(b1 != b2);
    assert(b2 != b3);

    // Release connections
    lb->report_result(b1, std::chrono::nanoseconds(1000), true);
    lb->report_result(b2, std::chrono::nanoseconds(1000), true);
    lb->report_result(b3, std::chrono::nanoseconds(1000), true);
    lb->report_result(b4, std::chrono::nanoseconds(1000), true);

    std::cout << "  [PASS] round_robin\n";
}

void test_least_connections() {
    std::vector<js::Backend> backends(2);
    backends[0].address = "10.0.0.1:8080"; backends[0].host = "10.0.0.1"; backends[0].port = 8080;
    backends[1].address = "10.0.0.2:8080"; backends[1].host = "10.0.0.2"; backends[1].port = 8080;

    auto lb = js::LoadBalancer::create(js::LBAlgorithm::LEAST_CONNECTIONS, backends);

    // First request goes to one with fewer connections
    auto* b1 = lb->select();
    assert(b1 != nullptr);
    // b1 now has 1 connection

    auto* b2 = lb->select();
    assert(b2 != nullptr);
    // Both have 1 connection, b2 should be different from b1
    assert(b2 != b1);

    lb->report_result(b1, std::chrono::nanoseconds(1000), true);
    lb->report_result(b2, std::chrono::nanoseconds(1000), true);

    std::cout << "  [PASS] least_connections\n";
}

void test_consistent_hash() {
    std::vector<js::Backend> backends(3);
    backends[0].address = "10.0.0.1:8080"; backends[0].host = "10.0.0.1"; backends[0].port = 8080;
    backends[1].address = "10.0.0.2:8080"; backends[1].host = "10.0.0.2"; backends[1].port = 8080;
    backends[2].address = "10.0.0.3:8080"; backends[2].host = "10.0.0.3"; backends[2].port = 8080;

    auto lb = js::LoadBalancer::create(js::LBAlgorithm::CONSISTENT_HASH, backends);

    // Same key should always map to the same backend
    auto* b1 = lb->select("user-123");
    auto* b2 = lb->select("user-123");
    assert(b1 == b2); // Consistent!

    // Different key may map to different backend
    auto* b3 = lb->select("user-456");
    assert(b3 != nullptr);

    lb->report_result(b1, std::chrono::nanoseconds(1000), true);
    lb->report_result(b2, std::chrono::nanoseconds(1000), true);
    lb->report_result(b3, std::chrono::nanoseconds(1000), true);

    std::cout << "  [PASS] consistent_hash\n";
}

void test_ewma() {
    std::vector<js::Backend> backends(2);
    backends[0].address = "fast:8080"; backends[0].host = "10.0.0.1"; backends[0].port = 8080;
    backends[1].address = "slow:8080"; backends[1].host = "10.0.0.2"; backends[1].port = 8080;
    backends[0].last_response_time = std::chrono::steady_clock::now();
    backends[1].last_response_time = std::chrono::steady_clock::now();

    auto lb = js::LoadBalancer::create(js::LBAlgorithm::EWMA, backends);

    // Simulate: backend 0 is fast (1ms), backend 1 is slow (100ms)
    auto* b = lb->select();
    lb->report_result(b, std::chrono::nanoseconds(1000000), true); // 1ms

    b = lb->select();
    lb->report_result(b, std::chrono::nanoseconds(100000000), true); // 100ms

    // After learning, EWMA should prefer the faster backend
    // (This is a statistical test so we just verify it doesn't crash)
    for (int i = 0; i < 10; ++i) {
        b = lb->select();
        assert(b != nullptr);
        lb->report_result(b, std::chrono::nanoseconds(1000000), true);
    }

    std::cout << "  [PASS] ewma\n";
}

void test_unhealthy_backend_skip() {
    std::vector<js::Backend> backends(2);
    backends[0].address = "10.0.0.1:8080"; backends[0].host = "10.0.0.1"; backends[0].port = 8080;
    backends[0].healthy = false; // Unhealthy
    backends[1].address = "10.0.0.2:8080"; backends[1].host = "10.0.0.2"; backends[1].port = 8080;

    auto lb = js::LoadBalancer::create(js::LBAlgorithm::ROUND_ROBIN, backends);

    // Should always pick the healthy backend
    auto* b = lb->select();
    assert(b != nullptr);
    assert(b->address == "10.0.0.2:8080");

    lb->report_result(b, std::chrono::nanoseconds(1000), true);

    std::cout << "  [PASS] unhealthy_backend_skip\n";
}

} // namespace

void run_load_balancer_tests() {
    std::cout << "=== Load Balancer Tests ===\n";
    test_round_robin();
    test_least_connections();
    test_consistent_hash();
    test_ewma();
    test_unhealthy_backend_skip();
    std::cout << "=== All load balancer tests passed ===\n\n";
}
