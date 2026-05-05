// Minimal test framework (no external dependencies)
#include <iostream>
#include <string>
#include <vector>
#include <functional>
#include <cstdlib>

struct TestCase {
    std::string name;
    std::function<bool()> func;
};

static std::vector<TestCase>& test_registry() {
    static std::vector<TestCase> tests;
    return tests;
}

bool register_test(const char* name, std::function<bool()> func) {
    test_registry().push_back({name, std::move(func)});
    return true;
}

#define TEST(name) \
    static bool test_##name(); \
    static bool _reg_##name = register_test(#name, test_##name); \
    static bool test_##name()

#define ASSERT_TRUE(expr) \
    do { if (!(expr)) { std::cerr << "  FAIL: " << #expr << " at " << __FILE__ << ":" << __LINE__ << "\n"; return false; } } while(0)

#define ASSERT_FALSE(expr) ASSERT_TRUE(!(expr))

#define ASSERT_EQ(a, b) \
    do { if ((a) != (b)) { std::cerr << "  FAIL: " << #a << " != " << #b << " at " << __FILE__ << ":" << __LINE__ << "\n"; return false; } } while(0)

// Include test files (they use the macros above)
// These are compiled as separate translation units, so we just run them here.

int main() {
    int passed = 0;
    int failed = 0;

    for (auto& tc : test_registry()) {
        std::cout << "  RUN  " << tc.name << "\n";
        try {
            if (tc.func()) {
                std::cout << "  PASS " << tc.name << "\n";
                passed++;
            } else {
                std::cout << "  FAIL " << tc.name << "\n";
                failed++;
            }
        } catch (const std::exception& e) {
            std::cerr << "  EXCEPTION: " << e.what() << "\n";
            std::cout << "  FAIL " << tc.name << "\n";
            failed++;
        }
    }

    std::cout << "\n" << passed << " passed, " << failed << " failed, "
              << (passed + failed) << " total\n";

    return failed > 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
