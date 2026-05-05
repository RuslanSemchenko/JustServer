#include "unicode.hpp"
#include <iostream>
#include <functional>

bool register_test(const char* name, std::function<bool()> func);

#define TEST(name) \
    static bool test_##name(); \
    static bool _reg_##name = register_test(#name, test_##name); \
    static bool test_##name()

#define ASSERT_TRUE(expr) \
    do { if (!(expr)) { std::cerr << "  FAIL: " << #expr << " at " << __FILE__ << ":" << __LINE__ << "\n"; return false; } } while(0)
#define ASSERT_FALSE(expr) ASSERT_TRUE(!(expr))

using namespace js;

TEST(unicode_valid_ascii) {
    ASSERT_TRUE(Unicode::is_valid_utf8("Hello, World!"));
    return true;
}

TEST(unicode_valid_multibyte) {
    ASSERT_TRUE(Unicode::is_valid_utf8("\xc3\xa9")); // e with accent (U+00E9)
    return true;
}

TEST(unicode_detect_overlong) {
    // Overlong encoding of '/' (U+002F): 0xC0 0xAF
    std::string overlong = "\xc0\xaf";
    ASSERT_TRUE(Unicode::has_overlong_encoding(overlong));
    return true;
}

TEST(unicode_detect_multibyte_bypass_fullwidth) {
    // Fullwidth slash U+FF0F (3 bytes: EF BC 8F)
    std::string fw_slash = "\xef\xbc\x8f";
    ASSERT_TRUE(Unicode::detect_multibyte_bypass(fw_slash));
    return true;
}

TEST(unicode_safe_text_no_bypass) {
    ASSERT_FALSE(Unicode::detect_multibyte_bypass("Hello World"));
    return true;
}

TEST(unicode_percent_decode) {
    auto result = Unicode::decode_percent_utf8("%2Fetc%2Fpasswd");
    ASSERT_TRUE(result == "/etc/passwd");
    return true;
}

TEST(unicode_normalize_strips_dangerous) {
    // Zero-width space (U+200B) should be stripped
    std::string input = "test\xe2\x80\x8bvalue"; // test + ZWSP + value
    auto result = Unicode::normalize_utf8(input);
    ASSERT_TRUE(result == "testvalue");
    return true;
}

TEST(unicode_shiftjis_bypass_detection) {
    // Shift-JIS lead byte 0x81 followed by ASCII '/' (0x2F)
    std::string sjis = "\x81\x2f";
    ASSERT_TRUE(Unicode::detect_shiftjis_bypass(sjis));
    return true;
}
